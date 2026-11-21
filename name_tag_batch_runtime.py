"""Verified Batch orchestration over the host Ledger and a synthetic adapter only."""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import json
import re
from hashlib import sha256
from types import MappingProxyType
from typing import Final

from name_tag_batch_approval import (
    BatchAuthRejected,
    VerifiedBatchApproval,
    VerifiedBatchRowAuthority,
    derive_batch_row_authority,
    revalidate_verified_batch,
)
from name_tag_batch_credentials import CredentialBlocked
from name_tag_batch_credentials import validate_issued_batch_session
from name_tag_batch_iam import IAMPolicyBlocked, KindPolicy, build_subset_session_policy
from name_tag_batch_report import ReportBlocked, make_authenticated_batch_report
from name_tag_batch_report import reconcile_batch_outcomes
from name_tag_batch_state import classify_batch_name
from name_tag_batch_trust import load_current_protected_owner_trust
from name_tag_batch_fake import (
    BatchOfflineRuntime,
    BatchRunResult,
    BatchRuntimeEvidence,
    FakeBatchSDKAdapter,
    JsonValue,
)
from name_tag_ledger import BatchExecutionState, IntentLedger, LedgerError
from name_tag_scope import ScopeEvidence, SideEffectEvidence


_VOLUME_POLICY: Final = MappingProxyType({
    "volume": KindPolicy("ec2:CreateTags", "ec2:DescribeVolumes")
})


def _evidence_for(
    batch: VerifiedBatchApproval,
    runtime: BatchOfflineRuntime,
    row: Mapping[str, object],
) -> BatchRuntimeEvidence:
    """Bind runtime Scope evidence to the signed Plan row; fail closed on any doubt."""
    scope_id = row.get("writer_control_scope_id")
    if not isinstance(scope_id, str):
        raise LedgerError("BLOCKED_SCOPE_MISMATCH")
    evidence = runtime.evidence_by_scope.get(scope_id)
    if not isinstance(evidence, BatchRuntimeEvidence):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    scope = evidence.scope
    try:
        plan = json.loads(batch.plan_bytes)
        account, partition = plan.get("account"), plan.get("partition")
    except (ValueError, AttributeError):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from None
    arn = row.get("resource_arn")
    now = datetime.now(timezone.utc)
    if (type(scope) is not ScopeEvidence
            or not isinstance(arn, str) or not arn
            or not isinstance(account, str) or not isinstance(partition, str)
            or scope.writer_control_scope_id != scope_id
            or scope.account != account
            or scope.partition != partition
            or scope.region != row.get("region")
            or arn not in scope.controlled_arns
            or scope.responsible_owner != batch.owner_principal_id
            or re.fullmatch(r"[0-9a-f]{64}", scope.writer_evidence_digest) is None
            or not scope.not_before_utc <= now <= scope.not_after_utc):
        raise LedgerError("BLOCKED_SCOPE_MISMATCH")
    effects = [e for e in evidence.side_effects
               if isinstance(e, SideEffectEvidence) and e.target_arn == arn]
    if (len(effects) != 1
            or effects[0].iam_abac_resource_tag_assessment != "PASS"
            or effects[0].iac_assessment != "PASS"
            or effects[0].event_automation_assessment != "PASS"
            or not effects[0].evidence_references
            or any(not ref for ref in effects[0].evidence_references)
            or not effects[0].not_before_utc <= now <= effects[0].not_after_utc):
        raise LedgerError("BLOCKED_SCOPE_MISMATCH")
    return evidence


def _current_authority(
    batch: VerifiedBatchApproval, row_index: int
) -> VerifiedBatchRowAuthority:
    trust = load_current_protected_owner_trust()
    return derive_batch_row_authority(
        batch, row_index, trust=trust, now_utc=datetime.now(timezone.utc)
    )


def _name_snapshot_hash(observation) -> str:
    from name_tag_batch_approval import canonical_bytes

    return sha256(canonical_bytes([
        observation.state, observation.name_key_present, observation.name_raw_value
    ])).hexdigest()


def _record_cap_for_unclaimed(
    batch: VerifiedBatchApproval,
    ledger: IntentLedger,
    runtime: BatchOfflineRuntime,
    state: BatchExecutionState,
) -> str | None:
    if state.send_attempts_consumed < state.max_send_attempts:
        raise LedgerError("BLOCKED_AUTH_REPLAY")
    for position, row_index in enumerate(batch.approved_row_indexes):
        if state.outcomes[position] != "UNCLAIMED":
            continue
        try:
            authority = _current_authority(batch, row_index)
        except BatchAuthRejected:
            ledger.stop_batch(batch,reason_code="BLOCKED_OWNER_AUTHN")
            return "BLOCKED_OWNER_AUTHN"
        try:
            evidence = _evidence_for(batch, runtime, authority.row)
        except LedgerError as error:
            ledger.stop_batch(batch,reason_code=error.code)
            return error.code
        try:
            ledger.record_batch_presend_disposition(
                authority, scope=evidence.scope, side_effects=evidence.side_effects,
                decision="NOT_ATTEMPTED_CAP", reason_code="SIGNED_CAP_REACHED",
            )
        except LedgerError as error:
            ledger.stop_batch(batch,reason_code=error.code)
            return error.code
    return None


def _execute_unclaimed_row(
    batch: VerifiedBatchApproval,
    row_index: int,
    ledger: IntentLedger,
    runtime: BatchOfflineRuntime,
    report: dict[str, JsonValue],
) -> bool:
    """Run one fresh row; return true when the Batch must stop."""
    try:
        authority = _current_authority(batch, row_index)
    except BatchAuthRejected:
        ledger.stop_batch(batch, reason_code="BLOCKED_OWNER_AUTHN")
        report["authentication_state"] = "OWNER_AUTHN_REVOKED"
        return True
    row = authority.row
    try:
        evidence = _evidence_for(batch, runtime, row)
    except LedgerError as error:
        ledger.stop_batch(batch, reason_code=error.code)
        return True
    resource_arn = row.get("resource_arn")
    approved_name = row.get("approved_name")
    if not isinstance(resource_arn, str) or not isinstance(approved_name, str):
        ledger.stop_batch(batch, reason_code="BLOCKED_SCOPE_STATE_UNKNOWN")
        return True
    try:
        subset = build_subset_session_policy(
            batch, (row_index,), kind_registry=_VOLUME_POLICY
        )
        issued = runtime.credential_issuer.issue(
            batch, subset, kind_registry=_VOLUME_POLICY
        )
        validate_issued_batch_session(batch, subset, issued)
    except (IAMPolicyBlocked, CredentialBlocked):
        ledger.stop_batch(batch, reason_code="AWS_WRITE_BLOCKED")
        return True
    try:
        current = classify_batch_name(
            runtime.adapter.read_current(resource_arn, session=issued))
    except CredentialBlocked:
        ledger.stop_batch(batch, reason_code="AWS_WRITE_BLOCKED")
        return True
    except OSError:
        ledger.stop_batch(batch, reason_code="BLOCKED_SCOPE_STATE_UNKNOWN")
        return True
    if current.state == "UNKNOWN":
        ledger.stop_batch(batch, reason_code="BLOCKED_NAME_UNKNOWN")
        return True
    if (current.state != row.get("name_state")
            or current.name_key_present != row.get("name_key_present")
            or current.name_raw_value != row.get("name_raw_value")):
        try:
            ledger.record_batch_presend_disposition(
                authority, scope=evidence.scope, side_effects=evidence.side_effects,
                decision="SKIPPED_NAME_CHANGED", reason_code="NAME_SNAPSHOT_CHANGED",
                observed_name_sha256=_name_snapshot_hash(current),
            )
        except LedgerError as error:
            ledger.stop_batch(batch, reason_code=error.code)
            raise
        return False
    try:
        evidence = _evidence_for(batch, runtime, row)
    except LedgerError as error:
        ledger.stop_batch(batch, reason_code=error.code)
        return True
    try:
        handle = ledger.create_batch_intent(
            authority, scope=evidence.scope, side_effects=evidence.side_effects
        )
        permit = ledger.consume_first_send(handle)
    except LedgerError as error:
        ledger.stop_batch(batch, reason_code=error.code)
        raise
    try:
        runtime.adapter.write_once(
            permit.resource_arn, permit.approved_name, session=issued)
        readback = classify_batch_name(runtime.adapter.readback(permit.resource_arn, session=issued))
        outcome = (
            "APPLIED_VERIFIED"
            if readback.state == "NONEMPTY" and readback.name_raw_value == permit.approved_name
            else "OUTCOME_UNKNOWN"
        )
        name_after = readback.name_raw_value
    except Exception:  # noqa: BLE001 - a consumed permit makes every send/readback error uncertain.
        outcome = "OUTCOME_UNKNOWN"
        name_after = None
    ledger.record_readback(handle, name_after=name_after, outcome=outcome)
    return outcome == "OUTCOME_UNKNOWN"


def _advance_batch_row(
    batch: VerifiedBatchApproval,
    row_index: int,
    position: int,
    state: BatchExecutionState,
    ledger: IntentLedger,
    runtime: BatchOfflineRuntime,
    report: dict[str, JsonValue],
) -> bool:
    outcome=state.outcomes[position]
    if outcome!="UNCLAIMED":
        if outcome=="SEND_ATTEMPT_CONSUMED":
            try:
                owned=ledger.batch_intent_owned_by_current_execution(batch,row_index)
            except LedgerError:
                owned=None
            report["unresolved_send_owner"]=(
                "CURRENT_EXECUTION" if owned is True else
                "OTHER_EXECUTION" if owned is False else "UNKNOWN"
            )
            return True
        if outcome=="WRITE_INTENT_RECORDED":
            ledger.stop_batch(batch,reason_code="BLOCKED_INCOMPLETE_INTENT")
            return True
        return state.state=="STOPPED"
    if state.state=="STOPPED":
        return True
    if state.send_attempts_consumed>=state.max_send_attempts:
        reason_code=_record_cap_for_unclaimed(batch,ledger,runtime,state)
        if reason_code=="BLOCKED_OWNER_AUTHN":
            report["authentication_state"]="OWNER_AUTHN_REVOKED"
        return True
    return _execute_unclaimed_row(batch,row_index,ledger,runtime,report)


def _row_outcomes_by_index(
    batch: VerifiedBatchApproval,
    state: BatchExecutionState,
) -> dict[int,str]:
    outcomes_by_row:dict[int,str]={}
    has_unresolved_send=any(outcome=="SEND_ATTEMPT_CONSUMED" for outcome in state.outcomes)
    for position,row_index in enumerate(batch.approved_row_indexes):
        outcome=state.outcomes[position]
        if outcome=="WRITE_INTENT_RECORDED":
            outcome="NOT_ATTEMPTED_BATCH_STOP"
        elif outcome=="SEND_ATTEMPT_CONSUMED":
            outcome="OUTCOME_UNKNOWN"
        elif outcome=="UNCLAIMED":
            if state.state!="STOPPED" and not has_unresolved_send:
                raise ReportBlocked("Active Batch has an unclaimed approved row")
            outcome="NOT_ATTEMPTED_BATCH_STOP"
        outcomes_by_row[row_index]=outcome
    return outcomes_by_row


def _complete_run_result(
    report: dict[str, JsonValue],
    state: BatchExecutionState,
    outcomes_by_row: dict[int,str],
    approved_row_indexes: tuple[int,...],
) -> BatchRunResult:
    report=reconcile_batch_outcomes(report,outcomes_by_row)
    report["batch_state"]=state.state
    report["send_attempts_consumed"]=state.send_attempts_consumed
    report["max_send_attempts"]=state.max_send_attempts
    remaining=state.outcomes.count("NOT_ATTEMPTED_CAP")
    report["remaining_unattempted_cap"]=remaining
    writes_complete=bool(
        state.state=="COMPLETED" and state.outcomes
        and all(outcome=="APPLIED_VERIFIED" for outcome in state.outcomes)
    )
    report["writes_complete"]=writes_complete
    report["execution_allowed"]=False
    report["execution_mode"]="OFFLINE_FAKE_ONLY"
    return BatchRunResult(
        state.state,state.send_attempts_consumed,state.max_send_attempts,
        remaining,tuple(outcomes_by_row[index] for index in approved_row_indexes),
        writes_complete,MappingProxyType(report),
    )


def execute_batch_offline(
    batch: VerifiedBatchApproval,
    *,
    plan_bytes: bytes,
    csv_bytes: bytes,
    ledger: IntentLedger,
    runtime: BatchOfflineRuntime,
) -> BatchRunResult:
    """Execute a signed Batch against the real durable Ledger and fake-only adapter."""
    if type(batch) is not VerifiedBatchApproval or type(ledger) is not IntentLedger:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if (type(runtime) is not BatchOfflineRuntime
            or type(runtime.adapter) is not FakeBatchSDKAdapter):
        raise LedgerError("AWS_WRITE_BLOCKED")
    if (plan_bytes != batch.plan_bytes or csv_bytes != batch.csv_bytes
            or not ledger._trusted_host):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    trust = load_current_protected_owner_trust()
    now = datetime.now(timezone.utc)
    try:
        batch = revalidate_verified_batch(batch, trust=trust, now_utc=now)
    except BatchAuthRejected as error:
        raise LedgerError("BLOCKED_OWNER_AUTHN") from error

    report = make_authenticated_batch_report(
        batch, plan_bytes=plan_bytes, csv_bytes=csv_bytes, trust=trust, now_utc=now
    )
    for position, row_index in enumerate(batch.approved_row_indexes):
        state = ledger.batch_execution_state(batch)
        if _advance_batch_row(batch,row_index,position,state,ledger,runtime,report):
            break

    state = ledger.batch_execution_state(batch)
    if state.state == "ACTIVE" and all(
        outcome not in ("UNCLAIMED", "WRITE_INTENT_RECORDED", "SEND_ATTEMPT_CONSUMED")
        for outcome in state.outcomes
    ):
        ledger.complete_batch(batch)
        state = ledger.batch_execution_state(batch)
    outcomes_by_row=_row_outcomes_by_index(batch,state)
    return _complete_run_result(report,state,outcomes_by_row,batch.approved_row_indexes)
