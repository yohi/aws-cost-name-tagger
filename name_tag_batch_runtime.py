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


# ---------------------------------------------------------------------------
# Task 7: Host-only protected dispatch over the same single Ledger (RG-PRC-004/005/008).
# ``execute_batch_offline`` above is unchanged and never reaches this path.
# ---------------------------------------------------------------------------
LIVE_EXECUTION_MODE: Final = "HOST_PROTECTED_DISPATCH"
_UNRESOLVED_INTENT: Final = "UNRESOLVED_WRITE_INTENT"
_REPORT_SCHEMA: Final = "aws-cnt-host-batch-report-v1"


class _LiveRefusal(Exception):
    """Internal: a pre-send refusal already durably handled (zero send for this row)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if isinstance(code, str) and re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,63}", code) else "AWS_RUNTIME_NOT_AUTHORIZED"


def _blocked_live(code: str, detail: str = "", **identity):
    from name_tag_batch_host_runtime import HostRuntimeBlocked
    return HostRuntimeBlocked(code, detail, **identity)


def _live_now(runtime) -> datetime:
    from name_tag_batch_host_runtime import require_aware_utc
    return require_aware_utc(runtime.clock())


def _durable_stop_and_hold(ledger: IntentLedger, batch, code: str,
                           scope_id: str | None) -> None:
    """STOP the Batch (and HOLD the Scope when given); failure to persist blocks the Host."""
    stopped = held = True
    try:
        ledger.stop_batch(batch, reason_code=code)
    except Exception:  # noqa: BLE001 - durability doubt blocks the Host
        stopped = False
    if scope_id is not None:
        try:
            ledger.hold_scope(scope_id, reason=f"host_unresolved:{code}")
        except Exception:  # noqa: BLE001
            held = False
    if not (stopped and held):
        raise _blocked_live("BLOCKED_SCOPE_STATE_UNKNOWN", "durable STOP/HOLD failed")


def _refuse_before_intent(ledger, batch, state: BatchExecutionState, code: str):
    """Window A: zero new Intent/Permit/write. An ACTIVE Batch is durably STOPPED."""
    if state.state == "ACTIVE":
        _durable_stop_and_hold(ledger, batch, code, None)
    raise _LiveRefusal(code)


def _finalize_unsent_intent(ledger, batch, handle, code: str, scope_id: str):
    """Window B: Intent exists, Permit not consumed -> atomic no-send finalizer, else
    an unresolved Intent with STOP/HOLD (never OUTCOME_UNKNOWN, never a replay)."""
    try:
        ledger._host_finalize_unsent_batch_intent(handle, reason_code=code, sdk_dispatches=0)
    except LedgerError:
        _durable_stop_and_hold(ledger, batch, code, scope_id)
    raise _LiveRefusal(code)


def _recheck_before_permit(runtime, issued, authority, vscope, deny, adapter_kind: str):
    """Revalidate every protected gate immediately before the durable consume_first_send."""
    from name_tag_batch_host_issuer import require_issued_session
    from name_tag_batch_host_runtime import require_verified_host
    from name_tag_batch_live import live_dispatch_adapter

    now = _live_now(runtime)
    host = require_verified_host(runtime.host)
    try:
        current = derive_batch_row_authority(
            authority.batch, authority.row_index,
            trust=load_current_protected_owner_trust(), now_utc=now)
    except BatchAuthRejected as error:
        raise _blocked_live("BLOCKED_OWNER_AUTHN", "Owner revoked/expired before Permit") from error
    if current.row_authority_id != authority.row_authority_id:
        raise _blocked_live("BLOCKED_OWNER_AUTHN", "row authority changed before Permit")
    require_issued_session(issued, host, now)
    if not (now < deny.expires_at_utc and now < vscope.not_after_utc):
        raise _blocked_live("G2_NOT_VERIFIED", "evidence expired before Permit")
    live_dispatch_adapter(adapter_kind)


def _live_record_cap(batch, ledger, runtime, state: BatchExecutionState) -> None:
    """Signed cap consumed: only the existing NOT_ATTEMPTED_CAP handling; no STS/Permit."""
    import name_tag_kind_capabilities as caps

    now = _live_now(runtime)
    for position, row_index in enumerate(batch.approved_row_indexes):
        if state.outcomes[position] != "UNCLAIMED":
            continue
        try:
            authority = derive_batch_row_authority(
                batch, row_index, trust=load_current_protected_owner_trust(), now_utc=now)
        except BatchAuthRejected:
            _durable_stop_and_hold(ledger, batch, "BLOCKED_OWNER_AUTHN", None)
            raise _LiveRefusal("BLOCKED_OWNER_AUTHN") from None
        row = authority.row
        try:
            target = caps.canonical_target_identity(
                kind=row["kind"], locator=row["locator"], resource_arn=row["resource_arn"],
                partition=batch.payload["partition"], account=batch.payload["account"],
                scope_region=row["region"])
            vscope = runtime.scope_verifier.resolve(
                row["writer_control_scope_id"], target, runtime.host, now)
            ledger.record_batch_presend_disposition(
                authority, scope=vscope.scope, side_effects=vscope.all_side_effects,
                decision="NOT_ATTEMPTED_CAP", reason_code="SIGNED_CAP_REACHED")
        except Exception as error:  # noqa: BLE001 - any doubt stops before a disposition
            code = getattr(error, "code", "BLOCKED_SCOPE_STATE_UNKNOWN")
            _durable_stop_and_hold(ledger, batch, code, None)
            raise _LiveRefusal(code) from None


def _execute_live_row(batch, row_index: int, ledger, runtime, state: BatchExecutionState,
                      report: dict[str, JsonValue]) -> bool:
    """One signed row through the single Coordinator; return true when the Batch stops."""
    from name_tag_batch_host_issuer import revalidate_issued_before_intent
    from name_tag_batch_host_runtime import (
        HostRuntimeBlocked, peek_selection, select_next_sts_subset)
    from name_tag_batch_live import AuthorizedBatchWritePort, live_dispatch_adapter

    host = runtime.host
    now = _live_now(runtime)
    # ---- refusal window A: everything up to and including create_batch_intent.
    try:
        spec = select_next_sts_subset(batch, ledger=ledger, kind_registry=runtime.kind_registry,
                                      host=host, now_utc=now)
        selection = peek_selection(spec, host)
        if selection.row_authority.row_index != row_index:
            raise HostRuntimeBlocked("BLOCKED_INCOMPLETE_INTENT", "wrong selected row index")
        issued = runtime.issuer.issue(batch, spec, host, now)
        authority = revalidate_issued_before_intent(issued, ledger=ledger, host=host,
                                                    now_utc=now)
        kind = authority.row["kind"]
        capability = selection.capability
        adapter = live_dispatch_adapter(kind)
        vscope = runtime.scope_verifier.resolve(selection.scope_id, selection.target, host, now)
        client = issued.sdk_client(capability.service, authority.row["region"], now_utc=now)
        current = classify_batch_name_observation(adapter.read_current(client, vscope.target))
    except _LiveRefusal:
        raise
    except Exception as error:  # noqa: BLE001 - every pre-Intent doubt refuses (zero send)
        _refuse_before_intent(ledger, batch, state, getattr(error, "code",
                                                            "BLOCKED_SCOPE_STATE_UNKNOWN"))
    row = authority.row
    if current.state == "UNKNOWN":
        _refuse_before_intent(ledger, batch, state, "BLOCKED_NAME_UNKNOWN")
    if (current.state != row.get("name_state")
            or current.name_key_present != row.get("name_key_present")
            or current.name_raw_value != row.get("name_raw_value")):
        try:
            ledger.record_batch_presend_disposition(
                authority, scope=vscope.scope, side_effects=vscope.all_side_effects,
                decision="SKIPPED_NAME_CHANGED", reason_code="NAME_SNAPSHOT_CHANGED",
                observed_name_sha256=_name_snapshot_hash(current))
        except LedgerError as error:
            _refuse_before_intent(ledger, batch, state, error.code)
        return False
    try:
        evidence = runtime.iam_evidence_source(issued, authority, vscope)
        deny = runtime.iam_verifier.verify(issued, authority, capability, vscope, evidence)
        handle = ledger.create_batch_intent(authority, scope=vscope.scope,
                                            side_effects=vscope.all_side_effects)
    except Exception as error:  # noqa: BLE001 - nothing was committed by the Ledger
        _refuse_before_intent(ledger, batch, state, getattr(error, "code", "G2_NOT_VERIFIED"))
    # ---- refusal window B: Intent recorded, Permit not yet consumed.
    try:
        _recheck_before_permit(runtime, issued, authority, vscope, deny, kind)
        permit = ledger.consume_first_send(handle)
    except Exception as error:  # noqa: BLE001 - the finalizer re-proves zero send
        _finalize_unsent_intent(ledger, batch, handle,
                                getattr(error, "code", "BLOCKED_SCOPE_STATE_UNKNOWN"),
                                vscope.scope_id)
    # ---- after Permit: exactly one send + same-credential Readback, durable disposition.
    outcome, name_after = "OUTCOME_UNKNOWN", None
    try:
        grant = runtime.runtime_verifier.authorize_once(authority, issued, vscope, deny, permit)
        port = AuthorizedBatchWritePort(client, adapter=adapter, target=vscope.target,
                                        clock=runtime.clock)
        port.write_once(session=issued, row=authority, permit=permit, runtime=grant)
        readback = classify_batch_name_observation(adapter.readback(client, vscope.target))
        name_after = readback.name_raw_value
        if readback.state == "NONEMPTY" and readback.name_raw_value == permit.approved_name:
            outcome = "APPLIED_VERIFIED"
    except Exception:  # noqa: BLE001 - a consumed Permit makes every error uncertain
        outcome, name_after = "OUTCOME_UNKNOWN", None
    try:
        ledger.record_readback(handle, name_after=name_after, outcome=outcome)
    except Exception:  # noqa: BLE001 - missing durable disposition: STOP/HOLD, no replay
        report["durable_readback_missing"] = True
        _durable_stop_and_hold(ledger, batch, "OUTCOME_UNKNOWN", vscope.scope_id)
        return True
    return outcome != "APPLIED_VERIFIED"


def classify_batch_name_observation(observation):
    """Adapters already return a classified NameObservation; reject anything else."""
    from name_tag_batch_state import NameObservation

    if type(observation) is not NameObservation:
        raise LedgerError("BLOCKED_NAME_UNKNOWN")
    return observation


def _advance_live_row(batch, row_index, position, state, ledger, runtime, report) -> bool:
    outcome = state.outcomes[position]
    if outcome != "UNCLAIMED":
        if outcome == "SEND_ATTEMPT_CONSUMED":
            try:
                owned = ledger.batch_intent_owned_by_current_execution(batch, row_index)
            except LedgerError:
                owned = None
            report["unresolved_send_owner"] = (
                "CURRENT_EXECUTION" if owned is True else
                "OTHER_EXECUTION" if owned is False else "UNKNOWN")
            return True
        if outcome == "WRITE_INTENT_RECORDED":
            ledger.stop_batch(batch, reason_code="BLOCKED_INCOMPLETE_INTENT")
            return True
        return state.state == "STOPPED"
    if state.state not in ("ACTIVE", "UNREGISTERED"):
        return True
    if state.send_attempts_consumed >= state.max_send_attempts:
        _live_record_cap(batch, ledger, runtime, state)
        return True
    return _execute_live_row(batch, row_index, ledger, runtime, state, report)


def _report_digest(report: Mapping[str, JsonValue]) -> tuple[str, bytes]:
    from name_tag_batch_approval import canonical_bytes

    body = canonical_bytes({k: v for k, v in report.items() if k != "report_sha256"})
    return sha256(b"aws-cnt-host-batch-report-v1\x00" + body).hexdigest(), body


def _persist_host_report(host, batch_id: str, report: Mapping[str, JsonValue]) -> str | None:
    """Protected durable report in the verified StateDirectory; None when unverifiable."""
    import os
    import stat as stat_module
    from pathlib import Path

    try:
        digest, body = _report_digest(report)
        root = Path(host.state_directory) / "batch-reports"
        batch_dir = root / batch_id
        for directory in (root, batch_dir):
            try:
                os.mkdir(directory, 0o700)
            except FileExistsError:
                pass
            info = os.lstat(directory)
            if (not stat_module.S_ISDIR(info.st_mode) or info.st_uid != host.service_uid
                    or info.st_mode & 0o077):
                return None
        path = batch_dir / f"{digest}.json"
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600)
        except FileExistsError:
            fd = None
        if fd is not None:
            try:
                view = memoryview(body)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            dir_fd = os.open(batch_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        read_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(read_fd)
            stored = os.read(read_fd, len(body) + 1)
        finally:
            os.close(read_fd)
        if (stored != body or info.st_uid != host.service_uid or info.st_mode & 0o077
                or sha256(b"aws-cnt-host-batch-report-v1\x00" + stored).hexdigest() != digest):
            return None
        return digest
    except (OSError, TypeError, ValueError):
        return None


def _complete_live_result(report, state, batch, refusal_code: str | None) -> BatchRunResult:
    """RG-PRC-008: authoritative report from the single Ledger; unresolved rows stay unresolved."""
    unresolved = [index for position, index in enumerate(batch.approved_row_indexes)
                  if state.outcomes[position] == "WRITE_INTENT_RECORDED"]
    truthful = tuple(
        _UNRESOLVED_INTENT if outcome == "WRITE_INTENT_RECORDED"
        else "OUTCOME_UNKNOWN" if outcome == "SEND_ATTEMPT_CONSUMED"
        else outcome for outcome in state.outcomes)
    if unresolved:
        report = dict(report)
        report["outcome_reconciliation"] = "UNRESOLVED"
        report["batch_state"] = state.state
        report["send_attempts_consumed"] = state.send_attempts_consumed
        report["max_send_attempts"] = state.max_send_attempts
        report["remaining_unattempted_cap"] = state.outcomes.count("NOT_ATTEMPTED_CAP")
        report["writes_complete"] = False
        report["execution_allowed"] = False
        result = BatchRunResult(state.state, state.send_attempts_consumed,
                                state.max_send_attempts,
                                state.outcomes.count("NOT_ATTEMPTED_CAP"), truthful, False,
                                MappingProxyType(report))
    else:
        result = _complete_run_result(report, state, _row_outcomes_by_index(batch, state),
                                      batch.approved_row_indexes)
    final = dict(result.report)
    final.update({
        "schema": _REPORT_SCHEMA, "batch_id": batch.batch_id,
        "execution_mode": LIVE_EXECUTION_MODE, "live_status": "NOT_VERIFIED",
        "row_ledger_outcomes": [[index, outcome] for index, outcome
                                in zip(batch.approved_row_indexes, truthful)],
        "unresolved_rows": unresolved,
        "applied_verified_count": state.outcomes.count("APPLIED_VERIFIED"),
        "refusal_code": refusal_code,
    })
    return BatchRunResult(result.batch_state, result.send_attempts_consumed,
                          result.max_send_attempts, result.remaining_unattempted_cap,
                          truthful, result.writes_complete, MappingProxyType(final))


def _run_live(batch: VerifiedBatchApproval, ledger: IntentLedger, runtime) -> BatchRunResult:
    now = _live_now(runtime)
    trust = load_current_protected_owner_trust()
    try:
        fresh = revalidate_verified_batch(batch, trust=trust, now_utc=now)
    except BatchAuthRejected as error:
        raise _blocked_live("BLOCKED_OWNER_AUTHN", "Owner verification failed") from error
    report = make_authenticated_batch_report(
        fresh, plan_bytes=fresh.plan_bytes, csv_bytes=fresh.csv_bytes, trust=trust, now_utc=now)
    refusal: str | None = None
    for position, row_index in enumerate(fresh.approved_row_indexes):
        state = ledger.batch_execution_state(fresh)
        try:
            if _advance_live_row(fresh, row_index, position, state, ledger, runtime, report):
                break
        except _LiveRefusal as stop:
            refusal = stop.code
            break
    state = ledger.batch_execution_state(fresh)
    if state.state == "UNREGISTERED":  # nothing durable happened for this Batch
        raise _blocked_live(refusal or "BLOCKED_SCOPE_STATE_UNKNOWN", "no Batch registration")
    if refusal is None and state.state == "ACTIVE" and all(
            outcome not in ("UNCLAIMED", "WRITE_INTENT_RECORDED", "SEND_ATTEMPT_CONSUMED")
            for outcome in state.outcomes):
        ledger.complete_batch(fresh)
        state = ledger.batch_execution_state(fresh)
    result = _complete_live_result(report, state, fresh, refusal)
    digest = _persist_host_report(runtime.host, fresh.batch_id, result.report)
    if refusal is not None:
        raise _blocked_live(refusal, "pre-send refusal; durable partial report",
                            batch_id=fresh.batch_id, report_sha256=digest)
    if digest is None:
        return result  # no report_sha256: the IPC mapping cannot claim COMPLETE
    final = dict(result.report)
    final["report_sha256"] = digest
    return BatchRunResult(result.batch_state, result.send_attempts_consumed,
                          result.max_send_attempts, result.remaining_unattempted_cap,
                          result.outcomes, result.writes_complete, MappingProxyType(final))


def execute_batch_live(batch: VerifiedBatchApproval, ledger: IntentLedger,
                       runtime) -> BatchRunResult:
    """Host-only protected dispatch; a distinct API that never replaces the Offline API."""
    from name_tag_batch_host_runtime import (
        HostRuntimeBlocked, bound_ledger, clear_selections, require_verified_host_runtime)

    verified = require_verified_host_runtime(runtime)
    if (type(batch) is not VerifiedBatchApproval or type(ledger) is not IntentLedger
            or ledger is not bound_ledger(verified.host) or not ledger._trusted_host):
        raise _blocked_live("BLOCKED_SCOPE_STATE_UNKNOWN", "not the Host-bound Ledger")
    try:
        return _run_live(batch, ledger, verified)
    except HostRuntimeBlocked:
        raise
    except LedgerError as error:
        raise _blocked_live(error.code, "Ledger refused the command") from error
    finally:
        clear_selections(verified.host)


class HostLedgerBatchCoordinator:
    """The single Coordinator behind ProtectedBatchHostEndpoint (HostBatchCoordinator).

    ``runtime_factory(host, issuer)`` opens the explicit-opt-in VerifiedHostRuntime for the
    freshly re-verified Host context of each accepted command; it must bind exactly that
    Host and issuer. The production endpoint wires no Coordinator in this phase.
    """

    def __init__(self, *, runtime_factory) -> None:
        if not callable(runtime_factory):
            raise _blocked_live("AWS_RUNTIME_NOT_AUTHORIZED", "no protected runtime factory")
        self._runtime_factory = runtime_factory

    def run_signed_batch(self, batch, *, host, issuer, now_utc):
        from name_tag_batch_host_runtime import (
            bound_ledger, require_aware_utc, require_verified_host,
            require_verified_host_runtime)

        host = require_verified_host(host)
        require_aware_utc(now_utc)
        runtime = require_verified_host_runtime(self._runtime_factory(host, issuer))
        if runtime.host is not host or runtime.issuer is not issuer:
            raise _blocked_live("AWS_RUNTIME_NOT_AUTHORIZED", "foreign Host/issuer")
        return execute_batch_live(batch, bound_ledger(host), runtime)
