from __future__ import annotations

# noqa: SIZE_OK — The 20 required cases share one signed Owner/ledger fixture under the two-file Task-5 scope.

import base64
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import final
from unittest.mock import patch

from name_tag_approval import (
    EnrolledOwner,
    Kind,
    NAMESPACES,
    OwnerTrust,
    VerifiedEnvelope,
    approval_digest,
    canonical_payload,
    verify_envelope,
)
from name_tag_ledger import (
    FirstSendPermit,
    IntentLedger,
    LedgerError,
    _canonical_scope_payload,
    _side_effect_digest,
    effective_scope_state,
    initialize_scope,
    open_ledger,
)
from name_tag_scope import ScopeEvidence, SideEffectEvidence
from name_tag_execution import (
    AuthorizedAwsRuntimeContext,
    ExecutionResult,
    FakeNameTagAdapter,
    NameTagAdapter,
    OfflineRuntimeContext,
    RuntimeContext,
    VerifiedRuntimePolicy,
    execute_once,
    offline_test_runtime,
)

OWNER = "owner@example.test"
ROLE = "EXECUTOR"
ARN = "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0"
OTHER_ARN = "arn:aws:ec2:us-east-1:123456789012:volume/vol-1123456789abcdef0"
OPERATION = "ec2:CreateTags:2016-11-15"


class LiveCallSentinel:
    def __init__(self) -> None:
        self.operation_id: str = OPERATION
        self.write_calls: int = 0
        self.last_resource_arn: str | None = None
        self.last_approved_name: str | None = None

    def read_tags(self, resource_arn: str) -> Mapping[str, str]:
        self.last_resource_arn = resource_arn
        return {"Name": ""}

    def write_name_only(self, resource_arn: str, approved_name: str) -> None:
        self.last_resource_arn = resource_arn
        self.last_approved_name = approved_name
        self.write_calls += 1

    def readback_tags(self, resource_arn: str) -> Mapping[str, str]:
        self.last_resource_arn = resource_arn
        return {"Name": ""}


@final
class NameTagExecutionTests(unittest.TestCase):
    temp: tempfile.TemporaryDirectory[str]
    root: Path
    key: Path
    public_key: str
    fingerprint: str
    allowed_signers: Path
    trust: OwnerTrust
    ledger: IntentLedger
    side_effect: SideEffectEvidence
    scope: ScopeEvidence

    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "owner_key"
        _ = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        public_key_fields = self.key.with_suffix(".pub").read_text(encoding="utf-8").split()
        self.public_key = " ".join(public_key_fields[:2])
        fingerprint_output = subprocess.run(
            ["ssh-keygen", "-lf", str(self.key.with_suffix(".pub")), "-E", "sha256"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.fingerprint = fingerprint_output.split()[1]
        self.allowed_signers = self.root / "allowed_signers"
        namespaces = ",".join((NAMESPACES["name"], NAMESPACES["execution"], "aws-cost-name-tagger-scope-decision-v1"))
        allowed_signer_line = f'{OWNER} namespaces="{namespaces}" {self.public_key}\n'
        _ = self.allowed_signers.write_text(allowed_signer_line, encoding="utf-8")
        self.allowed_signers.chmod(0o600)
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed_signers,
            pinned_sha256=hashlib.sha256(self.allowed_signers.read_bytes()).hexdigest(),
            enrolled={OWNER: {self.fingerprint: EnrolledOwner(self.fingerprint, ROLE)}},
        )
        self.ledger = open_ledger(self.root / "ledger.db", trusted_host=True)
        self.addCleanup(self.ledger.close)
        object.__setattr__(self.ledger, "_trust", self.trust)
        self.side_effect = self._side_effect()
        self.scope = ScopeEvidence(
            account="123456789012",
            partition="aws",
            region="us-east-1",
            writer_control_scope_id="scope-1",
            controlled_arns=frozenset({ARN}),
            not_before_utc=self.now - timedelta(hours=1),
            not_after_utc=self.now + timedelta(hours=1),
            writer_evidence_digest="a" * 64,
            responsible_owner=OWNER,
        )
        self._initialize_scope()

    @property
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _sign(self, message: bytes, namespace: str) -> bytes:
        message_path = self.root / f"message-{hashlib.sha256(message).hexdigest()}"
        _ = message_path.write_bytes(message)
        _ = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace, str(message_path)],
            check=True,
            capture_output=True,
        )
        signature_path = message_path.with_suffix(message_path.suffix + ".sig")
        signature = signature_path.read_bytes()
        signature_path.unlink()
        message_path.unlink()
        return signature

    def _signed_envelope(self, kind: Kind, payload: dict[str, object]) -> VerifiedEnvelope:
        canonical = canonical_payload(payload, kind=kind)
        signature = self._sign(canonical, NAMESPACES[kind])
        id_field = "approval_id" if kind == "name" else "authorization_id"
        envelope = {
            "payload": payload,
            id_field: approval_digest(canonical),
            "signature_ref": base64.b64encode(signature).decode("ascii"),
        }
        raw = json.dumps(envelope, separators=(",", ":")).encode()
        return verify_envelope(raw, kind=kind, trust=self.trust, now_utc=self.now)

    def _name_payload(self, *, approved_name: str = "web-prod", resource_arn: str = ARN) -> dict[str, object]:
        now = self.now
        return {
            "schema_version": 1,
            "approval_namespace": NAMESPACES["name"],
            "plan_sha256": "b" * 64,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "kind": "volume",
            "resource_arn": resource_arn,
            "locator": resource_arn.rsplit("/", 1)[-1],
            "name_state_at_plan": "ABSENT",
            "confidence": "high",
            "evidence_digest": "c" * 64,
            "suggested_name": approved_name,
            "approved_name": approved_name,
            "edit_reason": "",
            "decision": "APPROVED",
            "owner_decision_reference": "owner-review",
            "owner_principal_id": OWNER,
            "owner_key_fingerprint": self.fingerprint,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
            "decision_nonce": "name-nonce-1",
        }

    def _execution_payload(
        self,
        name_approval: VerifiedEnvelope,
        *,
        approved_name: str = "web-prod",
        resource_arn: str = ARN,
        aws_operation: str = OPERATION,
    ) -> dict[str, object]:
        now = self.now
        return {
            "schema_version": 1,
            "authorization_namespace": NAMESPACES["execution"],
            "name_approval_id": name_approval.content_id,
            "resource_arn": resource_arn,
            "approved_name": approved_name,
            "aws_operation": aws_operation,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "identity": "arn:aws:sts::123456789012:assumed-role/executor/session",
            "code_version": "test",
            "code_hash": "d" * 64,
            "writer_control_scope_id": "scope-1",
            "risk_acknowledgement": "test-owner-approved",
            "writer_control_evidence_refs": ["writer-evidence"],
            "side_effect_evidence_refs": ["iam", "iac", "events"],
            "owner_principal_id": OWNER,
            "owner_key_fingerprint": self.fingerprint,
            "allowed_role": ROLE,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
            "execution_nonce": "execution-nonce-1",
        }

    def _side_effect(self, arn: str = ARN) -> SideEffectEvidence:
        now = self.now
        return SideEffectEvidence(
            target_arn=arn,
            iam_abac_resource_tag_assessment="PASS",
            iac_assessment="PASS",
            event_automation_assessment="PASS",
            evidence_references=("iam", "iac", "events"),
            not_before_utc=now - timedelta(hours=1),
            not_after_utc=now + timedelta(hours=1),
        )

    def _initialize_scope(self) -> None:
        now = self.now
        side_effects = [self.side_effect]
        payload: dict[str, object] = {
            "schema_version": 1,
            "decision_namespace": "aws-cost-name-tagger-scope-decision-v1",
            "action": "INITIALIZE",
            "scope_id": "scope-1",
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "target_arns": [ARN],
            "writer_evidence_digest": "a" * 64,
            "side_effect_evidence_digest": _side_effect_digest(side_effects),
            "host_binding": self.ledger._host_binding,
            "owner_principal_id": OWNER,
            "owner_key_fingerprint": self.fingerprint,
            "allowed_role": ROLE,
            "issued_at_utc": now.isoformat(),
            "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
            "decision_nonce": "scope-nonce-1",
            "reason": "offline execution fixture",
        }
        canonical = _canonical_scope_payload(payload)
        envelope = {
            "payload": payload,
            "decision_id": approval_digest(canonical),
            "signature_ref": base64.b64encode(
                self._sign(canonical, "aws-cost-name-tagger-scope-decision-v1")
            ).decode("ascii"),
        }
        initialize_scope(self.ledger, envelope, action="INITIALIZE", scope=self.scope, side_effects=side_effects)

    def _signed_pair(
        self,
        *,
        approved_name: str = "web-prod",
        resource_arn: str = ARN,
        aws_operation: str = OPERATION,
    ) -> tuple[VerifiedEnvelope, VerifiedEnvelope]:
        name = self._signed_envelope("name", self._name_payload(approved_name=approved_name, resource_arn=resource_arn))
        execution = self._signed_envelope(
            "execution",
            self._execution_payload(name, approved_name=approved_name, resource_arn=resource_arn, aws_operation=aws_operation),
        )
        return name, execution

    def _offline(self, adapter: FakeNameTagAdapter) -> OfflineRuntimeContext:
        return offline_test_runtime(adapter)

    def _run(
        self,
        name_approval: VerifiedEnvelope | None = None,
        authorization: VerifiedEnvelope | None = None,
        *,
        adapter: NameTagAdapter | None = None,
        runtime: RuntimeContext | None = None,
    ) -> ExecutionResult:
        if name_approval is None or authorization is None:
            name_approval, authorization = self._signed_pair()
        if adapter is None:
            fake_adapter = FakeNameTagAdapter({"Product": "service"})
            actual_adapter: NameTagAdapter = fake_adapter
            actual_runtime = runtime or self._offline(fake_adapter)
        else:
            actual_adapter = adapter
            if runtime is None:
                raise AssertionError("explicit adapter requires explicit runtime fixture")
            actual_runtime = runtime
        return execute_once(
            name_approval,
            authorization,
            scope=self.scope,
            side_effects=self.side_effect,
            ledger=self.ledger,
            adapter=actual_adapter,
            runtime=actual_runtime,
        )

    def _intent_count(self) -> int:
        with closing(sqlite3.connect(str(self.ledger._path))) as conn, conn:
            return int(conn.execute("SELECT COUNT(*) FROM intents").fetchone()[0])

    def test_mock_first_send_then_readback_verified(self):
        adapter = FakeNameTagAdapter({"Product": "service"})
        name, execution = self._signed_pair()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "APPLIED_VERIFIED")
        self.assertEqual(adapter.write_calls, 1)
        self.assertEqual(adapter.tags, {"Product": "service", "Name": "web-prod"})

    def test_invalid_runtime_context_blocks_before_intent(self):
        adapter = FakeNameTagAdapter()
        other_adapter = FakeNameTagAdapter()
        result = self._run(adapter=adapter, runtime=self._offline(other_adapter))
        self.assertEqual(result.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)
        forged_runtime = self._offline(adapter)
        object.__setattr__(forged_runtime, "mode", "authorized_aws")
        object.__setattr__(forged_runtime, "source", "cli")
        result = self._run(adapter=adapter, runtime=forged_runtime)
        self.assertEqual(result.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_offline_stub_cannot_reach_live_sdk(self):
        fake = FakeNameTagAdapter()
        live = LiveCallSentinel()
        result = self._run(adapter=live, runtime=self._offline(fake))
        self.assertEqual(result.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(live.write_calls, 0)
        self.assertEqual(self._intent_count(), 0)

    def test_missing_trust_never_creates_intent(self):
        name, execution = self._signed_pair()
        object.__setattr__(self.ledger, "_trust", None)
        adapter = FakeNameTagAdapter()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_real_runtime_unconditionally_blocked(self):
        name, execution = self._signed_pair()
        adapter = FakeNameTagAdapter()
        policy = VerifiedRuntimePolicy("policy", OPERATION, "scope-1", ARN, "web-prod")
        runtime = AuthorizedAwsRuntimeContext("authorized_aws", policy, execution.content_id)
        result = self._run(name, execution, adapter=adapter, runtime=runtime)
        self.assertEqual(result.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_unauthorized_name_or_arn_blocks(self):
        changed_name = self._signed_envelope("name", self._name_payload(approved_name="other-name"))
        mismatched_execution = self._signed_envelope(
            "execution", self._execution_payload(changed_name, approved_name="web-prod")
        )
        result = self._run(changed_name, mismatched_execution)
        self.assertEqual(result.code, "BLOCKED_OWNER_AUTHN")
        other_name, other_execution = self._signed_pair(resource_arn=OTHER_ARN)
        result = self._run(other_name, other_execution)
        self.assertEqual(result.code, "BLOCKED_SCOPE_MISMATCH")
        self.assertEqual(self._intent_count(), 0)

    def test_side_effect_evidence_mismatch_blocks_before_intent(self):
        name = self._signed_envelope("name", self._name_payload())
        payload = self._execution_payload(name)
        payload["side_effect_evidence_refs"] = ["other-evidence"]
        execution = self._signed_envelope("execution", payload)
        adapter = FakeNameTagAdapter()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_SIDE_EFFECT_UNASSESSED")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_nonempty_or_unknown_blocks(self):
        for tags, expected in (({"Name": "existing"}, "BLOCKED_NAME_NONEMPTY"),
                               ({"NAME": "ambiguous"}, "BLOCKED_NAME_UNKNOWN")):
            with self.subTest(tags=tags):
                adapter = FakeNameTagAdapter(tags)
                result = self._run(adapter=adapter, runtime=self._offline(adapter))
                self.assertEqual(result.code, expected)
                self.assertEqual(adapter.write_calls, 0)
        self.assertEqual(self._intent_count(), 0)

    def test_mismatch_holds_scope(self):
        adapter = FakeNameTagAdapter()
        adapter.readback_override = {"Name": "wrong-name"}
        result = self._run(adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "FAILED_READBACK")
        self.assertEqual(effective_scope_state(self.ledger, "scope-1"), "HOLD")
        self.assertEqual(adapter.write_calls, 1)

    def test_timeout_never_retries(self):
        name, execution = self._signed_pair()
        adapter = FakeNameTagAdapter()
        adapter.write_error = TimeoutError("offline fake timeout")
        runtime = self._offline(adapter)
        first = self._run(name, execution, adapter=adapter, runtime=runtime)
        second = self._run(name, execution, adapter=adapter, runtime=runtime)
        self.assertEqual(first.code, "OUTCOME_UNKNOWN")
        self.assertEqual(second.code, "BLOCKED_SCOPE_HOLD")
        self.assertEqual(adapter.write_calls, 1)

    def test_failed_hold_persistence_blocks_host(self):
        adapter = FakeNameTagAdapter()
        adapter.readback_override = {"Name": "different"}
        with patch("name_tag_execution.record_readback", side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")):
            result = self._run(adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(adapter.write_calls, 1)

    def test_old_intent_never_retries(self):
        name, execution = self._signed_pair()
        adapter = FakeNameTagAdapter()
        runtime = self._offline(adapter)
        first = self._run(name, execution, adapter=adapter, runtime=runtime)
        second_adapter = FakeNameTagAdapter()
        second = self._run(
            name,
            execution,
            adapter=second_adapter,
            runtime=self._offline(second_adapter),
        )
        self.assertEqual(first.code, "APPLIED_VERIFIED")
        self.assertEqual(second.code, "BLOCKED_INTENT_REPLAY")
        self.assertEqual(adapter.write_calls, 1)
        self.assertEqual(second_adapter.write_calls, 0)

    def test_direct_production_adapter_write_blocked(self):
        adapter = LiveCallSentinel()
        policy = VerifiedRuntimePolicy("policy", OPERATION, "scope-1", ARN, "web-prod")
        runtime = AuthorizedAwsRuntimeContext("authorized_aws", policy, "execution-binding")
        result = self._run(adapter=adapter, runtime=runtime)
        self.assertEqual(result.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(adapter.write_calls, 0)
        self.assertEqual(self._intent_count(), 0)

    def test_unconsumed_or_mismatched_first_send_permit_denied(self):
        adapter = FakeNameTagAdapter()
        wrong = FirstSendPermit("wrong-id", ARN, "web-prod", "scope-1", OPERATION, "exec", "token")
        with patch("name_tag_execution.consume_first_send", return_value=wrong):
            result = self._run(adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_INTENT_REPLAY")
        self.assertEqual(adapter.write_calls, 0)

    def test_operation_mismatch_rejected_before_intent(self):
        name, execution = self._signed_pair(aws_operation="ec2:DeleteTags:2016-11-15")
        adapter = FakeNameTagAdapter()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "WRITE_UNSUPPORTED")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_permit_other_aws_api_rejected(self):
        name, execution = self._signed_pair()
        adapter = FakeNameTagAdapter()
        wrong = FirstSendPermit(execution.content_id, ARN, "web-prod", "scope-1", "ec2:DeleteTags:2016-11-15", "exec", "token")
        with patch("name_tag_execution.consume_first_send", return_value=wrong):
            result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_INTENT_REPLAY")
        self.assertEqual(adapter.write_calls, 0)

    def test_phase_a_operation_mismatch_zero_real_sdk_calls(self):
        name, execution = self._signed_pair(aws_operation="ec2:DeleteTags:2016-11-15")
        adapter = FakeNameTagAdapter()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "WRITE_UNSUPPORTED")
        self.assertEqual(adapter.write_calls, 0)
        self.assertEqual(self._intent_count(), 0)

    def test_mutated_verified_payload_blocks_before_intent(self):
        name, execution = self._signed_pair()
        object.__setattr__(execution, "raw_envelope_bytes", b"{}")
        adapter = FakeNameTagAdapter()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_forged_verified_envelope_has_zero_mutations(self):
        name, execution = self._signed_pair()
        forged = replace(execution, content_id="0" * 64)
        adapter = FakeNameTagAdapter()
        result = self._run(name, forged, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self._intent_count(), 0)
        self.assertEqual(adapter.write_calls, 0)

    def test_changed_signed_aws_operation_rejected(self):
        name, execution = self._signed_pair(aws_operation="ec2:DeleteTags:2016-11-15")
        adapter = FakeNameTagAdapter()
        result = self._run(name, execution, adapter=adapter, runtime=self._offline(adapter))
        self.assertEqual(result.code, "WRITE_UNSUPPORTED")
        self.assertEqual(self._intent_count(), 0)

    def test_phase_a_invalid_envelope_zero_live_sdk_calls(self):
        name, execution = self._signed_pair()
        forged = replace(execution, content_id="0" * 64)
        fake = FakeNameTagAdapter()
        live = LiveCallSentinel()
        result = self._run(name, forged, adapter=live, runtime=self._offline(fake))
        self.assertEqual(result.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(live.write_calls, 0)
        self.assertEqual(self._intent_count(), 0)
