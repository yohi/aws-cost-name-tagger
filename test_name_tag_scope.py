from datetime import datetime, timedelta, timezone
from types import MappingProxyType
import unittest

from name_tag_approval import Kind, VerifiedEnvelope, approval_digest, canonical_payload
from name_tag_scope import (
    ScopeEvidence,
    SideEffectEvidence,
    check_target_safety,
)


NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-12345678"


def make_approval(*, kind: Kind = "name", account: str = "123456789012", resource_arn: str = ARN) -> VerifiedEnvelope:
    payload: dict[str, str | int] = {
        "schema_version": 1,
        "approval_namespace": "aws-cost-name-tagger-name-approval-v1",
        "plan_sha256": "a" * 64,
        "account": account,
        "partition": "aws",
        "region": "us-east-1",
        "kind": "instance",
        "resource_arn": resource_arn,
        "locator": "i-12345678",
        "name_state_at_plan": "ABSENT",
        "confidence": "high",
        "evidence_digest": "b" * 64,
        "suggested_name": "example",
        "approved_name": "example",
        "edit_reason": "",
        "decision": "approve",
        "owner_decision_reference": "owner-ref",
        "owner_principal_id": "owner@example",
        "owner_key_fingerprint": "SHA256:test",
        "issued_at_utc": "2026-11-16T11:00:00Z",
        "expires_at_utc": "2026-11-16T13:00:00Z",
        "decision_nonce": "nonce",
    }
    canonical = canonical_payload(payload, kind="name")
    return VerifiedEnvelope(
        kind=kind,
        raw_envelope_bytes=b"verified fixture",
        canonical_payload_bytes=canonical,
        content_id=approval_digest(canonical),
        payload=MappingProxyType(payload),
        owner_principal_id="owner@example",
        signature_ref="fixture-signature",
    )


def make_scope(*, not_before: datetime = NOW - timedelta(hours=1), not_after: datetime = NOW + timedelta(hours=1), evidence_digest: str = "c" * 64) -> ScopeEvidence:
    return ScopeEvidence(
        account="123456789012",
        partition="aws",
        region="us-east-1",
        writer_control_scope_id="scope-1",
        controlled_arns=frozenset({ARN}),
        not_before_utc=not_before,
        not_after_utc=not_after,
        writer_evidence_digest=evidence_digest,
        responsible_owner="owner@example",
    )


def make_side_effects(*, iam: str = "PASS", iac: str = "PASS", event: str = "PASS", not_before: datetime = NOW - timedelta(hours=1), not_after: datetime = NOW + timedelta(hours=1)) -> SideEffectEvidence:
    return SideEffectEvidence(
        target_arn=ARN,
        iam_abac_resource_tag_assessment=iam,
        iac_assessment=iac,
        event_automation_assessment=event,
        evidence_references=("evidence://iam", "evidence://iac", "evidence://events"),
        not_before_utc=not_before,
        not_after_utc=not_after,
    )


class ScopeGuardTests(unittest.TestCase):

    def test_writer_unknown_blocks(self) -> None:
        result = check_target_safety(
            approval=make_approval(),
            scope=make_scope(evidence_digest=""),
            side_effects=make_side_effects(),
            now_utc=NOW,
        )
        self.assertEqual((result.allowed, result.code), (False, "BLOCKED_WRITER_UNKNOWN"))

    def test_side_effect_unknown_blocks(self) -> None:
        result = check_target_safety(
            approval=make_approval(),
            scope=make_scope(),
            side_effects=make_side_effects(iam="UNKNOWN"),
            now_utc=NOW,
        )
        self.assertEqual((result.allowed, result.code), (False, "BLOCKED_SIDE_EFFECT_UNASSESSED"))

    def test_scope_mismatch_blocks(self) -> None:
        result = check_target_safety(
            approval=make_approval(account="999999999999"),
            scope=make_scope(),
            side_effects=make_side_effects(),
            now_utc=NOW,
        )
        self.assertEqual((result.allowed, result.code), (False, "BLOCKED_SCOPE_MISMATCH"))

    def test_expired_evidence_blocks(self) -> None:
        result = check_target_safety(
            approval=make_approval(),
            scope=make_scope(not_after=NOW - timedelta(seconds=1)),
            side_effects=make_side_effects(),
            now_utc=NOW,
        )
        self.assertEqual((result.allowed, result.code), (False, "BLOCKED_SCOPE_EXPIRED"))

    def test_verified_scope_and_side_effects_allow_offline_precheck(self) -> None:
        result = check_target_safety(
            approval=make_approval(),
            scope=make_scope(),
            side_effects=make_side_effects(),
            now_utc=NOW,
        )
        self.assertEqual((result.allowed, result.code, result.scope_id), (True, "ALLOWED", "scope-1"))


if __name__ == "__main__":
    unittest.main()
