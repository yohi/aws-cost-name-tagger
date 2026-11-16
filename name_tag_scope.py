"""Offline safety decision from independently scoped writer evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from name_tag_approval import VerifiedEnvelope, approval_digest, canonical_payload


@dataclass(frozen=True, slots=True)
class ScopeEvidence:
    """Owner-responsible writer boundary bound to one fixed AWS identity."""

    account: str
    partition: str
    region: str
    writer_control_scope_id: str
    controlled_arns: frozenset[str]
    not_before_utc: datetime
    not_after_utc: datetime
    writer_evidence_digest: str
    responsible_owner: str


@dataclass(frozen=True, slots=True)
class SideEffectEvidence:
    """Independent assessment of authorization and automation side effects."""

    target_arn: str
    iam_abac_resource_tag_assessment: str
    iac_assessment: str
    event_automation_assessment: str
    evidence_references: tuple[str, ...]
    not_before_utc: datetime
    not_after_utc: datetime


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    """Result of the offline precheck; it does not authorize an AWS write."""

    allowed: bool
    code: str
    scope_id: str | None


def _valid_window(start: datetime, end: datetime, now: datetime) -> bool:
    """Check an inclusive, timezone-aware evidence validity interval."""
    if start.tzinfo is None or end.tzinfo is None or now.tzinfo is None:
        return False
    try:
        instant = now.astimezone(timezone.utc)
        return start.astimezone(timezone.utc) <= instant <= end.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return False


def _verified_name_approval(approval: VerifiedEnvelope) -> bool:
    """Recompute content identity and ownership from the immutable envelope."""
    if type(approval) is not VerifiedEnvelope or approval.kind != "name":
        return False
    if not isinstance(approval.payload, MappingProxyType):
        return False
    try:
        canonical = canonical_payload(approval.payload, kind="name")
    except (TypeError, ValueError):
        return False
    return (
        canonical == approval.canonical_payload_bytes
        and approval_digest(canonical) == approval.content_id
        and approval.payload.get("owner_principal_id") == approval.owner_principal_id
    )


def check_target_safety(
    *,
    approval: VerifiedEnvelope,
    scope: ScopeEvidence,
    side_effects: SideEffectEvidence,
    now_utc: datetime,
) -> SafetyDecision:
    """Fail closed unless verified Name approval and both evidence sets agree."""
    scope_id = scope.writer_control_scope_id
    if not _verified_name_approval(approval):
        return SafetyDecision(False, "BLOCKED_OWNER_AUTHN", scope_id)

    payload = approval.payload
    if (
        payload.get("account") != scope.account
        or payload.get("partition") != scope.partition
        or payload.get("region") != scope.region
        or payload.get("resource_arn") not in scope.controlled_arns
        or side_effects.target_arn != payload.get("resource_arn")
    ):
        return SafetyDecision(False, "BLOCKED_SCOPE_MISMATCH", scope_id)

    if not _valid_window(scope.not_before_utc, scope.not_after_utc, now_utc):
        return SafetyDecision(False, "BLOCKED_SCOPE_EXPIRED", scope_id)
    if not _valid_window(side_effects.not_before_utc, side_effects.not_after_utc, now_utc):
        return SafetyDecision(False, "BLOCKED_SCOPE_EXPIRED", scope_id)

    if (
        not scope.writer_control_scope_id
        or not scope.responsible_owner
        or scope.responsible_owner != approval.owner_principal_id
        or re.fullmatch(r"[0-9a-f]{64}", scope.writer_evidence_digest) is None
    ):
        return SafetyDecision(False, "BLOCKED_WRITER_UNKNOWN", scope_id)

    if (
        side_effects.iam_abac_resource_tag_assessment != "PASS"
        or side_effects.iac_assessment != "PASS"
        or side_effects.event_automation_assessment != "PASS"
        or not side_effects.evidence_references
        or any(type(reference) is not str or not reference for reference in side_effects.evidence_references)
    ):
        return SafetyDecision(False, "BLOCKED_SIDE_EFFECT_UNASSESSED", scope_id)

    return SafetyDecision(True, "ALLOWED", scope_id)
