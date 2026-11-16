"""Offline safety decision from independently scoped writer evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from name_tag_approval import (
    ApprovalRejected,
    VerifiedEnvelope,
    approval_digest,
    canonical_payload,
)


def _utc_datetime(value: datetime) -> datetime:
    """Validate and normalize a timezone-aware datetime to UTC."""
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Evidence validity bounds must be timezone-aware datetimes")
    try:
        return value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError("Evidence validity bounds must be representable in UTC") from None


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

    def __post_init__(self) -> None:
        """Freeze ARN membership and normalize the evidence validity window."""
        for name in ("account", "partition", "region", "writer_control_scope_id", "writer_evidence_digest", "responsible_owner"):
            if type(getattr(self, name)) is not str:
                raise TypeError(f"{name} must be a string")
        if type(self.controlled_arns) not in (set, frozenset, list, tuple):
            raise TypeError("controlled_arns must be a collection of ARN strings")
        normalized_arns: set[str] = set()
        normalized_arns.update(self.controlled_arns)
        controlled_arns = frozenset(normalized_arns)
        if any(type(arn) is not str or not arn for arn in controlled_arns):
            raise ValueError("controlled_arns must contain non-empty strings")
        object.__setattr__(self, "controlled_arns", controlled_arns)
        object.__setattr__(self, "not_before_utc", _utc_datetime(self.not_before_utc))
        object.__setattr__(self, "not_after_utc", _utc_datetime(self.not_after_utc))


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

    def __post_init__(self) -> None:
        """Freeze evidence references and normalize the validity window."""
        if type(self.target_arn) is not str:
            raise TypeError("target_arn must be a string")
        if type(self.evidence_references) not in (list, tuple):
            raise TypeError("evidence_references must be a list or tuple")
        references = tuple(reference for reference in self.evidence_references)
        if any(type(reference) is not str for reference in references):
            raise ValueError("evidence_references must contain strings")
        object.__setattr__(self, "evidence_references", references)
        object.__setattr__(self, "not_before_utc", _utc_datetime(self.not_before_utc))
        object.__setattr__(self, "not_after_utc", _utc_datetime(self.not_after_utc))


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    """Result of the offline precheck; it does not authorize an AWS write."""

    allowed: bool
    code: str
    scope_id: str | None


def _valid_window(start: datetime, end: datetime, now: datetime) -> bool:
    """Check an inclusive, timezone-aware evidence validity interval."""
    if (
        type(start) is not datetime
        or type(end) is not datetime
        or type(now) is not datetime
        or start.tzinfo is None
        or end.tzinfo is None
        or now.tzinfo is None
    ):
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
    except (ApprovalRejected, TypeError, ValueError):
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
    if type(scope) is not ScopeEvidence:
        return SafetyDecision(False, "BLOCKED_WRITER_UNKNOWN", None)
    scope_id = scope.writer_control_scope_id
    if not _verified_name_approval(approval):
        return SafetyDecision(False, "BLOCKED_OWNER_AUTHN", scope_id)
    if type(side_effects) is not SideEffectEvidence:
        return SafetyDecision(False, "BLOCKED_SIDE_EFFECT_UNASSESSED", scope_id)

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
        return SafetyDecision(False, "BLOCKED_SIDE_EFFECT_UNASSESSED", scope_id)

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
