"""Per-Kind Name evidence verification for approved Batch rows. Pure and offline.

A Name is signable only when a trusted per-Kind verifier deterministically rederives
it from the immutable Plan record evidence. Nonempty text, a user-supplied proposed
Name or an unverifiable formula is never sufficient (NAME_EVIDENCE_NOT_PROVEN).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping, Protocol

import name_tag_kind_capabilities as _caps
from name_tag_kind_capabilities import CanonicalTargetIdentity

NAME_EVIDENCE_NOT_PROVEN = "NAME_EVIDENCE_NOT_PROVEN"


class NameEvidenceNotProven(ValueError):
    """Raised when no trusted evidence formula can reproduce the proposed Name."""


@dataclass(frozen=True)
class VerifiedGeneratedName:
    kind: str
    resource_arn: str
    generated_name: str
    evidence_digest: str


class KindNameEvidenceVerifier(Protocol):
    def verify(self, plan_record: Mapping[str, object],
               target: CanonicalTargetIdentity) -> VerifiedGeneratedName: ...


def _digest(kind: str, arn: str, name: str, evidence: str) -> str:
    return hashlib.sha256("\x00".join((kind, arn, name, evidence)).encode("utf-8")).hexdigest()


class VolumeEbsEvidenceVerifier:
    """Existing Batch Volume EBS formula, unchanged: <EC2 Name anchor>-ebs-<device>-<last 7 of id>."""

    def verify(self, plan_record, target):
        from aws_cost_name_tagger_v3 import meaningful
        locator = plan_record.get("locator")
        evidence = plan_record.get("evidence")
        name = plan_record.get("proposed_name")
        if not isinstance(locator, str) or not isinstance(evidence, str) or not isinstance(name, str):
            raise NameEvidenceNotProven("Evidence does not support the generated Name")
        if meaningful(name) != name:
            raise NameEvidenceNotProven("Proposed Name is not a meaningful generated Name")
        match = re.fullmatch(
            rf"EBS {re.escape(locator)} -> attachment (i-(?:[0-9a-f]{{8}}|[0-9a-f]{{17}})) "
            rf"([a-z][a-z0-9-]*[a-z0-9]) -> EC2 \1 Name=(\S+?);.*", evidence)
        device = match.group(2) if match else None
        anchor = match.group(3) if match else None
        if anchor is None or meaningful(anchor) != anchor or f"{anchor}-ebs-{device}-{locator[-7:]}" != name:
            raise NameEvidenceNotProven("Evidence does not support the generated Name")
        return VerifiedGeneratedName(target.kind, target.resource_arn, name,
                                     _digest(target.kind, target.resource_arn, name, evidence))


# Only Kinds whose evidence formula is demonstrably supported are listed. Everything
# else stays NAME_EVIDENCE_NOT_PROVEN. Tests may patch this mapping with test-only
# fixtures; production decisions are never promoted by them.
_VERIFIERS: dict[str, KindNameEvidenceVerifier] = {"volume": VolumeEbsEvidenceVerifier()}


def verified_generated_name(record: Mapping[str, object],
                            target: CanonicalTargetIdentity) -> VerifiedGeneratedName:
    """Rederive the Name via the trusted per-Kind verifier selected by the signed Kind/ARN."""
    if not isinstance(target, CanonicalTargetIdentity) or record.get("kind") != target.kind:
        raise NameEvidenceNotProven(NAME_EVIDENCE_NOT_PROVEN)
    if record.get("locator") != target.locator:
        raise NameEvidenceNotProven(NAME_EVIDENCE_NOT_PROVEN)
    if record.get("resource_arn") != target.resource_arn:
        raise NameEvidenceNotProven(NAME_EVIDENCE_NOT_PROVEN)
    decision = _caps.resolve_kind_capability(target.kind)
    verifier = _VERIFIERS.get(target.kind)
    if decision.status != "IMPLEMENTED_OFFLINE" or verifier is None:
        raise NameEvidenceNotProven(NAME_EVIDENCE_NOT_PROVEN)
    result = verifier.verify(record, target)
    if (type(result) is not VerifiedGeneratedName or result.kind != target.kind
            or result.resource_arn != target.resource_arn
            or result.generated_name != record.get("proposed_name")
            or not result.generated_name):
        raise NameEvidenceNotProven(NAME_EVIDENCE_NOT_PROVEN)
    return result
