"""Host Scope, effective-IAM deny evidence and the one-shot VerifiedRuntimeGrant (§5.1).

OFFLINE in this phase. Every type here is a Host-issued, process-local protected reference
(not proof by fields): copies, pickles, constructed instances and caller-made evidence are
refused. Only synthetic evidence can be produced offline; it is marked
``OFFLINE_SYNTHETIC_NOT_STS`` and the protected (production) verifiers refuse it with
``AWS_RUNTIME_NOT_AUTHORIZED``. No live evidence producer exists until a separately
Owner-authorized Host acceptance; G2_NOT_VERIFIED / AWS_RUNTIME_NOT_AUTHORIZED stay effective.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from hashlib import sha256
from typing import Final, Protocol
from weakref import WeakKeyDictionary

import name_tag_kind_capabilities as caps
from name_tag_batch_approval import VerifiedBatchRowAuthority, canonical_bytes
from name_tag_batch_credentials import SYNTHETIC_PROVENANCE, is_offline_synthetic
from name_tag_batch_host_issuer import HostIssuedSession, require_issued_session
from name_tag_batch_host_runtime import (
    HostRuntimeBlocked, VerifiedHostContext, _NonCopyable, _blocked, bound_ledger,
    require_aware_utc, require_verified_host)
from name_tag_kind_capabilities import CanonicalTargetIdentity, KindCapabilityDecision
from name_tag_ledger import FirstSendPermit
from name_tag_scope import ScopeEvidence, SideEffectEvidence

LIVE_PROVENANCE: Final = "PROTECTED_LIVE_EVIDENCE"
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DENY_CASES: Final = frozenset({"FOREIGN_ARN", "OTHER_TAG_KEY", "ALTERNATE_API"})
_ACCEPTED_SOURCE: Final = "PROTECTED_EVIDENCE_PRODUCER"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _mint_guard(token: object) -> None:
    if token is not _MINT:
        raise _blocked("protected reference is minted only by the Host verifier")


_MINT: Final = object()


class _Protected(_NonCopyable):
    """Immutable slotted protected reference; attributes set once at mint time."""

    __slots__ = ()

    def __setattr__(self, name, value):
        raise _blocked("protected reference is immutable")

    def _init(self, values: dict) -> None:
        for name, value in values.items():
            object.__setattr__(self, name, value)


# ---------------------------------------------------------------- Host Scope
class ProtectedScopeSource(Protocol):
    """Host-trusted Scope/SideEffect evidence store (never IPC/caller supplied)."""

    def load(self, scope_id: str, host: VerifiedHostContext
             ) -> tuple[ScopeEvidence, tuple[SideEffectEvidence, ...]]: ...


class VerifiedHostScope(_Protected):
    __slots__ = ("host", "scope_id", "scope", "side_effects", "all_side_effects", "target",
                 "not_after_utc", "__weakref__")

    def __init__(self, _mint: object = None, **values) -> None:
        _mint_guard(_mint)
        self._init(values)


_SCOPES: WeakKeyDictionary = WeakKeyDictionary()


def ownership_proof_ref(host: VerifiedHostContext, scope: ScopeEvidence, arn: str) -> str:
    """Host-bound ownership attestation reference for exactly one target ARN."""
    return sha256(b"aws-cnt-ownership-v1\x00" + canonical_bytes([
        host.host_id, host.scope_evidence_sha256, scope.writer_control_scope_id, arn,
        scope.writer_evidence_digest])).hexdigest()


class HostScopeVerifier(Protocol):
    def resolve(self, signed_scope_id: str, target: CanonicalTargetIdentity,
                host: VerifiedHostContext, now_utc: datetime) -> VerifiedHostScope: ...


class ProtectedHostScopeVerifier:
    def __init__(self, *, source: ProtectedScopeSource) -> None:
        if source is None:
            raise _blocked("no protected Scope evidence source")
        self._source = source

    def resolve(self, signed_scope_id: str, target: CanonicalTargetIdentity,
                host: VerifiedHostContext, now_utc: datetime) -> VerifiedHostScope:
        host = require_verified_host(host)
        now = require_aware_utc(now_utc)
        if type(target) is not CanonicalTargetIdentity or not isinstance(signed_scope_id, str):
            raise _blocked("target is not a canonical identity", "BLOCKED_SCOPE_MISMATCH")
        try:
            caps.canonical_target_identity(
                kind=target.kind, locator=target.locator, resource_arn=target.resource_arn,
                partition=target.partition, account=target.owner_account,
                scope_region=target.scope_region)
            if bound_ledger(host).effective_scope_state(signed_scope_id) != "CLEARED":
                raise _blocked("Scope not CLEARED", "BLOCKED_SCOPE_HOLD")
            scope, effects = self._source.load(signed_scope_id, host)
        except HostRuntimeBlocked:
            raise
        except Exception as error:  # noqa: BLE001 - protected-state read failure fails closed
            raise _blocked("Scope evidence unreadable", "BLOCKED_SCOPE_STATE_UNKNOWN") from error
        arn = target.resource_arn
        if (type(scope) is not ScopeEvidence or scope.writer_control_scope_id != signed_scope_id
                or scope.account != target.owner_account or scope.partition != target.partition
                or scope.region != target.scope_region or arn not in scope.controlled_arns
                or _HEX64.fullmatch(scope.writer_evidence_digest) is None
                or not scope.not_before_utc <= now < scope.not_after_utc):
            raise _blocked("Scope evidence does not cover the target", "BLOCKED_SCOPE_MISMATCH")
        matching = [e for e in effects if type(e) is SideEffectEvidence and e.target_arn == arn] \
            if isinstance(effects, tuple) else []
        if (len(matching) != 1
                or (matching[0].iam_abac_resource_tag_assessment, matching[0].iac_assessment,
                    matching[0].event_automation_assessment) != ("PASS", "PASS", "PASS")
                or not matching[0].evidence_references
                or not all(matching[0].evidence_references)
                or not matching[0].not_before_utc <= now < matching[0].not_after_utc):
            raise _blocked("side-effect evidence unassessed", "BLOCKED_SIDE_EFFECT_UNASSESSED")
        ref = ownership_proof_ref(host, scope, arn)
        if target.ownership_proof_ref and target.ownership_proof_ref != ref:
            raise _blocked("ownership proof is not bound to this target", "BLOCKED_SCOPE_MISMATCH")
        verified = VerifiedHostScope(
            _MINT, host=host, scope_id=signed_scope_id, scope=scope, side_effects=tuple(matching),
            all_side_effects=tuple(effects),
            target=replace(target, ownership_proof_ref=ref),
            not_after_utc=min(scope.not_after_utc, matching[0].not_after_utc))
        _SCOPES[verified] = host
        return verified

    def reconfirm(self, vscope: VerifiedHostScope, now_utc: datetime) -> None:
        """Re-load the protected Scope source and require it unchanged (no Ledger read:
        the caller's own pending Intent makes the effective state HOLD by design)."""
        _reconfirm_scope(self._source, vscope, now_utc)


def _reconfirm_scope(source, vscope: object, now_utc: datetime) -> None:
    """Pre-Permit: the Host-protected Scope declaration/proof must be exactly unchanged."""
    vscope = _require_scope(vscope)
    now = require_aware_utc(now_utc)
    try:
        scope, effects = source.load(vscope.scope_id, vscope.host)
    except HostRuntimeBlocked:
        raise
    except Exception as error:  # noqa: BLE001 - protected-state read failure fails closed
        raise _blocked("Scope evidence unreadable", "BLOCKED_SCOPE_STATE_UNKNOWN") from error
    if (type(scope) is not ScopeEvidence or scope != vscope.scope
            or not isinstance(effects, tuple) or effects != vscope.all_side_effects
            or not scope.not_before_utc <= now < scope.not_after_utc
            or not now < vscope.not_after_utc
            or ownership_proof_ref(vscope.host, scope, vscope.target.resource_arn)
            != vscope.target.ownership_proof_ref):
        raise _blocked("Host Scope evidence changed before Permit", "BLOCKED_SCOPE_MISMATCH")


def _require_scope(scope: object) -> VerifiedHostScope:
    if type(scope) is not VerifiedHostScope or _SCOPES.get(scope) is not scope.host:
        raise _blocked("Scope is not a Host-verified reference", "BLOCKED_SCOPE_MISMATCH")
    require_verified_host(scope.host)
    return scope


# ---------------------------------------------------------------- effective-IAM evidence
@dataclass(frozen=True)
class IamDenyCase:
    case: str  # FOREIGN_ARN | OTHER_TAG_KEY | ALTERNATE_API
    resource_arn: str
    action: str
    tag_key: str
    decision: str


_EVIDENCE_FIELDS: Final = (
    "principal_arn", "account", "partition", "role_policy_digests", "trust_policy_sha256",
    "permission_boundary_sha256", "scp_sha256", "rcp_sha256", "resource_policy_sha256",
    "session_grant_sha256", "approved_allow", "deny_cases", "source", "captured_at_utc",
    "expires_at_utc", "captured_state_sha256", "current_state_sha256", "verifier_result")


class ProtectedIamEvidence(_Protected):
    """Separately sourced effective-IAM evidence bundle (not a Boolean)."""

    __slots__ = _EVIDENCE_FIELDS + ("provenance", "__weakref__")

    def __init__(self, _mint: object = None, **values) -> None:
        _mint_guard(_mint)
        self._init(values)

    def digest(self) -> str:
        values = []
        for name in _EVIDENCE_FIELDS + ("provenance",):
            value = getattr(self, name)
            if isinstance(value, datetime):
                value = value.isoformat()
            elif name == "deny_cases":
                value = [[c.case, c.resource_arn, c.action, c.tag_key, c.decision] for c in value]
            elif name in ("role_policy_digests", "approved_allow"):
                value = [list(v) if isinstance(v, tuple) else v for v in value]
            values.append(value)
        return sha256(canonical_bytes(values)).hexdigest()


_EVIDENCE: WeakKeyDictionary = WeakKeyDictionary()


class SyntheticIamEvidenceProducer:
    """OFFLINE ONLY: produces synthetic evidence for code-behaviour tests; never live."""

    def produce(self, **fields) -> ProtectedIamEvidence:
        if set(fields) != set(_EVIDENCE_FIELDS):
            raise _blocked("evidence bundle incomplete")
        evidence = ProtectedIamEvidence(_MINT, provenance=SYNTHETIC_PROVENANCE, **fields)
        _EVIDENCE[evidence] = SYNTHETIC_PROVENANCE
        return evidence


_DENY_FIELDS: Final = ("row_authority_id", "evidence_sha256", "expires_at_utc", "provenance")


def _field_digest(obj: object, names: tuple[str, ...]) -> str:
    """Digest of a protected reference's scalar fields, recorded at mint time."""
    values = []
    for name in names:
        value = getattr(obj, name)
        values.append(value.isoformat() if isinstance(value, datetime) else value)
    return sha256(canonical_bytes(values)).hexdigest()


@dataclass(frozen=True, eq=False)
class _DenyBinding:
    issued: HostIssuedSession
    scope: "VerifiedHostScope"
    provenance: str
    digest: str


class VerifiedDenyEvidence(_Protected):
    __slots__ = ("issued", "row_authority_id", "scope", "evidence_sha256", "expires_at_utc",
                 "provenance", "__weakref__")

    def __init__(self, _mint: object = None, **values) -> None:
        _mint_guard(_mint)
        self._init(values)


_DENIES: WeakKeyDictionary = WeakKeyDictionary()


class EffectiveIamEvidenceVerifier(Protocol):
    def verify(self, issued: HostIssuedSession, row: VerifiedBatchRowAuthority,
               capability: KindCapabilityDecision, scope: VerifiedHostScope,
               evidence: ProtectedIamEvidence) -> VerifiedDenyEvidence: ...


def _check_binding(issued, row, scope, now: datetime):
    scope = _require_scope(scope)
    if is_offline_synthetic(issued):
        raise _blocked("synthetic session cannot satisfy the Host")
    issued = require_issued_session(issued, scope.host, now)
    receipt = issued.receipt
    if (type(row) is not VerifiedBatchRowAuthority
            or row.row_authority_id != receipt.row_authority_id
            or row.row_index != receipt.row_index or row.batch.batch_id != receipt.batch_id
            or row.row.get("resource_arn") != receipt.target_arn
            or row.row.get("writer_control_scope_id") != receipt.scope_id
            or scope.scope_id != receipt.scope_id or scope.target.resource_arn != receipt.target_arn):
        raise _blocked("row/Scope not bound to the issued session")
    return issued, scope


def _validate_evidence(issued, row, capability, scope, evidence, now: datetime) -> str:
    issued, scope = _check_binding(issued, row, scope, now)
    if (type(capability) is not KindCapabilityDecision
            or capability != caps.resolve_kind_capability(row.row.get("kind"))
            or capability.status != "IMPLEMENTED_OFFLINE"
            or capability.iam_action != row.row.get("aws_operation")):
        raise _blocked("capability is not the genuine vetted Registry decision")
    if type(evidence) is not ProtectedIamEvidence or _EVIDENCE.get(evidence) != evidence.provenance:
        raise _blocked("IAM evidence is not a protected bundle")
    arn, action = row.row["resource_arn"], capability.iam_action
    receipt = issued.receipt
    if (evidence.source != _ACCEPTED_SOURCE
            or evidence.principal_arn != receipt.assumed_role_arn
            or evidence.account != receipt.account or evidence.partition != receipt.partition
            or evidence.verifier_result != "PASS"):
        raise _blocked("IAM evidence source/principal not acceptable")
    digests = [evidence.trust_policy_sha256, evidence.permission_boundary_sha256,
               evidence.scp_sha256, evidence.rcp_sha256, evidence.resource_policy_sha256,
               evidence.session_grant_sha256, evidence.captured_state_sha256]
    policies = evidence.role_policy_digests
    if (type(policies) is not tuple or not policies
            or any(type(p) is not tuple or len(p) != 3 or not all(isinstance(x, str) and x for x in p)
                   for p in policies)):
        raise _blocked("role policy provenance missing")
    digests.extend(p[2] for p in policies)
    if any(not isinstance(d, str) or _HEX64.fullmatch(d) is None for d in digests):
        raise _blocked("policy provenance digests malformed")
    if evidence.current_state_sha256 != evidence.captured_state_sha256:
        raise _blocked("effective IAM drifted since capture")
    if evidence.approved_allow != (arn, action, "Name"):
        raise _blocked("approved allow is not the exact ARN/action/Name key")
    cases = evidence.deny_cases
    if (type(cases) is not tuple or any(type(c) is not IamDenyCase for c in cases)
            or {c.case for c in cases} != _DENY_CASES or any(c.decision != "DENY" for c in cases)):
        raise _blocked("required deny cases missing or not denied")
    for c in cases:
        if ((c.case == "FOREIGN_ARN" and (c.resource_arn == arn or c.action != action))
                or (c.case == "OTHER_TAG_KEY" and (c.resource_arn != arn or c.tag_key == "Name"))
                or (c.case == "ALTERNATE_API" and (c.resource_arn != arn or c.action == action))):
            raise _blocked("deny case does not exercise its boundary")
    captured, expires = evidence.captured_at_utc, evidence.expires_at_utc
    if (type(captured) is not datetime or type(expires) is not datetime
            or captured.tzinfo is None or expires.tzinfo is None
            or not captured <= now < expires):
        raise _blocked("IAM evidence outside its validity window")
    return evidence.digest()


class _IamEvidenceVerifierBase:
    _required_provenance: str = ""

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock

    def verify(self, issued, row, capability, scope, evidence) -> VerifiedDenyEvidence:
        now = require_aware_utc(self._clock())
        digest = _validate_evidence(issued, row, capability, scope, evidence, now)
        if evidence.provenance != self._required_provenance:
            raise _blocked("live effective-IAM evidence NOT_VERIFIED (G2_NOT_VERIFIED)")
        deny = VerifiedDenyEvidence(
            _MINT, issued=issued, row_authority_id=row.row_authority_id, scope=scope,
            evidence_sha256=digest, provenance=evidence.provenance,
            expires_at_utc=min(evidence.expires_at_utc, issued.expiration, scope.not_after_utc))
        _DENIES[deny] = _DenyBinding(issued, scope, deny.provenance,
                                     _field_digest(deny, _DENY_FIELDS))
        return deny


class ProtectedEffectiveIamEvidenceVerifier(_IamEvidenceVerifierBase):
    """Production: only live protected evidence; none exists yet -> fail closed."""

    _required_provenance = LIVE_PROVENANCE


class OfflineSyntheticIamEvidenceVerifier(_IamEvidenceVerifierBase):
    """OFFLINE: identical checks over synthetic evidence; its result is never live."""

    _required_provenance = SYNTHETIC_PROVENANCE


# ---------------------------------------------------------------- one-shot runtime grant
_GRANT_FIELDS: Final = (
    "host_id", "run_id", "batch_id", "row_authority_id", "row_tuple_sha256", "resource_arn",
    "approved_name", "aws_operation", "scope_id", "ownership_proof_ref", "permit_sha256",
    "receipt_sha256", "client_identity", "capability_version", "proof_sha256",
    "expires_at_utc", "provenance")


class VerifiedRuntimeGrant(_Protected):
    """Process-local, non-serializable, one-shot grant consumed at SDK dispatch."""

    __slots__ = _GRANT_FIELDS + ("__weakref__",)

    def __init__(self, _mint: object = None, **values) -> None:
        _mint_guard(_mint)
        self._init(values)

    def __repr__(self) -> str:
        return (f"VerifiedRuntimeGrant(batch_id={self.batch_id!r}, "
                f"row_authority_id={self.row_authority_id!r}, provenance={self.provenance!r})")


@dataclass(frozen=True, eq=False)
class _GrantBinding:
    permit: FirstSendPermit
    issued: HostIssuedSession
    row: VerifiedBatchRowAuthority
    provenance: str
    digest: str


_GRANTS: WeakKeyDictionary = WeakKeyDictionary()
# One grant per (Host run, Batch, row) for the life of the process: an equal-valued second
# FirstSendPermit, a fresh deny bundle or a re-presented session can never mint another.
_GRANTED_ROWS: set[tuple[str, str, int]] = set()


def _permit_sha256(permit: FirstSendPermit) -> str:
    return sha256(canonical_bytes([
        permit.authorization_id, permit.resource_arn, permit.approved_name,
        permit.writer_control_scope_id, permit.aws_operation, permit.execution_id,
        sha256(permit.ownership_token.encode()).hexdigest()])).hexdigest()


class ProtectedBatchRuntimeVerifier(Protocol):
    def authorize_once(self, row: VerifiedBatchRowAuthority, issued: HostIssuedSession,
                       scope: VerifiedHostScope, deny: VerifiedDenyEvidence,
                       permit: FirstSendPermit) -> VerifiedRuntimeGrant: ...


class _RuntimeVerifierBase:
    _required_provenance: str = ""

    def __init__(self, *, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock

    def authorize_once(self, row, issued, scope, deny, permit) -> VerifiedRuntimeGrant:
        now = require_aware_utc(self._clock())
        issued, scope = _check_binding(issued, row, scope, now)
        binding = _DENIES.get(deny) if type(deny) is VerifiedDenyEvidence else None
        if (binding is None or binding.issued is not issued or binding.scope is not scope
                or deny.issued is not issued or deny.scope is not scope
                or binding.digest != _field_digest(deny, _DENY_FIELDS)
                or deny.row_authority_id != row.row_authority_id or not now < deny.expires_at_utc):
            raise _blocked("deny evidence missing, consumed, expired, altered or not bound")
        if binding.provenance != self._required_provenance or deny.provenance != binding.provenance:
            raise _blocked("live effective-IAM evidence NOT_VERIFIED (G2_NOT_VERIFIED)")
        receipt = issued.receipt
        row_key = (receipt.run_id, receipt.batch_id, row.row_index)
        if row_key in _GRANTED_ROWS:
            raise _blocked("a runtime grant was already minted for this row/session",
                           "BLOCKED_INTENT_REPLAY")
        fields = row.row
        if (type(permit) is not FirstSendPermit
                or permit.resource_arn != fields.get("resource_arn")
                or permit.approved_name != fields.get("approved_name")
                or permit.writer_control_scope_id != fields.get("writer_control_scope_id")
                or permit.aws_operation != fields.get("aws_operation")):
            raise _blocked("FirstSendPermit missing, reused or mismatched")
        if scope.scope.responsible_owner != row.batch.owner_principal_id:
            raise _blocked("Scope owner differs from the signing Owner", "BLOCKED_SCOPE_MISMATCH")
        ledger = bound_ledger(scope.host)
        try:
            owned = ledger.batch_intent_owned_by_current_execution(row.batch, row.row_index)
            recorded = ledger.batch_send_permit_identity(row.batch, row.row_index)
        except Exception as error:  # noqa: BLE001
            raise _blocked("Ledger Permit state unreadable",
                           "BLOCKED_SCOPE_STATE_UNKNOWN") from error
        presented = (permit.authorization_id, permit.execution_id,
                     sha256(permit.ownership_token.encode("utf-8")).hexdigest())
        if owned is not True or recorded != presented:
            raise _blocked("Permit is not the Ledger's consumed Intent for this execution")
        capability = caps.resolve_kind_capability(fields.get("kind"))
        grant = VerifiedRuntimeGrant(
            _MINT, host_id=receipt.host_id, run_id=receipt.run_id, batch_id=receipt.batch_id,
            row_authority_id=row.row_authority_id,
            row_tuple_sha256=sha256(canonical_bytes(dict(fields))).hexdigest(),
            resource_arn=fields["resource_arn"], approved_name=fields["approved_name"],
            aws_operation=fields["aws_operation"], scope_id=scope.scope_id,
            ownership_proof_ref=scope.target.ownership_proof_ref,
            permit_sha256=_permit_sha256(permit), receipt_sha256=receipt.receipt_sha256,
            client_identity=issued.client_identity(capability.service, fields["region"]),
            capability_version=capability.version, proof_sha256=deny.evidence_sha256,
            expires_at_utc=deny.expires_at_utc, provenance=deny.provenance)
        _GRANTED_ROWS.add(row_key)
        _DENIES.pop(deny, None)  # deny evidence is consumed by the single grant
        _GRANTS[grant] = _GrantBinding(permit, issued, row, grant.provenance,
                                       _field_digest(grant, _GRANT_FIELDS))
        return grant


class ProtectedHostRuntimeVerifier(_RuntimeVerifierBase):
    """Production gate: mints only from live deny evidence; none exists -> fail closed."""

    _required_provenance = LIVE_PROVENANCE


class OfflineSyntheticRuntimeVerifier(_RuntimeVerifierBase):
    """OFFLINE: same checks; its grants are synthetic and never satisfy a live dispatch."""

    _required_provenance = SYNTHETIC_PROVENANCE


def _consume_grant(grant: object, *, row: VerifiedBatchRowAuthority,
                   permit: FirstSendPermit, target: CanonicalTargetIdentity,
                   now_utc: datetime) -> _GrantBinding:
    now = require_aware_utc(now_utc)
    if type(grant) is not VerifiedRuntimeGrant:
        raise _blocked("no protected runtime grant")
    binding = _GRANTS.pop(grant, None)  # consumed even if a later check refuses
    if binding is None:
        raise _blocked("runtime grant unknown or already consumed")
    if (binding.digest != _field_digest(grant, _GRANT_FIELDS)
            or grant.provenance != binding.provenance):
        raise _blocked("runtime grant was altered after minting")
    if (binding.permit is not permit or binding.row is not row
            or row.row_authority_id != grant.row_authority_id
            or type(target) is not CanonicalTargetIdentity
            or target.resource_arn != grant.resource_arn
            or target.ownership_proof_ref != grant.ownership_proof_ref
            or not now < grant.expires_at_utc):
        raise _blocked("runtime grant does not match the dispatch")
    require_issued_session(binding.issued, binding.issued.selection.host, now)
    return binding


def consume_runtime_grant(grant: object, *, row: VerifiedBatchRowAuthority,
                          permit: FirstSendPermit, target: CanonicalTargetIdentity,
                          now_utc: datetime) -> None:
    """The SDK dispatch boundary: live-only, exactly once, no caller override."""
    binding = _consume_grant(grant, row=row, permit=permit, target=target, now_utc=now_utc)
    if binding.provenance != LIVE_PROVENANCE:
        raise _blocked("synthetic grant cannot authorize a live SDK dispatch")


def consume_offline_synthetic_grant(grant: object, *, row: VerifiedBatchRowAuthority,
                                    permit: FirstSendPermit, target: CanonicalTargetIdentity,
                                    now_utc: datetime) -> None:
    """OFFLINE tests only: consume a synthetic grant. Never a dispatch authorization."""
    binding = _consume_grant(grant, row=row, permit=permit, target=target, now_utc=now_utc)
    if binding.provenance != SYNTHETIC_PROVENANCE:
        raise _blocked("only synthetic grants are consumed offline")
