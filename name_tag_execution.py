"""Phase-A guarded Name execution using an explicitly offline fake adapter."""

# noqa: SIZE_OK — The verify→Intent→Permit→fake-write→Readback state machine must remain one review unit.

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import ClassVar, Final, Literal, NoReturn, Protocol, TypeGuard

try:
    from typing import assert_never
except ImportError:
    def assert_never(arg: NoReturn, /) -> NoReturn:
        raise AssertionError(f"Unexpected execution result code: {arg!r}")

from name_tag_approval import (
    ApprovalRejected,
    OwnerTrust,
    VerifiedEnvelope,
    revalidate_verified_envelope,
)
from name_tag_ledger import (
    FirstSendPermit,
    IntentHandle,
    IntentLedger,
    LedgerError,
    create_intent,
    consume_first_send,
    hold_scope,
    record_readback,
)
from name_tag_scope import ScopeEvidence, SideEffectEvidence, check_target_safety

AWS_CREATE_TAGS_OPERATION: Final = "ec2:CreateTags:2016-11-15"


@dataclass(frozen=True, slots=True)
class _OfflineTestProvenance:
    marker: Literal["test_harness"] = "test_harness"


_OFFLINE_TEST_PROVENANCE: Final = _OfflineTestProvenance()

ExecutionCode = Literal[
    "APPLIED_VERIFIED",
    "AWS_WRITE_BLOCKED",
    "BLOCKED_OWNER_AUTHN",
    "BLOCKED_SIDE_EFFECT_UNASSESSED",
    "BLOCKED_WRITER_UNKNOWN",
    "BLOCKED_SCOPE_EXPIRED",
    "BLOCKED_SCOPE_HOLD",
    "BLOCKED_INCOMPLETE_INTENT",
    "BLOCKED_INTENT_REPLAY",
    "BLOCKED_SCOPE_STATE_UNKNOWN",
    "BLOCKED_SCOPE_MISMATCH",
    "BLOCKED_NAME_NONEMPTY",
    "BLOCKED_NAME_UNKNOWN",
    "WRITE_UNSUPPORTED",
    "FAILED_READBACK",
    "OUTCOME_UNKNOWN",
]


class NameTagAdapter(Protocol):
    """One-target tag adapter; Phase A only admits the exact fake adapter."""

    operation_id: str

    def read_tags(self, resource_arn: str) -> Mapping[str, str]: ...

    def write_name_only(self, resource_arn: str, approved_name: str) -> None: ...

    def readback_tags(self, resource_arn: str) -> Mapping[str, str]: ...


class FakeNameTagAdapter:
    """Mutable in-memory adapter used exclusively by offline execution tests."""

    __slots__: ClassVar[tuple[str, ...]] = (
        "operation_id",
        "tags",
        "write_calls",
        "last_resource_arn",
        "last_approved_name",
        "write_error",
        "readback_error",
        "readback_override",
    )
    operation_id: str

    def __init__(self, tags: Mapping[str, str] | None = None) -> None:
        self.operation_id = AWS_CREATE_TAGS_OPERATION
        self.tags: dict[str, str] = dict(tags or {})
        self.write_calls: int = 0
        self.last_resource_arn: str | None = None
        self.last_approved_name: str | None = None
        self.write_error: OSError | None = None
        self.readback_error: OSError | None = None
        self.readback_override: Mapping[str, str] | None = None

    def read_tags(self, resource_arn: str) -> Mapping[str, str]:
        self.last_resource_arn = resource_arn
        return dict(self.tags)

    def write_name_only(self, resource_arn: str, approved_name: str) -> None:
        self.last_resource_arn = resource_arn
        self.last_approved_name = approved_name
        self.write_calls += 1
        if self.write_error is not None:
            raise self.write_error
        self.tags = {**self.tags, "Name": approved_name}

    def readback_tags(self, resource_arn: str) -> Mapping[str, str]:
        self.last_resource_arn = resource_arn
        if self.readback_error is not None:
            raise self.readback_error
        return dict(self.readback_override if self.readback_override is not None else self.tags)


@dataclass(frozen=True, slots=True)
class OfflineRuntimeContext:
    mode: Literal["offline"]
    source: Literal["test_harness"]
    fake_adapter: FakeNameTagAdapter
    _provenance: _OfflineTestProvenance = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class VerifiedRuntimePolicy:
    policy_id: str
    allowed_operation: str
    scope_id: str
    resource_arn: str
    approved_name: str


@dataclass(frozen=True, slots=True)
class AuthorizedAwsRuntimeContext:
    mode: Literal["authorized_aws"]
    policy: VerifiedRuntimePolicy
    execution_binding: str


RuntimeContext = OfflineRuntimeContext | AuthorizedAwsRuntimeContext


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    code: ExecutionCode
    authorization_id: str | None = None
    resource_arn: str | None = None
    approved_name: str | None = None
    name_after: str | None = None


@dataclass(frozen=True, slots=True)
class _ExecutionBinding:
    authorization_id: str
    resource_arn: str
    approved_name: str
    scope_id: str
    aws_operation: str


def _is_fake_adapter(adapter: NameTagAdapter) -> TypeGuard[FakeNameTagAdapter]:
    return type(adapter) is FakeNameTagAdapter


def offline_test_runtime(adapter: NameTagAdapter) -> OfflineRuntimeContext:
    """Create a context bound to this module's in-memory fake adapter only."""
    if not _is_fake_adapter(adapter):
        raise TypeError("exact FakeNameTagAdapter required")
    return OfflineRuntimeContext("offline", "test_harness", adapter, _OFFLINE_TEST_PROVENANCE)


def execute_once(
    name_approval: VerifiedEnvelope,
    authorization: VerifiedEnvelope,
    *,
    scope: ScopeEvidence,
    side_effects: SideEffectEvidence,
    ledger: IntentLedger,
    adapter: NameTagAdapter,
    runtime: RuntimeContext,
) -> ExecutionResult:
    """Verify both grants, consume one ledger permit, fake-write once, then read back."""
    if (
        type(runtime) is not OfflineRuntimeContext
        or not _offline_binding_matches(runtime, adapter)
    ):
        return ExecutionResult("AWS_WRITE_BLOCKED")
    trust = getattr(ledger, "_trust", None)
    if not isinstance(trust, OwnerTrust):
        return ExecutionResult("BLOCKED_OWNER_AUTHN")

    now = datetime.now(timezone.utc)
    if type(name_approval) is not VerifiedEnvelope or type(authorization) is not VerifiedEnvelope:
        return ExecutionResult("BLOCKED_OWNER_AUTHN")
    try:
        fresh_name = revalidate_verified_envelope(
            name_approval, kind="name", trust=trust, now_utc=now
        )
        fresh_execution = revalidate_verified_envelope(
            authorization, kind="execution", trust=trust, now_utc=now
        )
    except ApprovalRejected:
        return ExecutionResult("BLOCKED_OWNER_AUTHN")

    name_payload = fresh_name.payload
    execution_payload = fresh_execution.payload
    arn = name_payload.get("resource_arn")
    approved_name = name_payload.get("approved_name")
    operation = execution_payload.get("aws_operation")
    scope_id = scope.writer_control_scope_id
    if (
        not isinstance(arn, str)
        or not isinstance(approved_name, str)
        or not isinstance(operation, str)
        or execution_payload.get("name_approval_id") != fresh_name.content_id
        or execution_payload.get("resource_arn") != arn
        or execution_payload.get("approved_name") != approved_name
        or execution_payload.get("writer_control_scope_id") != scope_id
        or execution_payload.get("account") != name_payload.get("account")
        or execution_payload.get("partition") != name_payload.get("partition")
        or execution_payload.get("region") != name_payload.get("region")
        or name_payload.get("name_state_at_plan") not in ("ABSENT", "EMPTY")
    ):
        return ExecutionResult("BLOCKED_OWNER_AUTHN")
    writer_refs = _string_references(execution_payload.get("writer_control_evidence_refs"))
    side_effect_refs = _string_references(execution_payload.get("side_effect_evidence_refs"))
    if not writer_refs:
        return ExecutionResult("BLOCKED_WRITER_UNKNOWN", fresh_execution.content_id, arn, approved_name)
    if not side_effect_refs or side_effect_refs != side_effects.evidence_references:
        return ExecutionResult(
            "BLOCKED_SIDE_EFFECT_UNASSESSED", fresh_execution.content_id, arn, approved_name
        )
    if operation != AWS_CREATE_TAGS_OPERATION or operation != adapter.operation_id:
        return ExecutionResult("WRITE_UNSUPPORTED", fresh_execution.content_id, arn, approved_name)
    binding = _ExecutionBinding(fresh_execution.content_id, arn, approved_name, scope_id, operation)

    safety = check_target_safety(
        approval=fresh_name, scope=scope, side_effects=side_effects, now_utc=now
    )
    if not safety.allowed:
        return ExecutionResult(_safety_code(safety.code), fresh_execution.content_id, arn, approved_name)
    try:
        scope_state = ledger.effective_scope_state(scope_id)
    except LedgerError:
        return ExecutionResult("BLOCKED_SCOPE_STATE_UNKNOWN", fresh_execution.content_id, arn, approved_name)
    if scope_state != "CLEARED":
        code: ExecutionCode = "BLOCKED_SCOPE_HOLD" if scope_state == "HOLD" else "BLOCKED_SCOPE_STATE_UNKNOWN"
        return ExecutionResult(code, fresh_execution.content_id, arn, approved_name)

    try:
        tags = adapter.read_tags(arn)
    except OSError:
        return ExecutionResult("BLOCKED_SCOPE_STATE_UNKNOWN", fresh_execution.content_id, arn, approved_name)
    if any(key.casefold() == "name" and key != "Name" for key in tags):
        return ExecutionResult("BLOCKED_NAME_UNKNOWN", fresh_execution.content_id, arn, approved_name)
    actual_state = "ABSENT" if "Name" not in tags else "EMPTY" if tags["Name"] == "" else "NONEMPTY"
    if actual_state == "NONEMPTY":
        return ExecutionResult("BLOCKED_NAME_NONEMPTY", fresh_execution.content_id, arn, approved_name)
    if actual_state != name_payload.get("name_state_at_plan"):
        return ExecutionResult("BLOCKED_NAME_UNKNOWN", fresh_execution.content_id, arn, approved_name)

    try:
        handle = create_intent(
            ledger, fresh_execution, scope_id=scope_id,
            scope=scope, side_effects=[side_effects],
        )
        if handle.authorization_id != fresh_execution.content_id:
            raise LedgerError("BLOCKED_INTENT_REPLAY")
        permit = consume_first_send(ledger, handle)
    except LedgerError as error:
        code = _execution_error(error)
        if error.code == "BLOCKED_SCOPE_STATE_UNKNOWN":
            try:
                state = ledger.effective_scope_state(scope_id)
            except LedgerError:
                return ExecutionResult(
                    "BLOCKED_SCOPE_STATE_UNKNOWN", fresh_execution.content_id, arn, approved_name
                )
            if state == "HOLD":
                code = "BLOCKED_SCOPE_HOLD"
        return ExecutionResult(code, fresh_execution.content_id, arn, approved_name)

    if not _permit_matches(permit, binding, handle):
        try:
            hold_scope(ledger, scope_id, reason="first-send-permit-binding-mismatch")
        except LedgerError:
            return ExecutionResult("BLOCKED_SCOPE_STATE_UNKNOWN", fresh_execution.content_id, arn, approved_name)
        return ExecutionResult("BLOCKED_INTENT_REPLAY", fresh_execution.content_id, arn, approved_name)

    try:
        adapter.write_name_only(arn, approved_name)
    except OSError:
        return _record_outcome(
            ledger,
            handle,
            ExecutionResult("OUTCOME_UNKNOWN", binding.authorization_id, arn, approved_name),
        )
    try:
        readback = adapter.readback_tags(arn)
    except OSError:
        return _record_outcome(
            ledger,
            handle,
            ExecutionResult("OUTCOME_UNKNOWN", binding.authorization_id, arn, approved_name),
        )
    if any(key.casefold() == "name" and key != "Name" for key in readback):
        return _record_outcome(
            ledger,
            handle,
            ExecutionResult("OUTCOME_UNKNOWN", binding.authorization_id, arn, approved_name),
        )

    name_after = readback.get("Name")
    if name_after == approved_name:
        outcome: Literal["APPLIED_VERIFIED", "FAILED_READBACK"] = "APPLIED_VERIFIED"
    else:
        outcome = "FAILED_READBACK"
    return _record_outcome(
        ledger, handle,
        ExecutionResult(outcome, binding.authorization_id, arn, approved_name, name_after),
    )


def _offline_binding_matches(runtime: OfflineRuntimeContext, adapter: NameTagAdapter) -> bool:
    return (
        str(runtime.mode) == "offline"
        and str(runtime.source) == "test_harness"
        and getattr(runtime, "_provenance", None) is _OFFLINE_TEST_PROVENANCE
        and runtime.fake_adapter is adapter
    )


def _string_references(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        return ()
    references: list[str] = []
    for reference in value:
        if not isinstance(reference, str) or not reference:
            return ()
        references.append(reference)
    return tuple(references)


def _permit_matches(
    permit: FirstSendPermit,
    binding: _ExecutionBinding,
    handle: IntentHandle,
) -> bool:
    return (
        type(permit) is FirstSendPermit
        and permit.authorization_id == binding.authorization_id
        and permit.resource_arn == binding.resource_arn
        and permit.approved_name == binding.approved_name
        and permit.writer_control_scope_id == binding.scope_id
        and permit.aws_operation == binding.aws_operation
        and permit.execution_id == handle.execution_id
        and permit.ownership_token == handle.ownership_token
    )


def _record_outcome(
    ledger: IntentLedger,
    handle: IntentHandle,
    result: ExecutionResult,
) -> ExecutionResult:
    match result.code:
        case "APPLIED_VERIFIED" | "FAILED_READBACK" | "OUTCOME_UNKNOWN":
            try:
                record_readback(ledger, handle, name_after=result.name_after, outcome=result.code)
            except LedgerError as error:
                return ExecutionResult(
                    _execution_error(error), result.authorization_id, result.resource_arn,
                    result.approved_name, result.name_after,
                )
            return result
        case (
            "AWS_WRITE_BLOCKED"
            | "BLOCKED_OWNER_AUTHN"
            | "BLOCKED_SIDE_EFFECT_UNASSESSED"
            | "BLOCKED_WRITER_UNKNOWN"
            | "BLOCKED_SCOPE_EXPIRED"
            | "BLOCKED_SCOPE_HOLD"
            | "BLOCKED_INCOMPLETE_INTENT"
            | "BLOCKED_INTENT_REPLAY"
            | "BLOCKED_SCOPE_STATE_UNKNOWN"
            | "BLOCKED_SCOPE_MISMATCH"
            | "BLOCKED_NAME_NONEMPTY"
            | "BLOCKED_NAME_UNKNOWN"
            | "WRITE_UNSUPPORTED"
        ):
            return result
        case unexpected:
            assert_never(unexpected)


def _execution_error(error: LedgerError) -> ExecutionCode:
    match error.code:
        case "BLOCKED_AUTH_REPLAY":
            return "BLOCKED_INTENT_REPLAY"
        case "BLOCKED_AUTH_OWNER" | "BLOCKED_OWNER_AUTHN":
            return "BLOCKED_OWNER_AUTHN"
        case "BLOCKED_SCOPE_HOLD":
            return "BLOCKED_SCOPE_HOLD"
        case "BLOCKED_INCOMPLETE_INTENT":
            return "BLOCKED_INCOMPLETE_INTENT"
        case "BLOCKED_INTENT_REPLAY":
            return "BLOCKED_INTENT_REPLAY"
        case "BLOCKED_SCOPE_STATE_UNKNOWN":
            return "BLOCKED_SCOPE_STATE_UNKNOWN"
        case _:
            return "BLOCKED_SCOPE_STATE_UNKNOWN"


def _safety_code(code: str) -> ExecutionCode:
    match code:
        case "BLOCKED_OWNER_AUTHN":
            return "BLOCKED_OWNER_AUTHN"
        case "BLOCKED_SIDE_EFFECT_UNASSESSED":
            return "BLOCKED_SIDE_EFFECT_UNASSESSED"
        case "BLOCKED_WRITER_UNKNOWN":
            return "BLOCKED_WRITER_UNKNOWN"
        case "BLOCKED_SCOPE_EXPIRED":
            return "BLOCKED_SCOPE_EXPIRED"
        case "BLOCKED_SCOPE_MISMATCH":
            return "BLOCKED_SCOPE_MISMATCH"
        case _:
            return "BLOCKED_SCOPE_STATE_UNKNOWN"
