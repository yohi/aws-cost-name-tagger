"""Evidence-gated, single-Name-key SDK adapters (shared contract and dispatch).

Pure and offline: no boto3 client is ever constructed here; callers inject the client.
An adapter builds exactly one request for exactly one resource carrying exactly one
``Name`` tag; it never accepts caller-supplied SDK kwargs, never replaces a tag set and
never calls ``put_bucket_tagging``. Reads fail closed: malformed, duplicate, ambiguous,
partial or paginated tag sets are ``UNKNOWN`` (never ``ABSENT``).
The write method accepts a protected grant structurally only. Its presence is NOT
authorization; the actual send requires the Host verifier's one-use dispatch binding,
which this adapter consumes immediately before touching the SDK client.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Protocol

from name_tag_batch_state import NameObservation, classify_batch_name
from name_tag_kind_capabilities import (
    CanonicalTargetIdentity, KindCapabilityDecision, canonical_target_identity,
    resolve_kind_capability)

UNKNOWN = NameObservation("UNKNOWN", None, None)
_NAME_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Policy-level hard blocks that no decision value can override at dispatch.
_PROMOTION_BLOCKS = {"apigw_stage": "IAM_CONDITION_NOT_PROVEN"}


class AdapterRejected(RuntimeError):
    def __init__(self, code: str, kind: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.kind = kind


class AdapterUnavailable(AdapterRejected):
    """The Kind has no supportable offline adapter; carries the CNP reason_code."""

    def __init__(self, reason_code: str, kind: str = "") -> None:
        super().__init__(reason_code, kind)
        self.reason_code = reason_code


class AdapterIdentityMismatch(AdapterRejected):
    """A response described a different resource than the approved target."""


class _Unknown(Exception):
    """Internal: response is malformed/partial/ambiguous -> UNKNOWN observation."""


class _Mismatch(Exception):
    pass


class KindWriteAdapter(Protocol):
    def read_current(self, client: object, target: CanonicalTargetIdentity) -> NameObservation: ...
    def write_once(self, client: object, target: CanonicalTargetIdentity, name: str,
                   dispatch_binding: object) -> None: ...
    def readback(self, client: object, target: CanonicalTargetIdentity) -> NameObservation: ...


def pinned_operation_names(service: str) -> frozenset[str]:
    """snake_case operation names from the pinned botocore model (no client built)."""
    from botocore import xform_name
    from botocore.loaders import create_loader
    model = create_loader().load_service_model(service, "service-2")
    return frozenset(xform_name(op) for op in model["operations"])


# Call = (service, operation, kwargs)
Call = tuple[str, str, dict]


@dataclass(frozen=True)
class AdapterSpec:
    kind: str
    service: str                                    # registry service
    write_operation: str                            # snake_case SDK op
    reads: Callable[[CanonicalTargetIdentity], tuple[Call, ...]]
    extract: Callable[[CanonicalTargetIdentity, list], Any]   # -> tag list / dict
    write_kwargs: Callable[[CanonicalTargetIdentity, str], dict]
    required_ops: tuple[tuple[str, str], ...] = ()  # (service, snake op) read ops
    needs_ownership_proof: bool = False


def resource_part(target: CanonicalTargetIdentity) -> str:
    return target.resource_arn.split(":", 5)[5]


def one(items: object) -> dict:
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise _Unknown()
    return items[0]


def same(actual: object, expected: str) -> None:
    if not isinstance(actual, str):
        raise _Unknown()
    if actual != expected:
        raise _Mismatch()


def name_tag(name: str) -> list[dict]:
    return [{"Key": "Name", "Value": name}]


def _paginated(response: dict) -> bool:
    return any(isinstance(k, str) and k.lower().endswith(("token", "marker")) and v
               for k, v in response.items())


class SingleNameAdapter:
    """Table-driven adapter: one resource, one Name key, no caller kwargs."""

    def __init__(self, spec: AdapterSpec,
                 operation_names: Callable[[str], Iterable[str]] = pinned_operation_names
                 ) -> None:
        self._spec = spec
        self.kind = spec.kind
        needed = {(spec.service, spec.write_operation)}
        needed.update(spec.required_ops)
        for service, op in sorted(needed):
            if op not in set(operation_names(service)):
                raise AdapterUnavailable("API_SDK_UNAVAILABLE", spec.kind)

    # -- hooks -----------------------------------------------------------------
    def _invoke(self, client: object, service: str, op: str, kwargs: dict) -> object:
        return getattr(client, op)(**kwargs)

    def _preflight_write(self, client: object, target: CanonicalTargetIdentity) -> None:
        return None

    # -- contract --------------------------------------------------------------
    def _check(self, target: CanonicalTargetIdentity) -> None:
        try:
            if not isinstance(target, CanonicalTargetIdentity) or target.kind != self.kind:
                raise ValueError("kind")
            canonical_target_identity(
                kind=target.kind, locator=target.locator, resource_arn=target.resource_arn,
                partition=target.partition, account=target.owner_account,
                scope_region=target.scope_region)
        except ValueError as exc:
            raise AdapterRejected("TARGET_INVALID", self.kind) from exc

    def _observe(self, client: object, target: CanonicalTargetIdentity) -> NameObservation:
        self._check(target)
        responses = []
        for service, op, kwargs in self._spec.reads(target):
            response = self._invoke(client, service, op, dict(kwargs))
            if not isinstance(response, dict):
                return UNKNOWN
            if _paginated(response):
                return UNKNOWN
            responses.append(response)
        try:
            tags = self._spec.extract(target, responses)
        except _Mismatch:
            raise AdapterIdentityMismatch("IDENTITY_MISMATCH", self.kind) from None
        except (_Unknown, KeyError, TypeError, IndexError, AttributeError):
            return UNKNOWN
        return classify_batch_name(tags)

    def read_current(self, client: object, target: CanonicalTargetIdentity) -> NameObservation:
        return self._observe(client, target)

    def readback(self, client: object, target: CanonicalTargetIdentity) -> NameObservation:
        return self._observe(client, target)

    def write_once(self, client: object, target: CanonicalTargetIdentity, name: str,
                   dispatch_binding: object) -> None:
        self._check(target)
        if dispatch_binding is None:
            raise AdapterRejected("GRANT_REQUIRED", self.kind)
        if (not isinstance(name, str) or not name or name != name.strip()
                or len(name) > 256 or _NAME_CONTROL.search(name)):
            raise AdapterRejected("NAME_INVALID", self.kind)
        if self._spec.needs_ownership_proof and not target.ownership_proof_ref:
            raise AdapterRejected("ARN_OWNER_NOT_PROVEN", self.kind)
        from name_tag_batch_host_runtime import HostRuntimeBlocked
        from name_tag_batch_iam_evidence import consume_host_dispatch_binding

        try:
            consume_host_dispatch_binding(
                dispatch_binding, target=target, name=name, kind=self.kind)
        except HostRuntimeBlocked as error:
            raise AdapterRejected(error.code, self.kind) from error
        self._preflight_write(client, target)
        kwargs = self._spec.write_kwargs(target, name)
        self._invoke(client, self._spec.service, self._spec.write_operation, kwargs)


def candidate_adapter(kind: str, operation_names: Callable[[str], Iterable[str]]
                      = pinned_operation_names) -> KindWriteAdapter:
    """Candidate-shape adapter for tests/evaluation; NOT a promotion decision."""
    from name_tag_kind_adapters_ec2 import EC2_SPECS
    from name_tag_kind_adapters_services import build_service_adapter, SERVICE_SPECS
    if kind in EC2_SPECS:
        return SingleNameAdapter(EC2_SPECS[kind], operation_names)
    if kind in SERVICE_SPECS:
        return build_service_adapter(kind, operation_names)
    raise AdapterUnavailable("API_SDK_UNAVAILABLE", str(kind))


def adapter_for_capability(decision: KindCapabilityDecision) -> KindWriteAdapter:
    """Return a vetted adapter only for a genuine, IMPLEMENTED_OFFLINE Registry decision."""
    try:
        genuine = resolve_kind_capability(decision.kind)
    except (ValueError, AttributeError):
        raise AdapterUnavailable("API_SDK_UNAVAILABLE", str(getattr(decision, "kind", ""))) from None
    if decision != genuine:
        raise AdapterUnavailable("NAME_EVIDENCE_NOT_PROVEN", genuine.kind)
    if genuine.status != "IMPLEMENTED_OFFLINE":
        raise AdapterUnavailable(genuine.reason_code, genuine.kind)
    if genuine.tag_set_replacement:
        raise AdapterUnavailable("UNSUPPORTED_BY_POLICY", genuine.kind)
    if genuine.kind in _PROMOTION_BLOCKS:
        raise AdapterUnavailable(_PROMOTION_BLOCKS[genuine.kind], genuine.kind)
    adapter = candidate_adapter(genuine.kind)
    spec = adapter._spec  # type: ignore[attr-defined]
    contract = genuine.sdk_request_contract
    if contract.startswith(spec.service + "."):
        contract = contract[len(spec.service) + 1:]
    if spec.service != genuine.service or not contract.startswith(spec.write_operation + "("):
        raise AdapterUnavailable("API_SDK_UNAVAILABLE", genuine.kind)
    return adapter
