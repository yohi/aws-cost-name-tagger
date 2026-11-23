"""Fail-closed EC2 volume Name write boundary for future verified host runtimes."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, Protocol, TypedDict

from name_tag_batch_approval import VerifiedBatchRowAuthority
from name_tag_batch_credentials import IssuedBatchSession
from name_tag_kind_adapters import (
    AdapterRejected, KindWriteAdapter, adapter_for_capability)
from name_tag_kind_capabilities import resolve_kind_capability
from name_tag_ledger import FirstSendPermit


_VOLUME_ARN: Final = re.compile(
    r"\Aarn:(?P<partition>aws(?:-cn|-us-gov)?):ec2:"
    r"(?P<region>[a-z]{2}(?:-gov)?-[a-z]+-\d):"
    r"(?P<account>\d{12}):volume/(?P<volume_id>vol-[0-9a-f]{17})\Z",
    re.ASCII,
)
_NAME_CONTROL: Final = re.compile(r"[\x00-\x1f\x7f]")


class LiveWriteBlocked(RuntimeError):
    """A live-write gate is missing, mismatched, or not independently proven."""

    def __init__(self, code: str = "AWS_WRITE_BLOCKED") -> None:
        super().__init__(code)
        self.code = code


class EC2CreateTagsClient(Protocol):
    def create_tags(self, **kwargs: object) -> object: ...


class CreateTagsRequest(TypedDict):
    Resources: list[str]
    Tags: list[dict[str, str]]


def build_volume_create_tags_request(
    *, resource_arn: str, approved_name: str
) -> CreateTagsRequest:
    """Build the only supported request shape; this does not confer authority."""
    match = _VOLUME_ARN.fullmatch(resource_arn)
    if match is None:
        raise LiveWriteBlocked("WRITE_UNSUPPORTED")
    if (
        not approved_name
        or approved_name != approved_name.strip()
        or len(approved_name) > 256
        or _NAME_CONTROL.search(approved_name) is not None
    ):
        raise LiveWriteBlocked("BLOCKED_OWNER_AUTHN")
    return {
        "Resources": [match.group("volume_id")],
        "Tags": [{"Key": "Name", "Value": approved_name}],
    }


def protected_registry_adapter(kind: str) -> KindWriteAdapter:
    """Protected Registry dispatch: only a genuine IMPLEMENTED_OFFLINE Kind yields an adapter.

    Returning an adapter grants no authority and builds no client; the Host verifier
    still authorizes the actual send. Everything else stays denied by default.
    """
    try:
        return adapter_for_capability(resolve_kind_capability(kind))
    except (ValueError, AdapterRejected) as exc:
        raise LiveWriteBlocked(getattr(exc, "code", "WRITE_UNSUPPORTED")) from exc


@dataclass(frozen=True, slots=True)
class AuthorizedBatchRuntimePolicy:
    """Opaque runtime binding; a constructed instance is not a trusted policy."""

    batch_id: str
    row_authority_id: str
    account: str
    partition: str
    region: str
    resource_arn: str
    approved_name: str
    aws_operation: str
    session_identity: int
    permit_identity: int


# Obligation (g): the S3 adapter's tag-set-replacement property is UNPROVEN, so S3 is never a
# dispatchable live Kind here even if a Registry decision were promoted.
_LIVE_DISPATCH_BLOCKED: Final = {"s3_bucket": "TAG_SET_REPLACEMENT_NOT_PROVEN"}


def live_dispatch_adapter(kind: str) -> KindWriteAdapter:
    """Protected Registry adapter for a live dispatch; S3 stays non-dispatchable."""
    if kind in _LIVE_DISPATCH_BLOCKED:
        raise LiveWriteBlocked(_LIVE_DISPATCH_BLOCKED[kind])
    return protected_registry_adapter(kind)


class AuthorizedBatchWritePort:
    """Issue one injected SDK call only when a genuine one-shot runtime grant is consumed.

    A caller-constructed ``AuthorizedBatchRuntimePolicy`` (or anything that is not the
    Host verifier's ``VerifiedRuntimeGrant``) is always refused. With a grant, the live-only
    ``consume_runtime_grant`` is called at this same dispatch, before the client is touched;
    the test-only synthetic consumer is never imported or reachable from here.
    """

    def __init__(self, client: object, *, adapter: KindWriteAdapter | None = None,
                 target: object = None, clock=None) -> None:
        self._client = client
        self._adapter = adapter
        self._target = target
        self._clock = clock

    def write_once(
        self,
        *,
        session: IssuedBatchSession,
        row: VerifiedBatchRowAuthority,
        permit: FirstSendPermit,
        runtime: AuthorizedBatchRuntimePolicy,
    ) -> None:
        from name_tag_batch_host_issuer import HostIssuedSession
        from name_tag_batch_host_runtime import HostRuntimeBlocked
        from name_tag_batch_iam_evidence import VerifiedRuntimeGrant, consume_runtime_grant

        grant = runtime
        if (type(grant) is not VerifiedRuntimeGrant or self._adapter is None
                or self._target is None or self._clock is None):
            raise LiveWriteBlocked("AWS_RUNTIME_NOT_AUTHORIZED")
        if (type(session) is not HostIssuedSession
                or grant.receipt_sha256 != session.receipt.receipt_sha256
                or type(permit) is not FirstSendPermit
                or permit.approved_name != grant.approved_name
                or permit.resource_arn != grant.resource_arn):
            raise LiveWriteBlocked("AWS_RUNTIME_NOT_AUTHORIZED")
        try:
            dispatch_binding = consume_runtime_grant(
                grant, row=row, permit=permit, target=self._target, client=self._client,
                now_utc=self._clock())
        except HostRuntimeBlocked as error:
            raise LiveWriteBlocked(error.code) from error
        self._adapter.write_once(
            self._client, self._target, permit.approved_name, dispatch_binding)
