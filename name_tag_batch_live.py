"""Fail-closed EC2 volume Name write boundary for future verified host runtimes."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Final, Protocol, TypedDict

from name_tag_batch_approval import VerifiedBatchRowAuthority
from name_tag_batch_credentials import IssuedBatchSession
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


class AuthorizedBatchWritePort:
    """Issue one injected EC2 call only when a trusted runtime gate exists."""

    def __init__(self, client: EC2CreateTagsClient) -> None:
        self._client = client

    def write_once(
        self,
        *,
        session: IssuedBatchSession,
        row: VerifiedBatchRowAuthority,
        permit: FirstSendPermit,
        runtime: AuthorizedBatchRuntimePolicy,
    ) -> None:
        """Refuse until a protected host verifier can mint policy provenance."""
        raise LiveWriteBlocked("AWS_RUNTIME_NOT_AUTHORIZED")
