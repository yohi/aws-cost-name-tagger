"""Offline-safe EC2 volume adapter and pure Name-only request builder."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Protocol, TypeAlias

EC2_CREATE_TAGS_OPERATION = "ec2:CreateTags:2016-11-15"
_ACCOUNT_RE = re.compile(r"[0-9]{12}\Z", re.ASCII)
_ARN_RE = re.compile(
    r"arn:(aws|aws-cn|aws-us-gov):ec2:([a-z0-9-]+):([0-9]{12}):(volume/)(vol-(?:[0-9a-f]{8}|[0-9a-f]{17}))\Z",
    re.ASCII,
)
JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
Ec2Response: TypeAlias = Mapping[str, JsonValue]


class AdapterError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class Ec2ReadClient(Protocol):
    def describe_volumes(self, *, VolumeIds: list[str]) -> Ec2Response: ...


def _volume_id(resource_arn: str, account: str, region: str) -> str:
    match = _ARN_RE.fullmatch(resource_arn)
    if (
        match is None
        or not _ACCOUNT_RE.fullmatch(account)
        or match.group(3) != account
        or match.group(2) != region
    ):
        raise AdapterError("BLOCKED_SCOPE_MISMATCH")
    return match.group(5)


def build_volume_name_request(
    resource_arn: str,
    approved_name: str,
    *,
    account: str,
    region: str,
) -> dict[str, object]:  # noqa: DICT_OK, OBJECT_OK
    """Build exact EC2 CreateTags arguments without invoking a client."""
    volume_id = _volume_id(resource_arn, account, region)
    if not isinstance(approved_name, str) or not approved_name:
        raise AdapterError("BLOCKED_NAME_UNKNOWN")
    return {"Resources": [volume_id], "Tags": [{"Key": "Name", "Value": approved_name}]}


class EC2VolumeAdapter:
    """Read one injected EC2 volume; Phase-A writes are unconditionally blocked."""

    operation_id: str

    def __init__(self, client: Ec2ReadClient, *, account: str, region: str) -> None:
        if not _ACCOUNT_RE.fullmatch(account) or not isinstance(region, str) or not region:
            raise AdapterError("BLOCKED_SCOPE_MISMATCH")
        self._client = client
        self.account = account
        self.region = region
        self.operation_id = EC2_CREATE_TAGS_OPERATION

    def _read_volume(self, resource_arn: str) -> Mapping[str, str]:
        volume_id = _volume_id(resource_arn, self.account, self.region)
        try:
            response = self._client.describe_volumes(VolumeIds=[volume_id])
        except OSError as exc:
            raise AdapterError("BLOCKED_NAME_UNKNOWN") from exc
        next_token = response.get("NextToken")
        if next_token is not None:
            raise AdapterError("BLOCKED_NAME_UNKNOWN")
        volumes = response.get("Volumes")
        if not isinstance(volumes, list) or len(volumes) != 1:
            raise AdapterError("BLOCKED_NAME_UNKNOWN")
        volume = volumes[0]
        if not isinstance(volume, Mapping) or volume.get("VolumeId") != volume_id:
            raise AdapterError("BLOCKED_NAME_UNKNOWN")
        state = volume.get("State")
        attachments = volume.get("Attachments")
        if not isinstance(attachments, list):
            raise AdapterError("BLOCKED_NAME_UNKNOWN")
        if state == "available":
            if attachments:
                raise AdapterError("BLOCKED_NAME_UNKNOWN")
        elif state == "in-use":
            if not attachments or any(
                not isinstance(item, Mapping)
                or item.get("VolumeId") != volume_id
                or item.get("State") != "attached"
                or not isinstance(item.get("InstanceId"), str)
                or not isinstance(item.get("Device"), str)
                for item in attachments
            ):
                raise AdapterError("BLOCKED_NAME_UNKNOWN")
        else:
            raise AdapterError("BLOCKED_NAME_UNKNOWN")

        raw_tags = volume.get("Tags")
        if raw_tags is None:
            raw_tags = []
        if not isinstance(raw_tags, list):
            raise AdapterError("BLOCKED_NAME_UNKNOWN")
        tags: dict[str, str] = {}
        for tag in raw_tags:
            if not isinstance(tag, Mapping):
                raise AdapterError("BLOCKED_NAME_UNKNOWN")
            key = tag.get("Key")
            value = tag.get("Value")
            if not isinstance(key, str) or not isinstance(value, str):
                raise AdapterError("BLOCKED_NAME_UNKNOWN")
            if key.casefold() == "name" and key != "Name":
                raise AdapterError("BLOCKED_NAME_UNKNOWN")
            if key in tags:
                raise AdapterError("BLOCKED_NAME_UNKNOWN")
            tags[key] = value
        return tags

    def read_tags(self, resource_arn: str) -> Mapping[str, str]:
        return self._read_volume(resource_arn)

    def write_name_only(self, resource_arn: str, approved_name: str) -> None:
        raise AdapterError("AWS_WRITE_BLOCKED")

    def readback_tags(self, resource_arn: str) -> Mapping[str, str]:
        return self._read_volume(resource_arn)


def adapter_for_kind(
    kind: str,
    client: Ec2ReadClient,
    *,
    account: str,
    region: str,
) -> EC2VolumeAdapter:
    if kind != "volume":
        raise AdapterError("WRITE_UNSUPPORTED")
    return EC2VolumeAdapter(client, account=account, region=region)
