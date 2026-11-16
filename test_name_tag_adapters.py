from __future__ import annotations

import unittest
from collections.abc import Mapping
from typing import Protocol

from name_tag_adapters import (
    AdapterError,
    Ec2Response,
    EC2VolumeAdapter,
    JsonValue,
    adapter_for_kind,
    build_volume_name_request,
)

ARN = "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0"
VOLUME_ID = "vol-0123456789abcdef0"
NAME = "web-prod"


class FakeDescribeClient(Protocol):
    def describe_volumes(self, *, VolumeIds: list[str]) -> Ec2Response: ...


class FakeSdk:
    def __init__(self, response: Mapping[str, JsonValue]) -> None:
        self.response = response
        self.calls: list[list[str]] = []

    def describe_volumes(self, *, VolumeIds: list[str]) -> Ec2Response:
        self.calls.append(list(VolumeIds))
        return self.response


class FakeVolumeAdapter:
    operation_id = "ec2:CreateTags:2016-11-15"

    def __init__(self, tags: Mapping[str, str] | None = None) -> None:
        self.tags = dict(tags or {})
        self.calls: list[dict[str, object]] = []

    def read_tags(self, resource_arn: str) -> Mapping[str, str]:
        return dict(self.tags)

    def write_name_only(self, resource_arn: str, approved_name: str) -> None:
        request = build_volume_name_request(
            resource_arn, approved_name, account="123456789012", region="us-east-1"
        )
        self.calls.append(request)
        self.tags["Name"] = approved_name

    def readback_tags(self, resource_arn: str) -> Mapping[str, str]:
        return dict(self.tags)


def volume_response(
    *,
    volume_id: str = VOLUME_ID,
    state: str = "available",
    attachments: list[dict[str, str]] | None = None,
    tags: list[dict[str, str]] | None = None,
    next_token: str | None = None,
) -> dict[str, JsonValue]:
    attachment_values: list[JsonValue] = []
    for attachment in attachments or []:
        item: dict[str, JsonValue] = {}
        item.update(attachment)
        attachment_values.append(item)
    tag_values: list[JsonValue] = []
    for tag in tags if tags is not None else [{"Key": "Name", "Value": ""}]:
        item = {}
        item.update(tag)
        tag_values.append(item)
    volume: dict[str, JsonValue] = {
        "VolumeId": volume_id,
        "State": state,
        "Attachments": attachment_values,
        "Tags": tag_values,
    }
    response: dict[str, JsonValue] = {"Volumes": [volume]}
    if next_token is not None:
        response["NextToken"] = next_token
    return response


class VolumeAdapterTests(unittest.TestCase):
    def test_volume_exact_name_only_request(self):
        request = build_volume_name_request(
            ARN, NAME, account="123456789012", region="us-east-1"
        )
        self.assertEqual(
            request,
            {"Resources": [VOLUME_ID], "Tags": [{"Key": "Name", "Value": NAME}]},
        )
        fake = FakeVolumeAdapter({"Product": "service", "Name": ""})
        fake.write_name_only(ARN, NAME)
        self.assertEqual(fake.calls, [request])
        self.assertEqual(fake.readback_tags(ARN), {"Product": "service", "Name": NAME})

    def test_set_replacement_unsupported(self):
        request = build_volume_name_request(
            ARN, NAME, account="123456789012", region="us-east-1"
        )
        self.assertEqual(set(request), {"Resources", "Tags"})
        self.assertEqual(request["Tags"], [{"Key": "Name", "Value": NAME}])

    def test_region_account_id_mismatch(self):
        for account, region in (("000000000000", "us-east-1"), ("123456789012", "us-west-2")):
            with self.subTest(account=account, region=region):
                with self.assertRaises(AdapterError) as ctx:
                    build_volume_name_request(ARN, NAME, account=account, region=region)
                self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_MISMATCH")

    def test_noncanonical_volume_id_rejected(self):
        malformed_arn = "arn:aws:ec2:us-east-1:123456789012:volume/vol-123456789"
        with self.assertRaises(AdapterError) as ctx:
            build_volume_name_request(
                malformed_arn, NAME, account="123456789012", region="us-east-1"
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_MISMATCH")

    def test_malformed_or_paginated_tags_unknown(self):
        cases = (
            volume_response(next_token="next-page"),
            volume_response(next_token=""),
            volume_response(tags=[{"Key": "Name"}]),
            volume_response(tags=[{"Key": "Name", "Value": ""}, {"Key": "Name", "Value": ""}]),
            volume_response(volume_id="vol-fffffffffffffffff"),
            volume_response(state="creating"),
            volume_response(state="in-use", attachments=[]),
            volume_response(
                state="in-use",
                attachments=[{"VolumeId": VOLUME_ID + "x", "InstanceId": "i-1", "State": "attached", "Device": "/dev/sda1"}],
            ),
        )
        for response in cases:
            with self.subTest(response=response):
                adapter = EC2VolumeAdapter(
                    FakeSdk(response), account="123456789012", region="us-east-1"
                )
                with self.assertRaises(AdapterError) as ctx:
                    adapter.read_tags(ARN)
                self.assertEqual(ctx.exception.code, "BLOCKED_NAME_UNKNOWN")

    def test_untagged_volume_without_tags_field_is_absent(self):
        response = volume_response()
        volumes = response["Volumes"]
        assert isinstance(volumes, list)
        volume = volumes[0]
        assert isinstance(volume, dict)
        volume.pop("Tags")
        adapter = EC2VolumeAdapter(
            FakeSdk(response), account="123456789012", region="us-east-1"
        )
        self.assertEqual(adapter.read_tags(ARN), {})

    def test_in_use_volume_attachment_read_is_validated(self):
        response = volume_response(
            state="in-use",
            attachments=[{"VolumeId": VOLUME_ID, "InstanceId": "i-0123456789abcdef0", "State": "attached", "Device": "/dev/sda1"}],
        )
        client = FakeSdk(response)
        adapter = EC2VolumeAdapter(client, account="123456789012", region="us-east-1")
        self.assertEqual(adapter.read_tags(ARN), {"Name": ""})
        self.assertEqual(client.calls, [[VOLUME_ID]])

    def test_unimplemented_kind_blocked(self):
        with self.assertRaises(AdapterError) as ctx:
            adapter_for_kind("snapshot", FakeSdk(volume_response()), account="123456789012", region="us-east-1")
        self.assertEqual(ctx.exception.code, "WRITE_UNSUPPORTED")

    def test_direct_adapter_write_always_blocked(self):
        client = FakeSdk(volume_response())
        adapter = EC2VolumeAdapter(client, account="123456789012", region="us-east-1")
        with self.assertRaises(AdapterError) as ctx:
            adapter.write_name_only(ARN, NAME)
        self.assertEqual(ctx.exception.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(client.calls, [])
