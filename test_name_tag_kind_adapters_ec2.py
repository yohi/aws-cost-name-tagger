"""Offline Task 5 tests: seven EC2-family one-Name adapters (fake injected clients only)."""
from __future__ import annotations

import copy
import dataclasses
import unittest
from types import MappingProxyType, SimpleNamespace
from unittest import mock

import name_tag_kind_capabilities as caps
from name_tag_batch_state import NameObservation
from name_tag_kind_adapters import (
    AdapterIdentityMismatch, AdapterRejected, AdapterUnavailable, adapter_for_capability,
    candidate_adapter)

ACCT, R = "123456789012", "ap-northeast-1"
GRANT = SimpleNamespace(token="structural-only")


class FakeClient:
    """Records every call; responses are keyed by operation name. No AWS involved."""

    def __init__(self, responses=None, **attrs):
        self.responses = responses or {}
        self.calls = []
        for k, v in attrs.items():
            setattr(self, k, v)

    def __getattr__(self, op):
        if op.startswith("_") or op not in self.responses and not op.endswith(("tags", "tag")) \
                and not op.startswith(("describe", "get", "list", "add", "put", "create", "tag")):
            raise AttributeError(op)

        def call(**kwargs):
            self.calls.append((op, kwargs))
            value = self.responses.get(op, {})
            return copy.deepcopy(value)
        return call


def make_target(kind, arn, scope=R, account=ACCT, proof=""):
    t = caps.canonical_target_identity(kind=kind, locator=arn, resource_arn=arn,
                                       partition="aws", account=account, scope_region=scope)
    return dataclasses.replace(t, ownership_proof_ref=proof)


def tl(*pairs):
    return [{"Key": k, "Value": v} for k, v in pairs]


EC2_CASES = {
    "instance": dict(
        arn=f"arn:aws:ec2:{R}:{ACCT}:instance/i-0123456789abcdef0", rid="i-0123456789abcdef0",
        read=("describe_instances", {"InstanceIds": ["i-0123456789abcdef0"]}),
        resp=lambda rid, tags, **k: {"Reservations": [{"Instances": [{"InstanceId": rid, "Tags": tags}]}]}),
    "volume": dict(
        arn=f"arn:aws:ec2:{R}:{ACCT}:volume/vol-0123456789abcdef0", rid="vol-0123456789abcdef0",
        read=("describe_volumes", {"VolumeIds": ["vol-0123456789abcdef0"]}),
        resp=lambda rid, tags, **k: {"Volumes": [{"VolumeId": rid, "Tags": tags}]}),
    "snapshot": dict(
        arn=f"arn:aws:ec2:{R}::snapshot/snap-0123456789abcdef0", rid="snap-0123456789abcdef0",
        read=("describe_snapshots", {"SnapshotIds": ["snap-0123456789abcdef0"]}), proof="owner-proof-1",
        resp=lambda rid, tags, owner=ACCT, **k: {"Snapshots": [{"SnapshotId": rid, "OwnerId": owner, "Tags": tags}]}),
    "eni": dict(
        arn=f"arn:aws:ec2:{R}:{ACCT}:network-interface/eni-0123456789abcdef0", rid="eni-0123456789abcdef0",
        read=("describe_network_interfaces", {"NetworkInterfaceIds": ["eni-0123456789abcdef0"]}),
        resp=lambda rid, tags, **k: {"NetworkInterfaces": [{"NetworkInterfaceId": rid, "TagSet": tags}]}),
    "eip": dict(
        arn=f"arn:aws:ec2:{R}:{ACCT}:elastic-ip/eipalloc-0123456789abcdef0", rid="eipalloc-0123456789abcdef0",
        read=("describe_addresses", {"AllocationIds": ["eipalloc-0123456789abcdef0"]}),
        resp=lambda rid, tags, **k: {"Addresses": [{"AllocationId": rid, "Tags": tags}]}),
    "nat": dict(
        arn=f"arn:aws:ec2:{R}:{ACCT}:natgateway/nat-0123456789abcdef0", rid="nat-0123456789abcdef0",
        read=("describe_nat_gateways", {"NatGatewayIds": ["nat-0123456789abcdef0"]}),
        resp=lambda rid, tags, **k: {"NatGateways": [{"NatGatewayId": rid, "Tags": tags}]}),
    "endpoint": dict(
        arn=f"arn:aws:ec2:{R}:{ACCT}:vpc-endpoint/vpce-0123456789abcdef0", rid="vpce-0123456789abcdef0",
        read=("describe_vpc_endpoints", {"VpcEndpointIds": ["vpce-0123456789abcdef0"]}),
        resp=lambda rid, tags, **k: {"VpcEndpoints": [{"VpcEndpointId": rid, "Tags": tags}]}),
}


def ec2_target(kind):
    c = EC2_CASES[kind]
    return make_target(kind, c["arn"], proof=c.get("proof", ""))


def proven(kind):
    decision = dataclasses.replace(caps.resolve_kind_capability(kind),
                                   status="IMPLEMENTED_OFFLINE", reason_code="OFFLINE_CONTRACT_COMPLETE",
                                   evidence_refs=("test-only fixture",))
    return mock.patch.object(caps, "_DECISIONS", MappingProxyType({**caps._DECISIONS, kind: decision}))


class Ec2AdapterTests(unittest.TestCase):
    def test_ec2_exact_one_name_request_per_7_kinds(self):
        for kind, c in EC2_CASES.items():
            with self.subTest(kind=kind):
                adapter = candidate_adapter(kind)
                target = ec2_target(kind)
                client = FakeClient()
                adapter.write_once(client, target, "app-prod-name", GRANT)
                self.assertEqual(client.calls, [("create_tags", {
                    "Resources": [c["rid"]], "Tags": [{"Key": "Name", "Value": "app-prod-name"}]})])
                op, kwargs = c["read"]
                for tags, state in ((tl(), "ABSENT"), (tl(("Name", "x"), ("Env", "p")), "NONEMPTY")):
                    rc = FakeClient({op: c["resp"](c["rid"], tags)})
                    self.assertEqual(adapter.read_current(rc, target).state, state)
                    self.assertEqual(rc.calls, [(op, kwargs)])
                    self.assertEqual(adapter.readback(rc, target).state, state)

    def test_ec2_response_identity_is_independently_verified(self):
        for kind, c in EC2_CASES.items():
            with self.subTest(kind=kind):
                rc = FakeClient({c["read"][0]: c["resp"]("wrong-id", tl())})
                with self.assertRaises(AdapterIdentityMismatch):
                    candidate_adapter(kind).read_current(rc, ec2_target(kind))

    def test_snapshot_owner_mismatch_and_missing_proof(self):
        c = EC2_CASES["snapshot"]
        adapter = candidate_adapter("snapshot")
        rc = FakeClient({c["read"][0]: c["resp"](c["rid"], tl(), owner="999999999999")})
        with self.assertRaises(AdapterIdentityMismatch):
            adapter.read_current(rc, ec2_target("snapshot"))
        client = FakeClient()
        with self.assertRaises(AdapterRejected) as cm:
            adapter.write_once(client, make_target("snapshot", c["arn"]), "n", GRANT)
        self.assertEqual(cm.exception.code, "ARN_OWNER_NOT_PROVEN")
        self.assertEqual(client.calls, [])

    def test_tags_malformed_or_paginated_is_unknown(self):
        bad = {
            "duplicate": tl(("Name", "a"), ("Name", "b")),
            "case_variant": tl(("name", "a")),
            "extra_item_key": [{"Key": "Name", "Value": "a", "X": "y"}],
            "non_string": [{"Key": "Name", "Value": 3}],
            "not_a_list": "oops",
        }
        for kind, c in EC2_CASES.items():
            adapter, target = candidate_adapter(kind), ec2_target(kind)
            op = c["read"][0]
            for label, tags in bad.items():
                with self.subTest(kind=kind, case=label):
                    rc = FakeClient({op: c["resp"](c["rid"], tags)})
                    self.assertEqual(adapter.read_current(rc, target),
                                     NameObservation("UNKNOWN", None, None))
            with self.subTest(kind=kind, case="paginated"):
                resp = c["resp"](c["rid"], tl())
                resp["NextToken"] = "more"
                self.assertEqual(adapter.readback(FakeClient({op: resp}), target).state, "UNKNOWN")
            with self.subTest(kind=kind, case="partial_missing_tags"):
                resp = c["resp"](c["rid"], tl())
                for holder in (resp.get("Reservations", [{}])[0].get("Instances", [resp])[0:1] if kind == "instance" else
                               [next(v for v in resp.values() if isinstance(v, list))[0]]):
                    holder.pop("Tags", None)
                    holder.pop("TagSet", None)
                self.assertEqual(adapter.read_current(FakeClient({op: resp}), target).state, "UNKNOWN")
            with self.subTest(kind=kind, case="two_resources"):
                resp = c["resp"](c["rid"], tl())
                if kind == "instance":
                    resp["Reservations"].append(copy.deepcopy(resp["Reservations"][0]))
                else:
                    lst = next(v for v in resp.values() if isinstance(v, list))
                    lst.append(copy.deepcopy(lst[0]))
                self.assertEqual(adapter.read_current(FakeClient({op: resp}), target).state, "UNKNOWN")

    def test_extra_tag_or_resource_rejected(self):
        adapter, target = candidate_adapter("instance"), ec2_target("instance")
        for bad in ("", " x", "x ", "a\nb", "n" * 257, None, 5):
            with self.subTest(name=bad):
                client = FakeClient()
                with self.assertRaises(AdapterRejected):
                    adapter.write_once(client, target, bad, GRANT)
                self.assertEqual(client.calls, [])
        client = FakeClient()
        with self.assertRaises(AdapterRejected):
            adapter.write_once(client, target, "ok", None)          # grant is structural but required
        with self.assertRaises(TypeError):                          # no caller SDK kwargs
            adapter.write_once(client, target, "ok", GRANT, Tags=[{"Key": "Other", "Value": "x"}])
        other = ec2_target("volume")                                # wrong-Kind target
        with self.assertRaises(AdapterRejected):
            adapter.write_once(client, other, "ok", GRANT)
        forged = dataclasses.replace(target, locator="i-0123456789abcdef1")  # alias/forged identity
        with self.assertRaises(AdapterRejected):
            adapter.write_once(client, forged, "ok", GRANT)
        self.assertEqual(client.calls, [])

    def test_missing_pinned_operation_is_sdk_unavailable(self):
        with self.assertRaises(AdapterUnavailable) as cm:
            candidate_adapter("instance", operation_names=lambda service: ())
        self.assertEqual(cm.exception.reason_code, "API_SDK_UNAVAILABLE")

    def test_dispatch_supports_only_implemented_offline_and_rejects_cnp_with_reason(self):
        self.assertEqual(adapter_for_capability(caps.resolve_kind_capability("volume")).kind, "volume")
        for kind in ("instance", "snapshot", "eni", "eip", "nat", "endpoint"):
            decision = caps.resolve_kind_capability(kind)
            with self.subTest(kind=kind), self.assertRaises(AdapterUnavailable) as cm:
                adapter_for_capability(decision)
            self.assertEqual(cm.exception.reason_code, decision.reason_code)
        with proven("instance"):   # test-only fixture; production decision untouched
            self.assertEqual(adapter_for_capability(caps.resolve_kind_capability("instance")).kind, "instance")
        self.assertEqual(caps.resolve_kind_capability("instance").status, "CAPABILITY_NOT_PROVEN")

    def test_forged_decision_is_rejected(self):
        forged = dataclasses.replace(caps.resolve_kind_capability("instance"),
                                     status="IMPLEMENTED_OFFLINE")
        with self.assertRaises(AdapterUnavailable):
            adapter_for_capability(forged)


if __name__ == "__main__":
    unittest.main()
