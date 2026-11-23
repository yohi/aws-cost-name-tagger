"""Offline Task 5 tests: eleven non-EC2 Kind candidate shapes or explicit CNP."""
from __future__ import annotations

import copy
import dataclasses
import unittest
from types import SimpleNamespace

import name_tag_kind_capabilities as caps
from name_tag_kind_adapters import (
    AdapterIdentityMismatch, AdapterRejected, AdapterUnavailable, adapter_for_capability,
    candidate_adapter, pinned_operation_names)
from test_name_tag_kind_adapters_ec2 import ACCT, GRANT, R, FakeClient, make_target, proven, tl

UUID = "0123abcd-0123-4abc-8abc-0123456789ab"
N = "app-prod-name"


def _kv(tags):
    return {t["Key"]: t["Value"] for t in tags} if isinstance(tags, list) else tags


CASES = {
    "rds_cluster": dict(
        arn=f"arn:aws:rds:{R}:{ACCT}:cluster:mycluster",
        reads=[("describe_db_clusters", {"DBClusterIdentifier": "mycluster"}),
               ("list_tags_for_resource", {"ResourceName": f"arn:aws:rds:{R}:{ACCT}:cluster:mycluster"})],
        resp=lambda arn, tags: {"describe_db_clusters": {"DBClusters": [{"DBClusterArn": arn}]},
                                "list_tags_for_resource": {"TagList": tags}},
        write=("add_tags_to_resource", lambda arn: {"ResourceName": arn, "Tags": tl(("Name", N))})),
    "rds_instance": dict(
        arn=f"arn:aws:rds:{R}:{ACCT}:db:mydb",
        reads=[("describe_db_instances", {"DBInstanceIdentifier": "mydb"}),
               ("list_tags_for_resource", {"ResourceName": f"arn:aws:rds:{R}:{ACCT}:db:mydb"})],
        resp=lambda arn, tags: {"describe_db_instances": {"DBInstances": [{"DBInstanceArn": arn}]},
                                "list_tags_for_resource": {"TagList": tags}},
        write=("add_tags_to_resource", lambda arn: {"ResourceName": arn, "Tags": tl(("Name", N))})),
    "opensearch": dict(
        arn=f"arn:aws:es:{R}:{ACCT}:domain/mydomain",
        reads=[("describe_domain", {"DomainName": "mydomain"}),
               ("list_tags", {"ARN": f"arn:aws:es:{R}:{ACCT}:domain/mydomain"})],
        resp=lambda arn, tags: {"describe_domain": {"DomainStatus": {"ARN": arn}},
                                "list_tags": {"TagList": tags}},
        write=("add_tags", lambda arn: {"ARN": arn, "TagList": tl(("Name", N))})),
    "elbv2": dict(
        arn=f"arn:aws:elasticloadbalancing:{R}:{ACCT}:loadbalancer/app/my-lb/0123456789abcdef",
        reads=[("describe_load_balancers", {"LoadBalancerArns": [f"arn:aws:elasticloadbalancing:{R}:{ACCT}:loadbalancer/app/my-lb/0123456789abcdef"]}),
               ("describe_tags", {"ResourceArns": [f"arn:aws:elasticloadbalancing:{R}:{ACCT}:loadbalancer/app/my-lb/0123456789abcdef"]})],
        resp=lambda arn, tags: {"describe_load_balancers": {"LoadBalancers": [{"LoadBalancerArn": arn}]},
                                "describe_tags": {"TagDescriptions": [{"ResourceArn": arn, "Tags": tags}]}},
        write=("add_tags", lambda arn: {"ResourceArns": [arn], "Tags": tl(("Name", N))})),
    "apigw_stage": dict(
        arn=f"arn:aws:apigateway:{R}::/restapis/abcde12345/stages/prod",
        reads=[("get_stage", {"restApiId": "abcde12345", "stageName": "prod"}),
               ("get_tags", {"resourceArn": f"arn:aws:apigateway:{R}::/restapis/abcde12345/stages/prod"})],
        resp=lambda arn, tags: {"get_stage": {"stageName": "prod", "tags": _kv(tags)},
                                "get_tags": {"tags": _kv(tags)}},
        write=("tag_resource", lambda arn: {"resourceArn": arn, "tags": {"Name": N}})),
    "cloudfront": dict(
        arn=f"arn:aws:cloudfront::{ACCT}:distribution/EABCDEFGHIJ1", scope="global",
        reads=[("get_distribution", {"Id": "EABCDEFGHIJ1"}),
               ("list_tags_for_resource", {"Resource": f"arn:aws:cloudfront::{ACCT}:distribution/EABCDEFGHIJ1"})],
        resp=lambda arn, tags: {"get_distribution": {"Distribution": {"Id": "EABCDEFGHIJ1", "ARN": arn}},
                                "list_tags_for_resource": {"Tags": {"Items": tags}}},
        write=("tag_resource", lambda arn: {"Resource": arn, "Tags": {"Items": tl(("Name", N))}})),
    "athena_workgroup": dict(
        arn=f"arn:aws:athena:{R}:{ACCT}:workgroup/wg1",
        reads=[("get_work_group", {"WorkGroup": "wg1"}),
               ("list_tags_for_resource", {"ResourceARN": f"arn:aws:athena:{R}:{ACCT}:workgroup/wg1"})],
        resp=lambda arn, tags: {"get_work_group": {"WorkGroup": {"Name": "wg1"}},
                                "list_tags_for_resource": {"Tags": tags}},
        write=("tag_resource", lambda arn: {"ResourceARN": arn, "Tags": tl(("Name", N))})),
    "log_group": dict(
        arn=f"arn:aws:logs:{R}:{ACCT}:log-group:/aws/app",
        reads=[("describe_log_groups", {"logGroupNamePrefix": "/aws/app"}),
               ("list_tags_for_resource", {"resourceArn": f"arn:aws:logs:{R}:{ACCT}:log-group:/aws/app"})],
        resp=lambda arn, tags: {"describe_log_groups": {"logGroups": [
            {"logGroupName": "/aws/app2", "arn": arn + "2:*"}, {"logGroupName": "/aws/app", "arn": arn + ":*"}]},
            "list_tags_for_resource": {"tags": _kv(tags)}},
        write=("tag_resource", lambda arn: {"resourceArn": arn, "tags": {"Name": N}})),
    "lambda": dict(
        arn=f"arn:aws:lambda:{R}:{ACCT}:function:fn",
        reads=[("get_function", {"FunctionName": f"arn:aws:lambda:{R}:{ACCT}:function:fn"}),
               ("list_tags", {"Resource": f"arn:aws:lambda:{R}:{ACCT}:function:fn"})],
        resp=lambda arn, tags: {"get_function": {"Configuration": {"FunctionArn": arn}},
                                "list_tags": {"Tags": _kv(tags)}},
        write=("tag_resource", lambda arn: {"Resource": arn, "Tags": {"Name": N}})),
    "wafv2": dict(
        arn=f"arn:aws:wafv2:{R}:{ACCT}:regional/webacl/acl/{UUID}",
        reads=[("get_web_acl", {"Name": "acl", "Scope": "REGIONAL", "Id": UUID}),
               ("list_tags_for_resource", {"ResourceARN": f"arn:aws:wafv2:{R}:{ACCT}:regional/webacl/acl/{UUID}"})],
        resp=lambda arn, tags: {"get_web_acl": {"WebACL": {"ARN": arn}},
                                "list_tags_for_resource": {"TagInfoForResource": {"ResourceARN": arn, "TagList": tags}}},
        write=("tag_resource", lambda arn: {"ResourceARN": arn, "Tags": tl(("Name", N))})),
    "s3_bucket": dict(
        arn="arn:aws:s3:::my-bucket", scope="global", proof="owner-region-proof",
        reads=[("list_tags_for_resource", {"AccountId": ACCT, "ResourceArn": "arn:aws:s3:::my-bucket"})],
        resp=lambda arn, tags: {"list_tags_for_resource": {"Tags": tags}},
        write=("tag_resource", lambda arn: {"AccountId": ACCT, "ResourceArn": arn, "Tags": tl(("Name", N))})),
}
assert len(CASES) == 11


def tgt(kind):
    c = CASES[kind]
    return make_target(kind, c["arn"], scope=c.get("scope", R), proof=c.get("proof", ""))


def s3_bundle(responses=None, location="ap-northeast-1", region="ap-northeast-1"):
    s3 = FakeClient({"get_bucket_location": {"LocationConstraint": location}})
    ctl = FakeClient(responses or {}, meta=SimpleNamespace(region_name=region))
    return SimpleNamespace(s3=s3, s3control=ctl)


def client_for(kind, responses=None):
    if kind == "s3_bucket":
        return s3_bundle(responses)
    return FakeClient(responses)


def all_calls(client):
    if hasattr(client, "s3control"):
        return client.s3.calls + client.s3control.calls
    return client.calls


class ServiceAdapterTests(unittest.TestCase):
    def test_remaining_11_candidate_shapes_or_explicit_cnp(self):
        for kind, c in CASES.items():
            with self.subTest(kind=kind):
                adapter, target = candidate_adapter(kind), tgt(kind)
                resp = c["resp"](c["arn"], tl())
                client = client_for(kind, resp)
                self.assertEqual(adapter.read_current(client, target).state, "ABSENT")
                self.assertEqual([x for x in all_calls(client) if x[0] in dict(c["reads"])],
                                 [(op, kw) for op, kw in c["reads"]])
                if kind == "apigw_stage":
                    self.assertEqual(all_calls(client), [(op, kw) for op, kw in c["reads"]])
                resp = c["resp"](c["arn"], tl(("Name", "x"), ("Env", "p")))
                self.assertEqual(adapter.readback(client_for(kind, resp), target).state, "NONEMPTY")
                wclient = client_for(kind, resp)
                with self.assertRaises(AdapterRejected) as cm:
                    adapter.write_once(wclient, target, N, GRANT)
                self.assertEqual(cm.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
                self.assertEqual(all_calls(wclient), [])
                self.assertEqual(adapter._spec.write_kwargs(target, N), c["write"][1](c["arn"]))

    def test_registry_dispatch_rejects_all_11_cnp_with_reason(self):
        for kind in CASES:
            decision = caps.resolve_kind_capability(kind)
            with self.subTest(kind=kind), self.assertRaises(AdapterUnavailable) as cm:
                adapter_for_capability(decision)
            self.assertEqual(cm.exception.reason_code, decision.reason_code)
            self.assertEqual(decision.status, "CAPABILITY_NOT_PROVEN")

    def test_dispatch_with_test_only_proven_fixture_for_non_blocked_kinds(self):
        for kind in CASES:
            if kind == "apigw_stage":
                continue
            with self.subTest(kind=kind), proven(kind):
                adapter = adapter_for_capability(caps.resolve_kind_capability(kind))
                self.assertEqual(adapter.kind, kind)

    def test_tags_malformed_or_paginated_is_unknown(self):
        for kind, c in CASES.items():
            adapter, target = candidate_adapter(kind), tgt(kind)
            list_form = kind not in ("apigw_stage", "log_group", "lambda")
            bad = {"duplicate": tl(("Name", "a"), ("Name", "b")) if list_form else None,
                   "case_variant": tl(("name", "a")) if list_form else {"name": "a"},
                   "not_a_collection": "oops"}
            for label, tags in bad.items():
                if tags is None:
                    continue
                with self.subTest(kind=kind, case=label):
                    client = client_for(kind, c["resp"](c["arn"], tags))
                    self.assertEqual(adapter.read_current(client, target).state, "UNKNOWN")
            with self.subTest(kind=kind, case="paginated"):
                resp = c["resp"](c["arn"], tl())
                last = list(resp)[-1]
                resp[last]["NextToken"] = "more"
                self.assertEqual(adapter.readback(client_for(kind, resp), target).state, "UNKNOWN")
            with self.subTest(kind=kind, case="partial"):
                self.assertEqual(adapter.read_current(client_for(kind, {}), target).state, "UNKNOWN")

    def test_response_identity_mismatch_is_rejected(self):
        for kind, c in CASES.items():
            if kind in ("s3_bucket",):   # s3control response carries no resource identity
                continue
            with self.subTest(kind=kind):
                other = c["arn"][:-1] + ("0" if c["arn"][-1] != "0" else "1")
                resp = c["resp"](other, tl())
                if kind in ("log_group", "apigw_stage", "athena_workgroup", "cloudfront"):
                    continue  # identity is by exact name/id, covered below
                with self.assertRaises(AdapterIdentityMismatch):
                    candidate_adapter(kind).read_current(client_for(kind, resp), tgt(kind))
        resp = CASES["cloudfront"]["resp"](CASES["cloudfront"]["arn"], tl())
        resp["get_distribution"]["Distribution"]["Id"] = "EOTHER"
        with self.assertRaises(AdapterIdentityMismatch):
            candidate_adapter("cloudfront").read_current(FakeClient(resp), tgt("cloudfront"))
        resp = CASES["log_group"]["resp"](CASES["log_group"]["arn"], tl())
        resp["describe_log_groups"]["logGroups"] = [{"logGroupName": "/aws/app", "arn": "arn:aws:logs:x"}]
        with self.assertRaises(AdapterIdentityMismatch):
            candidate_adapter("log_group").read_current(FakeClient(resp), tgt("log_group"))

    def test_log_group_prefix_siblings_only_is_unknown_not_absent(self):
        c = CASES["log_group"]
        resp = c["resp"](c["arn"], tl())
        resp["describe_log_groups"]["logGroups"] = [{"logGroupName": "/aws/app2", "arn": c["arn"] + "2:*"}]
        self.assertEqual(candidate_adapter("log_group").read_current(FakeClient(resp), tgt("log_group")).state, "UNKNOWN")

    def test_apigw_inherited_name_is_unknown_for_stage_write(self):
        c = CASES["apigw_stage"]
        arn = c["arn"]
        inherited = {"get_stage": {"stageName": "prod", "tags": {}},
                     "get_tags": {"tags": {"Name": "parent-api"}}}
        client = FakeClient(inherited)
        adapter, target = candidate_adapter("apigw_stage"), tgt("apigw_stage")
        self.assertEqual(adapter.read_current(client, target).state, "UNKNOWN")
        with self.assertRaises(AdapterRejected) as cm:
            adapter.write_once(client, target, N, GRANT)
        self.assertEqual(cm.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertNotIn("tag_resource", [op for op, _ in client.calls])
        # Registry/dispatch: remains CNP even when a decision claims IMPLEMENTED_OFFLINE
        with proven("apigw_stage"), self.assertRaises(AdapterUnavailable) as cm:
            adapter_for_capability(caps.resolve_kind_capability("apigw_stage"))
        self.assertEqual(cm.exception.reason_code, "IAM_CONDITION_NOT_PROVEN")
        self.assertEqual(arn, target.resource_arn)

    def test_s3_sdk_missing_or_owner_unproven_no_write(self):
        # pinned model really contains the S3 Control operations
        self.assertTrue({"tag_resource", "list_tags_for_resource"} <= pinned_operation_names("s3control"))
        # SDK operation missing -> CNP-style unavailability, no adapter
        for missing in ("tag_resource", "list_tags_for_resource"):
            def ops(service, missing=missing):
                return {o for o in pinned_operation_names(service) if o != missing}
            with self.subTest(missing=missing), self.assertRaises(AdapterUnavailable) as cm:
                candidate_adapter("s3_bucket", operation_names=ops)
            self.assertEqual(cm.exception.reason_code, "API_SDK_UNAVAILABLE")
        adapter = candidate_adapter("s3_bucket")
        resp = {"list_tags_for_resource": {"Tags": []}}
        no_proof = make_target("s3_bucket", "arn:aws:s3:::my-bucket", scope="global")
        bundles = {
            "no_owner_proof": (s3_bundle(resp), no_proof, "ARN_OWNER_NOT_PROVEN"),
            "region_mismatch": (s3_bundle(resp, location="eu-west-1"), tgt("s3_bucket"), "ARN_OWNER_NOT_PROVEN"),
            "no_client_region": (SimpleNamespace(s3=s3_bundle().s3, s3control=FakeClient(resp)),
                                 tgt("s3_bucket"), "ARN_OWNER_NOT_PROVEN"),
        }
        for label, (bundle, target, code) in bundles.items():
            with self.subTest(case=label), self.assertRaises(AdapterRejected) as cm:
                adapter.write_once(bundle, target, N, GRANT)
            self.assertEqual(
                cm.exception.code,
                "ARN_OWNER_NOT_PROVEN" if label == "no_owner_proof" else "AWS_RUNTIME_NOT_AUTHORIZED",
            )
            self.assertEqual(all_calls(bundle), [])

    def test_s3_put_bucket_tagging_never_used(self):
        adapter = candidate_adapter("s3_bucket")
        bundle = s3_bundle({"list_tags_for_resource": {"Tags": tl(("Name", "old"), ("Keep", "me"))}})
        self.assertEqual(adapter.read_current(bundle, tgt("s3_bucket")).state, "NONEMPTY")
        with self.assertRaises(AdapterRejected) as cm:
            adapter.write_once(bundle, tgt("s3_bucket"), N, GRANT)
        self.assertEqual(cm.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        every = [op for op, _ in bundle.s3.calls + bundle.s3control.calls]
        self.assertNotIn("put_bucket_tagging", every)
        self.assertNotIn("tag_resource", every)
        # the adapter refuses the forbidden operation even if routed to it internally
        with self.assertRaises(AdapterRejected):
            adapter._invoke(bundle, "s3", "put_bucket_tagging", {})
        self.assertNotIn("put_bucket_tagging", [op for op, _ in bundle.s3.calls])
        # registry contract never names the legacy API
        decision = caps.resolve_kind_capability("s3_bucket")
        self.assertNotIn("put_bucket_tagging", decision.sdk_request_contract)
        self.assertFalse(decision.tag_set_replacement)

    def test_extra_tag_or_resource_rejected(self):
        for kind in CASES:
            with self.subTest(kind=kind):
                adapter, target = candidate_adapter(kind), tgt(kind)
                client = client_for(kind)
                for bad in ("", " x", "a\x00b", "n" * 257):
                    with self.assertRaises(AdapterRejected):
                        adapter.write_once(client, target, bad, GRANT)
                with self.assertRaises(TypeError):
                    adapter.write_once(client, target, N, GRANT, Tags=[{"Key": "Extra", "Value": "x"}])
                wrong = make_target("lambda", CASES["lambda"]["arn"]) if kind != "lambda" else tgt("rds_cluster")
                with self.assertRaises(AdapterRejected):
                    adapter.write_once(client, wrong, N, GRANT)
                self.assertEqual(all_calls(client), [])

    def test_all_18_kinds_are_covered(self):
        from test_name_tag_kind_adapters_ec2 import EC2_CASES
        self.assertEqual(set(CASES) | set(EC2_CASES), set(caps.REGISTRY_KINDS))


if __name__ == "__main__":
    unittest.main()
