"""Offline tests for the versioned 18-Kind capability and identity registry."""
from __future__ import annotations

import dataclasses
import unittest
from unittest import mock

import name_tag_kind_capabilities as caps

ACCT = "123456789012"
OTHER = "210987654321"
R = "ap-northeast-1"

# kind -> (locator, canonical ARN, expected scope_region, arn_region, arn_account)
POSITIVE = {
    "instance": ("i-0123456789abcdef0",
                 f"arn:aws:ec2:{R}:{ACCT}:instance/i-0123456789abcdef0", R, R, ACCT),
    "volume": ("vol-0123456789abcdef0",
               f"arn:aws:ec2:{R}:{ACCT}:volume/vol-0123456789abcdef0", R, R, ACCT),
    "snapshot": ("snap-0123456789abcdef0",
                 f"arn:aws:ec2:{R}::snapshot/snap-0123456789abcdef0", R, R, ""),
    "eni": ("eni-0123456789abcdef0",
            f"arn:aws:ec2:{R}:{ACCT}:network-interface/eni-0123456789abcdef0", R, R, ACCT),
    "eip": ("eipalloc-0123456789abcdef0",
            f"arn:aws:ec2:{R}:{ACCT}:elastic-ip/eipalloc-0123456789abcdef0", R, R, ACCT),
    "nat": ("nat-0123456789abcdef0",
            f"arn:aws:ec2:{R}:{ACCT}:natgateway/nat-0123456789abcdef0", R, R, ACCT),
    "endpoint": ("vpce-0123456789abcdef0",
                 f"arn:aws:ec2:{R}:{ACCT}:vpc-endpoint/vpce-0123456789abcdef0", R, R, ACCT),
    "rds_cluster": ("prod-cluster", f"arn:aws:rds:{R}:{ACCT}:cluster:prod-cluster", R, R, ACCT),
    "rds_instance": ("prod-db", f"arn:aws:rds:{R}:{ACCT}:db:prod-db", R, R, ACCT),
    "opensearch": ("search-dom", f"arn:aws:es:{R}:{ACCT}:domain/search-dom", R, R, ACCT),
    "elbv2": ("app/web/0123456789abcdef",
              f"arn:aws:elasticloadbalancing:{R}:{ACCT}:loadbalancer/app/web/0123456789abcdef",
              R, R, ACCT),
    "apigw_stage": ("a1b2c3d4e5/prod",
                    f"arn:aws:apigateway:{R}::/restapis/a1b2c3d4e5/stages/prod", R, R, ""),
    "cloudfront": ("E1ABCDEF234567",
                   f"arn:aws:cloudfront::{ACCT}:distribution/E1ABCDEF234567", "global", "", ACCT),
    "athena_workgroup": ("primary", f"arn:aws:athena:{R}:{ACCT}:workgroup/primary", R, R, ACCT),
    "log_group": ("/aws/app/x", f"arn:aws:logs:{R}:{ACCT}:log-group:/aws/app/x", R, R, ACCT),
    "lambda": ("my-func", f"arn:aws:lambda:{R}:{ACCT}:function:my-func", R, R, ACCT),
    "wafv2": ("web/0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f",
              f"arn:aws:wafv2:{R}:{ACCT}:regional/webacl/web/0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f",
              R, R, ACCT),
    "s3_bucket": ("my-bucket-1", "arn:aws:s3:::my-bucket-1", "global", "", ""),
}

WAF_GLOBAL = ("web/0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f",
              f"arn:aws:wafv2:us-east-1:{ACCT}:global/webacl/web/0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f")


def ident(kind, arn=None, locator=None, partition="aws", account=ACCT, scope=None):
    loc, canon, sc, _, _ = POSITIVE[kind]
    return caps.canonical_target_identity(
        kind=kind, locator=loc if locator is None else locator,
        resource_arn=canon if arn is None else arn, partition=partition,
        account=account, scope_region=sc if scope is None else scope)


class KindCapabilityRegistryTests(unittest.TestCase):
    def test_exact_18_kinds_and_default_cnp(self):
        import aws_cost_name_tagger_v3 as v3
        self.assertEqual(len(caps.REGISTRY_KINDS), 18)
        self.assertEqual(frozenset(caps.REGISTRY_KINDS), v3.SUPPORTED_KINDS)
        self.assertEqual(frozenset(POSITIVE), v3.SUPPORTED_KINDS)
        self.assertTrue(caps.REGISTRY_VERSION)
        for kind in caps.REGISTRY_KINDS:
            d = caps.resolve_kind_capability(kind)
            self.assertIsInstance(d, caps.KindCapabilityDecision)
            self.assertEqual(d.kind, kind)
            self.assertEqual(d.version, caps.REGISTRY_VERSION)
            self.assertTrue(d.reason_code)
            self.assertIn(d.status, caps.STATUSES)
            if kind == "volume":
                self.assertEqual(d.status, "IMPLEMENTED_OFFLINE")
                self.assertEqual(d.write_operation, "ec2:CreateTags")
                self.assertEqual(d.iam_action, "ec2:CreateTags")
            else:
                self.assertEqual(d.status, "CAPABILITY_NOT_PROVEN")
                self.assertIn(d.reason_code, caps.CNP_REASON_CODES)
        for bad in ("", "Volume", "unknown", "s3", None):
            with self.assertRaises(ValueError):
                caps.resolve_kind_capability(bad)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            caps.resolve_kind_capability("volume").status = "IMPLEMENTED_OFFLINE"
        # S3 whole-set replacement is never the candidate write.
        s3 = caps.resolve_kind_capability("s3_bucket")
        self.assertNotIn("put_bucket_tagging", s3.write_operation.lower())
        self.assertIn("s3control", s3.write_operation)

    def test_global_and_accountless_arn_matrix(self):
        for kind, (loc, arn, scope, arn_region, arn_account) in POSITIVE.items():
            i = ident(kind)
            self.assertEqual(
                (i.kind, i.locator, i.resource_arn, i.partition, i.owner_account,
                 i.scope_region, i.arn_region, i.arn_account, i.ownership_proof_ref),
                (kind, loc, arn, "aws", ACCT, scope, arn_region, arn_account, ""))
        self.assertEqual(ident("cloudfront").scope_region, "global")
        self.assertEqual(ident("s3_bucket").arn_account, "")
        self.assertEqual(ident("snapshot").scope_region, R)
        self.assertEqual(ident("apigw_stage").arn_account, "")
        waf_loc, waf_arn = WAF_GLOBAL
        w = caps.canonical_target_identity(
            kind="wafv2", locator=waf_loc, resource_arn=waf_arn, partition="aws",
            account=ACCT, scope_region="us-east-1")
        self.assertEqual((w.scope_region, w.arn_region), ("us-east-1", "us-east-1"))
        with self.assertRaises(ValueError):  # no invented 'global' for WAF
            caps.canonical_target_identity(
                kind="wafv2", locator=waf_loc, resource_arn=waf_arn, partition="aws",
                account=ACCT, scope_region="global")
        with self.assertRaises(ValueError):  # CLOUDFRONT-scope WAF must be us-east-1
            ident("wafv2", arn=waf_arn.replace("us-east-1", R), scope=R,
                  locator=waf_loc)
        # regional kinds need actual region equality; global kinds need 'global'
        with self.assertRaises(ValueError):
            ident("cloudfront", scope="us-east-1")
        with self.assertRaises(ValueError):
            ident("s3_bucket", scope=R)
        with self.assertRaises(ValueError):
            ident("instance", scope="global")
        with self.assertRaises(ValueError):
            ident("instance", scope="us-east-1")

    def test_wildcard_cross_account_and_alias_rejected(self):
        for kind, (loc, arn, scope, _, _) in POSITIVE.items():
            with self.subTest(kind=kind, case="foreign partition"):
                with self.assertRaises(ValueError):
                    ident(kind, arn=arn.replace("arn:aws:", "arn:aws-cn:", 1))
                with self.assertRaises(ValueError):
                    ident(kind, partition="aws-cn")
            with self.subTest(kind=kind, case="wildcard"):
                bads = [arn + "*", arn[:-1] + "*", arn + ":*", arn + "?"]
                if R in arn:
                    bads.append(arn.replace(R, "*"))
                for bad in bads:
                    with self.assertRaises(ValueError):
                        ident(kind, arn=bad)
            with self.subTest(kind=kind, case="alias/mutation"):
                for bad in (loc, arn.upper(), " " + arn, arn + " ", arn + "\n",
                            arn.replace("arn:", "ARN:", 1), "arn:aws", "", "arn:*:*:*"):
                    with self.assertRaises(ValueError):
                        ident(kind, arn=bad)
            with self.subTest(kind=kind, case="locator mismatch"):
                with self.assertRaises(ValueError):
                    ident(kind, locator="other-" + loc)
                with self.assertRaises(ValueError):
                    ident(kind, locator="")
            with self.subTest(kind=kind, case="bad account"):
                for bad in ("", "*", "12345", "1234567890123"):
                    with self.assertRaises(ValueError):
                        ident(kind, account=bad)
        for kind in ("instance", "volume", "eni", "eip", "nat", "endpoint", "rds_cluster",
                     "rds_instance", "opensearch", "elbv2", "athena_workgroup", "log_group",
                     "lambda", "wafv2", "cloudfront"):
            with self.subTest(kind=kind, case="cross account"):
                arn = POSITIVE[kind][1].replace(ACCT, OTHER)
                with self.assertRaises(ValueError):
                    ident(kind, arn=arn)
        # accountless kinds must stay accountless; account-qualified must not be blank
        with self.assertRaises(ValueError):
            ident("snapshot", arn=f"arn:aws:ec2:{R}:{ACCT}:snapshot/snap-0123456789abcdef0")
        with self.assertRaises(ValueError):
            ident("instance", arn=f"arn:aws:ec2:{R}::instance/i-0123456789abcdef0")
        with self.assertRaises(ValueError):
            ident("s3_bucket", arn=f"arn:aws:s3::{ACCT}:my-bucket-1")
        with self.assertRaises(ValueError):
            ident("cloudfront", arn=f"arn:aws:cloudfront:us-east-1:{ACCT}:distribution/E1ABCDEF234567")
        # wrong resource type / lambda qualifier / log-group wildcard suffix / unknown kind
        with self.assertRaises(ValueError):
            ident("volume", arn=POSITIVE["instance"][1])
        with self.assertRaises(ValueError):
            ident("lambda", arn=POSITIVE["lambda"][1] + ":live", locator="my-func:live")
        with self.assertRaises(ValueError):
            ident("log_group", arn=POSITIVE["log_group"][1] + ":*", locator="/aws/app/x:*")
        with self.assertRaises(ValueError):
            caps.canonical_target_identity(
                kind="bogus", locator="x", resource_arn="arn:aws:x:::x",
                partition="aws", account=ACCT, scope_region="global")


def pre(kind, **over):
    loc, arn, scope, _, _ = POSITIVE[kind]
    args = dict(kind=kind, locator=loc, discovered_region=R if scope != "global" else "us-east-1",
                discovered_arn=arn, partition="aws", account=ACCT, evidence="", proposed_name=None)
    args.update(over)
    return caps.project_pre_sign_kind_target(**args)


class PreSignProjectionTests(unittest.TestCase):
    def test_presign_operation_cnp_is_none(self):
        for kind in caps.REGISTRY_KINDS:
            if kind == "volume":
                continue
            t = pre(kind, evidence="Name evidence", proposed_name="web-1")
            self.assertIsInstance(t, caps.PreSignKindTarget)
            self.assertIsNone(t.aws_operation, kind)
            self.assertEqual(t.capability_status, "CAPABILITY_NOT_PROVEN")
            self.assertIn(t.reason_code, caps.CNP_REASON_CODES)
            self.assertEqual(t.identity, ident(kind))

    def test_snapshot_accountless_arn_s3_cloudfront_global_wafv2_region_matrix(self):
        self.assertEqual(pre("snapshot").identity.resource_arn,
                         f"arn:aws:ec2:{R}::snapshot/snap-0123456789abcdef0")
        self.assertEqual(pre("snapshot").identity.scope_region, R)
        self.assertEqual(pre("s3_bucket").identity.scope_region, "global")
        self.assertEqual(pre("s3_bucket").identity.arn_account, "")
        self.assertEqual(pre("cloudfront").identity.scope_region, "global")
        self.assertEqual(pre("cloudfront").identity.arn_region, "")
        loc, arn = WAF_GLOBAL
        w = pre("wafv2", locator=loc, discovered_arn=arn, discovered_region="us-east-1")
        self.assertEqual((w.identity.scope_region, w.identity.arn_region), ("us-east-1",) * 2)
        self.assertEqual(pre("wafv2").identity.scope_region, R)
        # discovered ARN region disagreeing with discovered region is refused (no fallback)
        with self.assertRaises(ValueError):
            pre("instance", discovered_region="us-east-1")
        # no ARN supplied: derived deterministically from locator for simple kinds
        self.assertEqual(pre("volume", discovered_arn=None).identity.resource_arn,
                         POSITIVE["volume"][1])
        self.assertEqual(pre("s3_bucket", discovered_arn=None).identity.resource_arn,
                         "arn:aws:s3:::my-bucket-1")
        with self.assertRaises(ValueError):  # not derivable: WAF id unknown
            pre("wafv2", discovered_arn=None)
        # scope helper
        self.assertEqual(caps.project_unsigned_scope_region(
            kind="cloudfront", classified_region="us-east-1",
            canonical_arn=POSITIVE["cloudfront"][1]), "global")
        self.assertEqual(caps.project_unsigned_scope_region(
            kind="wafv2", classified_region="us-east-1", canonical_arn=arn), "us-east-1")
        self.assertEqual(caps.project_unsigned_scope_region(
            kind="volume", classified_region=R, canonical_arn=POSITIVE["volume"][1]), R)

    def test_unsigned_scope_projection_rejects_classified_region_mismatch(self):
        with self.assertRaisesRegex(ValueError, "Classified region differs"):
            caps.project_unsigned_scope_region(
                kind="volume", classified_region="us-east-1",
                canonical_arn=POSITIVE["volume"][1])
        # Global-scope Kinds project to "global"; their service endpoint region
        # is intentionally not the ARN region (which is empty for CloudFront).
        self.assertEqual(caps.project_unsigned_scope_region(
            kind="cloudfront", classified_region="us-east-1",
            canonical_arn=POSITIVE["cloudfront"][1]), "global")

    def test_vetted_nonvolume_pre_sign_operation_only_after_evidence(self):
        base = caps.resolve_kind_capability("instance")
        vetted = dataclasses.replace(
            base, status="IMPLEMENTED_OFFLINE", reason_code="OFFLINE_CONTRACT_COMPLETE",
            write_operation="ec2:CreateTags", evidence_refs=("test-only-fixture",))
        table = dict(caps._DECISIONS)
        table["instance"] = vetted
        with mock.patch.object(caps, "_DECISIONS", table):
            self.assertEqual(pre("instance", evidence="deterministic Name evidence",
                                 proposed_name="web").aws_operation, "ec2:CreateTags")
            self.assertEqual(pre("instance", evidence="deterministic Name evidence",
                                 proposed_name="web").capability_status, "IMPLEMENTED_OFFLINE")
            for ev in ("", "   ", None):
                t = pre("instance", evidence=ev, proposed_name="web")
                self.assertIsNone(t.aws_operation)
                self.assertEqual(t.reason_code, "NAME_EVIDENCE_NOT_PROVEN")
            self.assertIsNone(pre("instance", evidence="x", proposed_name=None).aws_operation)
            # other kinds remain unaffected
            self.assertIsNone(pre("eni", evidence="x", proposed_name="n").aws_operation)
        # without the patch the same call is CNP / None
        self.assertIsNone(pre("instance", evidence="x", proposed_name="web").aws_operation)

    def test_original_volume_signed_identity_unchanged(self):
        t = pre("volume", evidence="", proposed_name=None)
        self.assertEqual(t.aws_operation, "ec2:CreateTags")
        self.assertEqual(t.capability_status, "IMPLEMENTED_OFFLINE")
        self.assertEqual(t.identity.resource_arn, POSITIVE["volume"][1])
        self.assertEqual(t.identity.scope_region, R)
        self.assertEqual(t.identity.partition, "aws")
        self.assertEqual(t.identity.owner_account, ACCT)
        self.assertEqual(t.identity.ownership_proof_ref, "")
        # legacy resource_arn() derivation yields the same bytes
        import aws_cost_name_tagger_v3 as v3
        legacy = v3.resource_arn({"kind": "volume", "locator": "vol-0123456789abcdef0",
                                  "region": R}, ACCT)
        self.assertEqual(legacy, t.identity.resource_arn)


class PurityTests(unittest.TestCase):
    def test_module_has_no_network_or_boto_imports(self):
        import ast
        import pathlib
        tree = ast.parse(pathlib.Path(caps.__file__).read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        self.assertFalse(names & {"boto3", "botocore", "socket", "urllib", "http", "requests",
                                  "ssl", "subprocess"})


if __name__ == "__main__":
    unittest.main()
