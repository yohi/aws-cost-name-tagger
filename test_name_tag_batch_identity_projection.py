"""Offline Task 2 tests: pre-sign Kind identity projection in plan_batch."""
from __future__ import annotations

import csv
import dataclasses
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import aws_cost_name_tagger_v3 as t
import name_tag_kind_capabilities as caps
from name_tag_batch_state import BatchValidationError, validate_batch_draft
from name_tag_batch_state import build_batch_review_projection

ACCT = "456720798575"
R = "ap-northeast-1"
CF_ID = "E1ABCDEF234567"
CF_ARN = f"arn:aws:cloudfront::{ACCT}:distribution/{CF_ID}"
VOL = "vol-0123456789abcdef0"
VOL_ARN = f"arn:aws:ec2:{R}:{ACCT}:volume/{VOL}"
WAF_UUID = "0a1b2c3d-0a1b-0a1b-0a1b-0a1b2c3d4e5f"
WAF_GLOBAL = f"arn:aws:wafv2:us-east-1:{ACCT}:global/webacl/web/{WAF_UUID}"
WAF_REGIONAL = f"arn:aws:wafv2:{R}:{ACCT}:regional/webacl/web/{WAF_UUID}"
INSTANCE = "i-0123456789abcdef0"
SNAP = "snap-0123456789abcdef0"
COLS = ("bill_billing_period_start_date", "line_item_usage_account_id",
        "line_item_line_item_type", "line_item_resource_id", "line_item_unblended_cost",
        "reservation_effective_cost", "savings_plan_savings_plan_effective_cost",
        "product_region_code", "line_item_product_code", "line_item_currency_code")


def cur_row(resource_id, cost="1", region=R):
    return {
        "bill_billing_period_start_date": "2026-10-01", "line_item_usage_account_id": ACCT,
        "line_item_line_item_type": "Usage", "line_item_resource_id": resource_id,
        "line_item_unblended_cost": cost, "reservation_effective_cost": "",
        "savings_plan_savings_plan_effective_cost": "", "product_region_code": region,
        "line_item_product_code": "X", "line_item_currency_code": "USD"}


def write_cur(path, rows):
    with gzip.open(path, "wt", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLS)
        writer.writeheader()
        writer.writerows(rows)


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": ACCT}


class FakeSession:
    def client(self, service, region_name=None, config=None):
        return FakeSTS()


def info_for(kind, write_target, status="proposed"):
    return {"status": status, "proposed_name": f"app-{kind}-1" if status == "proposed" else "",
            "confidence": "medium", "evidence": "deterministic evidence",
            "write_target": write_target, "kind": kind, "name_state": "ABSENT",
            "name_key_present": False, "name_raw_value": None, "existing_name": ""}


def make_investigator(infos, seen):
    class StubInvestigator:
        def __init__(self, session, account, retries=3):
            pass

        def resolve(self, item, **kwargs):
            seen.append(dict(item))
            return dict(infos[item["locator"]])
    return StubInvestigator


class PlanFixture(unittest.TestCase):
    def run_plan(self, rows, infos, scopes, *, kinds=None, min_cost="0", max_resources="100"):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        cur = base / "cur.csv.gz"
        write_cur(cur, rows)
        argv = ["batch-plan", "--cur", str(cur), "--month", "2026-10", "--account", ACCT,
                "--min-cost", min_cost, "--max-resources", max_resources,
                "--scope-declarations", str(base / "s.json"),
                "--output", str(base / "plan.json")]
        if kinds:
            argv += ["--kinds", kinds]
        args = t.parse_cli(argv)
        self.seen = []
        with mock.patch.object(t, "Investigator", make_investigator(infos, self.seen)):
            self.doc = t.plan_batch(args, scope_declarations=scopes, session=FakeSession())
        self.out = base / "plan.json"
        return self.doc

    @staticmethod
    def scope(region, arns, sid="scope-1"):
        return [{"writer_control_scope_id": sid, "account": ACCT, "partition": "aws",
                 "region": region, "resource_arns": sorted(arns)}]


class IdentityProjectionTests(PlanFixture):
    def test_apigateway_locator_is_projected_before_proposal_key(self):
        arn = f"arn:aws:apigateway:{R}::/restapis/abcdefghij/stages/prod"
        record = {"kind": "apigw_stage", "locator": f"abcdefghij|prod|{arn}",
                  "region": R, "write_target": arn, "status": "proposed",
                  "proposed_name": "api-prod", "evidence": ""}
        old_key = t.proposal_key(record)
        t._project_pre_sign_identity(record, "aws", ACCT)
        self.assertEqual(record["locator"], arn)
        self.assertNotEqual(t.proposal_key(record), old_key)

    def test_rds_cluster_projection_keeps_cur_locator(self):
        arn = f"arn:aws:rds:{R}:{ACCT}:cluster:orders"
        record = {"kind": "rds_cluster", "locator": "cluster-0123456789abcdef0",
                  "region": R, "write_target": arn, "status": "proposed",
                  "proposed_name": "orders-rds", "evidence": ""}
        t._project_pre_sign_identity(record, "aws", ACCT)
        self.assertEqual(record["locator"], "cluster-0123456789abcdef0")
        self.assertEqual(record["resource_arn"], arn)

    def test_cloudfront_presign_scope_global_and_arn_region_empty(self):
        doc = self.run_plan([cur_row(CF_ARN, region="us-east-1")],
                            {CF_ARN: info_for("cloudfront", CF_ARN)},
                            self.scope("global", [CF_ARN]), kinds="cloudfront")
        self.assertEqual(self.seen[0]["region"], "us-east-1")  # resolver: service endpoint
        rec = doc["records"][0]
        self.assertEqual(rec["region"], "global")
        self.assertEqual(rec["resource_arn"], CF_ARN)
        self.assertEqual(CF_ARN.split(":")[3], "")
        self.assertIsNone(rec["aws_operation"])  # CNP: preview only
        self.assertEqual(rec["proposal_id"], t.proposal_key(rec))  # key frozen post-projection
        self.assertEqual(doc["partition"], "aws")
        plan_bytes = self.out.read_bytes()
        validate_batch_draft(plan_bytes, build_batch_review_projection(plan_bytes))

    def test_cloudfront_projection_collision_rejected_before_sign(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        out = Path(base.name) / "plan.json"
        args = t.parse_cli(["batch-plan", "--cur", "x.csv.gz", "--month", "2026-10",
                            "--account", ACCT, "--min-cost", "0", "--max-resources", "10",
                            "--scope-declarations", "s.json", "--output", str(out)])
        candidates = [
            {"kind": "cloudfront", "locator": CF_ARN, "region": region,
             "effective_usage_cost_usd": "1", "legacy_rank_cost": 1.0}
            for region in ("us-east-1", "eu-west-1")]
        infos = {CF_ARN: info_for("cloudfront", CF_ARN)}
        with mock.patch.object(t, "cur_candidates_batch",
                               return_value=("2026-10", candidates, {}, {}, {})), \
                mock.patch.object(t, "Investigator", make_investigator(infos, [])):
            with self.assertRaisesRegex(SystemExit, "collision"):
                t.plan_batch(args, scope_declarations=self.scope("global", [CF_ARN]),
                             session=FakeSession())
        self.assertFalse(out.exists())

    def test_cur_pre_cap_counts_costs_unchanged(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        cur = Path(base.name) / "cur.csv.gz"
        write_cur(cur, [cur_row(CF_ARN, "5", "us-east-1"), cur_row(VOL, "2")])
        month, candidates, population, _reasons, _by_kind = t.cur_candidates_batch(
            [str(cur)], "2026-10", 0, 100, ACCT)
        self.assertEqual(population["cur_recognized"], {"count": 2, "cost_usd": "7"})
        self.assertEqual(population["lookup_selected"], {"count": 2, "cost_usd": "7"})
        cf = next(c for c in candidates if c["kind"] == "cloudfront")
        self.assertEqual(cf["region"], "us-east-1")  # classification untouched pre-sign
        doc = self.run_plan([cur_row(CF_ARN, "5", "us-east-1"), cur_row(VOL, "2")],
                            {CF_ARN: info_for("cloudfront", CF_ARN),
                             VOL: info_for("volume", VOL)},
                            self.scope("global", [CF_ARN]))
        self.assertEqual(doc["cur_population"], population)

    def test_wafv2_global_endpoint_not_scope_global(self):
        doc = self.run_plan(
            [cur_row(WAF_GLOBAL, "3", "us-east-1"), cur_row(WAF_REGIONAL, "2")],
            {WAF_GLOBAL: info_for("wafv2", WAF_GLOBAL),
             WAF_REGIONAL: info_for("wafv2", WAF_REGIONAL)},
            self.scope("us-east-1", [WAF_GLOBAL]) + self.scope(R, [WAF_REGIONAL], "scope-2"))
        by_arn = {r["resource_arn"]: r for r in doc["records"]}
        self.assertEqual(by_arn[WAF_GLOBAL]["region"], "us-east-1")
        self.assertNotEqual(by_arn[WAF_GLOBAL]["region"], "global")
        self.assertEqual(by_arn[WAF_REGIONAL]["region"], R)

    def test_volume_region_and_operation_regression(self):
        doc = self.run_plan([cur_row(VOL)], {VOL: info_for("volume", VOL)},
                            self.scope(R, [VOL_ARN]), kinds="volume")
        rec = doc["records"][0]
        self.assertEqual((rec["region"], rec["resource_arn"], rec["aws_operation"]),
                         (R, VOL_ARN, "ec2:CreateTags"))

    def test_presign_nonvolume_arn_region_operation_triplet(self):
        arn = f"arn:aws:ec2:{R}:{ACCT}:instance/{INSTANCE}"
        vetted = dataclasses.replace(
            caps.resolve_kind_capability("instance"), status="IMPLEMENTED_OFFLINE",
            reason_code="OFFLINE_CONTRACT_COMPLETE", write_operation="ec2:CreateTags",
            evidence_refs=("test-only-fixture",))
        table = dict(caps._DECISIONS)
        table["instance"] = vetted
        with mock.patch.object(caps, "_DECISIONS", table):
            doc = self.run_plan([cur_row(INSTANCE)], {INSTANCE: info_for("instance", INSTANCE)},
                                self.scope(R, [arn]), kinds="instance")
        rec = doc["records"][0]
        self.assertEqual((rec["resource_arn"], rec["region"], rec["aws_operation"]),
                         (arn, R, "ec2:CreateTags"))

    def test_cnp_unsigned_preview_operation_none(self):
        snap_arn = f"arn:aws:ec2:{R}::snapshot/{SNAP}"
        doc = self.run_plan([cur_row(SNAP)], {SNAP: info_for("snapshot", SNAP)},
                            self.scope(R, [snap_arn]), kinds="snapshot")
        rec = doc["records"][0]
        self.assertEqual(rec["resource_arn"], snap_arn)  # accountless preview ARN
        self.assertIsNone(rec["aws_operation"])
        self.assertEqual(rec["region"], R)

    def test_failed_resolution_keeps_unsigned_nonsignable_record(self):
        bad = {**info_for("volume", ""), "status": "api_error", "proposed_name": ""}
        doc = self.run_plan([cur_row(VOL)], {VOL: bad}, [], kinds="volume")
        self.assertEqual(doc["records"][0]["status"], "api_error")


class KindPreCapTests(PlanFixture):
    STAGES = ("cur_recognized", "below_min_cost", "above_min_cost", "lookup_selected",
              "max_resources_not_inspected")

    def build(self):
        rows = [cur_row(VOL, "5"), cur_row(CF_ARN, "4", "us-east-1"),
                cur_row(INSTANCE, "3"), cur_row(SNAP, "0.5")]
        infos = {VOL: info_for("volume", VOL), CF_ARN: info_for("cloudfront", CF_ARN)}
        return self.run_plan(rows, infos, self.scope("global", [CF_ARN]),
                             min_cost="1", max_resources="2")

    def test_18_kind_precap_below_cost_and_uninspected_reconcile(self):
        doc = self.build()
        field = doc["cur_population_by_kind"]
        self.assertEqual(field["schema_version"], 1)
        kinds = field["kinds"]
        self.assertEqual(tuple(kinds), caps.REGISTRY_KINDS)
        self.assertEqual(len(kinds), 18)
        self.assertEqual(kinds["volume"]["lookup_selected"], {"count": 1, "cost_usd": "5"})
        self.assertEqual(kinds["cloudfront"]["lookup_selected"], {"count": 1, "cost_usd": "4"})
        self.assertEqual(kinds["instance"]["max_resources_not_inspected"],
                         {"count": 1, "cost_usd": "3"})
        self.assertEqual(kinds["instance"]["above_min_cost"], {"count": 1, "cost_usd": "3"})
        self.assertEqual(kinds["snapshot"]["below_min_cost"], {"count": 1, "cost_usd": "0.5"})
        self.assertEqual(kinds["snapshot"]["above_min_cost"], {"count": 0, "cost_usd": "0"})
        self.assertEqual(kinds["lambda"]["cur_recognized"], {"count": 0, "cost_usd": "0"})
        for stage in self.STAGES:
            self.assertEqual(sum(k[stage]["count"] for k in kinds.values()),
                             doc["cur_population"][stage]["count"])
        self.assertEqual(doc["cur_population"]["max_resources_not_inspected"],
                         {"count": 1, "cost_usd": "3"})
        plan_bytes = self.out.read_bytes()
        validate_batch_draft(plan_bytes, build_batch_review_projection(plan_bytes))

    def mutated(self, mutate):
        doc = json.loads(self.out.read_bytes())
        mutate(doc["cur_population_by_kind"])
        return json.dumps(doc).encode()

    def test_precap_field_tamper_rejected(self):
        self.build()
        from name_tag_batch_state import _parse_plan

        def kinds(f):
            return f["kinds"]
        tampers = {
            "count": lambda f: kinds(f)["volume"]["lookup_selected"].update(count=2),
            "cost": lambda f: kinds(f)["volume"]["cur_recognized"].update(cost_usd="5.0"),
            "moved cost": lambda f: (kinds(f)["volume"]["cur_recognized"].update(cost_usd="4"),
                                     kinds(f)["volume"]["above_min_cost"].update(cost_usd="4")),
            "missing kind": lambda f: kinds(f).pop("lambda"),
            "extra kind": lambda f: kinds(f).update(bogus=kinds(f)["lambda"]),
            "schema": lambda f: f.update(schema_version=2),
            "extra stage": lambda f: kinds(f)["lambda"].update(extra={"count": 0, "cost_usd": "0"}),
            "extra top": lambda f: f.update(extra=1),
            "bool count": lambda f: kinds(f)["lambda"]["cur_recognized"].update(count=False),
            "identity": lambda f: (kinds(f)["lambda"]["cur_recognized"].update(count=1, cost_usd="0"),
                                   kinds(f)["lambda"]["below_min_cost"].update(count=0)),
        }
        for name, mutate in tampers.items():
            with self.subTest(name), self.assertRaises(BatchValidationError):
                _parse_plan(self.mutated(mutate))
        with self.subTest("not a dict"), self.assertRaises(BatchValidationError):
            doc = json.loads(self.out.read_bytes())
            doc["cur_population_by_kind"] = []
            _parse_plan(json.dumps(doc).encode())

    def test_legacy_plan_v3_without_kind_breakdown_accepted(self):
        self.build()
        doc = json.loads(self.out.read_bytes())
        del doc["cur_population_by_kind"]
        plan_bytes = json.dumps(doc).encode()
        draft = validate_batch_draft(plan_bytes, build_batch_review_projection(plan_bytes))
        self.assertNotIn("cur_population_by_kind", draft.plan)


if __name__ == "__main__":
    unittest.main()
