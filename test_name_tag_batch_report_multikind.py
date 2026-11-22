"""Offline Task 9 tests: 18-Kind capability coverage and exact Decimal pre-cap reporting.

Pure and offline: no Ledger, STS, SDK or network. Kind pre-cap totals come ONLY from the
signed Plan v3 ``cur_population_by_kind`` field; selected records/row outcomes add
post-selection detail only. Any promoted decision below is a TEST-ONLY value passed to the
reporting function (or patched in per test); the production Registry is never promoted.
"""
from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
import subprocess
import unittest
from decimal import Decimal
from types import MappingProxyType

import name_tag_kind_capabilities as caps
from name_tag_batch_approval import (
    BATCH_NAMESPACE, BatchAuthRejected, prepare_batch_approval, verify_batch_approval)
from name_tag_batch_outcomes import BatchOutcomeError, reconcile_batch_outcomes
from name_tag_batch_population import (
    KIND_PRECAP_STAGES, CurCostAggregate, _canonical_decimal, build_kind_precap, exact_add,
    partition_cur_population)
from name_tag_batch_report import (
    PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE, ReportBlocked, build_batch_dry_run,
    make_authenticated_batch_report, production_kind_decisions,
    report_kind_capability_coverage)
from name_tag_batch_state import build_batch_review_projection
from test_name_tag_kind_capabilities import ACCT, POSITIVE, R
import test_name_tag_kind_name_evidence as _evidence_tests

MIN_COST = 1.0
VOL_LOCATOR = POSITIVE["volume"][0]
VOL_NAME = f"app-prod-ebs-xvda-{VOL_LOCATOR[-7:]}"
VOL_EVIDENCE = (f"EBS {VOL_LOCATOR} -> attachment i-0123456789abcdef0 xvda -> EC2 "
                "i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)")


def _selected_cost(n):
    # High-precision, distinct exact Decimals (would round under a 28-digit float/Decimal sum).
    return Decimal(f"{n + 1}.{n:02d}00000000000000000000000000000001")


def eighteen_kind_aggregates():
    """Per Kind: one selected, one above-threshold-but-uninspected, one below-threshold row."""
    aggregates = {}
    for n, kind in enumerate(caps.REGISTRY_KINDS):
        locator, _arn, scope_region, _r, _a = POSITIVE[kind]
        aggregates[(kind, locator, scope_region)] = CurCostAggregate(_selected_cost(n), 1000.0 + n)
        aggregates[(kind, locator + "-uninspected", scope_region)] = CurCostAggregate(
            Decimal(f"0.{n:02d}7"), 10.0 + n)
        aggregates[(kind, locator + "-below", scope_region)] = CurCostAggregate(
            Decimal(f"-0.000{n:02d}3"), 0.5)
    return aggregates


def _record(kind, cost):
    locator, arn, scope_region, _r, _a = POSITIVE[kind]
    record = {
        "proposal_id": f"proposal-{kind}", "kind": kind, "locator": locator,
        "region": scope_region, "resource_arn": arn, "aws_operation": None,
        "status": "proposed", "confidence": "medium", "name_state": "ABSENT",
        "name_key_present": False, "name_raw_value": None, "existing_name": "",
        "proposed_name": f"app-{kind.replace('_', '-')}-1",
        "effective_usage_cost_usd": cost, "evidence": "deterministic evidence",
    }
    if kind == "volume":  # the only production IMPLEMENTED_OFFLINE Kind
        record.update(aws_operation="ec2:CreateTags", proposed_name=VOL_NAME,
                      evidence=VOL_EVIDENCE, confidence="high")
    return record


def eighteen_kind_plan(*, with_breakdown=True, account=ACCT):
    aggregates = eighteen_kind_aggregates()
    part = partition_cur_population(aggregates, min_cost=MIN_COST, max_resources=18)
    selected = part.pop("selected_keys")
    costs = {key: _canonical_decimal(aggregates[key].exact_cost) for key in selected}
    records = [_record(key[0], costs[key]) for key in selected]
    population = {
        "schema_version": 2, "accounting_complete": True, **part,
        "unattributable_cur": {"known": True, "billing_rows": 2, "cost_usd": "0.5"},
        "outside_requested_kinds": {"known": True, "billing_rows": 0, "cost_usd": "0"},
        "unsupported_kind": {"known": True, "billing_rows": 1, "cost_usd": "3"},
    }
    vol_arn = POSITIVE["volume"][1]
    plan = {
        "schema_version": 3, "account": account, "partition": "aws", "period": "2026-10",
        "count": len(records), "records": records, "cur_population": population,
        "cur_population_reason_details": {
            "UNATTRIBUTABLE_CUR:MISSING_RESOURCE_ID": {"billing_rows": 2, "cost_usd": "0.5"},
            "UNSUPPORTED_KIND:UNSUPPORTED_RESOURCE_KIND": {"billing_rows": 1, "cost_usd": "3"}},
        "execution_limits": {"max_send_attempts": 3},
        "scope_declarations": [{"writer_control_scope_id": "scope-1", "account": account,
                                "partition": "aws", "region": R, "resource_arns": [vol_arn]}],
    }
    if with_breakdown:
        plan["cur_population_by_kind"] = build_kind_precap(aggregates, selected, min_cost=MIN_COST)
    return plan


def shift_cost(field, stages, gain, lose, delta="0.25"):
    """Move exact cost between two Kinds on the given stages; keeps every identity and total."""
    for kind, sign in ((gain, ""), (lose, "-")):
        for name in stages:
            entry = field["kinds"][kind][name]
            entry["cost_usd"] = _canonical_decimal(exact_add((entry["cost_usd"], sign + delta)))


def encode(plan):
    return json.dumps(plan, ensure_ascii=False, sort_keys=True).encode()


def approve(plan_bytes, *proposal_ids):
    csv = build_batch_review_projection(plan_bytes)
    for pid in proposal_ids:
        csv = csv.replace(f",{pid},".encode(), f"YES,{pid},".encode())
    return csv


def decisions_with(**changes):
    """TEST-ONLY decision map passed to the reporting function (Registry untouched)."""
    decisions = dict(production_kind_decisions())
    for kind, fields in changes.items():
        decisions[kind] = dataclasses.replace(decisions[kind], **fields)
    return MappingProxyType(decisions)


def preview_outcomes(plan):
    report = build_batch_dry_run(encode(plan), build_batch_review_projection(encode(plan)))
    return {i: row["outcome"] for i, row in enumerate(report["rows"])}


class KindCoverageTests(unittest.TestCase):
    def test_all_18_kind_count_decimal_cost_reconciles(self):
        plan = eighteen_kind_plan()
        report = build_batch_dry_run(encode(plan), build_batch_review_projection(encode(plan)))
        coverage = report["kind_capability_coverage"]
        self.assertEqual(tuple(coverage["kinds"]), caps.REGISTRY_KINDS)
        self.assertEqual(coverage["precap_status"], "SIGNED_PLAN_CUR_POPULATION_BY_KIND")
        breakdown = plan["cur_population_by_kind"]["kinds"]
        population = plan["cur_population"]
        for stage in KIND_PRECAP_STAGES:
            self.assertEqual(sum(coverage["kinds"][k]["precap"][stage]["count"]
                                 for k in caps.REGISTRY_KINDS), population[stage]["count"])
            self.assertEqual(exact_add(Decimal(coverage["kinds"][k]["precap"][stage]["cost_usd"])
                                       for k in caps.REGISTRY_KINDS),
                             Decimal(population[stage]["cost_usd"]))
        outcome_count = 0
        outcome_cost = []
        for n, kind in enumerate(caps.REGISTRY_KINDS):
            entry = coverage["kinds"][kind]
            with self.subTest(kind=kind):
                self.assertEqual(entry["precap"], breakdown[kind])
                self.assertEqual(entry["precap"]["below_min_cost"]["count"], 1)
                self.assertEqual(entry["precap"]["max_resources_not_inspected"]["count"], 1)
                self.assertEqual(entry["selected"], {"count": 1, "cost_usd": _canonical_decimal(
                    _selected_cost(n))})
                self.assertEqual(entry["selected"], entry["precap"]["lookup_selected"])
                self.assertEqual(sum(v["count"] for v in entry["outcomes"].values()), 1)
                self.assertEqual(exact_add(Decimal(v["cost_usd"]) for v in entry["outcomes"].values()),
                                 Decimal(entry["selected"]["cost_usd"]))
                expected = "UNAPPROVED" if kind == "volume" else "WRITE_UNSUPPORTED"
                self.assertEqual(list(entry["outcomes"]), [expected])
                outcome_count += 1
                outcome_cost.extend(Decimal(v["cost_usd"]) for v in entry["outcomes"].values())
        self.assertEqual(outcome_count, report["outcome_reconciliation_total"]["count"])
        self.assertEqual(exact_add(outcome_cost),
                         Decimal(report["outcome_reconciliation_total"]["cost_usd"]))
        self.assertEqual(coverage["selected_total"], population["lookup_selected"])
        self.assertEqual(coverage["precap_total"],
                         {stage: population[stage] for stage in KIND_PRECAP_STAGES})
        # Existing global identities and billing/reason-detail reconciliation stay intact.
        self.assertEqual(report["cur_population"], population)
        self.assertEqual(report["cur_population_reason_details"],
                         plan["cur_population_reason_details"])

    def test_unsupported_vs_unproven_vs_not_run_are_distinct(self):
        plan = eighteen_kind_plan()
        outcomes = preview_outcomes(plan)
        decisions = decisions_with(
            instance={"status": "UNSUPPORTED_BY_POLICY", "reason_code": "UNSUPPORTED_BY_POLICY"},
            eni={"status": "UNSUPPORTED_API", "reason_code": "UNSUPPORTED_API"},
            **{"lambda": {"status": "LIVE_GATE_PENDING", "reason_code": "LIVE_GATE_PENDING",
                          "evidence_refs": ("test-only offline evidence",)}})
        coverage = report_kind_capability_coverage(plan, decisions, outcomes)
        kinds = coverage["kinds"]
        statuses = {k: kinds[k]["capability"]["status"] for k in
                    ("instance", "eni", "snapshot", "lambda", "volume")}
        self.assertEqual(statuses, {
            "instance": "UNSUPPORTED_BY_POLICY", "eni": "UNSUPPORTED_API",
            "snapshot": "CAPABILITY_NOT_PROVEN", "lambda": "LIVE_GATE_PENDING",
            "volume": "IMPLEMENTED_OFFLINE"})
        self.assertEqual(kinds["snapshot"]["capability"]["reason_code"], "ARN_OWNER_NOT_PROVEN")
        # NOT_RUN (live acceptance) is a separate axis from every capability status.
        self.assertEqual(coverage["live_acceptance"], "NOT_RUN")
        for kind in caps.REGISTRY_KINDS:
            with self.subTest(kind=kind):
                self.assertEqual(kinds[kind]["live_acceptance"], "NOT_RUN")
                self.assertNotEqual(kinds[kind]["capability"]["status"], "NOT_RUN")
        self.assertEqual({k: kinds[k]["offline_dispatch"]["dispatchable"] for k in caps.REGISTRY_KINDS
                          if kinds[k]["offline_dispatch"]["dispatchable"]}, {"volume": True})
        self.assertEqual(kinds["lambda"]["offline_dispatch"]["block_reason"], "LIVE_GATE_PENDING")
        self.assertEqual(kinds["snapshot"]["offline_dispatch"]["block_reason"],
                         "ARN_OWNER_NOT_PROVEN")
        # Capability and outcome are independent axes: changing the decision never moves rows.
        production = report_kind_capability_coverage(plan, production_kind_decisions(), outcomes)
        for kind in caps.REGISTRY_KINDS:
            self.assertEqual(production["kinds"][kind]["outcomes"], kinds[kind]["outcomes"])
            self.assertEqual(production["kinds"][kind]["precap"], kinds[kind]["precap"])
        # Row-level report carries the capability axis next to the unchanged outcome.
        rows = build_batch_dry_run(encode(plan), build_batch_review_projection(encode(plan)))["rows"]
        by_kind = {row["kind"]: row for row in rows}
        self.assertEqual((by_kind["s3_bucket"]["capability_status"],
                          by_kind["s3_bucket"]["capability_reason_code"],
                          by_kind["s3_bucket"]["outcome"]),
                         ("CAPABILITY_NOT_PROVEN", "ARN_OWNER_NOT_PROVEN", "WRITE_UNSUPPORTED"))
        # Reason codes must be grounded, never silently defaulted.
        for bad in (decisions_with(snapshot={"reason_code": "SOMETHING"}),
                    decisions_with(snapshot={"reason_code": ""}),
                    decisions_with(volume={"evidence_refs": ()}),
                    decisions_with(snapshot={"status": "NOT_RUN"}),
                    MappingProxyType({k: v for k, v in production_kind_decisions().items()
                                      if k != "wafv2"}),
                    MappingProxyType({**production_kind_decisions(),
                                      "eni": production_kind_decisions()["eip"]}),
                    MappingProxyType({**production_kind_decisions(), "bogus": None})):
            with self.subTest(bad=bad), self.assertRaises(ReportBlocked):
                report_kind_capability_coverage(plan, bad, outcomes)

    def test_signed_forgery_not_downgraded_to_unsupported_skip(self):
        plan = eighteen_kind_plan()
        s3_index = next(i for i, r in enumerate(plan["records"]) if r["kind"] == "s3_bucket")
        # (a) forged operation on a CNP row: rejected as a whole, never WRITE_UNSUPPORTED.
        for operation in ("s3:PutBucketTagging", "s3control:TagResource", "ec2:CreateTags"):
            forged = copy.deepcopy(plan)
            forged["records"][s3_index]["aws_operation"] = operation
            with self.subTest(operation=operation), self.assertRaises(ReportBlocked):
                build_batch_dry_run(encode(forged), build_batch_review_projection(encode(forged)))
        # (b) approved YES on a CNP row rejects the entire draft (not a reasoned skip).
        plan_bytes = encode(plan)
        with self.assertRaises(ReportBlocked):
            build_batch_dry_run(plan_bytes, approve(plan_bytes, "proposal-instance"))
        # (c) an attempt outcome claimed for an unsignable row is rejected.
        outcomes = preview_outcomes(plan)
        for claimed in ("APPLIED_VERIFIED", "OUTCOME_UNKNOWN", "NOT_ATTEMPTED_CAP"):
            with self.subTest(claimed=claimed), self.assertRaises(ReportBlocked):
                report_kind_capability_coverage(plan, production_kind_decisions(),
                                                {**outcomes, s3_index: claimed})
        # (d) the durable-outcome path refuses an unapproved/unsigned row.
        report = build_batch_dry_run(plan_bytes, build_batch_review_projection(plan_bytes))
        with self.assertRaises(BatchOutcomeError):
            reconcile_batch_outcomes(report, {s3_index: "APPLIED_VERIFIED"})
        # Legitimate unapproved CNP row: reasoned report, capability preserved.
        entry = report["kind_capability_coverage"]["kinds"]["s3_bucket"]
        self.assertEqual(list(entry["outcomes"]), ["WRITE_UNSUPPORTED"])
        self.assertEqual(entry["capability"]["status"], "CAPABILITY_NOT_PROVEN")
        self.assertEqual(entry["offline_dispatch"]["block_reason"], "ARN_OWNER_NOT_PROVEN")
        # Malformed outcome maps: missing/extra/unknown rows are rejected.
        for bad in ({k: v for k, v in outcomes.items() if k != 0}, {**outcomes, 99: "UNAPPROVED"},
                    {**outcomes, 0: "LIVE_VERIFIED"}, {**outcomes, "0": "UNAPPROVED"}):
            with self.subTest(bad=list(bad.items())[-1]), self.assertRaises(ReportBlocked):
                report_kind_capability_coverage(plan, production_kind_decisions(), bad)

    def test_one_kind_block_does_not_enable_others(self):
        plan = eighteen_kind_plan()
        outcomes = preview_outcomes(plan)

        def dispatchable(decisions):
            coverage = report_kind_capability_coverage(plan, decisions, outcomes)
            return {k for k, v in coverage["kinds"].items() if v["offline_dispatch"]["dispatchable"]}, coverage

        base, _ = dispatchable(production_kind_decisions())
        self.assertEqual(base, {"volume"})
        promoted = {"status": "IMPLEMENTED_OFFLINE", "reason_code": "OFFLINE_CONTRACT_COMPLETE",
                    "evidence_refs": ("test-only fixture",)}
        only_instance, _ = dispatchable(decisions_with(instance=promoted))
        self.assertEqual(only_instance, {"volume", "instance"})
        blocked, coverage = dispatchable(decisions_with(
            instance={"status": "UNSUPPORTED_BY_POLICY", "reason_code": "UNSUPPORTED_BY_POLICY"}))
        self.assertEqual(blocked, {"volume"})
        self.assertEqual(coverage["kinds"]["eni"]["capability"]["status"], "CAPABILITY_NOT_PROVEN")
        # Policy-level blocks survive any decision value: S3 (tag-set replacement unproven),
        # API Gateway (IAM condition) and tag-set replacement never become dispatchable.
        overrides, coverage = dispatchable(decisions_with(
            s3_bucket=promoted, apigw_stage=promoted,
            eni={**promoted, "tag_set_replacement": True}))
        self.assertEqual(overrides, {"volume"})
        self.assertEqual(coverage["kinds"]["s3_bucket"]["offline_dispatch"]["block_reason"],
                         "TAG_SET_REPLACEMENT_NOT_PROVEN")
        self.assertEqual(coverage["kinds"]["apigw_stage"]["offline_dispatch"]["block_reason"],
                         "IAM_CONDITION_NOT_PROVEN")
        self.assertEqual(coverage["kinds"]["eni"]["offline_dispatch"]["block_reason"],
                         "UNSUPPORTED_BY_POLICY")
        # The report's live-dispatch block mirrors the live dispatcher exactly.
        import name_tag_batch_live
        import name_tag_batch_report
        self.assertEqual(dict(name_tag_batch_report._LIVE_NOT_DISPATCHABLE),
                         dict(name_tag_batch_live._LIVE_DISPATCH_BLOCKED))

    def test_tampered_by_kind_count_or_cost_rejects(self):
        plan = eighteen_kind_plan()

        def mutated(change):
            forged = copy.deepcopy(plan)
            change(forged["cur_population_by_kind"])
            return forged

        def stage(field, kind, name):
            return field["kinds"][kind][name]

        def move_selected(field):
            # Keeps every per-stage total and every per-Kind identity: only the signed selected
            # record detail can catch it.
            shift_cost(field, ("cur_recognized", "above_min_cost", "lookup_selected"),
                       "instance", "eni")

        cases = {
            "count": lambda f: stage(f, "lambda", "below_min_cost").update(count=2),
            "cost": lambda f: stage(f, "lambda", "below_min_cost").update(cost_usd="-0.0001"),
            "noncanonical": lambda f: stage(f, "lambda", "below_min_cost").update(
                cost_usd=stage(f, "lambda", "below_min_cost")["cost_usd"] + "0"),
            "nan": lambda f: stage(f, "lambda", "below_min_cost").update(cost_usd="NaN"),
            "float": lambda f: stage(f, "lambda", "below_min_cost").update(cost_usd=0.5),
            "negative count": lambda f: stage(f, "eni", "below_min_cost").update(count=-1),
            "extra kind": lambda f: f["kinds"].update(bogus=copy.deepcopy(f["kinds"]["eni"])),
            "missing kind": lambda f: f["kinds"].pop("wafv2"),
            "extra stage": lambda f: f["kinds"]["eni"].update(selected={"count": 0, "cost_usd": "0"}),
            "schema": lambda f: f.update(schema_version=2),
            "move selected": move_selected,
        }
        for label, change in cases.items():
            forged = mutated(change)
            outcomes = {i: "WRITE_UNSUPPORTED" for i in range(len(plan["records"]))}
            with self.subTest(label), self.assertRaises(ReportBlocked):
                report_kind_capability_coverage(forged, production_kind_decisions(), outcomes)
            with self.subTest(f"dry-run {label}"), self.assertRaises(ReportBlocked):
                # The review CSV depends only on the records, so it comes from the valid Plan.
                build_batch_dry_run(encode(forged), build_batch_review_projection(encode(plan)))


class SignedCoverageTests(unittest.TestCase):
    NOW = _evidence_tests.SignedNonVolumeTests.NOW
    setUp_owner = _evidence_tests.SignedNonVolumeTests.setUp

    def setUp(self):
        self.setUp_owner()
        self.kw["authorized_role_arn"] = f"arn:aws:iam::{ACCT}:role/batch"
        self.signed = 0

    def sign(self, plan, csv):
        # A fresh message path per signature: ssh-keygen never prompts to overwrite a .sig.
        self.signed += 1
        prepared = prepare_batch_approval(plan, csv, **self.kw)
        message = self.root / f"payload-{self.signed}"
        message.write_bytes(prepared.canonical_payload_bytes)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", BATCH_NAMESPACE,
                        str(message)], check=True, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        signature = message.with_name(message.name + ".sig").read_bytes()
        return json.dumps({"payload": prepared.payload, "batch_id": prepared.batch_id,
                           "signature_ref": base64.b64encode(signature).decode()},
                          separators=(",", ":")).encode()

    def verified(self, plan_bytes, csv):
        envelope = self.sign(plan_bytes, csv)
        return envelope, verify_batch_approval(plan_bytes, csv, envelope, trust=self.trust,
                                               now_utc=self.NOW)

    def test_legacy_signed_plan_without_kind_breakdown_reports_unavailable(self):
        legacy = encode(eighteen_kind_plan(with_breakdown=False))
        self.assertNotIn(b"cur_population_by_kind", legacy)
        csv = approve(legacy, "proposal-volume")
        _envelope, batch = self.verified(legacy, csv)  # historical bytes verify unchanged
        self.assertEqual(batch.plan_bytes, legacy)
        report = make_authenticated_batch_report(batch, plan_bytes=legacy, csv_bytes=csv,
                                                 trust=self.trust, now_utc=self.NOW)
        coverage = report["kind_capability_coverage"]
        self.assertEqual(coverage["precap_status"], PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE)
        for kind in caps.REGISTRY_KINDS:
            with self.subTest(kind=kind):
                entry = coverage["kinds"][kind]
                self.assertIsNone(entry["precap"])  # never zero-filled
                self.assertEqual(entry["precap_status"], PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE)
                self.assertEqual(entry["selected"]["count"], 1)  # post-selection detail only
        self.assertNotIn('"below_min_cost": {"count": 0', json.dumps(coverage["kinds"]))
        # Global totals still come from the signed schema-2 population.
        self.assertEqual(coverage["precap_total"]["below_min_cost"]["count"], 18)
        self.assertEqual(report["outcome_reconciliation"]["NOT_ATTEMPTED_OWNER_VERIFIED"]["count"], 1)

    def test_new_plan_breakdown_is_signed_under_existing_plan_sha256(self):
        legacy_plan = encode(eighteen_kind_plan(with_breakdown=False))
        plan_bytes = encode(eighteen_kind_plan())
        csv = approve(plan_bytes, "proposal-volume")
        envelope, batch = self.verified(plan_bytes, csv)
        payload = json.loads(envelope)["payload"]
        self.assertEqual(payload["plan_sha256"], hashlib.sha256(plan_bytes).hexdigest())
        self.assertIn(b'"cur_population_by_kind"', plan_bytes)
        _legacy_envelope, _legacy = self.verified(legacy_plan, approve(legacy_plan, "proposal-volume"))
        self.assertEqual(set(json.loads(_legacy_envelope)["payload"]), set(payload))  # no new field
        report = make_authenticated_batch_report(batch, plan_bytes=plan_bytes, csv_bytes=csv,
                                                 trust=self.trust, now_utc=self.NOW)
        self.assertEqual(report["kind_capability_coverage"]["precap_status"],
                         "SIGNED_PLAN_CUR_POPULATION_BY_KIND")
        # A tamper that keeps every arithmetic identity is only caught by the signature.
        forged = json.loads(plan_bytes)
        shift_cost(forged["cur_population_by_kind"], ("cur_recognized", "below_min_cost"),
                   "instance", "eni")
        forged_bytes = encode(forged)
        build_batch_dry_run(forged_bytes, csv)  # arithmetically consistent, unsigned preview
        with self.assertRaises(BatchAuthRejected):
            verify_batch_approval(forged_bytes, csv, envelope, trust=self.trust, now_utc=self.NOW)
        dropped = json.loads(plan_bytes)
        del dropped["cur_population_by_kind"]
        with self.assertRaises(BatchAuthRejected):
            verify_batch_approval(encode(dropped), csv, envelope, trust=self.trust, now_utc=self.NOW)


if __name__ == "__main__":
    unittest.main()
