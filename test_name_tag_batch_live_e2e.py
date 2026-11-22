"""Offline Task 9 Fake E2E: Plan -> unsigned Preview -> approved CSV -> Owner signature ->
verified row -> protected injected Host -> Intent -> consumed Permit -> one write -> Readback
-> 18-Kind report.

Everything here is SYNTHETIC: Fake STS transport, Fake SDK client, Fake Host OS probe and a
TEST-ONLY "mock-proven" IAM evidence minted directly into the protected registry (no
production producer exists). The representative non-volume Kind ``instance`` is promoted
only inside each test by the TEST-ONLY fixture; the production Registry is never promoted.
A Fake successful write is never live acceptance: genuine Host acceptance is NOT_RUN and
G1/G2 stay unproven.
"""
from __future__ import annotations

import base64
import contextlib
import json
import os
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import aws_cost_name_tagger_v3 as tagger
import name_tag_batch_host_runtime as host_runtime
import name_tag_kind_capabilities as caps
from name_tag_batch_approval import (
    BATCH_NAMESPACE, BatchAuthRejected, prepare_batch_approval, verify_batch_approval)
from name_tag_batch_iam import verified_kind_policy
from name_tag_batch_iam_evidence import IamDenyCase
from name_tag_batch_live import LiveWriteBlocked, live_dispatch_adapter
from name_tag_batch_report import ReportBlocked, build_batch_dry_run
from name_tag_batch_state import build_batch_review_projection
from test_name_tag_batch_identity_projection import write_cur
from test_name_tag_batch_ledger import ACCOUNT, REGION, ROLE_ARN
import test_name_tag_batch_live_runtime as _live_runtime_tests
from test_name_tag_batch_live_runtime import ISSUED, FakeCloud, LiveHarness
from test_name_tag_kind_name_evidence import proven_instance_fixture

INSTANCES = ("i-0123456789abcdef0", "i-0123456789abcdef1", "i-0123456789abcdef2")
BUCKET = "shop-assets-bucket"
FORBIDDEN_LIVE_CLAIMS = ("LIVE_VERIFIED", "LIVE_ACCEPTED", "G2_PASS", "G1_PROVEN",
                         '"live_status": "VERIFIED"', '"live_acceptance": "PASS"')


def instance_arn(instance_id):
    return f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{instance_id}"


def instance_name(instance_id):
    return f"shop-prod-ec2-{instance_id[-7:]}"


def _instance_deny_cases(arn, action="ec2:CreateTags"):
    other = arn.replace("i-0", "i-9")
    return (IamDenyCase("FOREIGN_ARN", other, action, "Name", "DENY"),
            IamDenyCase("OTHER_TAG_KEY", arn, action, "Owner", "DENY"),
            IamDenyCase("ALTERNATE_API", arn, "ec2:DeleteTags", "Name", "DENY"))


class _Session:
    """Fake STS for plan_batch's account assertion; never networks."""

    class _Sts:
        def get_caller_identity(self):
            return {"Account": ACCOUNT}

    def client(self, service, region_name=None, config=None):
        return self._Sts()


def _cur_row(resource_id, cost, region=REGION):
    return {"bill_billing_period_start_date": "2026-10-01", "line_item_usage_account_id": ACCOUNT,
            "line_item_line_item_type": "Usage", "line_item_resource_id": resource_id,
            "line_item_unblended_cost": cost, "reservation_effective_cost": "",
            "savings_plan_savings_plan_effective_cost": "", "product_region_code": region,
            "line_item_product_code": "X", "line_item_currency_code": "USD"}


def _info(kind, target, *, evidence, name):
    return {"status": "proposed", "proposed_name": name, "confidence": "high",
            "evidence": evidence, "write_target": target, "kind": kind, "name_state": "ABSENT",
            "name_key_present": False, "name_raw_value": None, "existing_name": ""}


class InstanceCloud(FakeCloud):
    """Fake EC2 instance tag state; records which client object served each call."""

    def __init__(self):
        super().__init__()
        self.calls: list[tuple[int, str, str]] = []
        self.fail_write_number: int | None = None

    def create(self, service, region, *, access_key_id, secret_access_key, session_token):
        assert (access_key_id, secret_access_key, session_token) == ISSUED
        self.created.append((service, region, access_key_id))
        return _InstanceClient(self)


class _InstanceClient:
    def __init__(self, cloud):
        self.cloud = cloud
        self.reads = 0

    def describe_instances(self, *, InstanceIds):
        (instance_id,) = InstanceIds
        self.reads += 1
        self.cloud.calls.append((id(self), "describe_instances", instance_id))
        if self.cloud.readback_override is not None and self.reads > 1:
            return self.cloud.readback_override
        tags = self.cloud.tags.setdefault(instance_id, {})
        return {"Reservations": [{"Instances": [{
            "InstanceId": instance_id, "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}]}]}

    def create_tags(self, *, Resources, Tags):
        (instance_id,) = Resources
        (tag,) = Tags
        self.cloud.calls.append((id(self), "create_tags", instance_id))
        self.cloud.writes.append((instance_id, tuple(sorted(tag.items()))))
        self.cloud.tags.setdefault(instance_id, {})[tag["Key"]] = tag["Value"]
        if self.cloud.fail_write_number == len(self.cloud.writes):
            raise ConnectionResetError("synthetic transport loss after send")


class FakeE2EHarness(LiveHarness):
    """Task 7 Host harness, re-pointed at a TEST-ONLY proven ``instance`` Kind."""

    def setUp(self):
        super().setUp()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(proven_instance_fixture())
        self.cloud = InstanceCloud()
        self.issuer._factory = self.cloud
        self.kind_registry = {
            "instance": verified_kind_policy(caps.resolve_kind_capability("instance"))}
        self.work = Path(tempfile.mkdtemp(prefix="e2e-", dir=self.fx.state_dir))

    def evidence_source(self, issued, row, scope):
        # Same TEST-ONLY mock-proven evidence as Task 7, with instance-shaped deny probes.
        with mock.patch.object(_live_runtime_tests, "_deny_cases", _instance_deny_cases):
            return super().evidence_source(issued, row, scope)

    # ---- Plan -> unsigned Preview -> approved CSV -> signature -------------------------
    def generate_plan(self, instances, *, cap, extra_rows=(), extra_infos=None):
        cur = self.work / f"cur-{len(os.listdir(self.work))}.csv.gz"
        rows = [_cur_row(i, str(10 + n)) for n, i in enumerate(instances)] + list(extra_rows)
        write_cur(cur, rows)
        out = cur.with_name(cur.name.replace(".csv.gz", ".plan.json"))
        scopes = [{"writer_control_scope_id": "scope-1", "account": ACCOUNT, "partition": "aws",
                   "region": REGION, "resource_arns": sorted(instance_arn(i) for i in instances)}]
        infos = {i: _info("instance", instance_arn(i),
                          evidence=f"FIXTURE EC2 {i} tags app=shop env=prod", name=instance_name(i))
                 for i in instances}
        infos.update(extra_infos or {})

        class Investigator:
            def __init__(self, session, account, retries=3):
                pass

            def resolve(self, item, **kwargs):
                return dict(infos[item["locator"]])

        args = tagger.parse_cli(["batch-plan", "--cur", str(cur), "--month", "2026-10",
                                 "--account", ACCOUNT, "--min-cost", "1", "--max-resources", "10",
                                 "--max-send-attempts", str(cap), "--scope-declarations",
                                 str(self.work / "s.json"), "--output", str(out)])
        with mock.patch.object(tagger, "Investigator", Investigator):
            tagger.plan_batch(args, scope_declarations=scopes, session=_Session())
        plan_bytes = out.read_bytes()
        review = out.with_suffix(tagger.REVIEW_CSV_SUFFIX).read_bytes()
        self.assertEqual(review, build_batch_review_projection(plan_bytes))
        return plan_bytes, review

    def approve(self, plan_bytes, review, *kinds):
        csv = review
        for record in json.loads(plan_bytes)["records"]:
            if record["kind"] in kinds:
                pid = record["proposal_id"]
                csv = csv.replace(f",{pid},".encode(), f"YES,{pid},".encode())
        return csv

    def sign(self, plan_bytes, csv):
        prepared = prepare_batch_approval(
            plan_bytes, csv, owner_principal_id="batch-owner",
            owner_key_fingerprint=self.batch_fingerprint, authorized_role_arn=ROLE_ARN,
            issued_at_utc=self.now.isoformat().replace("+00:00", "Z"),
            expires_at_utc=(self.now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            batch_nonce=os.urandom(16).hex())
        signature = self._sign(self.batch_key_path, prepared.canonical_payload_bytes,
                               BATCH_NAMESPACE)
        return json.dumps({"payload": prepared.payload, "batch_id": prepared.batch_id,
                           "signature_ref": base64.b64encode(signature).decode("ascii")},
                          separators=(",", ":")).encode()

    def signed_batch(self, instances=INSTANCES[:1], *, cap=1, approve=("instance",), **plan_kw):
        plan_bytes, review = self.generate_plan(instances, cap=cap, **plan_kw)
        preview = build_batch_dry_run(plan_bytes, review)
        self.assertEqual((preview["authentication_state"], preview["execution_allowed"]),
                         ("UNSIGNED_PREVIEW", False))
        csv = self.approve(plan_bytes, review, *approve)
        approved_preview = build_batch_dry_run(plan_bytes, csv)
        self.assertEqual(approved_preview["approved_count"], len(instances))
        envelope = self.sign(plan_bytes, csv)
        with self.trusted():
            batch = verify_batch_approval(plan_bytes, csv, envelope, trust=self.trust,
                                          now_utc=self.now)
            self.source.scope, self.source.effects = self.init_scope(
                self.ledger, [instance_arn(i) for i in instances])
        return batch

    def assert_no_live_claim(self, *documents):
        text = json.dumps(documents, sort_keys=True, default=str)
        for claim in FORBIDDEN_LIVE_CLAIMS:
            self.assertNotIn(claim, text)


class FakeE2ETests(FakeE2EHarness):
    def test_fake_e2e_plan_to_report_one_instance_write(self):
        batch = self.signed_batch()
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED",))
        self.assertEqual(len(self.sts.calls), 1)
        self.assertEqual(self.cloud.writes, [
            (INSTANCES[0], (("Key", "Name"), ("Value", instance_name(INSTANCES[0]))))])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM intent_history WHERE "
                                  "event='SEND_ATTEMPT_CONSUMED'"), [(1,)])
        self.assertEqual(self.intents(), [("TERMINAL", "APPLIED_VERIFIED", "ec2:CreateTags")])
        # Same session: one client (one issued credential set) did read, write and readback.
        self.assertEqual(len(self.cloud.created), 1)
        self.assertEqual([op for _, op, _ in self.cloud.calls],
                         ["describe_instances", "create_tags", "describe_instances"])
        self.assertEqual(len({client for client, _, _ in self.cloud.calls}), 1)
        coverage = result.report["kind_capability_coverage"]
        self.assertEqual(coverage["kinds"]["instance"]["outcomes"],
                         {"APPLIED_VERIFIED": {"count": 1, "cost_usd": "10"}})
        self.assertEqual(coverage["kinds"]["instance"]["precap"]["lookup_selected"],
                         {"count": 1, "cost_usd": "10"})
        self.assertEqual(coverage["precap_status"], "SIGNED_PLAN_CUR_POPULATION_BY_KIND")
        stored = self.report_file(batch.batch_id, result.report["report_sha256"])
        self.assertEqual(stored["kind_capability_coverage"], coverage)
        self.assertEqual(stored["live_status"], "NOT_VERIFIED")
        for secret in ISSUED[1:]:
            self.assertNotIn(secret, json.dumps(stored))

    def test_fake_e2e_same_session_cap_and_unknown(self):
        # Cap: three signed rows, cap 2. Row 2's synthetic send loses its response.
        self.cloud.fail_write_number = 2
        batch = self.signed_batch(INSTANCES, cap=2)
        result = self.run_live(batch)
        self.assertEqual(len(self.sts.calls), 2)
        self.assertEqual(len(self.cloud.writes), 2)
        state = self.state(batch)
        self.assertEqual(state.outcomes[:2], ("APPLIED_VERIFIED", "OUTCOME_UNKNOWN"))
        self.assertEqual(state.state, "STOPPED")
        self.assertEqual(self.scope_state(), "HOLD")
        self.assertEqual(result.report["live_status"], "NOT_VERIFIED")
        self.assertEqual(result.report["kind_capability_coverage"]["kinds"]["instance"]["outcomes"][
            "OUTCOME_UNKNOWN"]["count"], 1)
        # Each issued session served exactly its own row's read/write(/readback).
        per_client = {}
        for client, op, target in self.cloud.calls:
            per_client.setdefault(client, set()).add(target)
        self.assertEqual(len(per_client), 2)
        self.assertTrue(all(len(targets) == 1 for targets in per_client.values()))
        # No replay: rerunning the same signed Batch never re-issues STS or resends.
        try:
            again = self.run_live(batch, self.runtime()).outcomes
        except host_runtime.HostRuntimeBlocked:
            again = self.state(batch).outcomes
        self.assertEqual(again[:2], ("APPLIED_VERIFIED", "OUTCOME_UNKNOWN"))
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)), (2, 2))

    def test_fake_e2e_cross_kind_cap_reports_not_attempted(self):
        batch = self.signed_batch(INSTANCES[:2], cap=1)
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED", "NOT_ATTEMPTED_CAP"))
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)), (1, 1))
        outcomes = result.report["kind_capability_coverage"]["kinds"]["instance"]["outcomes"]
        # Plan rows are cost-ranked: the 11 USD row is signed first and consumes the cap.
        self.assertEqual(outcomes, {"APPLIED_VERIFIED": {"count": 1, "cost_usd": "11"},
                                    "NOT_ATTEMPTED_CAP": {"count": 1, "cost_usd": "10"}})

    def test_fake_e2e_cnp_rows_reported_never_dispatched(self):
        extra_rows = [_cur_row(BUCKET, "7"), _cur_row(f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:my-func", "0.25")]
        extra_infos = {BUCKET: _info("s3_bucket", f"arn:aws:s3:::{BUCKET}",
                                     evidence="deterministic evidence", name="shop-assets")}
        plan_bytes, review = self.generate_plan(INSTANCES[:1], cap=1, extra_rows=extra_rows,
                                                extra_infos=extra_infos)
        s3 = next(r for r in json.loads(plan_bytes)["records"] if r["kind"] == "s3_bucket")
        self.assertIsNone(s3["aws_operation"])  # CNP: preview only, no signable operation
        with self.assertRaises(ReportBlocked):
            build_batch_dry_run(plan_bytes, self.approve(plan_bytes, review, "instance", "s3_bucket"))
        with self.assertRaises(BatchAuthRejected):
            self.sign(plan_bytes, self.approve(plan_bytes, review, "s3_bucket"))
        csv = self.approve(plan_bytes, review, "instance")
        with self.trusted():
            batch = verify_batch_approval(plan_bytes, csv, self.sign(plan_bytes, csv),
                                          trust=self.trust, now_utc=self.now)
            self.source.scope, self.source.effects = self.init_scope(
                self.ledger, [instance_arn(INSTANCES[0])])
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED",))
        self.assertEqual([w[0] for w in self.cloud.writes], [INSTANCES[0]])
        kinds = result.report["kind_capability_coverage"]["kinds"]
        self.assertEqual(kinds["s3_bucket"]["capability"]["status"], "CAPABILITY_NOT_PROVEN")
        self.assertEqual(kinds["s3_bucket"]["outcomes"],
                         {"WRITE_UNSUPPORTED": {"count": 1, "cost_usd": "7"}})
        self.assertEqual(kinds["lambda"]["precap"]["below_min_cost"],
                         {"count": 1, "cost_usd": "0.25"})
        self.assertEqual(kinds["lambda"]["selected"], {"count": 0, "cost_usd": "0"})

    def test_fake_e2e_tag_set_never_replaced(self):
        self.cloud.tags[INSTANCES[0]] = {"env": "prod", "Owner": "team-a"}
        result = self.run_live(self.signed_batch())
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED",))
        self.assertEqual(self.cloud.tags[INSTANCES[0]], {
            "env": "prod", "Owner": "team-a", "Name": instance_name(INSTANCES[0])})
        self.assertEqual(len(self.cloud.writes), 1)  # one request, exactly one Name tag
        # S3 (tag-set replacement unproven) stays non-dispatchable even if promoted.
        with self.assertRaises(LiveWriteBlocked) as caught:
            live_dispatch_adapter("s3_bucket")
        self.assertEqual(caught.exception.code, "TAG_SET_REPLACEMENT_NOT_PROVEN")
        self.assertEqual(result.report["kind_capability_coverage"]["kinds"]["s3_bucket"][
            "offline_dispatch"], {"dispatchable": False, "block_reason": "ARN_OWNER_NOT_PROVEN"})

    def test_fake_e2e_stale_name_proof_skips_without_send(self):
        batch = self.signed_batch()
        self.cloud.tags[INSTANCES[0]] = {"Name": "someone-else"}  # changed after signing
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("SKIPPED_NAME_CHANGED",))
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM intent_history WHERE "
                                  "event='SEND_ATTEMPT_CONSUMED'"), [(0,)])

    def test_fake_e2e_stale_iam_proof_refused_before_intent(self):
        batch = self.signed_batch()
        self.evidence_kind = "synthetic"  # unproven/stale evidence never satisfies the Host
        blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual((self.intents(), self.cloud.writes), ([], []))

    def test_fake_e2e_wrong_readback_is_never_applied_verified(self):
        batch = self.signed_batch()
        self.cloud.readback_override = {"Reservations": [{"Instances": [{
            "InstanceId": INSTANCES[0], "Tags": [{"Key": "Name", "Value": "other"}]}]}]}
        try:
            result = self.run_live(batch)
            outcomes = result.outcomes
        except host_runtime.HostRuntimeBlocked:
            outcomes = self.state(batch).outcomes
        self.assertEqual(len(self.cloud.writes), 1)
        self.assertNotIn("APPLIED_VERIFIED", outcomes)

    def test_fake_e2e_same_batch_rerun_never_resends(self):
        batch = self.signed_batch()
        self.run_live(batch)
        again = self.run_live(batch, self.runtime())
        self.assertEqual(again.outcomes, ("APPLIED_VERIFIED",))
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)), (1, 1))


class NoLiveClaimTests(FakeE2EHarness):
    def test_no_fake_result_claims_live_acceptance(self):
        batch = self.signed_batch()
        result = self.run_live(batch)
        stored = self.report_file(batch.batch_id, result.report["report_sha256"])
        coverage = result.report["kind_capability_coverage"]
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED",))  # synthetic Fake success
        self.assertEqual((result.report["live_status"], stored["live_status"]),
                         ("NOT_VERIFIED", "NOT_VERIFIED"))
        self.assertEqual(coverage["live_acceptance"], "NOT_RUN")
        for kind in caps.REGISTRY_KINDS:
            self.assertEqual(coverage["kinds"][kind]["live_acceptance"], "NOT_RUN")
        self.assertIs(result.report["execution_allowed"], False)
        self.assert_no_live_claim(dict(result.report), stored)
        # APPLIED_VERIFIED is backed by a consumed Permit plus same-session Readback in the
        # Ledger, never by a status imported from the Fake client.
        self.assertEqual(self.sql("SELECT COUNT(*) FROM intent_history WHERE "
                                  "event='SEND_ATTEMPT_CONSUMED'"), [(1,)])
        self.assertEqual(self.intents(), [("TERMINAL", "APPLIED_VERIFIED", "ec2:CreateTags")])
        self.assertEqual(stored["execution_mode"], "HOST_PROTECTED_DISPATCH")

    def test_fake_host_bootstrap_does_not_imply_g2_pass(self):
        # The Fake Host bootstrap verified (self.host) — that alone authorizes nothing.
        batch = self.signed_batch()
        self.evidence_kind = "synthetic"
        blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual((self.intents(), self.cloud.writes), ([], []))
        with self.assertRaises(host_runtime.HostRuntimeBlocked):
            host_runtime.production_host_runtime()
        self.assertIsNone(host_runtime.production_host_endpoint()._coordinator)
        self.assert_no_live_claim(vars(self.host) if hasattr(self.host, "__dict__") else repr(self.host),
                                  repr(blocked))


class ProductionRegistryUnchangedTests(unittest.TestCase):
    def test_fixture_never_promotes_production_registry(self):
        self.assertEqual(caps.resolve_kind_capability("instance").status, "CAPABILITY_NOT_PROVEN")
        self.assertEqual([k for k in caps.REGISTRY_KINDS
                          if caps.resolve_kind_capability(k).status == "IMPLEMENTED_OFFLINE"],
                         ["volume"])
        with self.assertRaises(LiveWriteBlocked):
            live_dispatch_adapter("instance")


if __name__ == "__main__":
    unittest.main()
