"""Offline Task 3 tests: evidence-backed Name generation and approved-row eligibility.

The bounded EC2 `instance` capability/evidence below is a TEST-ONLY fixture. It is
patched in only inside each test and never promotes a production Registry decision.
"""
from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from unittest import mock

import name_tag_kind_capabilities as caps
import name_tag_kind_name_evidence as evidence_module
from name_tag_approval import EnrolledOwner, OwnerTrust
from name_tag_batch_approval import (
    BATCH_NAMESPACE, BatchAuthRejected, derive_batch_row_authority, prepare_batch_approval,
    verify_batch_approval)
from name_tag_batch_state import (
    BatchValidationError, build_batch_review_projection, validate_batch_draft)
from test_helpers import sample_population
from test_name_tag_batch_identity_projection import ACCT, INSTANCE, R, PlanFixture, info_for

INSTANCE_ARN = f"arn:aws:ec2:{R}:{ACCT}:instance/{INSTANCE}"
INSTANCE_EVIDENCE = f"FIXTURE EC2 {INSTANCE} tags app=shop env=prod"
INSTANCE_NAME = f"shop-prod-ec2-{INSTANCE[-7:]}"
VOL = "vol-abcdef12345678901"
VOL_ARN = f"arn:aws:ec2:{R}:123456789012:volume/{VOL}"
VOL_EVIDENCE = (f"EBS {VOL} -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 "
                "Name=app-prod; Product(observed, not validated)=(unset)")
VOL_NAME = "app-prod-ebs-xvda-5678901"


class FixtureInstanceVerifier:
    """Test-only deterministic evidence formula: <app>-<env>-ec2-<last 7 of id>."""

    def verify(self, plan_record, target):
        import re
        evidence = plan_record.get("evidence")
        match = re.fullmatch(
            rf"FIXTURE EC2 {re.escape(target.locator)} tags app=([a-z]+) env=([a-z]+)", evidence or "")
        if match is None:
            raise evidence_module.NameEvidenceNotProven("fixture evidence mismatch")
        name = f"{match.group(1)}-{match.group(2)}-ec2-{target.locator[-7:]}"
        return evidence_module.VerifiedGeneratedName(
            target.kind, target.resource_arn, name,
            hashlib.sha256(evidence.encode()).hexdigest())


@contextlib.contextmanager
def proven_instance_fixture():
    """Patch the registry and verifier map only for the duration of one test."""
    decision = dataclasses.replace(
        caps.resolve_kind_capability("instance"), status="IMPLEMENTED_OFFLINE",
        reason_code="OFFLINE_CONTRACT_COMPLETE", evidence_refs=("test-only fixture",))
    decisions = MappingProxyType({**caps._DECISIONS, "instance": decision})
    with mock.patch.object(caps, "_DECISIONS", decisions), \
            mock.patch.dict(evidence_module._VERIFIERS, {"instance": FixtureInstanceVerifier()}):
        yield


def _record(kind, locator, arn, region, name, evidence, operation="ec2:CreateTags", pid="p"):
    return {"proposal_id": pid, "kind": kind, "locator": locator, "region": region,
            "resource_arn": arn, "aws_operation": operation, "status": "proposed",
            "confidence": "high", "name_state": "ABSENT", "name_key_present": False,
            "name_raw_value": None, "existing_name": "", "proposed_name": name,
            "effective_usage_cost_usd": "1", "evidence": evidence}


def _plan(records, scopes, account="123456789012"):
    count = len(records)
    return json.dumps({
        "schema_version": 3, "account": account, "partition": "aws", "count": count,
        "execution_limits": {"max_send_attempts": 1},
        "cur_population": sample_population(count=count, cost=str(count)),
        "scope_declarations": scopes, "records": records}).encode()


def _scope(arns, region=R, sid="s", account="123456789012"):
    return {"writer_control_scope_id": sid, "account": account, "partition": "aws",
            "region": region, "resource_arns": sorted(arns)}


def _volume_record(pid="p"):
    return _record("volume", VOL, VOL_ARN, R, VOL_NAME, VOL_EVIDENCE, pid=pid)


def _instance_record(pid="p", **overrides):
    record = _record("instance", INSTANCE, INSTANCE_ARN.replace(ACCT, "123456789012"), R,
                     INSTANCE_NAME, INSTANCE_EVIDENCE, pid=pid)
    record.update(overrides)
    return record


def _yes(plan_bytes, pid="p"):
    return build_batch_review_projection(plan_bytes).replace(f",{pid},".encode(), f"YES,{pid},".encode())


def _approve(plan_bytes, pid="p"):
    return validate_batch_draft(plan_bytes, _yes(plan_bytes, pid))


class VolumeEvidenceTests(unittest.TestCase):
    def target(self):
        return caps.canonical_target_identity(
            kind="volume", locator=VOL, resource_arn=VOL_ARN, partition="aws",
            account="123456789012", scope_region=R)

    def test_volume_evidence_formula_unchanged(self):
        result = evidence_module.verified_generated_name(_volume_record(), self.target())
        self.assertEqual(result.generated_name, VOL_NAME)
        self.assertEqual(result.kind, "volume")
        self.assertEqual(result.resource_arn, VOL_ARN)
        self.assertEqual(len(result.evidence_digest), 64)
        for name in ("app-prod-ebs-xvdb-5678901", "app-prod-ebs-xvda-0000000", "plainname"):
            with self.subTest(name=name), self.assertRaises(evidence_module.NameEvidenceNotProven):
                evidence_module.verified_generated_name({**_volume_record(), "proposed_name": name},
                                                        self.target())

    def test_volume_evidence_legacy_unchanged(self):
        plan = _plan([_volume_record()], [_scope([VOL_ARN])])
        row = _approve(plan).approved_rows[0]
        self.assertEqual(row["approved_name"], VOL_NAME)
        self.assertEqual(row["writer_control_scope_id"], "s")
        for evidence in ("manual note", VOL_EVIDENCE.replace("Name=app-prod", "Name=other-prod")):
            bad = _plan([{**_volume_record(), "evidence": evidence}], [_scope([VOL_ARN])])
            with self.subTest(evidence=evidence), self.assertRaises(BatchValidationError):
                _approve(bad)

    def test_14_column_csv_and_batch_approval_v1_unchanged(self):
        from name_tag_batch_approval import _FIELDS, _approved_tuples
        from name_tag_batch_state import CSV_COLUMNS
        self.assertEqual(len(CSV_COLUMNS), 14)
        self.assertEqual(CSV_COLUMNS[0], "approved")
        self.assertEqual(CSV_COLUMNS[-1], "evidence")
        self.assertEqual(_FIELDS, frozenset({
            "schema_version", "purpose", "csv_sha256", "plan_sha256", "approved_rows_sha256",
            "account", "partition", "authorized_role_arn", "owner_principal_id",
            "owner_key_fingerprint", "allowed_role", "issued_at_utc", "expires_at_utc",
            "batch_nonce"}))
        draft = _approve(_plan([_volume_record()], [_scope([VOL_ARN])]))
        row = draft.rows[0]
        self.assertEqual(_approved_tuples(draft), [[
            0, "p", "123456789012", "aws", R, VOL_ARN, "ABSENT", False, None, VOL_NAME,
            "ec2:CreateTags", "s", "YES"]])
        self.assertEqual(row["approved_name"], VOL_NAME)
        self.assertTrue(draft.csv_bytes.startswith(b"\xef\xbb\xbf"))


class EligibilityTests(unittest.TestCase):
    def test_unsigned_unproven_kind_still_reportable(self):
        record = _instance_record(aws_operation=None, status="proposed")
        plan = _plan([record], [_scope([record["resource_arn"]])])
        draft = validate_batch_draft(plan, build_batch_review_projection(plan))
        self.assertEqual(draft.approved_rows, ())
        self.assertEqual(draft.rows[0]["approved"], "")

    def test_cnp_approved_yes_rejects_whole_draft(self):
        instance = _instance_record(pid="q")
        plan = _plan([_volume_record(), instance],
                     [_scope([VOL_ARN, instance["resource_arn"]])])
        csv = build_batch_review_projection(plan)
        both = csv.replace(b",p,", b"YES,p,").replace(b",q,", b"YES,q,")
        only_volume = csv.replace(b",p,", b"YES,p,")
        self.assertEqual(len(validate_batch_draft(plan, only_volume).approved_rows), 1)
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan, both)  # production Registry: instance is CNP
        with self.assertRaises(BatchValidationError):
            validate_batch_draft(plan, csv.replace(b",q,", b"YES,q,"))
        with self.assertRaises(BatchAuthRejected):
            prepare_batch_approval(plan, both, owner_principal_id="o", owner_key_fingerprint="SHA256:k",
                                   authorized_role_arn="arn:aws:iam::123456789012:role/b",
                                   issued_at_utc="2026-11-19T00:00:00Z",
                                   expires_at_utc="2026-11-20T00:00:00Z", batch_nonce="ab" * 16)

    def test_production_registry_not_promoted_by_fixture(self):
        with proven_instance_fixture():
            self.assertEqual(caps.resolve_kind_capability("instance").status, "IMPLEMENTED_OFFLINE")
        self.assertEqual(caps.resolve_kind_capability("instance").status, "CAPABILITY_NOT_PROVEN")
        self.assertNotIn("instance", evidence_module._VERIFIERS)

    def test_kind_evidence_forged_or_unverifiable_rejects_whole_approval(self):
        scopes = [_scope([VOL_ARN, _instance_record()["resource_arn"]])]
        good_volume = _volume_record()
        forgeries = {
            "nonempty text only": {"evidence": "looks fine"},
            "user supplied name": {"proposed_name": "shop-prod-ec2-0000000"},
            "wrong app": {"evidence": INSTANCE_EVIDENCE.replace("app=shop", "app=evil")},
            "other instance": {"evidence": INSTANCE_EVIDENCE.replace("0123456789abcdef0", "0123456789abcdef1")},
        }
        with proven_instance_fixture():
            ok = _plan([good_volume, _instance_record(pid="q")], scopes)
            csv = build_batch_review_projection(ok).replace(b",p,", b"YES,p,").replace(b",q,", b"YES,q,")
            self.assertEqual(len(validate_batch_draft(ok, csv).approved_rows), 2)
            for label, change in forgeries.items():
                plan = _plan([good_volume, _instance_record(pid="q", **change)], scopes)
                csv = build_batch_review_projection(plan).replace(b",p,", b"YES,p,").replace(b",q,", b"YES,q,")
                with self.subTest(label), self.assertRaises(BatchValidationError):
                    validate_batch_draft(plan, csv)
        # Without the fixture the registry never makes the instance signable.
        with self.assertRaises(BatchValidationError):
            _approve(_plan([_instance_record()], scopes))

    def test_verified_name_must_be_verifier_output_not_user_text(self):
        class Lying:
            def verify(self, record, target):
                return evidence_module.VerifiedGeneratedName(
                    target.kind, target.resource_arn, "other-name", "0" * 64)
        with proven_instance_fixture(), mock.patch.dict(evidence_module._VERIFIERS, {"instance": Lying()}):
            plan = _plan([_instance_record()], [_scope([_instance_record()["resource_arn"]])])
            with self.assertRaises(BatchValidationError):
                _approve(plan)

    def test_global_scope_must_have_unique_signed_declaration(self):
        cf_id = "E1ABCDEF234567"
        arn = f"arn:aws:cloudfront::123456789012:distribution/{cf_id}"
        evidence = f"FIXTURE EC2 {cf_id} tags app=shop env=prod"
        name = f"shop-prod-ec2-{cf_id[-7:]}"
        record = _record("cloudfront", cf_id, arn, "global", name, evidence)
        decision = dataclasses.replace(
            caps.resolve_kind_capability("cloudfront"), status="IMPLEMENTED_OFFLINE",
            reason_code="OFFLINE_CONTRACT_COMPLETE", evidence_refs=("test-only fixture",),
            write_operation="cloudfront:TagResource")
        record["aws_operation"] = "cloudfront:TagResource"
        decisions = MappingProxyType({**caps._DECISIONS, "cloudfront": decision})
        with mock.patch.object(caps, "_DECISIONS", decisions), \
                mock.patch.dict(evidence_module._VERIFIERS, {"cloudfront": FixtureInstanceVerifier()}):
            declared = _plan([record], [_scope([arn], region="global")])
            self.assertEqual(_approve(declared).approved_rows[0]["writer_control_scope_id"], "s")
            with self.assertRaises(BatchValidationError):
                _approve(_plan([record], []))  # no signed declaration
            with self.assertRaises(BatchValidationError):
                _approve(_plan([record], [_scope([arn], region=R)]))  # wrong scope region
            with self.assertRaises(BatchValidationError):
                _approve(_plan([record], [_scope([arn], region="global", sid="a"),
                                          _scope([arn], region="global", sid="b")]))

    def test_nonvolume_locator_must_match_canonical_identity(self):
        arn = _instance_record()["resource_arn"]
        with proven_instance_fixture():
            for locator in ("i-0123456789abcdef1", "", "vol-abcdef12345678901"):
                plan = _plan([_instance_record(locator=locator)], [_scope([arn])])
                with self.subTest(locator=locator), self.assertRaises(BatchValidationError):
                    _approve(plan)
            self.assertEqual(len(_approve(_plan([_instance_record()], [_scope([arn])])).approved_rows), 1)

    def test_signed_nonvolume_draft_tamper_rejected(self):
        arn = _instance_record()["resource_arn"]
        other_arn = arn.replace("abcdef0", "abcdef1")
        tampers = {
            "wrong operation": {"aws_operation": "ec2:DeleteTags"},
            "null operation": {"aws_operation": None},
            "foreign account arn": {"resource_arn": arn.replace("123456789012", "999999999999")},
            "arn region": {"resource_arn": arn.replace(R, "us-east-1")},
            "row region": {"region": "us-east-1"},
            "other arn": {"resource_arn": other_arn},
            "name": {"proposed_name": INSTANCE_NAME + "x"},
        }
        with proven_instance_fixture():
            for label, change in tampers.items():
                plan = _plan([_instance_record(**change)], [_scope([arn, other_arn])])
                with self.subTest(label), self.assertRaises(BatchValidationError):
                    _approve(plan)


class SignedNonVolumeTests(PlanFixture):
    NOW = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "owner-key"
        self.allowed = self.root / "allowed_signers"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True)
        public = self.key.with_suffix(".pub").read_text().split()
        self.allowed.write_text(f'owner namespaces="{BATCH_NAMESPACE}" {public[0]} {public[1]}\n')
        self.allowed.chmod(0o600)
        self.fingerprint = subprocess.check_output(
            ["ssh-keygen", "-lf", str(self.key.with_suffix(".pub")), "-E", "sha256"], text=True).split()[1]
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed, pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={"owner": {self.fingerprint: EnrolledOwner(self.fingerprint, "batch-approver")}},
            expected_uid=os.getuid())
        self.kw = {"owner_principal_id": "owner", "owner_key_fingerprint": self.fingerprint,
                   "authorized_role_arn": f"arn:aws:iam::{ACCT}:role/batch",
                   "issued_at_utc": "2026-11-19T00:00:00Z", "expires_at_utc": "2026-11-20T00:00:00Z",
                   "batch_nonce": "ab" * 16}

    def sign(self, plan, csv):
        prepared = prepare_batch_approval(plan, csv, **self.kw)
        message = self.root / "payload"
        message.write_bytes(prepared.canonical_payload_bytes)
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", BATCH_NAMESPACE, str(message)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return json.dumps({"payload": prepared.payload, "batch_id": prepared.batch_id,
                           "signature_ref": base64.b64encode(message.with_suffix(".sig").read_bytes()).decode()},
                          separators=(",", ":")).encode()

    def build_instance_plan(self):
        info = {**info_for("instance", INSTANCE_ARN), "evidence": INSTANCE_EVIDENCE,
                "proposed_name": INSTANCE_NAME}
        from test_name_tag_batch_identity_projection import cur_row
        self.run_plan([cur_row(INSTANCE)], {INSTANCE: info}, self.scope(R, [INSTANCE_ARN]), kinds="instance")
        return self.out.read_bytes()

    def test_nonvolume_presign_to_verified_row_authority(self):
        with proven_instance_fixture():
            plan = self.build_instance_plan()
            record = json.loads(plan)["records"][0]
            self.assertEqual(record["aws_operation"], "ec2:CreateTags")  # fixture-proven only
            csv = build_batch_review_projection(plan).replace(b",%s," % record["proposal_id"].encode(),
                                                              b"YES,%s," % record["proposal_id"].encode())
            envelope = self.sign(plan, csv)
            verified = verify_batch_approval(plan, csv, envelope, trust=self.trust, now_utc=self.NOW)
            self.assertEqual(verified.approved_row_indexes, (0,))
            authority = derive_batch_row_authority(verified, 0, trust=self.trust, now_utc=self.NOW)
            self.assertEqual(authority.row["approved_name"], INSTANCE_NAME)
            self.assertEqual(authority.row["resource_arn"], INSTANCE_ARN)
            self.assertEqual(authority.row["writer_control_scope_id"], "scope-1")
            self.assertEqual(authority.row["kind"], "instance")
            # The Kind IAM policy / Adapter trace is closed by Tasks 4/5/9, not faked here.
        # Outside the fixture the production Registry (CNP) rejects the same signed bytes.
        with self.assertRaises(BatchAuthRejected):
            verify_batch_approval(plan, csv, envelope, trust=self.trust, now_utc=self.NOW)

    def test_signed_nonvolume_arn_scope_operation_tamper_rejected(self):
        with proven_instance_fixture():
            plan = self.build_instance_plan()
            pid = json.loads(plan)["records"][0]["proposal_id"].encode()
            csv = build_batch_review_projection(plan).replace(b",%s," % pid, b"YES,%s," % pid)
            envelope = self.sign(plan, csv)
            verify_batch_approval(plan, csv, envelope, trust=self.trust, now_utc=self.NOW)
            other = INSTANCE_ARN.replace("abcdef0", "abcdef1")
            mutations = {
                "arn": plan.replace(INSTANCE_ARN.encode(), other.encode()),
                "region": plan.replace(f'"region": "{R}"'.encode(), b'"region": "us-east-1"'),
                "operation": plan.replace(b'"ec2:CreateTags"', b'"ec2:DeleteTags"'),
                "name": plan.replace(INSTANCE_NAME.encode(), (INSTANCE_NAME + "x").encode()),
                "scope id": plan.replace(b'"scope-1"', b'"scope-2"'),
            }
            for label, mutated in mutations.items():
                self.assertNotEqual(mutated, plan, label)
                with self.subTest(label), self.assertRaises(BatchAuthRejected):
                    verify_batch_approval(mutated, csv, envelope, trust=self.trust, now_utc=self.NOW)
            for label, changed_csv in {
                    "csv name": csv.replace(INSTANCE_NAME.encode(), (INSTANCE_NAME + "x").encode()),
                    "csv locator": csv.replace(INSTANCE.encode(), b"i-0123456789abcdef1")}.items():
                self.assertNotEqual(changed_csv, csv, label)
                with self.subTest(label), self.assertRaises(BatchAuthRejected):
                    verify_batch_approval(plan, changed_csv, envelope, trust=self.trust, now_utc=self.NOW)

    @unittest.skip("Integrated in Tasks 4/5 and 9: Kind IAM policy and Adapter do not exist at Task 3")
    def test_nonvolume_fake_row_to_kind_iam_and_adapter_after_tasks4_5(self):
        pass


if __name__ == "__main__":
    unittest.main()
