import hashlib
import json
import unittest

from name_tag_approval import ApprovalRejected, NAME_PAYLOAD_FIELDS, NAMESPACES, approval_digest, canonical_payload
from name_tag_review import prepare_name_payload


class NameReviewTests(unittest.TestCase):
    record: dict[str, object] = {}
    plan_bytes: bytes = b""
    kwargs: dict[str, str] = {}

    def setUp(self):
        self.record = {
            "account": "123456789012",
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0",
            "kind": "volume",
            "region": "us-east-1",
            "locator": "vol-0123456789abcdef0",
            "status": "proposed",
            "confidence": "High",
            "name_state": "ABSENT",
            "name_key_present": False,
            "name_raw_value": None,
            "proposed_name": "web-prd-ec2",
            "evidence": "DescribeVolumes: volume vol-0123456789abcdef0",
            "proposal_id": "review-only-id",
        }
        self.kwargs = {
            "approved_name": "web-prd-ec2",
            "edit_reason": "",
            "owner_principal_id": "owner@example.test",
            "owner_key_fingerprint": "SHA256:owner-key",
            "issued_at_utc": "2026-11-16T00:00:00Z",
            "expires_at_utc": "2026-11-17T00:00:00Z",
            "decision_nonce": "nonce-1",
        }
        self.refresh_plan()

    def refresh_plan(self):
        self.record["evidence_digest"] = hashlib.sha256(
            str(self.record["evidence"]).encode()
        ).hexdigest()
        plan_record = {
            key: value for key, value in self.record.items()
            if key not in {"account", "evidence_digest", "plan_sha256"}
        }
        self.plan_bytes = json.dumps({
            "schema_version": 2,
            "account": self.record["account"],
            "records": [plan_record],
        }, separators=(",", ":")).encode()
        self.record["plan_sha256"] = hashlib.sha256(self.plan_bytes).hexdigest()

    def payload(self, **overrides: str) -> dict[str, object]:
        self.refresh_plan()
        return prepare_name_payload(self.plan_bytes, self.record, **(self.kwargs | overrides))

    def test_prepare_name_payload_edits_require_reason_and_new_signature(self):
        previous = self.payload()
        with self.assertRaises(ApprovalRejected):
            self.payload(approved_name="changed-name")
        edited = self.payload(approved_name="changed-name", edit_reason="Owner reviewed naming correction")
        self.assertEqual(edited["approved_name"], "changed-name")
        self.assertEqual(edited["decision"], "APPROVED")
        self.assertEqual(edited["owner_decision_reference"], "")
        self.assertNotEqual(approval_digest(canonical_payload(previous, kind="name")),
                            approval_digest(canonical_payload(edited, kind="name")))

    def test_absent_empty_high_medium_allowed(self):
        for state in ("ABSENT", "EMPTY"):
            for confidence in ("High", "Medium"):
                with self.subTest(state=state, confidence=confidence):
                    self.record["name_state"] = state
                    self.record["name_key_present"] = state == "EMPTY"
                    self.record["name_raw_value"] = "" if state == "EMPTY" else None
                    self.record["confidence"] = confidence
                    payload = self.payload()
                    self.assertEqual(payload["name_state_at_plan"], state)

    def test_absent_state_requires_explicit_missing_name(self):
        for key_present, raw_value in ((None, None), (False, ""), (True, None)):
            with self.subTest(key_present=key_present, raw_value=raw_value):
                self.record["name_state"] = "ABSENT"
                self.record["name_key_present"] = key_present
                self.record["name_raw_value"] = raw_value
                with self.assertRaises(ApprovalRejected):
                    self.payload()

    def test_nonempty_unknown_rejected(self):
        for state in ("NONEMPTY", "UNKNOWN"):
            with self.subTest(state=state):
                self.record["name_state"] = state
                with self.assertRaises(ApprovalRejected):
                    self.payload()

    def test_cloudfront_global_arn_uses_us_east_1_plan_region(self):
        arn = "arn:aws:cloudfront::123456789012:distribution/EDFDVBD6EXAMPLE"
        self.record.update(kind="cloudfront", resource_arn=arn, locator=arn, region="us-east-1")
        payload = self.payload()
        self.assertEqual(payload["resource_arn"], arn)
        self.assertEqual(payload["region"], "us-east-1")

    def test_api_gateway_arn_without_account_field_binds_components(self):
        arn = "arn:aws:apigateway:us-east-1::/restapis/api123/stages/prod"
        self.record.update(
            kind="apigw_stage",
            resource_arn=arn,
            locator=f"api123|prod|{arn}",
        )
        self.assertEqual(self.payload()["resource_arn"], arn)

    def test_rds_cluster_resource_id_locator_matches_cluster_arn_via_evidence(self):
        resource_id = "cluster-cqhvo5ft5f3wzyaymbnmh4lnu"
        cluster_identifier = "scs2-prd-db-cluster"
        arn = f"arn:aws:rds:us-east-1:123456789012:cluster:{cluster_identifier}"
        self.record.update(
            kind="rds_cluster",
            resource_arn=arn,
            locator=resource_id,
            evidence=(
                f"CUR cluster {resource_id} -> DescribeDBClusters {cluster_identifier} "
                f"/ DbClusterResourceId=CLUSTER-CQHVO5FT5F3WZYAYMBNMH4LNU / ARN={arn}"
            ),
        )
        payload = self.payload()
        self.assertEqual(payload["kind"], "rds_cluster")
        self.assertEqual(payload["locator"], resource_id)
        self.assertEqual(payload["resource_arn"], arn)
        self.record["locator"] = "cluster-aaaaaaaaaaaaaaaaaaaaaaaaaa"
        with self.assertRaises(ApprovalRejected):
            self.payload()

    def test_rds_cluster_evidence_requires_exact_arn_value(self):
        resource_id = "cluster-cqhvo5ft5f3wzyaymbnmh4lnu"
        arn = "arn:aws:rds:us-east-1:123456789012:cluster:scs2-prd-db-cluster"
        self.record.update(
            kind="rds_cluster",
            resource_arn=arn,
            locator=resource_id,
            evidence=(
                f"DbClusterResourceId={resource_id} "
                f"ARN={arn}extra"
            ),
        )
        with self.assertRaises(ApprovalRejected):
            self.payload()

    def test_non_s3_arn_kind_and_locator_must_match(self):
        self.record["resource_arn"] = "arn:aws:ec2:us-east-1:123456789012:volume/vol-fffffffffffffffff"
        with self.assertRaises(ApprovalRejected):
            self.payload()
        self.record.update(kind="rds_instance", resource_arn="arn:aws:rds:us-east-1:123456789012:db:db-0123456789")
        with self.assertRaises(ApprovalRejected):
            self.payload()
        self.record.update(
            kind="volume",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:snapshot/snap-0123456789abcdef0",
            locator="snap-0123456789abcdef0",
        )
        with self.assertRaises(ApprovalRejected):
            self.payload()

    def test_s3_candidate_can_be_reviewed_without_write_permission(self):
        self.record.update(
            kind="s3_bucket",
            resource_arn="arn:aws:s3:::example-bucket",
            locator="example-bucket",
            region="us-east-1",
        )
        payload = self.payload()
        self.assertEqual(payload["kind"], "s3_bucket")
        self.assertEqual(set(payload), NAME_PAYLOAD_FIELDS)
        self.assertEqual(payload["approval_namespace"], NAMESPACES["name"])

    def test_s3_arn_partition_resource_and_locator_are_bound(self):
        cases = (
            ("arn:evil:s3:::example-bucket", "example-bucket"),
            ("arn:aws:s3:::example-bucket/object", "example-bucket"),
            ("arn:aws:s3:::another-bucket", "example-bucket"),
        )
        for arn, locator in cases:
            with self.subTest(arn=arn):
                self.record.update(kind="s3_bucket", resource_arn=arn, locator=locator)
                with self.assertRaises(ApprovalRejected):
                    self.payload()

    def test_s3_region_may_be_empty_or_match_plan_region(self):
        self.record.update(kind="s3_bucket", resource_arn="arn:aws:s3:::example-bucket", locator="example-bucket")
        self.assertEqual(self.payload()["kind"], "s3_bucket")
        self.record["resource_arn"] = "arn:aws:s3:us-east-1::example-bucket"
        self.assertEqual(self.payload()["kind"], "s3_bucket")
        self.record["resource_arn"] = "arn:aws:s3:us-west-2::example-bucket"
        with self.assertRaises(ApprovalRejected):
            self.payload()

    def test_unknown_kind_is_rejected_explicitly(self):
        self.record["kind"] = "unlisted_kind"
        with self.assertRaises(ApprovalRejected) as caught:
            self.payload()
        self.assertEqual(caught.exception.code, "UNSUPPORTED_KIND_FOR_REVIEW")

    def test_edited_name_invalidates_old_signature(self):
        original = self.payload()
        edited = self.payload(approved_name="web-prd-api", edit_reason="Corrected service description")
        self.assertNotEqual(approval_digest(canonical_payload(original, kind="name")),
                            approval_digest(canonical_payload(edited, kind="name")))

    def test_precomputed_plan_and_evidence_digests_are_accepted(self):
        self.refresh_plan()
        self.assertEqual(self.record["plan_sha256"], hashlib.sha256(self.plan_bytes).hexdigest())
        self.assertEqual(
            self.record["evidence_digest"],
            hashlib.sha256(str(self.record["evidence"]).encode()).hexdigest(),
        )
        self.assertEqual(self.payload()["evidence_digest"], self.record["evidence_digest"])

    def test_whitespace_only_approved_name_rejected(self):
        with self.assertRaises(ApprovalRejected):
            self.payload(approved_name="   ")

    def test_foreign_account_or_stale_evidence_rejected(self):
        self.record["account"] = "999999999999"
        with self.assertRaises(ApprovalRejected):
            self.payload()
        self.record["account"] = "123456789012"
        self.record["evidence_digest"] = "0" * 64
        with self.assertRaises(ApprovalRejected):
            prepare_name_payload(self.plan_bytes, self.record, **self.kwargs)


if __name__ == "__main__":
    unittest.main()
