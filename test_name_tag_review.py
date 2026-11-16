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
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
            "kind": "ec2_instance",
            "region": "us-east-1",
            "locator": "i-0123456789abcdef0",
            "status": "proposed",
            "confidence": "High",
            "name_state": "ABSENT",
            "proposed_name": "web-prd-ec2",
            "evidence": "DescribeInstances: instance i-0123456789abcdef0",
            "proposal_id": "review-only-id",
        }
        self.record["evidence_digest"] = hashlib.sha256(
            "DescribeInstances: instance i-0123456789abcdef0".encode()
        ).hexdigest()
        plan_record = {key: value for key, value in self.record.items() if key != "plan_sha256"}
        self.plan_bytes = json.dumps({
            "schema_version": 2,
            "account": self.record["account"],
            "records": [plan_record],
        }, separators=(",", ":")).encode()
        self.record["plan_sha256"] = hashlib.sha256(self.plan_bytes).hexdigest()
        self.kwargs = {
            "approved_name": "web-prd-ec2",
            "edit_reason": "",
            "owner_principal_id": "owner@example.test",
            "owner_key_fingerprint": "SHA256:owner-key",
            "issued_at_utc": "2026-11-16T00:00:00Z",
            "expires_at_utc": "2026-11-17T00:00:00Z",
            "decision_nonce": "nonce-1",
        }

    def refresh_plan(self):
        self.record["evidence_digest"] = hashlib.sha256(
            "DescribeInstances: instance i-0123456789abcdef0".encode()
        ).hexdigest()
        plan_record = {key: value for key, value in self.record.items() if key != "plan_sha256"}
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

    def test_nonempty_unknown_rejected(self):
        for state in ("NONEMPTY", "UNKNOWN"):
            with self.subTest(state=state):
                self.record["name_state"] = state
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

    def test_edited_name_invalidates_old_signature(self):
        original = self.payload()
        edited = self.payload(approved_name="web-prd-api", edit_reason="Corrected service description")
        self.assertNotEqual(approval_digest(canonical_payload(original, kind="name")),
                            approval_digest(canonical_payload(edited, kind="name")))

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
