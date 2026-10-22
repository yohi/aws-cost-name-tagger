"""Offline-only G2 evidence bundle safety regression tests."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

import g2_evidence as g2


ACCOUNT = "456720798575"
BASELINE = "d4b3ec819fb70dab1e15b355143b78a93210904d"


class G2OfflineBundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "bundle"
        g2.init_bundle(self.bundle, ACCOUNT, BASELINE)

    def capture(self, name="iam.json", content=None, evidence="G2-A01"):
        source = self.root / "input.json"
        source.write_text(json.dumps(content or {"Roles": ["role-a"]}))
        g2.ingest(self.bundle, source, evidence, name, "IAM", "iam:GetAccountAuthorizationDetails", "global", 1, True)
        return self.bundle / "raw_secure" / name

    def test_init_is_non_atomic_unverified_and_private(self):
        m = g2.read_json(self.bundle / "02_ACQUISITION_MANIFEST.json")
        self.assertFalse(m["snapshot_atomic"])
        self.assertEqual(m["snapshot_consistency_status"], "NOT_ATTEMPTED")
        self.assertEqual(g2.verify_bundle(self.bundle)["g2_gate"], "NOT_VERIFIED")
        if os.name == "posix":
            self.assertEqual(self.bundle.stat().st_mode & 0o077, 0)
            self.assertEqual((self.bundle / "raw_secure").stat().st_mode & 0o077, 0)

    def test_no_overwrite_init(self):
        with self.assertRaises(g2.EvidenceError):
            g2.init_bundle(self.bundle, ACCOUNT, BASELINE)

    def test_bad_account_or_baseline_fails(self):
        with self.assertRaises(g2.EvidenceError):
            g2.init_bundle(self.root / "bad", "abc", BASELINE)
        with self.assertRaises(g2.EvidenceError):
            g2.init_bundle(self.root / "bad2", ACCOUNT, "not-sha")

    def test_capture_records_bytes_digest_and_partial(self):
        source = self.capture()
        item = g2.read_json(self.bundle / "02_ACQUISITION_MANIFEST.json")["files"][0]
        self.assertEqual(item["raw_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(item["status"], "PARTIAL")
        self.assertEqual(item["provenance"], "OFFLINE_USER_SUPPLIED_UNVERIFIED")
        self.assertTrue(item["pagination_complete"])
        self.assertEqual(g2.verify_bundle(self.bundle)["captured_files"], 1)

    def test_multiple_files_share_evidence_id(self):
        self.capture()
        self.capture(name="iam_other.json")
        self.assertEqual(g2.verify_bundle(self.bundle)["captured_files"], 2)

    def test_modified_bytes_rejected(self):
        file = self.capture()
        file.write_text('{"tampered": true}')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(self.bundle)

    def test_modified_sha256sums_rejected(self):
        self.capture()
        (self.bundle / "03_SHA256SUMS.txt").write_text("invalid\n")
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(self.bundle)

    def test_untracked_raw_rejected(self):
        (self.bundle / "raw_secure" / "rogue.json").write_text('{}')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(self.bundle)

    def test_manifest_gate_escalation_rejected(self):
        mf = self.bundle / "02_ACQUISITION_MANIFEST.json"
        data = g2.read_json(mf)
        data["snapshot_consistency_status"] = "CONSISTENT_WITHIN_CHECKED_FIELDS"
        mf.write_bytes(g2.json_bytes(data))
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(self.bundle)

    def test_credential_field_rejected_before_copy(self):
        source = self.root / "secrets.json"
        source.write_text('{"nested":{"SecretAccessKey":"do-not-import"}}')
        with self.assertRaises(g2.EvidenceError):
            g2.ingest(self.bundle, source, "G2-A01", "secret.json", "IAM", "iam:ListRoles", "global", 1, True)
        self.assertFalse((self.bundle / "raw_secure" / "secret.json").exists())

    def test_write_api_name_rejected(self):
        source = self.root / "data.json"
        source.write_text('{}')
        with self.assertRaises(g2.EvidenceError):
            g2.ingest(self.bundle, source, "G2-A01", "write.json", "IAM", "ec2:CreateTags", "global", 1, True)

    def test_bad_filename_and_symlink_rejected(self):
        src = self.root / "src.json"
        src.write_text('{}')
        with self.assertRaises(g2.EvidenceError):
            g2.ingest(self.bundle, src, "G2-A01", "../traverse.json", "IAM", "iam:ListRoles", "global", 1, True)
        alias = self.root / "alias.json"
        alias.symlink_to(src)
        with self.assertRaises(g2.EvidenceError):
            g2.ingest(self.bundle, alias, "G2-A01", "safe.json", "IAM", "iam:ListRoles", "global", 1, True)

    def approval(self, values):
        shared = self.bundle / "redacted_shared"
        entries = []
        for name, data in values.items():
            (shared / name).write_bytes(data)
            entries.append({"path": "redacted_shared/" + name, "sha256": g2.digest(data)})
        approval = self.root / "approved.json"
        approval.write_text(json.dumps({"reviewed_by": "test-human", "approved_at_utc": "2026-10-22T10:00:00Z", "files": entries}))
        return approval

    def test_export_only_explicitly_approved_shared_files(self):
        self.capture()
        approval = self.approval({"sanitized.json": b'{"count":1}'})
        dest = self.root / "shared.zip"
        result = g2.export_shared(self.bundle, dest, approval, True)
        self.assertFalse(result["redaction_independently_verified"])
        with zipfile.ZipFile(dest) as z:
            self.assertEqual(z.namelist(), ["redacted_shared/sanitized.json"])
        self.assertFalse(g2.verify_shared(dest)["raw_secure_included"])

    def test_export_requires_review_acknowledgement(self):
        approval = self.approval({"sanitized.json": b'{}'})
        with self.assertRaises(g2.EvidenceError):
            g2.export_shared(self.bundle, self.root / "shared.zip", approval, False)

    def test_unapproved_sanitized_file_is_not_exported(self):
        approval = self.approval({"approved.json": b'{"count":2}'})
        (self.bundle / "redacted_shared" / "not_approved.json").write_text('{"other":true}')
        dest = self.root / "shared.zip"
        g2.export_shared(self.bundle, dest, approval, True)
        with zipfile.ZipFile(dest) as z:
            self.assertEqual(z.namelist(), ["redacted_shared/approved.json"])

    def test_approval_digest_mismatch_rejected(self):
        approval = self.approval({"sanitized.json": b'{}'})
        (self.bundle / "redacted_shared" / "sanitized.json").write_text('{"changed":true}')
        with self.assertRaises(g2.EvidenceError):
            g2.export_shared(self.bundle, self.root / "shared.zip", approval, True)

    def test_shared_symlink_rejected(self):
        outside = self.root / "sensitive.json"
        outside.write_text('{"private":true}')
        alias = self.bundle / "redacted_shared" / "linked.json"
        alias.symlink_to(outside)
        approval = self.root / "approved.json"
        approval.write_text(json.dumps({"reviewed_by": "test", "approved_at_utc": "2026-10-22T10:00:00Z", "files": [{"path":"redacted_shared/linked.json", "sha256":g2.digest(outside.read_bytes())}]}))
        with self.assertRaises(g2.EvidenceError):
            g2.export_shared(self.bundle, self.root / "shared.zip", approval, True)

    def test_archive_with_raw_secure_fails(self):
        output = self.root / "unsafe.zip"
        with zipfile.ZipFile(output, "w") as z:
            z.writestr("raw_secure/sensitive.json", '{"secret": "oops"}')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)

    def test_archive_traversal_and_duplicates_fail(self):
        output = self.root / "bad.zip"
        with zipfile.ZipFile(output, "w") as z:
            z.writestr("redacted_shared/../raw_secure/secrets.json", '{}')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)
        with zipfile.ZipFile(output, "w") as z:
            z.writestr("redacted_shared/a.json", '{}')
            z.writestr("redacted_shared/a.json", '{"x":1}')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)

    def test_archive_symlink_entry_rejected(self):
        output = self.root / "unsafe.zip"
        info = zipfile.ZipInfo("redacted_shared/linked.json")
        info.create_system = 3
        info.external_attr = ((0o120777) << 16)
        with zipfile.ZipFile(output, "w") as z:
            z.writestr(info, 'raw_secure/leak.json')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)

    def test_raw_dir_world_readable_rejected(self):
        if os.name == "posix":
            (self.bundle / "raw_secure").chmod(0o755)
            with self.assertRaises(g2.EvidenceError):
                g2.verify_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()
