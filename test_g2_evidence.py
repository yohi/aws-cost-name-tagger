"""Offline-only G2 evidence bundle safety regression tests."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
import stat
from unittest import mock

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

    def test_git_worktree_destination_rejected(self):
        repo = self.root / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        with self.assertRaises(g2.EvidenceError):
            g2.init_bundle(repo / "private", ACCOUNT, BASELINE)

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
        approval.chmod(0o600)
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
        approval.chmod(0o600)
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

    def test_archive_alias_paths_fail_individually_and_together(self):
        output = self.root / "aliases.zip"
        with zipfile.ZipFile(output, "w") as z:
            z.writestr("redacted_shared/./a.json", b"{}")
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)
        with zipfile.ZipFile(output, "w") as z:
            z.writestr("redacted_shared/a.json", b"{}")
            z.writestr("redacted_shared/./a.json", b'{"x":1}')
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)

    def test_archive_comment_rejected(self):
        output = self.root / "commented.zip"
        with zipfile.ZipFile(output, "w") as z:
            z.writestr("redacted_shared/a.json", b"{}")
            z.comment = b"private metadata"
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(output)

    def test_archive_entry_comment_extra_and_nonfile_rejected(self):
        for field in ("comment", "extra", "directory"):
            with self.subTest(field=field):
                output = self.root / "badmeta.zip"
                info = zipfile.ZipInfo("redacted_shared/a.json")
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                if field == "comment":
                    info.comment = b"not approved"
                elif field == "extra":
                    info.extra = b"\xfe\xca\x00\x00"
                else:
                    info.external_attr = (stat.S_IFDIR | 0o700) << 16
                with zipfile.ZipFile(output, "w") as z:
                    z.writestr(info, b"{}", compress_type=zipfile.ZIP_DEFLATED)
                with self.assertRaises(g2.EvidenceError):
                    g2.verify_shared(output)

    def test_immutable_manifest_authorization_fields_rejected(self):
        values = {
            "read_only_assertion": "VERIFIED",
            "collector_principal_arn": "arn:aws:iam::456720798575:role/x",
            "snapshot_consistency_evidence": [{"claimed": "verified"}],
            "snapshot_started_at_utc": "2026-10-22T10:00:00+00:00",
            "snapshot_completed_at_utc": "2026-10-22T10:30:00+00:00",
            "snapshot_atomic": True,
            "capture_mode": "AWS_COLLECTED",
            "unexpected_field": "should fail",
        }
        path = self.bundle / "02_ACQUISITION_MANIFEST.json"
        baseline = g2.read_json(path)
        for field, value in values.items():
            with self.subTest(field=field):
                modified = {**baseline, field: value}
                path.write_bytes(g2.json_bytes(modified))
                with self.assertRaises(g2.EvidenceError):
                    g2.verify_bundle(self.bundle)
        path.write_bytes(g2.json_bytes(baseline))
        self.assertEqual(g2.verify_bundle(self.bundle)["g2_gate"], "NOT_VERIFIED")

    def test_scope_capture_mode_and_extra_field_rejected(self):
        path = self.bundle / "01_SCOPE.json"
        original = g2.read_json(path)
        for modified in ({**original, "capture_mode": "AWS_COLLECTED"},
                         {**original, "unapproved": True}):
            path.write_bytes(g2.json_bytes(modified))
            with self.assertRaises(g2.EvidenceError):
                g2.verify_bundle(self.bundle)
        path.write_bytes(g2.json_bytes(original))

    def test_manifest_record_escalation_rejected(self):
        self.capture()
        path = self.bundle / "02_ACQUISITION_MANIFEST.json"
        original = g2.read_json(path)
        for field, value in (("status", "COMPLETE"),
                             ("provenance", "AWS_VERIFIED"),
                             ("limitations", []),
                             ("extra", True)):
            with self.subTest(field=field):
                modified = json.loads(json.dumps(original))
                modified["files"][0][field] = value
                path.write_bytes(g2.json_bytes(modified))
                with self.assertRaises(g2.EvidenceError):
                    g2.verify_bundle(self.bundle)
        path.write_bytes(g2.json_bytes(original))

    def test_bundle_moved_into_git_is_blocked_for_all_operations(self):
        repo = self.root / "repo"
        repo.mkdir()
        (repo / ".git").write_text("gitdir: /elsewhere\n")
        moved = repo / "bundle"
        self.bundle.rename(moved)
        self.bundle = moved
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(moved)
        src = self.root / "input.json"
        src.write_text("{}")
        with self.assertRaises(g2.EvidenceError):
            g2.ingest(moved, src, "G2-A01", "x.json", "IAM",
                      "iam:ListRoles", "global", 1, True)
        with self.assertRaises(g2.EvidenceError):
            g2.export_shared(moved, self.root / "output.zip",
                             self.root / "nonexistent.json", True)

    def test_private_metadata_permissions_rechecked(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions required")
        for name in ("00_READ_FIRST.md", "01_SCOPE.json",
                     "02_ACQUISITION_MANIFEST.json", "03_SHA256SUMS.txt"):
            with self.subTest(name=name):
                path = self.bundle / name
                path.chmod(0o644)
                with self.assertRaises(g2.EvidenceError):
                    g2.verify_bundle(self.bundle)
                path.chmod(0o600)

    def test_interruption_after_manifest_is_fail_closed_and_recoverable(self):
        original_replace = g2.replace_private
        def fail_sums(path, data):
            if path.name == "03_SHA256SUMS.txt":
                raise OSError("simulated crash")
            return original_replace(path, data)
        with mock.patch.object(g2, "replace_private", side_effect=fail_sums):
            with self.assertRaises(OSError):
                self.capture()
        self.assertTrue((self.bundle / g2.JOURNAL_NAME).exists())
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(self.bundle)
        self.assertEqual(g2.recover_bundle(self.bundle)["status"], "RECOVERED_ROLL_FORWARD")
        self.assertEqual(g2.verify_bundle(self.bundle)["captured_files"], 1)
        self.assertFalse((self.bundle / g2.JOURNAL_NAME).exists())

    def test_interruption_before_raw_rolls_back_only_if_prior_state_matches(self):
        original_write = g2.write_private
        def fail_raw(path, data):
            if path.name == "iam.json":
                raise OSError("simulated failure before copying RAW")
            return original_write(path, data)
        with mock.patch.object(g2, "write_private", side_effect=fail_raw):
            with self.assertRaises(OSError):
                self.capture()
        with self.assertRaises(g2.EvidenceError):
            g2.verify_bundle(self.bundle)
        self.assertEqual(g2.recover_bundle(self.bundle)["status"], "ROLLED_BACK_NO_RAW")
        self.assertEqual(g2.verify_bundle(self.bundle)["captured_files"], 0)

    def test_interrupted_raw_corruption_blocks_recovery(self):
        original_replace = g2.replace_private
        def fail_sums(path, data):
            if path.name == "03_SHA256SUMS.txt":
                raise OSError("simulated failure")
            return original_replace(path, data)
        with mock.patch.object(g2, "replace_private", side_effect=fail_sums):
            with self.assertRaises(OSError):
                self.capture()
        (self.bundle / "raw_secure" / "iam.json").write_bytes(b"changed")
        with self.assertRaises(g2.EvidenceError):
            g2.recover_bundle(self.bundle)
        self.assertTrue((self.bundle / g2.JOURNAL_NAME).exists())

    def test_private_files_are_0600_at_creation(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions required")
        for path in self.bundle.iterdir():
            if path.is_file():
                with self.subTest(path=path.name):
                    self.assertEqual(path.stat().st_mode & 0o077, 0)
        raw = self.capture()
        self.assertEqual(raw.stat().st_mode & 0o077, 0)

    def test_concurrent_zip_destination_creation_is_not_overwritten(self):
        approval = self.approval({"sanitized.json": b'{"count":3}'})
        destination = self.root / "new.zip"
        original_link = g2.os.link
        def concurrent_file(src, dst):
            Path(dst).write_bytes(b"another operation")
            return original_link(src, dst)
        with mock.patch.object(g2.os, "link", side_effect=concurrent_file):
            with self.assertRaises(FileExistsError):
                g2.export_shared(self.bundle, destination, approval, True)
        self.assertEqual(destination.read_bytes(), b"another operation")

    def test_shared_zip_with_appended_hidden_bytes_rejected(self):
        approval = self.approval({"sanitized.json": b'{"count":4}'})
        archive = self.root / "shared.zip"
        g2.export_shared(self.bundle, archive, approval, True)
        archive.write_bytes(archive.read_bytes() + b"UNAPPROVED_TRAILING_DATA")
        with self.assertRaises(g2.EvidenceError):
            g2.verify_shared(archive)

    def test_raw_dir_world_readable_rejected(self):
        if os.name == "posix":
            (self.bundle / "raw_secure").chmod(0o755)
            with self.assertRaises(g2.EvidenceError):
                g2.verify_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()
