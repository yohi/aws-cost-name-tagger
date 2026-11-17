from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import name_tag_ledger_anchor as anchor
import name_tag_ledger_provision as provision
from name_tag_ledger import LedgerError, ledger_host_binding, open_ledger


class LedgerOpenAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger_directory = self.root / "runtime"
        self.ledger_directory.mkdir(mode=0o700)
        self.anchor_directory = self.root / "anchors"
        self.anchor_directory.mkdir(mode=0o700)
        for target, name, value in (
            (anchor, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory),
            (anchor, "_ANCHOR_OWNER_UID", os.geteuid()),
            (anchor, "require_root", lambda: None),
            (provision, "_require_root", lambda: None),
        ):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _provision(self, name: str = "ledger.db") -> Path:
        path = self.ledger_directory / name
        provision.initialize_ledger(path, runtime_uid=os.geteuid())
        return path

    def _anchor_path(self, path: Path) -> Path:
        return anchor.ledger_anchor_path(path, ledger_host_binding(path))

    def test_open_reopens_a_provisioned_ledger_with_the_same_instance_id(
        self,
    ) -> None:
        path = self._provision()
        with closing(open_ledger(path, trusted_host=True, trust=None)):
            pass
        with closing(open_ledger(path, trusted_host=True, trust=None)):
            with closing(sqlite3.connect(path)) as connection:
                row = connection.execute(
                    "SELECT value FROM ledger_meta WHERE key = 'ledger_instance_id'"
                ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(
            row[0],
            anchor.read_ledger_anchor(path, ledger_host_binding(path)).ledger_instance_id,
        )

    def test_open_does_not_recreate_a_deleted_provisioned_database(self) -> None:
        path = self._provision()
        path.unlink()

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse(path.exists())

    def test_open_rejects_an_existing_unanchored_empty_file(self) -> None:
        path = self.ledger_directory / "empty.db"
        path.touch(mode=0o600)

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_open_rejects_a_missing_anchor(self) -> None:
        path = self._provision()
        self._anchor_path(path).unlink()

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_open_rejects_a_corrupt_anchor(self) -> None:
        path = self._provision()
        anchor_path = self._anchor_path(path)
        anchor_path.write_bytes(b"not-json")

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_open_rejects_an_anchor_for_a_different_instance(self) -> None:
        path = self._provision()
        anchor_path = self._anchor_path(path)
        document = json.loads(anchor_path.read_text(encoding="utf-8"))
        document["ledger_instance_id"] = "f" * 32
        anchor_path.write_text(json.dumps(document), encoding="utf-8")
        anchor_path.chmod(0o644)

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_open_rejects_missing_instance_metadata(self) -> None:
        path = self._provision()
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "DELETE FROM ledger_meta WHERE key = 'ledger_instance_id'"
            )
            connection.commit()

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_open_rejects_wrong_instance_metadata(self) -> None:
        path = self._provision()
        with closing(sqlite3.connect(path)) as connection:
            connection.execute(
                "UPDATE ledger_meta SET value = ? WHERE key = 'ledger_instance_id'",
                ("f" * 32,),
            )
            connection.commit()

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_open_rejects_a_restored_snapshot_with_a_new_file_identity(self) -> None:
        path = self._provision()
        original_inode = path.stat().st_ino
        backup = self.root / "ledger-backup.db"
        shutil.copy2(path, backup)
        path.unlink()
        backup.replace(path)
        self.assertNotEqual(path.stat().st_ino, original_inode)

        with self.assertRaises(LedgerError) as context:
            open_ledger(path, trusted_host=True, trust=None)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
