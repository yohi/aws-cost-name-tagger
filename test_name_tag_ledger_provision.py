from __future__ import annotations

import importlib
import importlib.util
import os
import pwd
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from name_tag_ledger import LedgerError


class LedgerProvisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger_directory = self.root / "runtime"
        self.ledger_directory.mkdir(mode=0o700)
        self.anchor_directory = self.root / "anchors"
        self.anchor_directory.mkdir(mode=0o700)

    def _modules(self) -> tuple[ModuleType, ModuleType, ModuleType]:
        provision_spec = importlib.util.find_spec("name_tag_ledger_provision")
        self.assertIsNotNone(provision_spec, "ledger provision module is not implemented")
        provision = importlib.import_module("name_tag_ledger_provision")
        anchor = importlib.import_module("name_tag_ledger_anchor")
        ledger = importlib.import_module("name_tag_ledger")
        return provision, anchor, ledger

    def _allow_test_provisioning(
        self, provision: ModuleType, anchor: ModuleType
    ) -> None:
        for target, name, value in (
            (provision, "_require_root", lambda: None),
            (anchor, "require_root", lambda: None),
            (anchor, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory),
            (anchor, "_ANCHOR_OWNER_UID", os.geteuid()),
        ):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_initialize_ledger_creates_matching_anchor_and_private_database(
        self,
    ) -> None:
        provision, anchor, ledger = self._modules()
        self._allow_test_provisioning(provision, anchor)
        path = self.ledger_directory / "ledger.db"
        provision.initialize_ledger(path, runtime_uid=os.geteuid())

        self.assertTrue(path.is_file())
        self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        host_binding = ledger.ledger_host_binding(path)
        anchor_path = anchor.ledger_anchor_path(path, host_binding)
        anchor_info = anchor_path.stat()
        self.assertEqual(anchor_info.st_mode & 0o777, 0o640)
        self.assertEqual(anchor_info.st_gid, pwd.getpwuid(os.geteuid()).pw_gid)
        instance_id = anchor.read_ledger_anchor(path, host_binding).ledger_instance_id
        with sqlite3.connect(path) as connection:
            metadata = dict(connection.execute("SELECT key, value FROM ledger_meta"))
        self.assertEqual(metadata["host_binding"], host_binding)
        self.assertEqual(metadata["schema_version"], "1")
        self.assertEqual(metadata["ledger_instance_id"], instance_id)

    def test_initialize_ledger_refuses_existing_database_without_overwrite(
        self,
    ) -> None:
        provision, anchor, _ = self._modules()
        self._allow_test_provisioning(provision, anchor)
        path = self.ledger_directory / "existing.db"
        original = b"existing ledger bytes"
        path.write_bytes(original)

        with self.assertRaises(LedgerError) as context:
            provision.initialize_ledger(path, runtime_uid=os.geteuid())

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(path.read_bytes(), original)

    def test_initialize_ledger_refuses_existing_anchor_without_database(
        self,
    ) -> None:
        provision, anchor, ledger = self._modules()
        self._allow_test_provisioning(provision, anchor)
        path = self.ledger_directory / "missing.db"
        host_binding = ledger.ledger_host_binding(path)
        anchor_path = anchor.ledger_anchor_path(path, host_binding)
        original = b"preserve existing anchor"
        anchor_path.write_bytes(original)

        with self.assertRaises(LedgerError) as context:
            provision.initialize_ledger(path, runtime_uid=os.geteuid())

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse(path.exists())
        self.assertEqual(anchor_path.read_bytes(), original)

    def test_initialize_ledger_rejects_invalid_runtime_uid(self) -> None:
        provision, anchor, _ = self._modules()
        self._allow_test_provisioning(provision, anchor)
        path = self.ledger_directory / "invalid-uid.db"

        with self.assertRaises(LedgerError) as context:
            provision.initialize_ledger(path, runtime_uid=-1)

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse(path.exists())

    def test_initialize_ledger_rejects_group_or_world_writable_parent(
        self,
    ) -> None:
        provision, anchor, _ = self._modules()
        self._allow_test_provisioning(provision, anchor)
        self.ledger_directory.chmod(0o777)
        path = self.ledger_directory / "unsafe-parent.db"

        with self.assertRaises(LedgerError) as context:
            provision.initialize_ledger(path, runtime_uid=os.geteuid())

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse(path.exists())

    def test_initialize_ledger_rejects_symlink_parent(self) -> None:
        provision, anchor, _ = self._modules()
        self._allow_test_provisioning(provision, anchor)
        link = self.root / "runtime-link"
        link.symlink_to(self.ledger_directory, target_is_directory=True)
        path = link / "symlink-parent.db"

        with self.assertRaises(LedgerError) as context:
            provision.initialize_ledger(path, runtime_uid=os.geteuid())

        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse((self.ledger_directory / path.name).exists())

    def test_root_guard_rejects_non_root_effective_uid(self) -> None:
        provision, _, _ = self._modules()
        with patch.object(provision.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(LedgerError) as context:
                provision._require_root()
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
