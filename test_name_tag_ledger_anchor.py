from __future__ import annotations

import importlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from name_tag_ledger import LedgerError


class LedgerAnchorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.anchor_directory = self.root / "anchors"
        self.anchor_directory.mkdir(mode=0o700)
        self.ledger_path = Path("/var/lib/name-ledger.db")
        self.host_binding = "host-a:/var/lib/name-ledger.db"
        self.instance_id = "0123456789abcdef0123456789abcdef"

    def _anchor_module(self) -> ModuleType:
        spec = importlib.util.find_spec("name_tag_ledger_anchor")
        self.assertIsNotNone(spec, "ledger anchor module is not implemented")
        return importlib.import_module("name_tag_ledger_anchor")

    def _document(self) -> dict[str, int | str]:
        return {
            "schema_version": 1,
            "ledger_path": str(self.ledger_path.resolve(strict=False)),
            "host_binding": self.host_binding,
            "ledger_instance_id": self.instance_id,
        }

    def _write_anchor(self, raw: bytes) -> Path:
        module = self._anchor_module()
        with patch.object(module, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory):
            anchor_path = module.ledger_anchor_path(self.ledger_path, self.host_binding)
        anchor_path.write_bytes(raw)
        anchor_path.chmod(0o644)
        return anchor_path

    def _read_anchor(self) -> str:
        module = self._anchor_module()
        with (
            patch.object(module, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory),
            patch.object(module, "validate_anchor_directory"),
            patch.object(module, "_validate_anchor_file"),
        ):
            return module.read_ledger_anchor(self.ledger_path, self.host_binding)

    def test_anchor_path_hashes_host_binding(self) -> None:
        module = self._anchor_module()
        with patch.object(module, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory):
            result = module.ledger_anchor_path(self.ledger_path, self.host_binding)
        self.assertEqual(
            result,
            self.anchor_directory
            / "d3cd90936df336a471058e88b96a5fe4309d2ba6f1e6b7b33fa59fee4e70ce31.json",
        )

    def test_valid_anchor_returns_ledger_instance_id(self) -> None:
        self._write_anchor(json.dumps(self._document()).encode("utf-8"))
        self.assertEqual(self._read_anchor(), self.instance_id)

    def test_duplicate_json_key_is_rejected(self) -> None:
        duplicate = (
            '{"schema_version":1,"schema_version":1,'
            f'"ledger_path":"{self.ledger_path.resolve()}",'
            f'"host_binding":"{self.host_binding}",'
            f'"ledger_instance_id":"{self.instance_id}"'
            '}'
        )
        self._write_anchor(duplicate.encode("utf-8"))
        with self.assertRaises(LedgerError) as context:
            self._read_anchor()
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_unknown_field_is_rejected(self) -> None:
        document = self._document()
        document["unexpected"] = "value"
        self._write_anchor(json.dumps(document).encode("utf-8"))
        with self.assertRaises(LedgerError) as context:
            self._read_anchor()
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_wrong_schema_version_is_rejected(self) -> None:
        document = self._document()
        document["schema_version"] = 2
        self._write_anchor(json.dumps(document).encode("utf-8"))
        with self.assertRaises(LedgerError) as context:
            self._read_anchor()
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_malformed_instance_id_is_rejected(self) -> None:
        document = self._document()
        document["ledger_instance_id"] = "not-a-uuid"
        self._write_anchor(json.dumps(document).encode("utf-8"))
        with self.assertRaises(LedgerError) as context:
            self._read_anchor()
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_path_or_host_binding_mismatch_is_rejected(self) -> None:
        for field, wrong_value in (
            ("ledger_path", str(self.root / "another.db")),
            ("host_binding", "host-b:/var/lib/name-ledger.db"),
        ):
            with self.subTest(field=field):
                document = self._document()
                document[field] = wrong_value
                self._write_anchor(json.dumps(document).encode("utf-8"))
                with self.assertRaises(LedgerError) as context:
                    self._read_anchor()
                self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_symlink_anchor_file_is_rejected(self) -> None:
        module = self._anchor_module()
        with patch.object(module, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory):
            anchor_path = module.ledger_anchor_path(self.ledger_path, self.host_binding)
        target = self.root / "target.json"
        target.write_text(json.dumps(self._document()), encoding="utf-8")
        anchor_path.symlink_to(target)
        with patch.object(module, "validate_anchor_directory"):
            with self.assertRaises(LedgerError) as context:
                module.read_ledger_anchor(self.ledger_path, self.host_binding)
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_anchor_file_with_unsafe_mode_is_rejected(self) -> None:
        module = self._anchor_module()
        anchor_path = self.root / "unsafe.json"
        anchor_path.write_text("{}", encoding="utf-8")
        anchor_path.chmod(0o664)
        with (
            patch.object(module, "_ANCHOR_OWNER_UID", os.geteuid()),
            self.assertRaises(LedgerError) as context,
        ):
            module._validate_anchor_file(anchor_path)
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_anchor_directory_symlink_is_rejected(self) -> None:
        module = self._anchor_module()
        target = self.root / "target-dir"
        target.mkdir()
        link = self.root / "anchor-link"
        link.symlink_to(target, target_is_directory=True)
        with patch.object(module, "LEDGER_ANCHOR_DIRECTORY", link):
            with self.assertRaises(LedgerError) as context:
                module.validate_anchor_directory()
        self.assertEqual(context.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
