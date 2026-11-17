from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import name_tag_controlled
import name_tag_ledger_anchor as anchor
import name_tag_ledger_provision as provision
from name_tag_ledger_errors import LedgerError


class LedgerProvisionCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ledger_directory = self.root / "runtime"
        self.ledger_directory.mkdir(mode=0o700)
        self.anchor_directory = self.root / "anchors"
        self.anchor_directory.mkdir(mode=0o700)

    def _patch_test_anchor(self) -> None:
        for target, name, value in (
            (anchor, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory),
            (anchor, "_ANCHOR_OWNER_UID", os.geteuid()),
            (anchor, "require_root", lambda: None),
            (provision, "_require_root", lambda: None),
        ):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_parser_accepts_path_and_runtime_uid(self) -> None:
        path = self.ledger_directory / "ledger.db"
        args = name_tag_controlled.parse_cli(
            [
                "initialize-ledger",
                "--path",
                str(path),
                "--runtime-uid",
                str(os.geteuid()),
            ]
        )
        self.assertEqual(args.command, "initialize-ledger")
        self.assertEqual(args.path, path)
        self.assertEqual(args.runtime_uid, os.geteuid())

    def test_cli_provisions_a_ledger_without_loading_owner_trust(self) -> None:
        self._patch_test_anchor()
        path = self.ledger_directory / "ledger.db"
        output = io.StringIO()
        with (
            patch.object(
                name_tag_controlled,
                "_load_owner_trust",
                side_effect=AssertionError("provisioning must not load OwnerTrust"),
            ),
            redirect_stdout(output),
        ):
            result = name_tag_controlled.main(
                [
                    "initialize-ledger",
                    "--path",
                    str(path),
                    "--runtime-uid",
                    str(os.geteuid()),
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue().strip(), "LEDGER_INITIALIZED")
        self.assertTrue(path.is_file())

    def test_cli_reports_root_guard_failure(self) -> None:
        path = self.ledger_directory / "ledger.db"
        output = io.StringIO()
        with (
            patch.object(
                provision,
                "_require_root",
                side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN"),
            ),
            redirect_stdout(output),
        ):
            result = name_tag_controlled.main(
                ["initialize-ledger", "--path", str(path), "--runtime-uid", "1000"]
            )
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue().strip(), "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse(path.exists())

    def test_cli_refuses_existing_ledger_without_overwriting_it(self) -> None:
        self._patch_test_anchor()
        path = self.ledger_directory / "existing.db"
        original = b"existing ledger bytes"
        path.write_bytes(original)
        output = io.StringIO()

        with redirect_stdout(output):
            result = name_tag_controlled.main(
                [
                    "initialize-ledger",
                    "--path",
                    str(path),
                    "--runtime-uid",
                    str(os.geteuid()),
                ]
            )

        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue().strip(), "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(path.read_bytes(), original)

    def test_cli_rejects_negative_runtime_uid(self) -> None:
        self._patch_test_anchor()
        path = self.ledger_directory / "invalid-uid.db"
        output = io.StringIO()

        with redirect_stdout(output):
            result = name_tag_controlled.main(
                [
                    "initialize-ledger",
                    "--path",
                    str(path),
                    "--runtime-uid",
                    "-1",
                ]
            )

        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue().strip(), "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertFalse(path.exists())

    def test_cli_refuses_missing_required_arguments(self) -> None:
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            name_tag_controlled.parse_cli(["initialize-ledger", "--path", "ledger.db"])

    def test_cli_refuses_anchor_path_override(self) -> None:
        with (
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            name_tag_controlled.parse_cli(
                [
                    "initialize-ledger",
                    "--path",
                    "ledger.db",
                    "--runtime-uid",
                    "1000",
                    "--anchor-directory",
                    str(self.anchor_directory),
                ]
            )


if __name__ == "__main__":
    unittest.main()
