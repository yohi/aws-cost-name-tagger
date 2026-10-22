"""Regression tests for the shared G2 offline static guard."""
import unittest
import g2_static_guard as guard


class OfflineStaticGuardTests(unittest.TestCase):
    def test_clean_synthetic_code(self):
        self.assertEqual(guard.check_ast("import json\nfrom pathlib import Path\nx = Path('.')\n"), [])

    def test_http_client_and_network_imports_rejected(self):
        for src in ("import http.client", "from http.client import HTTPSConnection",
                    "import socket", "from urllib import request",
                    "import requests", "import boto3", "import botocore.client"):
            with self.subTest(src=src):
                self.assertTrue(guard.check_ast(src))

    def test_relative_import_without_module_rejected(self):
        self.assertTrue(guard.check_ast("from . import helper"))

    def test_dynamic_import_and_exec_rejected(self):
        for src in ('__import__("socket")', "import importlib",
                    'from importlib import import_module',
                    'eval("1 + 2")', 'exec("print(3)")', 'compile("1", "", "eval")'):
            with self.subTest(src=src):
                self.assertTrue(guard.check_ast(src))

    def test_process_execution_rejected(self):
        for src in ("import subprocess", 'os.system("curl")', "os.popen('echo ok')",
                    'os.execve("/bin/echo", [], {})',
                    "import os as operating_system\noperating_system.system('echo ok')",
                    "import os\nfrom os import system as run_command\nrun_command('echo ok')",
                    "from os import posix_spawn as launch\nlaunch('cmd', [], [])",
                    "import os\nos.posix_spawnp('cmd', [], [])",
                    "import os\nos.startfile('file')"):
            with self.subTest(src=src):
                self.assertTrue(guard.check_ast(src))

    def test_syntax_errors_fail_closed(self):
        self.assertTrue(guard.check_ast("def invalid(:\n"))

    def test_guard_refuses_arbitrary_file_to_scan(self):
        self.assertEqual(guard.main([]), 1)
        self.assertEqual(guard.main(["unknown.py"]), 1)
        self.assertEqual(guard.main(["/tmp/untrusted/g2_evidence.py",
                                     "g2_collector_contract.py"]), 1)
        self.assertEqual(guard.main(["../g2_evidence.py",
                                     "g2_collector_contract.py"]), 1)
        self.assertEqual(guard.main(["g2_evidence.py",
                                     "g2_collector_contract.py"]), 0)


if __name__ == "__main__":
    unittest.main()
