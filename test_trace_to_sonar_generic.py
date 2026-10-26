"""Standalone regression tests for strict, offline trace conversion."""
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from trace_to_sonar_generic import convert


class ConverterTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name) / "aws_cost_name_tagger_v3.py"
        self.trace = Path(tmp.name) / "aws_cost_name_tagger_v3.cover"

    def files(self, src, ann):
        self.source.write_bytes(src.encode())
        self.trace.write_bytes(ann.encode())

    def result(self):
        return convert(source=self.source, annotated=self.trace)

    def test_realistic_annotation(self):
        self.files(
            "def f(x):\n    if x:\n        return 1\n    return 0\n\n",
            "    1: def f(x):\n    2:     if x:\n    1:         return 1\n>>>>>>     return 0\n       \n",
        )
        xml = self.result()
        root = ET.fromstring(xml)
        self.assertEqual(root.attrib, {"version": "1"})
        self.assertEqual(root.find("file").attrib["path"], "aws_cost_name_tagger_v3.py")
        self.assertEqual(
            [(z.attrib["lineNumber"], z.attrib["covered"]) for z in root.find("file")],
            [("1", "true"), ("2", "true"), ("3", "true"), ("4", "false")],
        )
        self.assertEqual(xml, self.result())

    def test_large_hit_count(self):
        self.files("print(1)\n", " 100000: print(1)\n")
        self.assertEqual(ET.fromstring(self.result())[0][0].attrib["covered"], "true")

    def test_reject_wrong_source(self):
        self.files("print(1)\n", "    1: print(2)\n")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.result()

    def test_reject_wrong_uncovered(self):
        self.files("print(1)\n", ">>>>>> print(2)\n")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.result()

    def test_reject_modified_noncode(self):
        self.files("# comment\nprint(1)\n", "       # spoofed\n    1: print(1)\n")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.result()

    def test_reject_short_trace(self):
        self.files("print(1)\nprint(2)\n", "    1: print(1)\n")
        with self.assertRaisesRegex(ValueError, "line count"):
            self.result()

    def test_reject_invalid_count(self):
        self.files("print(1)\n", "    0: print(1)\n")
        with self.assertRaisesRegex(ValueError, "invalid execution count"):
            self.result()

    def test_reject_undocumented_prefix(self):
        self.files("print(1)\n", "WRONG: print(1)\n")
        with self.assertRaisesRegex(ValueError, "prefix"):
            self.result()

    def test_reject_no_executed_lines(self):
        self.files("print(1)\n", ">>>>>> print(1)\n")
        with self.assertRaisesRegex(ValueError, "unexecuted"):
            self.result()

    def test_reject_invalid_utf8(self):
        self.files("print(1)\n", "    1: print(1)\n")
        self.trace.write_bytes(b"\xff\n")
        with self.assertRaises(UnicodeDecodeError):
            self.result()

    def test_reject_crlf(self):
        self.files("print(1)\n", "    1: print(1)\n")
        self.trace.write_bytes(b"    1: print(1)\r\n")
        with self.assertRaisesRegex(ValueError, "CRLF"):
            self.result()

    def test_reject_other_module(self):
        self.files("print(1)\n", "    1: print(1)\n")
        wrong = self.source.with_name("test_aws_cost_name_tagger_v3.py")
        wrong.write_bytes(self.source.read_bytes())
        with self.assertRaisesRegex(ValueError, "non-allowlisted"):
            convert(source=wrong, annotated=self.trace)


if __name__ == "__main__":
    unittest.main()
