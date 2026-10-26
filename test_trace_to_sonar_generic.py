"""Standalone regression tests for strict, offline trace conversion."""
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from trace_to_sonar_generic import convert, _publish_report


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
        return convert(source_data=self.source.read_bytes(), trace_data=self.trace.read_bytes())

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

    def test_reject_empty_trace(self):
        self.files("print(1)\n", "")
        with self.assertRaisesRegex(ValueError, "line count"):
            self.result()


class R1RegressionTests(unittest.TestCase):
    """FND-25-R1-001 output collisions and FND-25-R1-002 trace LF."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.stage = self.folder / "sonar-generic-coverage.xml.tmp"
        self.output = self.folder / "sonar-generic-coverage.xml"
        self.xml = b'<coverage version="1"/>\n'

    def test_existing_stage_is_not_removed(self):
        self.stage.write_bytes(b"prior-stage")
        with self.assertRaises(FileExistsError):
            _publish_report(self.xml, self.folder)
        self.assertEqual(self.stage.read_bytes(), b"prior-stage")
        self.assertFalse(self.output.exists())

    def test_existing_output_is_not_overwritten(self):
        self.output.write_bytes(b"prior-final")
        with self.assertRaises(FileExistsError):
            _publish_report(self.xml, self.folder)
        self.assertEqual(self.output.read_bytes(), b"prior-final")
        self.assertFalse(self.stage.exists())

    def test_final_symlink_target_is_unchanged(self):
        victim = self.folder / "victim"
        victim.write_bytes(b"preserve")
        self.output.symlink_to(victim)
        with self.assertRaises(FileExistsError):
            _publish_report(self.xml, self.folder)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(victim.read_bytes(), b"preserve")

    def test_successful_publish_is_complete_and_removes_owned_stage(self):
        _publish_report(self.xml, self.folder)
        self.assertEqual(self.output.read_bytes(), self.xml)
        self.assertFalse(self.stage.exists())

    def test_open_failure_does_not_remove_foreign_file(self):
        with patch("trace_to_sonar_generic.os.open", side_effect=PermissionError("open failed")):
            with self.assertRaisesRegex(PermissionError, "open failed"):
                _publish_report(self.xml, self.folder)
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.output.exists())

    def test_write_failure_does_not_publish(self):
        with patch("trace_to_sonar_generic.os.write", side_effect=OSError("write failed")):
            with self.assertRaisesRegex(OSError, "write failed"):
                _publish_report(self.xml, self.folder)
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.output.exists())

    def test_partial_write_then_error_does_not_publish(self):
        original_write = os.write
        attempt = 0

        def short_then_fail(fd, data):
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                return original_write(fd, data[:2])
            raise OSError("partial write failed")

        with patch("trace_to_sonar_generic.os.write", side_effect=short_then_fail):
            with self.assertRaisesRegex(OSError, "partial write failed"):
                _publish_report(self.xml, self.folder)
        self.assertFalse(self.stage.exists())
        self.assertFalse(self.output.exists())

    def test_fsync_failure_does_not_publish(self):
        with patch("trace_to_sonar_generic.os.fsync", side_effect=OSError("sync failed")):
            with self.assertRaisesRegex(OSError, "sync failed"):
                _publish_report(self.xml, self.folder)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.stage.exists())

    def test_link_failure_does_not_publish(self):
        with patch("trace_to_sonar_generic.os.link", side_effect=OSError("link failed")):
            with self.assertRaisesRegex(OSError, "link failed"):
                _publish_report(self.xml, self.folder)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.stage.exists())

    def test_cleanup_failure_rolls_back_new_output(self):
        real_unlink = Path.unlink

        def cleanup_failure(path, *args, **kwargs):
            if path == self.stage:
                raise PermissionError("cleanup failed")
            return real_unlink(path, *args, **kwargs)

        with patch("trace_to_sonar_generic.Path.unlink", autospec=True, side_effect=cleanup_failure):
            with self.assertRaisesRegex(PermissionError, "cleanup failed"):
                _publish_report(self.xml, self.folder)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.stage.read_bytes(), self.xml)

    def test_cleanup_fault_preserves_preexisting_output(self):
        self.output.write_bytes(b"old-output")
        with patch("trace_to_sonar_generic.Path.unlink", side_effect=OSError("cleanup failed")):
            with self.assertRaisesRegex(OSError, "cleanup failed"):
                _publish_report(self.xml, self.folder)
        self.assertEqual(self.output.read_bytes(), b"old-output")

    def test_missing_trace_terminal_lf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "terminal LF"):
            convert(source_data=b"print(1)\n", trace_data=b"    1: print(1)")

    def test_missing_trace_terminal_lf_is_rejected_for_unterminated_source(self):
        with self.assertRaisesRegex(ValueError, "terminal LF"):
            convert(source_data=b"print(1)", trace_data=b"    1: print(1)")

    def test_unterminated_source_valid_with_terminated_trace(self):
        data = convert(source_data=b"print(1)", trace_data=b"    1: print(1)\n")
        self.assertIn(b'covered="true"', data)

    def test_normal_terminated_source_and_trace_valid(self):
        data = convert(source_data=b"print(1)\n", trace_data=b"    1: print(1)\n")
        self.assertIn(b'covered="true"', data)

    def test_complete_blank_physical_line_valid(self):
        data = convert(source_data=b"print(1)\n\n", trace_data=b"    1: print(1)\n       \n")
        self.assertIn(b'covered="true"', data)


if __name__ == "__main__":
    unittest.main()
