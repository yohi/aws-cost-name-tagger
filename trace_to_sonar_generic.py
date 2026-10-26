"""Fail-closed conversion of stdlib trace .cover to Sonar generic line coverage.

Local transformation only; does not contact Sonar, GitHub, or AWS.
"""
import sys
import hashlib
import os
from pathlib import Path
import re
import xml.etree.ElementTree as ET

_COUNT = re.compile(r"^\s*(\d+): (.*)$")
_MODULE = "aws_cost_name_tagger_v3.py"


def _status(annotated: str, actual: str, line: int) -> bool | None:
    if annotated.startswith(">>>>>> "):
        covered, text = False, annotated[7:]
    else:
        match = _COUNT.fullmatch(annotated)
        if match:
            if int(match.group(1)) <= 0:
                raise ValueError(f"line {line}: invalid execution count")
            covered, text = True, match.group(2)
        elif annotated.startswith("       "):
            covered, text = None, annotated[7:]
        else:
            raise ValueError(f"line {line}: invalid annotation prefix")
    if text != actual:
        raise ValueError(f"line {line}: source/trace mismatch")
    return covered


def convert(*, source_data: bytes, trace_data: bytes) -> bytes:
    if b"\r" in source_data or b"\r" in trace_data:
        raise ValueError("CRLF is not supported")
    # CPython trace appends LF even when the original source has no final LF.
    if not trace_data:
        raise ValueError("trace/source line count mismatch")
    if not trace_data.endswith(b"\n"):
        raise ValueError("trace missing terminal LF")
    # Strictly preserve physical LF line boundaries (unlike str.splitlines).
    lines = source_data.decode("utf-8", errors="strict").split("\n")
    trace = trace_data.decode("utf-8", errors="strict").split("\n")
    if source_data.endswith(b"\n"):
        lines.pop()
    trace.pop()  # The last trace field must be empty after its required LF.
    if not lines or len(lines) != len(trace):
        raise ValueError("trace/source line count mismatch")
    root = ET.Element("coverage", version="1")
    item = ET.SubElement(root, "file", path=_MODULE)
    eligible = executed = 0
    for line, (actual, raw) in enumerate(zip(lines, trace), 1):
        hit = _status(raw, actual, line)
        if hit is None:
            continue
        eligible += 1
        executed += hit
        ET.SubElement(item, "lineToCover", lineNumber=str(line), covered=str(hit).lower())
    if eligible == 0 or executed == 0:
        raise ValueError("refusing empty or unexecuted coverage")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def _publish_report(xml: bytes, folder: Path) -> None:
    """Publish fully written XML, never replacing an existing report or stage."""
    temporary = folder / "sonar-generic-coverage.xml.tmp"
    output = folder / "sonar-generic-coverage.xml"
    owned = published = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        owned = True
        try:
            remaining = memoryview(xml)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("no forward progress writing coverage XML")
                remaining = remaining[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.link(temporary, output)  # Atomic no-overwrite publication.
        published = True
    finally:
        if owned:
            try:
                temporary.unlink()
            except OSError:
                if published:
                    # A cleanup failure is an error: roll back our new output.
                    try:
                        output.unlink()
                    except OSError as rollback_error:
                        raise RuntimeError("coverage cleanup and rollback both failed") from rollback_error
                raise


def main() -> None:
    if len(sys.argv) != 1:
        raise SystemExit("no external path arguments accepted")
    root = Path(__file__).resolve().parent
    source_path = root / _MODULE
    folder = root / "offline-line-coverage"
    trace_path = folder / "aws_cost_name_tagger_v3.cover"
    if source_path.is_symlink() or folder.is_symlink() or trace_path.is_symlink():
        raise ValueError("symlink input refused")
    xml = convert(source_data=source_path.read_bytes(), trace_data=trace_path.read_bytes())
    _publish_report(xml, folder)
    file = ET.fromstring(xml).find("file")
    lines = file.findall("lineToCover")
    hit = sum(element.attrib["covered"] == "true" for element in lines)
    print(f"SONAR_GENERIC_LINES={hit}/{len(lines)}")
    print(f"SONAR_GENERIC_SHA256={hashlib.sha256(xml).hexdigest()}")


if __name__ == "__main__":
    main()
