"""Fail-closed conversion of stdlib trace .cover to Sonar generic line coverage.

Local transformation only; does not contact Sonar, GitHub, or AWS.
"""
import argparse
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


def convert(*, source: Path, annotated: Path) -> bytes:
    if source.name != _MODULE or annotated.name != "aws_cost_name_tagger_v3.cover":
        raise ValueError("non-allowlisted source or trace")
    source_data, trace_data = source.read_bytes(), annotated.read_bytes()
    if b"\r" in source_data or b"\r" in trace_data:
        raise ValueError("CRLF is not supported")
    lines = source_data.decode("utf-8", errors="strict").splitlines()
    trace = trace_data.decode("utf-8", errors="strict").splitlines()
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    xml = convert(source=args.source, annotated=args.trace)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_name(args.output.name + ".tmp")
    try:
        tmp.write_bytes(xml)
        os.replace(tmp, args.output)
    finally:
        tmp.unlink(missing_ok=True)
    file = ET.fromstring(xml).find("file")
    lines = file.findall("lineToCover")
    hit = sum(element.attrib["covered"] == "true" for element in lines)
    print(f"SONAR_GENERIC_LINES={hit}/{len(lines)}")
    print(f"SONAR_GENERIC_SHA256={hashlib.sha256(xml).hexdigest()}")


if __name__ == "__main__":
    main()
