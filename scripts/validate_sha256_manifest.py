#!/usr/bin/env python3
"""Validate every file recorded in SHA256_MANIFEST.json."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUIRED_FILES = {"uv.lock", ".github/workflows/ci.yml"}


def validate(root: Path) -> list[str]:
    manifest_path = root / "SHA256_MANIFEST.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"Unable to read SHA-256 manifest: {exc}"]

    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        return ["SHA-256 manifest must contain a files list"]

    errors: list[str] = []
    paths = [entry.get("path") for entry in entries if isinstance(entry, dict)]
    if len(paths) != len(entries):
        errors.append("Malformed manifest entry")
    if len(set(path for path in paths if isinstance(path, str))) != len(paths):
        errors.append("Duplicate manifest path")

    root = root.resolve()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        path_text = entry.get("path")
        if not isinstance(path_text, str) or not path_text:
            errors.append("Malformed manifest path")
            continue
        path = (root / path_text).resolve()
        if not path.is_relative_to(root):
            errors.append(f"Manifest path escapes repository: {path_text}")
            continue
        try:
            content = path.read_bytes()
        except OSError:
            errors.append(f"Missing manifest file: {path_text}")
            continue
        if hashlib.sha256(content).hexdigest() != entry.get("sha256"):
            errors.append(f"SHA-256 mismatch: {path_text}")
        if len(content) != entry.get("bytes"):
            errors.append(f"size mismatch: {path_text}")

    missing_required = REQUIRED_FILES - {
        path for path in paths if isinstance(path, str)
    }
    for path in sorted(missing_required):
        errors.append(f"Required file is not listed: {path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of scripts/)",
    )
    args = parser.parse_args()
    errors = validate(args.root)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    manifest = json.loads((args.root / "SHA256_MANIFEST.json").read_text(encoding="utf-8"))
    print(f"SHA256 manifest PASS ({len(manifest['files'])} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
