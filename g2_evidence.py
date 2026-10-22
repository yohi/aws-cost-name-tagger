"""Offline G2 evidence-bundle foundation. Does not import boto3 or access AWS."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
BASELINE_RE = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE_RE = re.compile(r"^G2-A[0-9]{2}[a-z]?$", re.ASCII)
FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.(json|jsonl)$")
SOURCES = {"IAM", "IDENTITY_CENTER", "ORGANIZATIONS", "EVENT_HISTORY", "TRAIL_S3", "CLOUDTRAIL_LAKE", "AUTOMATION", "NAME_TAGS", "CONSISTENCY"}
FORBIDDEN_JSON_KEYS = {"secretaccesskey", "sessiontoken", "clientsecret", "privatekey", "password", "secretstring", "secretbinary", "authorization", "xamzsecuritytoken"}
MAX_FILE = 64 * 1024 * 1024
MAX_SHARED_TOTAL = 64 * 1024 * 1024
MAX_SHARED_FILES = 50


class EvidenceError(ValueError):
    """Fail-closed bundle input or integrity violation."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"Not a regular, non-symlink file: {path}")


def private_root(bundle: Path) -> Path:
    if bundle.is_symlink() or not bundle.is_dir():
        raise EvidenceError("Bundle directory missing or symlink")
    raw = bundle / "raw_secure"
    if raw.is_symlink() or not raw.is_dir():
        raise EvidenceError("raw_secure directory missing or symlink")
    if os.name == "posix" and ((bundle.stat().st_mode & 0o077) or (raw.stat().st_mode & 0o077)):
        raise EvidenceError("Bundle and raw_secure must not be group/world accessible")
    return raw


def read_json(path: Path) -> dict:
    regular_file(path)
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise EvidenceError("Expected a JSON object")
    return obj


def inspect_json(data: bytes, suffix: str) -> None:
    # Defense-in-depth: this key-based scanner cannot prove data is sanitized.
    def visit(x):
        if isinstance(x, dict):
            for key, value in x.items():
                if re.sub(r"[^a-z0-9]", "", key.lower()) in FORBIDDEN_JSON_KEYS:
                    raise EvidenceError("Forbidden credential-like JSON field; acquisition halted")
                visit(value)
        elif isinstance(x, list):
            for item in x:
                visit(item)
    text = data.decode("utf-8")
    if suffix == ".jsonl":
        for line in text.splitlines():
            if line.strip():
                visit(json.loads(line))
    else:
        visit(json.loads(text))


def write_private(path: Path, data: bytes) -> None:
    with path.open("xb") as out:
        os.chmod(path, 0o600)
        out.write(data)


def replace_private(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise EvidenceError("Refusing to replace symlink")
    tmp = path.with_name(path.name + ".tmp")
    if tmp.exists() or tmp.is_symlink():
        raise EvidenceError("Temporary output already exists")
    try:
        write_private(tmp, data)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def require_outside_git(path: Path) -> None:
    # Git worktrees have .git as either a directory or a file.
    destination = path.resolve(strict=False)
    if any((parent / ".git").exists() for parent in (destination, *destination.parents)):
        raise EvidenceError("Private evidence and archives must be outside every Git worktree")


def init_bundle(bundle: Path, account: str, baseline: str) -> None:
    if not ACCOUNT_RE.fullmatch(account) or not BASELINE_RE.fullmatch(baseline):
        raise EvidenceError("Expected 12-digit account and 40-character Git commit SHA")
    require_outside_git(bundle)
    if bundle.exists() or bundle.is_symlink():
        raise EvidenceError("Bundle already exists; never overwrite an existing snapshot")
    bundle.mkdir(mode=0o700, parents=False)
    for name in ("raw_secure", "redacted_shared", "analysis"):
        (bundle / name).mkdir(mode=0o700)
    intro = ("# G2 evidence — local offline staging only\n\n"
             "No AWS calls, no AWS write authorization. Imported evidence remains unverified.\n"
             "raw_secure must never be placed in a shared ZIP.\n"
             "Review and independently approve each sanitized derivative before sharing.\n")
    write_private(bundle / "00_READ_FIRST.md", intro.encode())
    write_private(bundle / "01_SCOPE.json", json_bytes({"account_id": account, "source_baseline_sha": baseline, "capture_mode": "OFFLINE_IMPORT_ONLY"}))
    manifest = {"schema_version": "g2-evidence-1.1", "account_id": account,
                "source_baseline_sha": baseline, "snapshot_started_at_utc": None,
                "snapshot_completed_at_utc": None, "snapshot_atomic": False,
                "snapshot_consistency_status": "NOT_ATTEMPTED",
                "snapshot_consistency_evidence": [], "collector_principal_arn": None,
                "read_only_assertion": "REQUIRES_INDEPENDENT_VERIFICATION",
                "capture_mode": "OFFLINE_IMPORT_ONLY", "files": []}
    write_private(bundle / "02_ACQUISITION_MANIFEST.json", json_bytes(manifest))
    write_private(bundle / "03_SHA256SUMS.txt", b"")


def checksum_lines(entries: list[dict]) -> bytes:
    return "".join(f"{e['raw_sha256']}  {e['raw_path']}\n" for e in sorted(entries, key=lambda x: x["raw_path"])).encode()


def ingest(bundle: Path, source_file: Path, evidence_id: str, name: str,
           source: str, api: str, region: str, pages: int, pagination_complete: bool) -> None:
    raw = private_root(bundle)
    manifest_path = bundle / "02_ACQUISITION_MANIFEST.json"
    manifest = read_json(manifest_path)
    if manifest.get("capture_mode") != "OFFLINE_IMPORT_ONLY" or manifest.get("snapshot_atomic") is not False:
        raise EvidenceError("Invalid offline manifest")
    if not EVIDENCE_RE.fullmatch(evidence_id) or not FILENAME_RE.fullmatch(name):
        raise EvidenceError("Invalid evidence ID or output filename")
    if source not in SOURCES or not re.fullmatch(r"[a-z0-9-]+:(List|Get|Describe|Lookup|BatchGet)[A-Za-z0-9]+", api):
        raise EvidenceError("Unsupported source/API metadata (read-only names only)")
    if not re.fullmatch(r"(global|[a-z]{2}-[a-z]+-[0-9])", region) or pages < 0:
        raise EvidenceError("Invalid region or page count")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise EvidenceError("Malformed manifest")
    dest = raw / name
    if dest.exists() or dest.is_symlink():
        raise EvidenceError("Destination already exists")
    regular_file(source_file)
    if source_file.stat().st_size > MAX_FILE:
        raise EvidenceError("File too large")
    data = source_file.read_bytes()
    inspect_json(data, dest.suffix)
    item = {"evidence_id": evidence_id, "source": source, "raw_path": f"raw_secure/{name}",
            "derived_path": None, "api": api, "region": region, "scope": "USER_SUPPLIED_UNVERIFIED",
            "started_at_utc": None, "completed_at_utc": utc_now(),
            "pages": pages, "pagination_complete": pagination_complete,
            "status": "PARTIAL", "provenance": "OFFLINE_USER_SUPPLIED_UNVERIFIED",
            "raw_sha256": digest(data), "raw_bytes": len(data),
            "derived_sha256": None, "transform_log_ref": None,
            "limitations": ["AWS API was not executed by this tool", "Completeness and source authenticity are not proven"]}
    write_private(dest, data)
    updated = entries + [item]
    replace_private(manifest_path, json_bytes({**manifest, "files": updated}))
    replace_private(bundle / "03_SHA256SUMS.txt", checksum_lines(updated))


def verify_bundle(bundle: Path) -> dict:
    raw = private_root(bundle)
    manifest = read_json(bundle / "02_ACQUISITION_MANIFEST.json")
    scope = read_json(bundle / "01_SCOPE.json")
    if manifest.get("schema_version") != "g2-evidence-1.1" or manifest.get("snapshot_atomic") is not False:
        raise EvidenceError("Bad schema or atomic snapshot assertion")
    if manifest.get("capture_mode") != "OFFLINE_IMPORT_ONLY" or manifest.get("snapshot_consistency_status") != "NOT_ATTEMPTED":
        raise EvidenceError("Offline tool cannot certify snapshot consistency")
    if manifest.get("account_id") != scope.get("account_id") or manifest.get("source_baseline_sha") != scope.get("source_baseline_sha"):
        raise EvidenceError("Scope mismatch")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise EvidenceError("Malformed file list")
    actual = set()
    for child in raw.iterdir():
        regular_file(child)
        actual.add(f"raw_secure/{child.name}")
        if os.name == "posix" and (child.stat().st_mode & 0o077):
            raise EvidenceError("Evidence file is group/world accessible")
    expected = set()
    for entry in entries:
        name = entry.get("raw_path", "")
        if not isinstance(name, str) or not name.startswith("raw_secure/") or not FILENAME_RE.fullmatch(name[11:]):
            raise EvidenceError("Unsafe manifest raw path")
        if name in expected or not SHA_RE.fullmatch(entry.get("raw_sha256", "")):
            raise EvidenceError("Duplicate path or invalid digest")
        expected.add(name)
        data = (bundle / name).read_bytes() if (bundle / name).is_file() and not (bundle / name).is_symlink() else None
        if data is None or digest(data) != entry["raw_sha256"] or len(data) != entry.get("raw_bytes"):
            raise EvidenceError("Evidence bytes changed")
        if entry.get("status") != "PARTIAL" or entry.get("provenance") != "OFFLINE_USER_SUPPLIED_UNVERIFIED":
            raise EvidenceError("Offline import must remain unverified and partial")
        inspect_json(data, Path(name).suffix)
    if actual != expected:
        raise EvidenceError("Untracked or missing raw evidence")
    sums_path = bundle / "03_SHA256SUMS.txt"
    regular_file(sums_path)
    if sums_path.read_bytes() != checksum_lines(entries):
        raise EvidenceError("SHA256SUMS does not match manifest")
    return {"status": "INTEGRITY_VERIFIED_ONLY", "captured_files": len(entries),
            "g2_gate": "NOT_VERIFIED", "snapshot_consistency": "NOT_ATTEMPTED"}


def safe_shared_name(value: str) -> bool:
    parts = PurePosixPath(value).parts
    return (len(parts) == 2 and parts[0] == "redacted_shared" and
            bool(FILENAME_RE.fullmatch(parts[1])) and not value.startswith("/") and "\\" not in value)


def verify_shared(archive: Path) -> dict:
    regular_file(archive)
    total = 0
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        if not infos or len(infos) > MAX_SHARED_FILES:
            raise EvidenceError("Empty or oversized shared archive")
        seen = set()
        for i in infos:
            name = i.filename
            if not safe_shared_name(name) or name in seen:
                raise EvidenceError("Unsafe, duplicate or non-shared ZIP entry")
            if ((i.external_attr >> 16) & 0o170000) == stat.S_IFLNK:
                raise EvidenceError("Symlink in archive")
            if i.file_size > MAX_FILE:
                raise EvidenceError("Large ZIP member")
            total += i.file_size
            if total > MAX_SHARED_TOTAL:
                raise EvidenceError("Shared archive size limit")
            seen.add(name)
        if z.testzip() is not None:
            raise EvidenceError("ZIP CRC failure")
    return {"status": "ZIP_STRUCTURE_VERIFIED_ONLY", "files": len(seen),
            "raw_secure_included": False, "content_redaction_verified": False}


def export_shared(bundle: Path, output: Path, approval_file: Path, confirm_reviewed: bool) -> dict:
    verify_bundle(bundle)
    if not confirm_reviewed:
        raise EvidenceError("Explicit --confirm-reviewed flag required")
    approval = read_json(approval_file)
    if not approval.get("reviewed_by") or not approval.get("approved_at_utc"):
        raise EvidenceError("Human review attestation metadata missing")
    entries = approval.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_SHARED_FILES:
        raise EvidenceError("Explicit nonempty file SHA-256 allowlist required")
    shared_dir = bundle / "redacted_shared"
    if shared_dir.is_symlink() or not shared_dir.is_dir():
        raise EvidenceError("Shared directory missing or symlink")
    approved = {}
    for item in entries:
        path = item.get("path", "")
        if not safe_shared_name(path) or path in approved or not SHA_RE.fullmatch(item.get("sha256", "")):
            raise EvidenceError("Invalid approval entry")
        source = bundle / path
        regular_file(source)
        if source.stat().st_size > MAX_FILE:
            raise EvidenceError("Shared item too large")
        data = source.read_bytes()
        if digest(data) != item["sha256"]:
            raise EvidenceError("Approval digest mismatch")
        if source.suffix in (".json", ".jsonl"):
            inspect_json(data, source.suffix)
        approved[path] = data
    if sum(map(len, approved.values())) > MAX_SHARED_TOTAL:
        raise EvidenceError("Total shared output too large")
    require_outside_git(output)
    if output.exists() or output.is_symlink():
        raise EvidenceError("Refusing to overwrite existing ZIP")
    if not output.parent.is_dir():
        raise EvidenceError("Output parent directory missing")
    fd, temp = tempfile.mkstemp(prefix=".g2-shared-", suffix=".zip", dir=str(output.parent))
    os.close(fd)
    tmp = Path(temp)
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in sorted(approved.items()):
                z.writestr(name, data)
        verify_shared(tmp)
        os.replace(tmp, output)
    finally:
        tmp.unlink(missing_ok=True)
    return {"status": "SHARED_ZIP_CREATED_WITH_APPROVAL_METADATA", "files": len(approved),
            "sha256": digest(output.read_bytes()), "redaction_independently_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("init", help="Create a private, empty, offline-only bundle")
    p.add_argument("bundle", type=Path)
    p.add_argument("--account", required=True)
    p.add_argument("--baseline", required=True)
    p = commands.add_parser("ingest", help="Import pre-captured local JSON/JSONL, never contacting AWS")
    p.add_argument("bundle", type=Path)
    p.add_argument("source_file", type=Path)
    p.add_argument("--id", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--source", required=True, choices=sorted(SOURCES))
    p.add_argument("--api", required=True)
    p.add_argument("--region", required=True)
    p.add_argument("--pages", type=int, default=0)
    p.add_argument("--pagination-complete", action="store_true")
    p = commands.add_parser("verify", help="Verify local raw SHA-256, size, paths, permissions")
    p.add_argument("bundle", type=Path)
    p = commands.add_parser("export-shared", help="Export only SHA-approved redacted_shared files")
    p.add_argument("bundle", type=Path)
    p.add_argument("zip_path", type=Path)
    p.add_argument("--approval-file", required=True, type=Path)
    p.add_argument("--confirm-reviewed", action="store_true")
    p = commands.add_parser("verify-shared", help="Reject ZIPs containing any non-shared entries")
    p.add_argument("zip_path", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            init_bundle(args.bundle, args.account, args.baseline)
            result = {"status": "INITIALIZED_OFFLINE_ONLY"}
        elif args.command == "ingest":
            ingest(args.bundle, args.source_file, args.id, args.name, args.source,
                   args.api, args.region, args.pages, args.pagination_complete)
            result = {"status": "OFFLINE_IMPORTED_UNVERIFIED"}
        elif args.command == "verify":
            result = verify_bundle(args.bundle)
        elif args.command == "export-shared":
            result = export_shared(args.bundle, args.zip_path, args.approval_file, args.confirm_reviewed)
        else:
            result = verify_shared(args.zip_path)
    except (EvidenceError, OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
