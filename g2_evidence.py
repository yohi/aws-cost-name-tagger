"""Offline G2 evidence-bundle foundation. Does not import boto3 or access AWS."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
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
SHARED_RE = re.compile(r"redacted_shared/[A-Za-z0-9][A-Za-z0-9_.-]*\.(?:json|jsonl)\Z", re.ASCII)
IMMUTABLE_LIMITATIONS = ["AWS API was not executed by this tool",
                         "Completeness and source authenticity are not proven"]
MANIFEST_KEYS = {
    "schema_version", "account_id", "source_baseline_sha",
    "snapshot_started_at_utc", "snapshot_completed_at_utc",
    "snapshot_atomic", "snapshot_consistency_status",
    "snapshot_consistency_evidence", "collector_principal_arn",
    "read_only_assertion", "capture_mode", "files",
}
ENTRY_KEYS = {
    "evidence_id", "source", "raw_path", "derived_path", "api", "region",
    "scope", "started_at_utc", "completed_at_utc", "pages",
    "pagination_complete", "status", "provenance", "raw_sha256",
    "raw_bytes", "derived_sha256", "transform_log_ref", "limitations",
}
JOURNAL_KEYS = {"schema_version", "before_manifest_sha256", "after_manifest_sha256",
                "before_sums_sha256", "after_sums_sha256", "record"}
JOURNAL_NAME = "04_INGEST_PENDING.json"


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


def check_private(path: Path) -> None:
    regular_file(path)
    if os.name == "posix" and (path.stat().st_mode & 0o077):
        raise EvidenceError("Private metadata must not be group/world accessible")


def private_root(bundle: Path) -> Path:
    require_outside_git(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        raise EvidenceError("Bundle directory missing or symlink")
    raw = bundle / "raw_secure"
    for directory in (bundle, raw, bundle / "redacted_shared", bundle / "analysis"):
        if directory.is_symlink() or not directory.is_dir():
            raise EvidenceError("Bundle directory missing or symlink")
        if os.name == "posix" and (directory.stat().st_mode & 0o077):
            raise EvidenceError("Private bundle directory must not be group/world accessible")
    return raw

def read_json(path: Path) -> dict:
    check_private(path)
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
    # Open securely at creation time; chmod-after-open leaves a permission window.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


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


def expect_keys(obj: dict, keys: set[str], label: str) -> None:
    if not isinstance(obj, dict) or set(obj) != keys:
        raise EvidenceError(f"Unexpected {label} fields")


def valid_utc(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("+00:00"):
        return False
    try:
        return datetime.fromisoformat(value).utcoffset() == timezone.utc.utcoffset(None)
    except ValueError:
        return False


def validate_entry(item: dict) -> None:
    expect_keys(item, ENTRY_KEYS, "evidence record")
    name = item.get("raw_path")
    if (not isinstance(name, str) or not name.startswith("raw_secure/")
            or not FILENAME_RE.fullmatch(name[len("raw_secure/"):])):
        raise EvidenceError("Unsafe raw path")
    evidence = item.get("evidence_id")
    if (not isinstance(evidence, str) or not EVIDENCE_RE.fullmatch(evidence)
            or item.get("source") not in SOURCES):
        raise EvidenceError("Invalid evidence metadata")
    api = item.get("api")
    if not isinstance(api, str) or not re.fullmatch(
            r"[a-z0-9-]+:(List|Get|Describe|Lookup|BatchGet)[A-Za-z0-9]+", api):
        raise EvidenceError("Invalid read-only API metadata")
    region = item.get("region")
    if not isinstance(region, str) or not re.fullmatch(
            r"(global|[a-z]{2}-[a-z]+-[0-9])", region):
        raise EvidenceError("Invalid region")
    if (type(item.get("pages")) is not int or item["pages"] < 0
            or type(item.get("pagination_complete")) is not bool
            or type(item.get("raw_bytes")) is not int
            or not 0 <= item["raw_bytes"] <= MAX_FILE
            or not isinstance(item.get("raw_sha256"), str)
            or not SHA_RE.fullmatch(item["raw_sha256"])):
        raise EvidenceError("Malformed evidence length, digest or pagination")
    if (item.get("derived_path") is not None or item.get("derived_sha256") is not None
            or item.get("transform_log_ref") is not None
            or item.get("scope") != "USER_SUPPLIED_UNVERIFIED"
            or item.get("started_at_utc") is not None
            or not valid_utc(item.get("completed_at_utc"))
            or item.get("status") != "PARTIAL"
            or item.get("provenance") != "OFFLINE_USER_SUPPLIED_UNVERIFIED"
            or item.get("limitations") != IMMUTABLE_LIMITATIONS):
        raise EvidenceError("Offline provenance or status must remain unverified")


def validate_offline_manifest(manifest: dict, scope: dict) -> None:
    expect_keys(manifest, MANIFEST_KEYS, "manifest")
    expect_keys(scope, {"account_id", "source_baseline_sha", "capture_mode"}, "scope")
    account = manifest.get("account_id")
    baseline = manifest.get("source_baseline_sha")
    if (not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account)
            or not isinstance(baseline, str) or not BASELINE_RE.fullmatch(baseline)
            or scope != {"account_id": account, "source_baseline_sha": baseline,
                         "capture_mode": "OFFLINE_IMPORT_ONLY"}):
        raise EvidenceError("Scope or baseline mismatch")
    if (manifest.get("schema_version") != "g2-evidence-1.1"
            or manifest.get("snapshot_atomic") is not False
            or manifest.get("snapshot_started_at_utc") is not None
            or manifest.get("snapshot_completed_at_utc") is not None
            or manifest.get("snapshot_consistency_status") != "NOT_ATTEMPTED"
            or manifest.get("snapshot_consistency_evidence") != []
            or manifest.get("collector_principal_arn") is not None
            or manifest.get("read_only_assertion") != "REQUIRES_INDEPENDENT_VERIFICATION"
            or manifest.get("capture_mode") != "OFFLINE_IMPORT_ONLY"):
        raise EvidenceError("I0 cannot certify snapshot, collector or authorization")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise EvidenceError("Malformed manifest entries")
    for entry in entries:
        validate_entry(entry)


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
    verify_bundle(bundle)  # fail closed on any pending or inconsistent import
    raw = private_root(bundle)
    manifest_path = bundle / "02_ACQUISITION_MANIFEST.json"
    manifest = read_json(manifest_path)
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
            "limitations": IMMUTABLE_LIMITATIONS}
    validate_entry(item)
    updated = entries + [item]
    new_manifest = json_bytes({**manifest, "files": updated})
    new_sums = checksum_lines(updated)
    old_manifest = manifest_path.read_bytes()
    old_sums = (bundle / "03_SHA256SUMS.txt").read_bytes()
    journal = {"schema_version": "g2-ingest-journal-1",
               "before_manifest_sha256": digest(old_manifest),
               "after_manifest_sha256": digest(new_manifest),
               "before_sums_sha256": digest(old_sums),
               "after_sums_sha256": digest(new_sums), "record": item}
    # Exclusive journal establishes a detectable transaction boundary.
    write_private(bundle / JOURNAL_NAME, json_bytes(journal))
    write_private(dest, data)
    replace_private(manifest_path, new_manifest)
    replace_private(bundle / "03_SHA256SUMS.txt", new_sums)
    (bundle / JOURNAL_NAME).unlink()


def verify_bundle(bundle: Path, *, allow_pending: bool = False) -> dict:
    raw = private_root(bundle)
    pending = bundle / JOURNAL_NAME
    if pending.exists() or pending.is_symlink():
        if not allow_pending:
            raise EvidenceError("Pending ingest must be explicitly recovered")
        check_private(pending)
    manifest_path = bundle / "02_ACQUISITION_MANIFEST.json"
    scope_path = bundle / "01_SCOPE.json"
    sums_path = bundle / "03_SHA256SUMS.txt"
    for path in (bundle / "00_READ_FIRST.md", manifest_path, scope_path, sums_path):
        check_private(path)
    manifest = read_json(manifest_path)
    scope = read_json(scope_path)
    validate_offline_manifest(manifest, scope)
    entries = manifest["files"]
    actual = set()
    for child in raw.iterdir():
        check_private(child)
        actual.add(f"raw_secure/{child.name}")
    expected = set()
    for entry in entries:
        name = entry["raw_path"]
        if name in expected:
            raise EvidenceError("Duplicate evidence path")
        expected.add(name)
        source = bundle / name
        check_private(source)
        if source.stat().st_size > MAX_FILE:
            raise EvidenceError("RAW evidence exceeds size limit")
        data = source.read_bytes()
        if digest(data) != entry["raw_sha256"] or len(data) != entry["raw_bytes"]:
            raise EvidenceError("Evidence bytes changed")
        inspect_json(data, source.suffix)
    if actual != expected:
        raise EvidenceError("Untracked or missing raw evidence")
    if sums_path.read_bytes() != checksum_lines(entries):
        raise EvidenceError("SHA256SUMS does not match manifest")
    return {"status": "INTEGRITY_VERIFIED_ONLY", "captured_files": len(entries),
            "g2_gate": "NOT_VERIFIED", "snapshot_consistency": "NOT_ATTEMPTED"}

def recover_bundle(bundle: Path) -> dict:
    private_root(bundle)
    pending = bundle / JOURNAL_NAME
    if not pending.exists() and not pending.is_symlink():
        verify_bundle(bundle)
        return {"status": "NO_PENDING_INGEST"}
    journal = read_json(pending)
    expect_keys(journal, JOURNAL_KEYS, "ingest journal")
    if journal.get("schema_version") != "g2-ingest-journal-1":
        raise EvidenceError("Unexpected journal schema")
    for field in ("before_manifest_sha256", "after_manifest_sha256",
                  "before_sums_sha256", "after_sums_sha256"):
        if not isinstance(journal.get(field), str) or not SHA_RE.fullmatch(journal[field]):
            raise EvidenceError("Malformed journal digest")
    item = journal["record"]
    validate_entry(item)
    manifest_file = bundle / "02_ACQUISITION_MANIFEST.json"
    sums_file = bundle / "03_SHA256SUMS.txt"
    scope = read_json(bundle / "01_SCOPE.json")
    manifest = read_json(manifest_file)
    validate_offline_manifest(manifest, scope)
    current_sha = digest(manifest_file.read_bytes())
    before, after = journal["before_manifest_sha256"], journal["after_manifest_sha256"]
    if current_sha == before:
        original = manifest
    elif current_sha == after and manifest["files"] and manifest["files"][-1] == item:
        original = {**manifest, "files": manifest["files"][:-1]}
        if digest(json_bytes(original)) != before:
            raise EvidenceError("Recovery prior state does not match journal")
    else:
        raise EvidenceError("Manifest changed outside journal transaction")
    next_entries = original["files"] + [item]
    after_manifest = json_bytes({**original, "files": next_entries})
    before_sums = checksum_lines(original["files"])
    after_sums = checksum_lines(next_entries)
    if (digest(after_manifest) != after
            or digest(before_sums) != journal["before_sums_sha256"]
            or digest(after_sums) != journal["after_sums_sha256"]
            or sums_file.read_bytes() not in (before_sums, after_sums)):
        raise EvidenceError("Recovery checksum or record mismatch")
    source = bundle / item["raw_path"]
    if not source.exists() and not source.is_symlink():
        if current_sha != before or sums_file.read_bytes() != before_sums:
            raise EvidenceError("RAW absent after state update; manual quarantine required")
        verify_bundle(bundle, allow_pending=True)
        pending.unlink()
        return {"status": "ROLLED_BACK_NO_RAW"}
    check_private(source)
    data = source.read_bytes()
    if digest(data) != item["raw_sha256"] or len(data) != item["raw_bytes"]:
        raise EvidenceError("RAW byte mismatch; manual quarantine required")
    inspect_json(data, source.suffix)
    if current_sha == before:
        replace_private(manifest_file, after_manifest)
    if sums_file.read_bytes() != after_sums:
        replace_private(sums_file, after_sums)
    verify_bundle(bundle, allow_pending=True)
    pending.unlink()
    return {"status": "RECOVERED_ROLL_FORWARD", "g2_gate": "NOT_VERIFIED"}

def safe_shared_name(value: str) -> bool:
    if not isinstance(value, str):
        return False
    return bool(SHARED_RE.fullmatch(value) and PurePosixPath(value).as_posix() == value)


def verify_shared(archive: Path) -> dict:
    regular_file(archive)
    if archive.stat().st_size > MAX_SHARED_TOTAL + MAX_SHARED_FILES * 1024:
        raise EvidenceError("Shared ZIP archive exceeds bounded input size")
    total = 0
    with zipfile.ZipFile(archive) as z:
        if z.comment:
            raise EvidenceError("ZIP archive comment forbidden")
        infos = z.infolist()
        if not infos or len(infos) > MAX_SHARED_FILES:
            raise EvidenceError("Empty or oversized shared archive")
        seen = set()
        for i in infos:
            name = i.filename
            canonical = PurePosixPath(name).as_posix()
            if not safe_shared_name(name) or canonical != name or canonical in seen:
                raise EvidenceError("Unsafe, noncanonical or duplicate shared ZIP entry")
            if i.comment or i.extra:
                raise EvidenceError("ZIP member comments and extra fields forbidden")
            mode = i.external_attr >> 16
            if i.create_system != 3 or stat.S_IFMT(mode) != stat.S_IFREG or i.is_dir():
                raise EvidenceError("ZIP member must be an explicit regular file")
            if i.compress_type != zipfile.ZIP_DEFLATED or (i.flag_bits & 0x1):
                raise EvidenceError("Unsupported or encrypted ZIP member")
            if i.file_size > MAX_FILE:
                raise EvidenceError("Large ZIP member")
            total += i.file_size
            if total > MAX_SHARED_TOTAL:
                raise EvidenceError("Shared archive size limit")
            seen.add(canonical)
        if z.testzip() is not None:
            raise EvidenceError("ZIP CRC failure")
        # Rebuild exact canonical bytes to reject hidden data in local headers,
        # unindexed members, prefixes, trailers and other metadata channels.
        expected = io.BytesIO()
        with zipfile.ZipFile(expected, "w", compression=zipfile.ZIP_DEFLATED) as canonical_zip:
            for info in infos:
                canonical_member = zipfile.ZipInfo(info.filename)
                canonical_member.create_system = 3
                canonical_member.external_attr = (stat.S_IFREG | 0o600) << 16
                canonical_zip.writestr(canonical_member, z.read(info),
                                       compress_type=zipfile.ZIP_DEFLATED)
        if archive.read_bytes() != expected.getvalue():
            raise EvidenceError("ZIP contains noncanonical bytes outside approved file content")
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
                member = zipfile.ZipInfo(name)
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | 0o600) << 16
                z.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED)
        verify_shared(tmp)
        # Atomically refuse existing destinations, including a concurrent creation.
        os.link(tmp, output)
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
    p = commands.add_parser("recover", help="Explicitly reconcile an interrupted ingest journal")
    p.add_argument("bundle", type=Path)
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
        elif args.command == "recover":
            result = recover_bundle(args.bundle)
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
