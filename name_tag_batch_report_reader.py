"""Root-controlled local READ-ONLY Owner-authenticated Host Batch report recovery (Task 8).

Design §5.2.1 "authenticated read-only recovery": after a client-local ``UNKNOWN`` (or a lost
reply) the Owner never resubmits the command. Instead a root-controlled local administrator
runs this reader, which:

1. verifies a fresh, Batch-scoped **Owner read authorization** (its own signature namespace
   ``aws-cost-name-tagger-batch-report-read-v1``) against the *current* protected OwnerTrust,
   role and revocation, using the existing Batch Owner-signature verifier;
2. verifies the original signed Batch envelope over the exact Plan/CSV bytes against the
   current OwnerTrust and derives ``batch_id`` from it (never from the caller);
3. resolves the Host StateDirectory only from the root-pinned Host manifest (same pin and
   schema as the Task 6A bootstrap) and reads ``batch-reports/<batch_id>/index.json`` and the
   one report file that index names (no caller path, no traversal, no symlinks);
4. recomputes the exact stored-bytes ``report_sha256`` and checks it against the index and,
   when the Owner carried one from a reply, the signed expected digest; checks the embedded
   Batch ID, schema and signed Plan/CSV digests;
5. returns an Owner-private authenticated report, or ``NOT_VERIFIED`` plus a safe read of the
   protected Ledger status when one is wired. It never infers zero writes.

It performs zero STS/Intent/Permit/Write, opens no socket or listener, has no execution IPC
client and never mutates the Ledger, STOP or HOLD. ``SO_PEERCRED``, root alone, a
``batch_id``, an unverified local file or the CLI ``--report-out`` summary are never
substitutes for the Owner read authorization or the protected Host report.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Final

import name_tag_batch_approval as approval
import name_tag_batch_trust
from name_tag_batch_host_runtime import (
    PRODUCTION_MANIFEST_PATH, HostRuntimeBlocked, SystemdHostBootstrapVerifier,
    UnavailableHostOSProbe)
from name_tag_batch_runtime import (
    HOST_REPORT_INDEX_NAME, HOST_REPORT_INDEX_SCHEMA, HOST_REPORT_SCHEMA, HOST_REPORTS_DIRNAME,
    host_report_sha256)

READ_NAMESPACE: Final = "aws-cost-name-tagger-batch-report-read-v1"
READ_ALLOWED_ROLE: Final = "batch-approver"
MAX_READ_AUTHORIZATION_LIFETIME: Final = timedelta(minutes=15)
RECOVERY_SCHEMA: Final = "aws-cnt-owner-report-recovery-v1"
MAX_REPORT_BYTES: Final = 64 * 1024 * 1024
MAX_INDEX_BYTES: Final = 4096
_READ_FIELDS: Final = frozenset({
    "schema_version", "purpose", "batch_id", "expected_report_sha256", "owner_principal_id",
    "owner_key_fingerprint", "allowed_role", "issued_at_utc", "expires_at_utc", "read_nonce"})
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{32,128}")


class ReportReadDenied(ValueError):
    """Access denied before any protected report is read (fail closed)."""

    def __init__(self, code: str = "BLOCKED_OWNER_AUTHN") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class VerifiedReportReadAuthorization:
    authorization_id: str
    batch_id: str
    expected_report_sha256: str | None
    owner_principal_id: str


# ---------------------------------------------------------------- Owner read authorization
def _validate_read_payload(payload: object) -> dict:
    if (type(payload) is not dict or set(payload) != _READ_FIELDS
            or type(payload["schema_version"]) is not int or payload["schema_version"] != 1
            or payload["purpose"] != READ_NAMESPACE
            or payload["allowed_role"] != READ_ALLOWED_ROLE):
        raise ReportReadDenied()
    for key in _READ_FIELDS - {"schema_version", "expected_report_sha256"}:
        if type(payload[key]) is not str or not payload[key]:
            raise ReportReadDenied()
    expected = payload["expected_report_sha256"]
    if (_HEX64.fullmatch(payload["batch_id"]) is None
            or _NONCE.fullmatch(payload["read_nonce"]) is None
            or not (expected is None or (type(expected) is str and _HEX64.fullmatch(expected)))):
        raise ReportReadDenied()
    try:
        issued = approval._timestamp(payload["issued_at_utc"])
        expires = approval._timestamp(payload["expires_at_utc"])
    except approval.BatchAuthRejected as error:
        raise ReportReadDenied() from error
    if not issued < expires or expires - issued > MAX_READ_AUTHORIZATION_LIFETIME:
        raise ReportReadDenied()
    return payload


def prepare_report_read_authorization(*, batch_id: str, expected_report_sha256: str | None,
                                      owner_principal_id: str, owner_key_fingerprint: str,
                                      issued_at_utc: str, expires_at_utc: str,
                                      read_nonce: str) -> bytes:
    """Unsigned canonical payload bytes; the Owner signs them out of band in READ_NAMESPACE."""
    payload = _validate_read_payload({
        "schema_version": 1, "purpose": READ_NAMESPACE, "batch_id": batch_id,
        "expected_report_sha256": expected_report_sha256,
        "owner_principal_id": owner_principal_id, "owner_key_fingerprint": owner_key_fingerprint,
        "allowed_role": READ_ALLOWED_ROLE, "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc, "read_nonce": read_nonce})
    return approval.canonical_bytes(payload)


def verify_report_read_authorization(raw: bytes, *, trust: object,
                                     now_utc: datetime) -> VerifiedReportReadAuthorization:
    """Envelope ``{payload, authorization_id, signature_ref}`` checked against current trust."""
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=approval._unique_pairs,
                              parse_constant=approval._reject_json_constant)
        if type(envelope) is not dict or set(envelope) != {"payload", "authorization_id",
                                                           "signature_ref"}:
            raise ReportReadDenied()
        payload = _validate_read_payload(envelope["payload"])
        canonical = approval.canonical_bytes(payload)
        if envelope["authorization_id"] != sha256(canonical).hexdigest():
            raise ReportReadDenied()
        approval._verify_batch_owner_signature(payload, canonical, envelope, trust, now_utc,
                                               namespace=READ_NAMESPACE)
    except ReportReadDenied:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError, ImportError) as error:
        raise ReportReadDenied() from error
    return VerifiedReportReadAuthorization(
        envelope["authorization_id"], payload["batch_id"], payload["expected_report_sha256"],
        payload["owner_principal_id"])


def _verify_original_batch(plan_bytes: bytes, csv_bytes: bytes, envelope_bytes: bytes,
                           trust: object):
    """Original signed Batch identity against the *current* OwnerTrust/revocation.

    The approval window may have closed since execution; freshness comes from the read
    authorization, so the signature is evaluated at the envelope's own signed issue time.
    """
    try:
        envelope = json.loads(envelope_bytes.decode("utf-8"),
                              object_pairs_hook=approval._unique_pairs,
                              parse_constant=approval._reject_json_constant)
        signed_at = approval._timestamp(envelope["payload"]["issued_at_utc"])
        return approval.verify_batch_approval(plan_bytes, csv_bytes, envelope_bytes,
                                              trust=trust, now_utc=signed_at)
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise ReportReadDenied() from error


# ---------------------------------------------------------------- protected storage reads
class _NotVerified(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _private_dir(path: Path, uid: int, *, missing_code: str) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError as error:
        raise _NotVerified(missing_code) from error
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise _NotVerified("REPORT_STORAGE_NOT_PROTECTED")


def _read_protected_file(path: Path, uid: int, limit: int, *, missing_code: str) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    except FileNotFoundError as error:
        raise _NotVerified(missing_code) from error
    except OSError as error:  # ELOOP (symlink) and friends
        raise _NotVerified("REPORT_STORAGE_NOT_PROTECTED") from error
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077
                or info.st_size > limit):
            raise _NotVerified("REPORT_STORAGE_NOT_PROTECTED")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                raise _NotVerified("REPORT_STORAGE_NOT_PROTECTED")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _canonical_object(raw: bytes, code: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=approval._unique_pairs,
                           parse_constant=approval._reject_json_constant)
        if type(value) is not dict or approval.canonical_bytes(value) != raw:
            raise ValueError("not canonical")
    except (ValueError, UnicodeDecodeError) as error:
        raise _NotVerified(code) from error
    return value


# ---------------------------------------------------------------- reader
class HostReportReader:
    """Read-only protected report lookup; every input is injected (tests use temp dirs)."""

    def __init__(self, *, probe: object, manifest_path: str, manifest_sha256: str,
                 trust_loader: Callable[[], object] | None = None, ledger: object = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._manifest_verifier = SystemdHostBootstrapVerifier(
            probe=probe, manifest_path=manifest_path, manifest_sha256=manifest_sha256)
        self._probe = probe
        self._trust_loader = trust_loader
        self._ledger = ledger
        self._clock = clock

    def _trust(self) -> object:
        loader = self._trust_loader or name_tag_batch_trust.load_current_protected_owner_trust
        try:
            return loader()
        except (approval.BatchAuthRejected, OSError, ValueError) as error:
            raise ReportReadDenied() from error

    def _state_directory(self) -> tuple[Path, int]:
        """StateDirectory from the root-pinned manifest; its owner is the service UID."""
        manifest = self._manifest_verifier._manifest()  # pin, root ownership, exact schema
        state_dir = manifest["state_directory"]
        if not isinstance(state_dir, str) or not state_dir.startswith("/") or "\x00" in state_dir:
            raise HostRuntimeBlocked("AWS_RUNTIME_NOT_AUTHORIZED", "StateDirectory malformed")
        facts = self._probe.file_facts(state_dir)
        if (facts.file_type != "dir" or facts.symlink_free is not True or facts.mode & 0o077
                or type(facts.owner_uid) is not int):
            raise HostRuntimeBlocked("AWS_RUNTIME_NOT_AUTHORIZED", "StateDirectory not protected")
        info = os.lstat(state_dir)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != facts.owner_uid
                or info.st_mode & 0o077):
            raise HostRuntimeBlocked("AWS_RUNTIME_NOT_AUTHORIZED", "StateDirectory drifted")
        return Path(state_dir), facts.owner_uid

    def _verified_report(self, batch, auth: VerifiedReportReadAuthorization) -> tuple[str, dict]:
        state_dir, uid = self._state_directory()
        reports = state_dir / HOST_REPORTS_DIRNAME
        batch_dir = reports / batch.batch_id  # batch_id comes only from the signed envelope
        _private_dir(reports, uid, missing_code="REPORT_INDEX_ABSENT")
        _private_dir(batch_dir, uid, missing_code="REPORT_INDEX_ABSENT")
        index = _canonical_object(_read_protected_file(
            batch_dir / HOST_REPORT_INDEX_NAME, uid, MAX_INDEX_BYTES,
            missing_code="REPORT_INDEX_ABSENT"), "REPORT_INDEX_INVALID")
        if (set(index) != {"schema", "batch_id", "report_sha256"}
                or index["schema"] != HOST_REPORT_INDEX_SCHEMA
                or index["batch_id"] != batch.batch_id
                or type(index["report_sha256"]) is not str
                or _HEX64.fullmatch(index["report_sha256"]) is None):
            raise _NotVerified("REPORT_INDEX_INVALID")
        digest = index["report_sha256"]
        if auth.expected_report_sha256 is not None and auth.expected_report_sha256 != digest:
            raise _NotVerified("REPORT_DIGEST_MISMATCH")
        stored = _read_protected_file(batch_dir / f"{digest}.json", uid, MAX_REPORT_BYTES,
                                      missing_code="REPORT_FILE_ABSENT")
        if host_report_sha256(stored) != digest:
            raise _NotVerified("REPORT_DIGEST_MISMATCH")
        report = _canonical_object(stored, "REPORT_IDENTITY_MISMATCH")
        if (report.get("schema") != HOST_REPORT_SCHEMA
                or report.get("batch_id") != batch.batch_id
                or report.get("plan_sha256") != batch.payload["plan_sha256"]
                or report.get("csv_sha256") != batch.payload["csv_sha256"]):
            raise _NotVerified("REPORT_IDENTITY_MISMATCH")
        return digest, report

    def _ledger_status(self, batch) -> dict:
        """Safe read of the protected Ledger (read methods only); never a write inference."""
        if self._ledger is None:
            return {"status": "LEDGER_STATUS_NOT_AVAILABLE"}
        try:
            state = self._ledger.batch_execution_state(batch)
            scopes = sorted({row["writer_control_scope_id"] for row in batch.approved_rows})
            return {"status": "READ", "batch_state": state.state,
                    "send_attempts_consumed": state.send_attempts_consumed,
                    "max_send_attempts": state.max_send_attempts,
                    "row_outcomes": [[index, outcome] for index, outcome
                                     in zip(batch.approved_row_indexes, state.outcomes)],
                    "scope_states": {scope: self._ledger.effective_scope_state(scope)
                                     for scope in scopes}}
        except Exception:  # noqa: BLE001 - an unreadable Ledger is reported, never guessed
            return {"status": "LEDGER_STATUS_UNREADABLE"}

    def recover(self, *, plan_bytes: bytes, csv_bytes: bytes, envelope_bytes: bytes,
                read_authorization_bytes: bytes) -> dict:
        now = self._clock()
        trust = self._trust()
        auth = verify_report_read_authorization(read_authorization_bytes, trust=trust,
                                                now_utc=now)
        batch = _verify_original_batch(plan_bytes, csv_bytes, envelope_bytes, trust)
        if auth.batch_id != batch.batch_id or auth.owner_principal_id != batch.owner_principal_id:
            raise ReportReadDenied("BLOCKED_REPORT_SCOPE")
        result = {
            "schema": RECOVERY_SCHEMA, "operation": "READ_ONLY_OWNER_AUTHENTICATED",
            "batch_id": batch.batch_id, "authorization_id": auth.authorization_id,
            "owner_principal_id": auth.owner_principal_id,
            "expected_report_sha256": auth.expected_report_sha256,
            "digest_source": ("REPLY_DIGEST_AND_HOST_INDEX"
                              if auth.expected_report_sha256 is not None else "HOST_INDEX_ONLY"),
            "zero_writes_inferred": False, "execution_allowed": False,
        }
        try:
            digest, report = self._verified_report(batch, auth)
        except _NotVerified as missing:
            result.update({"recovery_status": "NOT_VERIFIED", "code": missing.code,
                           "report_sha256": None, "report": None,
                           "ledger_status": self._ledger_status(batch)})
            return result
        result.update({
            "recovery_status": "VERIFIED", "code": "REPORT_VERIFIED", "report_sha256": digest,
            "batch_state": report.get("batch_state"),
            "row_ledger_outcomes": report.get("row_ledger_outcomes"),
            "send_attempts_consumed": report.get("send_attempts_consumed"),
            "max_send_attempts": report.get("max_send_attempts"),
            "applied_verified_count": report.get("applied_verified_count"),
            "unresolved_rows": report.get("unresolved_rows"),
            "refusal_code": report.get("refusal_code"),
            "report": report, "ledger_status": self._ledger_status(batch)})
        return result


def production_report_reader() -> HostReportReader:
    """Production wiring in this phase: no accepted OS probe/pin -> fails closed."""
    return HostReportReader(probe=UnavailableHostOSProbe(), manifest_path=PRODUCTION_MANIFEST_PATH,
                            manifest_sha256="0" * 64)


def main(argv=None, *, reader: HostReportReader | None = None) -> int:
    """Root-controlled admin command; writes only a new private (0600) Owner output file."""
    from name_tag_batch_cli import _read_private, _resolve_cli_path, _write_new

    parser = argparse.ArgumentParser(prog="name_tag_batch_report_reader",
                                     description="Read-only Owner-authenticated report recovery",
                                     allow_abbrev=False)
    for flag in ("--plan", "--review", "--envelope", "--read-authorization", "--report-out"):
        parser.add_argument(flag, required=True)
    args = parser.parse_args(argv)
    try:
        paths = {name: _resolve_cli_path(getattr(args, name)) for name in
                 ("plan", "review", "envelope", "read_authorization", "report_out")}
        if paths["report_out"].exists() or paths["report_out"].is_symlink():
            raise ValueError("Refusing overwrite of existing output")
        result = (reader or production_report_reader()).recover(
            plan_bytes=_read_private(paths["plan"]), csv_bytes=_read_private(paths["review"]),
            envelope_bytes=_read_private(paths["envelope"]),
            read_authorization_bytes=_read_private(paths["read_authorization"]))
        _write_new(paths["report_out"], (json.dumps(result, ensure_ascii=False, sort_keys=True,
                                                    indent=2) + "\n").encode("utf-8"))
    except ReportReadDenied as denied:
        print(f"DENIED (read-only): {denied.code}", file=sys.stderr)
        return 2
    except (HostRuntimeBlocked, OSError, ValueError) as error:
        print(f"BLOCKED (read-only): {getattr(error, 'code', error)}", file=sys.stderr)
        return 2
    print(f"report recovery: {result['recovery_status']} {result['code']}")
    return 0 if result["recovery_status"] == "VERIFIED" else 3


__all__ = ["READ_NAMESPACE", "HostReportReader", "ReportReadDenied",
           "VerifiedReportReadAuthorization", "prepare_report_read_authorization",
           "production_report_reader", "verify_report_read_authorization", "main"]
