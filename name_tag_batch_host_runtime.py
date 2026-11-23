"""Host-only protected runtime: bootstrap context, STS issuance tombstones, singleton selector.

Design §§5.1-5.2. OFFLINE in this implementation phase: nothing here installs or starts a
systemd unit, binds a socket, reads /var or /run, or calls AWS. All OS facts arrive through
an injected ``HostOSProbe``; the production default probe is unavailable and fails closed
with ``AWS_RUNTIME_NOT_AUTHORIZED`` until a separately Owner-authorized Host acceptance.

``VerifiedHostContext`` is a Host-issued protected reference, not proof by fields: only a
context registered by ``SystemdHostBootstrapVerifier.verify_process`` in this process is
accepted, and copies, pickles, constructed instances or tampered contexts are refused.
"""
from __future__ import annotations

import errno
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields as dataclass_fields
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Final, Protocol
from weakref import WeakKeyDictionary

from name_tag_batch_approval import canonical_bytes
from name_tag_batch_trust import load_current_protected_owner_trust

AWS_RUNTIME_NOT_AUTHORIZED: Final = "AWS_RUNTIME_NOT_AUTHORIZED"
SERVICE_UNIT: Final = "aws-cnt-batch.service"
SERVICE_CGROUP: Final = "/system.slice/aws-cnt-batch.service"
SERVICE_USER: Final = "aws-cnt"
PRODUCTION_MANIFEST_PATH: Final = "/etc/aws-cnt/host-manifest.json"
REQUIRED_UNIT_PROPERTIES: Final = MappingProxyType({
    "User": "aws-cnt",
    "NoNewPrivileges": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "PrivateTmp": "yes",
    "UMask": "0077",
    "StateDirectory": "aws-cnt",
    "RuntimeDirectory": "aws-cnt",
})
_IMMUTABLE_ROLES: Final = frozenset({"unit", "executable", "config", "owner_trust", "scope_evidence"})
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ROLE_ARN = re.compile(r"arn:(aws|aws-cn|aws-us-gov):iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}")


class HostRuntimeBlocked(RuntimeError):
    """A Host gate is missing or failed; nothing downstream (STS/Intent/Permit) may run."""

    def __init__(self, code: str = AWS_RUNTIME_NOT_AUTHORIZED, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _blocked(detail: str, code: str = AWS_RUNTIME_NOT_AUTHORIZED) -> HostRuntimeBlocked:
    return HostRuntimeBlocked(code, detail)


def require_aware_utc(now_utc: object) -> datetime:
    if type(now_utc) is not datetime or now_utc.tzinfo is None or now_utc.utcoffset() is None:
        raise _blocked("now_utc must be timezone-aware")
    return now_utc.astimezone(timezone.utc)


class _NonCopyable:
    """Protected references cannot be copied, pickled or serialized."""

    __slots__ = ()

    def __copy__(self):
        raise _blocked("protected reference cannot be copied")

    def __deepcopy__(self, memo):
        raise _blocked("protected reference cannot be copied")

    def __reduce_ex__(self, protocol):
        raise _blocked("protected reference cannot be serialized")

    def __reduce__(self):
        raise _blocked("protected reference cannot be serialized")

    def __getstate__(self):
        raise _blocked("protected reference cannot be serialized")


# ---------------------------------------------------------------- OS probe contract
@dataclass(frozen=True)
class HostProcessFacts:
    """Facts reported by the OS (kernel/systemd) for the current process; not env/args."""

    platform: str
    init_system: str
    pid: int
    uid: int
    gid: int
    user_name: str
    cgroup: str
    unit_name: str
    unit_main_pid: int
    unit_active_state: str
    invocation_id: str
    boot_id: str
    machine_id: str
    unit_properties: Mapping[str, str]
    credentials_directory: str


@dataclass(frozen=True)
class ProtectedFileFacts:
    path: str
    file_type: str  # "file" | "dir"
    owner_uid: int
    group_gid: int
    mode: int
    symlink_free: bool  # no symlink in any path component
    sha256: str | None


class HostOSProbe(Protocol):
    def process_facts(self) -> HostProcessFacts: ...
    def file_facts(self, path: str) -> ProtectedFileFacts: ...
    def read_protected(self, path: str) -> bytes: ...


class UnavailableHostOSProbe:
    """Production default: real OS attestation is not built in this phase -> fail closed."""

    def process_facts(self) -> HostProcessFacts:
        raise _blocked("protected Host OS probe is not available (Owner HOLD)")

    def file_facts(self, path: str) -> ProtectedFileFacts:
        raise _blocked("protected Host OS probe is not available (Owner HOLD)")

    def read_protected(self, path: str) -> bytes:
        raise _blocked("protected Host OS probe is not available (Owner HOLD)")


# ---------------------------------------------------------------- protected Host context
@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class VerifiedHostContext(_NonCopyable):
    """Process-local reference; valid only while registered by the bootstrap verifier."""

    host_id: str
    run_id: str
    boot_id: str
    service_unit: str
    service_uid: int
    cgroup: str
    manifest_sha256: str
    owner_trust_sha256: str
    scope_evidence_sha256: str
    state_directory: str
    ledger_path: str
    ledger_identity: str
    credentials_directory: str
    authorized_role_arn: str
    verified_at_utc: datetime
    live_status: str = "NOT_VERIFIED"


@dataclass(frozen=True)
class _HostBinding:
    digest: str
    ledger: object
    journal: "IssuanceAttemptJournal"


_HOSTS: WeakKeyDictionary = WeakKeyDictionary()


def _context_digest(host: VerifiedHostContext) -> str:
    values = []
    for f in dataclass_fields(VerifiedHostContext):
        value = getattr(host, f.name)
        values.append(value.isoformat() if isinstance(value, datetime) else value)
    return sha256(canonical_bytes(values)).hexdigest()


def require_verified_host(host: object) -> VerifiedHostContext:
    """Accept only the exact, untampered context minted by this process's bootstrap."""
    if type(host) is not VerifiedHostContext:
        raise _blocked("Host context is not a protected reference")
    try:
        binding = _HOSTS.get(host)
    except TypeError:
        binding = None
    if binding is None or binding.digest != _context_digest(host):
        raise _blocked("Host context is not registered or was altered")
    return host


def bound_ledger(host: VerifiedHostContext) -> object:
    return _HOSTS[require_verified_host(host)].ledger


def bound_journal(host: VerifiedHostContext) -> "IssuanceAttemptJournal":
    return _HOSTS[require_verified_host(host)].journal


def _require_hex(value: object, pattern: re.Pattern[str], what: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _blocked(f"{what} is malformed")
    return value


def _strict_json(raw: bytes) -> dict:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate key")
            out[key] = value
        return out

    def constant(_value):
        raise ValueError("non-finite number")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    if type(value) is not dict:
        raise ValueError("object required")
    return value


class HostBootstrapVerifier(Protocol):
    def verify_process(self, *, now_utc: datetime) -> VerifiedHostContext: ...


class SystemdHostBootstrapVerifier:
    """HostBootstrapVerifier for the single fixed ``aws-cnt-batch.service`` architecture."""

    def __init__(
        self,
        *,
        probe: HostOSProbe,
        manifest_path: str,
        manifest_sha256: str,
        ledger_opener: Callable[[str], object] | None = None,
        fsync: Callable[[int], None] = os.fsync,
    ) -> None:
        self._probe = probe
        self._manifest_path = manifest_path
        self._manifest_sha256 = manifest_sha256
        self._ledger_opener = ledger_opener or _open_protected_ledger
        self._fsync = fsync

    # -- helpers -----------------------------------------------------------------
    def _file(self, path: str, *, kind: str, owner: int, mode_mask: int,
              exact_mode: int | None = None) -> ProtectedFileFacts:
        if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
            raise _blocked("protected path must be absolute")
        try:
            facts = self._probe.file_facts(path)
        except HostRuntimeBlocked:
            raise
        except (OSError, ValueError) as error:
            raise _blocked(f"protected path unavailable: {path}") from error
        if (type(facts) is not ProtectedFileFacts or facts.path != path
                or facts.file_type != kind or facts.symlink_free is not True
                or facts.owner_uid != owner or facts.mode & mode_mask
                or (exact_mode is not None and facts.mode & 0o777 != exact_mode)):
            raise _blocked(f"protected path ownership/mode/type mismatch: {path}")
        return facts

    def _verify_process_facts(self, facts: object) -> HostProcessFacts:
        if type(facts) is not HostProcessFacts:
            raise _blocked("process facts are not OS-reported facts")
        properties = facts.unit_properties
        if (facts.platform != "linux" or facts.init_system != "systemd"
                or facts.unit_name != SERVICE_UNIT or facts.cgroup != SERVICE_CGROUP
                or facts.unit_active_state not in ("active", "reloading")
                or type(facts.pid) is not int or facts.pid <= 1
                or facts.pid != os.getpid() or facts.unit_main_pid != facts.pid
                or facts.user_name != SERVICE_USER
                or type(facts.uid) is not int or facts.uid == 0 or facts.uid != os.getuid()
                or type(facts.gid) is not int or facts.gid == 0
                or not isinstance(properties, Mapping)
                or any(properties.get(k) != v for k, v in REQUIRED_UNIT_PROPERTIES.items())):
            raise _blocked("service/process/cgroup/unit hardening not verified")
        for value, what in ((facts.invocation_id, "invocation id"), (facts.boot_id, "boot id"),
                            (facts.machine_id, "machine id")):
            _require_hex(value, _HEX32, what)
        return facts

    def _manifest(self) -> dict:
        _require_hex(self._manifest_sha256, _HEX64, "manifest pin")
        facts = self._file(self._manifest_path, kind="file", owner=0, mode_mask=0o022)
        try:
            raw = self._probe.read_protected(self._manifest_path)
        except HostRuntimeBlocked:
            raise
        except OSError as error:
            raise _blocked("manifest unreadable") from error
        if (not isinstance(raw, bytes) or sha256(raw).hexdigest() != self._manifest_sha256
                or facts.sha256 != self._manifest_sha256):
            raise _blocked("manifest digest differs from the root pin")
        try:
            manifest = _strict_json(raw)
            if canonical_bytes(manifest) != raw:
                raise ValueError("manifest is not canonical")
        except (ValueError, UnicodeDecodeError) as error:
            raise _blocked("manifest is malformed") from error
        if (set(manifest) != {"schema", "immutable_files", "state_directory", "ledger_path",
                              "authorized_role_arn"}
                or manifest["schema"] != "aws-cnt-host-manifest-v1"
                or type(manifest["immutable_files"]) is not dict
                or set(manifest["immutable_files"]) != _IMMUTABLE_ROLES
                or not isinstance(manifest["authorized_role_arn"], str)
                or _ROLE_ARN.fullmatch(manifest["authorized_role_arn"]) is None):
            raise _blocked("manifest content is not the pinned schema")
        return manifest

    # -- contract ------------------------------------------------------------------
    def verify_process(self, *, now_utc: datetime) -> VerifiedHostContext:
        now = require_aware_utc(now_utc)
        try:
            process = self._verify_process_facts(self._probe.process_facts())
        except HostRuntimeBlocked:
            raise
        except (OSError, ValueError, TypeError, AttributeError) as error:
            raise _blocked("process facts unavailable") from error
        manifest = self._manifest()
        digests = {}
        for role in sorted(_IMMUTABLE_ROLES):
            entry = manifest["immutable_files"][role]
            if type(entry) is not dict or set(entry) != {"path", "sha256"}:
                raise _blocked("manifest entry malformed")
            expected = _require_hex(entry["sha256"], _HEX64, "pinned digest")
            facts = self._file(entry["path"], kind="file", owner=0, mode_mask=0o022)
            if facts.sha256 != expected:
                raise _blocked(f"pinned digest drift: {role}")
            digests[role] = expected
        state_dir = manifest["state_directory"]
        ledger_path = manifest["ledger_path"]
        self._file(state_dir, kind="dir", owner=process.uid, mode_mask=0o077, exact_mode=0o700)
        if (not isinstance(ledger_path, str) or not ledger_path.startswith(state_dir + "/")
                or "/../" in ledger_path or ledger_path.endswith("/..")):
            raise _blocked("Ledger is not inside the verified StateDirectory")
        self._file(ledger_path, kind="file", owner=process.uid, mode_mask=0o077, exact_mode=0o600)
        self._file(process.credentials_directory, kind="dir", owner=process.uid, mode_mask=0o077)
        host_id = sha256(b"aws-cnt-host-v1\x00" + process.machine_id.encode("ascii")).hexdigest()
        ledger_identity = sha256(canonical_bytes([host_id, ledger_path, process.uid])).hexdigest()
        journal = IssuanceAttemptJournal(Path(state_dir) / "issuance-attempts",
                                         service_uid=process.uid, fsync=self._fsync)
        try:
            journal.scan()  # read-only startup reconciliation; corrupt records block startup
            ledger = self._ledger_opener(ledger_path)
        except HostRuntimeBlocked:
            raise
        except Exception as error:  # noqa: BLE001 - any Ledger/journal doubt fails closed
            raise _blocked("protected Ledger/journal reconciliation failed") from error
        if ledger is None:
            raise _blocked("protected Ledger unavailable")
        host = VerifiedHostContext(
            host_id=host_id, run_id=process.invocation_id, boot_id=process.boot_id,
            service_unit=process.unit_name, service_uid=process.uid, cgroup=process.cgroup,
            manifest_sha256=self._manifest_sha256, owner_trust_sha256=digests["owner_trust"],
            scope_evidence_sha256=digests["scope_evidence"], state_directory=state_dir,
            ledger_path=ledger_path, ledger_identity=ledger_identity,
            credentials_directory=process.credentials_directory,
            authorized_role_arn=manifest["authorized_role_arn"], verified_at_utc=now)
        _HOSTS[host] = _HostBinding(_context_digest(host), ledger, journal)
        return host


def _open_protected_ledger(path: str) -> object:
    """Production opener: only the provisioned Host-bound Ledger v2 (no create/reinit)."""
    from name_tag_ledger import open_ledger

    return open_ledger(path, trusted_host=True, trust=load_current_protected_owner_trust())


def production_bootstrap_verifier() -> SystemdHostBootstrapVerifier:
    """The only production wiring; fails closed until a real OS probe is accepted."""
    return SystemdHostBootstrapVerifier(
        probe=UnavailableHostOSProbe(), manifest_path=PRODUCTION_MANIFEST_PATH,
        manifest_sha256="0" * 64)


# ---------------------------------------------------------------- STS row-attempt tombstone
ISSUANCE_PENDING: Final = "ISSUANCE_PENDING"
ISSUED_VERIFIED: Final = "ISSUED_VERIFIED"
ISSUANCE_REFUSED: Final = "ISSUANCE_REFUSED"
ISSUANCE_UNRESOLVED: Final = "ISSUANCE_UNRESOLVED"
_FINAL_STATES: Final = frozenset({ISSUED_VERIFIED, ISSUANCE_REFUSED, ISSUANCE_UNRESOLVED})
_RECORD_SCHEMA: Final = "aws-cnt-issuance-attempt-v1"
_RECORD_FIELDS: Final = frozenset({
    "schema", "status", "batch_id", "batch_nonce_sha256", "plan_sha256", "csv_sha256",
    "row_index", "row_authority_id", "scope_id", "host_id", "run_id", "role_arn",
    "role_session_name", "policy_sha256", "name_evidence_sha256", "attempt_id",
    "created_at_utc", "updated_at_utc", "receipt_sha256", "response_sha256", "refusal_code",
})
_RECORD_NAME = re.compile(r"(0|[1-9][0-9]{0,8})-([0-9a-f]{64})\.json")
_MAX_RECORD_BYTES: Final = 65536
_TOMBSTONE_BLOCKED: Final = "BLOCKED_ISSUANCE_ATTEMPT_EXISTS"


def _record_digest(body: Mapping[str, object]) -> str:
    return sha256(b"aws-cnt-issuance-attempt-v1\x00" + canonical_bytes(dict(body))).hexdigest()


def _validate_record(record: object, *, batch_id: str, row_index: int,
                     row_authority_id: str) -> dict:
    if type(record) is not dict or set(record) != _RECORD_FIELDS | {"record_sha256"}:
        raise _blocked("issuance record schema mismatch")
    body = {k: v for k, v in record.items() if k != "record_sha256"}
    if record["record_sha256"] != _record_digest(body):
        raise _blocked("issuance record digest mismatch (tampered)")
    if (body["schema"] != _RECORD_SCHEMA
            or body["status"] not in _FINAL_STATES | {ISSUANCE_PENDING}
            or body["batch_id"] != batch_id or body["row_index"] != row_index
            or type(body["row_index"]) is not int
            or body["row_authority_id"] != row_authority_id):
        raise _blocked("issuance record identity mismatch")
    for key in ("batch_nonce_sha256", "plan_sha256", "csv_sha256", "host_id",
                "policy_sha256", "name_evidence_sha256", "attempt_id"):
        _require_hex(body[key], _HEX64, key)
    _require_hex(body["run_id"], _HEX32, "run_id")
    if body["status"] == ISSUED_VERIFIED:
        _require_hex(body["receipt_sha256"], _HEX64, "receipt_sha256")
        _require_hex(body["response_sha256"], _HEX64, "response_sha256")
    return record


class IssuanceAttemptJournal:
    """Durable, metadata-only, create-exclusive pre-STS row-attempt tombstones.

    Not a second Ledger: it never authorizes a send, registers a Batch or consumes the
    signed send cap. It only denies a second AssumeRole for the same signed row.
    """

    def __init__(self, root: Path, *, service_uid: int,
                 fsync: Callable[[int], None] = os.fsync) -> None:
        self._root = Path(root)
        self._uid = service_uid
        self._fsync = fsync

    # -- filesystem primitives (no symlink, private modes, durable) -------------------
    def _secure_dir(self, path: Path, *, create: bool) -> bool:
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            if not create:
                return False
            os.mkdir(path, 0o700)
            info = os.lstat(path)
            self._sync_dir(path.parent)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self._uid
                or info.st_mode & 0o077):
            raise _blocked("issuance journal directory is not private")
        return True

    def _sync_dir(self, path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            self._fsync(fd)
        finally:
            os.close(fd)

    def _batch_dir(self, batch_id: str) -> Path:
        _require_hex(batch_id, _HEX64, "batch_id")
        return self._root / batch_id

    def _name(self, row_index: int, row_authority_id: str) -> str:
        if type(row_index) is not int or row_index < 0 or row_index > 999_999_999:
            raise _blocked("row index malformed")
        _require_hex(row_authority_id, _HEX64, "row_authority_id")
        return f"{row_index}-{row_authority_id}.json"

    def _read_path(self, path: Path, *, batch_id: str) -> dict:
        match = _RECORD_NAME.fullmatch(path.name)
        if match is None:
            raise _blocked("unexpected file in issuance journal")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid
                    or info.st_mode & 0o077 or info.st_size > _MAX_RECORD_BYTES):
                raise _blocked("issuance record is not a private regular file")
            raw = os.read(fd, _MAX_RECORD_BYTES + 1)
        finally:
            os.close(fd)
        try:
            record = _strict_json(raw)
            if canonical_bytes(record) != raw:
                raise ValueError("noncanonical record")
        except (ValueError, UnicodeDecodeError) as error:
            raise _blocked("issuance record is corrupt") from error
        return _validate_record(record, batch_id=batch_id, row_index=int(match.group(1)),
                                row_authority_id=match.group(2))

    # -- read-only reconciliation --------------------------------------------------
    def scan(self) -> tuple[dict, ...]:
        """Validate every record (startup / pre-selection). Any doubt raises."""
        try:
            if not self._secure_dir(self._root, create=False):
                return ()
            records = []
            for batch_dir in sorted(self._root.iterdir()):
                if _HEX64.fullmatch(batch_dir.name) is None:
                    raise _blocked("unexpected entry in issuance journal")
                self._secure_dir(batch_dir, create=False)
                for path in sorted(batch_dir.iterdir()):
                    records.append(self._read_path(path, batch_id=batch_dir.name))
            return tuple(records)
        except HostRuntimeBlocked:
            raise
        except OSError as error:
            raise _blocked("issuance journal unreadable") from error

    def records_for_row(self, batch_id: str, row_index: int) -> tuple[dict, ...]:
        """Every record for the signed row (any authority/run). Unreadable -> raise."""
        try:
            batch_dir = self._batch_dir(batch_id)
            if not self._secure_dir(self._root, create=False):
                return ()
            if not self._secure_dir(batch_dir, create=False):
                return ()
            prefix = f"{row_index}-"
            return tuple(self._read_path(p, batch_id=batch_id)
                         for p in sorted(batch_dir.iterdir()) if p.name.startswith(prefix))
        except HostRuntimeBlocked:
            raise
        except OSError as error:
            raise _blocked("issuance journal unreadable") from error

    def assert_row_unattempted(self, batch_id: str, row_index: int) -> None:
        if self.records_for_row(batch_id, row_index):
            raise HostRuntimeBlocked(_TOMBSTONE_BLOCKED, "prior STS attempt for signed row")

    def read(self, batch_id: str, row_index: int, row_authority_id: str) -> dict | None:
        path = self._batch_dir(batch_id) / self._name(row_index, row_authority_id)
        try:
            return self._read_path(path, batch_id=batch_id)
        except FileNotFoundError:
            return None
        except HostRuntimeBlocked:
            raise
        except OSError as error:
            raise _blocked("issuance record unreadable") from error

    # -- durable writes -----------------------------------------------------------
    def create_pending(self, body: Mapping[str, object]) -> dict:
        """Exclusive create + file fsync + parent directory fsync, before any STS call."""
        record_body = dict(body)
        record_body.update(schema=_RECORD_SCHEMA, status=ISSUANCE_PENDING,
                           updated_at_utc=record_body.get("created_at_utc"),
                           receipt_sha256=None, response_sha256=None, refusal_code=None)
        record = {**record_body, "record_sha256": _record_digest(record_body)}
        batch_id = record_body.get("batch_id")
        row_index = record_body.get("row_index")
        authority = record_body.get("row_authority_id")
        _validate_record(record, batch_id=batch_id, row_index=row_index,
                         row_authority_id=authority)  # type: ignore[arg-type]
        try:
            self._secure_dir(self._root, create=True)
            batch_dir = self._batch_dir(batch_id)  # type: ignore[arg-type]
            self._secure_dir(batch_dir, create=True)
            self.assert_row_unattempted(batch_id, row_index)  # type: ignore[arg-type]
            path = batch_dir / self._name(row_index, authority)  # type: ignore[arg-type]
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600)
            try:
                self._write_all(fd, canonical_bytes(record))
                self._fsync(fd)
            finally:
                os.close(fd)
            self._sync_dir(batch_dir)
        except HostRuntimeBlocked:
            raise
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise HostRuntimeBlocked(_TOMBSTONE_BLOCKED, "row tombstone exists") from error
            raise _blocked("issuance tombstone could not be made durable") from error
        return record

    def finalize(self, pending: Mapping[str, object], *, status: str, updated_at_utc: str,
                 receipt_sha256: str | None = None, response_sha256: str | None = None,
                 refusal_code: str | None = None) -> dict:
        """Atomically replace the exact PENDING record with its single final state."""
        if status not in _FINAL_STATES:
            raise _blocked("invalid final issuance state")
        batch_id = pending["batch_id"]
        row_index = pending["row_index"]
        authority = pending["row_authority_id"]
        current = self.read(batch_id, row_index, authority)  # type: ignore[arg-type]
        if current is None or current != dict(pending) or current["status"] != ISSUANCE_PENDING:
            raise _blocked("issuance record changed before finalization")
        body = {k: v for k, v in current.items() if k != "record_sha256"}
        body.update(status=status, updated_at_utc=updated_at_utc, receipt_sha256=receipt_sha256,
                    response_sha256=response_sha256, refusal_code=refusal_code)
        record = {**body, "record_sha256": _record_digest(body)}
        _validate_record(record, batch_id=batch_id, row_index=row_index,
                         row_authority_id=authority)  # type: ignore[arg-type]
        batch_dir = self._batch_dir(batch_id)  # type: ignore[arg-type]
        name = self._name(row_index, authority)  # type: ignore[arg-type]
        tmp = batch_dir / f".{name}.{body['attempt_id']}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                         | os.O_CLOEXEC, 0o600)
            try:
                self._write_all(fd, canonical_bytes(record))
                self._fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, batch_dir / name)
            self._sync_dir(batch_dir)
        except OSError as error:
            raise _blocked("issuance final state could not be made durable") from error
        return record

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]


# ---------------------------------------------------------------- RG-PRC-005 selector
_TERMINAL_ROW_OUTCOMES: Final = frozenset({
    "APPLIED_VERIFIED", "SKIPPED_NAME_CHANGED", "SKIPPED_IAM_UNSUPPORTED", "NOT_ATTEMPTED_CAP"})
_SEND_CONSUMING_TERMINALS: Final = frozenset({"APPLIED_VERIFIED"})
_NONCE = re.compile(r"[0-9a-f]{32,128}")


@dataclass(frozen=True, eq=False)
class HostSelection:
    """Host-protected singleton selection; one-shot input to HostCredentialIssuer.issue."""

    host: VerifiedHostContext
    batch: object  # freshly Owner-revalidated VerifiedBatchApproval
    spec: object  # SessionPolicySpec
    row_authority: object  # VerifiedBatchRowAuthority
    snapshot: object  # BatchExecutionState read under the Coordinator lock
    signed_cap: int
    scope_id: str
    capability: object  # KindCapabilityDecision
    target: object  # CanonicalTargetIdentity
    name_evidence_sha256: str
    selected_at_utc: datetime


_SELECTIONS: dict[int, HostSelection] = {}


def _lookup_selection(spec: object, host: object, *, pop: bool) -> HostSelection:
    host = require_verified_host(host)
    selection = _SELECTIONS.get(id(spec))
    if selection is None or selection.spec is not spec or selection.host is not host:
        raise _blocked("subset was not selected by this protected Host")
    if pop:
        del _SELECTIONS[id(spec)]
    return selection


def peek_selection(spec: object, host: VerifiedHostContext) -> HostSelection:
    return _lookup_selection(spec, host, pop=False)


def take_selection(spec: object, host: VerifiedHostContext) -> HostSelection:
    """Consume the Host selection exactly once (a copied/caller-built spec never matches)."""
    return _lookup_selection(spec, host, pop=True)


def _current_owner_batch(batch: object, now: datetime):
    import name_tag_batch_approval as approval

    if type(batch) is not approval.VerifiedBatchApproval:
        raise _blocked("batch is not Owner-verified", "BLOCKED_OWNER_AUTHN")
    try:
        trust = load_current_protected_owner_trust()
        return approval.revalidate_verified_batch(batch, trust=trust, now_utc=now)
    except (approval.BatchAuthRejected, OSError, ValueError, TypeError) as error:
        raise _blocked("current OwnerTrust rejects the batch", "BLOCKED_OWNER_AUTHN") from error


def _current_row_authority(batch, row_index: int, now: datetime):
    import name_tag_batch_approval as approval

    try:
        trust = load_current_protected_owner_trust()
        return approval.derive_batch_row_authority(batch, row_index, trust=trust, now_utc=now)
    except (approval.BatchAuthRejected, OSError, ValueError, TypeError, KeyError) as error:
        raise _blocked("row authority rejected", "BLOCKED_OWNER_AUTHN") from error


def _signed_shape(batch) -> tuple[tuple[int, ...], int]:
    """Re-derive approved indexes and the signed cap from the exact signed bytes."""
    from name_tag_batch_approval import _approved_tuples
    from name_tag_batch_state import BatchValidationError, validate_batch_draft

    try:
        draft = validate_batch_draft(batch.plan_bytes, batch.csv_bytes)
        indexes = tuple(row[0] for row in _approved_tuples(draft))
        cap = draft.plan["execution_limits"]["max_send_attempts"]
    except (BatchValidationError, KeyError, TypeError, ValueError) as error:
        raise _blocked("signed Plan/CSV invalid", "BLOCKED_OWNER_AUTHN") from error
    approved = batch.approved_row_indexes
    if (type(approved) is not tuple or approved != indexes or not indexes
            or list(indexes) != sorted(set(indexes))
            or len(batch.approved_rows) != len(indexes)):
        raise _blocked("approved row indexes do not match signed tuples", "BLOCKED_OWNER_AUTHN")
    nonce = batch.payload.get("batch_nonce")
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise _blocked("signed batch nonce malformed", "BLOCKED_OWNER_AUTHN")
    if type(cap) is not int or not 1 <= cap <= 20:
        raise _blocked("signed max_send_attempts invalid", "BLOCKED_OWNER_AUTHN")
    return indexes, cap


def read_batch_snapshot(ledger: object, batch, *, signed_cap: int, row_count: int):
    """Read the existing Ledger state and accept only real UNREGISTERED/ACTIVE shapes."""
    from name_tag_ledger import BatchExecutionState
    from name_tag_ledger_errors import LedgerError

    try:
        snapshot = ledger.batch_execution_state(batch)  # type: ignore[attr-defined]
    except LedgerError as error:
        raise HostRuntimeBlocked(error.code, "Ledger refused the batch state") from error
    except Exception as error:  # noqa: BLE001 - unknown Ledger failure is never first-run
        raise _blocked("Ledger state unreadable", "BLOCKED_SCOPE_STATE_UNKNOWN") from error
    if (type(snapshot) is not BatchExecutionState
            or type(snapshot.send_attempts_consumed) is not int
            or type(snapshot.max_send_attempts) is not int
            or type(snapshot.outcomes) is not tuple
            or snapshot.max_send_attempts != signed_cap
            or len(snapshot.outcomes) != row_count
            or not 0 <= snapshot.send_attempts_consumed <= signed_cap):
        raise _blocked("Ledger state inconsistent with signed batch", "BLOCKED_SCOPE_STATE_UNKNOWN")
    if snapshot.state in ("STOPPED", "COMPLETED"):
        raise _blocked("batch already stopped/completed", "BLOCKED_AUTH_REPLAY")
    if snapshot.state == "UNREGISTERED":
        if (snapshot.send_attempts_consumed != 0
                or any(outcome != "UNCLAIMED" for outcome in snapshot.outcomes)):
            raise _blocked("fabricated UNREGISTERED state", "BLOCKED_SCOPE_STATE_UNKNOWN")
        return snapshot
    if snapshot.state != "ACTIVE":
        raise _blocked("unknown batch state", "BLOCKED_SCOPE_STATE_UNKNOWN")
    if any(o != "UNCLAIMED" and o not in _TERMINAL_ROW_OUTCOMES for o in snapshot.outcomes):
        raise _blocked("unresolved Intent/Permit/outcome in batch", "BLOCKED_INCOMPLETE_INTENT")
    if snapshot.send_attempts_consumed != sum(
            o in _SEND_CONSUMING_TERMINALS for o in snapshot.outcomes):
        raise _blocked("send counter inconsistent with durable rows", "BLOCKED_SCOPE_STATE_UNKNOWN")
    return snapshot


def _select_position(snapshot) -> int:
    for position, outcome in enumerate(snapshot.outcomes):
        if outcome == "UNCLAIMED":
            if snapshot.send_attempts_consumed >= snapshot.max_send_attempts:
                raise HostRuntimeBlocked("SIGNED_CAP_REACHED",
                                         "cap exhausted: only NOT_ATTEMPTED_CAP handling")
            return position
        if outcome not in _TERMINAL_ROW_OUTCOMES:
            raise _blocked("earlier row unresolved", "BLOCKED_INCOMPLETE_INTENT")
    raise _blocked("no eligible approved row", "BLOCKED_AUTH_REPLAY")


def select_next_sts_subset(batch, *, ledger, kind_registry: Mapping[str, object],
                           host: VerifiedHostContext, now_utc: datetime):
    """RG-PRC-005: the lowest approved UNCLAIMED singleton, or fail before STS/Intent."""
    import name_tag_kind_capabilities as caps
    import name_tag_kind_name_evidence as name_evidence
    from name_tag_batch_iam import (
        IAMPolicyBlocked, SessionPolicySpec, build_subset_session_policy, verified_kind_policy)

    host = require_verified_host(host)
    now = require_aware_utc(now_utc)
    if ledger is not bound_ledger(host):
        raise _blocked("Ledger is not the Host-bound Ledger", "BLOCKED_SCOPE_STATE_UNKNOWN")
    fresh = _current_owner_batch(batch, now)
    indexes, cap = _signed_shape(fresh)
    journal = bound_journal(host)
    journal.scan()  # read-only reconciliation before every selection
    snapshot = read_batch_snapshot(ledger, fresh, signed_cap=cap, row_count=len(indexes))
    position = _select_position(snapshot)
    row_index = indexes[position]
    for scope_id in sorted({row["writer_control_scope_id"] for row in fresh.approved_rows}):
        try:
            scope_state = ledger.effective_scope_state(scope_id)
        except Exception as error:  # noqa: BLE001
            raise _blocked("Scope state unreadable", "BLOCKED_SCOPE_STATE_UNKNOWN") from error
        if scope_state != "CLEARED":
            raise _blocked(f"signed Scope not CLEARED: {scope_id}", "BLOCKED_SCOPE_HOLD")
    journal.assert_row_unattempted(fresh.batch_id, row_index)
    authority = _current_row_authority(fresh, row_index, now)
    row = authority.row
    if authority.row_index != row_index or authority.batch.batch_id != fresh.batch_id:
        raise _blocked("row authority mismatch", "BLOCKED_OWNER_AUTHN")
    try:
        capability = caps.resolve_kind_capability(row["kind"])
        if kind_registry.get(row["kind"]) != verified_kind_policy(capability):
            raise IAMPolicyBlocked("unvetted Kind policy")
        target = caps.canonical_target_identity(
            kind=row["kind"], locator=row["locator"], resource_arn=row["resource_arn"],
            partition=fresh.payload["partition"], account=fresh.payload["account"],
            scope_region=row["region"])
        evidence = name_evidence.verified_generated_name(row, target)
        spec = build_subset_session_policy(fresh, (row_index,), kind_registry=kind_registry)
    except (IAMPolicyBlocked, ValueError, KeyError, TypeError) as error:
        raise _blocked("Kind/policy/Name evidence not proven", "AWS_WRITE_BLOCKED") from error
    if (type(spec) is not SessionPolicySpec or spec.row_indexes != (row_index,)
            or spec.batch_id != fresh.batch_id
            or sha256(spec.policy_bytes).hexdigest() != spec.policy_sha256
            or evidence.generated_name != row.get("approved_name")
            or row.get("aws_operation") != capability.write_operation):
        raise _blocked("selected policy is not the exact singleton", "AWS_WRITE_BLOCKED")
    _SELECTIONS[id(spec)] = HostSelection(
        host=host, batch=fresh, spec=spec, row_authority=authority, snapshot=snapshot,
        signed_cap=cap, scope_id=row["writer_control_scope_id"], capability=capability,
        target=target, name_evidence_sha256=evidence.evidence_digest, selected_at_utc=now)
    return spec


# ---------------------------------------------------------------- protected command endpoint
class HostBatchCoordinator(Protocol):
    """Task 7: the existing single name_tag_batch_runtime Coordinator over the Host Ledger."""

    def run_signed_batch(self, batch, *, host: VerifiedHostContext, issuer: object,
                         now_utc: datetime): ...


class ProtectedHostCommandEndpoint(Protocol):
    def execute_signed_batch(self, *, plan_bytes: bytes, csv_bytes: bytes,
                             owner_envelope_bytes: bytes, host: VerifiedHostContext): ...


class ProtectedBatchHostEndpoint:
    """Host-only endpoint entered after formal IPC acceptance (Task 6B server calls it).

    Re-verifies the Host context and the exact signed Plan/CSV/Owner envelope against the
    current protected OwnerTrust, then delegates to the single Coordinator. Without a
    protected Host issuer and Coordinator it refuses with AWS_RUNTIME_NOT_AUTHORIZED.
    Raises HostRuntimeBlocked(code) for every refusal; it never returns a fabricated result.
    """

    def __init__(self, *, issuer: object = None, coordinator: HostBatchCoordinator | None = None,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> None:
        self._issuer = issuer
        self._coordinator = coordinator
        self._clock = clock

    def execute_signed_batch(self, *, plan_bytes: bytes, csv_bytes: bytes,
                             owner_envelope_bytes: bytes, host: VerifiedHostContext):
        import name_tag_batch_approval as approval
        from name_tag_batch_host_issuer import HostBatchCredentialIssuer

        host = require_verified_host(host)
        if any(type(v) is not bytes or not v for v in (plan_bytes, csv_bytes, owner_envelope_bytes)):
            raise _blocked("signed inputs must be non-empty exact bytes", "BLOCKED_OWNER_AUTHN")
        if type(self._issuer) is not HostBatchCredentialIssuer or self._coordinator is None:
            raise _blocked("no protected Host issuer/Coordinator is wired")
        now = require_aware_utc(self._clock())
        try:
            batch = approval.verify_batch_approval(
                plan_bytes, csv_bytes, owner_envelope_bytes,
                trust=load_current_protected_owner_trust(), now_utc=now)
        except (approval.BatchAuthRejected, OSError, ValueError, TypeError) as error:
            raise _blocked("Owner verification failed", "BLOCKED_OWNER_AUTHN") from error
        return self._coordinator.run_signed_batch(batch, host=host, issuer=self._issuer,
                                                  now_utc=now)


def production_host_endpoint() -> ProtectedBatchHostEndpoint:
    """Production wiring in this phase: no protected issuer/Coordinator -> fail closed."""
    return ProtectedBatchHostEndpoint()
