"""Host-owned AF_UNIX protected command server (Design §5.2.1).

The only Host listener. ``aws-cnt-batch.service`` verifies its protected bootstrap, then THIS
process binds ``/run/aws-cnt/host.sock`` itself; systemd socket activation (``LISTEN_FDS``)
is never adopted and its presence blocks startup. All OS interaction (stat/chown/chmod, socket
creation, ``SO_PEERCRED``) goes through an injected ``ListenerOS`` facade; the production
default is unavailable and fails closed (``AWS_RUNTIME_NOT_AUTHORIZED``) until a separately
Owner-authorized Host acceptance. Offline tests use Fakes only.

Per connection: peer admission -> strict frame/EOF/JSON/Base64 decode (``name_tag_batch_ipc``)
-> single-active-Batch slot -> internal ``IPC_REQUEST_ACCEPTED`` -> bootstrap re-verification ->
``ProtectedHostCommandEndpoint.execute_signed_batch`` (Owner re-verification and the single
Coordinator/Ledger live behind it) -> a *best effort* bounded response. After acceptance a
vanished client or failed response write never cancels or rewrites the command. ``SO_PEERCRED``
is local peer filtering only and ``request_id`` is correlation only.
"""
from __future__ import annotations

import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, Protocol

from name_tag_batch_host_runtime import (
    AWS_RUNTIME_NOT_AUTHORIZED, HostBootstrapVerifier, HostRuntimeBlocked,
    ProtectedHostCommandEndpoint, require_verified_host)
from name_tag_batch_ipc import (
    HOST_SOCKET_PATH, IPC_BUSY, IPC_PEER_REJECTED, PROTOCOL_VERSION, ZERO_REQUEST_ID,
    BatchHostIPCCodec, HostIPCRequest, HostIPCResponse, IPCError, StrictBatchHostIPCCodec)

SOCKET_PATH: Final = HOST_SOCKET_PATH
RUNTIME_DIRECTORY: Final = SOCKET_PATH.rsplit("/", 1)[0]
IPC_GROUP: Final = "aws-cnt-ipc"
RUNTIME_DIR_MODE: Final = 0o750
SOCKET_MODE: Final = 0o660
LISTEN_BACKLOG: Final = 8
MAX_CONNECTIONS: Final = 8
IPC_LISTENER_BLOCKED: Final = "IPC_LISTENER_BLOCKED"
IPC_REQUEST_ACCEPTED: Final = "IPC_REQUEST_ACCEPTED"  # internal control-flow marker only
HOST_COMMAND_UNKNOWN: Final = "HOST_COMMAND_UNKNOWN"
_ACTIVATION_ENV: Final = ("LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


def _listener_blocked(detail: str) -> HostRuntimeBlocked:
    return HostRuntimeBlocked(IPC_LISTENER_BLOCKED, detail)


# ---------------------------------------------------------------- injected OS facade
@dataclass(frozen=True)
class PathFacts:
    kind: str  # "dir" | "socket" | "symlink" | "file" | "other" (never follows symlinks)
    uid: int
    gid: int
    mode: int
    inode: int
    device: int


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class PeerPolicy:
    """Configured local operator admission. Empty policy admits nobody (fail closed)."""

    allowed_uids: frozenset[int]
    allowed_gids: frozenset[int]

    def admits(self, creds: PeerCredentials) -> bool:
        if type(creds) is not PeerCredentials or creds.pid <= 0:
            return False
        return creds.uid in self.allowed_uids or creds.gid in self.allowed_gids


class ListenerSocket(Protocol):
    def bind(self, path: str) -> None: ...
    def getsockname(self) -> str: ...
    def listen(self, backlog: int) -> None: ...
    def accept(self) -> tuple[object, object]: ...
    def close(self) -> None: ...


class ListenerOS(Protocol):
    def getenv(self, name: str) -> str | None: ...
    def process_ids(self) -> tuple[int, int]: ...
    def lookup_group(self, name: str) -> int | None: ...
    def lstat(self, path: str) -> PathFacts | None: ...
    def chown(self, path: str, uid: int, gid: int) -> None: ...
    def chmod(self, path: str, mode: int) -> None: ...
    def new_listener(self) -> ListenerSocket: ...  # AF_UNIX / SOCK_STREAM, created by us
    def peer_credentials(self, conn: object) -> PeerCredentials: ...  # SO_PEERCRED


class UnavailableListenerOS:
    """Production default in this phase: every OS interaction fails closed."""

    def _no(self, *_args, **_kwargs):
        raise HostRuntimeBlocked(AWS_RUNTIME_NOT_AUTHORIZED,
                                 "Host listener OS facade is not available (Owner HOLD)")

    getenv = process_ids = lookup_group = lstat = chown = chmod = _no
    new_listener = peer_credentials = _no


# ---------------------------------------------------------------- response mapping
def _hex64_or_none(value: object) -> str | None:
    return value if type(value) is str and _HEX64.fullmatch(value) else None


def _identity(batch_id: object, report_sha256: object) -> tuple[str | None, str | None]:
    batch = _hex64_or_none(batch_id)
    return batch, (_hex64_or_none(report_sha256) if batch is not None else None)


def _report_identity(result: object) -> tuple[str | None, str | None]:
    report = getattr(result, "report", None)
    if not isinstance(report, Mapping):
        return None, None
    return _identity(report.get("batch_id"), report.get("report_sha256"))


def map_endpoint_result(request_id: str, result: object) -> HostIPCResponse:
    """Map a returned BatchRunResult to the six-field response (RG-PRC-008)."""
    batch_id, report = _report_identity(result)
    outcomes = getattr(result, "outcomes", ())
    if "OUTCOME_UNKNOWN" in tuple(outcomes):
        status, code = "UNKNOWN", "OUTCOME_UNKNOWN"
    elif getattr(result, "batch_state", None) == "STOPPED":
        status, code = "BLOCKED", "BATCH_STOPPED"
    elif report is not None:
        status, code = "COMPLETE", "COMPLETE"
    else:
        status, code = "UNKNOWN", "REPORT_NOT_VERIFIED"
    return HostIPCResponse(PROTOCOL_VERSION, request_id, status, code, batch_id, report)


def map_blocked(request_id: str, blocked: HostRuntimeBlocked) -> HostIPCResponse:
    code = getattr(blocked, "code", None)
    if type(code) is not str or _CODE.fullmatch(code) is None:
        code = AWS_RUNTIME_NOT_AUTHORIZED
    batch_id, report = _identity(getattr(blocked, "batch_id", None),
                                 getattr(blocked, "report_sha256", None))
    return HostIPCResponse(PROTOCOL_VERSION, request_id, "BLOCKED", code, batch_id, report)


def _pre_accept(request_id: str | None, code: str) -> HostIPCResponse:
    return HostIPCResponse(PROTOCOL_VERSION, request_id or ZERO_REQUEST_ID, "BLOCKED",
                           code, None, None)


# ---------------------------------------------------------------- server
def _thread_spawn(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, daemon=True).start()


class ProtectedHostIPCServer:
    """The only Host listener and decoder dispatch; one serial active Batch."""

    def __init__(self, *, os_facade: ListenerOS, peer_policy: PeerPolicy,
                 codec: BatchHostIPCCodec | None = None,
                 clock_utc: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 spawn: Callable[[Callable[[], None]], None] = _thread_spawn,
                 trace: Callable[[str], None] | None = None,
                 host_check: Callable[[object], object] = require_verified_host,
                 max_connections: int = MAX_CONNECTIONS) -> None:
        self._os = os_facade
        self._policy = peer_policy
        self._codec = codec if codec is not None else StrictBatchHostIPCCodec()
        self._clock_utc = clock_utc
        self._spawn = spawn
        self._trace = trace or (lambda _event: None)
        self._host_check = host_check
        self._max_connections = max_connections
        self._guard = threading.Lock()
        self._batch_slot = threading.Lock()
        self._connections = 0
        self.response_write_failures = 0

    # ---- startup
    def _verify_directory(self, uid: int, ipc_gid: int) -> None:
        facts = self._os.lstat(RUNTIME_DIRECTORY)
        if facts is None or facts.kind != "dir":
            raise _listener_blocked("runtime directory is missing or not a real directory")
        if facts.uid != uid or facts.mode & 0o022:
            raise _listener_blocked("runtime directory owner or write bits are wrong")
        self._os.chown(RUNTIME_DIRECTORY, uid, ipc_gid)
        self._os.chmod(RUNTIME_DIRECTORY, RUNTIME_DIR_MODE)
        facts = self._os.lstat(RUNTIME_DIRECTORY)
        if (facts is None or facts.kind != "dir" or facts.uid != uid or facts.gid != ipc_gid
                or facts.mode & 0o7777 != RUNTIME_DIR_MODE):
            raise _listener_blocked("runtime directory ownership/mode did not verify")

    def _bind_listener(self, uid: int, ipc_gid: int) -> ListenerSocket:
        if self._os.lstat(SOCKET_PATH) is not None:
            raise _listener_blocked("socket path already exists; never unlinked or reused")
        listener = self._os.new_listener()
        try:
            listener.bind(SOCKET_PATH)
            if listener.getsockname() != SOCKET_PATH:
                raise _listener_blocked("listener is not bound to the literal socket path")
            self._os.chown(SOCKET_PATH, uid, ipc_gid)
            self._os.chmod(SOCKET_PATH, SOCKET_MODE)
            before = self._os.lstat(SOCKET_PATH)
            self._check_socket(before, uid, ipc_gid)
            listener.listen(LISTEN_BACKLOG)
            after = self._os.lstat(SOCKET_PATH)
            self._check_socket(after, uid, ipc_gid)
            if (after.inode, after.device) != (before.inode, before.device):
                raise _listener_blocked("socket inode changed after listen")
        except BaseException:
            listener.close()
            raise
        return listener

    @staticmethod
    def _check_socket(facts: PathFacts | None, uid: int, ipc_gid: int) -> None:
        if (facts is None or facts.kind != "socket" or facts.uid != uid
                or facts.gid != ipc_gid or facts.mode & 0o7777 != SOCKET_MODE):
            raise _listener_blocked("socket type/owner/mode did not verify")

    def open_listener(self, bootstrap: HostBootstrapVerifier) -> ListenerSocket:
        for name in _ACTIVATION_ENV:
            if self._os.getenv(name) is not None:
                raise _listener_blocked("systemd socket activation is not supported")
        host = self._host_check(bootstrap.verify_process(now_utc=self._clock_utc()))
        uid, _gid = self._os.process_ids()
        if uid != host.service_uid:
            raise _listener_blocked("process uid is not the verified service uid")
        ipc_gid = self._os.lookup_group(IPC_GROUP)
        if ipc_gid is None:
            raise _listener_blocked("aws-cnt-ipc group is not provisioned")
        self._verify_directory(uid, ipc_gid)
        return self._bind_listener(uid, ipc_gid)

    def serve(self, *, bootstrap: HostBootstrapVerifier,
              endpoint: ProtectedHostCommandEndpoint) -> None:
        listener = self.open_listener(bootstrap)
        try:
            while True:
                try:
                    conn, _addr = listener.accept()
                except OSError:
                    return  # listener closed/failed: stop serving, never rebind
                self._spawn(lambda c=conn: self.handle_connection(
                    c, bootstrap=bootstrap, endpoint=endpoint))
        finally:
            listener.close()

    # ---- per connection
    def _send(self, conn: object, response: HostIPCResponse) -> None:
        try:
            self._codec.write_response(conn, response)
        except Exception:  # noqa: BLE001 - a lost reply never changes Host state
            with self._guard:
                self.response_write_failures += 1

    def _slot(self) -> bool:
        with self._guard:
            if self._connections >= self._max_connections:
                return False
            self._connections += 1
            return True

    def handle_connection(self, conn: object, *, bootstrap: HostBootstrapVerifier,
                          endpoint: ProtectedHostCommandEndpoint) -> None:
        try:
            if not self._slot():
                self._send(conn, _pre_accept(None, IPC_BUSY))
                return
            try:
                self._serve_connection(conn, bootstrap, endpoint)
            finally:
                with self._guard:
                    self._connections -= 1
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def _serve_connection(self, conn: object, bootstrap, endpoint) -> None:
        try:
            admitted = self._policy.admits(self._os.peer_credentials(conn))
        except Exception:  # noqa: BLE001 - unreadable credentials are a rejection
            admitted = False
        if not admitted:
            self._send(conn, _pre_accept(None, IPC_PEER_REJECTED))
            return
        try:
            request = self._codec.read_request(conn)
        except IPCError as error:
            self._send(conn, _pre_accept(error.request_id, error.code))
            return
        if not self._batch_slot.acquire(blocking=False):
            self._send(conn, _pre_accept(request.request_id, IPC_BUSY))
            return
        try:
            self._trace(IPC_REQUEST_ACCEPTED)
            response = self._run_accepted(request, bootstrap, endpoint)
        finally:
            self._batch_slot.release()
        self._send(conn, response)  # best effort; the command already ran to its outcome

    def _run_accepted(self, request: HostIPCRequest, bootstrap, endpoint) -> HostIPCResponse:
        try:
            host = self._host_check(bootstrap.verify_process(now_utc=self._clock_utc()))
            result = endpoint.execute_signed_batch(
                plan_bytes=request.plan_bytes, csv_bytes=request.csv_bytes,
                owner_envelope_bytes=request.owner_envelope_bytes, host=host)
        except HostRuntimeBlocked as blocked:
            return map_blocked(request.request_id, blocked)
        except Exception:  # noqa: BLE001 - never leak details; outcome is unverified
            return HostIPCResponse(PROTOCOL_VERSION, request.request_id, "UNKNOWN",
                                   HOST_COMMAND_UNKNOWN, None, None)
        return map_endpoint_result(request.request_id, result)


def production_ipc_server() -> ProtectedHostIPCServer:
    """Production wiring in this phase: unavailable OS facade, empty policy -> fail closed."""
    return ProtectedHostIPCServer(os_facade=UnavailableListenerOS(),
                                  peer_policy=PeerPolicy(frozenset(), frozenset()))
