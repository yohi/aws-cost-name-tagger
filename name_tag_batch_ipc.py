"""Strict AWS-CNT-BATCH-IPC/1 codec, wire types and client (Design §5.2.1).

Shared by the Host listener (``name_tag_batch_host_server``) and the untrusted CLI client.
Pure framing: no AWS/STS/SDK/Ledger/OwnerTrust import. Streams are duck-typed objects with
``recv(n)``/``settimeout(seconds)``/``sendall(data)`` (a real socket or a test Fake); all
deadlines use an injected monotonic clock.

Wire: exactly one ``uint32_be(length)`` + strict UTF-8 JSON object per direction. Request
length 1..64 MiB (checked before any allocation; the body is read in bounded chunks), response
1..64 KiB. After the declared request body the Host reads at most one more byte and requires
zero-byte EOF (client half-close), all within the cumulative 30 s body deadline.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Protocol

PROTOCOL_NAME: Final = "AWS-CNT-BATCH-IPC/1"
PROTOCOL_VERSION: Final = 1
COMMAND: Final = "execute_signed_batch"
HOST_SOCKET_PATH: Final = "/run/aws-cnt/host.sock"
ZERO_REQUEST_ID: Final = "0" * 32

MAX_REQUEST_BYTES: Final = 64 * 1024 * 1024
MAX_RESPONSE_BYTES: Final = 64 * 1024
MAX_PLAN_BYTES: Final = 32 * 1024 * 1024
MAX_CSV_BYTES: Final = 12 * 1024 * 1024
MAX_ENVELOPE_BYTES: Final = 256 * 1024
READ_CHUNK: Final = 64 * 1024

HEADER_DEADLINE_S: Final = 5.0
BODY_EOF_DEADLINE_S: Final = 30.0
RESPONSE_WRITE_DEADLINE_S: Final = 5.0
CLIENT_CONNECT_DEADLINE_S: Final = 3.0
CLIENT_RESPONSE_DEADLINE_S: Final = 120.0

IPC_INVALID_FRAME: Final = "IPC_INVALID_FRAME"
IPC_UNSUPPORTED_VERSION: Final = "IPC_UNSUPPORTED_VERSION"
IPC_REQUEST_TOO_LARGE: Final = "IPC_REQUEST_TOO_LARGE"
IPC_BAD_PAYLOAD: Final = "IPC_BAD_PAYLOAD"
IPC_TIMEOUT: Final = "IPC_TIMEOUT"
IPC_PEER_REJECTED: Final = "IPC_PEER_REJECTED"
IPC_BUSY: Final = "IPC_BUSY"
IPC_ERROR_CODES: Final = frozenset({
    IPC_INVALID_FRAME, IPC_UNSUPPORTED_VERSION, IPC_REQUEST_TOO_LARGE, IPC_BAD_PAYLOAD,
    IPC_TIMEOUT, IPC_PEER_REJECTED, IPC_BUSY})
# Client-local transport classifications (never sent by the Host).
IPC_SOCKET_UNAVAILABLE: Final = "IPC_SOCKET_UNAVAILABLE"
IPC_RESPONSE_LOST: Final = "IPC_RESPONSE_LOST"
IPC_RESPONSE_INVALID: Final = "IPC_RESPONSE_INVALID"

STATUSES: Final = frozenset({"COMPLETE", "BLOCKED", "UNKNOWN"})
_REQUEST_FIELDS: Final = frozenset({
    "protocol_version", "command", "request_id", "plan_b64", "review_csv_b64",
    "owner_envelope_b64"})
_RESPONSE_FIELDS: Final = frozenset({
    "protocol_version", "request_id", "status", "code", "batch_id", "report_sha256"})
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


class IPCError(Exception):
    """Pre-dispatch protocol failure; ``code`` is one of IPC_ERROR_CODES."""

    def __init__(self, code: str, detail: str = "", *, request_id: str | None = None) -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.request_id = request_id if request_id and _HEX32.fullmatch(request_id) else None


@dataclass(frozen=True)
class HostIPCRequest:
    protocol_version: int
    request_id: str
    plan_bytes: bytes
    csv_bytes: bytes
    owner_envelope_bytes: bytes


@dataclass(frozen=True)
class HostIPCResponse:
    protocol_version: int
    request_id: str
    status: str
    code: str
    batch_id: str | None
    report_sha256: str | None


class BatchHostIPCCodec(Protocol):
    def read_request(self, stream: object) -> HostIPCRequest: ...
    def write_response(self, stream: object, response: HostIPCResponse) -> None: ...


class UnixBatchHostClientProtocol(Protocol):
    def execute(self, *, plan_bytes: bytes, csv_bytes: bytes,
                owner_envelope_bytes: bytes, request_id: str) -> HostIPCResponse: ...


class Deadline:
    """Monotonic deadline; ``remaining`` raises IPC_TIMEOUT once it has passed."""

    def __init__(self, clock: Callable[[], float], seconds: float) -> None:
        self._clock = clock
        self._end = clock() + seconds

    def expired(self) -> bool:
        return self._clock() >= self._end

    def remaining(self) -> float:
        left = self._end - self._clock()
        if left <= 0:
            raise IPCError(IPC_TIMEOUT, "deadline reached")
        return left


def _recv(stream: object, size: int, deadline: Deadline) -> bytes:
    stream.settimeout(deadline.remaining())
    try:
        data = stream.recv(size)
    except TimeoutError as error:
        raise IPCError(IPC_TIMEOUT, "read timed out") from error
    if type(data) is not bytes or len(data) > size:
        raise IPCError(IPC_INVALID_FRAME, "stream returned invalid data")
    if deadline.expired():
        raise IPCError(IPC_TIMEOUT, "deadline reached")
    return data


def _read_exact(stream: object, count: int, deadline: Deadline) -> bytes:
    """Read exactly ``count`` bytes in bounded chunks (never allocates ``count`` up front)."""
    out = bytearray()
    while len(out) < count:
        chunk = _recv(stream, min(READ_CHUNK, count - len(out)), deadline)
        if not chunk:
            raise IPCError(IPC_INVALID_FRAME, "truncated frame")
        out += chunk
    return bytes(out)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(name: str):
    raise ValueError(f"non-finite JSON constant {name}")


def _strict_object(body: bytes) -> dict:
    try:
        text = body.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_no_duplicates,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise IPCError(IPC_BAD_PAYLOAD, "body is not one strict JSON object") from error
    if type(value) is not dict:
        raise IPCError(IPC_BAD_PAYLOAD, "body must be a JSON object")
    return value


def _decode_b64(value: object, limit: int, what: str, request_id: str | None) -> bytes:
    if type(value) is not str or not value or not value.isascii():
        raise IPCError(IPC_BAD_PAYLOAD, f"{what} must be non-empty ASCII base64",
                       request_id=request_id)
    if len(value) > 4 * ((limit + 2) // 3):
        raise IPCError(IPC_REQUEST_TOO_LARGE, f"{what} too large", request_id=request_id)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as error:
        raise IPCError(IPC_BAD_PAYLOAD, f"{what} is not valid base64",
                       request_id=request_id) from error
    if not raw or base64.b64encode(raw).decode("ascii") != value:
        raise IPCError(IPC_BAD_PAYLOAD, f"{what} is not canonical padded base64",
                       request_id=request_id)
    if len(raw) > limit:
        raise IPCError(IPC_REQUEST_TOO_LARGE, f"{what} too large", request_id=request_id)
    return raw


def _frame(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                      allow_nan=False, sort_keys=False).encode("ascii")


def validate_response(response: object) -> HostIPCResponse:
    if type(response) is not HostIPCResponse:
        raise IPCError(IPC_BAD_PAYLOAD, "response must be HostIPCResponse")
    ok = (response.protocol_version == PROTOCOL_VERSION
          and type(response.protocol_version) is int
          and type(response.request_id) is str and _HEX32.fullmatch(response.request_id)
          and response.status in STATUSES
          and type(response.code) is str and _CODE.fullmatch(response.code)
          and (response.batch_id is None
               or (type(response.batch_id) is str and _HEX64.fullmatch(response.batch_id)))
          and (response.report_sha256 is None
               or (type(response.report_sha256) is str
                   and _HEX64.fullmatch(response.report_sha256))))
    if not ok:
        raise IPCError(IPC_BAD_PAYLOAD, "response fields invalid")
    return response


class StrictBatchHostIPCCodec:
    """The only IPC v1 encoder/decoder, used by both Host and client."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock

    # ---- request (Host side read, client side encode)
    def read_request(self, stream: object) -> HostIPCRequest:
        header = _read_exact(stream, 4, Deadline(self._clock, HEADER_DEADLINE_S))
        length = int.from_bytes(header, "big")
        if length > MAX_REQUEST_BYTES:
            raise IPCError(IPC_REQUEST_TOO_LARGE, "declared length exceeds 64 MiB")
        if length < 1:
            raise IPCError(IPC_INVALID_FRAME, "empty frame")
        deadline = Deadline(self._clock, BODY_EOF_DEADLINE_S)
        body = _read_exact(stream, length, deadline)
        if _recv(stream, 1, deadline):  # at most one byte beyond the declared body
            raise IPCError(IPC_INVALID_FRAME, "trailing bytes or second frame")
        return self.decode_request_body(body)

    def decode_request_body(self, body: bytes) -> HostIPCRequest:
        obj = _strict_object(body)
        rid = obj.get("request_id") if type(obj.get("request_id")) is str else None
        if set(obj) != _REQUEST_FIELDS:
            raise IPCError(IPC_BAD_PAYLOAD, "request must have exactly six fields",
                           request_id=rid)
        version = obj["protocol_version"]
        if type(version) is not int:
            raise IPCError(IPC_BAD_PAYLOAD, "protocol_version must be an integer",
                           request_id=rid)
        if version != PROTOCOL_VERSION:
            raise IPCError(IPC_UNSUPPORTED_VERSION, "unsupported protocol_version",
                           request_id=rid)
        if obj["command"] != COMMAND:
            raise IPCError(IPC_BAD_PAYLOAD, "unsupported command", request_id=rid)
        if type(rid) is not str or _HEX32.fullmatch(rid) is None:
            raise IPCError(IPC_BAD_PAYLOAD, "request_id must be 32 lowercase hex")
        return HostIPCRequest(
            PROTOCOL_VERSION, rid,
            _decode_b64(obj["plan_b64"], MAX_PLAN_BYTES, "plan_b64", rid),
            _decode_b64(obj["review_csv_b64"], MAX_CSV_BYTES, "review_csv_b64", rid),
            _decode_b64(obj["owner_envelope_b64"], MAX_ENVELOPE_BYTES,
                        "owner_envelope_b64", rid))

    def encode_request(self, *, plan_bytes: bytes, csv_bytes: bytes,
                       owner_envelope_bytes: bytes, request_id: str) -> bytes:
        if type(request_id) is not str or _HEX32.fullmatch(request_id) is None:
            raise IPCError(IPC_BAD_PAYLOAD, "request_id must be 32 lowercase hex")
        fields = ((plan_bytes, MAX_PLAN_BYTES), (csv_bytes, MAX_CSV_BYTES),
                  (owner_envelope_bytes, MAX_ENVELOPE_BYTES))
        for raw, limit in fields:
            if type(raw) is not bytes or not raw:
                raise IPCError(IPC_BAD_PAYLOAD, "inputs must be non-empty bytes")
            if len(raw) > limit:
                raise IPCError(IPC_REQUEST_TOO_LARGE, "input exceeds its size bound")
        b64 = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
        payload = _canonical_json({
            "protocol_version": PROTOCOL_VERSION, "command": COMMAND, "request_id": request_id,
            "plan_b64": b64(plan_bytes), "review_csv_b64": b64(csv_bytes),
            "owner_envelope_b64": b64(owner_envelope_bytes)})
        if len(payload) > MAX_REQUEST_BYTES:
            raise IPCError(IPC_REQUEST_TOO_LARGE, "request exceeds 64 MiB")
        return _frame(payload)

    # ---- response (Host side write, client side read)
    def encode_response(self, response: HostIPCResponse) -> bytes:
        validate_response(response)
        payload = _canonical_json({
            "protocol_version": response.protocol_version, "request_id": response.request_id,
            "status": response.status, "code": response.code,
            "batch_id": response.batch_id, "report_sha256": response.report_sha256})
        if not 1 <= len(payload) <= MAX_RESPONSE_BYTES:
            raise IPCError(IPC_BAD_PAYLOAD, "response size out of bounds")
        return _frame(payload)

    def write_response(self, stream: object, response: HostIPCResponse) -> None:
        data = self.encode_response(response)
        deadline = Deadline(self._clock, RESPONSE_WRITE_DEADLINE_S)
        stream.settimeout(deadline.remaining())
        try:
            stream.sendall(data)
        except TimeoutError as error:
            raise IPCError(IPC_TIMEOUT, "response write timed out") from error
        if deadline.expired():
            raise IPCError(IPC_TIMEOUT, "response write deadline reached")

    def read_response(self, stream: object, deadline: Deadline) -> HostIPCResponse:
        header = _read_exact(stream, 4, deadline)
        length = int.from_bytes(header, "big")
        if not 1 <= length <= MAX_RESPONSE_BYTES:
            raise IPCError(IPC_INVALID_FRAME, "response length out of bounds")
        obj = _strict_object(_read_exact(stream, length, deadline))
        if set(obj) != _RESPONSE_FIELDS:
            raise IPCError(IPC_BAD_PAYLOAD, "response must have exactly six fields")
        return validate_response(HostIPCResponse(
            obj["protocol_version"], obj["request_id"], obj["status"], obj["code"],
            obj["batch_id"], obj["report_sha256"]))


def _connect_unix(path: str, timeout: float):  # pragma: no cover - real OS only
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect(path)
    except BaseException:
        sock.close()
        raise
    return sock


class UnixBatchHostClient:
    """Untrusted local client: one connection, one frame, one reply, never retries."""

    def __init__(self, *, connector: Callable[[str, float], object] = _connect_unix,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._connector = connector
        self._clock = clock
        self._codec = StrictBatchHostIPCCodec(clock=clock)

    def _local(self, request_id: str, status: str, code: str) -> HostIPCResponse:
        return HostIPCResponse(PROTOCOL_VERSION, request_id, status, code, None, None)

    def execute(self, *, plan_bytes: bytes, csv_bytes: bytes,
                owner_envelope_bytes: bytes, request_id: str) -> HostIPCResponse:
        frame = self._codec.encode_request(
            plan_bytes=plan_bytes, csv_bytes=csv_bytes,
            owner_envelope_bytes=owner_envelope_bytes, request_id=request_id)
        connect_deadline = Deadline(self._clock, CLIENT_CONNECT_DEADLINE_S)
        try:
            sock = self._connector(HOST_SOCKET_PATH, CLIENT_CONNECT_DEADLINE_S)
        except TimeoutError:
            return self._local(request_id, "UNKNOWN", IPC_TIMEOUT)
        except OSError:
            return self._local(request_id, "BLOCKED", IPC_SOCKET_UNAVAILABLE)
        try:
            if connect_deadline.expired():
                return self._local(request_id, "UNKNOWN", IPC_TIMEOUT)
            deadline = Deadline(self._clock, CLIENT_RESPONSE_DEADLINE_S)
            try:
                sock.settimeout(deadline.remaining())
                sock.sendall(frame)
                sock.shutdown(socket.SHUT_WR)  # half-close; the read half stays open
                response = self._codec.read_response(sock, deadline)
            except IPCError as error:
                code = IPC_TIMEOUT if error.code == IPC_TIMEOUT else IPC_RESPONSE_LOST
                return self._local(request_id, "UNKNOWN", code)
            except OSError:
                return self._local(request_id, "UNKNOWN", IPC_RESPONSE_LOST)
            pre_decode_error = (response.request_id == ZERO_REQUEST_ID
                                and response.status == "BLOCKED"
                                and response.code in IPC_ERROR_CODES)
            if response.request_id != request_id and not pre_decode_error:
                return self._local(request_id, "UNKNOWN", IPC_RESPONSE_INVALID)
            return response if not pre_decode_error else HostIPCResponse(
                PROTOCOL_VERSION, request_id, "BLOCKED", response.code, None, None)
        finally:
            try:
                sock.close()
            except OSError:
                pass
