"""Offline IPC v1 codec/client tests (Design §5.2.1). Fake streams and clocks only."""
from __future__ import annotations

import ast
import base64
import json
import socket
import struct
import unittest
from pathlib import Path
from unittest import mock

import name_tag_batch_ipc as ipc
from name_tag_batch_ipc import (
    HostIPCResponse, IPCError, StrictBatchHostIPCCodec, UnixBatchHostClient)

RID = "0123456789abcdef0123456789abcdef"
PLAN, CSV, ENV = b"\x00plan\xff bytes", b"\xef\xbb\xbfcsv,bytes\r\n", b"{\"env\": 1}\n "
H64 = "ab" * 32


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class FakeStream:
    """recv serves scripted chunks; then EOF (b""), TimeoutError, or a clock jump."""

    def __init__(self, data: bytes, clock: FakeClock, *, chunk: int = 7, at_end: str = "eof",
                 step: float = 0.0):
        self.data, self.clock, self.chunk, self.at_end, self.step = data, clock, chunk, at_end, step
        self.pos = 0
        self.sizes: list[int] = []
        self.timeouts: list[float] = []
        self.sent = b""
        self.shutdowns: list[int] = []

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def recv(self, size):
        self.sizes.append(size)
        self.clock.now += self.step
        if self.pos >= len(self.data):
            if self.at_end == "timeout":
                raise TimeoutError()
            if self.at_end == "hang":
                self.clock.now += 3600
            return b""
        out = self.data[self.pos:self.pos + min(size, self.chunk)]
        self.pos += len(out)
        return out

    def sendall(self, data):
        self.sent += data

    def shutdown(self, how):
        self.shutdowns.append(how)

    def close(self):
        pass


def request_frame(**overrides) -> bytes:
    codec = StrictBatchHostIPCCodec()
    return codec.encode_request(plan_bytes=PLAN, csv_bytes=CSV, owner_envelope_bytes=ENV,
                                request_id=RID)


def body_of(**changes) -> bytes:
    obj = {"protocol_version": 1, "command": "execute_signed_batch", "request_id": RID,
           "plan_b64": base64.b64encode(PLAN).decode(),
           "review_csv_b64": base64.b64encode(CSV).decode(),
           "owner_envelope_b64": base64.b64encode(ENV).decode()}
    for key, value in changes.items():
        if value is KeyError:
            obj.pop(key)
        else:
            obj[key] = value
    return json.dumps(obj, separators=(",", ":")).encode()


def framed(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


def read(data: bytes, **kw):
    clock = FakeClock()
    stream = FakeStream(data, clock, **kw)
    codec = StrictBatchHostIPCCodec(clock=clock)
    return codec.read_request(stream), stream


def code_of(data: bytes, **kw) -> str:
    try:
        read(data, **kw)
    except IPCError as error:
        return error.code
    raise AssertionError("expected IPCError")


class CodecTests(unittest.TestCase):
    def test_ipc_v1_frame_roundtrip_exact_original_bytes(self):
        request, stream = read(request_frame())
        self.assertEqual((request.protocol_version, request.request_id), (1, RID))
        self.assertEqual((request.plan_bytes, request.csv_bytes, request.owner_envelope_bytes),
                         (PLAN, CSV, ENV))
        frame = request_frame()
        self.assertEqual(int.from_bytes(frame[:4], "big"), len(frame) - 4)
        self.assertEqual(set(json.loads(frame[4:])), set(ipc._REQUEST_FIELDS))
        resp = HostIPCResponse(1, RID, "BLOCKED", "BLOCKED_OWNER_AUTHN", H64, H64)
        codec = StrictBatchHostIPCCodec()
        out = FakeStream(b"", FakeClock())
        codec.write_response(out, resp)
        clock = FakeClock()
        back = codec.read_response(FakeStream(out.sent, clock), ipc.Deadline(clock, 120))
        self.assertEqual(back, resp)

    def test_valid_request_reads_at_most_one_byte_past_body(self):
        data = request_frame()
        _, stream = read(data, chunk=10**9)
        self.assertEqual(stream.sizes[-1], 1)
        self.assertEqual(sum(1 for s in stream.sizes if s == 1), 1 if len(data) > 5 else 0)

    def test_ipc_over_64m_rejected_before_allocation(self):
        header = struct.pack(">I", ipc.MAX_REQUEST_BYTES + 1)
        clock = FakeClock()
        stream = FakeStream(header, clock, chunk=4)
        with mock.patch.object(ipc, "_read_exact", wraps=ipc._read_exact) as spy:
            with self.assertRaises(IPCError) as ctx:
                StrictBatchHostIPCCodec(clock=clock).read_request(stream)
        self.assertEqual(ctx.exception.code, "IPC_REQUEST_TOO_LARGE")
        self.assertEqual(spy.call_count, 1)  # header only; body was never read
        self.assertEqual(stream.sizes, [4])
        # a declared 64 MiB body is read in bounded chunks, never preallocated whole
        _, big = (None, FakeStream(struct.pack(">I", ipc.MAX_REQUEST_BYTES) + b"x" * 100,
                                   clock, chunk=10**9, at_end="timeout"))
        with self.assertRaises(IPCError):
            StrictBatchHostIPCCodec(clock=clock).read_request(big)
        self.assertLessEqual(max(big.sizes), ipc.READ_CHUNK)

    def test_zero_length_frame_invalid(self):
        self.assertEqual(code_of(struct.pack(">I", 0)), "IPC_INVALID_FRAME")

    def test_partial_header_body_extra_frame_invalid_utf8_duplicate_key_rejected(self):
        good = request_frame()
        self.assertEqual(code_of(b""), "IPC_INVALID_FRAME")
        self.assertEqual(code_of(good[:2]), "IPC_INVALID_FRAME")  # partial header
        self.assertEqual(code_of(good[:-5]), "IPC_INVALID_FRAME")  # partial body
        self.assertEqual(code_of(good + b"x"), "IPC_INVALID_FRAME")  # trailing byte
        self.assertEqual(code_of(good + good), "IPC_INVALID_FRAME")  # second frame
        self.assertEqual(code_of(good + b" \n"), "IPC_INVALID_FRAME")
        self.assertEqual(code_of(framed(b"\xff\xfe{}")), "IPC_BAD_PAYLOAD")
        dup = body_of().replace(b'"command"', b'"request_id":"' + RID.encode()
                                + b'","command"', 1)
        self.assertEqual(code_of(framed(dup)), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(b'{"protocol_version":NaN}')), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(b"[]")), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(b"\xef\xbb\xbf" + body_of())), "IPC_BAD_PAYLOAD")

    def test_ipc_version_command_and_base64_rejected(self):
        self.assertEqual(code_of(framed(body_of(protocol_version=2))), "IPC_UNSUPPORTED_VERSION")
        self.assertEqual(code_of(framed(body_of(protocol_version="1"))), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(body_of(protocol_version=True))), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(body_of(command="other"))), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(body_of(request_id=RID.upper()))), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(body_of(request_id="ab"))), "IPC_BAD_PAYLOAD")
        good = base64.b64encode(PLAN + b"x").decode()  # 13 bytes -> two '=' pad chars
        self.assertTrue(good.endswith("=="))
        for bad in (good.rstrip("="), good + "\n", "!!!!", "", good[:-3] + "B==", 7, None,
                    good.replace("A", "é", 1), "AA==AA=="):
            with self.subTest(bad=bad):
                self.assertEqual(code_of(framed(body_of(plan_b64=bad))), "IPC_BAD_PAYLOAD")
        self.assertEqual(code_of(framed(body_of(owner_envelope_b64=base64.b64encode(
            b"x" * (ipc.MAX_ENVELOPE_BYTES + 1)).decode()))), "IPC_REQUEST_TOO_LARGE")
        self.assertEqual(code_of(framed(body_of(plan_b64=KeyError))), "IPC_BAD_PAYLOAD")

    def test_ipc_v1_has_no_subset_or_session_name_fields(self):
        for extra in ("row_index", "subset", "row_indexes", "role_session_name", "policy",
                      "session_name", "report_sha256", "credentials"):
            with self.subTest(extra=extra):
                self.assertEqual(code_of(framed(body_of(**{extra: 1}))), "IPC_BAD_PAYLOAD")
        self.assertEqual(set(StrictBatchHostIPCCodec().encode_request(
            plan_bytes=PLAN, csv_bytes=CSV, owner_envelope_bytes=ENV, request_id=RID)[4:].decode()
            and json.loads(request_frame()[4:])), set(ipc._REQUEST_FIELDS))
        self.assertEqual(len(ipc._RESPONSE_FIELDS), 6)

    def test_extra_subset_field_rejected_before_owner_or_sts(self):
        err = None
        try:
            read(framed(body_of(subset=[1])))
        except IPCError as error:
            err = error
        self.assertEqual(err.code, "IPC_BAD_PAYLOAD")
        self.assertEqual(err.request_id, RID)

    def test_response_validation_rejects_bad_fields(self):
        codec = StrictBatchHostIPCCodec()
        for bad in (HostIPCResponse(2, RID, "COMPLETE", "OK", None, None),
                    HostIPCResponse(1, "x", "COMPLETE", "OK", None, None),
                    HostIPCResponse(1, RID, "DONE", "OK", None, None),
                    HostIPCResponse(1, RID, "COMPLETE", "lower", None, None),
                    HostIPCResponse(1, RID, "COMPLETE", "OK", "zz", None),
                    HostIPCResponse(1, RID, "COMPLETE", "OK", None, "A" * 64)):
            with self.subTest(bad=bad), self.assertRaises(IPCError):
                codec.encode_response(bad)

    def test_deadlines_header_5s_body_eof_30s_monotonic(self):
        good = request_frame()
        clock = FakeClock()
        stream = FakeStream(good, clock, chunk=1, step=2.0)  # 2 s per byte: header takes 8 s
        with self.assertRaises(IPCError) as ctx:
            StrictBatchHostIPCCodec(clock=clock).read_request(stream)
        self.assertEqual(ctx.exception.code, "IPC_TIMEOUT")
        self.assertLessEqual(stream.timeouts[0], 5.0)
        # body+EOF cumulative budget: header fast, body drips past 30 s
        clock = FakeClock()
        stream = FakeStream(good, clock, chunk=10**9)
        orig = stream.recv
        calls = []

        def slow(size):
            calls.append(size)
            if len(calls) > 1:
                clock.now += 31
            return orig(size)

        stream.recv = slow
        with self.assertRaises(IPCError) as ctx:
            StrictBatchHostIPCCodec(clock=clock).read_request(stream)
        self.assertEqual(ctx.exception.code, "IPC_TIMEOUT")
        self.assertLessEqual(max(stream.timeouts[1:]), 30.0)

    def test_module_has_no_aws_sts_sdk_or_ledger_import(self):
        tree = ast.parse(Path(ipc.__file__).read_text())
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add((node.module or "").split(".")[0])
        for forbidden in ("boto3", "botocore", "sqlite3", "name_tag_ledger",
                          "name_tag_batch_host_runtime", "name_tag_batch_host_issuer",
                          "name_tag_batch_trust", "name_tag_batch_runtime",
                          "name_tag_batch_approval"):
            self.assertNotIn(forbidden, names)


class EofGateTests(unittest.TestCase):
    """Correction A: framing + bounded EOF before any acceptance."""

    def test_fake_ipc_valid_half_close_eof_before_owner(self):
        request, stream = read(request_frame(), chunk=3)
        self.assertEqual(request.request_id, RID)
        self.assertEqual(stream.sizes[-1], 1)

    def test_fake_ipc_extra_frame_rejected_no_intent(self):
        self.assertEqual(code_of(request_frame() + request_frame()), "IPC_INVALID_FRAME")

    def test_fake_ipc_eof_missing_timeout_no_intent(self):
        self.assertEqual(code_of(request_frame(), at_end="timeout"), "IPC_TIMEOUT")
        self.assertEqual(code_of(request_frame(), at_end="hang"), "IPC_TIMEOUT")

    def test_fake_ipc_partial_body_rejected_no_intent(self):
        self.assertEqual(code_of(request_frame()[:30]), "IPC_INVALID_FRAME")

    def test_fake_ipc_partial_header_rejected_no_intent(self):
        self.assertEqual(code_of(request_frame()[:3]), "IPC_INVALID_FRAME")


# ---------------------------------------------------------------- client
class FakeSocket(FakeStream):
    def __init__(self, reply: bytes, clock: FakeClock, **kw):
        super().__init__(reply, clock, chunk=5, **kw)
        self.events: list[str] = []
        self.closed = False

    def sendall(self, data):
        self.events.append("sendall")
        super().sendall(data)

    def shutdown(self, how):
        self.events.append("shutdown")
        super().shutdown(how)

    def recv(self, size):
        self.events.append("recv")
        return super().recv(size)

    def close(self):
        self.events.append("close")
        self.closed = True


def reply_frame(response: HostIPCResponse) -> bytes:
    return StrictBatchHostIPCCodec().encode_response(response)


class ClientTests(unittest.TestCase):
    def make(self, reply: bytes, **kw):
        clock = FakeClock()
        sock = FakeSocket(reply, clock, **kw)
        connects = []

        def connector(path, timeout):
            connects.append((path, timeout))
            return sock

        client = UnixBatchHostClient(connector=connector, clock=clock)
        return client, sock, connects

    def run_exec(self, client):
        return client.execute(plan_bytes=PLAN, csv_bytes=CSV, owner_envelope_bytes=ENV,
                              request_id=RID)

    def test_sendall_shutdown_write_then_read_same_connection(self):
        resp = HostIPCResponse(1, RID, "COMPLETE", "COMPLETE", H64, H64)
        client, sock, connects = self.make(reply_frame(resp))
        self.assertEqual(self.run_exec(client), resp)
        self.assertEqual(connects, [(ipc.HOST_SOCKET_PATH, 3.0)])
        self.assertEqual(sock.events[:2], ["sendall", "shutdown"])
        self.assertEqual(sock.shutdowns, [socket.SHUT_WR])
        self.assertTrue(all(e == "recv" for e in sock.events[2:-1]))
        self.assertEqual(sock.events[-1], "close")
        self.assertEqual(sock.sent, request_frame())

    def test_client_uses_literal_socket_path_only(self):
        self.assertEqual(ipc.HOST_SOCKET_PATH, "/run/aws-cnt/host.sock")
        import inspect
        self.assertNotIn("path", inspect.signature(UnixBatchHostClient.execute).parameters)
        self.assertNotIn("socket_path", inspect.signature(UnixBatchHostClient).parameters)

    def test_missing_socket_blocks_and_timeout_or_loss_is_unknown(self):
        clock = FakeClock()

        def missing(path, timeout):
            raise FileNotFoundError(path)

        r = self.run_exec(UnixBatchHostClient(connector=missing, clock=clock))
        self.assertEqual((r.status, r.code), ("BLOCKED", "IPC_SOCKET_UNAVAILABLE"))

        def slow(path, timeout):
            raise TimeoutError()

        r = self.run_exec(UnixBatchHostClient(connector=slow, clock=clock))
        self.assertEqual((r.status, r.code), ("UNKNOWN", "IPC_TIMEOUT"))
        for reply, kw in ((b"", {}), (b"\x00\x00", {}), (b"\x00\x00\x00\x09{}", {}),
                          (b"\x00\x01\x00\x01x", {}), (b"", {"at_end": "timeout"}),
                          (b"\x00\x00\x00\x00", {})):
            with self.subTest(reply=reply, kw=kw):
                client, sock, _ = self.make(reply, **kw)
                r = self.run_exec(client)
                self.assertEqual(r.status, "UNKNOWN")
                self.assertIsNone(r.batch_id)
                self.assertTrue(sock.closed)

    def test_response_deadline_120s_monotonic(self):
        client, sock, _ = self.make(b"", at_end="hang")
        r = self.run_exec(client)
        self.assertEqual((r.status, r.code), ("UNKNOWN", "IPC_TIMEOUT"))
        self.assertLessEqual(sock.timeouts[0], 120.0)

    def test_wrong_request_id_reply_is_unknown(self):
        other = HostIPCResponse(1, "f" * 32, "COMPLETE", "COMPLETE", H64, H64)
        client, _, _ = self.make(reply_frame(other))
        self.assertEqual(self.run_exec(client).status, "UNKNOWN")

    def test_pre_decode_host_error_reply_maps_to_blocked(self):
        err = HostIPCResponse(1, ipc.ZERO_REQUEST_ID, "BLOCKED", "IPC_BUSY", None, None)
        client, _, _ = self.make(reply_frame(err))
        r = self.run_exec(client)
        self.assertEqual((r.status, r.code, r.request_id), ("BLOCKED", "IPC_BUSY", RID))

    def test_no_retry_one_connection_even_on_blocked_or_unknown(self):
        for reply in (reply_frame(HostIPCResponse(1, RID, "BLOCKED", "X", None, None)), b""):
            client, _, connects = self.make(reply)
            self.run_exec(client)
            self.assertEqual(len(connects), 1)

    def test_local_input_bounds_checked_before_connect(self):
        client, _, connects = self.make(b"")
        for kw in ({"plan_bytes": b""}, {"csv_bytes": b"x" * (ipc.MAX_CSV_BYTES + 1)},
                   {"request_id": "nope"}):
            args = {"plan_bytes": PLAN, "csv_bytes": CSV, "owner_envelope_bytes": ENV,
                    "request_id": RID, **kw}
            with self.subTest(kw=list(kw)), self.assertRaises(IPCError):
                client.execute(**args)
        self.assertEqual(connects, [])


class NoRealSocketTests(unittest.TestCase):
    def test_no_actual_socket_or_aws_during_fake_ipc(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("real socket")), \
             mock.patch.object(socket, "create_connection",
                               side_effect=AssertionError("network")):
            read(request_frame())
            clock = FakeClock()
            sock = FakeSocket(reply_frame(HostIPCResponse(1, RID, "COMPLETE", "COMPLETE",
                                                          None, None)), clock)
            UnixBatchHostClient(connector=lambda p, t: sock, clock=clock).execute(
                plan_bytes=PLAN, csv_bytes=CSV, owner_envelope_bytes=ENV, request_id=RID)


if __name__ == "__main__":
    unittest.main()
