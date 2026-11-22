"""Offline Host AF_UNIX server tests (Design §5.2.1). Fake OS/socket/endpoint only.

No socket is ever bound, no /run path touched, no systemd, STS or AWS call is made.
"""
from __future__ import annotations

import ast
import hashlib
import socket
import unittest
from types import SimpleNamespace
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from unittest import mock

import name_tag_batch_host_runtime as host_runtime
import name_tag_batch_host_server as server_mod
import name_tag_batch_ipc as ipc
from name_tag_batch_fake import BatchRunResult
from name_tag_batch_host_runtime import HostRuntimeBlocked, ProtectedBatchHostEndpoint
from name_tag_batch_host_server import (
    PathFacts, PeerCredentials, PeerPolicy, ProtectedHostIPCServer)
from name_tag_batch_ipc import StrictBatchHostIPCCodec
from test_name_tag_batch_host_issuer import IssuerHarness
from test_name_tag_batch_host_runtime import NOW, owner_verified
from test_name_tag_batch_ipc import (
    CSV, ENV, PLAN, RID, FakeClock, FakeStream, request_frame, body_of, framed)

SVC_UID, SVC_GID, IPC_GID, OPERATOR_UID = 990, 990, 991, 1000
BATCH_ID, REPORT = "ab" * 32, "cd" * 32
SOCK = ipc.HOST_SOCKET_PATH
RUN_DIR = "/run/aws-cnt"


class ListenerClosed(OSError):
    pass


class FakeConn(FakeStream):
    def __init__(self, data: bytes, clock: FakeClock, *, uid=OPERATOR_UID, gid=OPERATOR_UID,
                 pid=4242, send_error: Exception | None = None, **kw):
        super().__init__(data, clock, chunk=4096, **kw)
        self.peer = None if uid is None else PeerCredentials(pid, uid, gid)
        self.send_error = send_error
        self.closed = False

    def sendall(self, data):
        if self.send_error is not None:
            raise self.send_error
        super().sendall(data)

    def close(self):
        self.closed = True

    def reply(self) -> HostIPCResponse | None:
        if not self.sent:
            return None
        clock = FakeClock()
        return StrictBatchHostIPCCodec(clock=clock).read_response(
            FakeStream(self.sent, clock), ipc.Deadline(clock, 120))


HostIPCResponse = ipc.HostIPCResponse


class FakeListener:
    def __init__(self, os_, conns):
        self.os, self.conns = os_, list(conns)
        self.calls: list[str] = []
        self.name = SOCK

    def bind(self, path):
        self.calls.append("bind")
        self.os.bound_paths.append(path)
        self.os.files[path] = PathFacts("socket", SVC_UID, SVC_GID, 0o600, 77, 1)

    def getsockname(self):
        return self.os.sockname if self.os.sockname is not None else self.name

    def listen(self, backlog):
        self.calls.append("listen")
        self.os.backlogs.append(backlog)
        if self.os.swap_inode_on_listen:
            self.os.files[SOCK] = replace(self.os.files[SOCK], inode=99)

    def accept(self):
        if not self.conns:
            raise ListenerClosed()
        return self.conns.pop(0), None

    def close(self):
        self.calls.append("close")


class FakeListenerOS:
    def __init__(self, conns=()):
        self.env: dict[str, str] = {}
        self.files: dict[str, PathFacts] = {
            RUN_DIR: PathFacts("dir", SVC_UID, SVC_GID, 0o750, 5, 1)}
        self.groups = {"aws-cnt-ipc": IPC_GID}
        self.ids = (SVC_UID, SVC_GID)
        self.conns = list(conns)
        self.listener: FakeListener | None = None
        self.bound_paths: list[str] = []
        self.backlogs: list[int] = []
        self.sockname = None
        self.swap_inode_on_listen = False
        self.chmod_ignored_for: set[str] = set()
        self.chown_ignored_for: set[str] = set()
        self.peer_error = False
        self.log: list[str] = []

    def getenv(self, name):
        return self.env.get(name)

    def process_ids(self):
        return self.ids

    def lookup_group(self, name):
        return self.groups.get(name)

    def lstat(self, path):
        return self.files.get(path)

    def chown(self, path, uid, gid):
        self.log.append(f"chown {path} {uid}:{gid}")
        if path not in self.chown_ignored_for:
            self.files[path] = replace(self.files[path], uid=uid, gid=gid)

    def chmod(self, path, mode):
        self.log.append(f"chmod {path} {mode:o}")
        if path not in self.chmod_ignored_for:
            self.files[path] = replace(self.files[path], mode=mode)

    def new_listener(self):
        self.log.append("new_listener")
        self.listener = FakeListener(self, self.conns)
        return self.listener

    def peer_credentials(self, conn):
        if self.peer_error or conn.peer is None:
            raise OSError("SO_PEERCRED unavailable")
        return conn.peer


class FakeBootstrap:
    def __init__(self, events, *, error: Exception | None = None, host=None):
        self.events, self.error, self.calls = events, error, 0
        self.host = host if host is not None else SimpleNamespace(service_uid=SVC_UID)

    def verify_process(self, *, now_utc):
        self.calls += 1
        self.events.append("verify_process")
        if self.error:
            raise self.error
        return self.host


class FakeEndpoint:
    """Records the call; models a durable Ledger that outlives the connection."""

    def __init__(self, events, *, result=None, error: Exception | None = None, hook=None):
        self.events, self.result, self.error, self.hook = events, result, error, hook
        self.calls: list[dict] = []
        self.durable: list[str] = []
        self.seen_batches: set[bytes] = set()

    def execute_signed_batch(self, *, plan_bytes, csv_bytes, owner_envelope_bytes, host):
        self.events.append("endpoint")
        self.calls.append(dict(plan_bytes=plan_bytes, csv_bytes=csv_bytes,
                               owner_envelope_bytes=owner_envelope_bytes, host=host))
        if self.hook:
            self.hook()
        if plan_bytes in self.seen_batches:  # existing Ledger refuses a replay
            raise HostRuntimeBlocked("BLOCKED_BATCH_REPLAY", "already admitted")
        self.seen_batches.add(plan_bytes)
        self.durable.append("APPLIED_VERIFIED")
        if self.error:
            raise self.error
        return self.result


def run_result(report=None, *, state="COMPLETED", outcomes=("APPLIED_VERIFIED",)):
    return BatchRunResult(state, 1, 2, 0, tuple(outcomes), state == "COMPLETED",
                          MappingProxyType(report if report is not None else {
                              "batch_id": BATCH_ID, "report_sha256": REPORT}))


class Rig:
    def __init__(self, testcase=None, *, conns=(), policy=None, endpoint_kwargs=None, **kw):
        self.events: list[str] = []
        self.clock = FakeClock()
        self.os = FakeListenerOS(conns)
        self.bootstrap = FakeBootstrap(self.events, **kw)
        self.endpoint = FakeEndpoint(self.events, **(endpoint_kwargs or {}))
        self.server = ProtectedHostIPCServer(
            os_facade=self.os, peer_policy=policy or PeerPolicy(
                allowed_uids=frozenset({OPERATOR_UID}), allowed_gids=frozenset()),
            codec=StrictBatchHostIPCCodec(clock=self.clock), spawn=lambda fn: fn(),
            trace=self.events.append, host_check=lambda host: host)

    def conn(self, data=None, **kw):
        return FakeConn(request_frame() if data is None else data, self.clock, **kw)

    def handle(self, conn, endpoint=None):
        self.server.handle_connection(conn, bootstrap=self.bootstrap,
                                      endpoint=endpoint or self.endpoint)
        return conn.reply()


# ---------------------------------------------------------------- listener / startup
class StartupTests(unittest.TestCase):
    def serve(self, rig):
        rig.server.serve(bootstrap=rig.bootstrap, endpoint=rig.endpoint)

    def test_service_owns_bind_no_systemd_socket_activation(self):
        rig = Rig()
        self.serve(rig)
        self.assertEqual(rig.events[0], "verify_process")  # bootstrap proof precedes bind
        self.assertEqual(rig.os.listener.calls[:2], ["bind", "listen"])
        self.assertEqual(rig.os.bound_paths, [SOCK])
        self.assertEqual(rig.os.backlogs, [8])
        f = rig.os.files[SOCK]
        self.assertEqual((f.kind, f.uid, f.gid, f.mode), ("socket", SVC_UID, IPC_GID, 0o660))
        d = rig.os.files[RUN_DIR]
        self.assertEqual((d.gid, d.mode), (IPC_GID, 0o750))
        self.assertEqual(server_mod.SOCKET_PATH, "/run/aws-cnt/host.sock")
        # LISTEN_FDS / socket activation env is blocked, never adopted
        for name in ("LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"):
            with self.subTest(name=name):
                rig = Rig()
                rig.os.env[name] = "1"
                with self.assertRaises(HostRuntimeBlocked) as caught:
                    self.serve(rig)
                self.assertEqual(caught.exception.code, "IPC_LISTENER_BLOCKED")
                self.assertEqual(rig.os.bound_paths, [])
                self.assertNotIn("new_listener", rig.os.log)
        tree = ast.parse(Path(server_mod.__file__).read_text())
        attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertNotIn("fromfd", attrs)
        self.assertNotIn("sd_listen_fds", Path(server_mod.__file__).read_text())

    def test_host_startup_wrong_socket_path_mode_owner_or_peer_blocks(self):
        def f(**kw):
            return PathFacts(**{"kind": "dir", "uid": SVC_UID, "gid": SVC_GID, "mode": 0o750,
                                "inode": 5, "device": 1, **kw})

        cases = {
            "runtime_dir_missing": lambda o: o.files.pop(RUN_DIR),
            "runtime_dir_symlink": lambda o: o.files.update({RUN_DIR: f(kind="symlink")}),
            "runtime_dir_is_file": lambda o: o.files.update({RUN_DIR: f(kind="file")}),
            "runtime_dir_wrong_owner": lambda o: o.files.update({RUN_DIR: f(uid=0)}),
            "runtime_dir_group_writable": lambda o: o.files.update({RUN_DIR: f(mode=0o770)}),
            "runtime_dir_world_writable": lambda o: o.files.update({RUN_DIR: f(mode=0o757)}),
            "socket_path_exists_stale": lambda o: o.files.update(
                {SOCK: PathFacts("socket", SVC_UID, SVC_GID, 0o660, 3, 1)}),
            "socket_path_symlink": lambda o: o.files.update({SOCK: f(kind="symlink")}),
            "socket_path_regular_file": lambda o: o.files.update({SOCK: f(kind="file")}),
            "ipc_group_missing": lambda o: o.groups.clear(),
            "process_uid_not_service": lambda o: setattr(o, "ids", (0, 0)),
            "chmod_runtime_ignored": lambda o: (o.chmod_ignored_for.add(RUN_DIR),
                                                o.files.update({RUN_DIR: f(mode=0o700)})),
            "chown_runtime_ignored": lambda o: o.chown_ignored_for.add(RUN_DIR),
            "chmod_socket_ignored": lambda o: o.chmod_ignored_for.add(SOCK),
            "chown_socket_ignored": lambda o: o.chown_ignored_for.add(SOCK),
            "socket_inode_swapped": lambda o: setattr(o, "swap_inode_on_listen", True),
            "bound_to_other_path": lambda o: setattr(o, "sockname", "/tmp/other.sock"),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                rig = Rig()
                mutate(rig.os)
                with self.assertRaises(HostRuntimeBlocked) as caught:
                    self.serve(rig)
                self.assertEqual(caught.exception.code, "IPC_LISTENER_BLOCKED")
                self.assertNotIn(f"chmod {SOCK} 777", rig.os.log)
        # existing path is never unlinked/replaced and nothing is bound over it
        rig = Rig()
        rig.os.files[SOCK] = PathFacts("socket", SVC_UID, SVC_GID, 0o660, 3, 1)
        with self.assertRaises(HostRuntimeBlocked):
            self.serve(rig)
        self.assertEqual(rig.os.bound_paths, [])
        self.assertEqual(rig.os.files[SOCK].inode, 3)
        # missing protected Host proof: bootstrap failure blocks before any listener exists
        rig = Rig(error=HostRuntimeBlocked("AWS_RUNTIME_NOT_AUTHORIZED", "no proof"))
        with self.assertRaises(HostRuntimeBlocked):
            self.serve(rig)
        self.assertNotIn("new_listener", rig.os.log)
        # a peer outside policy is rejected before any bytes are read
        rig = Rig()
        conn = rig.conn(uid=OPERATOR_UID + 5)
        reply = rig.handle(conn)
        self.assertEqual((reply.status, reply.code), ("BLOCKED", "IPC_PEER_REJECTED"))
        self.assertEqual(conn.sizes, [])
        self.assertEqual(rig.endpoint.calls, [])
        self.assertNotIn("verify_process", rig.events)

    def test_unreadable_or_empty_policy_peer_credentials_rejected(self):
        for kw in ({"uid": None}, {"pid": 0}):
            rig = Rig()
            reply = rig.handle(rig.conn(**kw))
            self.assertEqual(reply.code, "IPC_PEER_REJECTED")
            self.assertEqual(rig.endpoint.calls, [])
        rig = Rig(policy=PeerPolicy(frozenset(), frozenset()))
        self.assertEqual(rig.handle(rig.conn()).code, "IPC_PEER_REJECTED")
        rig = Rig(policy=PeerPolicy(frozenset(), frozenset({IPC_GID})))
        self.assertNotEqual(rig.handle(rig.conn(uid=1, gid=IPC_GID)).code, "IPC_PEER_REJECTED")

    def test_serve_dispatches_accepted_connections_then_stops_on_listener_close(self):
        rig = Rig()
        rig.os.conns = [rig.conn(), rig.conn(request_frame()[:3])]
        rig.endpoint.result = run_result()
        rig.server.serve(bootstrap=rig.bootstrap, endpoint=rig.endpoint)
        self.assertEqual(len(rig.endpoint.calls), 1)

    def test_unavailable_production_server_fails_closed(self):
        prod = server_mod.production_ipc_server()
        with self.assertRaises(HostRuntimeBlocked) as caught:
            prod.serve(bootstrap=host_runtime.production_bootstrap_verifier(),
                       endpoint=host_runtime.production_host_endpoint())
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")


# ---------------------------------------------------------------- framing gate
class PreAcceptTests(unittest.TestCase):
    def test_invalid_preaccept_stream_never_calls_endpoint(self):
        good = request_frame()
        bad_streams = {
            "partial_header": (good[:3], {}), "partial_body": (good[:-9], {}),
            "extra_frame": (good + good, {}), "trailing": (good + b"\n", {}),
            "no_eof": (good, {"at_end": "timeout"}), "hang": (good, {"at_end": "hang"}),
            "bad_json": (framed(b"{"), {}), "bad_version": (framed(body_of(protocol_version=9)), {}),
            "extra_field": (framed(body_of(subset=[0])), {}),
            "oversize": ((ipc.MAX_REQUEST_BYTES + 1).to_bytes(4, "big"), {}),
        }
        expect = {"partial_header": "IPC_INVALID_FRAME", "partial_body": "IPC_INVALID_FRAME",
                  "extra_frame": "IPC_INVALID_FRAME", "trailing": "IPC_INVALID_FRAME",
                  "no_eof": "IPC_TIMEOUT", "hang": "IPC_TIMEOUT", "bad_json": "IPC_BAD_PAYLOAD",
                  "bad_version": "IPC_UNSUPPORTED_VERSION", "extra_field": "IPC_BAD_PAYLOAD",
                  "oversize": "IPC_REQUEST_TOO_LARGE"}
        for name, (data, kw) in bad_streams.items():
            with self.subTest(name):
                rig = Rig()
                conn = rig.conn(data, **kw)
                reply = rig.handle(conn)
                self.assertEqual((reply.status, reply.code), ("BLOCKED", expect[name]))
                self.assertEqual(rig.endpoint.calls, [])
                self.assertEqual(rig.events, [])  # no accepted marker, no re-verification
                self.assertEqual(rig.endpoint.durable, [])
                self.assertTrue(conn.closed)
                self.assertIsNone(reply.batch_id)
                self.assertIsNone(reply.report_sha256)

    def test_bad_payload_reply_echoes_known_request_id_else_zeros(self):
        rig = Rig()
        self.assertEqual(rig.handle(rig.conn(framed(body_of(subset=[0])))).request_id, RID)
        rig = Rig()
        self.assertEqual(rig.handle(rig.conn(b"\x00")).request_id, ipc.ZERO_REQUEST_ID)

    def test_unwritable_preaccept_error_just_closes(self):
        rig = Rig()
        conn = rig.conn(request_frame()[:2], send_error=BrokenPipeError())
        self.assertIsNone(rig.handle(conn))
        self.assertTrue(conn.closed)

    def test_no_actual_socket_or_aws_during_fake_ipc(self):
        with mock.patch.object(socket, "socket", side_effect=AssertionError("real socket")), \
             mock.patch.object(socket, "create_connection", side_effect=AssertionError("net")):
            rig = Rig(endpoint_kwargs={"result": run_result()})
            rig.os.conns = [rig.conn()]
            rig.server.serve(bootstrap=rig.bootstrap, endpoint=rig.endpoint)
            reply = rig.handle(rig.conn(), endpoint=FakeEndpoint(rig.events, result=run_result()))
        self.assertEqual(reply.status, "COMPLETE")
        source = Path(server_mod.__file__).read_text()
        for forbidden in ("boto3", "botocore", "name_tag_batch_host_issuer", "sqlite3"):
            self.assertNotIn(f"import {forbidden}", source)


# ---------------------------------------------------------------- accepted-command lifecycle
class AcceptedTests(unittest.TestCase):
    def test_accepted_command_called_once_with_exact_bytes_after_marker(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        reply = rig.handle(rig.conn())
        self.assertEqual(rig.events, ["IPC_REQUEST_ACCEPTED", "verify_process", "endpoint"])
        (call,) = rig.endpoint.calls
        self.assertEqual((call["plan_bytes"], call["csv_bytes"], call["owner_envelope_bytes"]),
                         (PLAN, CSV, ENV))
        self.assertIs(call["host"], rig.bootstrap.host)
        self.assertNotIn("request_id", call)
        self.assertEqual((reply.status, reply.code, reply.request_id, reply.batch_id,
                          reply.report_sha256), ("COMPLETE", "COMPLETE", RID, BATCH_ID, REPORT))

    def test_host_accepted_disconnect_still_calls_fake_coordinator(self):
        for send_error in (BrokenPipeError(), ConnectionResetError(), TimeoutError()):
            with self.subTest(error=type(send_error).__name__):
                rig = Rig(endpoint_kwargs={"result": run_result()})
                conn = rig.conn(send_error=send_error)
                self.assertIsNone(rig.handle(conn))  # reply lost; no exception escapes
                self.assertEqual(len(rig.endpoint.calls), 1)
                self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])
                self.assertTrue(conn.closed)
        # client closing its read side mid-command is not a cancellation signal
        rig = Rig(endpoint_kwargs={"result": run_result()})
        conn = rig.conn()
        rig.endpoint.hook = lambda: setattr(conn, "send_error", BrokenPipeError())
        rig.handle(conn)
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])

    def test_host_response_write_failure_preserves_fake_durable_result(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        rig.handle(rig.conn(send_error=BrokenPipeError()))
        self.assertEqual(rig.server.response_write_failures, 1)
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])  # not rolled back/rewritten
        # the Host stays healthy: the next command is served normally
        rig.endpoint.seen_batches.clear()
        self.assertEqual(rig.handle(rig.conn()).status, "COMPLETE")

    def test_duplicate_request_id_does_not_authorize_replay(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        first = rig.handle(rig.conn())
        second = rig.handle(rig.conn())  # same request_id, same batch bytes
        self.assertEqual(first.status, "COMPLETE")
        self.assertEqual((second.status, second.code), ("BLOCKED", "BLOCKED_BATCH_REPLAY"))
        self.assertEqual(len(rig.endpoint.calls), 2)  # Ledger (not request_id) decides
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])  # one send only
        # a changed request_id does not help either
        other = rig.handle(rig.conn(framed(body_of(request_id="f" * 32))))
        self.assertEqual((other.status, other.code, other.request_id),
                         ("BLOCKED", "BLOCKED_BATCH_REPLAY", "f" * 32))
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])

    def test_one_active_batch_busy_returns_no_intent(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        inner: list = []

        def during_first():
            second = rig.conn(framed(body_of(plan_b64="AAAA")))
            inner.append((second, rig.handle(second, endpoint=rig.endpoint)))

        rig.endpoint.hook = during_first
        outer = rig.handle(rig.conn())
        (second_conn, busy), = inner
        self.assertEqual((busy.status, busy.code), ("BLOCKED", "IPC_BUSY"))
        self.assertEqual(busy.request_id, RID)
        self.assertEqual(len(rig.endpoint.calls), 1)  # second never reached the endpoint
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])
        self.assertEqual(rig.events.count("verify_process"), 1)
        self.assertTrue(second_conn.closed)
        self.assertEqual(outer.status, "COMPLETE")
        # the slot is released afterwards, also after an endpoint failure
        rig.endpoint.hook = None
        rig.endpoint.seen_batches.clear()
        self.assertEqual(rig.handle(rig.conn()).status, "COMPLETE")

    def test_busy_slot_released_after_endpoint_exception(self):
        rig = Rig(endpoint_kwargs={"error": RuntimeError("boom")})
        self.assertEqual(rig.handle(rig.conn()).status, "UNKNOWN")
        rig.endpoint.error = None
        rig.endpoint.result = run_result()
        rig.endpoint.seen_batches.clear()
        self.assertEqual(rig.handle(rig.conn()).status, "COMPLETE")

    def test_connection_cap_busy_only_for_admitted_peers(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        rig.server._max_connections = 0
        reply = rig.handle(rig.conn(uid=OPERATOR_UID + 7))
        self.assertEqual(reply.code, "IPC_PEER_REJECTED")

    def test_forged_host_context_blocked_before_endpoint(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        rig.server._host_check = host_runtime.require_verified_host  # production default
        reply = rig.handle(rig.conn())  # bootstrap returns a forged SimpleNamespace
        self.assertEqual(reply.status, "BLOCKED")
        self.assertEqual(rig.endpoint.calls, [])
        self.assertEqual(rig.events, ["IPC_REQUEST_ACCEPTED", "verify_process"])

    def test_connection_cap_returns_busy_without_reading(self):
        rig = Rig(endpoint_kwargs={"result": run_result()})
        rig.server._max_connections = 0
        conn = rig.conn()
        reply = rig.handle(conn)
        self.assertEqual(reply.code, "IPC_BUSY")
        self.assertEqual(conn.sizes, [])
        self.assertEqual(rig.endpoint.calls, [])

    def test_post_accept_bootstrap_reverification_failure_blocks_before_endpoint(self):
        rig = Rig(error=HostRuntimeBlocked("AWS_RUNTIME_NOT_AUTHORIZED", "drift"))
        reply = rig.handle(rig.conn())
        self.assertEqual((reply.status, reply.code), ("BLOCKED", "AWS_RUNTIME_NOT_AUTHORIZED"))
        self.assertEqual(rig.endpoint.calls, [])


# ---------------------------------------------------------------- response mapping
class PartialCoded(HostRuntimeBlocked):
    def __init__(self, code, batch_id, report_sha256):
        super().__init__(code, "later row refused")
        self.batch_id, self.report_sha256 = batch_id, report_sha256


class MappingTests(unittest.TestCase):
    def run_endpoint(self, **kw):
        rig = Rig(endpoint_kwargs=kw)
        return rig.handle(rig.conn()), rig

    def test_host_partial_success_then_blocked_preserves_report(self):
        reply, rig = self.run_endpoint(error=PartialCoded("BLOCKED_SCOPE_MISMATCH",
                                                          BATCH_ID, REPORT))
        self.assertEqual((reply.status, reply.code), ("BLOCKED", "BLOCKED_SCOPE_MISMATCH"))
        self.assertEqual((reply.batch_id, reply.report_sha256), (BATCH_ID, REPORT))
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])  # earlier row kept
        # a returned partial result with a stopped Batch is also BLOCKED, report preserved
        reply, _ = self.run_endpoint(result=run_result(state="STOPPED"))
        self.assertEqual((reply.status, reply.batch_id, reply.report_sha256),
                         ("BLOCKED", BATCH_ID, REPORT))

    def test_host_response_batch_id_and_durable_report_sha256(self):
        reply, _ = self.run_endpoint(result=run_result())
        self.assertEqual((reply.protocol_version, reply.status, reply.batch_id,
                          reply.report_sha256), (1, "COMPLETE", BATCH_ID, REPORT))
        self.assertEqual(len(ipc._RESPONSE_FIELDS), 6)
        digest = hashlib.sha256(b"stored report bytes").hexdigest()
        reply, _ = self.run_endpoint(result=run_result({"batch_id": BATCH_ID,
                                                        "report_sha256": digest}))
        self.assertEqual(reply.report_sha256, digest)
        # malformed identifiers are never echoed
        reply, _ = self.run_endpoint(result=run_result({"batch_id": "xyz",
                                                        "report_sha256": REPORT.upper()}))
        self.assertIsNone(reply.batch_id)
        self.assertIsNone(reply.report_sha256)
        self.assertEqual(reply.status, "UNKNOWN")
        # a digest without a verified Batch ID is dropped
        reply, _ = self.run_endpoint(result=run_result({"report_sha256": REPORT}))
        self.assertIsNone(reply.report_sha256)

    def test_host_unverifiable_partial_report_not_complete_or_zero_sends(self):
        reply, rig = self.run_endpoint(result=run_result({"batch_id": BATCH_ID}))
        self.assertEqual((reply.status, reply.code), ("UNKNOWN", "REPORT_NOT_VERIFIED"))
        self.assertEqual(reply.batch_id, BATCH_ID)
        self.assertIsNone(reply.report_sha256)
        self.assertEqual(rig.endpoint.durable, ["APPLIED_VERIFIED"])
        reply, _ = self.run_endpoint(result=run_result(
            outcomes=("APPLIED_VERIFIED", "OUTCOME_UNKNOWN"), state="STOPPED"))
        self.assertEqual((reply.status, reply.code), ("UNKNOWN", "OUTCOME_UNKNOWN"))
        reply, _ = self.run_endpoint(error=RuntimeError("secret detail"))
        self.assertEqual((reply.status, reply.code, reply.batch_id),
                         ("UNKNOWN", "HOST_COMMAND_UNKNOWN", None))
        self.assertNotIn("secret", repr(reply))

    def test_non_completed_states_with_valid_digest_never_complete(self):
        for state in ("RECOVERY_REQUIRED", "HOLD", "ACTIVE", "WEIRD", "COMPLETE"):
            with self.subTest(state=state):
                reply, _ = self.run_endpoint(result=run_result(state=state))
                self.assertEqual((reply.status, reply.code), ("BLOCKED", "BATCH_NOT_COMPLETED"))
                self.assertEqual((reply.batch_id, reply.report_sha256), (BATCH_ID, REPORT))
        reply, _ = self.run_endpoint(result=object())  # not a BatchRunResult
        self.assertEqual((reply.status, reply.code), ("UNKNOWN", "HOST_COMMAND_UNKNOWN"))
        reply, _ = self.run_endpoint(result=None)
        self.assertEqual(reply.status, "UNKNOWN")

    def test_host_blocked_codes_are_mapped_and_unknown_codes_sanitized(self):
        reply, _ = self.run_endpoint(error=HostRuntimeBlocked("BLOCKED_OWNER_AUTHN", "x"))
        self.assertEqual((reply.status, reply.code, reply.batch_id),
                         ("BLOCKED", "BLOCKED_OWNER_AUTHN", None))
        reply, _ = self.run_endpoint(error=HostRuntimeBlocked("not a code!", "x"))
        self.assertEqual((reply.status, reply.code), ("BLOCKED", "AWS_RUNTIME_NOT_AUTHORIZED"))

    def test_production_endpoint_refuses_aws_runtime_not_authorized(self):
        rig = Rig()
        endpoint = host_runtime.production_host_endpoint()
        rig.bootstrap.host = object()
        reply = rig.handle(rig.conn(), endpoint=endpoint)
        self.assertEqual((reply.status, reply.code), ("BLOCKED", "AWS_RUNTIME_NOT_AUTHORIZED"))


# ---------------------------------------------------------------- real endpoint through IPC
class RealEndpointTests(unittest.TestCase):
    def test_host_endpoint_reverifies_owner_and_uses_single_coordinator(self):
        h = IssuerHarness(self)
        coordinator = mock.Mock()
        coordinator.run_signed_batch.return_value = run_result()
        endpoint = ProtectedBatchHostEndpoint(issuer=h.issuer, coordinator=coordinator,
                                              clock=lambda: NOW)
        rig = Rig()
        rig.bootstrap.host = h.host
        plan, csv, env = h.batch.plan_bytes, h.batch.csv_bytes, b'{"owner":"envelope"}'
        data = StrictBatchHostIPCCodec().encode_request(
            plan_bytes=plan, csv_bytes=csv, owner_envelope_bytes=env, request_id=RID)
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()), \
                mock.patch("name_tag_batch_approval.verify_batch_approval",
                           return_value=h.batch) as verify:
            reply = rig.handle(rig.conn(data), endpoint=endpoint)
        self.assertEqual(reply.status, "COMPLETE")
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[:3], (plan, csv, env))  # exact original bytes
        coordinator.run_signed_batch.assert_called_once()
        self.assertIs(coordinator.run_signed_batch.call_args.kwargs["host"], h.host)
        # Owner verification failure is a normal BLOCKED reply, no Coordinator call
        coordinator.reset_mock()
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()):
            reply = rig.handle(rig.conn(data), endpoint=endpoint)
        self.assertEqual((reply.status, reply.code), ("BLOCKED", "BLOCKED_OWNER_AUTHN"))
        coordinator.run_signed_batch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
