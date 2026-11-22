"""Task 8: ``batch-live`` is only an untrusted local client of the protected Host service.

Fake local IPC only: a loopback Fake socket hands exactly the bytes the CLI sent to the real
Task 6 ``ProtectedHostIPCServer`` (Fake listener OS/bootstrap) and returns its reply on the
same connection. No real socket bind/connect, systemd, STS or AWS operation happens here.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import name_tag_batch_cli as cli
import name_tag_batch_host_runtime as host_runtime
import name_tag_batch_ipc as ipc
from name_tag_batch_host_runtime import (
    HostOutcomeUnknown, HostRuntimeBlocked, ProtectedBatchHostEndpoint)
from name_tag_batch_ipc import HostIPCResponse, UnixBatchHostClient
from test_name_tag_batch_host_issuer import IssuerHarness
from test_name_tag_batch_host_runtime import build_batch
from test_name_tag_batch_host_server import FakeConn, Rig, run_result
from test_name_tag_batch_ipc import FakeClock

REPORT = "cd" * 32
CLI_SOURCE = Path(cli.__file__).read_text(encoding="utf-8")
LIVE_ARGS = ["batch-live", "--plan", "plan.json", "--review", "review.csv",
             "--envelope", "envelope.json", "--report-out", "live.json", "--live-opt-in"]


def live_inputs(batch=None):
    """Exact Plan/CSV bytes plus a structurally valid but *unsigned* Batch envelope."""
    batch = batch or build_batch()
    envelope = json.dumps({
        "payload": dict(batch.payload), "batch_id": batch.batch_id,
        "signature_ref": base64.b64encode(b"unsigned-fixture").decode("ascii")},
        separators=(",", ":")).encode()
    return batch.plan_bytes, batch.csv_bytes, envelope, batch.batch_id


class LoopbackHostSocket:
    """Client-side Fake socket bridged to the real Task 6 server (single connection).

    ``sendall`` buffers; ``shutdown(SHUT_WR)`` lets the server handle exactly those bytes and
    capture its reply; ``recv`` serves the (optionally lost/truncated) reply. A ``recv``
    before the half-close is a protocol violation and fails the test.
    """

    def __init__(self, rig: Rig, endpoint, *, reply_mode: str = "deliver",
                 truncate_to: int | None = None, host_view=None, conn_kwargs=None):
        self.rig, self.endpoint = rig, endpoint
        self.reply_mode, self.truncate_to = reply_mode, truncate_to
        self.host_view = host_view or (lambda data: data)
        self.conn_kwargs = conn_kwargs or {}
        self.events: list = []
        self.sent = b""
        self.reply = b""
        self.pos = 0
        self.half_closed = False
        self.host_reply: HostIPCResponse | None = None

    def settimeout(self, seconds):
        self.events.append("settimeout")

    def sendall(self, data):
        assert not self.half_closed, "write after half-close"
        self.events.append("sendall")
        self.sent += data

    def shutdown(self, how):
        self.events.append(("shutdown", how))
        self.half_closed = True
        conn = FakeConn(self.host_view(self.sent), self.rig.clock, **self.conn_kwargs)
        self.rig.server.handle_connection(conn, bootstrap=self.rig.bootstrap,
                                          endpoint=self.endpoint)
        self.host_reply = conn.reply()
        reply = conn.sent
        if self.reply_mode == "lost":
            reply = b""
        elif self.truncate_to is not None:
            reply = reply[:self.truncate_to]
        self.reply = reply

    def recv(self, size):
        assert self.half_closed, "recv before shutdown(SHUT_WR)"
        self.events.append("recv")
        if self.reply_mode == "hang":
            raise TimeoutError()
        out = self.reply[self.pos:self.pos + min(size, 5)]
        self.pos += len(out)
        return out

    def close(self):
        self.events.append("close")


class LiveCase(unittest.TestCase):
    """Private temporary workspace + fake Host behind the literal-path client."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        os.chmod(self.root, 0o700)
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        self.plan, self.csv, self.envelope, self.batch_id = live_inputs()
        self.write_inputs()
        self.rig = Rig()
        self.endpoint = self.rig.endpoint
        self.sockets: list[LoopbackHostSocket] = []
        self.connects: list[tuple[str, float]] = []
        self.clients: list[UnixBatchHostClient] = []
        self.client_factory_args: list = []
        self.connect_error: BaseException | None = None
        self.socket_kwargs: dict = {}

    def write_inputs(self, plan=None, csv=None, envelope=None):
        for name, data in (("plan.json", plan or self.plan), ("review.csv", csv or self.csv),
                           ("envelope.json", envelope or self.envelope)):
            path = self.root / name
            path.unlink(missing_ok=True)
            path.write_bytes(data)
            path.chmod(0o600)

    def connector(self, path, timeout):
        self.connects.append((path, timeout))
        if self.connect_error is not None:
            raise self.connect_error
        sock = LoopbackHostSocket(self.rig, self.endpoint, **self.socket_kwargs)
        self.sockets.append(sock)
        return sock

    def client_factory(self, *args, **kwargs):
        self.client_factory_args.append((args, kwargs))
        client = UnixBatchHostClient(connector=self.connector, clock=FakeClock())
        self.clients.append(client)
        return client

    def run_cli(self, argv=None, *, out="live.json"):
        argv = list(LIVE_ARGS if argv is None else argv)
        if out != "live.json" and "--report-out" in argv:
            argv[argv.index("--report-out") + 1] = out
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(ipc, "UnixBatchHostClient", side_effect=self.client_factory), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        self.stdout, self.stderr = stdout.getvalue(), stderr.getvalue()
        return code

    def summary(self, name="live.json"):
        return json.loads((self.root / name).read_bytes())

    def sent_request(self, index=0) -> dict:
        frame = self.sockets[index].sent
        return json.loads(frame[4:])

    def assert_never_success_claim(self, doc):
        self.assertIs(doc["zero_writes_implied"], False)
        self.assertIs(doc["all_rows_applied_implied"], False)
        self.assertIs(doc["applied_verified_asserted"], False)
        self.assertIs(doc["execution_allowed"], False)
        self.assertEqual(doc["summary_kind"], "LOCAL_UNTRUSTED_HOST_REPLY_SUMMARY")


# ================================================================ Step 1 (brief RED list)
class OptInBoundaryTests(LiveCase):
    def test_default_cli_never_calls_aws_or_sts(self):
        dry = ["batch-dryrun", "--plan", "plan.json", "--review", "review.csv",
               "--report-out", "dry.json"]
        with mock.patch.dict(sys.modules, {"boto3": None, "botocore": None}), \
                mock.patch.object(socket, "socket", side_effect=AssertionError("socket")), \
                mock.patch.object(socket, "create_connection",
                                  side_effect=AssertionError("network")):
            self.assertEqual(self.run_cli(dry), 0)
            # batch-live without the explicit opt-in never builds a client.
            self.assertEqual(self.run_cli(LIVE_ARGS[:-1], out="x.json"), 2)
        self.assertEqual((self.clients, self.connects), ([], []))
        self.assertFalse((self.root / "x.json").exists())
        self.assertFalse(json.loads((self.root / "dry.json").read_bytes())["execution_allowed"])

    def test_live_opt_in_flag_alone_denied(self):
        # The production Host endpoint (no protected issuer/Coordinator) refuses.
        self.endpoint = host_runtime.production_host_endpoint()
        self.assertEqual(self.run_cli(), 2)
        doc = self.summary()
        self.assertEqual((doc["status"], doc["code"]), ("BLOCKED", "AWS_RUNTIME_NOT_AUTHORIZED"))
        self.assert_never_success_claim(doc)
        # The opt-in flag is never transmitted; the request has exactly the six v1 fields.
        self.assertEqual(set(self.sent_request()), {
            "protocol_version", "command", "request_id", "plan_b64", "review_csv_b64",
            "owner_envelope_b64"})

    def test_invalid_or_unsigned_live_plan_rejected(self):
        # (a) Not a Batch envelope for these Plan/CSV bytes: refused locally, before connect.
        for envelope in (b"not json", json.dumps({"payload": {}}).encode(),
                         self.envelope.replace(b'"batch_id":"', b'"batch_id":"0')):
            with self.subTest(envelope=envelope[:20]):
                self.write_inputs(envelope=envelope)
                self.assertEqual(self.run_cli(out="bad.json"), 2)
                self.assertFalse((self.root / "bad.json").exists())
        self.write_inputs(plan=self.plan + b" ")
        self.assertEqual(self.run_cli(out="bad.json"), 2)
        self.assertEqual(self.connects, [])
        # (b) Well-formed but unsigned: the Host endpoint re-verifies and refuses.
        self.write_inputs()
        h = IssuerHarness(self)
        coordinator = mock.Mock()
        self.endpoint = ProtectedBatchHostEndpoint(issuer=h.issuer, coordinator=coordinator)
        self.rig.bootstrap.host = h.host
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()):
            self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.summary()["code"], "BLOCKED_OWNER_AUTHN")
        coordinator.run_signed_batch.assert_not_called()

    def test_fake_runtime_file_cannot_enable_live(self):
        (self.root / "runtime.json").write_text("{}")
        (self.root / "runtime.json").chmod(0o600)
        for extra in (["--runtime-evidence", "runtime.json"], ["--host-runtime", "runtime.json"],
                      ["--ledger-path", "fixture.db"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                self.run_cli(LIVE_ARGS + extra)
        self.endpoint = host_runtime.production_host_endpoint()
        with mock.patch.dict(os.environ, {host_runtime.HOST_PROTECTED_DISPATCH_OPT_IN: "1",
                                          "AWS_CNT_HOST_RUNTIME": "runtime.json"}):
            self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.summary()["status"], "BLOCKED")
        self.assertEqual(self.client_factory_args, [((), {})])

    def test_dryrun_and_simulate_unchanged(self):
        parser = cli._build_parser()
        subs = next(a for a in parser._actions if a.dest == "command")
        for command, flags in (
                ("prepare-batch", {"--plan", "--review", "--owner-id", "--owner-fingerprint",
                                   "--role-arn", "--issued-at", "--expires-at", "--nonce",
                                   "--payload-out", "--manifest-out"}),
                ("batch-dryrun", {"--plan", "--review", "--report-out"}),
                ("verify-batch", {"--plan", "--review", "--report-out", "--envelope"}),
                ("batch-simulate", {"--plan", "--review", "--report-out", "--envelope",
                                    "--ledger-path", "--runtime-evidence"})):
            with self.subTest(command=command):
                options = {o for a in subs.choices[command]._actions for o in a.option_strings
                           if o not in ("-h", "--help")}
                self.assertEqual(options, flags)
        self.assertEqual(self.run_cli(["batch-dryrun", "--plan", "plan.json", "--review",
                                       "review.csv", "--report-out", "dry.json"]), 0)
        self.assertEqual(json.loads((self.root / "dry.json").read_bytes())
                         ["authentication_state"], "UNSIGNED_PREVIEW")
        self.assertEqual(self.clients, [])


# ================================================================ client wiring / transport
class ClientWiringTests(LiveCase):
    def test_cli_sends_exact_signed_bytes_over_fake_ipc(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.assertEqual(self.run_cli(), 0)
        (call,) = self.endpoint.calls
        self.assertEqual((call["plan_bytes"], call["csv_bytes"], call["owner_envelope_bytes"]),
                         (self.plan, self.csv, self.envelope))
        doc = self.summary()
        self.assertEqual((doc["status"], doc["code"], doc["batch_id"], doc["report_sha256"]),
                         ("COMPLETE", "COMPLETE", self.batch_id, REPORT))
        self.assertEqual(doc["request_id"], self.sent_request()["request_id"])
        self.assert_never_success_claim(doc)
        self.assertEqual(os.stat(self.root / "live.json").st_mode & 0o777, 0o600)

    def test_cli_sendall_shutdown_write_then_read_same_connection(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.run_cli()
        (sock,) = self.sockets
        self.assertEqual(self.connects, [(ipc.HOST_SOCKET_PATH, ipc.CLIENT_CONNECT_DEADLINE_S)])
        events = [e for e in sock.events if e != "settimeout"]
        self.assertEqual(events[:2], ["sendall", ("shutdown", socket.SHUT_WR)])
        self.assertTrue(all(e == "recv" for e in events[2:-1]))
        self.assertEqual(events[-1], "close")
        self.assertEqual(sock.sent.count(b'"protocol_version"'), 1)  # exactly one frame

    def test_cli_never_imports_sdk_or_ledger(self):
        forbidden = {"boto3", "botocore", "name_tag_ledger", "name_tag_batch_host_runtime",
                     "name_tag_batch_host_issuer", "name_tag_batch_host_server",
                     "name_tag_batch_runtime", "name_tag_batch_live",
                     "name_tag_batch_credentials", "name_tag_batch_iam_evidence"}
        imported = set()
        for node in ast.walk(ast.parse(CLI_SOURCE)):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertEqual(imported & forbidden, set())
        names = set(cli._batch_live.__code__.co_names)
        for helper in (cli._local_live_shape_check, cli._live_summary):
            names |= set(helper.__code__.co_names)
        for name in ("IntentLedger", "VerifiedHostRuntime", "open_verified_host_runtime",
                     "load_current_protected_owner_trust", "verify_batch_approval",
                     "execute_batch_live", "HostBatchCredentialIssuer", "OwnerTrust"):
            self.assertNotIn(name, names)
        # Behavioural: no Owner verifier, Ledger, Host runtime or SDK is touched on this path.
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        boom = AssertionError("batch-live must not reach this")
        with mock.patch.dict(sys.modules, {"boto3": None, "botocore": None}), \
                mock.patch("name_tag_batch_trust.load_current_protected_owner_trust",
                           side_effect=boom), \
                mock.patch("name_tag_batch_approval.verify_batch_approval", side_effect=boom), \
                mock.patch("name_tag_ledger.open_ledger", side_effect=boom), \
                mock.patch("name_tag_batch_runtime.execute_batch_live", side_effect=boom), \
                mock.patch.object(host_runtime, "open_verified_host_runtime", side_effect=boom):
            self.assertEqual(self.run_cli(), 0)

    def test_cli_cannot_choose_socket_or_env_grant(self):
        for extra in (["--socket", "/tmp/evil.sock"], ["--socket-path", "x"],
                      ["--grant", "g"], ["--credentials", "c"], ["--sock", "x"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                self.run_cli(LIVE_ARGS + extra)
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        env = {"AWS_CNT_HOST_SOCKET": "/tmp/evil.sock", "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE",
               "AWS_SECRET_ACCESS_KEY": "secret-value", "AWS_SESSION_TOKEN": "token-value",
               "AWS_CNT_GRANT": "grant"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(self.run_cli(), 0)
        self.assertEqual([p for p, _ in self.connects], [ipc.HOST_SOCKET_PATH])
        self.assertEqual(self.client_factory_args, [((), {})])
        wire = self.sockets[0].sent + (self.root / "live.json").read_bytes()
        for value in env.values():
            self.assertNotIn(value.encode(), wire)

    def test_connect_header_body_response_timeout_fail_closed(self):
        self.connect_error = TimeoutError()
        self.assertEqual(self.run_cli(out="c.json"), 3)
        self.assertEqual((self.summary("c.json")["status"], self.summary("c.json")["code"]),
                         ("UNKNOWN", "IPC_TIMEOUT"))
        self.connect_error = None
        # Host header deadline (nothing arrives) and body/EOF deadline: BLOCKED pre-accept.
        for name, view in (("h.json", lambda data: b""), ("b.json", lambda data: data[:9])):
            self.socket_kwargs = {"host_view": view, "conn_kwargs": {"at_end": "timeout"}}
            self.assertEqual(self.run_cli(out=name), 2)
            self.assertEqual((self.summary(name)["status"], self.summary(name)["code"]),
                             ("BLOCKED", "IPC_TIMEOUT"))
        self.assertEqual(self.endpoint.calls, [])
        # Client 120 s response deadline: UNKNOWN even though the Host already ran.
        self.socket_kwargs = {"reply_mode": "hang"}
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.assertEqual(self.run_cli(out="r.json"), 3)
        doc = self.summary("r.json")
        self.assertEqual((doc["status"], doc["code"], doc["report_sha256"]),
                         ("UNKNOWN", "IPC_TIMEOUT", None))
        self.assert_never_success_claim(doc)
        self.assertEqual(len(self.endpoint.calls), 1)

    def test_partial_reply_or_disconnect_unknown_not_success(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        for index, cut in enumerate((0, 3, 4, 20)):
            with self.subTest(cut=cut):
                self.endpoint.seen_batches.clear()
                self.socket_kwargs = {"truncate_to": cut}
                name = f"p{index}.json"
                self.assertEqual(self.run_cli(out=name), 3)
                doc = self.summary(name)
                self.assertEqual(doc["status"], "UNKNOWN")
                self.assertIn(doc["code"], ("IPC_RESPONSE_LOST", "IPC_TIMEOUT"))
                self.assertIsNone(doc["batch_id"])
                self.assert_never_success_claim(doc)
                self.assertEqual(self.sockets[-1].host_reply.status, "COMPLETE")

    def test_no_auto_retry_on_same_or_new_request_id(self):
        self.socket_kwargs = {"reply_mode": "lost"}
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        with mock.patch.object(UnixBatchHostClient, "execute", autospec=True,
                               side_effect=UnixBatchHostClient.execute) as spy:
            self.assertEqual(self.run_cli(), 3)
        self.assertEqual(spy.call_count, 1)
        self.assertEqual((len(self.connects), len(self.endpoint.calls)), (1, 1))
        self.assertEqual(len(self.clients), 1)

    def test_duplicate_batch_command_refused_by_fake_ledger(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.assertEqual(self.run_cli(out="first.json"), 0)
        self.assertEqual(self.run_cli(out="second.json"), 2)
        second = self.summary("second.json")
        self.assertEqual((second["status"], second["code"]), ("BLOCKED", "BLOCKED_BATCH_REPLAY"))
        self.assert_never_success_claim(second)
        self.assertEqual(self.endpoint.durable, ["APPLIED_VERIFIED"])

    def test_lost_reply_client_unknown_host_terminal_unchanged(self):
        self.socket_kwargs = {"reply_mode": "lost"}
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.assertEqual(self.run_cli(), 3)
        doc = self.summary()
        self.assertEqual((doc["status"], doc["code"]), ("UNKNOWN", "IPC_RESPONSE_LOST"))
        self.assert_never_success_claim(doc)
        self.assertEqual(self.sockets[0].host_reply.status, "COMPLETE")
        self.assertEqual(self.endpoint.durable, ["APPLIED_VERIFIED"])
        self.assertEqual(self.rig.server.response_write_failures, 0)

    def test_post_permit_missing_durable_readback_unknown_stop_hold(self):
        ledger = {"batch": "ACTIVE", "scope": "CLEARED"}

        def stop_hold():
            ledger.update(batch="STOPPED", scope="HOLD")
        self.endpoint.hook = stop_hold
        self.endpoint.error = HostOutcomeUnknown("OUTCOME_UNKNOWN", "post-Permit readback missing",
                                                 batch_id=self.batch_id)
        self.assertEqual(self.run_cli(), 3)
        doc = self.summary()
        self.assertEqual((doc["status"], doc["code"], doc["batch_id"], doc["report_sha256"]),
                         ("UNKNOWN", "OUTCOME_UNKNOWN", self.batch_id, None))
        self.assert_never_success_claim(doc)
        self.assertEqual(ledger, {"batch": "STOPPED", "scope": "HOLD"})
        self.assertEqual(len(self.connects), 1)


# ================================================================ RG-PRC-005/006
class SubsetSelectionTests(LiveCase):
    def test_ipc_v1_has_no_subset_or_session_name_fields(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.run_cli()
        request = self.sent_request()
        self.assertEqual(set(request), {"protocol_version", "command", "request_id", "plan_b64",
                                        "review_csv_b64", "owner_envelope_b64"})
        self.assertEqual((request["protocol_version"], request["command"]),
                         (1, "execute_signed_batch"))
        self.assertEqual(base64.b64decode(request["plan_b64"]), self.plan)

    def test_extra_subset_field_rejected_before_owner_or_sts(self):
        def add_subset(data):
            body = json.loads(data[4:])
            body["row_indexes"] = [0]
            raw = json.dumps(body, separators=(",", ":")).encode()
            return len(raw).to_bytes(4, "big") + raw
        self.socket_kwargs = {"host_view": add_subset}
        self.assertEqual(self.run_cli(), 2)
        doc = self.summary()
        self.assertEqual((doc["status"], doc["code"]), ("BLOCKED", "IPC_BAD_PAYLOAD"))
        self.assertEqual(self.endpoint.calls, [])
        self.assertNotIn("endpoint", self.rig.events)

    def test_cli_cannot_change_host_selected_index(self):
        for extra in (["--row-index", "1"], ["--subset", "0,1"], ["--role-session-name", "x"],
                      ["--policy", "p.json"], ["--request-id", "1" * 32]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                self.run_cli(LIVE_ARGS + extra)
        self.assertEqual(self.connects, [])

    def test_changed_request_id_cannot_reissue_sts_for_same_batch(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.run_cli(out="a.json")
        self.run_cli(out="b.json")
        ids = {self.summary("a.json")["request_id"], self.summary("b.json")["request_id"]}
        self.assertEqual(len(ids), 2)  # request_id is correlation only
        self.assertEqual(self.summary("b.json")["code"], "BLOCKED_BATCH_REPLAY")
        self.assertEqual(self.endpoint.durable, ["APPLIED_VERIFIED"])

    def test_cli_does_not_retry_blocked_subset(self):
        self.endpoint.error = HostRuntimeBlocked("BLOCKED_SCOPE_MISMATCH", "selected row refused")
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.summary()["code"], "BLOCKED_SCOPE_MISMATCH")
        self.assertEqual((len(self.connects), len(self.endpoint.calls)), (1, 1))


# ================================================================ RG-PRC-008
class StatusSemanticsTests(LiveCase):
    def test_partial_success_blocked_reply_still_reports_applied_row(self):
        self.endpoint.error = HostRuntimeBlocked("AWS_RUNTIME_NOT_AUTHORIZED", "row 2 refused",
                                                 batch_id=self.batch_id, report_sha256=REPORT)
        self.assertEqual(self.run_cli(), 2)
        doc = self.summary()
        self.assertEqual((doc["status"], doc["batch_id"], doc["report_sha256"]),
                         ("BLOCKED", self.batch_id, REPORT))
        self.assert_never_success_claim(doc)
        self.assertIn("earlier rows", doc["status_meaning"].lower())
        self.assertEqual(self.endpoint.durable, ["APPLIED_VERIFIED"])

    def test_cli_blocked_never_implies_zero_writes(self):
        self.connect_error = FileNotFoundError(ipc.HOST_SOCKET_PATH)
        self.assertEqual(self.run_cli(out="m.json"), 2)
        self.connect_error = None
        self.endpoint.error = HostRuntimeBlocked("BLOCKED_SCOPE_MISMATCH")
        self.assertEqual(self.run_cli(out="s.json"), 2)
        for name in ("m.json", "s.json"):
            doc = self.summary(name)
            self.assertEqual(doc["status"], "BLOCKED")
            self.assert_never_success_claim(doc)
            self.assertNotIn("no write", doc["status_meaning"].lower())
        self.assertNotIn("zero", self.stdout.lower())

    def test_cli_complete_not_all_rows_applied(self):
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT},
                                          outcomes=("APPLIED_VERIFIED", "NOT_ATTEMPTED_CAP"))
        self.assertEqual(self.run_cli(), 0)
        doc = self.summary()
        self.assertEqual(doc["status"], "COMPLETE")
        self.assert_never_success_claim(doc)
        self.assertIn("not that every row", doc["status_meaning"])
        self.assertNotIn("rows", doc)  # no per-row claims from the transport reply

    def test_response_loss_preserves_host_terminal_and_client_unknown(self):
        self.socket_kwargs = {"reply_mode": "lost"}
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        self.assertEqual(self.run_cli(out="lost.json"), 3)
        self.socket_kwargs = {}
        self.assertEqual(self.run_cli(out="again.json"), 2)  # manual re-run: Ledger refuses
        self.assertEqual(self.summary("lost.json")["status"], "UNKNOWN")
        self.assertEqual(self.summary("again.json")["code"], "BLOCKED_BATCH_REPLAY")
        self.assertEqual(self.endpoint.durable, ["APPLIED_VERIFIED"])

    def test_no_auto_retry_complete_blocked_unknown(self):
        cases = (("complete.json", {}, None), ("blocked.json", {},
                                                HostRuntimeBlocked("BLOCKED_SCOPE_MISMATCH")),
                 ("unknown.json", {"reply_mode": "lost"}, None))
        for name, kwargs, error in cases:
            with self.subTest(name=name):
                self.connects.clear()
                self.endpoint.calls.clear()
                self.endpoint.seen_batches.clear()
                self.endpoint.error = error
                self.endpoint.result = run_result({"batch_id": self.batch_id,
                                                   "report_sha256": REPORT})
                self.socket_kwargs = kwargs
                self.run_cli(out=name)
                self.assertEqual((len(self.connects), len(self.endpoint.calls)), (1, 1))


# ================================================================ Finding 004
class HostAuthorityTests(LiveCase):
    def test_batch_live_missing_socket_fail_closed(self):
        self.connect_error = FileNotFoundError(ipc.HOST_SOCKET_PATH)
        self.assertEqual(self.run_cli(), 2)
        doc = self.summary()
        self.assertEqual((doc["status"], doc["code"]), ("BLOCKED", "IPC_SOCKET_UNAVAILABLE"))
        self.assert_never_success_claim(doc)
        self.assertEqual(len(self.connects), 1)
        self.assertEqual(self.endpoint.calls, [])

    def test_batch_live_cli_cannot_create_grant_or_sdk_client(self):
        for pattern in ("boto3", "botocore", "assume_role", "AssumeRole", "LiveWriteGrant",
                        "HostBatchCredentialIssuer", "open_verified_host_runtime",
                        "ProtectedBatchHostEndpoint", "HostLedgerBatchCoordinator",
                        "execute_batch_live"):
            self.assertNotIn(pattern, CLI_SOURCE)
        self.endpoint.result = run_result({"batch_id": self.batch_id, "report_sha256": REPORT})
        boom = AssertionError("no grant/SDK on the client")
        with mock.patch("name_tag_batch_host_issuer.HostBatchCredentialIssuer.issue",
                        side_effect=boom), \
                mock.patch.dict(sys.modules, {"boto3": None, "botocore": None}):
            self.assertEqual(self.run_cli(), 0)

    def test_cli_supplied_host_runtime_path_ignored_and_rejected(self):
        for extra in (["--host-runtime", "x"], ["--manifest", "m.json"], ["--state-dir", "."],
                      ["--host-manifest", "m.json"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                self.run_cli(LIVE_ARGS + extra)
        (self.root / "host-manifest.json").write_text('{"schema":"aws-cnt-host-manifest-v1"}')
        self.endpoint = host_runtime.production_host_endpoint()
        with mock.patch.dict(os.environ, {"AWS_CNT_HOST_MANIFEST": "host-manifest.json",
                                          "AWS_CNT_STATE_DIRECTORY": str(self.root)}):
            self.assertEqual(self.run_cli(), 2)
        self.assertEqual(self.summary()["code"], "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_unix_socket_peer_check_not_owner_approval(self):
        # An admitted local peer with an unsigned envelope still meets Owner re-verification.
        h = IssuerHarness(self)
        coordinator = mock.Mock()
        self.endpoint = ProtectedBatchHostEndpoint(issuer=h.issuer, coordinator=coordinator)
        self.rig.bootstrap.host = h.host
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()):
            self.assertEqual(self.run_cli(out="peer.json"), 2)
        self.assertEqual(self.summary("peer.json")["code"], "BLOCKED_OWNER_AUTHN")
        coordinator.run_signed_batch.assert_not_called()
        # A rejected peer never reaches the endpoint at all.
        self.socket_kwargs = {"conn_kwargs": {"uid": 4321, "gid": 4321}}
        self.endpoint = self.rig.endpoint
        self.assertEqual(self.run_cli(out="rejected.json"), 2)
        self.assertEqual(self.summary("rejected.json")["code"], "IPC_PEER_REJECTED")
        self.assertEqual(self.rig.endpoint.calls, [])

    def test_old_offline_commands_unchanged(self):
        before = ("prepare-batch", "batch-dryrun", "verify-batch", "batch-simulate")
        parser = cli._build_parser()
        subs = next(a for a in parser._actions if a.dest == "command")
        self.assertEqual(tuple(subs.choices)[:4], before)
        self.assertEqual(set(subs.choices), set(before) | {"batch-live"})
        for command in before:
            options = {o for a in subs.choices[command]._actions for o in a.option_strings}
            self.assertNotIn("--live-opt-in", options)
        # verify-batch still fails closed offline with no envelope (unchanged behaviour).
        args = ["verify-batch", "--plan", "plan.json", "--review", "review.csv",
                "--envelope", "none", "--report-out", "v.json"]
        self.assertEqual(self.run_cli(args, out="v.json"), 2)
        self.assertIn("BLOCKED (offline)", self.stderr)
        self.assertEqual(self.clients, [])

    def test_host_only_endpoint_uses_existing_coordinator(self):
        # No Host-internal entry point is exposed to or imported by the CLI.
        self.assertFalse(hasattr(cli, "execute_batch_live_from_host"))
        self.assertNotIn("execute_batch_live", CLI_SOURCE)
        # Real Task 6 server -> real endpoint -> the single Coordinator (fake) behind it.
        h = IssuerHarness(self)
        coordinator = mock.Mock()
        coordinator.run_signed_batch.return_value = run_result(
            {"batch_id": self.batch_id, "report_sha256": REPORT})
        self.endpoint = ProtectedBatchHostEndpoint(issuer=h.issuer, coordinator=coordinator)
        self.rig.bootstrap.host = h.host
        verified = object()
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()), \
                mock.patch("name_tag_batch_approval.verify_batch_approval",
                           return_value=verified) as verify:
            self.assertEqual(self.run_cli(), 0)
        args = verify.call_args.args
        self.assertEqual(args, (self.plan, self.csv, self.envelope))
        coordinator.run_signed_batch.assert_called_once()
        self.assertIs(coordinator.run_signed_batch.call_args.args[0], verified)
        self.assertIs(coordinator.run_signed_batch.call_args.kwargs["issuer"], h.issuer)


if __name__ == "__main__":
    unittest.main()
