"""Task 8: Owner-authenticated, root-controlled, READ-ONLY Host report recovery.

Reports are produced by the real Task 7 Coordinator over a real temporary Ledger v2 and the
Fake Host StateDirectory (temp dir) of ``LiveHarness``; Owner signatures are real OpenSSH
signatures over test keys. No STS, AWS, socket, /var or /run access happens here.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

import name_tag_batch_report_reader as reader_mod
import name_tag_batch_runtime as batch_runtime
from name_tag_approval import EnrolledOwner, OwnerTrust
from name_tag_batch_approval import BATCH_NAMESPACE, canonical_bytes
from name_tag_batch_host_runtime import HostRuntimeBlocked
from name_tag_batch_report_reader import (
    READ_NAMESPACE, HostReportReader, ReportReadDenied, prepare_report_read_authorization)
from name_tag_ledger import SCOPE_DECISION_NAMESPACE
from test_name_tag_batch_ledger import volume_record
from test_name_tag_batch_live_runtime import LiveHarness

READER_SOURCE = Path(reader_mod.__file__).read_text(encoding="utf-8")


def _utc(value):
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class ReaderHarness(LiveHarness):
    def setUp(self):
        super().setUp()
        self.read_trust = self.make_trust()

    def make_trust(self, *, role="batch-approver", revoked=False, read_namespace=True):
        namespaces = [BATCH_NAMESPACE, SCOPE_DECISION_NAMESPACE]
        if read_namespace:
            namespaces.append(READ_NAMESPACE)
        path = self.root / f"read-allowed-signers-{role}-{revoked}-{read_namespace}"
        path.write_text(f'batch-owner namespaces="{",".join(namespaces)}" '
                        f'{self.batch_public_key}\n')
        path.chmod(0o600)
        return OwnerTrust.from_allowed_signers(
            path, pinned_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            enrolled={"batch-owner": {self.batch_fingerprint: EnrolledOwner(
                self.batch_fingerprint, role, revoked)}},
            expected_uid=os.getuid())

    def read_auth(self, batch_id, expected=None, *, namespace=READ_NAMESPACE,
                  lifetime=timedelta(minutes=10), issued_offset=timedelta(minutes=1),
                  owner="batch-owner", tamper=None):
        issued = self.clock_now - issued_offset
        fields = dict(
            batch_id=batch_id, expected_report_sha256=expected, owner_principal_id=owner,
            owner_key_fingerprint=self.batch_fingerprint, issued_at_utc=_utc(issued),
            expires_at_utc=_utc(issued + lifetime), read_nonce=os.urandom(16).hex())
        if lifetime <= reader_mod.MAX_READ_AUTHORIZATION_LIFETIME:
            canonical = prepare_report_read_authorization(**fields)
        else:  # deliberately invalid artifact the helper refuses to prepare
            canonical = canonical_bytes({"schema_version": 1, "purpose": READ_NAMESPACE,
                                         "allowed_role": "batch-approver", **fields})
        signature = self._sign(self.batch_key_path, canonical, namespace)
        payload = json.loads(canonical)
        if tamper:
            payload.update(tamper)
        return json.dumps({"payload": payload,
                           "authorization_id": hashlib.sha256(canonical).hexdigest(),
                           "signature_ref": base64.b64encode(signature).decode("ascii")},
                          separators=(",", ":")).encode()

    def reader(self, *, trust=None, ledger="default"):
        return HostReportReader(
            probe=self.fx.os, manifest_path=self.fx.os.manifest_path,
            manifest_sha256=self.fx.os.manifest_sha256,
            trust_loader=lambda: trust or self.read_trust,
            ledger=self.ledger if ledger == "default" else ledger, clock=self.clock)

    def recover(self, batch, auth, *, envelope=None, **kw):
        with self.trusted():
            return self.reader(**kw).recover(
                plan_bytes=batch.plan_bytes, csv_bytes=batch.csv_bytes,
                envelope_bytes=envelope or batch.raw_envelope_bytes,
                read_authorization_bytes=auth)

    def report_dir(self, batch):
        return Path(self.fx.state_dir) / batch_runtime.HOST_REPORTS_DIRNAME / batch.batch_id

    def completed_with_lost_reply(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        response, server = self.serve_once(batch)  # reply lost: client-local UNKNOWN
        self.assertEqual(server.response_write_failures, 1)
        return batch, response


class ReportRecoveryTests(ReaderHarness):
    def test_unknown_full_reply_loss_owner_lookup_by_signed_batch_id(self):
        batch, lost = self.completed_with_lost_reply()
        # The client saw nothing: no batch_id/report digest is supplied by the Owner.
        result = self.recover(batch, self.read_auth(batch.batch_id, None))
        self.assertEqual((result["recovery_status"], result["code"]),
                         ("VERIFIED", "REPORT_VERIFIED"))
        self.assertEqual(result["digest_source"], "HOST_INDEX_ONLY")
        self.assertEqual(result["batch_id"], batch.batch_id)
        self.assertEqual(result["report_sha256"], lost.report_sha256)  # Host index digest
        self.assertEqual(result["row_ledger_outcomes"], [[0, "APPLIED_VERIFIED"]])
        self.assertEqual((result["send_attempts_consumed"], result["max_send_attempts"]), (1, 1))
        self.assertIs(result["zero_writes_inferred"], False)
        self.assertIs(result["execution_allowed"], False)
        index = json.loads((self.report_dir(batch) / "index.json").read_bytes())
        self.assertEqual(index["report_sha256"], result["report_sha256"])
        self.assertEqual(len(self.cloud.writes), 1)

    def test_unknown_with_digest_exact_report_hash(self):
        batch, lost = self.completed_with_lost_reply()
        result = self.recover(batch, self.read_auth(batch.batch_id, lost.report_sha256))
        self.assertEqual(result["recovery_status"], "VERIFIED")
        self.assertEqual(result["digest_source"], "REPLY_DIGEST_AND_HOST_INDEX")
        stored = (self.report_dir(batch) / f"{lost.report_sha256}.json").read_bytes()
        self.assertEqual(batch_runtime.host_report_sha256(stored), result["report_sha256"])
        self.assertEqual(json.loads(stored), result["report"])
        wrong = self.recover(batch, self.read_auth(batch.batch_id, "e" * 64))
        self.assertEqual((wrong["recovery_status"], wrong["code"], wrong["report"]),
                         ("NOT_VERIFIED", "REPORT_DIGEST_MISMATCH", None))

    def test_report_digest_tamper_or_other_batch_denied(self):
        batch, lost = self.completed_with_lost_reply()
        with self.trusted():
            other = self.make_batch([volume_record(1)], cap=1, nonce=os.urandom(16).hex())
        directory = self.report_dir(batch)
        path = directory / f"{lost.report_sha256}.json"
        original = path.read_bytes()
        # (1) Tampered report bytes: digest no longer matches index -> nothing exposed.
        path.write_bytes(original.replace(b'"APPLIED_VERIFIED"', b'"NOT_ATTEMPTED_CAP"', 1))
        tampered = self.recover(batch, self.read_auth(batch.batch_id))
        self.assertEqual((tampered["recovery_status"], tampered["code"], tampered["report"]),
                         ("NOT_VERIFIED", "REPORT_DIGEST_MISMATCH", None))
        path.write_bytes(original)
        # (2) A forged report for another Batch planted under this index (digest recomputed).
        forged = json.loads(original)
        forged["batch_id"] = other.batch_id
        forged_bytes = canonical_bytes(forged)
        forged_digest = batch_runtime.host_report_sha256(forged_bytes)
        (directory / f"{forged_digest}.json").write_bytes(forged_bytes)
        (directory / f"{forged_digest}.json").chmod(0o600)
        index_path = directory / "index.json"
        index_bytes = index_path.read_bytes()
        index_path.write_bytes(index_bytes.replace(lost.report_sha256.encode(),
                                                   forged_digest.encode()))
        planted = self.recover(batch, self.read_auth(batch.batch_id))
        self.assertEqual((planted["recovery_status"], planted["code"]),
                         ("NOT_VERIFIED", "REPORT_IDENTITY_MISMATCH"))
        index_path.write_bytes(index_bytes)
        # (3) Symlinked report file is never followed.
        path.rename(directory / "moved.json")
        path.symlink_to(directory / "moved.json")
        linked = self.recover(batch, self.read_auth(batch.batch_id))
        self.assertEqual(linked["recovery_status"], "NOT_VERIFIED")
        path.unlink()
        (directory / "moved.json").rename(path)
        # (4) Read authorization scoped to another Batch: denied before any storage read.
        with mock.patch.object(HostReportReader, "_verified_report",
                               side_effect=AssertionError("storage read")):
            with self.assertRaises(ReportReadDenied) as caught:
                self.recover(batch, self.read_auth(other.batch_id))
        self.assertEqual(caught.exception.code, "BLOCKED_REPORT_SCOPE")
        # (5) Untampered state verifies again.
        self.assertEqual(self.recover(batch, self.read_auth(batch.batch_id))["recovery_status"],
                         "VERIFIED")

    def test_owner_revoked_or_wrong_role_report_read_denied(self):
        batch, _ = self.completed_with_lost_reply()
        auth = self.read_auth(batch.batch_id)
        denied = {
            "revoked": dict(trust=self.make_trust(revoked=True)),
            "wrong_role": dict(trust=self.make_trust(role="ledger-migrator")),
            "namespace_not_enrolled": dict(trust=self.make_trust(read_namespace=False)),
        }
        for name, kw in denied.items():
            with self.subTest(name=name), self.assertRaises(ReportReadDenied):
                self.recover(batch, auth, **kw)
        for name, raw in (
                ("batch_namespace_signature", self.read_auth(batch.batch_id,
                                                             namespace=BATCH_NAMESPACE)),
                ("expired", self.read_auth(batch.batch_id, issued_offset=timedelta(minutes=20))),
                ("too_long_lived", self.read_auth(batch.batch_id, lifetime=timedelta(hours=1))),
                ("payload_altered", self.read_auth(batch.batch_id,
                                                   tamper={"expected_report_sha256": "f" * 64})),
                ("unsigned", json.dumps({"batch_id": batch.batch_id}).encode())):
            with self.subTest(name=name), self.assertRaises(ReportReadDenied):
                self.recover(batch, raw)
        # The original Batch envelope must still verify: a forged envelope is denied.
        forged = batch.raw_envelope_bytes.replace(b'"signature_ref":"', b'"signature_ref":"AAAA')
        with self.assertRaises(ReportReadDenied):
            self.recover(batch, auth, envelope=forged)

    def test_read_namespace_signature_cannot_be_batch_envelope(self):
        """Reverse of the batch_namespace_signature case: namespaces are not interchangeable."""
        from name_tag_batch_approval import BatchAuthRejected, verify_batch_approval
        batch = self.prepare(cap=1, records=[volume_record(0)])
        envelope = json.loads(batch.raw_envelope_bytes)

        def signed_with(namespace):
            signature = self._sign(self.batch_key_path, batch.canonical_payload_bytes, namespace)
            return json.dumps({**envelope, "signature_ref": base64.b64encode(signature).decode()},
                              separators=(",", ":")).encode()
        # The key is enrolled for both namespaces, so only the namespace check can deny.
        verified = verify_batch_approval(batch.plan_bytes, batch.csv_bytes,
                                         signed_with(BATCH_NAMESPACE), trust=self.read_trust,
                                         now_utc=self.clock_now)
        self.assertEqual(verified.batch_id, batch.batch_id)
        with self.assertRaises(BatchAuthRejected):
            verify_batch_approval(batch.plan_bytes, batch.csv_bytes, signed_with(READ_NAMESPACE),
                                  trust=self.read_trust, now_utc=self.clock_now)
        with self.assertRaises(ReportReadDenied):  # and the reader denies it as an envelope
            self.recover(batch, self.read_auth(batch.batch_id),
                         envelope=signed_with(READ_NAMESPACE))

    def test_read_only_report_command_never_calls_execution_ipc_or_sts(self):
        imported = set()
        for node in ast.walk(ast.parse(READER_SOURCE)):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add((node.module or "").split(".")[0])
        self.assertEqual(imported & {"boto3", "botocore", "socket", "name_tag_batch_ipc",
                                     "name_tag_batch_host_server", "name_tag_batch_host_issuer",
                                     "name_tag_batch_live", "subprocess"}, set())
        batch, _ = self.completed_with_lost_reply()
        intents_before = self.sql("SELECT * FROM intents")
        state_before = self.state(batch)
        sts_before, writes_before = len(self.sts.calls), len(self.cloud.writes)
        boom = AssertionError("read-only recovery reached an execution path")
        with mock.patch("name_tag_batch_ipc.UnixBatchHostClient.execute", side_effect=boom), \
                mock.patch("name_tag_batch_host_runtime.ProtectedBatchHostEndpoint."
                           "execute_signed_batch", side_effect=boom), \
                mock.patch("name_tag_batch_host_server.ProtectedHostIPCServer.serve",
                           side_effect=boom), \
                mock.patch.object(batch_runtime, "execute_batch_live", side_effect=boom), \
                mock.patch.object(self.issuer, "issue", side_effect=boom), \
                mock.patch.object(self.ledger, "create_batch_intent", side_effect=boom), \
                mock.patch.object(self.ledger, "stop_batch", side_effect=boom), \
                mock.patch.object(self.ledger, "hold_scope", side_effect=boom), \
                mock.patch.object(socket, "socket", side_effect=boom):
            result = self.recover(batch, self.read_auth(batch.batch_id))
        self.assertEqual(result["recovery_status"], "VERIFIED")
        self.assertEqual(result["operation"], "READ_ONLY_OWNER_AUTHENTICATED")
        self.assertEqual(self.sql("SELECT * FROM intents"), intents_before)
        self.assertEqual(self.state(batch), state_before)
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)),
                         (sts_before, writes_before))
        # The production wiring has no accepted OS probe/pin: it fails closed.
        with self.trusted(), self.assertRaises(HostRuntimeBlocked):
            prod = reader_mod.production_report_reader()
            prod._trust_loader = lambda: self.read_trust
            prod._clock = self.clock
            prod.recover(plan_bytes=batch.plan_bytes, csv_bytes=batch.csv_bytes,
                         envelope_bytes=batch.raw_envelope_bytes,
                         read_authorization_bytes=self.read_auth(batch.batch_id))

    def test_missing_report_not_verified_not_zero_sends(self):
        batch = self.prepare()
        self.fail_evidence_on = {2}
        with mock.patch.object(batch_runtime, "_persist_host_report", return_value=None):
            self.run_blocked(batch)  # row 1 sent; no verified report -> UNKNOWN
        self.assertEqual(len(self.cloud.writes), 1)
        result = self.recover(batch, self.read_auth(batch.batch_id))
        self.assertEqual((result["recovery_status"], result["code"], result["report"]),
                         ("NOT_VERIFIED", "REPORT_INDEX_ABSENT", None))
        self.assertIs(result["zero_writes_inferred"], False)
        ledger = result["ledger_status"]
        self.assertEqual(ledger["status"], "READ")
        self.assertEqual(ledger["row_outcomes"][0], [0, "APPLIED_VERIFIED"])
        self.assertEqual(ledger["send_attempts_consumed"], 1)
        no_ledger = self.recover(batch, self.read_auth(batch.batch_id), ledger=None)
        self.assertEqual(no_ledger["ledger_status"], {"status": "LEDGER_STATUS_NOT_AVAILABLE"})
        self.assertIs(no_ledger["zero_writes_inferred"], False)

    def test_fifo_is_opened_nonblocking_then_rejected(self):
        fifo = Path(self.root) / "report-fifo"
        os.mkfifo(fifo, 0o600)
        requested_flags = []
        real_open = os.open

        def open_nonblocking_for_test(path, flags, *args, **kwargs):
            requested_flags.append(flags)
            return real_open(path, flags | os.O_NONBLOCK, *args, **kwargs)

        with mock.patch.object(reader_mod.os, "open", side_effect=open_nonblocking_for_test):
            with self.assertRaises(reader_mod._NotVerified) as caught:
                reader_mod._read_protected_file(
                    fifo, os.getuid(), 1024, missing_code="REPORT_FILE_ABSENT")
        self.assertEqual(caught.exception.code, "REPORT_STORAGE_NOT_PROTECTED")
        self.assertTrue(requested_flags[0] & os.O_NONBLOCK)

    def test_read_oserror_returns_not_verified_without_partial_report(self):
        batch, _ = self.completed_with_lost_reply()
        authorization = self.read_auth(batch.batch_id)
        report_fds = set()
        real_open, real_read = os.open, os.read

        def track_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            if batch.batch_id in Path(path).parts:
                report_fds.add(fd)
            return fd

        def fail_report_read(fd, size):
            if fd in report_fds:
                raise OSError("read failed")
            return real_read(fd, size)

        with mock.patch.object(reader_mod.os, "open", side_effect=track_open), \
                mock.patch.object(reader_mod.os, "read", side_effect=fail_report_read):
            result = self.recover(batch, authorization)
        self.assertEqual((result["recovery_status"], result["code"], result["report"]),
                         ("NOT_VERIFIED", "REPORT_STORAGE_NOT_PROTECTED", None))
        self.assertEqual(result["ledger_status"]["status"], "READ")

    def test_partial_success_stop_hold_readback(self):
        batch = self.prepare()
        self.fail_evidence_on = {2}
        blocked = self.run_blocked(batch)  # row 1 APPLIED_VERIFIED, row 2 refused -> STOP
        self.assertIsNotNone(blocked.report_sha256)
        result = self.recover(batch, self.read_auth(batch.batch_id, blocked.report_sha256))
        self.assertEqual(result["recovery_status"], "VERIFIED")
        self.assertEqual(result["row_ledger_outcomes"],
                         [[0, "APPLIED_VERIFIED"], [1, "NOT_ATTEMPTED_BATCH_STOP"]])
        self.assertEqual((result["batch_state"], result["refusal_code"]),
                         ("STOPPED", "AWS_RUNTIME_NOT_AUTHORIZED"))
        self.assertEqual((result["send_attempts_consumed"], result["max_send_attempts"],
                          result["applied_verified_count"]), (1, 2, 1))
        self.assertEqual(result["ledger_status"]["batch_state"], "STOPPED")
        self.assertIn(result["ledger_status"]["scope_states"]["scope-1"],
                      ("CLEARED", "HOLD"))  # reported as read, never rewritten

    def test_report_digest_withheld_until_index_is_durable(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        with mock.patch.object(batch_runtime, "_publish_report_index", return_value=False):
            blocked = self.run_blocked(batch)  # sent, but no durable index -> UNKNOWN
        self.assertEqual((blocked.code, blocked.report_sha256), ("REPORT_NOT_VERIFIED", None))
        self.assertFalse((self.report_dir(batch) / "index.json").exists())
        result = self.recover(batch, self.read_auth(batch.batch_id))
        self.assertEqual((result["recovery_status"], result["code"]),
                         ("NOT_VERIFIED", "REPORT_INDEX_ABSENT"))

    def test_cli_main_writes_private_owner_output_only(self):
        batch, _ = self.completed_with_lost_reply()
        work = Path(self.root) / "admin"
        work.mkdir(mode=0o700)
        for name, data in (("plan.json", batch.plan_bytes), ("review.csv", batch.csv_bytes),
                           ("envelope.json", batch.raw_envelope_bytes),
                           ("read.json", self.read_auth(batch.batch_id))):
            (work / name).write_bytes(data)
            (work / name).chmod(0o600)
        previous = Path.cwd()
        os.chdir(work)
        self.addCleanup(os.chdir, previous)
        argv = ["--plan", "plan.json", "--review", "review.csv", "--envelope", "envelope.json",
                "--read-authorization", "read.json", "--report-out", "owner-report.json"]
        with self.trusted(), mock.patch("sys.stdout"):
            self.assertEqual(reader_mod.main(argv, reader=self.reader()), 0)
        out = work / "owner-report.json"
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(out.read_bytes())["recovery_status"], "VERIFIED")
        with self.trusted(), mock.patch("sys.stderr"):
            self.assertEqual(reader_mod.main(argv, reader=self.reader()), 2)  # never overwrite


class ReportReaderEntrypointTests(unittest.TestCase):
    def test_script_entrypoint_validates_required_arguments(self):
        script = Path(reader_mod.__file__)
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=script.parent,
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage: name_tag_batch_report_reader", result.stderr)


if __name__ == "__main__":
    import unittest
    unittest.main()
