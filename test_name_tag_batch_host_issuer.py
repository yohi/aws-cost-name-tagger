"""Offline Task 6 Host issuer tests. Fake OS/credential/STS transports only; zero network."""
from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import json
import logging
import os
import pickle
import stat
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

import name_tag_batch_host_issuer as issuer_module
import name_tag_batch_host_runtime as host_runtime
from name_tag_batch_host_issuer import (
    HostBatchCredentialIssuer, HostIssuedSession, ProtectedBootstrapCredentials, StsExchange,
    StsRefused, SystemdEncryptedCredentialProvider, derive_role_session_name,
    revalidate_issued_before_intent)
from name_tag_batch_host_runtime import HostRuntimeBlocked
from name_tag_batch_iam import build_subset_session_policy
from name_tag_ledger_errors import LedgerError
from test_name_tag_batch_host_runtime import (
    KIND_REGISTRY, NOW, ROLE_ARN, SVC_UID, build_batch, host_fixture, owner_verified, state)

AKID = "ASIA" + "A" * 16
SECRET = "S" * 40
TOKEN = "T" * 300
CRED_FILE = "aws-bootstrap.json"


def _cred_bytes(**changes) -> bytes:
    body = {"AccessKeyId": AKID, "SecretAccessKey": SECRET, "SessionToken": TOKEN,
            "Expiration": "2026-11-19T13:00:00Z"}
    body.update(changes)
    return json.dumps({k: v for k, v in body.items() if v is not None}).encode()


def install_credentials(fx, data: bytes | None = None, *, owner=SVC_UID, mode=0o400,
                        symlink_free=True) -> None:
    fx.os.add_file(fx.os.cred_dir + "/" + CRED_FILE, _cred_bytes() if data is None else data,
                   owner=owner, mode=mode, symlink_free=symlink_free)


@contextlib.contextmanager
def no_ambient_sdk():
    """Any attempt to build an SDK client/session from ambient configuration fails loudly."""
    boom = AssertionError("ambient SDK credential chain used")
    with mock.patch("boto3.client", side_effect=boom), \
            mock.patch("boto3.resource", side_effect=boom), \
            mock.patch("boto3.session.Session", side_effect=boom), \
            mock.patch("botocore.session.Session", side_effect=boom), \
            mock.patch("botocore.session.get_session", side_effect=boom), \
            mock.patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIAAMBIENTAMBIENT00",
                                         "AWS_SECRET_ACCESS_KEY": "ambient-secret",
                                         "AWS_PROFILE": "ambient",
                                         "CREDENTIALS_DIRECTORY": "/tmp/attacker"}):
        yield


class BootstrapCredentialTests(unittest.TestCase):
    def setUp(self):
        self.fx = host_fixture(self)
        self.provider = SystemdEncryptedCredentialProvider(probe=self.fx.os)

    def test_loads_exact_short_lived_triplet_from_verified_directory(self):
        install_credentials(self.fx)
        host = self.fx.verify()
        creds = self.provider.load(host, now_utc=NOW)
        self.assertIs(type(creds), ProtectedBootstrapCredentials)
        self.assertEqual(creds.access_key_id, AKID)
        self.assertNotIn(SECRET, repr(creds))
        self.assertNotIn(TOKEN, repr(creds))
        for attempt in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(HostRuntimeBlocked):
                attempt(creds)

    def test_encrypted_credential_missing_expired_or_substituted_denied(self):
        cases = {
            "missing": None,
            "expired": dict(data=_cred_bytes(Expiration="2026-11-19T11:59:00Z")),
            "too_long_lived": dict(data=_cred_bytes(Expiration="2026-11-21T12:00:00Z")),
            "long_term_key": dict(data=_cred_bytes(AccessKeyId="AKIA" + "A" * 16)),
            "extra_field": dict(data=_cred_bytes(Region="us-east-1")),
            "missing_token": dict(data=_cred_bytes(SessionToken=None)),
            "duplicate_key": dict(data=b'{"AccessKeyId":"x","AccessKeyId":"y"}'),
            "wrong_owner": dict(owner=SVC_UID + 1),
            "group_readable": dict(mode=0o440),
            "symlink": dict(symlink_free=False),
        }
        for name, case in cases.items():
            with self.subTest(case=name):
                fx = host_fixture(self)
                if case is not None:
                    install_credentials(fx, **case)
                host = fx.verify()
                provider = SystemdEncryptedCredentialProvider(probe=fx.os)
                with self.assertRaises(HostRuntimeBlocked) as caught:
                    provider.load(host, now_utc=NOW)
                self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_environment_directory_hint_is_never_authority(self):
        host = self.fx.verify()
        self.fx.os.add_file("/tmp/attacker/" + CRED_FILE, _cred_bytes(), owner=SVC_UID, mode=0o400)
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/tmp/attacker"}):
            with self.assertRaises(HostRuntimeBlocked):
                self.provider.load(host, now_utc=NOW)

    def test_unverified_host_cannot_load_credentials(self):
        install_credentials(self.fx)
        with self.assertRaises(HostRuntimeBlocked):
            self.provider.load(object(), now_utc=NOW)  # type: ignore[arg-type]

    def test_default_credential_chain_never_used(self):
        install_credentials(self.fx)
        with no_ambient_sdk():
            host = self.fx.verify()
            creds = self.provider.load(host, now_utc=NOW)
        self.assertEqual(creds.access_key_id, AKID)
        self.assertFalse(hasattr(issuer_module, "boto3"))



# ---------------------------------------------------------------- STS / issuer fakes

ISSUED_AKID = "ASIA" + "B" * 16
ISSUED_SECRET = "R" * 40
ISSUED_TOKEN = "Q" * 320
SECRETS = (SECRET, TOKEN, ISSUED_SECRET, ISSUED_TOKEN)


class _Crash(BaseException):
    """Simulated process death in the middle of the STS call."""


class FakeSts:
    """Host-owned STS transport double: records exact bytes, never opens a socket."""

    def __init__(self, fx, *, refuse=None, crash=False, mutate=None, sent=None, error=None):
        self.fx, self.refuse, self.crash, self.mutate = fx, refuse, crash, mutate
        self.sent, self.error = sent, error
        self.calls: list[bytes] = []
        self.pending_seen: list[dict] = []

    def assume_role(self, *, request_bytes, credentials):
        self.calls.append(request_bytes)
        self.fx.events.append("assume_role")
        self.pending_seen.extend(host_runtime.IssuanceAttemptJournal(
            Path(self.fx.state_dir) / "issuance-attempts", service_uid=SVC_UID).scan())
        if self.crash:
            raise _Crash()
        if self.error is not None:
            raise self.error
        if self.refuse:
            raise StsRefused(self.refuse)
        request = json.loads(request_bytes)
        name = request["RoleSessionName"]
        response = {
            "Credentials": {"AccessKeyId": ISSUED_AKID, "SecretAccessKey": ISSUED_SECRET,
                            "SessionToken": ISSUED_TOKEN,
                            "Expiration": NOW + timedelta(seconds=900)},
            "AssumedRoleUser": {"Arn": f"arn:aws:sts::123456789012:assumed-role/Batch/{name}",
                                "AssumedRoleId": "AROA" + "C" * 17 + ":" + name},
        }
        if self.mutate is not None:
            self.mutate(response)
        return StsExchange(sent_request_bytes=self.sent or request_bytes, response=response)


class Gate:
    def __init__(self, *, pre=True, post=True):
        self.pre, self.post, self.calls = pre, post, []

    def check_pre_sts(self, selection, *, now_utc):
        self.calls.append("pre")
        if not self.pre:
            raise HostRuntimeBlocked("G2_NOT_VERIFIED", "fake independent evidence denies")

    def check_issued(self, issued, *, now_utc):
        self.calls.append("post")
        if not self.post:
            raise HostRuntimeBlocked("G2_NOT_VERIFIED", "fake independent evidence denies")


class ClientFactory:
    def __init__(self):
        self.calls = []

    def create(self, service, region, *, access_key_id, secret_access_key, session_token):
        self.calls.append((service, region, access_key_id, secret_access_key, session_token))
        return object()


class IssuerHarness:
    def __init__(self, testcase, *, restart_of=None, sts_kwargs=None, gate=None, batch=None):
        self.fx = host_fixture(testcase, restart_of=None if restart_of is None else restart_of.fx)
        install_credentials(self.fx)
        self.host = self.fx.verify()
        self.batch = batch or build_batch()
        self.fx.ledger.state = state()
        self.sts = FakeSts(self.fx, **(sts_kwargs or {}))
        self.gate = gate or Gate()
        self.factory = ClientFactory()
        self.issuer = HostBatchCredentialIssuer(
            provider=SystemdEncryptedCredentialProvider(probe=self.fx.os), transport=self.sts,
            evidence_gate=self.gate, client_factory=self.factory)

    def select(self, batch=None):
        with owner_verified():
            return host_runtime.select_next_sts_subset(
                batch or self.batch, ledger=self.fx.ledger, kind_registry=KIND_REGISTRY,
                host=self.host, now_utc=NOW)

    def issue(self, subset=None, batch=None):
        batch = batch or self.batch
        subset = subset or self.select(batch)
        with owner_verified():
            return self.issuer.issue(batch, subset, self.host, NOW)

    def revalidate(self, issued):
        with owner_verified():
            return revalidate_issued_before_intent(
                issued, ledger=self.fx.ledger, host=self.host, now_utc=NOW)

    def records(self):
        return host_runtime.IssuanceAttemptJournal(
            Path(self.fx.state_dir) / "issuance-attempts", service_uid=SVC_UID).scan()

    def journal_bytes(self) -> bytes:
        root = Path(self.fx.state_dir) / "issuance-attempts"
        return b"".join(p.read_bytes() for p in sorted(root.rglob("*.json")))


class SessionNameTests(unittest.TestCase):
    def test_nonce_32_64_128_yield_valid_64_char_session_name(self):
        for length in (32, 64, 128):
            nonce = ("0123456789abcdef" * 8)[:length]
            name = derive_role_session_name(nonce)
            expected = "cnt-" + hashlib.sha256(
                b"aws-cnt-role-session-v1\x00" + nonce.encode("ascii")).hexdigest()[:60]
            self.assertEqual(name, expected)
            self.assertEqual(len(name), 64)
            self.assertRegex(name, r"\A[\w+=,.@-]{2,64}\Z")
        for bad in ("AB" * 16, "ab" * 15, "a" * 129, "g" * 32, 123):
            with self.assertRaises(HostRuntimeBlocked):
                derive_role_session_name(bad)  # type: ignore[arg-type]

    def test_nonce_not_modified_or_resigned(self):
        h = IssuerHarness(self)
        before = dict(h.batch.payload)
        issued = h.issue()
        self.assertEqual(dict(h.batch.payload), before)
        self.assertEqual(issued.receipt.batch_nonce, before["batch_nonce"])
        self.assertEqual(issued.receipt.batch_nonce_sha256,
                         hashlib.sha256(before["batch_nonce"].encode()).hexdigest())
        request = json.loads(h.sts.calls[0])
        self.assertEqual(request["RoleSessionName"], derive_role_session_name(before["batch_nonce"]))
        self.assertNotIn(before["batch_nonce"].encode(), h.sts.calls[0])


class IssuerTests(unittest.TestCase):
    def test_actual_sts_request_bytes_bound_to_response_receipt(self):
        h = IssuerHarness(self)
        subset = h.select()
        issued = h.issue(subset)
        receipt = issued.receipt
        self.assertEqual(receipt.request_sha256, hashlib.sha256(h.sts.calls[0]).hexdigest())
        self.assertEqual(receipt.policy_sha256, subset.policy_sha256)
        self.assertEqual(receipt.row_index, 0)
        self.assertEqual(receipt.host_id, h.host.host_id)
        self.assertEqual(receipt.run_id, h.host.run_id)
        self.assertEqual(receipt.role_arn, ROLE_ARN)
        self.assertEqual(receipt.assumed_role_id.split(":")[1], receipt.role_session_name)
        (record,) = h.records()
        self.assertEqual(record["status"], "ISSUED_VERIFIED")
        self.assertEqual(record["receipt_sha256"], receipt.receipt_sha256)
        self.assertEqual(record["response_sha256"], receipt.response_sha256)
        self.assertEqual(record["name_evidence_sha256"], receipt.name_evidence_sha256)
        self.assertEqual(receipt.credential_fingerprint, issuer_module._credential_fingerprint(
            ISSUED_AKID, ISSUED_SECRET, ISSUED_TOKEN))
        issued.sdk_client("ec2", "ap-northeast-1", now_utc=NOW)
        self.assertEqual(h.factory.calls, [("ec2", "ap-northeast-1", ISSUED_AKID,
                                            ISSUED_SECRET, ISSUED_TOKEN)])
        self.assertTrue(issuer_module.verify_receipt(receipt))
        self.assertFalse(issuer_module.verify_receipt(replace(receipt, row_index=1)))

    def test_assume_role_single_call_exact_parameters(self):
        h = IssuerHarness(self)
        subset = h.select()
        h.issue(subset)
        self.assertEqual(len(h.sts.calls), 1)
        self.assertEqual(json.loads(h.sts.calls[0]), {
            "Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": ROLE_ARN,
            "RoleSessionName": derive_role_session_name(h.batch.payload["batch_nonce"]),
            "Policy": subset.policy_bytes.decode("ascii"), "DurationSeconds": 900})

    def test_pre_sts_does_not_require_packed_metric(self):
        h = IssuerHarness(self)
        issued = h.issue()  # the Fake response carries no PackedPolicySize at all
        self.assertIs(type(issued), HostIssuedSession)
        h2 = IssuerHarness(self, sts_kwargs={"mutate": lambda r: r.update(PackedPolicySize=99)})
        self.assertIs(type(h2.issue()), HostIssuedSession)

    def test_assume_role_packed_policy_too_large_no_intent(self):
        h = IssuerHarness(self, sts_kwargs={"refuse": "PackedPolicyTooLarge"})
        with self.assertRaises(HostRuntimeBlocked) as caught:
            h.issue()
        self.assertEqual(caught.exception.code, "AWS_WRITE_BLOCKED")
        self.assertEqual(len(h.sts.calls), 1)
        (record,) = h.records()
        self.assertEqual((record["status"], record["refusal_code"]),
                         ("ISSUANCE_REFUSED", "PackedPolicyTooLarge"))
        self.assertNotIn("create_batch_intent", h.fx.ledger.calls)
        with self.assertRaises(HostRuntimeBlocked):
            h.select()  # no retry, no broader/split policy for the same row
        self.assertEqual(len(h.sts.calls), 1)

    def test_sts_response_wrong_identity_expiration_or_receipt_no_intent(self):
        def creds(**changes):
            return lambda r: r["Credentials"].update(changes)
        mutations = [
            creds(Expiration=NOW - timedelta(seconds=1)),
            creds(Expiration=NOW + timedelta(hours=2)),
            creds(Expiration="not-a-time"),
            creds(AccessKeyId="AKIA" + "B" * 16),
            creds(SessionToken=""),
            lambda r: r.pop("AssumedRoleUser"),
            lambda r: r.update(Unexpected="x"),
        ]
        for n, mutate in enumerate(mutations):
            with self.subTest(n=n):
                h = IssuerHarness(self, sts_kwargs={"mutate": mutate})
                with self.assertRaises(HostRuntimeBlocked):
                    h.issue()
                (record,) = h.records()
                self.assertEqual(record["status"], "ISSUANCE_UNRESOLVED")
        h = IssuerHarness(self, sts_kwargs={"sent": b'{"substituted":true}'})
        with self.assertRaises(HostRuntimeBlocked):
            h.issue()

    def test_sts_wrong_session_suffix_or_role_rejected(self):
        def user(**changes):
            return lambda r: r["AssumedRoleUser"].update(changes)
        good = derive_role_session_name("ab" * 16)
        mutations = [
            user(Arn=f"arn:aws:sts::123456789012:assumed-role/Batch/{good[:-1]}x"),
            user(Arn=f"arn:aws:sts::123456789012:assumed-role/Other/{good}"),
            user(Arn=f"arn:aws:sts::210987654321:assumed-role/Batch/{good}"),
            user(Arn=f"arn:aws-cn:sts::123456789012:assumed-role/Batch/{good}"),
            user(AssumedRoleId="AROA" + "C" * 17 + ":other-session"),
        ]
        for n, mutate in enumerate(mutations):
            with self.subTest(n=n):
                h = IssuerHarness(self, sts_kwargs={"mutate": mutate})
                with self.assertRaises(HostRuntimeBlocked):
                    h.issue()
        h = IssuerHarness(self)
        h.fx.os.manifest["authorized_role_arn"] = "arn:aws:iam::123456789012:role/Other"
        h.fx.repin()
        h.host = h.fx.verify()
        with self.assertRaises(HostRuntimeBlocked):
            h.issue()
        self.assertEqual(h.sts.calls, [])  # wrong fixed RoleArn: refused before STS

    def test_sts_role_session_name_request_response_receipt_binding(self):
        h = IssuerHarness(self)
        issued = h.issue()
        r = issued.receipt
        name = derive_role_session_name(h.batch.payload["batch_nonce"])
        self.assertEqual(r.role_session_name, name)
        self.assertEqual(json.loads(h.sts.calls[0])["RoleSessionName"], name)
        self.assertTrue(r.assumed_role_arn.endswith("/" + name))
        self.assertTrue(r.assumed_role_id.endswith(":" + name))
        self.assertEqual((r.account, r.partition), ("123456789012", "aws"))
        self.assertEqual(r.batch_id, h.batch.batch_id)
        self.assertEqual(r.scope_id, "s1")
        self.assertEqual(r.target_arn, h.batch.approved_rows[0]["resource_arn"])

    def test_derived_name_conflicting_binding_denied(self):
        h = IssuerHarness(self)
        h.issue()
        other = build_batch(approve=("p1",))  # same signed nonce, different Batch
        h.fx.ledger.state = state(outcomes=("UNCLAIMED",))
        with self.assertRaises(HostRuntimeBlocked) as caught:
            h.issue(batch=other)
        self.assertEqual(caught.exception.code, "BLOCKED_AUTH_REPLAY")
        self.assertEqual(len(h.sts.calls), 1)
        restarted = IssuerHarness(self, restart_of=h, batch=other)
        restarted.fx.ledger.state = state(outcomes=("UNCLAIMED",))
        with self.assertRaises(HostRuntimeBlocked):
            restarted.issue()  # journal binding survives the restart
        self.assertEqual(restarted.sts.calls, [])

    def test_unselectable_subset_never_issues_sts(self):
        h = IssuerHarness(self)
        forged = [build_subset_session_policy(h.batch, (0,), kind_registry=KIND_REGISTRY),
                  build_subset_session_policy(h.batch, (0, 1), kind_registry=KIND_REGISTRY)]
        for subset in forged:
            with self.assertRaises(HostRuntimeBlocked):
                h.issue(subset)
        selected = h.select()
        other_host = IssuerHarness(self)
        with owner_verified(), self.assertRaises(HostRuntimeBlocked):
            other_host.issuer.issue(h.batch, selected, other_host.host, NOW)
        self.assertEqual(h.sts.calls + other_host.sts.calls, [])

    def test_post_sts_session_token_utilization_recorded_if_present(self):
        h = IssuerHarness(self, sts_kwargs={
            "mutate": lambda r: r.update(SessionTokenUtilization=42)})
        self.assertEqual(h.issue().receipt.session_token_utilization, "42")

    def test_missing_utilization_not_fabricated(self):
        h = IssuerHarness(self)
        self.assertEqual(h.issue().receipt.session_token_utilization, "NOT_OBSERVED")

    def test_independent_iam_g1_g2_remains_blocking(self):
        h = IssuerHarness(self, gate=Gate(pre=False))
        with self.assertRaises(HostRuntimeBlocked):
            h.issue()
        self.assertEqual((h.sts.calls, h.records()), ([], ()))
        h = IssuerHarness(self, gate=Gate(post=False))
        with self.assertRaises(HostRuntimeBlocked):
            h.issue()
        self.assertEqual(len(h.sts.calls), 1)
        default = HostBatchCredentialIssuer(
            provider=SystemdEncryptedCredentialProvider(probe=h.fx.os), transport=h.sts,
            client_factory=ClientFactory())
        h.fx.ledger.state = state("ACTIVE", 1, outcomes=("APPLIED_VERIFIED", "UNCLAIMED"))
        with owner_verified(), self.assertRaises(HostRuntimeBlocked) as caught:
            default.issue(h.batch, h.select(), h.host, NOW)
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual(len(h.sts.calls), 1)

    def test_host_issuer_requires_protected_transport(self):
        with self.assertRaises(HostRuntimeBlocked) as caught:
            HostBatchCredentialIssuer(provider=None, transport=None)  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_copy_or_synthetic_session_rejected(self):
        from name_tag_batch_credentials import OfflineFakeIssuer
        h = IssuerHarness(self)
        issued = h.issue()
        for attempt in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(HostRuntimeBlocked):
                attempt(issued)
        with self.assertRaises(HostRuntimeBlocked):
            HostIssuedSession()  # type: ignore[call-arg]
        synthetic = OfflineFakeIssuer().issue(
            h.batch, build_subset_session_policy(h.batch, (0,), kind_registry=KIND_REGISTRY),
            kind_registry=KIND_REGISTRY)
        self.assertEqual(synthetic.provenance, "OFFLINE_SYNTHETIC_NOT_STS")
        for candidate in (synthetic, object(), None):
            with self.assertRaises(HostRuntimeBlocked):
                h.revalidate(candidate)
        self.assertNotIn(ISSUED_SECRET, repr(issued))

    def test_actual_sts_request_receipt_only_mocked(self):
        source = Path(issuer_module.__file__).read_text()
        imported = {alias.name.split(".")[0] for node in ast.walk(ast.parse(source))
                    if isinstance(node, (ast.Import, ast.ImportFrom))
                    for alias in (node.names if isinstance(node, ast.Import)
                                  else [ast.alias(node.module or "")])}
        self.assertFalse(imported & {"boto3", "botocore", "socket", "urllib", "http",
                                     "requests", "subprocess"})
        with mock.patch("socket.socket", side_effect=AssertionError("network")), no_ambient_sdk():
            h = IssuerHarness(self)
            issued = h.issue()
        self.assertIsInstance(h.sts, FakeSts)
        self.assertEqual(issued.live_status, "NOT_VERIFIED")

    def test_default_credential_chain_never_used_through_issuance(self):
        with no_ambient_sdk():
            h = IssuerHarness(self)
            h.issue().sdk_client("ec2", "ap-northeast-1", now_utc=NOW)
        self.assertEqual(h.factory.calls[0][2], ISSUED_AKID)

    def test_no_secrets_in_receipt_ledger_logs(self):
        captured: list[str] = []

        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(self.format(record))

        handler = Capture(level=logging.DEBUG)
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            h = IssuerHarness(self)
            issued = h.issue()
            errors = []
            for kwargs in ({"refuse": "AccessDenied"}, {"mutate": lambda r: r.update(X=1)}):
                failing = IssuerHarness(self, sts_kwargs=kwargs)
                try:
                    failing.issue()
                except HostRuntimeBlocked as error:
                    errors.append(repr(error) + str(error))
        finally:
            root.removeHandler(handler)
            root.setLevel(old_level)
        blobs = [issued.receipt.canonical_bytes().decode(), repr(issued), str(issued),
                 repr(issued.receipt), h.journal_bytes().decode(), *captured, *errors]
        for blob in blobs:
            for secret in SECRETS:
                self.assertNotIn(secret, blob)


class SessionTamperTests(unittest.TestCase):
    def test_swapped_private_triplet_or_policy_detected(self):
        for name, value in (("_triplet", (ISSUED_AKID, "Z" * 40, ISSUED_TOKEN)),
                            ("_policy_bytes", b'{"Statement":[]}')):
            with self.subTest(field=name):
                h = IssuerHarness(self)
                issued = h.issue()
                object.__setattr__(issued, name, value)
                with self.assertRaises(HostRuntimeBlocked):
                    issued.sdk_client("ec2", "ap-northeast-1", now_utc=NOW)
                with self.assertRaises(HostRuntimeBlocked):
                    h.revalidate(issued)


class TombstoneTests(unittest.TestCase):
    def test_issuance_attempt_fsynced_before_assume_role(self):
        h = IssuerHarness(self)
        h.issue()
        events = h.fx.events
        sts_at = events.index("assume_role")
        self.assertIn("fsync_file", events[:sts_at])
        self.assertIn("fsync_dir", events[events.index("fsync_file"):sts_at])
        self.assertEqual([r["status"] for r in h.sts.pending_seen], ["ISSUANCE_PENDING"])
        path = (Path(h.fx.state_dir) / "issuance-attempts" / h.batch.batch_id)
        (record_path,) = path.iterdir()
        self.assertEqual(oct(record_path.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o700")
        self.assertRegex(record_path.name, r"\A0-[0-9a-f]{64}\.json\Z")

    def test_journal_write_or_directory_sync_failure_zero_sts(self):
        for failing in ("fsync_file", "fsync_dir"):
            with self.subTest(failing=failing):
                h = IssuerHarness(self)
                original = h.fx.fsync

                def fsync(fd, failing=failing, original=original):
                    kind = "fsync_dir" if stat.S_ISDIR(os.fstat(fd).st_mode) else "fsync_file"
                    if kind == failing:
                        raise OSError(5, "EIO")
                    original(fd)

                host_runtime.bound_journal(h.host)._fsync = fsync
                with self.assertRaises(HostRuntimeBlocked):
                    h.issue()
                self.assertEqual(h.sts.calls, [])
        h = IssuerHarness(self)
        root = Path(h.fx.state_dir) / "issuance-attempts"
        root.mkdir(mode=0o755)
        os.chmod(root, 0o755)  # not private: create must refuse
        with self.assertRaises(HostRuntimeBlocked):
            h.issue()
        self.assertEqual(h.sts.calls, [])

    def test_same_batch_row_restart_pending_blocks_assume_role(self):
        h = IssuerHarness(self, sts_kwargs={"crash": True})
        with self.assertRaises(_Crash):
            h.issue()
        restarted = IssuerHarness(self, restart_of=h)
        (record,) = restarted.records()
        self.assertEqual(record["status"], "ISSUANCE_PENDING")
        with self.assertRaises(HostRuntimeBlocked) as caught:
            restarted.issue()
        self.assertEqual(caught.exception.code, "BLOCKED_ISSUANCE_ATTEMPT_EXISTS")
        self.assertEqual(restarted.sts.calls, [])

    def test_post_sts_crash_before_intent_still_blocks_reissue(self):
        h = IssuerHarness(self)
        h.issue()  # ISSUED_VERIFIED, then the Host dies before any Ledger Intent
        restarted = IssuerHarness(self, restart_of=h)  # SQLite is still UNREGISTERED
        self.assertEqual(restarted.fx.ledger.state.state, "UNREGISTERED")
        with self.assertRaises(HostRuntimeBlocked) as caught:
            restarted.issue()
        self.assertEqual(caught.exception.code, "BLOCKED_ISSUANCE_ATTEMPT_EXISTS")
        self.assertEqual((len(h.sts.calls), restarted.sts.calls), (1, []))

    def test_existing_intent_and_tombstone_reconciled_without_replay(self):
        h = IssuerHarness(self)
        h.issue()
        restarted = IssuerHarness(self, restart_of=h)
        restarted.fx.ledger.state = state("ACTIVE", 0, outcomes=("WRITE_INTENT_RECORDED", "UNCLAIMED"))
        with self.assertRaises(HostRuntimeBlocked):
            restarted.issue()  # original Ledger no-replay rule: never skip to row 1
        restarted.fx.ledger.state = state("ACTIVE", 1, outcomes=("APPLIED_VERIFIED", "UNCLAIMED"))
        issued = restarted.issue()  # row 0 durably terminal; its tombstone only denies row 0
        self.assertEqual(issued.receipt.row_index, 1)
        self.assertEqual(sorted(r["row_index"] for r in restarted.records()), [0, 1])

    def test_tampered_tombstone_fails_closed(self):
        h = IssuerHarness(self)
        h.issue()
        (path,) = (Path(h.fx.state_dir) / "issuance-attempts" / h.batch.batch_id).iterdir()
        path.write_bytes(path.read_bytes().replace(b"ISSUED_VERIFIED", b"ISSUANCE_REFUSED"))
        with self.assertRaises(HostRuntimeBlocked):
            IssuerHarness(self, restart_of=h)  # startup reconciliation refuses
        with self.assertRaises(HostRuntimeBlocked):
            h.select()  # and so does pre-selection reconciliation in the live process

    def test_same_run_verified_receipt_allows_single_intent(self):
        h = IssuerHarness(self)
        issued = h.issue()
        authority = h.revalidate(issued)
        self.assertEqual((authority.row_index, authority.batch.batch_id), (0, h.batch.batch_id))
        with self.assertRaises(HostRuntimeBlocked):
            h.revalidate(issued)  # one Intent admission per issued session
        h2 = IssuerHarness(self)
        issued2 = h2.issue()
        restarted = IssuerHarness(self, restart_of=h2)
        with owner_verified(), self.assertRaises(HostRuntimeBlocked):
            revalidate_issued_before_intent(issued2, ledger=restarted.fx.ledger,
                                            host=restarted.host, now_utc=NOW)

    def test_state_drift_after_sts_prevents_intent(self):
        drifts = [
            lambda h: setattr(h.fx.ledger, "state", state("ACTIVE", 0, outcomes=("WRITE_INTENT_RECORDED", "UNCLAIMED"))),
            lambda h: setattr(h.fx.ledger, "error", LedgerErrorFactory()),
            lambda h: h.fx.ledger.scope_states.update(s1="HOLD"),
        ]
        for n, drift in enumerate(drifts):
            with self.subTest(n=n):
                h = IssuerHarness(self)
                issued = h.issue()
                drift(h)
                with self.assertRaises(HostRuntimeBlocked):
                    h.revalidate(issued)
                self.assertNotIn("create_batch_intent", h.fx.ledger.calls)

    def test_tombstone_no_credentials_or_cap_consumption(self):
        h = IssuerHarness(self)
        h.issue()
        raw = h.journal_bytes()
        for secret in SECRETS + (AKID, ISSUED_AKID):
            self.assertNotIn(secret.encode(), raw)
        (record,) = h.records()
        self.assertFalse({k for k in record if "attempts" in k or "cap" in k or "permit" in k})
        # Selection read + Task 7 pre-STS re-read; both read-only, no Intent/cap call.
        self.assertEqual(h.fx.ledger.calls, ["batch_execution_state", "batch_execution_state"])

    def test_stale_selection_refused_before_tombstone_or_sts(self):
        """Task 7 obligation (d): issue() re-reads the Ledger/Scope before any tombstone."""
        for mutate in (lambda led: setattr(led, "state", state("ACTIVE", outcomes=("SKIPPED_NAME_CHANGED", "UNCLAIMED"))),
                       lambda led: led.scope_states.update(s1="HOLD")):
            with self.subTest(mutate=mutate):
                h = IssuerHarness(self)
                subset = h.select()
                mutate(h.fx.ledger)
                with self.assertRaises(HostRuntimeBlocked):
                    h.issue(subset)
                self.assertEqual(h.sts.calls, [])
                self.assertEqual(h.records(), ())


def LedgerErrorFactory():
    return LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


if __name__ == "__main__":
    unittest.main()
