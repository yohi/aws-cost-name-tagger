"""Offline Task 7 tests: Host gate integrated with the single durable Batch/Ledger Coordinator.

Real migrated Ledger v2 (temporary file), Fake Host OS/STS/SDK clients only. Zero real STS,
AWS or network. The "mock-proven" live IAM evidence below is a TEST-ONLY fixture minted
directly into the protected registry; no production producer exists, the production runtime
fails closed, and every result is labelled ``live_status=NOT_VERIFIED`` (fake success is
never labelled live). Network client state is never Host authorization or a Ledger outcome.
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest import mock

import name_tag_batch_host_runtime as host_runtime
import name_tag_batch_iam_evidence as iam_evidence
import name_tag_batch_runtime as batch_runtime
import name_tag_kind_capabilities as caps
from name_tag_batch_approval import BatchAuthRejected, canonical_bytes
from name_tag_batch_executor import (
    BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter)
from name_tag_batch_host_issuer import (
    HostBatchCredentialIssuer, StsExchange, SystemdEncryptedCredentialProvider)
from name_tag_batch_host_runtime import (
    HOST_PROTECTED_DISPATCH_OPT_IN, HostOutcomeUnknown, HostRuntimeBlocked,
    ProtectedBatchHostEndpoint,
    open_verified_host_runtime)
from name_tag_batch_host_server import (
    PeerPolicy, ProtectedHostIPCServer, UnavailableListenerOS, map_blocked, map_endpoint_result)
from name_tag_batch_iam import verified_kind_policy
from name_tag_batch_iam_evidence import (
    LIVE_PROVENANCE, IamDenyCase, OfflineSyntheticIamEvidenceVerifier,
    OfflineSyntheticRuntimeVerifier, ProtectedEffectiveIamEvidenceVerifier,
    ProtectedHostRuntimeVerifier, ProtectedHostScopeVerifier, SyntheticIamEvidenceProducer)
from name_tag_batch_ipc import HostIPCRequest
from name_tag_batch_live import (
    AuthorizedBatchRuntimePolicy, AuthorizedBatchWritePort, LiveWriteBlocked)
from name_tag_batch_runtime import HostLedgerBatchCoordinator, execute_batch_live
from name_tag_ledger import open_ledger
from name_tag_ledger_errors import LedgerError
from test_name_tag_batch_host_issuer import Gate, _cred_bytes, install_credentials
from test_name_tag_batch_host_runtime import host_fixture
from test_name_tag_batch_ledger import (
    LAMBDA_ARN, VOLUMES, RealLedgerV2Case, lambda_record, proven_lambda, volume_record)

H = "a" * 64
ISSUED = ("ASIA" + "B" * 16, "R" * 40, "Q" * 320)


class LiveSts:
    """Host STS transport double (real-time expiry); records exact bytes, never networks."""

    def __init__(self, harness):
        self.h = harness
        self.calls: list[bytes] = []
        self.error: BaseException | None = None

    def assume_role(self, *, request_bytes, credentials):
        self.calls.append(request_bytes)
        if self.error is not None:
            raise self.error
        name = json.loads(request_bytes)["RoleSessionName"]
        return StsExchange(sent_request_bytes=request_bytes, response={
            "Credentials": {"AccessKeyId": ISSUED[0], "SecretAccessKey": ISSUED[1],
                            "SessionToken": ISSUED[2],
                            "Expiration": self.h.clock_now + timedelta(seconds=900)},
            "AssumedRoleUser": {"Arn": f"arn:aws:sts::123456789012:assumed-role/Batch/{name}",
                                "AssumedRoleId": "AROA" + "C" * 17 + ":" + name}})


class FakeCloud:
    """In-memory EC2/Lambda tag state behind the explicit-triplet SDK client factory."""

    def __init__(self):
        self.tags: dict[str, dict[str, str]] = {}
        self.writes: list[tuple[str, str]] = []
        self.write_error: BaseException | None = None
        self.readback_override: list | None = None
        self.created: list[tuple[str, str, str]] = []

    def create(self, service, region, *, access_key_id, secret_access_key, session_token):
        assert (access_key_id, secret_access_key, session_token) == ISSUED
        self.created.append((service, region, access_key_id))
        return _Client(self)


class _Client:
    def __init__(self, cloud):
        self.cloud = cloud
        self.reads = 0

    def describe_volumes(self, *, VolumeIds):
        (volume_id,) = VolumeIds
        self.reads += 1
        if self.cloud.readback_override is not None and self.reads > 1:
            return self.cloud.readback_override
        tags = self.cloud.tags.setdefault(volume_id, {})
        return {"Volumes": [{"VolumeId": volume_id,
                             "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}]}

    def create_tags(self, *, Resources, Tags):
        (volume_id,) = Resources
        ((tag,),) = (Tags,)
        self.cloud.writes.append((volume_id, tag["Value"]))
        self.cloud.tags.setdefault(volume_id, {})[tag["Key"]] = tag["Value"]
        if self.cloud.write_error is not None:
            raise self.cloud.write_error


class ScopeSource:
    def __init__(self):
        self.scope = None
        self.effects = ()

    def load(self, scope_id, host):
        return self.scope, self.effects


def _deny_cases(arn, action="ec2:CreateTags"):
    other = arn.replace("vol-0", "vol-9").replace("vol-a", "vol-9")
    return (IamDenyCase("FOREIGN_ARN", other, action, "Name", "DENY"),
            IamDenyCase("OTHER_TAG_KEY", arn, action, "Owner", "DENY"),
            IamDenyCase("ALTERNATE_API", arn, "ec2:DeleteTags", "Name", "DENY"))


def mock_proven_live_evidence(**fields):
    """TEST-ONLY mock-proven Host evidence. No production producer exists."""
    evidence = iam_evidence.ProtectedIamEvidence(iam_evidence._MINT, provenance=LIVE_PROVENANCE,
                                                 **fields)
    iam_evidence._EVIDENCE[evidence] = LIVE_PROVENANCE
    return evidence


class LiveHarness(RealLedgerV2Case):
    def setUp(self):
        super().setUp()
        self.clock_now = self.now
        self.revoked = False
        self.cloud = FakeCloud()
        self.source = ScopeSource()
        self.evidence_kind = "live"
        self.evidence_calls = 0
        self.evidence_ttl = timedelta(minutes=10)
        self.fail_evidence_on: set[int] = set()
        self.ledger = self.open()
        self.fx = host_fixture(self)
        self.fx.ledger = self.ledger
        self.fx.repin()
        install_credentials(self.fx, _cred_bytes(
            Expiration=(self.now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")))
        self.sts = LiveSts(self)
        self.gate = Gate()
        self.issuer = HostBatchCredentialIssuer(
            provider=SystemdEncryptedCredentialProvider(probe=self.fx.os), transport=self.sts,
            evidence_gate=self.gate, client_factory=self.cloud)
        self.host = self.fx.verifier.verify_process(now_utc=self.now)
        self.kind_registry = {"volume": verified_kind_policy(caps.resolve_kind_capability("volume"))}

    # -- wiring -------------------------------------------------------------------
    def clock(self):
        return self.clock_now

    def trusted(self):
        stack = contextlib.ExitStack()

        def load():
            if self.revoked:
                raise BatchAuthRejected()
            return self.trust
        for target in ("name_tag_batch_trust.load_current_protected_owner_trust",
                       "name_tag_batch_runtime.load_current_protected_owner_trust",
                       "name_tag_batch_host_runtime.load_current_protected_owner_trust"):
            stack.enter_context(mock.patch(target, side_effect=load))
        return stack

    def evidence_source(self, issued, row, scope):
        self.evidence_calls += 1
        arn = row.row["resource_arn"]
        action = row.row["aws_operation"]
        fields = dict(
            principal_arn=issued.receipt.assumed_role_arn, account="123456789012",
            partition="aws", role_policy_digests=(("BatchRole", "v3", H),),
            trust_policy_sha256=H, permission_boundary_sha256=H, scp_sha256=H, rcp_sha256=H,
            resource_policy_sha256=H, session_grant_sha256=H, approved_allow=(arn, action, "Name"),
            deny_cases=_deny_cases(arn, action), source="PROTECTED_EVIDENCE_PRODUCER",
            captured_at_utc=self.clock_now - timedelta(minutes=1),
            expires_at_utc=self.clock_now + self.evidence_ttl, captured_state_sha256=H,
            current_state_sha256=H, verifier_result="PASS")
        if self.evidence_kind == "synthetic" or self.evidence_calls in self.fail_evidence_on:
            return SyntheticIamEvidenceProducer().produce(**fields)
        return mock_proven_live_evidence(**fields)

    def runtime(self, host=None, issuer=None):
        return open_verified_host_runtime(
            host=host or self.host, issuer=issuer or self.issuer,
            scope_verifier=ProtectedHostScopeVerifier(source=self.source),
            iam_verifier=ProtectedEffectiveIamEvidenceVerifier(clock=self.clock),
            iam_evidence_source=self.evidence_source,
            runtime_verifier=ProtectedHostRuntimeVerifier(clock=self.clock),
            kind_registry=self.kind_registry, clock=self.clock,
            opt_in=HOST_PROTECTED_DISPATCH_OPT_IN)

    def prepare(self, records=None, *, cap=2, scope_arns=None, nonce=None):
        # A fresh signed nonce per test: derived STS session names are process-bound.
        nonce = nonce or os.urandom(16).hex()
        self.nonce = nonce
        records = records or [volume_record(0, VOLUMES[0]), volume_record(1, VOLUMES[1])]
        with self.trusted():
            batch = self.make_batch(records, cap=cap, nonce=nonce)
            arns = scope_arns or [r["resource_arn"] for r in records]
            self.source.scope, self.source.effects = self.init_scope(self.ledger, arns)
        return batch

    def run_live(self, batch, runtime=None):
        with self.trusted():
            return execute_batch_live(batch, self.ledger, runtime or self.runtime())

    def run_blocked(self, batch, runtime=None) -> HostRuntimeBlocked:
        with self.assertRaises(HostRuntimeBlocked) as caught:
            self.run_live(batch, runtime)
        return caught.exception

    # -- observations --------------------------------------------------------------
    def state(self, batch):
        with self.trusted():
            return self.ledger.batch_execution_state(batch)

    def scope_state(self):
        return self.sql("SELECT state FROM scopes WHERE scope_id='scope-1'")[0][0]

    def journal(self):
        return host_runtime.IssuanceAttemptJournal(
            Path(self.fx.state_dir) / "issuance-attempts", service_uid=os.getuid()).scan()

    def report_file(self, batch_id, digest):
        path = Path(self.fx.state_dir) / "batch-reports" / batch_id / f"{digest}.json"
        return json.loads(path.read_bytes())

    @contextlib.contextmanager
    def after(self, obj, name, action):
        real = getattr(obj, name)

        def wrapper(*args, **kwargs):
            result = real(*args, **kwargs)
            action()
            return result
        with mock.patch.object(obj, name, wrapper):
            yield

    def endpoint(self):
        coordinator = HostLedgerBatchCoordinator(
            runtime_factory=lambda host, issuer: self.runtime(host, issuer))
        return ProtectedBatchHostEndpoint(issuer=self.issuer, coordinator=coordinator,
                                          clock=self.clock)

    def serve_once(self, batch, request_id="1" * 32, *, reply_lost=True):
        """Accepted command through the Host server; the client vanished (reply lost)."""
        request = HostIPCRequest(1, request_id, batch.plan_bytes, batch.csv_bytes,
                                 batch.raw_envelope_bytes)

        class Codec:
            sent = []

            def read_request(self, conn):
                return request

            def write_response(self, conn, response):
                Codec.sent.append(response)
                if reply_lost:
                    raise BrokenPipeError("client disconnected")
        server = ProtectedHostIPCServer(os_facade=UnavailableListenerOS(),
                                        peer_policy=PeerPolicy(frozenset(), frozenset()),
                                        codec=Codec(), clock_utc=self.clock)
        with self.trusted():
            server._read_and_run(object(), self.fx.verifier, self.endpoint())
        return Codec.sent[-1], server


# ============================================================== Step 1 (RG-PRC-004)
class LiveCoordinatorStepOneTests(LiveHarness):
    def test_live_denies_offline_fake_and_caller_constructed_policy(self):
        batch = self.prepare()
        offline = BatchOfflineRuntime({"scope-1": BatchRuntimeEvidence(
            self.source.scope, self.source.effects)}, FakeBatchSDKAdapter({}))
        for forged in (offline, object(), None):
            with self.subTest(runtime=type(forged).__name__), self.trusted():
                with self.assertRaises(HostRuntimeBlocked):
                    execute_batch_live(batch, self.ledger, forged)
        for kwargs in ({"iam_verifier": OfflineSyntheticIamEvidenceVerifier()},
                       {"runtime_verifier": OfflineSyntheticRuntimeVerifier()},
                       {"opt_in": "yes"}):
            base = dict(host=self.host, issuer=self.issuer,
                        scope_verifier=ProtectedHostScopeVerifier(source=self.source),
                        iam_verifier=ProtectedEffectiveIamEvidenceVerifier(),
                        iam_evidence_source=self.evidence_source,
                        runtime_verifier=ProtectedHostRuntimeVerifier(),
                        kind_registry=self.kind_registry, clock=self.clock,
                        opt_in=HOST_PROTECTED_DISPATCH_OPT_IN)
            base.update(kwargs)
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(HostRuntimeBlocked):
                open_verified_host_runtime(**base)
        with self.assertRaises(HostRuntimeBlocked):
            host_runtime.production_host_runtime()
        policy = AuthorizedBatchRuntimePolicy("b", "r", "1", "aws", "r", VOLUMES[0], "n",
                                              "ec2:CreateTags", 1, 1)
        with self.assertRaises(LiveWriteBlocked) as refused:
            AuthorizedBatchWritePort(object(), adapter=object(), target=object(),
                                     clock=self.clock).write_once(
                session=None, row=None, permit=None, runtime=policy)
        self.assertEqual(refused.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        # Synthetic evidence never satisfies the protected verifier: refused before Intent.
        self.evidence_kind = "synthetic"
        blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual((self.intents(), self.cloud.writes), ([], []))

    def test_expired_iam_evidence_refused_before_intent_and_sdk(self):
        # IAM evidence already expired when the Host consumes it: refused before any
        # Intent / create_batch_intent / SDK write; no send happens after expiry.
        self.evidence_ttl = timedelta(seconds=-1)
        batch = self.prepare()
        with mock.patch.object(self.ledger, "create_batch_intent",
                               wraps=self.ledger.create_batch_intent) as create_intent:
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        create_intent.assert_not_called()
        self.assertEqual(self.intents(), [])
        self.assertEqual(self.cloud.writes, [])
        self.assertGreaterEqual(self.evidence_calls, 1)

    def test_valid_mock_proven_host_one_permit_one_send_readback(self):
        batch = self.prepare()
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED", "APPLIED_VERIFIED"))
        self.assertEqual(result.batch_state, "COMPLETED")
        self.assertEqual(len(self.sts.calls), 2)
        self.assertEqual(sorted(self.cloud.writes), sorted(
            (arn.rsplit("/", 1)[1], volume_record(i, arn)["proposed_name"])
            for i, arn in enumerate(VOLUMES)))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM intent_history WHERE "
                                  "event='SEND_ATTEMPT_CONSUMED'"), [(2,)])
        self.assertEqual(result.report["live_status"], "NOT_VERIFIED")
        self.assertEqual(result.report["execution_mode"], "HOST_PROTECTED_DISPATCH")
        digest = result.report["report_sha256"]
        stored = self.report_file(batch.batch_id, digest)
        self.assertEqual(stored["applied_verified_count"], 2)
        self.assertNotIn("report_sha256", stored)
        response = map_endpoint_result("1" * 32, result)
        self.assertEqual((response.status, response.code, response.batch_id,
                          response.report_sha256), ("COMPLETE", "COMPLETE", batch.batch_id, digest))
        self.assertEqual([s for s in host_runtime._SELECTIONS.values() if s.host is self.host], [])
        for secret in ISSUED[1:]:
            self.assertNotIn(secret, json.dumps(stored))

    def test_expired_or_revoked_before_permit_zero_send(self):
        # Expired evidence/Owner window between Intent and Permit -> proven no-send finalizer.
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent",
                        lambda: setattr(self, "clock_now", self.now + timedelta(hours=2))):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.intents(), [("TERMINAL", "NOT_ATTEMPTED_BATCH_STOP", "ec2:CreateTags")])
        self.assertEqual(self.state(batch).state, "STOPPED")
        self.assertEqual(self.scope_state(), "HOLD")

    def test_revoked_before_permit_leaves_unresolved_intent_stop_hold(self):
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent", lambda: setattr(self, "revoked", True)):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.intents(), [("WRITE_INTENT_RECORDED", None, "ec2:CreateTags")])
        self.assertEqual(self.sql("SELECT state FROM batch_registry"), [("STOPPED",)])
        self.assertEqual(self.scope_state(), "HOLD")

    def test_crash_after_permit_outcome_unknown_no_resend(self):
        batch = self.prepare()
        self.cloud.write_error = TimeoutError("connection reset after send")
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("OUTCOME_UNKNOWN", "NOT_ATTEMPTED_BATCH_STOP"))
        self.assertEqual((result.batch_state, self.scope_state()), ("STOPPED", "HOLD"))
        self.assertEqual(map_endpoint_result("1" * 32, result).status, "UNKNOWN")
        self.cloud.write_error = None
        again = self.run_live(batch, self.runtime())
        self.assertEqual(again.outcomes, result.outcomes)
        self.assertEqual((len(self.cloud.writes), len(self.sts.calls)), (1, 1))

    def test_hold_failure_blocks_host(self):
        batch = self.prepare()
        failing = mock.patch.object(self.ledger, "record_readback",
                                    side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN"))
        no_stop = mock.patch.object(self.ledger, "stop_batch",
                                    side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN"))
        no_hold = mock.patch.object(self.ledger, "hold_scope",
                                    side_effect=sqlite3.OperationalError("disk I/O error"))
        with failing, no_stop, no_hold:
            blocked = self.run_blocked(batch)
        # A consumed Permit whose disposition and STOP/HOLD are not durable is UNKNOWN.
        self.assertIsInstance(blocked, HostOutcomeUnknown)
        self.assertEqual(blocked.code, "OUTCOME_UNKNOWN")
        response = map_blocked("1" * 32, blocked)
        self.assertEqual((response.status, response.code, response.report_sha256),
                         ("UNKNOWN", "OUTCOME_UNKNOWN", None))
        self.assertEqual(self.intents(), [("SEND_ATTEMPT_CONSUMED", None, "ec2:CreateTags")])
        self.assertEqual(len(self.cloud.writes), 1)

    def test_cross_kind_signed_cap_preserved(self):
        with proven_lambda():
            batch = self.prepare([volume_record(0), lambda_record(1)], cap=1)
            result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED", "NOT_ATTEMPTED_CAP"))
        self.assertEqual((result.batch_state, result.send_attempts_consumed,
                          result.max_send_attempts), ("COMPLETED", 1, 1))
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)), (1, 1))

    def test_client_disconnect_after_accept_before_permit_host_uses_ledger_rules(self):
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent",
                        lambda: setattr(self, "clock_now", self.now + timedelta(hours=2))):
            response, server = self.serve_once(batch)
        self.assertEqual(server.response_write_failures, 1)
        self.assertEqual((response.status, response.code), ("BLOCKED", "BLOCKED_OWNER_AUTHN"))
        self.assertEqual(response.batch_id, batch.batch_id)
        self.assertRegex(response.report_sha256, r"\A[0-9a-f]{64}\Z")
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.intents(), [("TERMINAL", "NOT_ATTEMPTED_BATCH_STOP", "ec2:CreateTags")])

    def test_client_disconnect_after_permit_verified_readback_keeps_terminal_outcome(self):
        batch = self.prepare()
        response, server = self.serve_once(batch)
        self.assertEqual(server.response_write_failures, 1)
        self.assertEqual(response.status, "COMPLETE")
        self.assertEqual(self.state(batch).outcomes, ("APPLIED_VERIFIED", "APPLIED_VERIFIED"))
        again, _ = self.serve_once(batch, "2" * 32, reply_lost=False)
        self.assertEqual(self.state(batch).outcomes, ("APPLIED_VERIFIED", "APPLIED_VERIFIED"))
        self.assertEqual((len(self.cloud.writes), len(self.sts.calls)), (2, 2))
        self.assertEqual(again.status, "COMPLETE")

    def test_client_disconnect_and_missing_durable_readback_yields_outcome_unknown_stop_hold(self):
        batch = self.prepare()
        with mock.patch.object(self.ledger, "record_readback",
                               side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")):
            response, server = self.serve_once(batch)
        self.assertEqual(server.response_write_failures, 1)
        self.assertEqual((response.status, response.code), ("UNKNOWN", "OUTCOME_UNKNOWN"))
        self.assertEqual(self.intents(), [("SEND_ATTEMPT_CONSUMED", None, "ec2:CreateTags")])
        self.assertEqual((self.state(batch).state, self.scope_state()), ("STOPPED", "HOLD"))
        self.serve_once(batch, "2" * 32)
        self.assertEqual((len(self.cloud.writes), len(self.sts.calls)), (1, 1))

    def test_same_batch_new_request_id_cannot_resend(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        first, _ = self.serve_once(batch, "1" * 32, reply_lost=False)
        second, _ = self.serve_once(batch, "f" * 32, reply_lost=False)
        self.assertEqual((first.status, second.status), ("COMPLETE", "COMPLETE"))
        self.assertEqual(first.report_sha256, second.report_sha256)
        self.assertEqual((len(self.cloud.writes), len(self.sts.calls)), (1, 1))


# ============================================================== RG-PRC-005
class LiveSelectionLedgerTests(LiveHarness):
    def test_same_host_live_executions_serialize_selection_cleanup(self):
        batch = self.prepare()
        runtime = self.runtime()
        first_entered = threading.Event()
        second_entered = threading.Event()
        release_first = threading.Event()
        release_second = threading.Event()
        second_selection_preserved = threading.Event()
        call_count = 0
        errors = []

        def fake_run_live(_batch, _ledger, active_runtime):
            nonlocal call_count
            call_number = call_count
            call_count += 1
            spec = object()
            selection = host_runtime.HostSelection(
                host=active_runtime.host, batch=batch, spec=spec, row_authority=None,
                snapshot=None, signed_cap=1, scope_id="scope-1", capability=None,
                target=None, name_evidence_sha256="a" * 64, selected_at_utc=self.now)
            host_runtime._SELECTIONS[id(spec)] = selection
            if call_number == 0:
                first_entered.set()
                if not release_first.wait(5):
                    raise AssertionError("first execution was not released")
            else:
                second_entered.set()
                if not release_second.wait(5):
                    raise AssertionError("second execution was not released")
                try:
                    self.assertIs(host_runtime.peek_selection(spec, active_runtime.host),
                                  selection)
                    second_selection_preserved.set()
                except BaseException as error:
                    errors.append(error)
                    raise
            return object()

        def execute():
            try:
                execute_batch_live(batch, self.ledger, runtime)
            except BaseException as error:
                errors.append(error)

        first = threading.Thread(target=execute)
        second = threading.Thread(target=execute)
        with mock.patch.object(batch_runtime, "_run_live", side_effect=fake_run_live):
            first.start()
            self.assertTrue(first_entered.wait(5))
            second.start()
            try:
                self.assertFalse(second_entered.wait(0.1))
            finally:
                release_first.set()
            first.join(5)
            self.assertFalse(first.is_alive())
            self.assertTrue(second_entered.wait(5))
            release_second.set()
            second.join(5)

        self.assertFalse(second.is_alive())
        self.assertEqual(errors, [])
        self.assertTrue(second_selection_preserved.is_set())

    def test_endpoint_selection_cleanup_uses_host_execution_lock(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        endpoint = self.endpoint()
        lock = host_runtime.host_execution_lock(self.host)
        clear_lock_states = []
        real_clear_selections = host_runtime.clear_selections

        def clear_while_recording_lock(host):
            self.assertIs(host, self.host)
            clear_lock_states.append(lock.locked())
            return real_clear_selections(host)

        with self.trusted(), \
                mock.patch("name_tag_batch_approval.verify_batch_approval",
                           return_value=batch), \
                mock.patch.object(host_runtime, "clear_selections",
                                  side_effect=clear_while_recording_lock):
            endpoint.execute_signed_batch(
                plan_bytes=batch.plan_bytes, csv_bytes=batch.csv_bytes,
                owner_envelope_bytes=b"{}", host=self.host)

        self.assertEqual(clear_lock_states, [True, True])

    def _verified_scope(self, batch):
        record = batch.approved_rows[0]
        arn_parts = record["resource_arn"].split(":", 5)
        target = caps.canonical_target_identity(
            kind=record["kind"], locator=record["locator"],
            resource_arn=record["resource_arn"], partition=arn_parts[1],
            account=arn_parts[4], scope_region=record["region"])
        verifier = self.runtime().scope_verifier
        return verifier, verifier.resolve("scope-1", target, self.host, self.now)

    def test_scope_reconfirmation_accepts_reordered_valid_evidence(self):
        batch = self.prepare()
        verifier, verified_scope = self._verified_scope(batch)
        self.source.effects = tuple(reversed(self.source.effects))

        verifier.reconfirm(verified_scope, self.now)

    def test_scope_reconfirmation_rejects_invalid_or_changed_evidence(self):
        batch = self.prepare()
        verifier, verified_scope = self._verified_scope(batch)
        original = self.source.effects
        cases = {
            "wrong element type": ("not-side-effect-evidence", *original[1:]),
            "duplicate target": (original[0], original[0]),
            "missing target": original[:-1],
            "changed content": (replace(original[0], evidence_references=("changed://evidence",)),
                                *original[1:]),
        }

        for label, effects in cases.items():
            with self.subTest(case=label):
                self.source.effects = effects
                with self.assertRaises(HostRuntimeBlocked):
                    verifier.reconfirm(verified_scope, self.now)
        self.source.effects = original

    def test_signed_row_indexes_ascending_singleton_selection(self):
        batch = self.prepare()
        self.run_live(batch)
        records = sorted(self.journal(), key=lambda r: r["created_at_utc"])
        self.assertEqual([r["row_index"] for r in self.journal()],
                         list(batch.approved_row_indexes))
        policies = [json.loads(json.loads(call)["Policy"]) for call in self.sts.calls]
        self.assertEqual(len(self.sts.calls), len(batch.approved_row_indexes))
        self.assertEqual(len(policies), len(batch.approved_row_indexes))
        write_arns = []
        for policy in policies:
            writes = [statement for statement in policy["Statement"]
                      if "ec2:CreateTags" in statement["Action"]]
            self.assertEqual(len(writes), 1)
            self.assertEqual(len(writes[0]["Resource"]), 1)
            write_arns.append(writes[0]["Resource"][0])
        self.assertCountEqual(write_arns, [batch.approved_rows[i]["resource_arn"]
                                           for i in batch.approved_row_indexes])
        for position, policy in enumerate(policies):
            arn = batch.approved_rows[batch.approved_row_indexes[position]]["resource_arn"]
            dumped = json.dumps(policy)
            self.assertIn(arn.rsplit("/", 1)[1], dumped)
            self.assertNotIn([a for a in VOLUMES if a != arn][0].rsplit("/", 1)[1], dumped)
        self.assertEqual(len(records), 2)

    def test_cross_kind_cap_blocks_further_issuance(self):
        with proven_lambda():
            batch = self.prepare([volume_record(0), lambda_record(1)], cap=1)
            self.run_live(batch)
            self.run_live(batch, self.runtime())
        self.assertEqual([r["row_index"] for r in self.journal()], [batch.approved_row_indexes[0]])
        self.assertEqual(len(self.sts.calls), 1)

    def test_ledger_drift_between_issuer_and_permit_blocks(self):
        batch = self.prepare()
        with self.after(self.issuer, "issue",
                        lambda: self.ledger.hold_scope("scope-1", reason="drift")):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_HOLD")
        self.assertEqual((self.intents(), self.cloud.writes), ([], []))

    def test_ledger_drift_between_intent_and_permit_finalizes_no_send(self):
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent",
                        lambda: self.ledger.hold_scope("scope-1", reason="drift")):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_HOLD")
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.intents(), [("TERMINAL", "NOT_ATTEMPTED_BATCH_STOP", "ec2:CreateTags")])

    def test_unresolved_intent_or_hold_no_next_subset(self):
        batch = self.prepare()
        with self.trusted():
            other = open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
            self.addCleanup(other.close)
            other.create_batch_intent(self.authority(batch), scope=self.source.scope,
                                      side_effects=self.source.effects)
        result = self.run_live(batch)
        self.assertEqual(result.batch_state, "STOPPED")
        self.assertEqual(result.outcomes[0], "UNRESOLVED_WRITE_INTENT")
        self.assertEqual((self.sts.calls, self.cloud.writes), ([], []))

    def test_scope_hold_no_next_subset(self):
        batch = self.prepare()
        self.ledger.hold_scope("scope-1", reason="operator hold")
        blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_HOLD")
        self.assertEqual((self.sts.calls, self.intents()), ([], []))

    def test_duplicate_batch_never_reissues_or_resends(self):
        batch = self.prepare()
        self.run_live(batch)
        again = self.run_live(batch, self.runtime())
        self.assertEqual(again.batch_state, "COMPLETED")
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)), (2, 2))

    def test_initial_ledger_state_error_is_unknown_with_batch_id(self):
        batch = self.prepare()
        runtime = self.runtime()
        with self.trusted(), mock.patch.object(
                self.ledger, "batch_execution_state",
                side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")):
            with self.assertRaises(HostOutcomeUnknown) as caught:
                execute_batch_live(batch, self.ledger, runtime)

        self.assertEqual(caught.exception.batch_id, batch.batch_id)

    def test_stopped_unresolved_permit_retries_scope_hold_without_resend(self):
        batch = self.prepare([volume_record(0)], cap=1)
        real_hold_scope = self.ledger.hold_scope
        hold_attempts = []

        def fail_first_hold(scope_id, *, reason):
            hold_attempts.append((scope_id, reason))
            if len(hold_attempts) == 1:
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            return real_hold_scope(scope_id, reason=reason)

        with self.trusted(), mock.patch.object(
                self.ledger, "record_readback",
                side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")), mock.patch.object(
                    self.ledger, "hold_scope", side_effect=fail_first_hold):
            with self.assertRaises(HostOutcomeUnknown) as caught:
                execute_batch_live(batch, self.ledger, self.runtime())
            self.assertEqual(caught.exception.batch_id, batch.batch_id)
            self.assertEqual(self.state(batch).state, "STOPPED")
            self.assertEqual(self.scope_state(), "CLEARED")
            sends_after_first_attempt = len(self.cloud.writes)
            sts_after_first_attempt = len(self.sts.calls)
            result = execute_batch_live(batch, self.ledger, self.runtime())

        self.assertEqual(result.batch_state, "STOPPED")
        self.assertEqual(self.scope_state(), "HOLD")
        self.assertEqual(len(hold_attempts), 2)
        self.assertEqual(len(self.cloud.writes), sends_after_first_attempt)
        self.assertEqual(len(self.sts.calls), sts_after_first_attempt)


class LiveFirstRegistrationTests(LiveHarness):
    def test_valid_first_unregistered_sts_to_active_intent_permit(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        self.assertEqual(self.state(batch).state, "UNREGISTERED")
        result = self.run_live(batch)
        self.assertEqual(result.batch_state, "COMPLETED")
        (record,) = self.journal()
        self.assertEqual(record["status"], "ISSUED_VERIFIED")
        events = [e for (e,) in self.sql("SELECT event FROM batch_events ORDER BY event_id")]
        self.assertEqual(events[:3], ["BATCH_REGISTERED", "INTENT_ADMITTED", "SEND_ATTEMPT_CONSUMED"])

    def test_nonce_collision_between_sts_and_intent_blocks_send(self):
        batch = self.prepare()
        with self.trusted():
            rival = self.make_batch([volume_record(0)], nonce=self.nonce, cap=1)

        def register_rival():
            with self.trusted():
                self.ledger.stop_batch(rival, reason_code="RIVAL")
        with self.after(self.issuer, "issue", register_rival):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_AUTH_REPLAY")
        self.assertEqual((self.intents(), self.cloud.writes), ([], []))
        self.assertEqual(self.sql("SELECT batch_id FROM batch_registry"), [(rival.batch_id,)])

    def test_first_batch_double_registration_only_one_wins(self):
        batch = self.prepare()
        with self.trusted():
            other = open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
            self.addCleanup(other.close)

        def rival_first():
            with self.trusted():
                other.create_batch_intent(self.authority(batch), scope=self.source.scope,
                                          side_effects=self.source.effects)
        with self.after(self.issuer, "issue", rival_first):
            self.run_blocked(batch)
        self.assertEqual(len(self.intents()), 1)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM batch_registry"), [(1,)])
        self.assertEqual(self.cloud.writes, [])

    def test_first_snapshot_missing_ledger_is_not_unregistered(self):
        batch = self.prepare()
        with mock.patch.object(self.ledger, "batch_execution_state",
                               side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "OUTCOME_UNKNOWN")
        self.assertIsInstance(blocked, HostOutcomeUnknown)
        self.assertEqual(blocked.batch_id, batch.batch_id)
        self.assertEqual((self.sts.calls, self.intents()), ([], []))

    def test_first_scope_hold_or_pending_intent_denied(self):
        batch = self.prepare()
        with self.trusted():
            rival = self.make_batch([volume_record(0)], nonce=os.urandom(16).hex(), cap=1)
            other = open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
            self.addCleanup(other.close)
            other.create_batch_intent(self.authority(rival), scope=self.source.scope,
                                      side_effects=self.source.effects)
        blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_HOLD")
        self.assertEqual(self.sts.calls, [])
        self.assertEqual(self.state(batch).state, "UNREGISTERED")

    def test_active_batch_cap_and_replay_unchanged(self):
        batch = self.prepare(cap=1)
        result = self.run_live(batch)
        self.assertEqual(result.outcomes, ("APPLIED_VERIFIED", "NOT_ATTEMPTED_CAP"))
        with self.trusted(), self.assertRaises(LedgerError):
            self.ledger.create_batch_intent(self.authority(batch, 1), scope=self.source.scope,
                                            side_effects=self.source.effects)
        self.run_live(batch, self.runtime())
        self.assertEqual((len(self.sts.calls), len(self.cloud.writes)), (1, 1))


# ============================================================== refusal windows
class LiveRefusalWindowTests(LiveHarness):
    def test_pre_intent_refusal_zero_intent_permit_write(self):
        batch = self.prepare()
        self.evidence_kind = "synthetic"
        blocked = self.run_blocked(batch)
        self.assertEqual(self.intents(), [])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM intent_history"), [(0,)])
        self.assertEqual(self.cloud.writes, [])
        self.assertEqual(self.state(batch).state, "UNREGISTERED")
        self.assertIsNone(blocked.batch_id)

    def test_post_intent_prepermit_refusal_retains_original_intent(self):
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent", lambda: setattr(self, "revoked", True)):
            self.run_blocked(batch)
        rows = self.sql("SELECT intent_id,state FROM intents")
        self.assertEqual([state for _, state in rows], ["WRITE_INTENT_RECORDED"])
        self.assertEqual(self.sql("SELECT event FROM intent_history"), [("WRITE_INTENT_RECORDED",)])

    def test_post_intent_proven_no_send_atomic_terminal_stop_hold(self):
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent",
                        lambda: setattr(self, "clock_now", self.now + timedelta(minutes=20))):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "AWS_RUNTIME_NOT_AUTHORIZED")  # issued session expired
        self.assertEqual(self.intents(), [("TERMINAL", "NOT_ATTEMPTED_BATCH_STOP", "ec2:CreateTags")])
        self.assertEqual((self.state(batch).state, self.scope_state()), ("STOPPED", "HOLD"))
        self.assertEqual(blocked.batch_id, batch.batch_id)
        stored = self.report_file(batch.batch_id, blocked.report_sha256)
        self.assertEqual(stored["applied_verified_count"], 0)
        self.assertEqual(stored["row_ledger_outcomes"][0][1], "NOT_ATTEMPTED_BATCH_STOP")
        self.assertEqual(self.cloud.writes, [])

    def test_report_failure_after_proven_no_send_remains_blocked(self):
        batch = self.prepare()
        with mock.patch.object(
                self.ledger, "consume_first_send",
                side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")), \
                mock.patch.object(batch_runtime, "_persist_host_report", return_value=None):
            blocked = self.run_blocked(batch)

        self.assertNotIsInstance(blocked, HostOutcomeUnknown)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(self.cloud.writes, [])

    def test_post_intent_uncertain_permit_stays_unresolved_and_blocks(self):
        batch = self.prepare()
        real = self.ledger.consume_first_send

        def consumed_then_lost(handle):
            real(handle)
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        with mock.patch.object(self.ledger, "consume_first_send", consumed_then_lost):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(self.intents(), [("SEND_ATTEMPT_CONSUMED", None, "ec2:CreateTags")])
        self.assertEqual((self.state(batch).state, self.scope_state()), ("STOPPED", "HOLD"))
        self.assertEqual(self.cloud.writes, [])
        self.run_live(batch, self.runtime())
        self.assertEqual((len(self.sts.calls), self.cloud.writes), (1, []))

    def test_scope_proof_changed_before_permit_finalizes_no_send(self):
        """m2: the Host-protected Scope is re-resolved and compared before the Permit."""
        import dataclasses
        batch = self.prepare()

        def change_scope():
            self.source.scope = dataclasses.replace(self.source.scope,
                                                    writer_evidence_digest="e" * 64)
        with self.after(self.ledger, "create_batch_intent", change_scope):
            blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "BLOCKED_SCOPE_MISMATCH")
        self.assertEqual(self.intents(), [("TERMINAL", "NOT_ATTEMPTED_BATCH_STOP", "ec2:CreateTags")])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM intent_history WHERE "
                                  "event='SEND_ATTEMPT_CONSUMED'"), [(0,)])
        self.assertEqual(self.cloud.writes, [])

    def test_stop_batch_alone_not_intent_terminal(self):
        batch = self.prepare()
        with self.trusted():
            other = open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
            self.addCleanup(other.close)
            other.create_batch_intent(self.authority(batch), scope=self.source.scope,
                                      side_effects=self.source.effects)
            self.ledger.stop_batch(batch, reason_code="OPERATOR")
        self.assertEqual(self.intents(), [("WRITE_INTENT_RECORDED", None, "ec2:CreateTags")])
        result = self.run_live(batch)
        self.assertEqual(result.outcomes[0], "UNRESOLVED_WRITE_INTENT")
        self.assertEqual(result.report["unresolved_rows"], [batch.approved_row_indexes[0]])
        self.assertEqual(result.report["outcome_reconciliation"], "UNRESOLVED")

    def test_post_intent_owner_scope_recheck_and_replay_denied(self):
        batch = self.prepare()
        with self.after(self.ledger, "create_batch_intent",
                        lambda: setattr(self, "clock_now", self.now + timedelta(hours=2))):
            self.run_blocked(batch)
        self.clock_now = self.now
        self.run_live(batch, self.runtime())
        with self.trusted(), self.assertRaises(LedgerError):
            self.ledger.create_batch_intent(self.authority(batch), scope=self.source.scope,
                                            side_effects=self.source.effects)
        self.assertEqual((len(self.intents()), self.cloud.writes, len(self.sts.calls)),
                         (1, [], 1))

    def test_issuance_journal_crash_reconciliation_never_reissues_sts(self):
        batch = self.prepare()
        self.sts.error = ConnectionResetError("network vanished mid-STS")
        blocked = self.run_blocked(batch)
        self.assertEqual(blocked.code, "AWS_WRITE_BLOCKED")
        self.assertEqual([r["status"] for r in self.journal()], ["ISSUANCE_UNRESOLVED"])
        self.sts.error = None
        restarted = self.fx.verifier.verify_process(now_utc=self.now)
        blocked = self.run_blocked(batch, self.runtime(host=restarted))
        self.assertEqual(blocked.code, "BLOCKED_ISSUANCE_ATTEMPT_EXISTS")
        self.assertEqual((len(self.sts.calls), self.intents()), (1, []))


# ============================================================== RG-PRC-008
class HostReportPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.state_directory = Path(self._temporary.name)
        self.host = SimpleNamespace(state_directory=str(self.state_directory),
                                    service_uid=os.getuid())

    @staticmethod
    def _report(batch_id):
        return {"batch_id": batch_id, "batch_state": "COMPLETED",
                "applied_verified_count": 1}

    def _paths(self, batch_id, report):
        digest, body = batch_runtime._report_digest(report)
        batch_dir = self.state_directory / "batch-reports" / batch_id
        return digest, body, batch_dir, batch_dir / f"{digest}.json"

    def _persist(self, batch_id, report):
        return batch_runtime._persist_host_report(self.host, batch_id, report)

    def test_new_report_uses_exclusive_temp_file_and_same_directory_replace(self):
        batch_id = "b" * 64
        report = self._report(batch_id)
        digest, body, batch_dir, final_path = self._paths(batch_id, report)
        created = []
        real_open = os.open

        def capture_open(path, flags, mode=0o777):
            if flags & os.O_CREAT:
                created.append((Path(path), flags, mode))
            return real_open(path, flags, mode)

        with mock.patch.object(os, "open", side_effect=capture_open), \
                mock.patch.object(os, "replace", wraps=os.replace) as replace_file:
            self.assertEqual(self._persist(batch_id, report), digest)

        self.assertEqual(len(created), 2)
        report_temp, report_flags, report_mode = created[0]
        index_temp, index_flags, index_mode = created[1]
        index_path = batch_dir / batch_runtime.HOST_REPORT_INDEX_NAME
        self.assertEqual(report_temp.parent, batch_dir)
        self.assertNotEqual(report_temp, final_path)
        self.assertTrue(report_flags & os.O_EXCL)
        self.assertTrue(report_flags & os.O_NOFOLLOW)
        self.assertEqual(report_mode, 0o600)
        self.assertEqual(index_temp.parent, batch_dir)
        self.assertNotEqual(index_temp, index_path)
        self.assertTrue(index_flags & os.O_EXCL)
        self.assertTrue(index_flags & os.O_NOFOLLOW)
        self.assertEqual(index_mode, 0o600)
        replace_file.assert_has_calls([
            mock.call(report_temp, final_path),
            mock.call(index_temp, index_path),
        ])
        self.assertEqual(replace_file.call_count, 2)
        self.assertFalse(report_temp.exists())
        self.assertFalse(index_temp.exists())
        self.assertEqual(final_path.read_bytes(), body)
        self.assertEqual(json.loads(index_path.read_bytes()), {
            "schema": batch_runtime.HOST_REPORT_INDEX_SCHEMA,
            "batch_id": batch_id,
            "report_sha256": digest,
        })

    def test_write_file_fsync_and_replace_failures_clean_temp_and_allow_retry(self):
        failures = (("write", "write"), ("file_fsync", "fsync"),
                    ("replace", "replace"))
        for position, (name, operation) in enumerate(failures, start=1):
            with self.subTest(failure=name):
                batch_id = f"{position:064x}"
                report = self._report(batch_id)
                digest, _body, batch_dir, final_path = self._paths(batch_id, report)
                with mock.patch.object(os, operation, side_effect=OSError(name)):
                    self.assertIsNone(self._persist(batch_id, report))
                self.assertEqual(list(batch_dir.glob(f".{digest}.*.tmp")), [])
                self.assertFalse(final_path.exists())
                self.assertEqual(self._persist(batch_id, report), digest)

    def test_cleanup_failure_does_not_block_retry_with_unique_temp_name(self):
        batch_id = "c" * 64
        report = self._report(batch_id)
        digest, _body, batch_dir, final_path = self._paths(batch_id, report)
        with mock.patch.object(os, "replace", side_effect=OSError("replace failed")), \
                mock.patch.object(os, "unlink", side_effect=OSError("cleanup failed")):
            self.assertIsNone(self._persist(batch_id, report))
        stale_temps = list(batch_dir.glob(f".{digest}.*.tmp"))
        self.assertEqual(len(stale_temps), 1)

        self.assertEqual(self._persist(batch_id, report), digest)
        self.assertTrue(final_path.is_file())
        self.assertIn(stale_temps[0], list(batch_dir.glob(f".{digest}.*.tmp")))

    def test_new_and_reused_reports_sync_file_then_directory_ancestry_bottom_up(self):
        batch_id = "d" * 64
        report = self._report(batch_id)
        digest, _body, batch_dir, final_path = self._paths(batch_id, report)
        report_root = batch_dir.parent
        real_open, real_fsync = os.open, os.fsync
        descriptor_paths = {}
        sync_paths = []

        def capture_open(path, flags, mode=0o777):
            fd = real_open(path, flags, mode)
            descriptor_paths[fd] = Path(path)
            return fd

        def capture_fsync(fd):
            sync_paths.append(descriptor_paths[fd])
            return real_fsync(fd)

        with mock.patch.object(os, "open", side_effect=capture_open), \
                mock.patch.object(os, "fsync", side_effect=capture_fsync):
            self.assertEqual(self._persist(batch_id, report), digest)

        self.assertTrue(sync_paths[0].name.startswith(f".{digest}."))
        self.assertEqual(sync_paths[1:5],
                         [final_path, batch_dir, report_root, self.state_directory])
        self.assertTrue(sync_paths[5].name.startswith(".index-"))
        self.assertEqual(sync_paths[6], batch_dir)

        descriptor_paths.clear()
        sync_paths.clear()
        with mock.patch.object(os, "open", side_effect=capture_open), \
                mock.patch.object(os, "fsync", side_effect=capture_fsync):
            self.assertEqual(self._persist(batch_id, report), digest)
        self.assertEqual(sync_paths[:4], [final_path, batch_dir, report_root, self.state_directory])
        self.assertTrue(sync_paths[4].name.startswith(".index-"))
        self.assertEqual(sync_paths[5], batch_dir)

    def test_reused_digest_requires_exact_verification_and_successful_syncs(self):
        batch_id = "e" * 64
        report = self._report(batch_id)
        digest, body, batch_dir, final_path = self._paths(batch_id, report)
        self.assertEqual(self._persist(batch_id, report), digest)

        final_path.write_bytes(b"x" * len(body))
        self.assertIsNone(self._persist(batch_id, report))
        final_path.write_bytes(body)

        real_open, real_fsync = os.open, os.fsync
        descriptor_paths = {}

        def capture_open(path, flags, mode=0o777):
            fd = real_open(path, flags, mode)
            descriptor_paths[fd] = Path(path)
            return fd

        def fail_batch_directory_sync(fd):
            if descriptor_paths[fd] == batch_dir:
                raise OSError("directory sync failed")
            return real_fsync(fd)

        with mock.patch.object(os, "open", side_effect=capture_open), \
                mock.patch.object(os, "fsync", side_effect=fail_batch_directory_sync):
            self.assertIsNone(self._persist(batch_id, report))

        self.assertEqual(self._persist(batch_id, report), digest)


class LivePartialReportTests(LiveHarness):
    def _partial(self):
        batch = self.prepare()
        self.fail_evidence_on = {2}
        blocked = self.run_blocked(batch)
        return batch, blocked

    def test_row1_applied_verified_row2_blocked_preserves_row1(self):
        batch, blocked = self._partial()
        self.assertEqual(blocked.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        state = self.state(batch)
        self.assertEqual(state.outcomes, ("APPLIED_VERIFIED", "NOT_ATTEMPTED_BATCH_STOP"))
        self.assertEqual(state.state, "STOPPED")
        self.assertEqual(len(self.intents()), 1)
        self.assertEqual(len(self.cloud.writes), 1)

    def test_partial_report_retains_nonzero_applied_count(self):
        batch, blocked = self._partial()
        response = map_blocked("1" * 32, blocked)
        self.assertEqual((response.status, response.batch_id), ("BLOCKED", batch.batch_id))
        stored = self.report_file(batch.batch_id, response.report_sha256)
        self.assertEqual(stored["applied_verified_count"], 1)
        self.assertEqual(stored["send_attempts_consumed"], 1)
        self.assertEqual(stored["refusal_code"], "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual(stored["batch_state"], "STOPPED")
        self.assertEqual(stored["outcome_reconciliation"]["APPLIED_VERIFIED"]["count"], 1)

    def test_partial_report_failure_never_claims_zero_writes(self):
        batch = self.prepare()
        self.fail_evidence_on = {2}
        with mock.patch.object(batch_runtime, "_persist_host_report", return_value=None):
            blocked = self.run_blocked(batch)
        # Row 1 was sent; without a verified report the answer is UNKNOWN, never BLOCKED.
        self.assertIsInstance(blocked, HostOutcomeUnknown)
        response = map_blocked("1" * 32, blocked)
        self.assertEqual((response.status, response.code, response.batch_id,
                          response.report_sha256),
                         ("UNKNOWN", "REPORT_NOT_VERIFIED", batch.batch_id, None))

    def test_completed_report_unverifiable_is_never_complete(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        with mock.patch.object(batch_runtime, "_persist_host_report", return_value=None):
            blocked = self.run_blocked(batch)
        response = map_blocked("1" * 32, blocked)
        self.assertEqual((response.status, response.code), ("UNKNOWN", "REPORT_NOT_VERIFIED"))
        self.assertEqual(len(self.cloud.writes), 1)

    def test_pre_send_refusal_without_report_stays_blocked(self):
        batch = self.prepare()
        self.evidence_kind = "synthetic"
        with mock.patch.object(batch_runtime, "_persist_host_report", return_value=None):
            blocked = self.run_blocked(batch)
        self.assertNotIsInstance(blocked, HostOutcomeUnknown)
        self.assertEqual(map_blocked("1" * 32, blocked).status, "BLOCKED")
        self.assertEqual(self.cloud.writes, [])

    def test_ledger_error_after_send_is_unknown_not_blocked(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        with mock.patch.object(self.ledger, "complete_batch",
                               side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")):
            blocked = self.run_blocked(batch)
        self.assertIsInstance(blocked, HostOutcomeUnknown)
        self.assertEqual(map_blocked("1" * 32, blocked).status, "UNKNOWN")
        self.assertEqual(len(self.cloud.writes), 1)

    def test_rerun_retries_stop_hold_for_undisposed_consumed_permit(self):
        """m3: a rerun never resends; it retries the durable STOP/HOLD."""
        batch = self.prepare(cap=1, records=[volume_record(0)])
        with mock.patch.object(self.ledger, "record_readback",
                               side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")), \
                mock.patch.object(self.ledger, "stop_batch",
                                  side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")), \
                mock.patch.object(self.ledger, "hold_scope",
                                  side_effect=LedgerError("BLOCKED_SCOPE_HOLD")):
            first = self.run_blocked(batch)
        self.assertIsInstance(first, HostOutcomeUnknown)
        self.assertEqual((self.state(batch).state, self.scope_state()), ("ACTIVE", "CLEARED"))
        result = self.run_live(batch, self.runtime())
        self.assertEqual(result.outcomes, ("OUTCOME_UNKNOWN",))
        self.assertEqual((self.state(batch).state, self.scope_state()), ("STOPPED", "HOLD"))
        self.assertEqual(map_endpoint_result("1" * 32, result).status, "UNKNOWN")
        self.assertEqual((len(self.cloud.writes), len(self.sts.calls)), (1, 1))

    def test_response_loss_does_not_mutate_terminal_row(self):
        batch = self.prepare(cap=1, records=[volume_record(0)])
        _, server = self.serve_once(batch)
        before = self.sql("SELECT state,outcome,updated_at_utc FROM intents")
        self.serve_once(batch, "3" * 32)
        self.assertEqual(self.sql("SELECT state,outcome,updated_at_utc FROM intents"), before)
        self.assertEqual(server.response_write_failures, 1)

    def test_repeat_request_never_resends_row1(self):
        batch, _ = self._partial()
        self.fail_evidence_on = set()
        again = self.run_live(batch, self.runtime())
        self.assertEqual(again.outcomes, ("APPLIED_VERIFIED", "NOT_ATTEMPTED_BATCH_STOP"))
        self.assertEqual((len(self.cloud.writes), len(self.sts.calls)), (1, 2))


# ============================================================== carried obligations
class CarriedObligationTests(unittest.TestCase):
    def test_host_runtime_blocked_carries_only_hex64_identity(self):
        ok = HostRuntimeBlocked("X", batch_id="a" * 64, report_sha256="b" * 64)
        self.assertEqual((ok.batch_id, ok.report_sha256), ("a" * 64, "b" * 64))
        bad = HostRuntimeBlocked("X", batch_id="zz", report_sha256="b" * 64)
        self.assertEqual((bad.batch_id, bad.report_sha256), (None, None))
        self.assertEqual(map_blocked("1" * 32, ok).report_sha256, "b" * 64)

    def test_selector_accepts_ledger_no_send_terminals_but_blocks_unresolved(self):
        from name_tag_ledger import BatchExecutionState

        class Ledger:
            def __init__(self, outcomes, consumed):
                self.value = BatchExecutionState("ACTIVE", consumed, 3, outcomes)

            def batch_execution_state(self, batch):
                return self.value
        ok = (("SKIPPED_NAME_CHANGED", "NOT_ATTEMPTED_BATCH_STOP", "UNCLAIMED"), 0)
        snapshot = host_runtime.read_batch_snapshot(Ledger(*ok), None, signed_cap=3, row_count=3)
        self.assertEqual(snapshot.outcomes, ok[0])
        for outcomes, consumed in ((("APPLIED_VERIFIED", "OUTCOME_UNKNOWN", "UNCLAIMED"), 2),
                                   (("SEND_ATTEMPT_CONSUMED", "UNCLAIMED", "UNCLAIMED"), 1),
                                   (("WRITE_INTENT_RECORDED", "UNCLAIMED", "UNCLAIMED"), 0),
                                   (("APPLIED_VERIFIED", "UNCLAIMED", "UNCLAIMED"), 0)):
            with self.subTest(outcomes=outcomes), self.assertRaises(HostRuntimeBlocked):
                host_runtime.read_batch_snapshot(Ledger(outcomes, consumed), None,
                                                 signed_cap=3, row_count=3)

    def test_s3_is_never_a_dispatchable_live_kind(self):
        import dataclasses
        from name_tag_batch_live import live_dispatch_adapter
        promoted = dataclasses.replace(caps.resolve_kind_capability("s3_bucket"),
                                       status="IMPLEMENTED_OFFLINE")
        with mock.patch.object(caps, "_DECISIONS",
                               MappingProxyType({**caps._DECISIONS, "s3_bucket": promoted})):
            with self.assertRaises(LiveWriteBlocked) as caught:
                live_dispatch_adapter("s3_bucket")
        self.assertEqual(caught.exception.code, "TAG_SET_REPLACEMENT_NOT_PROVEN")
        for kind in caps.REGISTRY_KINDS:
            if kind != "volume":
                with self.subTest(kind=kind), self.assertRaises(LiveWriteBlocked):
                    live_dispatch_adapter(kind)

    def test_dispatch_never_reaches_offline_synthetic_consumer(self):
        import inspect
        import name_tag_batch_live as live
        source = inspect.getsource(live) + inspect.getsource(batch_runtime)
        self.assertIn("consume_runtime_grant", inspect.getsource(live.AuthorizedBatchWritePort))
        self.assertNotIn("consume_offline_synthetic_grant", source)

    def test_production_endpoint_still_fails_closed(self):
        endpoint = host_runtime.production_host_endpoint()
        self.assertIsNone(endpoint._coordinator)

    def test_map_endpoint_failure_after_run_is_unknown_not_escaped(self):
        from name_tag_batch_host_server import HOST_COMMAND_UNKNOWN
        from name_tag_batch_fake import BatchRunResult
        server = ProtectedHostIPCServer(os_facade=UnavailableListenerOS(),
                                        peer_policy=PeerPolicy(frozenset(), frozenset()),
                                        host_check=lambda host: host)

        class Bootstrap:
            def verify_process(self, *, now_utc):
                return object()

        class FailingOutcomes:
            def __init__(self):
                self.iterations = 0

            def __iter__(self):
                self.iterations += 1
                raise RuntimeError("mapping bug")

        outcomes = FailingOutcomes()
        result = BatchRunResult("COMPLETED", 0, 1, 1, outcomes, False,
                                MappingProxyType({}))

        class Endpoint:
            calls = 0

            def execute_signed_batch(self, **kwargs):
                self.calls += 1
                return result

        endpoint = Endpoint()
        request = HostIPCRequest(1, "1" * 32, b"p", b"c", b"e")
        response = server._run_accepted(request, Bootstrap(), endpoint)

        self.assertEqual((response.status, response.code), ("UNKNOWN", HOST_COMMAND_UNKNOWN))
        self.assertEqual(response.request_id, request.request_id)
        self.assertEqual((endpoint.calls, outcomes.iterations), (1, 1))


if __name__ == "__main__":
    unittest.main()
