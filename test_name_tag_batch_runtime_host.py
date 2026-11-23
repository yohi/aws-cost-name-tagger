"""Offline Task 6 runtime-host tests: Scope, effective-IAM evidence and one-shot grant.

Fake OS/STS/Ledger/evidence only. Synthetic evidence can never satisfy the protected
(live) verifier: AWS_RUNTIME_NOT_AUTHORIZED stays effective in this phase.
"""
from __future__ import annotations

import copy
import pickle
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest import mock

import name_tag_batch_host_runtime as host_runtime
import name_tag_kind_capabilities as caps
from name_tag_batch_credentials import (
    SYNTHETIC_PROVENANCE, BatchCredentialIssuer, OfflineFakeIssuer)
from name_tag_batch_host_issuer import HostCredentialIssuer
from name_tag_batch_host_runtime import HostRuntimeBlocked, ProtectedBatchHostEndpoint
from name_tag_batch_iam_evidence import (
    IamDenyCase, OfflineSyntheticIamEvidenceVerifier, OfflineSyntheticRuntimeVerifier,
    ProtectedEffectiveIamEvidenceVerifier, ProtectedHostRuntimeVerifier,
    LIVE_PROVENANCE, ProtectedHostScopeVerifier, SyntheticIamEvidenceProducer,
    VerifiedRuntimeGrant, consume_offline_synthetic_grant, consume_runtime_grant,
    ownership_proof_ref)
from name_tag_ledger import FirstSendPermit
from name_tag_scope import ScopeEvidence, SideEffectEvidence
from test_name_tag_batch_host_issuer import IssuerHarness
from test_name_tag_batch_host_runtime import NOW, VOL0, VOL1, owner_verified

H = "a" * 64


class BatchCredentialIssuerContractTests(unittest.TestCase):
    def test_offline_fake_issuer_implements_the_runtime_issuer_contract(self) -> None:
        issuer: BatchCredentialIssuer = OfflineFakeIssuer()

        self.assertTrue(callable(issuer.issue))

    def test_offline_fake_issuer_is_not_a_host_issuer(self) -> None:
        import inspect
        host_params = list(inspect.signature(HostCredentialIssuer.issue).parameters)
        fake_params = list(inspect.signature(OfflineFakeIssuer.issue).parameters)
        self.assertEqual(host_params, ["self", "batch", "subset", "host", "now_utc"])
        self.assertNotEqual(fake_params[:5], host_params)
        self.assertEqual(SYNTHETIC_PROVENANCE, "OFFLINE_SYNTHETIC_NOT_STS")


class FakeScopeSource:
    def __init__(self, arn=VOL0, *, owner="owner", window=timedelta(hours=1), effects="PASS"):
        self.scope = ScopeEvidence(
            account="123456789012", partition="aws", region="ap-northeast-1",
            writer_control_scope_id="s1", controlled_arns=frozenset({arn}),
            not_before_utc=NOW - window, not_after_utc=NOW + window,
            writer_evidence_digest="d" * 64, responsible_owner=owner)
        self.effects = (SideEffectEvidence(
            target_arn=arn, iam_abac_resource_tag_assessment=effects, iac_assessment="PASS",
            event_automation_assessment="PASS", evidence_references=("ref-1",),
            not_before_utc=NOW - window, not_after_utc=NOW + window),)

    def load(self, scope_id, host):
        return self.scope, self.effects


def _deny_cases(arn=VOL0):
    return (
        IamDenyCase("FOREIGN_ARN", arn.replace("vol-0123", "vol-9999"), "ec2:CreateTags", "Name", "DENY"),
        IamDenyCase("OTHER_TAG_KEY", arn, "ec2:CreateTags", "Owner", "DENY"),
        IamDenyCase("ALTERNATE_API", arn, "ec2:DeleteTags", "Name", "DENY"),
    )


class GrantHarness:
    def __init__(self, testcase, **scope_kwargs):
        self.h = IssuerHarness(testcase)
        self.issued = self.h.issue()
        self.authority = self.h.revalidate(self.issued)
        self.capability = caps.resolve_kind_capability("volume")
        self.target = self.issued.selection.target
        self.source = FakeScopeSource(**scope_kwargs)
        self.scope_verifier = ProtectedHostScopeVerifier(source=self.source)
        self.producer = SyntheticIamEvidenceProducer()
        self.h.fx.ledger.owned = True
        self.h.fx.ledger.permit_identity = self.ledger_identity(self.permit())
        self.clock = lambda: NOW

    def scope(self, target=None):
        return self.scope_verifier.resolve("s1", target or self.target, self.h.host, NOW)

    def evidence(self, **changes):
        fields = dict(
            principal_arn=self.issued.receipt.assumed_role_arn, account="123456789012",
            partition="aws", role_policy_digests=(("BatchRole", "v3", H),),
            trust_policy_sha256=H, permission_boundary_sha256=H, scp_sha256=H, rcp_sha256=H,
            resource_policy_sha256=H, session_grant_sha256=H,
            approved_allow=(VOL0, "ec2:CreateTags", "Name"), deny_cases=_deny_cases(),
            source="PROTECTED_EVIDENCE_PRODUCER", captured_at_utc=NOW - timedelta(minutes=1),
            expires_at_utc=NOW + timedelta(minutes=10), captured_state_sha256=H,
            current_state_sha256=H, verifier_result="PASS")
        fields.update(changes)
        return self.producer.produce(**fields)

    def deny(self, evidence=None, scope=None):
        return OfflineSyntheticIamEvidenceVerifier(clock=self.clock).verify(
            self.issued, self.authority, self.capability, scope or self.scope(),
            evidence or self.evidence())

    @staticmethod
    def ledger_identity(permit):
        """What the Ledger's own Intent row records for the consumed Permit."""
        import hashlib
        return (permit.authorization_id, permit.execution_id,
                hashlib.sha256(permit.ownership_token.encode()).hexdigest())

    def grant(self):
        scope = self.scope()
        permit = self.permit()
        grant = OfflineSyntheticRuntimeVerifier(clock=self.clock).authorize_once(
            self.authority, self.issued, scope, self.deny(scope=scope), permit)
        return grant, scope, permit

    def permit(self, **changes):
        row = self.authority.row
        fields = dict(authorization_id="i" * 64, resource_arn=row["resource_arn"],
                      approved_name=row["approved_name"],
                      writer_control_scope_id=row["writer_control_scope_id"],
                      aws_operation=row["aws_operation"], execution_id="e" * 32,
                      ownership_token="t" * 32)
        fields.update(changes)
        return FirstSendPermit(**fields)


class ScopeVerifierTests(unittest.TestCase):
    def test_scope_retains_verified_evidence_for_every_controlled_arn(self):
        g = GrantHarness(self)
        g.source.scope = replace(g.source.scope, controlled_arns=frozenset({VOL0, VOL1}))
        g.source.effects += (SideEffectEvidence(
            target_arn=VOL1, iam_abac_resource_tag_assessment="PASS", iac_assessment="PASS",
            event_automation_assessment="PASS", evidence_references=("ref-2",),
            not_before_utc=NOW - timedelta(minutes=10),
            not_after_utc=NOW + timedelta(minutes=10)),)

        scope = g.scope()

        self.assertEqual(
            tuple(effect.target_arn for effect in scope.side_effects), (VOL0, VOL1))
        self.assertEqual(scope.target.ownership_proof_ref,
                         ownership_proof_ref(g.h.host, scope.scope, VOL0))

    def test_scope_binds_ownership_proof_to_target(self):
        g = GrantHarness(self)
        scope = g.scope()
        self.assertTrue(scope.target.ownership_proof_ref)
        self.assertEqual(scope.target.resource_arn, VOL0)
        self.assertEqual(g.target.ownership_proof_ref, "")  # syntax identity alone carries none
        forged = replace(g.target, ownership_proof_ref="truthy-but-unbound")
        with self.assertRaises(HostRuntimeBlocked):
            g.scope(forged)

    def test_scope_mismatch_hold_or_stale_rejected(self):
        cases = [dict(arn=VOL0.replace("vol-0123", "vol-9999")), dict(effects="UNASSESSED"),
                 dict(window=timedelta(seconds=0))]
        for case in cases:
            with self.subTest(case=case):
                g = GrantHarness(self, **case)
                with self.assertRaises(HostRuntimeBlocked):
                    g.scope()
        g = GrantHarness(self)
        g.h.fx.ledger.scope_states["s1"] = "HOLD"
        with self.assertRaises(HostRuntimeBlocked):
            g.scope()


class EffectiveIamEvidenceTests(unittest.TestCase):
    def test_foreign_arn_tagkey_and_alternate_api_evidence_rejected(self):
        g = GrantHarness(self)
        foreign, other_key, alt_api = _deny_cases()
        approved = (VOL0, "ec2:CreateTags", "Name")
        self.assertEqual((foreign.resource_arn, foreign.action, foreign.tag_key),
                         (VOL0.replace("vol-0123", "vol-9999"), approved[1], approved[2]))
        self.assertEqual((other_key.resource_arn, other_key.action, other_key.tag_key),
                         (approved[0], approved[1], "Owner"))
        self.assertEqual((alt_api.resource_arn, alt_api.action, alt_api.tag_key),
                         (approved[0], "ec2:DeleteTags", approved[2]))
        bad = [
            dict(approved_allow=(VOL0.replace("vol-0123", "vol-9999"), "ec2:CreateTags", "Name")),
            dict(approved_allow=(VOL0, "ec2:CreateTags", "Owner")),
            dict(approved_allow=(VOL0, "ec2:DeleteTags", "Name")),
            dict(deny_cases=(other_key, alt_api)),
            dict(deny_cases=(foreign, alt_api)),
            dict(deny_cases=(foreign, other_key)),
            dict(deny_cases=(replace(foreign, decision="ALLOW"), other_key, alt_api)),
            dict(deny_cases=(replace(foreign, resource_arn=VOL0), other_key, alt_api)),
            dict(deny_cases=(replace(foreign, tag_key="Owner"), other_key, alt_api)),
            dict(deny_cases=(replace(foreign, action="ec2:DeleteTags"), other_key, alt_api)),
            dict(deny_cases=(foreign, replace(other_key, tag_key="Name"), alt_api)),
            dict(deny_cases=(foreign, replace(other_key, action="ec2:DeleteTags"), alt_api)),
            dict(deny_cases=(foreign, other_key, replace(alt_api, action="ec2:CreateTags"))),
            dict(deny_cases=(foreign, other_key, replace(alt_api, tag_key="Owner"))),
            dict(principal_arn="arn:aws:sts::123456789012:assumed-role/Batch/other"),
            dict(source="POLICY_SIMULATOR"),
            dict(source="GET_CALLER_IDENTITY"),
            dict(source="SESSION_POLICY_ONLY"),
            dict(current_state_sha256="b" * 64),  # drift since capture
            dict(verifier_result="TRUE"),
            dict(role_policy_digests=()),
            dict(scp_sha256="not-a-digest"),
        ]
        for n, change in enumerate(bad):
            with self.subTest(n=n):
                with self.assertRaises(HostRuntimeBlocked):
                    g.deny(g.evidence(**change))
        self.assertEqual(g.deny().provenance, "OFFLINE_SYNTHETIC_NOT_STS")

    def test_runtime_evidence_expired_no_intent(self):
        g = GrantHarness(self)
        expired = g.evidence(captured_at_utc=NOW - timedelta(hours=2),
                             expires_at_utc=NOW - timedelta(seconds=1))
        future = g.evidence(captured_at_utc=NOW + timedelta(minutes=1))
        for evidence in (expired, future):
            with self.assertRaises(HostRuntimeBlocked):
                g.deny(evidence)
        deny = g.deny()
        late = OfflineSyntheticRuntimeVerifier(clock=lambda: NOW + timedelta(minutes=11))
        with self.assertRaises(HostRuntimeBlocked):
            late.authorize_once(g.authority, g.issued, g.scope(), deny, g.permit())
        self.assertNotIn("create_batch_intent", g.h.fx.ledger.calls)

    def test_evidence_is_protected_reference_not_fields(self):
        g = GrantHarness(self)
        evidence = g.evidence()
        for attempt in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(HostRuntimeBlocked):
                attempt(evidence)
        with self.assertRaises(HostRuntimeBlocked):
            type(evidence)()  # direct construction is refused
        with self.assertRaises(HostRuntimeBlocked):
            g.deny(mock.Mock(provenance="PROTECTED_LIVE_EVIDENCE"))

    def test_protected_verifier_fails_closed_without_live_evidence(self):
        g = GrantHarness(self)
        with self.assertRaises(HostRuntimeBlocked) as caught:
            ProtectedEffectiveIamEvidenceVerifier(clock=g.clock).verify(
                g.issued, g.authority, g.capability, g.scope(), g.evidence())
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")


class RuntimeGrantTests(unittest.TestCase):
    def test_concurrent_authorize_once_mints_only_one_grant_per_row(self):
        g = GrantHarness(self)
        scope = g.scope()
        denies = (g.deny(scope=scope), g.deny(scope=scope))
        permit = g.permit()
        verifier = OfflineSyntheticRuntimeVerifier(clock=g.clock)
        barrier = threading.Barrier(2)

        outcomes = []

        def authorize(deny):
            try:
                barrier.wait(timeout=5)
                outcomes.append(("grant", verifier.authorize_once(
                    g.authority, g.issued, scope, deny, permit)))
            except HostRuntimeBlocked as error:
                outcomes.append(("blocked", error))

        threads = [threading.Thread(target=authorize, args=(deny,)) for deny in denies]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([kind for kind, _ in outcomes].count("grant"), 1)
        self.assertEqual([kind for kind, _ in outcomes].count("blocked"), 1)

    def test_synthetic_grant_is_one_shot_bound_and_never_live(self):
        g = GrantHarness(self)
        scope = g.scope()
        deny = g.deny(scope=scope)
        permit = g.permit()
        verifier = OfflineSyntheticRuntimeVerifier(clock=g.clock)
        grant = verifier.authorize_once(g.authority, g.issued, scope, deny, permit)
        self.assertIs(type(grant), VerifiedRuntimeGrant)
        self.assertEqual(grant.provenance, "OFFLINE_SYNTHETIC_NOT_STS")
        self.assertEqual(grant.ownership_proof_ref, scope.target.ownership_proof_ref)
        self.assertEqual(grant.receipt_sha256, g.issued.receipt.receipt_sha256)
        for attempt in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(HostRuntimeBlocked):
                attempt(grant)
        with self.assertRaises(HostRuntimeBlocked) as caught:
            consume_runtime_grant(grant, row=g.authority, permit=permit, target=scope.target,
                                  client=object(), now_utc=NOW)  # the dispatch boundary is live-only
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        with self.assertRaises(HostRuntimeBlocked):  # consumed even by the refused attempt
            consume_offline_synthetic_grant(grant, row=g.authority, permit=permit,
                                            target=scope.target, now_utc=NOW)
        with self.assertRaises(HostRuntimeBlocked):  # one Permit -> one grant only
            verifier.authorize_once(g.authority, g.issued, scope, deny, permit)

    def test_offline_grant_consumption_checks_target_and_permit(self):
        g = GrantHarness(self)
        scope = g.scope()
        permit = g.permit()
        grant = OfflineSyntheticRuntimeVerifier(clock=g.clock).authorize_once(
            g.authority, g.issued, scope, g.deny(scope=scope), permit)
        with self.assertRaises(HostRuntimeBlocked):
            consume_offline_synthetic_grant(grant, row=g.authority, permit=g.permit(),
                                            target=scope.target, now_utc=NOW)  # other Permit
        g2 = GrantHarness(self)
        scope2 = g2.scope()
        permit2 = g2.permit()
        grant2 = OfflineSyntheticRuntimeVerifier(clock=g2.clock).authorize_once(
            g2.authority, g2.issued, scope2, g2.deny(scope=scope2), permit2)
        consume_offline_synthetic_grant(grant2, row=g2.authority, permit=permit2,
                                        target=scope2.target, now_utc=NOW)
        with self.assertRaises(HostRuntimeBlocked):
            consume_offline_synthetic_grant(grant2, row=g2.authority, permit=permit2,
                                            target=scope2.target, now_utc=NOW)

    def test_permit_mismatch_unowned_or_constructed_grant_rejected(self):
        g = GrantHarness(self)
        scope = g.scope()
        deny = g.deny(scope=scope)
        verifier = OfflineSyntheticRuntimeVerifier(clock=g.clock)
        for change in (dict(resource_arn=VOL0.replace("vol-0123", "vol-9999")),
                       dict(approved_name="Other"), dict(writer_control_scope_id="s2"),
                       dict(aws_operation="ec2:DeleteTags")):
            with self.subTest(change=change):
                with self.assertRaises(HostRuntimeBlocked):
                    verifier.authorize_once(g.authority, g.issued, scope, deny, g.permit(**change))
        g.h.fx.ledger.owned = False  # Ledger does not show this execution's consumed Permit
        with self.assertRaises(HostRuntimeBlocked):
            verifier.authorize_once(g.authority, g.issued, scope, deny, g.permit())
        with self.assertRaises(HostRuntimeBlocked):
            VerifiedRuntimeGrant()  # type: ignore[call-arg]

    def test_protected_runtime_verifier_rejects_synthetic_deny(self):
        g = GrantHarness(self)
        scope = g.scope()
        with self.assertRaises(HostRuntimeBlocked) as caught:
            ProtectedHostRuntimeVerifier(clock=g.clock).authorize_once(
                g.authority, g.issued, scope, g.deny(scope=scope), g.permit())
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_copy_or_synthetic_session_rejected_by_runtime_gates(self):
        from name_tag_batch_iam import build_subset_session_policy
        from test_name_tag_batch_host_runtime import KIND_REGISTRY
        g = GrantHarness(self)
        synthetic = OfflineFakeIssuer().issue(
            g.h.batch, build_subset_session_policy(g.h.batch, (0,), kind_registry=KIND_REGISTRY),
            kind_registry=KIND_REGISTRY)
        with self.assertRaises(HostRuntimeBlocked):
            OfflineSyntheticIamEvidenceVerifier(clock=g.clock).verify(
                synthetic, g.authority, g.capability, g.scope(), g.evidence())


class GrantFixRoundTests(unittest.TestCase):
    """Review fix round 1: one grant per row/session, live-only dispatch, no promotion."""

    def test_equal_valued_second_permit_cannot_mint_second_grant(self):
        g = GrantHarness(self)
        scope = g.scope()
        deny = g.deny(scope=scope)
        permit = g.permit()
        verifier = OfflineSyntheticRuntimeVerifier(clock=g.clock)
        verifier.authorize_once(g.authority, g.issued, scope, deny, permit)
        twin = g.permit()  # equal-valued, distinct object; Ledger identity still matches
        self.assertEqual(twin, permit)
        with self.assertRaises(HostRuntimeBlocked):  # deny evidence consumed at mint
            verifier.authorize_once(g.authority, g.issued, scope, deny, twin)
        with self.assertRaises(HostRuntimeBlocked):  # fresh deny, same session/row
            verifier.authorize_once(g.authority, g.issued, scope, g.deny(scope=scope), twin)

    def test_permit_not_matching_ledger_intent_rejected(self):
        for change in (dict(ownership_token="x" * 32), dict(execution_id="f" * 32),
                       dict(authorization_id="j" * 64)):
            with self.subTest(change=change):
                g = GrantHarness(self)
                scope = g.scope()
                with self.assertRaises(HostRuntimeBlocked):
                    OfflineSyntheticRuntimeVerifier(clock=g.clock).authorize_once(
                        g.authority, g.issued, scope, g.deny(scope=scope), g.permit(**change))
        g = GrantHarness(self)
        g.h.fx.ledger.permit_identity = None  # no consumed Intent recorded for the row
        scope = g.scope()
        with self.assertRaises(HostRuntimeBlocked):
            OfflineSyntheticRuntimeVerifier(clock=g.clock).authorize_once(
                g.authority, g.issued, scope, g.deny(scope=scope), g.permit())

    def test_dispatch_boundary_has_no_live_flag_and_synthetic_cannot_dispatch(self):
        import inspect
        self.assertEqual(sorted(inspect.signature(consume_runtime_grant).parameters),
                         ["client", "grant", "now_utc", "permit", "row", "target"])
        g = GrantHarness(self)
        grant, scope, permit = g.grant()
        with self.assertRaises(TypeError):
            consume_runtime_grant(grant, row=g.authority, permit=permit, target=scope.target,
                                  now_utc=NOW, require_live=False)
        with self.assertRaises(HostRuntimeBlocked) as caught:
            consume_runtime_grant(grant, row=g.authority, permit=permit, target=scope.target,
                                  client=object(), now_utc=NOW)
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        g2 = GrantHarness(self)
        grant2, scope2, permit2 = g2.grant()
        self.assertIsNone(consume_offline_synthetic_grant(
            grant2, row=g2.authority, permit=permit2, target=scope2.target, now_utc=NOW))

    def test_setattr_provenance_promotion_detected(self):
        g = GrantHarness(self)
        grant, scope, permit = g.grant()
        object.__setattr__(grant, "provenance", LIVE_PROVENANCE)
        with self.assertRaises(HostRuntimeBlocked):
            consume_runtime_grant(grant, row=g.authority, permit=permit, target=scope.target,
                                  client=object(), now_utc=NOW)
        for verifier in (ProtectedHostRuntimeVerifier, OfflineSyntheticRuntimeVerifier):
            with self.subTest(verifier=verifier.__name__):
                g = GrantHarness(self)
                scope = g.scope()
                deny = g.deny(scope=scope)
                object.__setattr__(deny, "provenance", LIVE_PROVENANCE)
                with self.assertRaises(HostRuntimeBlocked):
                    verifier(clock=g.clock).authorize_once(
                        g.authority, g.issued, scope, deny, g.permit())


class LedgerPermitIdentityTests(unittest.TestCase):
    def test_ledger_reports_consumed_permit_identity_for_current_execution(self):
        import hashlib
        import sqlite3
        from name_tag_ledger import IntentLedger
        conn = sqlite3.connect(":memory:")
        conn.executescript(
            "CREATE TABLE batch_rows(batch_id TEXT,row_index INTEGER,intent_id TEXT);"
            "CREATE TABLE intents(intent_id TEXT,authorization_id TEXT,execution_id TEXT,"
            "ownership_token TEXT,state TEXT);"
            "INSERT INTO batch_rows VALUES('b',0,'i1');"
            "INSERT INTO intents VALUES('i1','auth','exec','tok','SEND_ATTEMPT_CONSUMED');"
            "INSERT INTO batch_rows VALUES('b',1,'i2');"
            "INSERT INTO intents VALUES('i2','auth2','exec','tok2','WRITE_INTENT_RECORDED');")

        class _Conn:
            def __enter__(self_inner):
                return conn

            def __exit__(self_inner, *exc):
                return False

        ledger = object.__new__(IntentLedger)
        ledger._execution_id = "exec"
        class _Batch:
            batch_id = "b"

        batch = _Batch()
        with mock.patch("name_tag_ledger.VerifiedBatchApproval", _Batch), \
                mock.patch.object(IntentLedger, "_assert_batch_source_identity"), \
                mock.patch.object(IntentLedger, "_lock"), \
                mock.patch.object(IntentLedger, "_unlock"), \
                mock.patch.object(IntentLedger, "_validate_ledger_state"), \
                mock.patch.object(IntentLedger, "_connection", return_value=_Conn()):
            self.assertEqual(ledger.batch_send_permit_identity(batch, 0),
                             ("auth", "exec", hashlib.sha256(b"tok").hexdigest()))
            self.assertIsNone(ledger.batch_send_permit_identity(batch, 1))  # not consumed
            self.assertIsNone(ledger.batch_send_permit_identity(batch, 2))  # no Intent
            ledger._execution_id = "other"
            self.assertIsNone(ledger.batch_send_permit_identity(batch, 0))  # other execution


class EndpointTests(unittest.TestCase):
    def test_host_without_protected_issuer_returns_aws_runtime_not_authorized(self):
        h = IssuerHarness(self)
        for endpoint in (ProtectedBatchHostEndpoint(),
                         ProtectedBatchHostEndpoint(issuer=OfflineFakeIssuer(), coordinator=object()),
                         host_runtime.production_host_endpoint()):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(HostRuntimeBlocked) as caught:
                    endpoint.execute_signed_batch(
                        plan_bytes=h.batch.plan_bytes, csv_bytes=h.batch.csv_bytes,
                        owner_envelope_bytes=b"{}", host=h.host)
                self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual(h.fx.ledger.calls, [])
        self.assertEqual(h.sts.calls, [])

    def test_endpoint_requires_verified_host_and_owner(self):
        h = IssuerHarness(self)
        endpoint = ProtectedBatchHostEndpoint(issuer=h.issuer, coordinator=mock.Mock())
        with self.assertRaises(HostRuntimeBlocked):
            endpoint.execute_signed_batch(plan_bytes=h.batch.plan_bytes,
                                          csv_bytes=h.batch.csv_bytes,
                                          owner_envelope_bytes=b"{}", host=object())
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()):
            with self.assertRaises(HostRuntimeBlocked) as caught:
                endpoint.execute_signed_batch(plan_bytes=h.batch.plan_bytes,
                                              csv_bytes=h.batch.csv_bytes,
                                              owner_envelope_bytes=b"{}", host=h.host)
        self.assertEqual(caught.exception.code, "BLOCKED_OWNER_AUTHN")
        endpoint._coordinator.run_signed_batch.assert_not_called()

    def test_endpoint_delegates_verified_batch_to_single_coordinator(self):
        h = IssuerHarness(self)
        coordinator = mock.Mock()
        endpoint = ProtectedBatchHostEndpoint(issuer=h.issuer, coordinator=coordinator)
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()), \
                mock.patch("name_tag_batch_approval.verify_batch_approval",
                           return_value=h.batch) as verify:
            result = endpoint.execute_signed_batch(
                plan_bytes=h.batch.plan_bytes, csv_bytes=h.batch.csv_bytes,
                owner_envelope_bytes=b"{}", host=h.host)
        verify.assert_called_once()
        coordinator.run_signed_batch.assert_called_once()
        args, kwargs = coordinator.run_signed_batch.call_args
        self.assertIs(args[0], h.batch)
        self.assertIs(kwargs["host"], h.host)
        self.assertIs(kwargs["issuer"], h.issuer)
        self.assertIs(result, coordinator.run_signed_batch.return_value)


if __name__ == "__main__":
    unittest.main()
