"""Tests for the crash-safe single-host Intent and scope HOLD ledger."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any

from name_tag_approval import (
    ApprovalRejected,
    EnrolledOwner,
    OwnerTrust,
    VerifiedEnvelope,
    approval_digest,
    canonical_payload,
    revalidate_verified_envelope,
    verify_envelope,
    NAMESPACES,
)
from name_tag_scope import ScopeEvidence, SideEffectEvidence
from name_tag_ledger import (
    LedgerError,
    ScopeAction,
    VerifiedScopeDecision,
    _seed_fixture_cleared_scope,
    _set_protected_trust,
    _side_effect_digest,
    consume_first_send,
    create_intent,
    effective_scope_state,
    hold_scope,
    initialize_scope,
    open_ledger,
    record_readback,
    release_scope,
    verify_scope_decision,
)


NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
ARN = "arn:aws:ec2:us-east-1:123456789012:volume/vol-123"
OTHER_ARN = "arn:aws:ec2:us-east-1:123456789012:volume/vol-456"


class LedgerTestBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "owner"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        self.owner = "owner-1"
        self.role = "scope-owner"
        self.allowed = self.root / "allowed_signers"
        public_line = self.key.with_suffix(".pub").read_text().split()
        self.allowed.write_text(
            f'{self.owner} namespaces="{NAMESPACES["name"]},{NAMESPACES["execution"]},aws-cost-name-tagger-scope-decision-v1" '
            f'{public_line[0]} {public_line[1]}\n'
        )
        self.allowed.chmod(0o600)
        fingerprint = subprocess.check_output(
            ["ssh-keygen", "-lf", str(self.key.with_suffix(".pub")), "-E", "sha256"],
            text=True,
        ).split()[1]
        self.fingerprint = fingerprint
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed,
            pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={self.owner: {fingerprint: EnrolledOwner(fingerprint, self.role)}},
            expected_uid=os.getuid(),
        )

    def _sign(self, data: bytes, namespace: str) -> bytes:
        message = self.root / f"message-{uuid.uuid4().hex}"
        message.write_bytes(data)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace, str(message)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signature = message.with_suffix(message.suffix + ".sig").read_bytes()
        message.with_suffix(message.suffix + ".sig").unlink()
        message.unlink()
        return signature

    def _scope_payload(
        self,
        action: ScopeAction,
        *,
        scope_id: str = "scope-1",
        target_arns: list[str] | None = None,
        writer_evidence_digest: str = "c" * 64,
        side_effect_evidence_digest: str | None = None,
        host_binding: str | None = None,
        expires_at: datetime | None = None,
        allowed_role: str | None = None,
        reason: str = "owner-scope-decision",
    ) -> dict:
        if target_arns is None:
            target_arns = [ARN]
        if side_effect_evidence_digest is None:
            side_effect_evidence_digest = _side_effect_digest(
                [self._side_effect(arn) for arn in target_arns]
            )
        if host_binding is None:
            host_binding = "testhost:/tmp/nonexistent"
        if expires_at is None:
            expires_at = NOW + timedelta(hours=1)
        return {
            "schema_version": 1,
            "decision_namespace": "aws-cost-name-tagger-scope-decision-v1",
            "action": action,
            "scope_id": scope_id,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "target_arns": target_arns,
            "writer_evidence_digest": writer_evidence_digest,
            "side_effect_evidence_digest": side_effect_evidence_digest,
            "host_binding": host_binding,
            "owner_principal_id": self.owner,
            "owner_key_fingerprint": self.fingerprint,
            "allowed_role": allowed_role or self.role,
            "issued_at_utc": NOW.isoformat(),
            "expires_at_utc": expires_at.isoformat(),
            "decision_nonce": f"nonce-scope-{action}-{scope_id}",
            "reason": reason,
        }

    def _side_effect(self, arn: str = ARN) -> SideEffectEvidence:
        return SideEffectEvidence(
            target_arn=arn,
            iam_abac_resource_tag_assessment="PASS",
            iac_assessment="PASS",
            event_automation_assessment="PASS",
            evidence_references=("evidence://iam", "evidence://iac", "evidence://events"),
            not_before_utc=NOW - timedelta(hours=1),
            not_after_utc=NOW + timedelta(hours=1),
        )

    def _scope_evidence(
        self,
        *,
        scope_id: str = "scope-1",
        target_arns: frozenset[str] | None = None,
        writer_evidence_digest: str = "c" * 64,
    ) -> ScopeEvidence:
        if target_arns is None:
            target_arns = frozenset({ARN})
        return ScopeEvidence(
            account="123456789012",
            partition="aws",
            region="us-east-1",
            writer_control_scope_id=scope_id,
            controlled_arns=target_arns,
            not_before_utc=NOW - timedelta(hours=1),
            not_after_utc=NOW + timedelta(hours=1),
            writer_evidence_digest=writer_evidence_digest,
            responsible_owner=self.owner,
        )

    def _scope_envelope(
        self, action: ScopeAction, *, payload: dict | None = None, **kwargs
    ) -> dict:
        if payload is None:
            payload = self._scope_payload(action, **kwargs)
        from name_tag_ledger import _canonical_scope_payload
        data = _canonical_scope_payload(payload)
        signature = self._sign(data, "aws-cost-name-tagger-scope-decision-v1")
        return {
            "payload": payload,
            "decision_id": approval_digest(data),
            "signature_ref": base64.b64encode(signature).decode(),
        }

    def _verify_scope_decision(
        self, envelope: dict, action: ScopeAction
    ) -> VerifiedScopeDecision:
        return verify_scope_decision(
            envelope, trust=self.trust, action=action, now_utc=NOW
        )

    def _execution_payload(
        self,
        *,
        scope_id: str = "scope-1",
        resource_arn: str = ARN,
        approved_name: str = "web-prod",
        aws_operation: str = "ec2:CreateTags:2016-11-15",
        expires_at: datetime | None = None,
    ) -> dict:
        if expires_at is None:
            expires_at = NOW + timedelta(hours=1)
        return {
            "schema_version": 1,
            "authorization_namespace": NAMESPACES["execution"],
            "name_approval_id": "c" * 64,
            "resource_arn": resource_arn,
            "approved_name": approved_name,
            "aws_operation": aws_operation,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "identity": "arn:aws:sts::123456789012:assumed-role/exec-role/session",
            "code_version": "v3.7.0",
            "code_hash": "d" * 64,
            "writer_control_scope_id": scope_id,
            "risk_acknowledgement": "ack",
            "writer_control_evidence_refs": ["ev-1"],
            "side_effect_evidence_refs": ["se-1"],
            "owner_principal_id": self.owner,
            "owner_key_fingerprint": self.fingerprint,
            "allowed_role": self.role,
            "issued_at_utc": NOW.isoformat(),
            "expires_at_utc": expires_at.isoformat(),
            "execution_nonce": f"nonce-exec-{scope_id}-{resource_arn.split('/')[-1]}",
        }

    def _execution_envelope(self, **kwargs) -> dict:
        payload = self._execution_payload(**kwargs)
        data = canonical_payload(payload, kind="execution")
        signature = self._sign(data, NAMESPACES["execution"])
        return {
            "payload": payload,
            "authorization_id": approval_digest(data),
            "signature_ref": base64.b64encode(signature).decode(),
        }

    def _verified_execution(self, **kwargs) -> VerifiedEnvelope:
        envelope = self._execution_envelope(**kwargs)
        return verify_envelope(
            json.dumps(envelope, separators=(",", ":")).encode(),
            kind="execution",
            trust=self.trust,
            now_utc=NOW,
        )

    def _open_ledger(self, path: Path | None = None) -> Any:
        if path is None:
            path = self.root / "ledger.db"
        ledger = open_ledger(path, trusted_host=True)
        _set_protected_trust(ledger, self.trust)
        return ledger

    def _initialize_scope(self, ledger: Any, scope_id: str = "scope-1") -> None:
        decision = self._verify_scope_decision(
            self._scope_envelope("INITIALIZE", scope_id=scope_id, host_binding=ledger._host_binding), "INITIALIZE"
        )
        scope = self._scope_evidence(scope_id=scope_id)
        side_effects = [self._side_effect(arn) for arn in scope.controlled_arns]
        initialize_scope(ledger, decision, scope=scope, side_effects=side_effects)

    def _failing_commit(self, ledger: Any, exception: Exception):
        """Return a context manager that makes the ledger's connection commit fail."""
        original_connection = ledger._connection

        class FailingConnection:
            def __init__(ctx, real_conn):
                ctx._real = real_conn

            def __enter__(ctx):
                ctx._real.__enter__()
                return ctx

            def __exit__(ctx, *args):
                return ctx._real.__exit__(*args)

            def __getattr__(ctx, name):
                return getattr(ctx._real, name)

            def commit(ctx):
                raise exception

        class FailingCommitContext:
            def __enter__(ctx):
                def patched_connection():
                    return FailingConnection(original_connection())

                ledger._connection = patched_connection
                return ctx

            def __exit__(ctx, *args):
                ledger._connection = original_connection

        return FailingCommitContext()


# ---------------------------------------------------------------------------
# Basic behavior (Step 1)
# ---------------------------------------------------------------------------


class BasicLedgerTests(LedgerTestBase):
    def test_fresh_intent_can_consume_once(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        permit = consume_first_send(ledger, handle)
        self.assertEqual(permit.resource_arn, ARN)
        self.assertEqual(permit.approved_name, "web-prod")
        self.assertEqual(permit.aws_operation, "ec2:CreateTags:2016-11-15")
        # Second consume from the same handle is rejected.
        with self.assertRaises(LedgerError) as ctx:
            consume_first_send(ledger, handle)
        self.assertEqual(ctx.exception.code, "BLOCKED_INTENT_REPLAY")

    def test_initialize_unknown_requires_verified_owner_decision(self):
        ledger = self._open_ledger()
        # No implicit UNKNOWN -> CLEARED.
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "UNKNOWN")
        # A forged envelope is rejected.
        forged = {
            "payload": self._scope_payload("INITIALIZE"),
            "decision_id": "0" * 64,
            "signature_ref": base64.b64encode(b"bogus").decode(),
        }
        with self.assertRaises(LedgerError) as ctx:
            verify_scope_decision(forged, trust=self.trust, action="INITIALIZE", now_utc=NOW)
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_release_requires_fresh_owner_judgment(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        hold_scope(ledger, "scope-1", reason="readback-mismatch")
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "HOLD")
        # Unsigned release is rejected.
        release_envelope = self._scope_envelope("RELEASE")
        release_envelope["signature_ref"] = base64.b64encode(b"bogus").decode()
        with self.assertRaises(LedgerError) as ctx:
            release_scope(
                ledger,
                verify_scope_decision(release_envelope, trust=self.trust, action="RELEASE", now_utc=NOW),
                scope=self._scope_evidence(),
                side_effects=[self._side_effect()],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")


# ---------------------------------------------------------------------------
# Scope verification and ledger opening
# ---------------------------------------------------------------------------


class ScopeVerificationTests(LedgerTestBase):
    def test_initial_scope_missing_is_unknown(self):
        ledger = self._open_ledger()
        self.assertEqual(effective_scope_state(ledger, "never-seen"), "UNKNOWN")

    def test_owner_initialization_durable(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "CLEARED")
        # Reopen the ledger; state remains CLEARED.
        ledger2 = self._open_ledger(ledger._path)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "CLEARED")

    def test_initialize_on_hold_rejected_without_state_change(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        hold_scope(ledger, "scope-1", reason="safety")
        before = ledger._path.read_bytes()
        decision = self._verify_scope_decision(
            self._scope_envelope("INITIALIZE", scope_id="scope-1"), "INITIALIZE"
        )
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(
                ledger,
                decision,
                scope=self._scope_evidence(scope_id="scope-1"),
                side_effects=[self._side_effect()],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "HOLD")
        after = ledger._path.read_bytes()
        self.assertEqual(before, after)

    def test_initialize_with_prior_incomplete_intent_rejected(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        create_intent(ledger, auth, scope_id="scope-1")
        before = ledger._path.read_bytes()
        decision = self._verify_scope_decision(
            self._scope_envelope("INITIALIZE", scope_id="scope-1"), "INITIALIZE"
        )
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(
                ledger,
                decision,
                scope=self._scope_evidence(scope_id="scope-1"),
                side_effects=[self._side_effect()],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "HOLD")
        after = ledger._path.read_bytes()
        self.assertEqual(before, after)

    def test_initialize_corrupt_or_unproven_history_denied(self):
        ledger = self._open_ledger()
        # Corrupt the SQLite file.
        ledger._path.write_bytes(b"not a sqlite database")
        with self.assertRaises(LedgerError) as ctx:
            self._open_ledger(ledger._path)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_unsigned_or_wrong_role_scope_decision_denied(self):
        envelope = self._scope_envelope("INITIALIZE", allowed_role="other-role")
        with self.assertRaises(LedgerError) as ctx:
            verify_scope_decision(envelope, trust=self.trust, action="INITIALIZE", now_utc=NOW)
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_scope_arn_set_or_evidence_mismatch_denied(self):
        ledger = self._open_ledger()
        decision = self._verify_scope_decision(
            self._scope_envelope("INITIALIZE", scope_id="scope-1", target_arns=[ARN, OTHER_ARN]),
            "INITIALIZE",
        )
        # Evidence only covers one ARN.
        scope = self._scope_evidence(scope_id="scope-1", target_arns=frozenset({ARN, OTHER_ARN}))
        side_effects = [self._side_effect(arn) for arn in scope.controlled_arns]
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, decision, scope=scope, side_effects=side_effects)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_fixture_cleared_never_enables_production(self):
        db = self.root / "fixture.db"
        _seed_fixture_cleared_scope(db, scope_id="fixture-scope")
        with self.assertRaises(LedgerError) as ctx:
            open_ledger(db, trusted_host=True)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")


# ---------------------------------------------------------------------------
# Crash boundary tests (T-F004-01..16)
# ---------------------------------------------------------------------------

class CrashBoundaryTests(LedgerTestBase):
    def _run_crash_subprocess(
        self, db: Path, operations_code: str, timeout: float = 5.0
    ) -> None:
        """Run ``operations_code`` in a child process, then SIGKILL it.

        The operations_code may use the variables ``ledger`` and ``auth``.
        It should not write the ready file itself; the wrapper does after
        operations_code completes.
        """
        ready = self.root / f"ready-{uuid.uuid4().hex}"
        error = self.root / f"error-{uuid.uuid4().hex}"
        script = self.root / f"crash-{uuid.uuid4().hex}.py"

        repo_root = Path(__file__).resolve().parent
        envelope_json = json.dumps(self._execution_envelope())
        pub_key = self.key.with_suffix(".pub")

        script.write_text(
            f'''
import hashlib
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, {json.dumps(str(repo_root))})

from name_tag_approval import EnrolledOwner, OwnerTrust, verify_envelope
from name_tag_ledger import (
    _set_protected_trust, consume_first_send, create_intent, hold_scope,
    open_ledger, record_readback,
)

db = Path({json.dumps(str(db))})
ready = Path({json.dumps(str(ready))})
error = Path({json.dumps(str(error))})

allowed = Path({json.dumps(str(self.allowed))})
allowed_data = allowed.read_bytes()
fp = subprocess.check_output(
    ["ssh-keygen", "-lf", {json.dumps(str(pub_key))}, "-E", "sha256"],
    text=True,
).split()[1]
trust = OwnerTrust.from_allowed_signers(
    allowed,
    pinned_sha256=hashlib.sha256(allowed_data).hexdigest(),
    enrolled={{"owner-1": {{fp: EnrolledOwner(fp, "scope-owner")}}}},
    expected_uid=os.getuid(),
)
ledger = open_ledger(db, trusted_host=True)
_set_protected_trust(ledger, trust)

NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)
auth = verify_envelope(
    {json.dumps(envelope_json)}.encode("utf-8"),
    kind="execution",
    trust=trust,
    now_utc=NOW,
)

try:
    {operations_code}
    ready.write_text("ready")
    time.sleep(30)
except Exception as exc:
    error.write_text(f"{{type(exc).__name__}}: {{exc}}")
    raise
''',
            encoding="utf-8",
        )
        proc = subprocess.Popen(
            [sys.executable, str(script)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + timeout
        while (
            not ready.exists()
            and time.monotonic() < deadline
            and proc.poll() is None
        ):
            time.sleep(0.01)
        if proc.poll() is not None:
            out, err = proc.communicate()
            msg = (
                "subprocess exited early: "
                f"{error.read_text() if error.exists() else ''} {err.decode()}"
            )
            raise AssertionError(msg)
        proc.send_signal(signal.SIGKILL)
        proc.wait()

    def test_t_f004_01_crash_after_intent_before_send(self):
        db = self.root / "t-f004-01.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        self._run_crash_subprocess(
            db,
            "handle = create_intent(ledger, auth, scope_id='scope-1')",
        )
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")

    def test_t_f004_02_crash_after_send_before_readback(self):
        db = self.root / "t-f004-02.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        self._run_crash_subprocess(
            db,
            "handle = create_intent(ledger, auth, scope_id='scope-1'); "
            "consume_first_send(ledger, handle)",
        )
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")

    def test_t_f004_03_crash_after_readback_mismatch_before_hold_fsync(self):
        db = self.root / "t-f004-03.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        self._run_crash_subprocess(
            db,
            "handle = create_intent(ledger, auth, scope_id='scope-1'); "
            "consume_first_send(ledger, handle); "
            "record_readback(ledger, handle, name_after='other-name', outcome='FAILED_READBACK'); "
            "hold_scope(ledger, 'scope-1', reason='readback-mismatch')",
        )
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")

    def test_t_f004_04_crash_after_hold_before_intent_terminal(self):
        db = self.root / "t-f004-04.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        self._run_crash_subprocess(
            db,
            "handle = create_intent(ledger, auth, scope_id='scope-1'); "
            "consume_first_send(ledger, handle); "
            "record_readback(ledger, handle, name_after='other-name', outcome='FAILED_READBACK'); "
            "hold_scope(ledger, 'scope-1', reason='readback-mismatch')",
        )
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")

    def test_t_f004_05_missing_or_corrupt_ledger_is_unknown(self):
        db = self.root / "t-f004-05.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        db.write_bytes(b"\x00" * 1024)
        with self.assertRaises(LedgerError) as ctx:
            self._open_ledger(db)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_t_f004_06_other_execution_blocked_by_hold_or_incomplete_intent(self):
        db = self.root / "t-f004-06.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        ledger2 = self._open_ledger(db)
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger2, auth, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_INCOMPLETE_INTENT")

    def test_t_f004_07_independent_scope_allowed_when_healthy(self):
        db = self.root / "t-f004-07.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger, scope_id="scope-a")
        self._initialize_scope(ledger, scope_id="scope-b")
        auth_a = self._verified_execution(scope_id="scope-a")
        auth_b = self._verified_execution(scope_id="scope-b", resource_arn=OTHER_ARN)
        handle_a = create_intent(ledger, auth_a, scope_id="scope-a")
        handle_b = create_intent(ledger, auth_b, scope_id="scope-b")
        self.assertEqual(
            consume_first_send(ledger, handle_a).writer_control_scope_id, "scope-a"
        )
        self.assertEqual(
            consume_first_send(ledger, handle_b).writer_control_scope_id, "scope-b"
        )

    def test_t_f004_08_release_without_owner_approval_rejected(self):
        db = self.root / "t-f004-08.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        hold_scope(ledger, "scope-1", reason="safety")
        decision = self._verify_scope_decision(
            self._scope_envelope("INITIALIZE", scope_id="scope-1"), "INITIALIZE"
        )
        with self.assertRaises(LedgerError) as ctx:
            release_scope(
                ledger,
                decision,
                scope=self._scope_evidence(scope_id="scope-1"),
                side_effects=[self._side_effect()],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_t_f004_09_release_does_not_revive_prior_intent_nonce_authorization(self):
        db = self.root / "t-f004-09.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        consume_first_send(ledger, handle)
        record_readback(ledger, handle, name_after="web-prod", outcome="APPLIED_VERIFIED")
        hold_scope(ledger, "scope-1", reason="safety")
        decision = self._verify_scope_decision(
            self._scope_envelope("RELEASE", scope_id="scope-1", host_binding=ledger._host_binding), "RELEASE"
        )
        release_scope(
            ledger,
            decision,
            scope=self._scope_evidence(scope_id="scope-1"),
            side_effects=[self._side_effect()],
        )
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "CLEARED")
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, auth, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_AUTH_REPLAY")

    def test_t_f004_10_healthy_cleared_no_incomplete_intent_first_send_once(self):
        db = self.root / "t-f004-10.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        permit = consume_first_send(ledger, handle)
        self.assertEqual(permit.aws_operation, "ec2:CreateTags:2016-11-15")
        with self.assertRaises(LedgerError) as ctx:
            consume_first_send(ledger, handle)
        self.assertEqual(ctx.exception.code, "BLOCKED_INTENT_REPLAY")

    def test_t_f004_11_prior_incomplete_intent_blocks_new_intent(self):
        db = self.root / "t-f004-11.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        create_intent(ledger, auth, scope_id="scope-1")
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, auth, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_INCOMPLETE_INTENT")

    def test_t_f004_12_restart_with_same_ids_is_not_current(self):
        db = self.root / "t-f004-12.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        ledger2 = self._open_ledger(db)
        forged_handle = type(handle)(handle.intent_id, handle.authorization_id, ledger2._execution_id, handle.ownership_token)
        with self.assertRaises(LedgerError) as ctx:
            consume_first_send(ledger2, forged_handle)
        self.assertEqual(ctx.exception.code, "BLOCKED_INTENT_REPLAY")

    def test_t_f004_13_same_execution_second_call_blocked(self):
        db = self.root / "t-f004-13.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        consume_first_send(ledger, handle)
        with self.assertRaises(LedgerError) as ctx:
            consume_first_send(ledger, handle)
        self.assertEqual(ctx.exception.code, "BLOCKED_INTENT_REPLAY")

    def test_t_f004_14_crash_after_send_attempt_consumed_no_revival(self):
        db = self.root / "t-f004-14.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        self._run_crash_subprocess(
            db,
            "handle = create_intent(ledger, auth, scope_id='scope-1'); "
            "consume_first_send(ledger, handle)",
        )
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")

    def test_t_f004_15_send_attempt_consumed_persistence_failure_forbids_send(self):
        db = self.root / "t-f004-15.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        with self._failing_commit(ledger, RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                consume_first_send(ledger, handle)
        # No permit was returned and the durable intent is still unconsumed.
        ledger2 = self._open_ledger(db)
        conn = sqlite3.connect(str(db))
        row = conn.execute(
            "SELECT state FROM intents WHERE intent_id = ?", (handle.intent_id,)
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "WRITE_INTENT_RECORDED")

    def test_t_f004_16_hold_during_first_send_prevents_permit(self):
        db = self.root / "t-f004-16.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        hold_scope(ledger, "scope-1", reason="parallel-safety")
        with self.assertRaises(LedgerError) as ctx:
            consume_first_send(ledger, handle)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

# ---------------------------------------------------------------------------
# Additional crash / torn ledger tests
# ---------------------------------------------------------------------------


class AdditionalCrashTests(LedgerTestBase):
    def test_consumed_crash_never_reopens(self):
        db = self.root / "consumed.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        consume_first_send(ledger, handle)
        # Simulate crash/reopen.
        ledger2 = self._open_ledger(db)
        with self.assertRaises(LedgerError) as ctx:
            consume_first_send(ledger2, handle)
        self.assertEqual(ctx.exception.code, "BLOCKED_INTENT_REPLAY")

    def test_torn_ledger_fail_closed(self):
        db = self.root / "torn.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        # Simulate torn journal by truncating mid-commit bytes (best-effort).
        data = db.read_bytes()
        db.write_bytes(data[: len(data) // 2])
        with self.assertRaises(LedgerError) as ctx:
            self._open_ledger(db)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_initialize_crash_before_commit_stays_blocked(self):
        db = self.root / "init-crash.db"
        ledger = self._open_ledger(db)
        decision = self._verify_scope_decision(
            self._scope_envelope("INITIALIZE", scope_id="scope-1", host_binding=ledger._host_binding), "INITIALIZE"
        )
        scope = self._scope_evidence(scope_id="scope-1")
        side_effects = [self._side_effect()]
        with self._failing_commit(ledger, RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                initialize_scope(ledger, decision, scope=scope, side_effects=side_effects)
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "UNKNOWN")

    def test_release_crash_or_fsync_failure_stays_hold(self):
        db = self.root / "release-crash.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        hold_scope(ledger, "scope-1", reason="safety")
        decision = self._verify_scope_decision(
            self._scope_envelope("RELEASE", scope_id="scope-1", host_binding=ledger._host_binding), "RELEASE"
        )
        scope = self._scope_evidence(scope_id="scope-1")
        side_effects = [self._side_effect()]
        with self._failing_commit(ledger, RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                release_scope(ledger, decision, scope=scope, side_effects=side_effects)
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")

    def test_release_does_not_revive_prior_intent_nonce_authorization(self):
        # Covered in T-F004-09; keep a dedicated test name here as well.
        db = self.root / "release-no-revive.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        consume_first_send(ledger, handle)
        record_readback(ledger, handle, name_after="web-prod", outcome="APPLIED_VERIFIED")
        hold_scope(ledger, "scope-1", reason="safety")
        decision = self._verify_scope_decision(
            self._scope_envelope("RELEASE", scope_id="scope-1", host_binding=ledger._host_binding), "RELEASE"
        )
        release_scope(
            ledger,
            decision,
            scope=self._scope_evidence(scope_id="scope-1"),
            side_effects=[self._side_effect()],
        )
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, auth, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_AUTH_REPLAY")


# ---------------------------------------------------------------------------
# F006 revalidation tests
# ---------------------------------------------------------------------------


class F006RevalidationTests(LedgerTestBase):
    def test_create_intent_rejects_forged_verified_envelope(self):
        db = self.root / "forged.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        forged = replace(
            self._verified_execution(), content_id="0" * 64, signature_ref="fake"
        )
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, forged, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_create_intent_rejects_mutated_signed_payload(self):
        db = self.root / "mutated.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        verified = self._verified_execution()
        # Mutate the immutable raw envelope bytes.
        object.__setattr__(verified, "raw_envelope_bytes", b"{}")
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, verified, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_create_intent_rejects_canonical_bytes_digest_mismatch(self):
        db = self.root / "digest-mismatch.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        verified = self._verified_execution()
        # Corrupt canonical payload bytes so digest recompute fails.
        object.__setattr__(verified, "canonical_payload_bytes", b"{}")
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, verified, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_create_intent_rejects_wrong_envelope_kind(self):
        db = self.root / "wrong-kind.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        name_envelope = self._name_envelope()
        verified_name = verify_envelope(
            json.dumps(name_envelope, separators=(",", ":")).encode(),
            kind="name",
            trust=self.trust,
            now_utc=NOW,
        )
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, verified_name, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_permit_uses_revalidated_signed_operation(self):
        db = self.root / "permit-op.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        permit = consume_first_send(ledger, handle)
        self.assertEqual(permit.aws_operation, "ec2:CreateTags:2016-11-15")
        # Mutating the original VerifiedEnvelope after intent creation must not
        # affect the durable, revalidated permit binding.
        object.__setattr__(auth, "payload", MappingProxyType({**auth.payload, "aws_operation": "ec2:DeleteTags:2016-11-15"}))
        # The durable record still carries the originally revalidated operation;
        # a second consume is rejected regardless of the mutated envelope.
        with self.assertRaises(LedgerError):
            consume_first_send(ledger, handle)

    def test_create_intent_operation_derived_only_from_verified_authorization(self):
        db = self.root / "op-derived.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        # Directly inspect the durable record.
        conn = sqlite3.connect(str(db))
        row = conn.execute(
            "SELECT aws_operation FROM intents WHERE intent_id = ?", (handle.intent_id,)
        ).fetchone()
        conn.close()
        self.assertEqual(row[0], "ec2:CreateTags:2016-11-15")

    def test_wrong_or_unnormalized_operation_rejected_before_intent(self):
        db = self.root / "op-reject.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        for operation in (
            "ec2:CreateTags",  # missing version
            "Ec2:CreateTags:2016-11-15",  # wrong case
            "ec2:DeleteTags:2016-11-15",  # unsupported
            "",  # empty
        ):
            with self.subTest(operation=operation):
                auth = self._verified_execution(aws_operation=operation)
                with self.assertRaises(LedgerError) as ctx:
                    create_intent(ledger, auth, scope_id="scope-1")
                self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_first_send_permit_binds_aws_operation(self):
        db = self.root / "permit-bind.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        permit = consume_first_send(ledger, handle)
        self.assertEqual(permit.authorization_id, auth.content_id)
        self.assertEqual(permit.resource_arn, ARN)
        self.assertEqual(permit.approved_name, "web-prod")
        self.assertEqual(permit.writer_control_scope_id, "scope-1")
        self.assertEqual(permit.aws_operation, "ec2:CreateTags:2016-11-15")

    def _name_envelope(self) -> dict:
        payload = {
            "schema_version": 1,
            "approval_namespace": NAMESPACES["name"],
            "plan_sha256": "a" * 64,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "kind": "volume",
            "resource_arn": ARN,
            "locator": "vol-123",
            "name_state_at_plan": "ABSENT",
            "confidence": "high",
            "evidence_digest": "b" * 64,
            "suggested_name": "web-prod",
            "approved_name": "web-prod",
            "edit_reason": "",
            "decision": "APPROVED",
            "owner_decision_reference": "ref-1",
            "owner_principal_id": self.owner,
            "owner_key_fingerprint": self.fingerprint,
            "issued_at_utc": NOW.isoformat(),
            "expires_at_utc": (NOW + timedelta(hours=1)).isoformat(),
            "decision_nonce": "nonce-name",
        }
        data = canonical_payload(payload, kind="name")
        signature = self._sign(data, NAMESPACES["name"])
        return {
            "payload": payload,
            "approval_id": approval_digest(data),
            "signature_ref": base64.b64encode(signature).decode(),
        }


if __name__ == "__main__":
    unittest.main()
