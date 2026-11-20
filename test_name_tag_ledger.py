"""Tests for the crash-safe single-host Intent and scope HOLD ledger."""

from __future__ import annotations

import base64
import fcntl
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
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import patch

from name_tag_approval import (
    EnrolledOwner,
    OwnerTrust,
    VerifiedEnvelope,
    approval_digest,
    canonical_payload,
    verify_envelope,
    NAMESPACES,
)
from name_tag_scope import ScopeEvidence, SideEffectEvidence
import name_tag_ledger_anchor as ledger_anchor
import name_tag_ledger_provision as ledger_provision
from name_tag_ledger import (
    IntentLedger,
    LedgerError,
    _side_effect_digest,
    ScopeAction,
    VerifiedScopeDecision,
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
        self.anchor_directory = self.root / "anchors"
        self.anchor_directory.mkdir(mode=0o700)
        for target, name, value in (
            (ledger_anchor, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory),
            (ledger_anchor, "_ANCHOR_OWNER_UID", os.geteuid()),
            (ledger_anchor, "require_root", lambda: None),
            (ledger_provision, "_require_root", lambda: None),
        ):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
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

    def _scope_payload_for(
        self,
        ledger,
        action: ScopeAction,
        **kwargs,
    ) -> dict:
        if "host_binding" not in kwargs:
            kwargs["host_binding"] = ledger._host_binding
        return self._scope_payload(action, **kwargs)

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
        hold_generation_id: str | None = None,
    ) -> dict:
        if target_arns is None:
            target_arns = [ARN]
        if side_effect_evidence_digest is None:
            side_effect_evidence_digest = _side_effect_digest(
                [self._side_effect(arn) for arn in target_arns]
            )
        if host_binding is None:
            host_binding = "__ledger_host_binding__"
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
            "hold_generation_id": hold_generation_id,
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


    def _fixture_only_seed_cleared_scope(self, ledger):
        """Insert a fixture-only CLEARED scope row; rejected by public API."""
        with closing(sqlite3.connect(str(ledger._path))) as conn, conn:
            ts = NOW.isoformat()
            conn.execute(
                """
                INSERT INTO scopes (
                    scope_id, state, account, partition, region, target_arns,
                    writer_evidence_digest, side_effect_evidence_digest, host_binding,
                    owner_principal_id, decision_id, issued_at_utc, expires_at_utc,
                    reason, fixture_only, created_at_utc, updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    "fixture-scope", "CLEARED", "123456789012", "aws", "us-east-1",
                    json.dumps([ARN], separators=(",", ":")),
                    "c" * 64, "c" * 64, ledger._host_binding, self.owner,
                    "decision-fixture", ts, ts, "fixture", ts, ts,
                ),
            )
            conn.commit()

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
        self, action: ScopeAction, *, ledger=None, payload: dict | None = None, **kwargs
    ) -> dict:
        if payload is None:
            if ledger is not None and "host_binding" not in kwargs:
                kwargs["host_binding"] = ledger._host_binding
            if action == "RELEASE" and ledger is not None:
                with closing(sqlite3.connect(str(ledger._path))) as conn:
                    row = conn.execute(
                        "SELECT id FROM scope_history WHERE scope_id = ? AND state = 'HOLD' ORDER BY id DESC LIMIT 1",
                        (kwargs.get("scope_id", "scope-1"),),
                    ).fetchone()
                kwargs["hold_generation_id"] = str(row[0]) if row else None
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

    def _verify_scope_decision_for(
        self, ledger, action: ScopeAction, **kwargs
    ) -> VerifiedScopeDecision:
        if "host_binding" not in kwargs:
            kwargs["host_binding"] = ledger._host_binding
        envelope = self._scope_envelope(action, **kwargs)
        return self._verify_scope_decision(envelope, action)

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
        if not path.exists():
            ledger_provision.initialize_ledger(path, runtime_uid=os.geteuid())
        ledger = open_ledger(path, trusted_host=True, trust=self.trust)
        self.addCleanup(ledger.close)
        ledger._now = lambda: NOW
        return ledger

    def _initialize_scope(self, ledger: Any, scope_id: str = "scope-1") -> None:
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id=scope_id)
        scope = self._scope_evidence(scope_id=scope_id)
        side_effects = [self._side_effect(arn) for arn in scope.controlled_arns]
        initialize_scope(ledger, envelope, action="INITIALIZE", scope=scope, side_effects=side_effects)

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
                try:
                    ctx._real._conn.rollback()
                except Exception:
                    pass
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
        # Unsigned release is rejected at verification.
        release_envelope = self._scope_envelope("RELEASE", ledger=ledger)
        release_envelope["signature_ref"] = base64.b64encode(b"bogus").decode()
        with self.assertRaises(LedgerError) as ctx:
            verify_scope_decision(release_envelope, trust=self.trust, action="RELEASE", now_utc=NOW)
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")


# ---------------------------------------------------------------------------
# Scope verification and ledger opening
# ---------------------------------------------------------------------------


class ScopeVerificationTests(LedgerTestBase):
    def test_open_ledger_receives_owner_trust(self):
        ledger = self._open_ledger()
        self.assertIs(ledger._trust, self.trust)

    def test_connection_closes_and_normalizes_sqlite_pragma_failure(self):
        ledger = self._open_ledger()

        class FailingConnection:
            closed = False

            def execute(self, sql):
                raise sqlite3.DatabaseError("invalid database")

            def close(self):
                self.closed = True

        connection = FailingConnection()
        with patch("name_tag_ledger.sqlite3.connect", return_value=connection):
            with self.assertRaises(LedgerError) as ctx:
                ledger._connection()

        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertTrue(connection.closed)

    def test_connection_closes_when_journal_mode_is_not_delete(self):
        ledger = self._open_ledger()

        class UnexpectedJournalModeConnection:
            closed = False

            def execute(self, sql):
                return self

            def fetchone(self):
                return ("wal",)

            def close(self):
                self.closed = True

        connection = UnexpectedJournalModeConnection()
        with patch("name_tag_ledger.sqlite3.connect", return_value=connection):
            with self.assertRaises(LedgerError) as ctx:
                ledger._connection()

        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertTrue(connection.closed)

    def test_open_ledger_acquires_process_lock_before_sqlite_connection(self):
        db = self.root / "lock-order.db"
        ledger_provision.initialize_ledger(db, runtime_uid=os.geteuid())
        lock_acquired = False
        real_flock = fcntl.flock
        real_connect = sqlite3.connect

        def observe_flock(fd, operation):
            nonlocal lock_acquired
            if operation == fcntl.LOCK_EX:
                lock_acquired = True
            return real_flock(fd, operation)

        def require_lock_before_connect(*args, **kwargs):
            self.assertTrue(lock_acquired)
            return real_connect(*args, **kwargs)

        with patch("name_tag_ledger.fcntl.flock", side_effect=observe_flock):
            with patch("name_tag_ledger.sqlite3.connect", side_effect=require_lock_before_connect):
                ledger = self._open_ledger(db)

        self.assertTrue(lock_acquired)
        ledger.close()

    def test_scope_operation_closes_lock_file_descriptor(self):
        ledger = self._open_ledger()
        opened_fds = []
        real_open = os.open

        def track_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.append(fd)
            return fd

        with patch("name_tag_ledger.os.open", side_effect=track_open):
            hold_scope(ledger, "scope-1", reason="operator-hold")

        self.assertIsNone(ledger._lock_fd)
        with self.assertRaises(OSError):
            os.fstat(opened_fds[0])

    def test_failed_lock_acquisition_closes_lock_file_descriptor(self):
        ledger = self._open_ledger()
        opened_fds = []
        real_open = os.open

        def track_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened_fds.append(fd)
            return fd

        with patch("name_tag_ledger.fcntl.flock", side_effect=OSError("lock failed")):
            with patch("name_tag_ledger.os.open", side_effect=track_open):
                with self.assertRaises(OSError):
                    ledger._lock()

        self.assertIsNone(ledger._lock_fd)
        with self.assertRaises(OSError):
            os.fstat(opened_fds[0])

    def test_missing_scopes_table_maps_database_error_to_ledger_error(self):
        ledger = self._open_ledger()
        with closing(sqlite3.connect(str(ledger._path))) as conn, conn:
            conn.execute("DROP TABLE scopes")

        with self.assertRaises(LedgerError) as ctx:
            effective_scope_state(ledger, "scope-1")

        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_release_unknown_scope_persists_scope_evidence(self):
        ledger = self._open_ledger()
        hold_scope(ledger, "scope-1", reason="operator-hold")
        scope = self._scope_evidence(scope_id="scope-1")
        side_effects = [self._side_effect(ARN)]
        release_scope(
            ledger,
            self._scope_envelope("RELEASE", ledger=ledger, scope_id="scope-1"),
            action="RELEASE",
            scope=scope,
            side_effects=side_effects,
        )
        authorization = self._verified_execution()
        create_intent(ledger, authorization, scope_id="scope-1")

    def test_release_rejects_stale_hold_generation(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        hold_scope(ledger, "scope-1", reason="first-hold")
        stale_release = self._scope_envelope("RELEASE", ledger=ledger)
        hold_scope(ledger, "scope-1", reason="newer-hold")
        with self.assertRaises(LedgerError) as ctx:
            release_scope(
                ledger,
                stale_release,
                action="RELEASE",
                scope=self._scope_evidence(),
                side_effects=[self._side_effect()],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_release_unknown_hold_rejects_arn_owned_by_another_scope(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger, scope_id="scope-1")
        hold_scope(ledger, "scope-2", reason="operator-hold")
        scope = self._scope_evidence(scope_id="scope-2")
        envelope = self._scope_envelope(
            "RELEASE", ledger=ledger, scope_id="scope-2", target_arns=[ARN]
        )

        with self.assertRaises(LedgerError) as ctx:
            release_scope(
                ledger,
                envelope,
                action="RELEASE",
                scope=scope,
                side_effects=[self._side_effect(ARN)],
            )

        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_release_expanding_hold_rejects_arn_owned_by_another_scope(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger, scope_id="scope-1")
        scope_2 = self._scope_evidence(
            scope_id="scope-2", target_arns=frozenset({OTHER_ARN})
        )
        initialize_scope(
            ledger,
            self._scope_envelope(
                "INITIALIZE", ledger=ledger, scope_id="scope-2", target_arns=[OTHER_ARN]
            ),
            action="INITIALIZE",
            scope=scope_2,
            side_effects=[self._side_effect(OTHER_ARN)],
        )
        hold_scope(ledger, "scope-1", reason="operator-hold")
        expanded_arns = frozenset({ARN, OTHER_ARN})
        scope_1 = self._scope_evidence(scope_id="scope-1", target_arns=expanded_arns)
        envelope = self._scope_envelope(
            "RELEASE", ledger=ledger, scope_id="scope-1", target_arns=sorted(expanded_arns)
        )

        with self.assertRaises(LedgerError) as ctx:
            release_scope(
                ledger,
                envelope,
                action="RELEASE",
                scope=scope_1,
                side_effects=[self._side_effect(arn) for arn in expanded_arns],
            )

        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_initialize_allows_arn_that_is_only_a_substring_match(self):
        ledger = self._open_ledger()
        existing_arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-1"
        distinct_arn = "arn:aws:ec2:us-east-1:123456789012:instance/i-10"
        existing_scope = self._scope_evidence(
            scope_id="scope-1", target_arns=frozenset({existing_arn})
        )
        initialize_scope(
            ledger,
            self._scope_envelope(
                "INITIALIZE", ledger=ledger, scope_id="scope-1", target_arns=[existing_arn]
            ),
            action="INITIALIZE",
            scope=existing_scope,
            side_effects=[self._side_effect(existing_arn)],
        )
        distinct_scope = self._scope_evidence(
            scope_id="scope-2", target_arns=frozenset({distinct_arn})
        )
        initialize_scope(
            ledger,
            self._scope_envelope(
                "INITIALIZE", ledger=ledger, scope_id="scope-2", target_arns=[distinct_arn]
            ),
            action="INITIALIZE",
            scope=distinct_scope,
            side_effects=[self._side_effect(distinct_arn)],
        )

    def test_missing_host_binding_metadata_is_rejected(self):
        ledger = self._open_ledger()
        with closing(sqlite3.connect(str(ledger._path))) as conn, conn:
            conn.execute("DELETE FROM ledger_meta WHERE key = 'host_binding'")
        with self.assertRaises(LedgerError) as ctx:
            effective_scope_state(ledger, "scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_existing_empty_file_is_not_initialized_as_new_ledger(self):
        db = self.root / "preexisting-empty.db"
        db.touch(mode=0o600)
        with self.assertRaises(LedgerError) as ctx:
            self._open_ledger(db)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

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
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1")
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, envelope, action="INITIALIZE", scope=self._scope_evidence(scope_id="scope-1"),
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
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1")
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, envelope, action="INITIALIZE", scope=self._scope_evidence(scope_id="scope-1"),
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
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1", target_arns=[ARN, OTHER_ARN])
        scope = self._scope_evidence(scope_id="scope-1", target_arns=frozenset({ARN}))
        side_effects = [self._side_effect(arn) for arn in scope.controlled_arns]
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, envelope, action="INITIALIZE", scope=scope, side_effects=side_effects)
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
    def test_fixture_cleared_never_enables_production(self):
        db = self.root / "fixture.db"
        ledger = self._open_ledger(db)
        self._fixture_only_seed_cleared_scope(ledger)
        # A production open must reject any ledger containing fixture-only rows.
        with self.assertRaises(LedgerError) as ctx:
            open_ledger(db, trusted_host=True, trust=self.trust)
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
    consume_first_send, create_intent, hold_scope,
    open_ledger, record_readback,
)
import name_tag_ledger_anchor as ledger_anchor

ledger_anchor.LEDGER_ANCHOR_DIRECTORY = Path({json.dumps(str(self.anchor_directory))})
ledger_anchor._ANCHOR_OWNER_UID = os.getuid()

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
ledger = open_ledger(db, trusted_host=True, trust=trust)
ledger._now = lambda: NOW

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
        if not ready.exists():
            proc.kill()
            out, err = proc.communicate()
            raise AssertionError(
                "subprocess did not reach ready before timeout: "
                f"{error.read_text() if error.exists() else ''} "
                f"stdout={out.decode(errors='replace')} "
                f"stderr={err.decode(errors='replace')}"
            )
        proc.send_signal(signal.SIGKILL)
        proc.communicate()

    def test_crash_helper_fails_if_child_never_reaches_ready(self):
        db = self.root / "never-ready.db"
        self._open_ledger(db)
        with self.assertRaisesRegex(AssertionError, "did not reach ready"):
            self._run_crash_subprocess(db, "time.sleep(30)", timeout=0.1)
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

    def test_t_f004_03_crash_after_atomic_hold_and_terminal_commit(self):
        db = self.root / "t-f004-03.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        self._run_crash_subprocess(
            db,
            "handle = create_intent(ledger, auth, scope_id='scope-1'); "
            "consume_first_send(ledger, handle); "
            "record_readback(ledger, handle, name_after='other-name', outcome='FAILED_READBACK')",
        )
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "HOLD")
        with closing(sqlite3.connect(str(db))) as conn:
            row = conn.execute("SELECT state FROM intents LIMIT 1").fetchone()
        self.assertEqual(row[0], "TERMINAL")

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
        # scope-b covers a different ARN to avoid fixed-target alias rejection.
        decision_b = self._verify_scope_decision_for(
            ledger, "INITIALIZE", scope_id="scope-b", target_arns=[OTHER_ARN]
        )
        scope_b = self._scope_evidence(scope_id="scope-b", target_arns=frozenset({OTHER_ARN}))
        init_envelope_b = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-b", target_arns=[OTHER_ARN])
        initialize_scope(ledger, init_envelope_b, action="INITIALIZE", scope=scope_b, side_effects=[self._side_effect(OTHER_ARN)])
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
        release_envelope = self._scope_envelope("RELEASE", ledger=ledger, scope_id="scope-1")
        release_envelope["signature_ref"] = base64.b64encode(b"bogus").decode()
        with self.assertRaises(LedgerError) as ctx:
            release_scope(ledger, release_envelope, action="RELEASE", scope=self._scope_evidence(scope_id="scope-1"),
                side_effects=[self._side_effect()],
            )

    def test_t_f004_09_release_does_not_revive_prior_intent_nonce_authorization(self):
        db = self.root / "t-f004-09.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        consume_first_send(ledger, handle)
        record_readback(ledger, handle, name_after="web-prod", outcome="APPLIED_VERIFIED")
        hold_scope(ledger, "scope-1", reason="safety")
        release_envelope = self._scope_envelope("RELEASE", ledger=ledger, scope_id="scope-1")
        release_scope(ledger, release_envelope, action="RELEASE", scope=self._scope_evidence(scope_id="scope-1"),
            side_effects=[self._side_effect()],
        )
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "CLEARED")
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, auth, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_AUTH_REPLAY")

    def test_create_intent_rejects_reused_execution_nonce(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        first = create_intent(ledger, self._verified_execution(), scope_id="scope-1")
        consume_first_send(ledger, first)
        record_readback(ledger, first, name_after="web-prod", outcome="APPLIED_VERIFIED")
        payload = self._execution_payload()
        payload["risk_acknowledgement"] = "distinct-authorization"
        data = canonical_payload(payload, kind="execution")
        second = verify_envelope(
            json.dumps(
                {
                    "payload": payload,
                    "authorization_id": approval_digest(data),
                    "signature_ref": base64.b64encode(
                        self._sign(data, NAMESPACES["execution"])
                    ).decode(),
                },
                separators=(",", ":"),
            ).encode(),
            kind="execution",
            trust=self.trust,
            now_utc=NOW,
        )
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, second, scope_id="scope-1")
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
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_HOLD")

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
        init_envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1")
        scope = self._scope_evidence(scope_id="scope-1")
        side_effects = [self._side_effect()]
        with self._failing_commit(ledger, RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                initialize_scope(ledger, init_envelope, action="INITIALIZE", scope=scope, side_effects=side_effects)
        ledger2 = self._open_ledger(db)
        self.assertEqual(effective_scope_state(ledger2, "scope-1"), "UNKNOWN")

    def test_release_crash_or_fsync_failure_stays_hold(self):
        db = self.root / "release-crash.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        hold_scope(ledger, "scope-1", reason="safety")
        release_envelope = self._scope_envelope("RELEASE", ledger=ledger, scope_id="scope-1")
        scope = self._scope_evidence(scope_id="scope-1")
        side_effects = [self._side_effect()]
        with self._failing_commit(ledger, RuntimeError("disk full")):
            with self.assertRaises(RuntimeError):
                release_scope(ledger, release_envelope, action="RELEASE", scope=scope, side_effects=side_effects)
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
        release_envelope = self._scope_envelope("RELEASE", ledger=ledger, scope_id="scope-1")
        release_scope(ledger, release_envelope, action="RELEASE", scope=self._scope_evidence(scope_id="scope-1"),
            side_effects=[self._side_effect()],
        )
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, auth, scope_id="scope-1")
        self.assertEqual(ctx.exception.code, "BLOCKED_AUTH_REPLAY")




    def test_side_effect_coverage_required(self):
        ledger = self._open_ledger()
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1", target_arns=[ARN, OTHER_ARN])
        scope = self._scope_evidence(scope_id="scope-1", target_arns=frozenset({ARN, OTHER_ARN}))
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, envelope, action="INITIALIZE", scope=scope, side_effects=[])
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_side_effect_digest_must_match(self):
        ledger = self._open_ledger()
        scope = self._scope_evidence(scope_id="scope-1")
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1")
        bad_effect = self._side_effect(arn=ARN)
        bad_effect = replace(bad_effect, evidence_references=("tampered",))
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, envelope, action="INITIALIZE", scope=scope, side_effects=[bad_effect])
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_side_effect_coverage_rejects_wrong_target(self):
        ledger = self._open_ledger()
        scope = self._scope_evidence(scope_id="scope-1")
        envelope = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-1")
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(
                ledger,
                envelope,
                action="INITIALIZE",
                scope=scope,
                side_effects=[self._side_effect(OTHER_ARN)],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_create_intent_rejects_arn_outside_scope(self):
        ledger = self._open_ledger(self.root / "cross-arn.db")
        self._initialize_scope(ledger, scope_id="scope-a")
        auth = self._verified_execution(scope_id="scope-a", resource_arn=OTHER_ARN)
        with self.assertRaises(LedgerError) as ctx:
            create_intent(ledger, auth, scope_id="scope-a")
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_record_readback_commit_failure_keeps_scope_cleared(self):
        db = self.root / "readback-commit-fail.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger)
        auth = self._verified_execution()
        handle = create_intent(ledger, auth, scope_id="scope-1")
        consume_first_send(ledger, handle)
        with self._failing_commit(ledger, sqlite3.OperationalError("disk full")):
            with self.assertRaises(LedgerError) as ctx:
                record_readback(ledger, handle, name_after="other-name", outcome="FAILED_READBACK")
            self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        ledger2 = self._open_ledger(db)
        with closing(sqlite3.connect(str(db))) as conn, conn:
            scope_state = conn.execute(
                "SELECT state FROM scopes WHERE scope_id = ?", ("scope-1",)
            ).fetchone()[0]
            row = conn.execute(
                "SELECT state FROM intents WHERE intent_id = ?", (handle.intent_id,)
            ).fetchone()
        self.assertEqual(scope_state, "CLEARED")
        self.assertEqual(row[0], "SEND_ATTEMPT_CONSUMED")

    def test_cross_scope_arn_alias_rejected(self):
        db = self.root / "alias.db"
        ledger = self._open_ledger(db)
        self._initialize_scope(ledger, scope_id="scope-a")
        init_b = self._scope_envelope("INITIALIZE", ledger=ledger, scope_id="scope-b", target_arns=[ARN])
        scope_b = self._scope_evidence(scope_id="scope-b", target_arns=frozenset({ARN}))
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(ledger, init_b, action="INITIALIZE", scope=scope_b, side_effects=[self._side_effect(ARN)])
        self.assertEqual(ctx.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_scope_transition_rejects_decision_object_in_envelope_payload(self):
        ledger = self._open_ledger()
        decision = self._verify_scope_decision_for(ledger, "INITIALIZE")
        envelope: dict[str, object] = {"payload": decision}
        with self.assertRaises(LedgerError) as ctx:
            initialize_scope(
                ledger,
                envelope,
                action="INITIALIZE",
                scope=self._scope_evidence(),
                side_effects=[self._side_effect()],
            )
        self.assertEqual(ctx.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_unrecognized_readback_outcome_holds_scope(self):
        ledger = self._open_ledger()
        self._initialize_scope(ledger)
        handle = create_intent(ledger, self._verified_execution(), scope_id="scope-1")
        consume_first_send(ledger, handle)
        record_readback(ledger, handle, name_after=None, outcome="UNRECOGNIZED_RESULT")
        self.assertEqual(effective_scope_state(ledger, "scope-1"), "HOLD")


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


class BatchDispositionInputTests(unittest.TestCase):
    def test_non_string_observed_name_digest_is_blocked_as_invalid_input(self):
        ledger=object.__new__(IntentLedger)
        with self.assertRaises(LedgerError) as rejected:
            ledger._validate_batch_disposition_input(
                "SKIPPED_NAME_CHANGED","NAME_SNAPSHOT_CHANGED",123)
        self.assertEqual(rejected.exception.code,"BLOCKED_INPUT_INVALID")


if __name__ == "__main__":
    unittest.main()
