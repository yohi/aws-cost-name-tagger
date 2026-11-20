"""Apply the separately Owner-signed Batch Ledger schema transition."""
from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from name_tag_batch_migration import (
    BatchMigrationRejected,
    VerifiedLedgerMigrationDecision,
    _verify_payload,
)
from name_tag_batch_trust import load_current_protected_owner_trust
from name_tag_ledger import IntentLedger, _LEDGER_CONSTRUCTOR_SENTINEL, _ledger_metadata_value
from name_tag_ledger_errors import LedgerError


def _batch_schema_statements() -> tuple[str, ...]:
    return (
        """CREATE TABLE batch_registry (
            batch_id TEXT PRIMARY KEY, batch_nonce TEXT NOT NULL UNIQUE,
            plan_sha256 TEXT NOT NULL, csv_sha256 TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('ACTIVE','STOPPED','COMPLETED')),
            max_send_attempts INTEGER NOT NULL CHECK(max_send_attempts BETWEEN 1 AND 20),
            send_attempts_consumed INTEGER NOT NULL DEFAULT 0
                CHECK(send_attempts_consumed >= 0 AND send_attempts_consumed <= max_send_attempts),
            stop_reason TEXT, created_at_utc TEXT NOT NULL, stopped_at_utc TEXT,
            completed_at_utc TEXT)""",
        """CREATE TABLE batch_rows (
            row_authority_id TEXT PRIMARY KEY,
            batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),
            row_index INTEGER NOT NULL CHECK(row_index >= 0), proposal_id TEXT NOT NULL,
            intent_id TEXT NOT NULL UNIQUE REFERENCES intents(intent_id),
            resource_arn TEXT NOT NULL, approved_name TEXT NOT NULL,
            aws_operation TEXT NOT NULL, scope_id TEXT NOT NULL,
            UNIQUE(batch_id,row_index), UNIQUE(batch_id,resource_arn,aws_operation))""",
        """CREATE TABLE batch_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),
            event TEXT NOT NULL, reason TEXT, scope_id TEXT, intent_id TEXT,
            timestamp_utc TEXT NOT NULL)""",
        """CREATE TABLE batch_row_dispositions (
            batch_id TEXT NOT NULL REFERENCES batch_registry(batch_id),
            row_index INTEGER NOT NULL CHECK(row_index >= 0),
            row_authority_id TEXT NOT NULL UNIQUE,
            decision TEXT NOT NULL CHECK(decision IN (
                'SKIPPED_NAME_CHANGED','SKIPPED_IAM_UNSUPPORTED','NOT_ATTEMPTED_CAP')),
            reason_code TEXT NOT NULL, observed_name_sha256 TEXT,
            decided_at_utc TEXT NOT NULL, PRIMARY KEY(batch_id,row_index))""",
        """CREATE TABLE ledger_migration_receipts (
            decision_id TEXT PRIMARY KEY, migration_nonce TEXT NOT NULL UNIQUE,
            ledger_instance_id TEXT NOT NULL, committed_at_utc TEXT NOT NULL)""",
    )


def upgrade_ledger_v1_to_batch_v2(
    path: Path, *, decision: VerifiedLedgerMigrationDecision
) -> None:
    """Apply only the exact signed migration to its bound, protected Ledger path."""
    if type(decision) is not VerifiedLedgerMigrationDecision:
        raise BatchMigrationRejected()
    current_trust = load_current_protected_owner_trust()
    now = datetime.now(timezone.utc)
    payload, _canonical, decision_id, resolved_path = _verify_payload(
        decision.raw_envelope_json, trust=current_trust, now_utc=now,
        allowed_attempt_decision=None,
    )
    if (resolved_path != path.resolve(strict=True) or decision_id != decision.decision_id
            or decision.ledger_path != resolved_path
            or decision.migration_nonce != payload["migration_nonce"]
            or decision.ledger_instance_id != payload["ledger_instance_id"]):
        raise BatchMigrationRejected()
    host_binding = payload["host_binding"]
    ledger = IntentLedger(
        path=resolved_path, trusted_host=True, trust=current_trust,
        host_binding=host_binding, execution_id=uuid.uuid4().hex,
        _constructor_token=_LEDGER_CONSTRUCTOR_SENTINEL,
    )
    marker = f"migration_attempt:{payload['migration_nonce']}"
    ledger._lock()
    try:
        lock_fd = ledger._lock_fd
        if lock_fd is None:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        try:
            locked_identity = os.fstat(lock_fd)
            path_identity = resolved_path.stat(follow_symlinks=False)
        except OSError as error:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
        if ((locked_identity.st_dev, locked_identity.st_ino)
                != (path_identity.st_dev, path_identity.st_ino)
                or (locked_identity.st_dev, locked_identity.st_ino)
                != (payload["ledger_device"], payload["ledger_inode"])):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        with ledger._connection() as connection:
            if _ledger_metadata_value(connection, "schema_version") != "1":
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            if connection.execute("SELECT 1 FROM ledger_meta WHERE key=?", (marker,)).fetchone():
                raise LedgerError("BLOCKED_AUTH_REPLAY")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO ledger_meta(key,value) VALUES(?,?)", (marker, decision_id)
            )
            connection.commit()
            os.fsync(lock_fd)
            latest_trust = load_current_protected_owner_trust()
            _verify_payload(
                decision.raw_envelope_json, trust=latest_trust,
                now_utc=datetime.now(timezone.utc),
                allowed_attempt_decision=decision_id,
            )
            connection.execute("BEGIN IMMEDIATE")
            for statement in _batch_schema_statements():
                connection.execute(statement)
            timestamp = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "INSERT INTO ledger_migration_receipts VALUES(?,?,?,?)",
                (decision_id, payload["migration_nonce"], payload["ledger_instance_id"], timestamp),
            )
            connection.execute(
                "UPDATE ledger_meta SET value=? WHERE key=?",
                (f"COMMITTED:{decision_id}", marker),
            )
            connection.execute(
                "UPDATE ledger_meta SET value='2' WHERE key='schema_version'"
            )
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity != ("ok",):
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            connection.commit()
            os.fsync(lock_fd)
    except sqlite3.Error as error:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
    finally:
        ledger.close()
