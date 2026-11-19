"""Crash-safe single-host Intent and scope HOLD ledger.

This module implements the F005/F006 ledger contract: a single, authoritative,
host-bound SQLite journal that durably records scope state transitions and
one-shot write Intents.  It never calls live AWS APIs.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import socket
import sqlite3
import stat
import uuid
from contextlib import closing, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, cast
from collections.abc import Mapping, Sequence

from name_tag_approval import (
    ApprovalRejected,
    OwnerTrust,
    VerifiedEnvelope,
    _select_signer_lines,
    _verify_signature,
    approval_digest,
    revalidate_verified_envelope,
)
from name_tag_scope import ScopeEvidence, SideEffectEvidence
from name_tag_ledger_anchor import read_ledger_anchor
from name_tag_ledger_errors import LedgerError
from name_tag_batch_approval import (
    BatchAuthRejected,
    VerifiedBatchApproval,
    VerifiedBatchRowAuthority,
    canonical_bytes,
    derive_batch_row_authority,
)


SCOPE_DECISION_NAMESPACE = "aws-cost-name-tagger-scope-decision-v1"

# Canonical execution payload operation allowlist.
SUPPORTED_OPERATIONS = frozenset({"ec2:CreateTags:2016-11-15"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Decision verification (F005)
# ---------------------------------------------------------------------------

ScopeAction = Literal["INITIALIZE", "RELEASE"]


_LEDGER_CONSTRUCTOR_SENTINEL = object()


@dataclass(frozen=True, slots=True)
class VerifiedScopeDecision:
    """Parsed Owner scope decision; state transitions reverify its raw envelope."""

    action: ScopeAction
    scope_id: str
    account: str
    partition: str
    region: str
    target_arns: frozenset[str]
    writer_evidence_digest: str
    side_effect_evidence_digest: str
    host_binding: str
    owner_principal_id: str
    decision_id: str
    issued_at_utc: datetime
    expires_at_utc: datetime
    reason: str
    decision_nonce: str
    hold_generation_id: str | None


def _canonicalize_arn_set(arns: Sequence[object] | None) -> frozenset[str]:
    """Return a canonical frozenset of non-empty ARN strings."""
    if arns is None:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    if not isinstance(arns, (list, tuple, set, frozenset)):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    normalized = {str(item) for item in arns}
    if any(not arn for arn in normalized):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    return frozenset(normalized)







def _ensure_target_arns_unaliased(
    conn: sqlite3.Connection, scope_id: str, target_arns: frozenset[str]
) -> None:
    existing_target_sets = conn.execute(
        """
        SELECT scope_id, target_arns FROM scopes
        WHERE target_arns IS NOT NULL AND scope_id != ?
        """,
        (scope_id,),
    ).fetchall()
    for _, stored_arns in existing_target_sets:
        try:
            decoded_arns = json.loads(stored_arns)
        except (json.JSONDecodeError, TypeError) as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        if (
            not isinstance(decoded_arns, list)
            or any(not isinstance(arn, str) for arn in decoded_arns)
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if set(decoded_arns).intersection(target_arns):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def _valid_window(not_before: datetime, not_after: datetime, now: datetime) -> None:
    """Fail-closed validity-window check."""
    if now < not_before or now > not_after:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")




def _require_sha256(value: object) -> str:
    """Require a 64-hex string; fail closed otherwise."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    return value


def _require_non_empty_str(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    return value


def ledger_host_binding(path: Path) -> str:
    """Return a stable host identifier derived from hostname and ledger path."""
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    try:
        absolute = path.resolve(strict=False)
    except OSError:
        absolute = path.absolute()
    return f"{hostname}:{absolute}"


def _parse_iso_utc(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LedgerError("BLOCKED_OWNER_AUTHN") from exc
    if value.tzinfo is None:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    return value.astimezone(timezone.utc)


def _canonical_scope_payload(payload: Mapping[str, Any]) -> bytes:
    """Canonicalize a scope-decision payload with the same deterministic rules."""
    expected_fields = {
        "schema_version",
        "decision_namespace",
        "action",
        "scope_id",
        "account",
        "partition",
        "region",
        "target_arns",
        "writer_evidence_digest",
        "side_effect_evidence_digest",
        "host_binding",
        "owner_principal_id",
        "owner_key_fingerprint",
        "allowed_role",
        "issued_at_utc",
        "expires_at_utc",
        "decision_nonce",
        "reason",
        "hold_generation_id",
    }
    if set(payload) != expected_fields:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if payload.get("decision_namespace") != SCOPE_DECISION_NAMESPACE:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if payload.get("schema_version") != 1:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if payload.get("action") not in ("INITIALIZE", "RELEASE"):
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    for key, value in payload.items():
        if key == "schema_version":
            if type(value) is not int or value != 1:
                raise LedgerError("BLOCKED_OWNER_AUTHN")
        elif key == "target_arns":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise LedgerError("BLOCKED_OWNER_AUTHN")
        elif key == "hold_generation_id":
            if value is not None and not isinstance(value, str):
                raise LedgerError("BLOCKED_OWNER_AUTHN")
        else:
            if not isinstance(value, str):
                raise LedgerError("BLOCKED_OWNER_AUTHN")

    # Build a canonical dict with sorted/deduplicated ARNs.
    canonical = dict(payload)
    arns = sorted(set(canonical["target_arns"]))
    canonical["target_arns"] = arns

    def _canon(value: Any) -> str:
        if value is None:
            return "null"
        if value is True:
            return "true"
        if value is False:
            return "false"
        if type(value) is int:
            return str(value)
        if isinstance(value, str):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if isinstance(value, list):
            return "[" + ",".join(_canon(item) for item in value) + "]"
        if isinstance(value, dict):
            return "{" + ",".join(
                _canon(key) + ":" + _canon(value[key]) for key in sorted(value)
            ) + "}"
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    return _canon(canonical).encode("utf-8")


def _verify_owner_signature(
    signature: bytes,
    message: bytes,
    owner_id: str,
    namespace: str,
    trust: OwnerTrust,
    candidate_lines: list[str],
) -> str:
    try:
        trust._check_file()
        return _verify_signature(signature, message, owner_id, namespace, candidate_lines)
    except ApprovalRejected:
        raise LedgerError("BLOCKED_OWNER_AUTHN") from None


def verify_scope_decision(
    envelope: Mapping[str, object],
    *,
    trust: OwnerTrust,
    action: ScopeAction,
    now_utc: datetime,
) -> VerifiedScopeDecision:
    """Verify an Owner-signed scope decision envelope.

    Fails closed with ``BLOCKED_OWNER_AUTHN`` for signature/role/key problems or
    ``BLOCKED_SCOPE_STATE_UNKNOWN`` for scope-shape problems.
    """
    if not isinstance(trust, OwnerTrust) or now_utc.tzinfo is None:
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    if not isinstance(envelope, Mapping):
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if set(envelope) != {"payload", "decision_id", "signature_ref"}:
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    payload = envelope.get("payload")
    decision_id = envelope.get("decision_id")
    signature_ref = envelope.get("signature_ref")
    if not isinstance(payload, Mapping) or not isinstance(decision_id, str) or not isinstance(signature_ref, str):
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if not re.fullmatch(r"[0-9a-f]{64}", decision_id):
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    try:
        canonical = _canonical_scope_payload(payload)
        computed_id = approval_digest(canonical)
        if computed_id != decision_id:
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        signature = base64.b64decode(signature_ref, validate=True)
    except (ValueError, TypeError, ApprovalRejected):
        raise LedgerError("BLOCKED_OWNER_AUTHN") from None

    if payload.get("action") != action:
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    for field_name in ("account", "partition", "region"):
        value = payload.get(field_name)
        if not isinstance(value, str) or not value:
            raise LedgerError("BLOCKED_OWNER_AUTHN")

    owner_id = payload.get("owner_principal_id")
    if not isinstance(owner_id, str):
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    allowed_role = payload.get("allowed_role")
    if not isinstance(allowed_role, str):
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    expires_at = payload.get("expires_at_utc")
    if not isinstance(expires_at, str):
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    try:
        expiry = _parse_iso_utc(expires_at)
    except LedgerError:
        raise
    if expiry <= now_utc.astimezone(timezone.utc):
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    issued_at = payload.get("issued_at_utc")
    if not isinstance(issued_at, str):
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    try:
        issued = _parse_iso_utc(issued_at)
    except LedgerError:
        raise
    if issued > now_utc.astimezone(timezone.utc):
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    owners: Any = getattr(trust, "_owners")
    entries = owners.get(owner_id, {})
    if not entries:
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    try:
        trust_data = trust._check_file()
        candidate_lines = _select_signer_lines(trust_data, owner_id, set(entries))
    except ApprovalRejected:
        raise LedgerError("BLOCKED_OWNER_AUTHN") from None
    verifying_fingerprint = _verify_owner_signature(
        signature, canonical, owner_id, SCOPE_DECISION_NAMESPACE, trust, candidate_lines
    )

    entry = entries.get(verifying_fingerprint)
    if entry is None or entry.revoked or entry.role != allowed_role:
        raise LedgerError("BLOCKED_OWNER_AUTHN")
    if payload.get("owner_key_fingerprint") != verifying_fingerprint:
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    scope_id = payload.get("scope_id")
    if not isinstance(scope_id, str) or not scope_id:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    try:
        target_arns = _canonicalize_arn_set(cast(Sequence[object], payload.get("target_arns")))
    except LedgerError:
        raise

    writer_evidence_digest = _require_sha256(payload.get("writer_evidence_digest"))
    side_effect_evidence_digest = _require_sha256(payload.get("side_effect_evidence_digest"))
    host_binding = _require_non_empty_str(payload.get("host_binding"))
    reason = _require_non_empty_str(payload.get("reason"))

    decision_nonce = _require_non_empty_str(payload.get("decision_nonce"))
    hold_generation_id = payload.get("hold_generation_id")
    if action == "RELEASE":
        hold_generation_id = _require_non_empty_str(hold_generation_id)
    elif hold_generation_id is not None:
        raise LedgerError("BLOCKED_OWNER_AUTHN")

    return VerifiedScopeDecision(
        action=action,
        scope_id=scope_id,
        account=_require_non_empty_str(payload.get("account")),
        partition=_require_non_empty_str(payload.get("partition")),
        region=_require_non_empty_str(payload.get("region")),
        target_arns=target_arns,
        writer_evidence_digest=writer_evidence_digest,
        side_effect_evidence_digest=side_effect_evidence_digest,
        host_binding=host_binding,
        owner_principal_id=owner_id,
        decision_id=decision_id,
        issued_at_utc=issued,
        expires_at_utc=expiry,
        reason=reason,
        decision_nonce=decision_nonce,
        hold_generation_id=hold_generation_id,
    )


# ---------------------------------------------------------------------------
# Side-effect evidence canonical digest
# ---------------------------------------------------------------------------


def _canonical_side_effect_evidence(side_effects: Sequence[SideEffectEvidence]) -> bytes:
    """Return canonical JSON bytes for a sequence of side-effect evidence."""
    items = []
    for effect in sorted(side_effects, key=lambda e: e.target_arn):
        items.append(
            {
                "target_arn": effect.target_arn,
                "iam_abac_resource_tag_assessment": effect.iam_abac_resource_tag_assessment,
                "iac_assessment": effect.iac_assessment,
                "event_automation_assessment": effect.event_automation_assessment,
                "evidence_references": sorted(effect.evidence_references),
                "not_before_utc": effect.not_before_utc.astimezone(timezone.utc).isoformat(),
                "not_after_utc": effect.not_after_utc.astimezone(timezone.utc).isoformat(),
            }
        )

    def _canon(value: Any) -> str:
        if isinstance(value, str):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if isinstance(value, list):
            return "[" + ",".join(_canon(v) for v in value) + "]"
        if isinstance(value, dict):
            return "{" + ",".join(
                _canon(key) + ":" + _canon(value[key]) for key in sorted(value)
            ) + "}"
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    return _canon(items).encode("utf-8")


def _side_effect_digest(side_effects: Sequence[SideEffectEvidence]) -> str:
    return approval_digest(_canonical_side_effect_evidence(side_effects))


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FirstSendPermit:
    """Non-persistable, single-use, process-local first-send authorization."""

    authorization_id: str
    resource_arn: str
    approved_name: str
    writer_control_scope_id: str
    aws_operation: str
    execution_id: str
    ownership_token: str


@dataclass(frozen=True, slots=True)
class BatchExecutionState:
    state: str
    send_attempts_consumed: int
    max_send_attempts: int
    outcomes: tuple[str, ...]


@dataclass(frozen=False)
class IntentHandle:
    """Opaque handle to a recorded Intent; bound to current execution ownership."""

    intent_id: str
    authorization_id: str
    execution_id: str
    ownership_token: str
    batch_row_authority: VerifiedBatchRowAuthority | None = None
    batch_scope: ScopeEvidence | None = None
    batch_side_effects: tuple[SideEffectEvidence, ...] | None = None


class _CloseableConnection:
    """Context manager that always closes the underlying SQLite connection."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn: sqlite3.Connection = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *_exc: object) -> None:
        try:
            self._conn.rollback()
        except sqlite3.Error:
            pass
        self._conn.close()

    def execute(self, sql: str, parameters: Any = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, parameters)

    def executescript(self, sql_script: Any) -> sqlite3.Cursor:
        return self._conn.executescript(sql_script)

    def commit(self) -> None:
        self._conn.commit()


class IntentLedger:
    """Single-host durable ledger for scope state and one-shot Intents."""

    def __init__(
        self,
        *,
        path: Path,
        trusted_host: bool,
        trust: OwnerTrust | None,
        host_binding: str,
        execution_id: str,
        _constructor_token: object,
    ) -> None:
        if _constructor_token is not _LEDGER_CONSTRUCTOR_SENTINEL:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        self._path: Path = path
        self._trusted_host: bool = trusted_host
        self._trust: OwnerTrust | None = trust
        self._host_binding: str = host_binding
        self._execution_id: str = execution_id
        self._lock_fd: int | None = None
    # ------------------------------------------------------------------
    # Lock helpers
    # ------------------------------------------------------------------

    def _lock(self) -> None:
        """Acquire a cross-process advisory lock on the ledger file."""
        if self._lock_fd is None:
            self._lock_fd = os.open(
                self._path,
                os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        except OSError:
            lock_fd = self._lock_fd
            self._lock_fd = None
            if lock_fd is not None:
                with suppress(OSError):
                    os.close(lock_fd)
            raise

    def _unlock(self) -> None:
        lock_fd = self._lock_fd
        if lock_fd is None:
            return
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            self._lock_fd = None
            with suppress(OSError):
                os.close(lock_fd)

    def close(self) -> None:
        """Release the advisory lock and close the lock file descriptor."""
        self._unlock()

    # ------------------------------------------------------------------
    # Schema / integrity
    # ------------------------------------------------------------------

    def _connection(self) -> _CloseableConnection:
        conn = sqlite3.connect(
            self._path.as_uri() + "?mode=rw", timeout=10.0, uri=True
        )
        connection_ready = False
        try:
            _ = conn.execute("PRAGMA synchronous = FULL")
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()
            if (
                not isinstance(journal_mode, tuple)
                or len(journal_mode) != 1
                or not isinstance(journal_mode[0], str)
                or journal_mode[0].lower() != "delete"
            ):
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            _ = conn.execute("PRAGMA foreign_keys = ON")
            connection_ready = True
        except sqlite3.Error as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        finally:
            if not connection_ready:
                with suppress(sqlite3.Error):
                    conn.close()
        return _CloseableConnection(conn)

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ledger_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scopes (
                scope_id TEXT PRIMARY KEY,
                state TEXT NOT NULL CHECK(state IN ('CLEARED', 'HOLD', 'UNKNOWN')),
                account TEXT,
                partition TEXT,
                region TEXT,
                target_arns TEXT,
                writer_evidence_digest TEXT,
                side_effect_evidence_digest TEXT,
                host_binding TEXT,
                owner_principal_id TEXT,
                decision_id TEXT,
                issued_at_utc TEXT,
                expires_at_utc TEXT,
                reason TEXT,
                fixture_only INTEGER NOT NULL DEFAULT 0,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scope_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_id TEXT NOT NULL,
                state TEXT NOT NULL,
                decision_id TEXT,
                decision_nonce TEXT,
                owner_principal_id TEXT,
                writer_evidence_digest TEXT,
                side_effect_evidence_digest TEXT,
                target_arns TEXT,
                reason TEXT,
                timestamp_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS used_decisions (
                scope_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                decision_nonce TEXT NOT NULL,
                used_at_utc TEXT NOT NULL,
                PRIMARY KEY (scope_id, decision_id)
            );

            CREATE TABLE IF NOT EXISTS intents (
                intent_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL,
                authorization_id TEXT NOT NULL,
                execution_nonce TEXT NOT NULL,
                resource_arn TEXT NOT NULL,
                approved_name TEXT NOT NULL,
                writer_control_scope_id TEXT NOT NULL,
                aws_operation TEXT NOT NULL,
                ownership_token TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('WRITE_INTENT_RECORDED', 'SEND_ATTEMPT_CONSUMED', 'TERMINAL')),
                outcome TEXT,
                name_after TEXT,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS intent_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_id TEXT NOT NULL,
                event TEXT NOT NULL,
                timestamp_utc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_intents_scope ON intents(scope_id);
            CREATE INDEX IF NOT EXISTS idx_intents_state ON intents(state);
            CREATE INDEX IF NOT EXISTS idx_intents_auth ON intents(authorization_id);
            """
        )

    def _validate_ledger_state(self, conn: sqlite3.Connection) -> None:
        """Fail closed if the ledger is torn, corrupt, or bound to another host."""
        try:
            result = conn.execute(
                "SELECT value FROM ledger_meta WHERE key = 'host_binding'"
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        if result is None or result[0] != self._host_binding:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

        _validate_ledger_schema_state(conn)

        try:
            cursor = conn.execute("SELECT COUNT(*) FROM sqlite_master")
            cursor.fetchone()
        except sqlite3.DatabaseError as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc

        # Reject any fixture-only scope in a production ledger.
        try:
            cursor = conn.execute("SELECT 1 FROM scopes WHERE fixture_only != 0 LIMIT 1")
            fixture_scope = cursor.fetchone()
        except sqlite3.DatabaseError as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        if fixture_scope is not None:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _iso(self, value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Scope state
    # ------------------------------------------------------------------

    def effective_scope_state(self, scope_id: str) -> str:
        """Return UNKNOWN, HOLD, or CLEARED for ``scope_id``.

        A CLEARED scope with any prior incomplete Intent is effectively HOLD.
        """
        with self._connection() as conn:
            self._validate_ledger_state(conn)
            return self._effective_scope_state(conn, scope_id)

    def _assert_scope_evidence(
        self, conn: sqlite3.Connection, scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
    ) -> None:
        row = conn.execute(
            """SELECT account, partition, region, target_arns,
                      writer_evidence_digest, side_effect_evidence_digest,
                      host_binding, owner_principal_id, decision_id,
                      issued_at_utc, expires_at_utc, reason
               FROM scopes WHERE scope_id = ?""",
            (scope.writer_control_scope_id,),
        ).fetchone()
        if row is None or any(not isinstance(value, str) for value in row):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        try:
            target_arns = json.loads(row[3])
            if not isinstance(target_arns, list) or any(
                not isinstance(arn, str) for arn in target_arns
            ):
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            decision = VerifiedScopeDecision(
                action="INITIALIZE",
                scope_id=scope.writer_control_scope_id,
                account=row[0], partition=row[1], region=row[2],
                target_arns=frozenset(target_arns),
                writer_evidence_digest=row[4], side_effect_evidence_digest=row[5],
                host_binding=row[6], owner_principal_id=row[7], decision_id=row[8],
                issued_at_utc=datetime.fromisoformat(row[9]),
                expires_at_utc=datetime.fromisoformat(row[10]), reason=row[11],
                decision_nonce="persisted", hold_generation_id=None,
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        self._assert_decision_matches_evidence(decision, scope, side_effects, self._now())


    def _effective_scope_state(self, conn: sqlite3.Connection, scope_id: str) -> str:
        row = conn.execute(
            "SELECT state FROM scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        if row is None:
            return "UNKNOWN"
        state = row[0]
        if state == "HOLD":
            return "HOLD"
        if state == "UNKNOWN":
            return "UNKNOWN"
        # CLEARED: still blocked if any incomplete Intent remains.
        incomplete = conn.execute(
            "SELECT 1 FROM intents WHERE scope_id = ? AND state != 'TERMINAL' LIMIT 1",
            (scope_id,),
        ).fetchone()
        if incomplete is not None:
            return "HOLD"
        return "CLEARED"

    def _scope_exists(self, conn: sqlite3.Connection, scope_id: str) -> bool:
        return (
            conn.execute("SELECT 1 FROM scopes WHERE scope_id = ?", (scope_id,))
            .fetchone()
            is not None
        )

    def _assert_decision_matches_evidence(
        self,
        decision: VerifiedScopeDecision,
        scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
        now: datetime,
    ) -> None:
        _valid_window(scope.not_before_utc, scope.not_after_utc, now)
        for effect in side_effects:
            _valid_window(effect.not_before_utc, effect.not_after_utc, now)
        if decision.scope_id != scope.writer_control_scope_id:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if (
            decision.account != scope.account
            or decision.partition != scope.partition
            or decision.region != scope.region
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if decision.target_arns != scope.controlled_arns:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if decision.writer_evidence_digest != scope.writer_evidence_digest:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if decision.host_binding != self._host_binding:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if decision.owner_principal_id != scope.responsible_owner:
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        # Complete per-ARN side-effect coverage.
        covered = {effect.target_arn for effect in side_effects}
        if covered != set(scope.controlled_arns):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if len(side_effects) != len(covered):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        computed_digest = _side_effect_digest(side_effects)
        if computed_digest != decision.side_effect_evidence_digest:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    def _verify_scope_transition(
        self,
        envelope: Mapping[str, object],
        action: ScopeAction,
        scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
    ) -> tuple[VerifiedScopeDecision, datetime]:
        if not self._trusted_host:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        trust = self._trust
        if not isinstance(trust, OwnerTrust):
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        now = self._now()
        decision = verify_scope_decision(
            envelope, trust=trust, action=action, now_utc=now
        )
        self._assert_decision_matches_evidence(decision, scope, side_effects, now)
        if decision.expires_at_utc <= now:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        return decision, now

    def _check_decision_replay(
        self, conn: sqlite3.Connection, decision: VerifiedScopeDecision
    ) -> None:
        existing = conn.execute(
            "SELECT 1 FROM used_decisions WHERE scope_id = ? AND decision_id = ? LIMIT 1",
            (decision.scope_id, decision.decision_id),
        ).fetchone()
        if existing is not None:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    def _record_decision_use(
        self, conn: sqlite3.Connection, decision: VerifiedScopeDecision
    ) -> None:
        timestamp = decision.issued_at_utc.astimezone(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO used_decisions (scope_id, decision_id, decision_nonce, used_at_utc)
            VALUES (?, ?, ?, ?)
            """,
            (decision.scope_id, decision.decision_id, decision.decision_nonce, timestamp),
        )
    def initialize_scope(
        self,
        envelope: Mapping[str, object],
        *,
        action: ScopeAction,
        scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
    ) -> None:
        """Durably transition a provably-new scope to CLEARED.

        Requires a verified INITIALIZE decision and matching evidence.  Rejects
        scopes that are already registered, held, or have any prior history.
        """
        if action != "INITIALIZE":
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        decision, now = self._verify_scope_transition(
            envelope, action, scope, side_effects
        )

        self._lock()
        try:
            with self._connection() as conn:
                self._validate_ledger_state(conn)
                conn.execute("BEGIN IMMEDIATE")

                self._check_decision_replay(conn, decision)

                # Fail closed if the scope has any recorded state or history.
                if self._scope_exists(conn, decision.scope_id):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                history = conn.execute(
                    "SELECT 1 FROM scope_history WHERE scope_id = ? LIMIT 1",
                    (decision.scope_id,),
                ).fetchone()
                if history is not None:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                intents = conn.execute(
                    "SELECT 1 FROM intents WHERE scope_id = ? LIMIT 1",
                    (decision.scope_id,),
                ).fetchone()
                if intents is not None:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

                _ensure_target_arns_unaliased(
                    conn, decision.scope_id, decision.target_arns
                )

                timestamp = self._iso(now)
                conn.execute(
                    """
                    INSERT INTO scopes (
                        scope_id, state, account, partition, region, target_arns,
                        writer_evidence_digest, side_effect_evidence_digest, host_binding,
                        owner_principal_id, decision_id, issued_at_utc, expires_at_utc,
                        reason, fixture_only, created_at_utc, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.scope_id,
                        "CLEARED",
                        scope.account,
                        scope.partition,
                        scope.region,
                        json.dumps(sorted(decision.target_arns), separators=(",", ":")),
                        decision.writer_evidence_digest,
                        decision.side_effect_evidence_digest,
                        decision.host_binding,
                        decision.owner_principal_id,
                        decision.decision_id,
                        self._iso(decision.issued_at_utc),
                        self._iso(decision.expires_at_utc),
                        decision.reason,
                        0,
                        timestamp,
                        timestamp,
                    ),
                )
                self._record_decision_use(conn, decision)
                conn.execute(
                    """
                    INSERT INTO scope_history (
                        scope_id, state, decision_id, decision_nonce, owner_principal_id,
                        writer_evidence_digest, side_effect_evidence_digest, target_arns,
                        reason, timestamp_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.scope_id,
                        "CLEARED",
                        decision.decision_id,
                        decision.decision_nonce,
                        decision.owner_principal_id,
                        decision.writer_evidence_digest,
                        decision.side_effect_evidence_digest,
                        json.dumps(sorted(decision.target_arns), separators=(",", ":")),
                        decision.reason,
                        timestamp,
                    ),
                )
                conn.commit()
        finally:
            self._unlock()

    def release_scope(
        self,
        envelope: Mapping[str, object],
        *,
        action: ScopeAction,
        scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
    ) -> None:
        """Durably transition a HOLD scope to CLEARED.

        Requires a verified RELEASE decision and fresh evidence.  Does not
        revive prior Intents, nonces, or authorizations.
        """
        if action != "RELEASE":
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        decision, now = self._verify_scope_transition(
            envelope, action, scope, side_effects
        )

        self._lock()
        try:
            with self._connection() as conn:
                self._validate_ledger_state(conn)
                conn.execute("BEGIN IMMEDIATE")

                self._check_decision_replay(conn, decision)

                row = conn.execute(
                    "SELECT state FROM scopes WHERE scope_id = ?", (decision.scope_id,)
                ).fetchone()
                if row is None or row[0] != "HOLD":
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

                hold = conn.execute(
                    "SELECT id FROM scope_history WHERE scope_id = ? AND state = 'HOLD' ORDER BY id DESC LIMIT 1",
                    (decision.scope_id,),
                ).fetchone()
                if hold is None or decision.hold_generation_id != str(hold[0]):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

                # Reject release if any prior Intent is still non-terminal.
                incomplete = conn.execute(
                    "SELECT 1 FROM intents WHERE scope_id = ? AND state != 'TERMINAL' LIMIT 1",
                    (decision.scope_id,),
                ).fetchone()
                if incomplete is not None:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

                _ensure_target_arns_unaliased(
                    conn, decision.scope_id, decision.target_arns
                )

                timestamp = self._iso(now)
                conn.execute(
                    """
                    UPDATE scopes SET
                        state = ?, account = ?, partition = ?, region = ?, target_arns = ?,
                        writer_evidence_digest = ?, side_effect_evidence_digest = ?,
                        host_binding = ?, owner_principal_id = ?, decision_id = ?,
                        issued_at_utc = ?, expires_at_utc = ?, reason = ?, updated_at_utc = ?
                    WHERE scope_id = ?
                    """,
                    (
                        "CLEARED", scope.account, scope.partition, scope.region,
                        json.dumps(sorted(decision.target_arns), separators=(",", ":")),
                        decision.writer_evidence_digest, decision.side_effect_evidence_digest,
                        decision.host_binding, decision.owner_principal_id, decision.decision_id,
                        self._iso(decision.issued_at_utc), self._iso(decision.expires_at_utc),
                        decision.reason, timestamp, decision.scope_id,
                    ),
                )
                self._record_decision_use(conn, decision)
                conn.execute(
                    """
                    INSERT INTO scope_history (
                        scope_id, state, decision_id, decision_nonce, owner_principal_id,
                        writer_evidence_digest, side_effect_evidence_digest, target_arns,
                        reason, timestamp_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.scope_id,
                        "CLEARED",
                        decision.decision_id,
                        decision.decision_nonce,
                        decision.owner_principal_id,
                        decision.writer_evidence_digest,
                        decision.side_effect_evidence_digest,
                        json.dumps(sorted(decision.target_arns), separators=(",", ":")),
                        decision.reason,
                        timestamp,
                    ),
                )
                conn.commit()
        finally:
            self._unlock()

    def hold_scope(self, scope_id: str, *, reason: str) -> None:
        """Durably place a scope on HOLD."""
        if not isinstance(reason, str) or not reason:
            raise LedgerError("BLOCKED_SCOPE_HOLD")
        if not self._trusted_host:
            raise LedgerError("BLOCKED_SCOPE_HOLD")

        now = self._now()
        self._lock()
        try:
            with self._connection() as conn:
                self._validate_ledger_state(conn)
                conn.execute("BEGIN IMMEDIATE")

                existing = conn.execute(
                    "SELECT 1 FROM scopes WHERE scope_id = ?", (scope_id,)
                ).fetchone()
                timestamp = self._iso(now)
                if existing is None:
                    # Record an explicit HOLD even for a previously unknown scope.
                    conn.execute(
                        """
                        INSERT INTO scopes (
                            scope_id, state, account, partition, region, target_arns,
                            writer_evidence_digest, side_effect_evidence_digest, host_binding,
                            owner_principal_id, decision_id, issued_at_utc, expires_at_utc,
                            reason, fixture_only, created_at_utc, updated_at_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scope_id,
                            "HOLD",
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            self._host_binding,
                            None,
                            None,
                            None,
                            None,
                            reason,
                            0,
                            timestamp,
                            timestamp,
                        ),
                    )
                else:
                    conn.execute(
                        "UPDATE scopes SET state = ?, reason = ?, updated_at_utc = ? WHERE scope_id = ?",
                        ("HOLD", reason, timestamp, scope_id),
                    )
                conn.execute(
                    """
                    INSERT INTO scope_history (scope_id, state, decision_id, reason, timestamp_utc)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (scope_id, "HOLD", None, reason, timestamp),
                )
                conn.commit()
        finally:
            self._unlock()

    # ------------------------------------------------------------------
    # Intents (F006)
    # ------------------------------------------------------------------

    def _revalidate_authorization(
        self, authorization: VerifiedEnvelope, scope_id: str
    ) -> VerifiedEnvelope:
        if self._trust is None or not isinstance(self._trust, OwnerTrust):
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        now = self._now()
        try:
            fresh = revalidate_verified_envelope(
                authorization, kind="execution", trust=self._trust, now_utc=now
            )
        except ApprovalRejected as exc:
            raise LedgerError("BLOCKED_OWNER_AUTHN") from exc

        if fresh.payload.get("writer_control_scope_id") != scope_id:
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        aws_operation = fresh.payload.get("aws_operation")
        if aws_operation not in SUPPORTED_OPERATIONS:
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        return fresh

    def _revalidate_batch_row(
        self, authority: VerifiedBatchRowAuthority
    ) -> VerifiedBatchRowAuthority:
        if type(authority) is not VerifiedBatchRowAuthority:
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        from name_tag_batch_trust import load_current_protected_owner_trust

        try:
            trust = load_current_protected_owner_trust()
            return derive_batch_row_authority(
                authority.batch, authority.row_index, trust=trust, now_utc=self._now()
            )
        except BatchAuthRejected as error:
            raise LedgerError("BLOCKED_OWNER_AUTHN") from error

    def _batch_plan_state(
        self, connection: sqlite3.Connection, batch: VerifiedBatchApproval
    ) -> tuple[str, str, str, int, tuple[str, ...]]:
        if type(batch) is not VerifiedBatchApproval:
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        self._assert_batch_source_identity(batch)
        if _ledger_metadata_value(connection, "schema_version") != "2":
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        plan_sha256 = batch.payload.get("plan_sha256")
        csv_sha256 = batch.payload.get("csv_sha256")
        batch_nonce = batch.payload.get("batch_nonce")
        try:
            plan = json.loads(batch.plan_bytes.decode("utf-8"))
            max_send_attempts = plan["execution_limits"]["max_send_attempts"]
            if (type(max_send_attempts) is not int
                    or not 1 <= max_send_attempts <= 20
                    or not isinstance(plan_sha256, str)
                    or not isinstance(csv_sha256, str)
                    or not isinstance(batch_nonce, str)):
                raise LedgerError("BLOCKED_OWNER_AUTHN")
            scope_ids = tuple(sorted({
                row["writer_control_scope_id"] for row in batch.approved_rows
                if isinstance(row.get("writer_control_scope_id"), str)
            }))
        except (KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LedgerError("BLOCKED_OWNER_AUTHN") from error
        if not scope_ids or len(scope_ids) == 0:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        return batch_nonce, plan_sha256, csv_sha256, max_send_attempts, scope_ids

    def _assert_batch_source_identity(self, batch: VerifiedBatchApproval) -> None:
        try:
            canonical = canonical_bytes(dict(batch.payload))
            plan_sha256 = hashlib.sha256(batch.plan_bytes).hexdigest()
            csv_sha256 = hashlib.sha256(batch.csv_bytes).hexdigest()
        except (BatchAuthRejected, TypeError, ValueError) as error:
            raise LedgerError("BLOCKED_OWNER_AUTHN") from error
        if (canonical != batch.canonical_payload_bytes
                or approval_digest(canonical) != batch.batch_id
                or batch.payload.get("plan_sha256") != plan_sha256
                or batch.payload.get("csv_sha256") != csv_sha256):
            raise LedgerError("BLOCKED_OWNER_AUTHN")

    def _expected_batch_row_identity(
        self, batch: VerifiedBatchApproval, row_index: int
    ) -> tuple[str,str,str,str,str,str]:
        try:
            position=batch.approved_row_indexes.index(row_index)
            row=batch.approved_rows[position]
            proposal_id=row["proposal_id"]
            account=batch.payload["account"]
            partition=batch.payload["partition"]
            region=row["region"]
            resource_arn=row["resource_arn"]
            approved_name=row["approved_name"]
            aws_operation=row["aws_operation"]
            scope_id=row["writer_control_scope_id"]
        except (ValueError,IndexError,KeyError,TypeError) as error:
            raise LedgerError("BLOCKED_OWNER_AUTHN") from error
        values=(proposal_id,account,partition,region,resource_arn,approved_name,aws_operation,scope_id)
        if any(not isinstance(value,str) or not value for value in values):
            raise LedgerError("BLOCKED_OWNER_AUTHN")
        identity=[batch.batch_id,row_index,proposal_id,account,partition,region,
                  resource_arn,approved_name,aws_operation,scope_id]
        row_authority_id=hashlib.sha256(canonical_bytes(identity)).hexdigest()
        return row_authority_id,proposal_id,resource_arn,approved_name,aws_operation,scope_id

    def _register_batch_in_transaction(
        self,
        connection: sqlite3.Connection,
        batch: VerifiedBatchApproval,
        *,
        timestamp: str,
        current_intent_id: str | None = None,
        require_clear_scopes: bool = True,
    ) -> tuple[str, str, str, int, tuple[str, ...]]:
        batch_nonce, plan_sha256, csv_sha256, cap, scope_ids = self._batch_plan_state(
            connection, batch
        )
        row = connection.execute(
            "SELECT batch_nonce,plan_sha256,csv_sha256,state,max_send_attempts "
            "FROM batch_registry WHERE batch_id=?", (batch.batch_id,)
        ).fetchone()
        if row is None:
            nonce_owner = connection.execute(
                "SELECT batch_id FROM batch_registry WHERE batch_nonce=?", (batch_nonce,)
            ).fetchone()
            if nonce_owner is not None:
                raise LedgerError("BLOCKED_AUTH_REPLAY")
            now = self._now()
            created_at_utc = self._iso(now)
            try:
                connection.execute(
                    "INSERT INTO batch_registry(batch_id,batch_nonce,plan_sha256,csv_sha256,"
                    "state,max_send_attempts,created_at_utc) VALUES(?,?,?,?,?,?,?)",
                    (batch.batch_id,batch_nonce,plan_sha256,csv_sha256,"ACTIVE",cap,created_at_utc),
                )
            except sqlite3.IntegrityError as error:
                raise LedgerError("BLOCKED_AUTH_REPLAY") from error
            connection.execute(
                "INSERT INTO batch_events(batch_id,event,reason,timestamp_utc) VALUES(?,?,?,?)",
                (batch.batch_id,"BATCH_REGISTERED",None,created_at_utc),
            )
        elif row != (batch_nonce,plan_sha256,csv_sha256,"ACTIVE",cap):
            raise LedgerError("BLOCKED_AUTH_REPLAY")
        for scope_id in scope_ids:
            if not require_clear_scopes:
                continue
            scope_state = connection.execute(
                "SELECT state FROM scopes WHERE scope_id=?", (scope_id,)
            ).fetchone()
            if scope_state != ("CLEARED",):
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            pending = connection.execute(
                "SELECT 1 FROM intents WHERE scope_id=? AND state!='TERMINAL' "
                "AND intent_id!=COALESCE(?, '') LIMIT 1",
                (scope_id,current_intent_id),
            ).fetchone()
            if pending is not None:
                raise LedgerError("BLOCKED_INCOMPLETE_INTENT")
        stored = connection.execute(
            "SELECT send_attempts_consumed FROM batch_registry WHERE batch_id=?",
            (batch.batch_id,),
        ).fetchone()
        consumed = connection.execute(
            "SELECT COUNT(DISTINCT br.intent_id) FROM batch_rows br "
            "JOIN intent_history ih ON ih.intent_id=br.intent_id "
            "WHERE br.batch_id=? AND ih.event='SEND_ATTEMPT_CONSUMED'",
            (batch.batch_id,),
        ).fetchone()
        if stored is None or consumed is None or stored[0] != consumed[0]:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        return batch_nonce,plan_sha256,csv_sha256,cap,scope_ids

    def stop_batch(self,batch:VerifiedBatchApproval,*,reason_code:str)->None:
        """Persist an authenticated Batch stop without creating an Intent."""
        if not isinstance(reason_code,str) or re.fullmatch(r"[A-Z0-9_]{1,64}",reason_code) is None:
            raise LedgerError("BLOCKED_INPUT_INVALID")
        if not self._trusted_host:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        from name_tag_batch_trust import load_current_protected_owner_trust
        from name_tag_batch_approval import revalidate_verified_batch
        self._assert_batch_source_identity(batch)
        fresh=None
        try:
            fresh=revalidate_verified_batch(
                batch,trust=load_current_protected_owner_trust(),now_utc=self._now()
            )
        except BatchAuthRejected:
            fresh=None
        timestamp=self._iso(self._now())
        self._lock()
        try:
            with self._connection() as connection:
                self._validate_ledger_state(connection)
                connection.execute("BEGIN IMMEDIATE")
                state=connection.execute(
                    "SELECT batch_nonce,plan_sha256,csv_sha256,state FROM batch_registry "
                    "WHERE batch_id=?",(batch.batch_id,)
                ).fetchone()
                if state is None:
                    if fresh is None:
                        raise LedgerError("BLOCKED_OWNER_AUTHN")
                    self._register_batch_in_transaction(
                        connection,fresh,timestamp=timestamp,require_clear_scopes=False
                    )
                elif (state[0]!=batch.payload.get("batch_nonce")
                        or state[1]!=batch.payload.get("plan_sha256")
                        or state[2]!=batch.payload.get("csv_sha256")):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                elif state[3] == "STOPPED":
                    connection.rollback()
                    return
                elif state[3] != "ACTIVE":
                    raise LedgerError("BLOCKED_AUTH_REPLAY")
                connection.execute(
                    "UPDATE batch_registry SET state='STOPPED',stop_reason=?,stopped_at_utc=? "
                    "WHERE batch_id=? AND state='ACTIVE'",
                    (reason_code,timestamp,batch.batch_id),
                )
                connection.execute(
                    "INSERT INTO batch_events(batch_id,event,reason,timestamp_utc) VALUES(?,?,?,?)",
                    (batch.batch_id,"STOP",reason_code,timestamp),
                )
                connection.commit()
        except sqlite3.Error as error:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
        finally:
            self._unlock()

    def create_batch_intent(
        self,
        row_authority: VerifiedBatchRowAuthority,
        *,
        scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
    ) -> IntentHandle:
        """Admit one signed Batch row into the current v2 host-bound Ledger."""
        if not self._trusted_host:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        fresh = self._revalidate_batch_row(row_authority)
        batch = fresh.batch
        row = fresh.row
        scope_id = row.get("writer_control_scope_id")
        resource_arn = row.get("resource_arn")
        approved_name = row.get("approved_name")
        aws_operation = row.get("aws_operation")
        proposal_id = row.get("proposal_id")
        if (not all(isinstance(value, str) and value for value in
                    (scope_id, resource_arn, approved_name, aws_operation, proposal_id))
                or aws_operation != "ec2:CreateTags"
                or not isinstance(scope, ScopeEvidence)
                or scope.writer_control_scope_id != scope_id
                or not isinstance(side_effects, Sequence)
                or not side_effects
                or any(not isinstance(item, SideEffectEvidence) for item in side_effects)):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        now = self._now()
        intent_id = uuid.uuid4().hex
        ownership_token = uuid.uuid4().hex
        execution_nonce = f"batch:{batch.batch_id}:{fresh.row_index}:{fresh.row_authority_id}"
        timestamp = self._iso(now)
        self._lock()
        try:
            with self._connection() as connection:
                self._validate_ledger_state(connection)
                connection.execute("BEGIN IMMEDIATE")
                self._register_batch_in_transaction(connection,batch,timestamp=timestamp)
                self._assert_scope_evidence(connection,scope,side_effects)
                if self._effective_scope_state(connection,scope_id) != "CLEARED":
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                scope_row=connection.execute(
                    "SELECT target_arns FROM scopes WHERE scope_id=?",(scope_id,)
                ).fetchone()
                if scope_row is None or not isinstance(scope_row[0],str):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                try:
                    controlled_arns=json.loads(scope_row[0])
                except json.JSONDecodeError as error:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
                if (not isinstance(controlled_arns,list)
                        or resource_arn not in controlled_arns
                        or resource_arn not in scope.controlled_arns):
                    raise LedgerError("BLOCKED_SCOPE_MISMATCH")
                pending=connection.execute(
                    "SELECT 1 FROM intents WHERE scope_id=? AND state!='TERMINAL' LIMIT 1",
                    (scope_id,),
                ).fetchone()
                if pending is not None:
                    raise LedgerError("BLOCKED_INCOMPLETE_INTENT")
                admission_check=self._revalidate_batch_row(fresh)
                if admission_check.row_authority_id != fresh.row_authority_id:
                    raise LedgerError("BLOCKED_OWNER_AUTHN")
                duplicate=connection.execute(
                    "SELECT 1 FROM batch_rows WHERE (batch_id=? AND row_index=?) "
                    "OR row_authority_id=? UNION ALL "
                    "SELECT 1 FROM batch_row_dispositions WHERE (batch_id=? AND row_index=?) "
                    "OR row_authority_id=? LIMIT 1",
                    (batch.batch_id,fresh.row_index,fresh.row_authority_id,
                     batch.batch_id,fresh.row_index,fresh.row_authority_id),
                ).fetchone()
                if duplicate is not None:
                    raise LedgerError("BLOCKED_AUTH_REPLAY")
                cap_row=connection.execute(
                    "SELECT max_send_attempts,send_attempts_consumed,state "
                    "FROM batch_registry WHERE batch_id=?",(batch.batch_id,)
                ).fetchone()
                if cap_row is None or cap_row[2] != "ACTIVE":
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                if cap_row[1] >= cap_row[0]:
                    raise LedgerError("BLOCKED_AUTH_REPLAY")
                connection.execute(
                    "INSERT INTO intents(intent_id,scope_id,authorization_id,execution_nonce,"
                    "resource_arn,approved_name,writer_control_scope_id,aws_operation,"
                    "ownership_token,execution_id,state,outcome,name_after,created_at_utc,updated_at_utc) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (intent_id,scope_id,fresh.row_authority_id,execution_nonce,resource_arn,
                     approved_name,scope_id,aws_operation,ownership_token,self._execution_id,
                     "WRITE_INTENT_RECORDED",None,None,timestamp,timestamp),
                )
                connection.execute(
                    "INSERT INTO batch_rows(row_authority_id,batch_id,row_index,proposal_id,intent_id,"
                    "resource_arn,approved_name,aws_operation,scope_id) VALUES(?,?,?,?,?,?,?,?,?)",
                    (fresh.row_authority_id,batch.batch_id,fresh.row_index,proposal_id,intent_id,
                     resource_arn,approved_name,aws_operation,scope_id),
                )
                connection.execute(
                    "INSERT INTO intent_history(intent_id,event,timestamp_utc) VALUES(?,?,?)",
                    (intent_id,"WRITE_INTENT_RECORDED",timestamp),
                )
                connection.execute(
                    "INSERT INTO batch_events(batch_id,event,scope_id,intent_id,timestamp_utc) "
                    "VALUES(?,?,?,?,?)",
                    (batch.batch_id,"INTENT_ADMITTED",scope_id,intent_id,timestamp),
                )
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise LedgerError("BLOCKED_AUTH_REPLAY") from error
        except sqlite3.Error as error:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
        finally:
            self._unlock()
        return IntentHandle(
            intent_id=intent_id,authorization_id=fresh.row_authority_id,
            execution_id=self._execution_id,ownership_token=ownership_token,
            batch_row_authority=fresh,batch_scope=scope,batch_side_effects=tuple(side_effects),
        )

    def record_batch_presend_disposition(
        self,
        row_authority: VerifiedBatchRowAuthority,
        *,
        scope: ScopeEvidence,
        side_effects: Sequence[SideEffectEvidence],
        decision: Literal[
            "SKIPPED_NAME_CHANGED", "SKIPPED_IAM_UNSUPPORTED", "NOT_ATTEMPTED_CAP"
        ],
        reason_code: str,
        observed_name_sha256: str | None = None,
    ) -> None:
        """Persist a one-shot terminal no-send decision without allocating an Intent."""
        if decision not in (
            "SKIPPED_NAME_CHANGED", "SKIPPED_IAM_UNSUPPORTED", "NOT_ATTEMPTED_CAP"
        ):
            raise LedgerError("BLOCKED_INPUT_INVALID")
        if (not isinstance(reason_code,str) or re.fullmatch(r"[A-Z0-9_]{1,64}",reason_code) is None
                or (observed_name_sha256 is not None
                    and re.fullmatch(r"[0-9a-f]{64}",observed_name_sha256) is None)
                or (decision == "SKIPPED_NAME_CHANGED" and observed_name_sha256 is None)):
            raise LedgerError("BLOCKED_INPUT_INVALID")
        if type(scope) is not ScopeEvidence or not side_effects:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        fresh=self._revalidate_batch_row(row_authority)
        batch=fresh.batch
        row=fresh.row
        scope_id=row.get("writer_control_scope_id")
        resource_arn=row.get("resource_arn")
        if (not isinstance(scope_id,str) or scope_id != scope.writer_control_scope_id
                or not isinstance(resource_arn,str) or resource_arn not in scope.controlled_arns):
            raise LedgerError("BLOCKED_SCOPE_MISMATCH")
        timestamp=self._iso(self._now())
        self._lock()
        try:
            with self._connection() as connection:
                self._validate_ledger_state(connection)
                connection.execute("BEGIN IMMEDIATE")
                self._register_batch_in_transaction(connection,batch,timestamp=timestamp)
                self._assert_scope_evidence(connection,scope,side_effects)
                if self._effective_scope_state(connection,scope_id) != "CLEARED":
                    raise LedgerError("BLOCKED_SCOPE_HOLD")
                batch_state=connection.execute(
                    "SELECT state,max_send_attempts,send_attempts_consumed "
                    "FROM batch_registry WHERE batch_id=?",(batch.batch_id,)
                ).fetchone()
                if batch_state is None or batch_state[0] != "ACTIVE":
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                if decision == "NOT_ATTEMPTED_CAP":
                    if batch_state[2] < batch_state[1]:
                        raise LedgerError("BLOCKED_AUTH_REPLAY")
                elif batch_state[2] >= batch_state[1]:
                    raise LedgerError("BLOCKED_AUTH_REPLAY")
                duplicate=connection.execute(
                    "SELECT 1 FROM batch_rows WHERE (batch_id=? AND row_index=?) "
                    "OR row_authority_id=? UNION ALL "
                    "SELECT 1 FROM batch_row_dispositions WHERE (batch_id=? AND row_index=?) "
                    "OR row_authority_id=? LIMIT 1",
                    (batch.batch_id,fresh.row_index,fresh.row_authority_id,
                     batch.batch_id,fresh.row_index,fresh.row_authority_id),
                ).fetchone()
                if duplicate is not None:
                    raise LedgerError("BLOCKED_AUTH_REPLAY")
                disposition_check=self._revalidate_batch_row(fresh)
                if disposition_check.row_authority_id != fresh.row_authority_id:
                    raise LedgerError("BLOCKED_OWNER_AUTHN")
                connection.execute(
                    "INSERT INTO batch_row_dispositions(batch_id,row_index,row_authority_id,"
                    "decision,reason_code,observed_name_sha256,decided_at_utc) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch.batch_id,fresh.row_index,fresh.row_authority_id,decision,
                     reason_code,observed_name_sha256,timestamp),
                )
                connection.execute(
                    "INSERT INTO batch_events(batch_id,event,reason,scope_id,timestamp_utc) "
                    "VALUES(?,?,?,?,?)",
                    (batch.batch_id,decision,reason_code,scope_id,timestamp),
                )
                connection.commit()
        except sqlite3.IntegrityError as error:
            raise LedgerError("BLOCKED_AUTH_REPLAY") from error
        except sqlite3.Error as error:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
        finally:
            self._unlock()

    def complete_batch(self, batch: VerifiedBatchApproval) -> None:
        """Complete an active Batch only after every approved row is terminal and known."""
        from name_tag_batch_trust import load_current_protected_owner_trust
        from name_tag_batch_approval import revalidate_verified_batch

        try:
            trust=load_current_protected_owner_trust()
            fresh_batch=revalidate_verified_batch(batch,trust=trust,now_utc=self._now())
            row_authorities=tuple(
                derive_batch_row_authority(
                    fresh_batch,row_index,
                    trust=load_current_protected_owner_trust(),now_utc=self._now(),
                )
                for row_index in fresh_batch.approved_row_indexes
            )
        except BatchAuthRejected as error:
            raise LedgerError("BLOCKED_OWNER_AUTHN") from error
        self._lock()
        try:
            with self._connection() as connection:
                self._validate_ledger_state(connection)
                connection.execute("BEGIN IMMEDIATE")
                self._register_batch_in_transaction(
                    connection,fresh_batch,timestamp=self._iso(self._now())
                )
                for authority in row_authorities:
                    completion_check=self._revalidate_batch_row(authority)
                    if completion_check.row_authority_id != authority.row_authority_id:
                        raise LedgerError("BLOCKED_OWNER_AUTHN")
                    expected=self._expected_batch_row_identity(
                        fresh_batch,authority.row_index
                    )
                    intent=connection.execute(
                        "SELECT br.row_authority_id,br.proposal_id,br.resource_arn,"
                        "br.approved_name,br.aws_operation,br.scope_id,i.state,i.outcome "
                        "FROM batch_rows br JOIN intents i ON i.intent_id=br.intent_id "
                        "WHERE br.batch_id=? AND br.row_index=?",
                        (fresh_batch.batch_id,authority.row_index),
                    ).fetchone()
                    disposition=connection.execute(
                        "SELECT row_authority_id,decision FROM batch_row_dispositions "
                        "WHERE batch_id=? AND row_index=?",
                        (fresh_batch.batch_id,authority.row_index),
                    ).fetchone()
                    if (intent is not None) == (disposition is not None):
                        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                    if intent is not None:
                        if (tuple(intent[:6]) != expected or intent[6] != "TERMINAL"
                                or intent[7] != "APPLIED_VERIFIED"):
                            raise LedgerError("BLOCKED_INCOMPLETE_INTENT")
                    elif disposition is None or disposition[0] != expected[0]:
                        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                active=connection.execute(
                    "SELECT state FROM batch_registry WHERE batch_id=?",
                    (fresh_batch.batch_id,),
                ).fetchone()
                if active != ("ACTIVE",):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                timestamp=self._iso(self._now())
                connection.execute(
                    "UPDATE batch_registry SET state='COMPLETED',completed_at_utc=? "
                    "WHERE batch_id=? AND state='ACTIVE'",
                    (timestamp,fresh_batch.batch_id),
                )
                connection.execute(
                    "INSERT INTO batch_events(batch_id,event,timestamp_utc) VALUES(?,?,?)",
                    (fresh_batch.batch_id,"COMPLETED",timestamp),
                )
                connection.commit()
        except sqlite3.Error as error:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
        finally:
            self._unlock()

    def batch_execution_state(self, batch: VerifiedBatchApproval) -> BatchExecutionState:
        """Read reconciled durable row outcomes for the exact signed Batch."""
        from name_tag_batch_trust import load_current_protected_owner_trust
        from name_tag_batch_approval import revalidate_verified_batch

        trust_valid = True
        try:
            trust=load_current_protected_owner_trust()
            fresh_batch=revalidate_verified_batch(batch,trust=trust,now_utc=self._now())
        except BatchAuthRejected:
            self._assert_batch_source_identity(batch)
            fresh_batch=batch
            trust_valid=False
        self._lock()
        try:
            with self._connection() as connection:
                self._validate_ledger_state(connection)
                nonce,plan_sha256,csv_sha256,cap,_scope_ids=self._batch_plan_state(
                    connection,fresh_batch
                )
                registry=connection.execute(
                    "SELECT batch_nonce,plan_sha256,csv_sha256,state,max_send_attempts,send_attempts_consumed "
                    "FROM batch_registry WHERE batch_id=?",
                    (fresh_batch.batch_id,),
                ).fetchone()
                if registry is None:
                    if not trust_valid:
                        raise LedgerError("BLOCKED_OWNER_AUTHN")
                    nonce_owner=connection.execute(
                        "SELECT batch_id FROM batch_registry WHERE batch_nonce=?",(nonce,)
                    ).fetchone()
                    claimed=connection.execute(
                        "SELECT 1 FROM batch_rows WHERE batch_id=? UNION ALL "
                        "SELECT 1 FROM batch_row_dispositions WHERE batch_id=? LIMIT 1",
                        (fresh_batch.batch_id,fresh_batch.batch_id),
                    ).fetchone()
                    if nonce_owner is not None or claimed is not None:
                        raise LedgerError("BLOCKED_AUTH_REPLAY")
                    return BatchExecutionState(
                        "UNREGISTERED",0,cap,tuple("UNCLAIMED" for _ in fresh_batch.approved_row_indexes)
                    )
                if (registry[0]!=nonce or registry[1]!=plan_sha256
                        or registry[2]!=csv_sha256 or registry[4]!=cap):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                consumed=connection.execute(
                    "SELECT COUNT(DISTINCT br.intent_id) FROM batch_rows br "
                    "JOIN intent_history ih ON ih.intent_id=br.intent_id "
                    "WHERE br.batch_id=? AND ih.event='SEND_ATTEMPT_CONSUMED'",
                    (fresh_batch.batch_id,),
                ).fetchone()
                if consumed is None or consumed[0]!=registry[5]:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                result_by_row:dict[int,str]={}
                for index in fresh_batch.approved_row_indexes:
                    expected=self._expected_batch_row_identity(fresh_batch,index)
                    intent=connection.execute(
                        "SELECT br.row_authority_id,br.proposal_id,br.resource_arn,"
                        "br.approved_name,br.aws_operation,br.scope_id,i.state,i.outcome FROM batch_rows br "
                        "JOIN intents i ON i.intent_id=br.intent_id "
                        "WHERE br.batch_id=? AND br.row_index=?",
                        (fresh_batch.batch_id,index),
                    ).fetchone()
                    disposition=connection.execute(
                        "SELECT row_authority_id,decision FROM batch_row_dispositions "
                        "WHERE batch_id=? AND row_index=?",
                        (fresh_batch.batch_id,index),
                    ).fetchone()
                    if intent is None and disposition is None:
                        if registry[3] == "STOPPED":
                            result_by_row[index]="NOT_ATTEMPTED_BATCH_STOP"
                            continue
                        if registry[3] == "ACTIVE":
                            result_by_row[index]="UNCLAIMED"
                            continue
                        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                    if (intent is not None) == (disposition is not None):
                        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                    if intent is not None:
                        if tuple(intent[:6]) != expected:
                            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                        result_by_row[index]=intent[7] if intent[6]=="TERMINAL" else intent[6]
                    else:
                        if disposition[0] != expected[0]:
                            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                        result_by_row[index]=disposition[1]
                return BatchExecutionState(
                    registry[3],registry[5],registry[4],
                    tuple(result_by_row[index] for index in fresh_batch.approved_row_indexes),
                )
        except sqlite3.Error as error:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from error
        finally:
            self._unlock()

    def create_intent(
        self, authorization: VerifiedEnvelope, *, scope_id: str,
        scope: ScopeEvidence | None = None,
        side_effects: Sequence[SideEffectEvidence] | None = None,
    ) -> IntentHandle:
        """Create a durable, current-execution Intent for one authorized send."""
        if not self._trusted_host:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

        fresh = self._revalidate_authorization(authorization, scope_id)
        payload = fresh.payload
        authorization_id = fresh.content_id
        execution_nonce = payload.get("execution_nonce")
        resource_arn = payload.get("resource_arn")
        approved_name = payload.get("approved_name")
        writer_control_scope_id = payload.get("writer_control_scope_id")
        aws_operation = payload.get("aws_operation")
        if not all(
            isinstance(value, str) and value
            for value in (
                authorization_id,
                execution_nonce,
                resource_arn,
                approved_name,
                writer_control_scope_id,
                aws_operation,
            )
        ):
            raise LedgerError("BLOCKED_OWNER_AUTHN")

        intent_id = uuid.uuid4().hex
        ownership_token = uuid.uuid4().hex
        now = self._now()

        self._lock()
        try:
            with self._connection() as conn:
                self._validate_ledger_state(conn)
                conn.execute("BEGIN IMMEDIATE")

                # No prior incomplete Intent may exist for this scope.
                prior = conn.execute(
                    "SELECT 1 FROM intents WHERE scope_id = ? AND state != 'TERMINAL' LIMIT 1",
                    (scope_id,),
                ).fetchone()
                if prior is not None:
                    raise LedgerError("BLOCKED_INCOMPLETE_INTENT")

                if self._effective_scope_state(conn, scope_id) != "CLEARED":
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                if (scope is None) != (side_effects is None):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                if scope is not None and side_effects is not None:
                    self._assert_scope_evidence(conn, scope, side_effects)

                scope_row = conn.execute(
                    "SELECT target_arns FROM scopes WHERE scope_id = ?", (scope_id,)
                ).fetchone()
                if scope_row is None or not isinstance(scope_row[0], str):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                try:
                    decoded_target_arns = json.loads(scope_row[0])
                except json.JSONDecodeError as exc:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
                if (
                    not isinstance(decoded_target_arns, list)
                    or any(not isinstance(arn, str) for arn in decoded_target_arns)
                ):
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                controlled_arns = frozenset(decoded_target_arns)
                if resource_arn not in controlled_arns:
                    raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

                # Idempotency / replay guard: one authorization_id may not be reused.
                reused = conn.execute(
                    "SELECT 1 FROM intents WHERE authorization_id = ? OR execution_nonce = ? LIMIT 1",
                    (authorization_id, execution_nonce),
                ).fetchone()
                if reused is not None:
                    raise LedgerError("BLOCKED_AUTH_REPLAY")

                timestamp = self._iso(now)
                conn.execute(
                    """
                    INSERT INTO intents (
                        intent_id, scope_id, authorization_id, execution_nonce, resource_arn,
                        approved_name, writer_control_scope_id, aws_operation, ownership_token,
                        execution_id, state, outcome, name_after, created_at_utc, updated_at_utc
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        intent_id, scope_id, authorization_id, execution_nonce, resource_arn,
                        approved_name,
                        writer_control_scope_id,
                        aws_operation,
                        ownership_token,
                        self._execution_id,
                        "WRITE_INTENT_RECORDED",
                        None,
                        None,
                        timestamp,
                        timestamp,
                    ),
                )
                conn.execute(
                    """
                    INSERT INTO intent_history (intent_id, event, timestamp_utc)
                    VALUES (?, ?, ?)
                    """,
                    (intent_id, "WRITE_INTENT_RECORDED", timestamp),
                )
                conn.commit()
        finally:
            self._unlock()

        return IntentHandle(
            intent_id=intent_id,
            authorization_id=authorization_id,
            execution_id=self._execution_id,
            ownership_token=ownership_token,
        )

    def consume_first_send(self, handle: IntentHandle) -> FirstSendPermit:
        """Consume the one first-send right for ``handle``.

        Verifies current exclusive execution ownership and durable
        ``SEND_ATTEMPT_CONSUMED``, then returns a non-persistable permit.
        """
        if not isinstance(handle, IntentHandle) or not handle.ownership_token:
            raise LedgerError("BLOCKED_INTENT_REPLAY")
        if handle.execution_id != self._execution_id:
            raise LedgerError("BLOCKED_INTENT_REPLAY")

        batch_authority = handle.batch_row_authority
        fresh_batch_authority = (
            self._revalidate_batch_row(batch_authority)
            if batch_authority is not None else None
        )
        if (fresh_batch_authority is not None
                and fresh_batch_authority.row_authority_id != handle.authorization_id):
            raise LedgerError("BLOCKED_INTENT_REPLAY")

        self._lock()
        try:
            with self._connection() as conn:
                self._validate_ledger_state(conn)
                conn.execute("BEGIN IMMEDIATE")

                row = conn.execute(
                    """
                    SELECT scope_id, state, authorization_id, resource_arn, approved_name,
                           writer_control_scope_id, aws_operation, ownership_token, execution_id
                    FROM intents WHERE intent_id = ?
                    """,
                    (handle.intent_id,),
                ).fetchone()
                if row is None:
                    raise LedgerError("BLOCKED_INTENT_REPLAY")
                (
                    scope_id,
                    state,
                    authorization_id,
                    resource_arn,
                    approved_name,
                    writer_control_scope_id,
                    aws_operation,
                    stored_token,
                    stored_execution_id,
                ) = row
                if stored_token != handle.ownership_token:
                    raise LedgerError("BLOCKED_INTENT_REPLAY")
                if stored_execution_id != self._execution_id:
                    raise LedgerError("BLOCKED_INTENT_REPLAY")
                if state in ("TERMINAL", "SEND_ATTEMPT_CONSUMED"):
                    raise LedgerError("BLOCKED_INTENT_REPLAY")
                if state != "WRITE_INTENT_RECORDED":
                    raise LedgerError("BLOCKED_INTENT_REPLAY")

                # Explicit scope HOLD/UNKNOWN blocks first send.
                scope_row = conn.execute(
                    "SELECT state FROM scopes WHERE scope_id = ?", (scope_id,)
                ).fetchone()
                if scope_row is None or scope_row[0] != "CLEARED":
                    raise LedgerError("BLOCKED_SCOPE_HOLD")

                # Any other non-terminal intent for this scope is a prior incomplete intent.
                prior = conn.execute(
                    "SELECT 1 FROM intents WHERE scope_id = ? AND intent_id != ? AND state != 'TERMINAL' LIMIT 1",
                    (scope_id, handle.intent_id),
                ).fetchone()
                if prior is not None:
                    raise LedgerError("BLOCKED_INCOMPLETE_INTENT")

                batch_record = None
                if _ledger_metadata_value(conn, "schema_version") == "2":
                    batch_record = conn.execute(
                        "SELECT row_authority_id,batch_id,row_index,resource_arn,approved_name,"
                        "aws_operation,scope_id FROM batch_rows WHERE intent_id=?",
                        (handle.intent_id,),
                    ).fetchone()
                if batch_record is not None:
                    if fresh_batch_authority is None:
                        raise LedgerError("BLOCKED_OWNER_AUTHN")
                    fresh_batch=fresh_batch_authority.batch
                    if (batch_record[0] != fresh_batch_authority.row_authority_id
                            or batch_record[1] != fresh_batch.batch_id
                            or batch_record[2] != fresh_batch_authority.row_index
                            or batch_record[3] != resource_arn
                            or batch_record[4] != approved_name
                            or batch_record[5] != aws_operation
                            or batch_record[6] != scope_id
                            or handle.batch_scope is None
                            or handle.batch_side_effects is None):
                        raise LedgerError("BLOCKED_INTENT_REPLAY")
                    self._register_batch_in_transaction(
                        conn,fresh_batch,timestamp=self._iso(self._now()),
                        current_intent_id=handle.intent_id,
                    )
                    self._assert_scope_evidence(
                        conn,handle.batch_scope,handle.batch_side_effects
                    )
                    batch_state=conn.execute(
                        "SELECT max_send_attempts,send_attempts_consumed,state "
                        "FROM batch_registry WHERE batch_id=?",(fresh_batch.batch_id,)
                    ).fetchone()
                    if batch_state is None or batch_state[2] != "ACTIVE":
                        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
                    if batch_state[1] >= batch_state[0]:
                        raise LedgerError("BLOCKED_AUTH_REPLAY")
                elif fresh_batch_authority is not None:
                    raise LedgerError("BLOCKED_INTENT_REPLAY")

                now = self._now()
                timestamp = self._iso(now)
                conn.execute(
                    "UPDATE intents SET state = ?, updated_at_utc = ? WHERE intent_id = ?",
                    ("SEND_ATTEMPT_CONSUMED", timestamp, handle.intent_id),
                )
                conn.execute(
                    """
                    INSERT INTO intent_history (intent_id, event, timestamp_utc)
                    VALUES (?, ?, ?)
                    """,
                    (handle.intent_id, "SEND_ATTEMPT_CONSUMED", timestamp),
                )
                if batch_record is not None and fresh_batch_authority is not None:
                    conn.execute(
                        "UPDATE batch_registry SET send_attempts_consumed="
                        "send_attempts_consumed+1 WHERE batch_id=? AND state='ACTIVE'",
                        (fresh_batch_authority.batch.batch_id,),
                    )
                    conn.execute(
                        "INSERT INTO batch_events(batch_id,event,scope_id,intent_id,timestamp_utc) "
                        "VALUES(?,?,?,?,?)",
                        (fresh_batch_authority.batch.batch_id,"SEND_ATTEMPT_CONSUMED",
                         scope_id,handle.intent_id,timestamp),
                    )
                conn.commit()
        finally:
            self._unlock()

        return FirstSendPermit(
            authorization_id=authorization_id,
            resource_arn=resource_arn,
            approved_name=approved_name,
            writer_control_scope_id=writer_control_scope_id,
            aws_operation=aws_operation,
            execution_id=self._execution_id,
            ownership_token=handle.ownership_token,
        )

    def record_readback(
        self, handle: IntentHandle, *, name_after: str | None, outcome: str
    ) -> None:
        """Record the readback outcome for a consumed Intent.

        For failure/unknown outcomes, scope HOLD is written in the **same**
        transaction before the Intent is marked terminal.  If the HOLD commit
        cannot durably persist, the whole transaction aborts and the host is
        blocked with ``BLOCKED_SCOPE_STATE_UNKNOWN``.
        """
        if not isinstance(handle, IntentHandle) or not handle.ownership_token:
            raise LedgerError("BLOCKED_INTENT_REPLAY")
        if handle.execution_id != self._execution_id:
            raise LedgerError("BLOCKED_INTENT_REPLAY")
        if not isinstance(outcome, str) or not outcome:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

        self._lock()
        try:
            with self._connection() as conn:
                self._validate_ledger_state(conn)
                conn.execute("BEGIN IMMEDIATE")

                row = conn.execute(
                    "SELECT scope_id, state, ownership_token FROM intents WHERE intent_id = ?",
                    (handle.intent_id,),
                ).fetchone()
                if row is None or row[1] != "SEND_ATTEMPT_CONSUMED":
                    raise LedgerError("BLOCKED_INTENT_REPLAY")
                scope_id = row[0]
                if row[2] != handle.ownership_token:
                    raise LedgerError("BLOCKED_INTENT_REPLAY")
                batch_record = None
                if _ledger_metadata_value(conn,"schema_version") == "2":
                    batch_record = conn.execute(
                        "SELECT batch_id,row_authority_id FROM batch_rows WHERE intent_id=?",
                        (handle.intent_id,),
                    ).fetchone()
                if batch_record is not None and (
                    handle.batch_row_authority is None
                    or batch_record[1] != handle.batch_row_authority.row_authority_id
                    or batch_record[1] != handle.authorization_id
                ):
                    raise LedgerError("BLOCKED_INTENT_REPLAY")

                now = self._now()
                timestamp = self._iso(now)

                # Any outcome other than explicit success requires durable scope HOLD before terminal.
                if outcome != "APPLIED_VERIFIED":
                    conn.execute(
                        "UPDATE scopes SET state = ?, reason = ?, updated_at_utc = ? WHERE scope_id = ?",
                        ("HOLD", f"readback:{outcome}", timestamp, scope_id),
                    )
                    conn.execute(
                        """
                        INSERT INTO scope_history (
                            scope_id, state, decision_id, decision_nonce, owner_principal_id,
                            writer_evidence_digest, side_effect_evidence_digest, target_arns,
                            reason, timestamp_utc
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (scope_id, "HOLD", None, None, None, None, None, None, f"readback:{outcome}", timestamp),
                    )

                conn.execute(
                    """
                    UPDATE intents SET state = 'TERMINAL', outcome = ?, name_after = ?,
                                       updated_at_utc = ? WHERE intent_id = ?
                    """,
                    (outcome, name_after, timestamp, handle.intent_id),
                )
                conn.execute(
                    """
                    INSERT INTO intent_history (intent_id, event, timestamp_utc)
                    VALUES (?, ?, ?)
                    """,
                    (handle.intent_id, f"TERMINAL:{outcome}", timestamp),
                )
                if batch_record is not None:
                    if outcome != "APPLIED_VERIFIED":
                        conn.execute(
                            "UPDATE batch_registry SET state='STOPPED',stop_reason=?,stopped_at_utc=? "
                            "WHERE batch_id=? AND state='ACTIVE'",
                            (outcome,timestamp,batch_record[0]),
                        )
                    conn.execute(
                        "INSERT INTO batch_events(batch_id,event,reason,scope_id,intent_id,timestamp_utc) "
                        "VALUES(?,?,?,?,?,?)",
                        (batch_record[0],f"TERMINAL:{outcome}",outcome,scope_id,
                         handle.intent_id,timestamp),
                    )
                conn.commit()
        except LedgerError as exc:
            # Re-raise known LedgerErrors (e.g., replay) as-is.
            raise exc
        except sqlite3.Error as exc:
            # A database failure means the HOLD/terminal state is not durable.
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
        finally:
            self._unlock()

# ---------------------------------------------------------------------------
# Ledger opening
# ---------------------------------------------------------------------------


def _check_ledger_path(path: Path) -> None:
    """Reject symlinks and unsafe owner/mode on the ledger path and its parent."""
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        # Creating a new ledger file is allowed; parent checks still apply.
        pass
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    else:
        if stat.S_ISLNK(info.st_mode):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if not stat.S_ISREG(info.st_mode):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if info.st_mode & 0o077:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if info.st_uid != os.geteuid():
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    parent = path.parent
    try:
        parent_info = parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    if stat.S_ISLNK(parent_info.st_mode):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    if not stat.S_ISDIR(parent_info.st_mode):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    if parent_info.st_uid != os.geteuid():
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    if parent_info.st_mode & 0o022:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def create_ledger_database(
    path: Path, host_binding: str, ledger_instance_id: str
) -> None:
    """Create a fresh schema/database for a separately anchored ledger."""
    _check_ledger_path(path)
    if (
        os.path.lexists(path)
        or ledger_host_binding(path) != host_binding
        or re.fullmatch(r"[0-9a-f]{32}", ledger_instance_id) is None
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    try:
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        os.close(fd)
        with closing(sqlite3.connect(str(path), timeout=10.0)) as connection:
            _ = connection.execute("PRAGMA synchronous = FULL")
            _ = connection.execute("PRAGMA journal_mode = DELETE")
            _ = connection.execute("PRAGMA foreign_keys = ON")
            ledger = IntentLedger(
                path=path,
                trusted_host=True,
                trust=None,
                host_binding=host_binding,
                execution_id=uuid.uuid4().hex,
                _constructor_token=_LEDGER_CONSTRUCTOR_SENTINEL,
            )
            ledger._ensure_schema(connection)
            _ = connection.executemany(
                "INSERT INTO ledger_meta (key, value) VALUES (?, ?)",
                (
                    ("host_binding", host_binding),
                    ("schema_version", "1"),
                    ("ledger_instance_id", ledger_instance_id),
                ),
            )
            integrity_row = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()
            if (
                not isinstance(integrity_row, tuple)
                or len(integrity_row) != 1
                or not isinstance(integrity_row[0], str)
                or integrity_row[0] != "ok"
            ):
                raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
            connection.commit()
        file_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fchmod(file_fd, 0o600)
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except LedgerError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc


def _ledger_metadata_value(connection: sqlite3.Connection, key: str) -> str:
    row = connection.execute(
        "SELECT value FROM ledger_meta WHERE key = ?", (key,)
    ).fetchone()
    if not isinstance(row, tuple) or len(row) != 1 or not isinstance(row[0], str):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    return row[0]


def _validate_ledger_schema_state(connection: sqlite3.Connection) -> None:
    version = _ledger_metadata_value(connection, "schema_version")
    if version == "1":
        attempt = connection.execute(
            "SELECT 1 FROM ledger_meta WHERE key GLOB 'migration_attempt:*' LIMIT 1"
        ).fetchone()
        if attempt is not None:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        return
    if version != "2":
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    required_tables = {
        "batch_registry", "batch_rows", "batch_events",
        "batch_row_dispositions", "ledger_migration_receipts",
    }
    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    if not isinstance(table_rows, list) or not required_tables.issubset(
        {row[0] for row in table_rows if isinstance(row, tuple) and len(row) == 1}
    ):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    receipts = connection.execute(
        "SELECT decision_id,migration_nonce,ledger_instance_id "
        "FROM ledger_migration_receipts"
    ).fetchall()
    if not isinstance(receipts, list) or len(receipts) != 1:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
    receipt = receipts[0]
    marker = connection.execute(
        "SELECT value FROM ledger_meta WHERE key=?",
        (f"migration_attempt:{receipt[1]}",),
    ).fetchone()
    if (not isinstance(receipt, tuple) or len(receipt) != 3
            or not all(isinstance(value, str) and value for value in receipt)
            or marker != (f"COMMITTED:{receipt[0]}",)
            or _ledger_metadata_value(connection, "ledger_instance_id") != receipt[2]):
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")


def open_ledger(
    path: Path | str, *, trusted_host: bool, trust: OwnerTrust | None
) -> IntentLedger:
    """Open only a provisioned host-bound Intent ledger and fail closed otherwise."""
    file_path = Path(path).absolute()
    _check_ledger_path(file_path)
    if not trusted_host:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

    host_binding = ledger_host_binding(file_path)
    anchor_identity = read_ledger_anchor(file_path, host_binding)
    ledger = IntentLedger(
        path=file_path,
        trusted_host=trusted_host,
        trust=trust,
        host_binding=host_binding,
        execution_id=uuid.uuid4().hex,
        _constructor_token=_LEDGER_CONSTRUCTOR_SENTINEL,
    )
    connection: sqlite3.Connection | None = None
    try:
        ledger._lock()
        lock_fd = ledger._lock_fd
        if lock_fd is None:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        locked_file = os.fstat(lock_fd)
        path_file = file_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(path_file.st_mode)
            or locked_file.st_dev != path_file.st_dev
            or locked_file.st_ino != path_file.st_ino
            or path_file.st_dev != anchor_identity.ledger_device
            or path_file.st_ino != anchor_identity.ledger_inode
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")

        connection = sqlite3.connect(
            file_path.as_uri() + "?mode=rw", timeout=10.0, uri=True
        )
        _ = connection.execute("PRAGMA synchronous = FULL")
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        if (
            not isinstance(journal_mode, tuple)
            or len(journal_mode) != 1
            or not isinstance(journal_mode[0], str)
            or journal_mode[0].lower() != "delete"
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        _ = connection.execute("PRAGMA foreign_keys = ON")

        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if (
            not isinstance(integrity, tuple)
            or len(integrity) != 1
            or not isinstance(integrity[0], str)
            or integrity[0] != "ok"
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        if _ledger_metadata_value(connection, "host_binding") != host_binding:
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        _validate_ledger_schema_state(connection)
        if (
            _ledger_metadata_value(connection, "ledger_instance_id")
            != anchor_identity.ledger_instance_id
        ):
            raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")
        ledger._validate_ledger_state(connection)
        return ledger
    except LedgerError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN") from exc
    finally:
        if connection is not None:
            connection.close()
        ledger.close()






# ---------------------------------------------------------------------------
# Module-level convenience wrappers (identical signatures to IntentLedger methods)
# ---------------------------------------------------------------------------


def effective_scope_state(ledger: IntentLedger, scope_id: str) -> str:
    return ledger.effective_scope_state(scope_id)


def initialize_scope(
    ledger: IntentLedger,
    envelope: Mapping[str, object],
    *,
    action: ScopeAction,
    scope: ScopeEvidence,
    side_effects: Sequence[SideEffectEvidence],
) -> None:
    ledger.initialize_scope(envelope, action=action, scope=scope, side_effects=side_effects)


def release_scope(
    ledger: IntentLedger,
    envelope: Mapping[str, object],
    *,
    action: ScopeAction,
    scope: ScopeEvidence,
    side_effects: Sequence[SideEffectEvidence],
) -> None:
    ledger.release_scope(envelope, action=action, scope=scope, side_effects=side_effects)


def hold_scope(ledger: IntentLedger, scope_id: str, *, reason: str) -> None:
    ledger.hold_scope(scope_id, reason=reason)


def create_intent(
    ledger: IntentLedger, authorization: VerifiedEnvelope, *, scope_id: str,
    scope: ScopeEvidence | None = None,
    side_effects: Sequence[SideEffectEvidence] | None = None,
) -> IntentHandle:
    return ledger.create_intent(
        authorization, scope_id=scope_id, scope=scope, side_effects=side_effects
    )


def consume_first_send(ledger: IntentLedger, handle: IntentHandle) -> FirstSendPermit:
    return ledger.consume_first_send(handle)


def record_readback(
    ledger: IntentLedger, handle: IntentHandle, *, name_after: str | None, outcome: str
) -> None:
    ledger.record_readback(handle, name_after=name_after, outcome=outcome)
