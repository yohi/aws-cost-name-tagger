"""Owner-signed, one-shot v1-to-v2 migration gate for the host-bound Ledger."""
from __future__ import annotations

import base64
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

from name_tag_approval import ApprovalRejected, OwnerTrust, _select_signer_lines, _verify_signature
from name_tag_batch_approval import canonical_bytes
from name_tag_ledger import _ledger_metadata_value, ledger_host_binding
from name_tag_ledger_anchor import read_ledger_anchor
from name_tag_ledger_errors import LedgerError

MIGRATION_NAMESPACE = "aws-cost-name-tagger-ledger-migration-v1"
_MIGRATION_FIELDS = frozenset({
    "schema_version", "purpose", "ledger_path", "host_binding",
    "ledger_instance_id", "ledger_device", "ledger_inode",
    "from_schema_version", "to_schema_version", "owner_principal_id",
    "owner_key_fingerprint", "allowed_role", "issued_at_utc",
    "expires_at_utc", "migration_nonce",
})
class BatchMigrationRejected(Exception):
    """A typed fail-closed result for malformed or unauthorized migration input."""

    def __init__(self, code: str = "BLOCKED_OWNER_AUTHN") -> None:
        self.code = code
        super().__init__(self.code)


@dataclass(frozen=True, slots=True)
class VerifiedLedgerMigrationDecision:
    raw_envelope_json: bytes
    canonical_payload_bytes: bytes
    decision_id: str
    migration_nonce: str
    ledger_path: Path
    host_binding: str
    ledger_instance_id: str
    owner_principal_id: str


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BatchMigrationRejected()
        result[key] = value
    return result


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value
    ) is None:
        raise BatchMigrationRejected()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (OverflowError, ValueError) as error:
        raise BatchMigrationRejected() from error


def _schema_version_one(path: Path, host_binding: str, ledger_instance_id: str) -> None:
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as connection:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise BatchMigrationRejected()
            if _ledger_metadata_value(connection, "host_binding") != host_binding:
                raise BatchMigrationRejected()
            if _ledger_metadata_value(connection, "ledger_instance_id") != ledger_instance_id:
                raise BatchMigrationRejected()
            if _ledger_metadata_value(connection, "schema_version") != "1":
                raise BatchMigrationRejected()
    except (OSError, sqlite3.Error, LedgerError) as error:
        raise BatchMigrationRejected() from error


def _decode_migration_envelope(raw_envelope_json,trust,now_utc):
    if type(raw_envelope_json) is not bytes or not isinstance(trust,OwnerTrust):
        raise BatchMigrationRejected()
    if type(now_utc) is not datetime or now_utc.tzinfo is None or now_utc.utcoffset() is None:
        raise BatchMigrationRejected()
    try:
        envelope=json.loads(
            raw_envelope_json.decode("utf-8"),object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(BatchMigrationRejected()),
        )
    except (UnicodeDecodeError,json.JSONDecodeError) as error:
        raise BatchMigrationRejected() from error
    if type(envelope) is not dict or set(envelope)!={"payload","decision_id","signature_ref"}:
        raise BatchMigrationRejected()
    return envelope


def _validate_migration_payload_shape(payload):
    if type(payload) is not dict or set(payload)!=_MIGRATION_FIELDS:
        raise BatchMigrationRejected()
    if type(payload.get("schema_version")) is not int or payload["schema_version"]!=1:
        raise BatchMigrationRejected()
    integer_fields=("ledger_device","ledger_inode","from_schema_version","to_schema_version")
    if any(type(payload.get(key)) is not int for key in integer_fields):
        raise BatchMigrationRejected()
    string_fields=_MIGRATION_FIELDS-{"schema_version",*integer_fields}
    if any(type(payload.get(key)) is not str for key in string_fields):
        raise BatchMigrationRejected()


def _validate_migration_payload_constraints(payload):
    constraints=(
        payload["purpose"]==MIGRATION_NAMESPACE
        and payload["from_schema_version"]==1
        and payload["to_schema_version"]==2
        and payload["allowed_role"]=="ledger-migrator"
        and payload["ledger_device"]>=0 and payload["ledger_inode"]>=0
        and re.fullmatch(r"[0-9a-f]{32}",payload["ledger_instance_id"]) is not None
        and re.fullmatch(r"[0-9a-f]{32,128}",payload["migration_nonce"]) is not None
        and re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}",payload["owner_key_fingerprint"]) is not None
    )
    if not constraints:
        raise BatchMigrationRejected()


def _validate_migration_payload_fields(payload):
    _validate_migration_payload_shape(payload)
    _validate_migration_payload_constraints(payload)


def _validate_migration_time(payload,now_utc):
    issued=_timestamp(payload["issued_at_utc"])
    expires=_timestamp(payload["expires_at_utc"])
    now=now_utc.astimezone(timezone.utc)
    if issued>=expires or issued>now or now>=expires:
        raise BatchMigrationRejected()


def _resolve_migration_ledger_path(payload):
    path=Path(payload["ledger_path"])
    if not path.is_absolute():
        raise BatchMigrationRejected()
    try:
        if str(path)!=str(path.resolve(strict=True)):
            raise BatchMigrationRejected()
    except OSError as error:
        raise BatchMigrationRejected() from error
    return path


def _verify_migration_ledger(path,payload,allowed_attempt_decision):
    try:
        host_binding=ledger_host_binding(path)
        anchor_identity=read_ledger_anchor(path,host_binding)
        info=path.stat(follow_symlinks=False)
        identity_matches=(
            host_binding==payload["host_binding"]
            and anchor_identity.ledger_instance_id==payload["ledger_instance_id"]
            and anchor_identity.ledger_device==payload["ledger_device"]
            and anchor_identity.ledger_inode==payload["ledger_inode"]
            and info.st_dev==payload["ledger_device"]
            and info.st_ino==payload["ledger_inode"]
        )
        if not identity_matches:
            raise BatchMigrationRejected()
    except (OSError,LedgerError) as error:
        raise BatchMigrationRejected() from error
    marker=f"migration_attempt:{payload['migration_nonce']}"
    try:
        with closing(sqlite3.connect(path.as_uri()+"?mode=ro",uri=True)) as connection:
            schema_version=_ledger_metadata_value(connection,"schema_version")
            if schema_version=="2":
                table=connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='ledger_migration_receipts'"
                ).fetchone()
                receipt=(table is not None and connection.execute(
                    "SELECT 1 FROM ledger_migration_receipts WHERE migration_nonce=?",
                    (payload["migration_nonce"],),
                ).fetchone() is not None)
                if receipt:
                    raise BatchMigrationRejected("BLOCKED_AUTH_REPLAY")
                raise BatchMigrationRejected()
            if schema_version!="1":
                raise BatchMigrationRejected()
            marker_value=connection.execute("SELECT value FROM ledger_meta WHERE key=?",(marker,)).fetchone()
            _validate_migration_attempt_marker(marker_value,allowed_attempt_decision)
    except sqlite3.Error as error:
        raise BatchMigrationRejected() from error
    _schema_version_one(path,host_binding,anchor_identity.ledger_instance_id)


def _validate_migration_attempt_marker(marker_value,allowed_attempt_decision):
    if allowed_attempt_decision is None:
        if marker_value is not None:
            raise BatchMigrationRejected("BLOCKED_AUTH_REPLAY")
        return
    if marker_value!=(allowed_attempt_decision,):
        raise BatchMigrationRejected("BLOCKED_AUTH_REPLAY")


def _verify_migration_owner(payload,envelope,canonical,trust):
    owner_id=payload["owner_principal_id"]
    owner_rows=trust._owners.get(owner_id)
    if owner_rows is None:
        raise BatchMigrationRejected()
    fingerprint=payload["owner_key_fingerprint"]
    owner=owner_rows.get(fingerprint)
    if owner is None or owner.revoked or owner.role!="ledger-migrator":
        raise BatchMigrationRejected()
    try:
        allowed=trust._check_file()
        lines=_select_signer_lines(allowed,owner_id,{fingerprint})
        signature=base64.b64decode(envelope["signature_ref"],validate=True)
        actual_fingerprint=_verify_signature(signature,canonical,owner_id,MIGRATION_NAMESPACE,lines)
    except (ApprovalRejected,ValueError,OSError) as error:
        raise BatchMigrationRejected() from error
    if actual_fingerprint!=fingerprint:
        raise BatchMigrationRejected()


def _verify_payload(
    raw_envelope_json: bytes,
    *,
    trust: OwnerTrust,
    now_utc: datetime,
    allowed_attempt_decision: str | None,
) -> tuple[dict[str, object], bytes, str, Path]:
    envelope=_decode_migration_envelope(raw_envelope_json,trust,now_utc)
    payload=envelope["payload"]
    _validate_migration_payload_fields(payload)
    canonical=canonical_bytes(payload)
    decision_id=sha256(canonical).hexdigest()
    if envelope["decision_id"]!=decision_id or not isinstance(envelope["signature_ref"],str):
        raise BatchMigrationRejected()
    _validate_migration_time(payload,now_utc)
    path=_resolve_migration_ledger_path(payload)
    _verify_migration_ledger(path,payload,allowed_attempt_decision)
    _verify_migration_owner(payload,envelope,canonical,trust)
    return payload,canonical,decision_id,path


def verify_ledger_migration_decision(
    raw_envelope_json: bytes, *, trust: OwnerTrust, now_utc: datetime
) -> VerifiedLedgerMigrationDecision:
    payload, canonical, decision_id, path = _verify_payload(
        raw_envelope_json, trust=trust, now_utc=now_utc,
        allowed_attempt_decision=None,
    )
    return VerifiedLedgerMigrationDecision(
        bytes(raw_envelope_json), canonical, decision_id, payload["migration_nonce"],
        path, payload["host_binding"], payload["ledger_instance_id"],
        payload["owner_principal_id"],
    )


def upgrade_ledger_v1_to_batch_v2(
    path: Path, *, decision: VerifiedLedgerMigrationDecision
) -> None:
    from name_tag_batch_migration_apply import upgrade_ledger_v1_to_batch_v2 as apply_migration

    apply_migration(path, decision=decision)
