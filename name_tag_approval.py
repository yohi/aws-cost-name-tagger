"""Canonical and authenticated Owner approval envelopes.

The canonicalizer intentionally supports a restricted JSON subset rather than
claiming a complete RFC 8785 implementation.  It is deterministic, sorts keys,
escapes strings per JSON, and rejects floats, unpaired surrogates, duplicate
keys, unknown fields and mixed types.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Mapping

Kind = Literal["name", "execution"]

NAMESPACES: dict[Kind, str] = {
    "name": "aws-cost-name-tagger-name-approval-v1",
    "execution": "aws-cost-name-tagger-execution-v1",
}

# Field allowlists mirror the Design R0.2.1 payload contracts.
NAME_PAYLOAD_FIELDS: frozenset[str] = frozenset({
    "schema_version",
    "approval_namespace",
    "plan_sha256",
    "account",
    "partition",
    "region",
    "kind",
    "resource_arn",
    "locator",
    "name_state_at_plan",
    "confidence",
    "evidence_digest",
    "suggested_name",
    "approved_name",
    "edit_reason",
    "decision",
    "owner_decision_reference",
    "owner_principal_id",
    "owner_key_fingerprint",
    "issued_at_utc",
    "expires_at_utc",
    "decision_nonce",
})

EXECUTION_PAYLOAD_FIELDS: frozenset[str] = frozenset({
    "schema_version",
    "authorization_namespace",
    "name_approval_id",
    "resource_arn",
    "approved_name",
    "aws_operation",
    "account",
    "partition",
    "region",
    "identity",
    "code_version",
    "code_hash",
    "writer_control_scope_id",
    "risk_acknowledgement",
    "writer_control_evidence_refs",
    "side_effect_evidence_refs",
    "owner_principal_id",
    "owner_key_fingerprint",
    "allowed_role",
    "issued_at_utc",
    "expires_at_utc",
    "execution_nonce",
})

PAYLOAD_FIELDS: dict[Kind, frozenset[str]] = {
    "name": NAME_PAYLOAD_FIELDS,
    "execution": EXECUTION_PAYLOAD_FIELDS,
}

ENVELOPE_FIELDS: dict[Kind, frozenset[str]] = {
    "name": frozenset({"payload", "approval_id", "signature_ref"}),
    "execution": frozenset({"payload", "authorization_id", "signature_ref"}),
}

CONTENT_ID_KEYS: dict[Kind, str] = {
    "name": "approval_id",
    "execution": "authorization_id",
}
# Type schema for each payload field.  All fields are strings except schema_version.
# Evidence refs are typed as ordered lists of strings.
PayloadType = Literal["str", "int", "list_str"]
PAYLOAD_TYPES: dict[Kind, dict[str, PayloadType]] = {
    "name": {
        "schema_version": "int",
        "approval_namespace": "str",
        "plan_sha256": "str",
        "account": "str",
        "partition": "str",
        "region": "str",
        "kind": "str",
        "resource_arn": "str",
        "locator": "str",
        "name_state_at_plan": "str",
        "confidence": "str",
        "evidence_digest": "str",
        "suggested_name": "str",
        "approved_name": "str",
        "edit_reason": "str",
        "decision": "str",
        "owner_decision_reference": "str",
        "owner_principal_id": "str",
        "owner_key_fingerprint": "str",
        "issued_at_utc": "str",
        "expires_at_utc": "str",
        "decision_nonce": "str",
    },
    "execution": {
        "schema_version": "int",
        "authorization_namespace": "str",
        "name_approval_id": "str",
        "resource_arn": "str",
        "approved_name": "str",
        "aws_operation": "str",
        "account": "str",
        "partition": "str",
        "region": "str",
        "identity": "str",
        "code_version": "str",
        "code_hash": "str",
        "writer_control_scope_id": "str",
        "risk_acknowledgement": "str",
        "writer_control_evidence_refs": "list_str",
        "side_effect_evidence_refs": "list_str",
        "owner_principal_id": "str",
        "owner_key_fingerprint": "str",
        "allowed_role": "str",
        "issued_at_utc": "str",
        "expires_at_utc": "str",
        "execution_nonce": "str",
    },
}


class ApprovalRejected(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class EnrolledOwner:
    fingerprint: str
    role: str
    revoked: bool = False


class OwnerTrust:
    """Pinned, protected Owner trust anchor.

    Constructed exclusively from a protected `allowed_signers` file and an
    enrolled Owner ID / fingerprint / allowed role mapping.  The executing user
    must not choose or write the trusted keys at call time.
    """

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    @classmethod
    def from_allowed_signers(
        cls,
        path: str | os.PathLike[str],
        *,
        pinned_sha256: str,
        enrolled: Mapping[str, Mapping[str, EnrolledOwner]],
        expected_uid: int | None = None,
    ) -> OwnerTrust:
        file_path = Path(path)
        expected_uid = os.geteuid() if expected_uid is None else expected_uid
        try:
            info = file_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
            if info.st_mode & 0o022:
                raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
            if info.st_uid != expected_uid:
                raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
            data = file_path.read_bytes()
        except (OSError, ApprovalRejected):
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None

        if hashlib.sha256(data).hexdigest().lower() != pinned_sha256.lower():
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

        instance = object.__new__(cls)
        object.__setattr__(instance, "_path", file_path)
        object.__setattr__(instance, "_data_hash", pinned_sha256.lower())
        object.__setattr__(instance, "_expected_uid", expected_uid)
        object.__setattr__(instance, "_owners", MappingProxyType({
            owner: MappingProxyType(dict(keys))
            for owner, keys in enrolled.items()
        }))
        return instance

    def _check_file(self) -> None:
        try:
            info = self._path.stat(follow_symlinks=False)
            data = self._path.read_bytes()
        except OSError:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        if info.st_uid != self._expected_uid:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        if hashlib.sha256(data).hexdigest() != self._data_hash:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        result[key] = value
    return result


def _parse_json(raw: bytes) -> object:
    try:
        text = bytes(raw).decode("utf-8", "strict")
        return json.loads(
            text,
            object_pairs_hook=_reject_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ApprovalRejected("BLOCKED_OWNER_AUTHN")),
        )
    except ApprovalRejected:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None


def _validate_ascii_field_name(key: str) -> None:
    if not isinstance(key, str) or not key.isascii() or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")


def _validate_value(value: object) -> None:
    if value is None or type(value) in (bool, int):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None
        return
    if isinstance(value, list):
        for item in value:
            _validate_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_ascii_field_name(key)
            _validate_value(item)
        return
    raise ApprovalRejected("BLOCKED_OWNER_AUTHN")


def _canonical(value: object) -> str:
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
        return "[" + ",".join(_canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            _canonical(key) + ":" + _canonical(value[key]) for key in sorted(value)
        ) + "}"
    raise ApprovalRejected("BLOCKED_OWNER_AUTHN")


def canonical_payload(payload: Mapping[str, object], *, kind: Kind) -> bytes:
    if kind not in PAYLOAD_FIELDS or not isinstance(payload, Mapping):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    copied: dict[str, object] = dict(payload)
    required = PAYLOAD_FIELDS[kind]
    if set(copied) != required:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    namespace_key = "approval_namespace" if kind == "name" else "authorization_namespace"
    if copied.get(namespace_key) != NAMESPACES[kind]:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    types = PAYLOAD_TYPES[kind]
    for key, value in copied.items():
        _validate_ascii_field_name(key)
        expected = types[key]
        if expected == "int":
            if type(value) is not int or value != 1:
                raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        elif expected == "str":
            if not isinstance(value, str):
                raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        elif expected == "list_str":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    _validate_value(copied)
    return _canonical(copied).encode("utf-8")


def approval_digest(canonical_bytes: bytes) -> str:
    if not isinstance(canonical_bytes, bytes):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    return hashlib.sha256(canonical_bytes).hexdigest()


def _freeze(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class VerifiedEnvelope:
    kind: Kind
    raw_envelope_bytes: bytes
    canonical_payload_bytes: bytes
    content_id: str
    payload: Mapping[str, object]
    owner_principal_id: str
    signature_ref: str


def _fingerprint_for_key_line(key_line: str) -> str | None:
    """Return SHA256 fingerprint for a single OpenSSH public key line."""
    parts = key_line.split()
    if len(parts) < 2:
        return None
    with tempfile.TemporaryDirectory() as directory:
        key_path = Path(directory) / "key.pub"
        key_path.write_text(" ".join(parts[-2:]) + "\n", encoding="ascii")
        result = subprocess.run(
            ["ssh-keygen", "-lf", str(key_path), "-E", "sha256"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode != 0:
            return None
        return result.stdout.split()[1]


def _select_signer_lines(
    trust: OwnerTrust, owner_id: str, eligible_fingerprints: set[str]
) -> list[str]:
    """Return allowed_signers lines matching owner and enrolled fingerprints."""
    try:
        lines = trust._path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None

    selected: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # OpenSSH allowed_signers format: identity [options] keytype base64-key
        # The identity field may be a comma-separated list.
        parts = stripped.split()
        if len(parts) < 3:
            continue
        # Find the key type marker (starts with ssh- or sk- or ecdsa- etc.)
        key_index = None
        for idx, part in enumerate(parts):
            if part.startswith(("ssh-", "ecdsa-", "sk-")):
                key_index = idx
                break
        if key_index is None or key_index < 1:
            continue
        identities = parts[0].split(",")
        if owner_id not in identities:
            continue
        fp = _fingerprint_for_key_line(stripped)
        if fp in eligible_fingerprints:
            selected.append(stripped)
    return selected


def _try_verify(
    signature: bytes,
    message: bytes,
    owner_id: str,
    namespace: str,
    signer_line: str,
) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        sig_path = Path(directory) / "signature"
        signer_path = Path(directory) / "allowed_signers"
        sig_path.write_bytes(signature)
        signer_path.write_text(signer_line + "\n", encoding="utf-8")
        signer_path.chmod(0o600)
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(signer_path), "-I", owner_id,
             "-n", namespace, "-s", str(sig_path)],
            input=message,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    return result.returncode == 0


def _verify_signature(
    signature: bytes,
    message: bytes,
    owner_id: str,
    namespace: str,
    trust: OwnerTrust,
    candidate_lines: list[str],
) -> str:
    """Try candidate signer lines one at a time; return the verifying fingerprint."""
    trust._check_file()
    if not candidate_lines:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    last_error: ApprovalRejected | None = None
    for line in candidate_lines:
        fp = _fingerprint_for_key_line(line)
        if fp is None:
            continue
        if _try_verify(signature, message, owner_id, namespace, line):
            return fp
    raise ApprovalRejected("BLOCKED_OWNER_AUTHN")


def _parse_iso_utc(text: str) -> datetime:
    try:
        value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from exc
    if value.tzinfo is None:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    return value.astimezone(timezone.utc)


def verify_envelope(
    raw_envelope_json: bytes, *, kind: Kind, trust: OwnerTrust, now_utc: datetime
) -> VerifiedEnvelope:
    if kind not in NAMESPACES or not isinstance(trust, OwnerTrust):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    if now_utc.tzinfo is None:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    envelope = _parse_json(raw_envelope_json)
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS[kind]:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    id_key = CONTENT_ID_KEYS[kind]
    content_id = envelope.get(id_key)
    signature_ref = envelope.get("signature_ref")
    payload = envelope.get("payload")
    if not all(isinstance(value, str) for value in (content_id, signature_ref)) or not isinstance(payload, dict):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    if not re.fullmatch(r"[0-9a-f]{64}", content_id):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    namespace = NAMESPACES[kind]
    try:
        canonical = canonical_payload(payload, kind=kind)
        computed_id = approval_digest(canonical)
        if computed_id != content_id:
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        signature = base64.b64decode(signature_ref, validate=True)
    except (ValueError, TypeError):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None

    owner_id = payload.get("owner_principal_id")
    if not isinstance(owner_id, str):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    expected_role: str | None = None
    if kind == "execution":
        expected_role = payload.get("allowed_role")
        if not isinstance(expected_role, str):
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    expires_at = payload.get("expires_at_utc")
    if not isinstance(expires_at, str):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    try:
        expiry = _parse_iso_utc(expires_at)
    except ApprovalRejected:
        raise
    if expiry <= now_utc.astimezone(timezone.utc):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    entries = trust._owners.get(owner_id, {})
    if not entries:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    candidate_lines = _select_signer_lines(trust, owner_id, set(entries))
    verifying_fingerprint = _verify_signature(
        signature, canonical, owner_id, namespace, trust, candidate_lines,
    )

    entry = entries.get(verifying_fingerprint)
    if entry is None or entry.revoked:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    if expected_role is not None and entry.role != expected_role:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
    if payload.get("owner_key_fingerprint") != verifying_fingerprint:
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN")

    return VerifiedEnvelope(
        kind,
        bytes(raw_envelope_json),
        bytes(canonical),
        content_id,
        _freeze(payload),
        owner_id,
        signature_ref,
    )


def revalidate_verified_envelope(
    verified: VerifiedEnvelope, *, kind: Kind, trust: OwnerTrust, now_utc: datetime
) -> VerifiedEnvelope:
    try:
        fresh = verify_envelope(bytes(verified.raw_envelope_bytes), kind=kind, trust=trust, now_utc=now_utc)
        if (
            fresh.kind != verified.kind
            or fresh.owner_principal_id != verified.owner_principal_id
            or fresh.canonical_payload_bytes != bytes(verified.canonical_payload_bytes)
            or fresh.content_id != verified.content_id
            or fresh.signature_ref != verified.signature_ref
        ):
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        thawed_payload = _thaw(verified.payload)
        if _canonical(thawed_payload).encode("utf-8") != bytes(verified.canonical_payload_bytes):
            raise ApprovalRejected("BLOCKED_OWNER_AUTHN")
        return fresh
    except (AttributeError, TypeError, ValueError, ApprovalRejected):
        raise ApprovalRejected("BLOCKED_OWNER_AUTHN") from None
