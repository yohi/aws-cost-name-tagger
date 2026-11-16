"""Prepare unsigned, plan-bound Name approval payloads offline."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import NoReturn

from name_tag_approval import ApprovalRejected, NAMESPACES, canonical_payload


def _reject() -> NoReturn:
    raise ApprovalRejected("BLOCKED_NAME_REVIEW")


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _reject()
    return value


def _text(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        _reject()
    return value


def _canonical_arn(arn: str, *, account: str, region: str, kind: str) -> None:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
        _reject()
    _, partition, service, arn_region, arn_account, resource = parts
    if service == "s3":
        if kind != "s3_bucket" or arn_region or arn_account or ":" in resource or not resource:
            _reject()
        return
    if arn_account != account or arn_region != region:
        _reject()
    if partition not in {"aws", "aws-cn", "aws-us-gov"}:
        _reject()


def prepare_name_payload(
    plan_bytes: bytes,
    record: Mapping[str, object],
    *,
    approved_name: str,
    edit_reason: str,
    owner_principal_id: str,
    owner_key_fingerprint: str,
    issued_at_utc: str,
    expires_at_utc: str,
    decision_nonce: str,
) -> dict[str, object]:
    """Build the unsigned Name payload for an Owner to sign out of band."""
    plan_digest = hashlib.sha256(plan_bytes).hexdigest()
    if record.get("plan_sha256") != plan_digest:
        _reject()
    try:
        parsed: object = json.loads(plan_bytes.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _reject()
    plan = _mapping(parsed)
    if plan.get("schema_version") != 2:
        _reject()

    account = _text(record, "account")
    if not re.fullmatch(r"[0-9]{12}", account) or plan.get("account") != account:
        _reject()
    proposal_id = _text(record, "proposal_id")
    records_value = plan.get("records")
    if not isinstance(records_value, list):
        _reject()
    records: list[object] = records_value
    matches = [row for candidate in records
               if isinstance(candidate, Mapping)
               for row in [_mapping(candidate)]
               if row.get("proposal_id") == proposal_id]
    if len(matches) != 1:
        _reject()
    plan_record = _mapping(matches[0])
    for key in ("kind", "region", "locator", "resource_arn", "status", "confidence", "name_state", "proposed_name", "evidence"):
        if record.get(key) != plan_record.get(key):
            _reject()

    kind = _text(record, "kind")
    region = _text(record, "region")
    arn = _text(record, "resource_arn")
    locator = _text(record, "locator")
    _canonical_arn(arn, account=account, region=region, kind=kind)
    if record.get("status") != "proposed":
        _reject()
    confidence = _text(record, "confidence")
    if confidence.lower() not in {"high", "medium"}:
        _reject()
    name_state = record.get("name_state")
    if name_state not in {"ABSENT", "EMPTY"}:
        _reject()
    if name_state == "ABSENT" and record.get("name_key_present") is True:
        _reject()
    if name_state == "EMPTY" and (record.get("name_key_present") is not True or record.get("name_raw_value") != ""):
        _reject()
    evidence = _text(record, "evidence")
    evidence_digest = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    if record.get("evidence_digest") != evidence_digest:
        _reject()
    suggested_name = _text(record, "proposed_name")
    if not approved_name:
        _reject()
    if approved_name != suggested_name and not edit_reason.strip():
        _reject()

    payload: dict[str, object] = {
        "schema_version": 1,
        "approval_namespace": NAMESPACES["name"],
        "plan_sha256": plan_digest,
        "account": account,
        "partition": arn.split(":", 2)[1],
        "region": region,
        "kind": kind,
        "resource_arn": arn,
        "locator": locator,
        "name_state_at_plan": name_state,
        "confidence": confidence,
        "evidence_digest": evidence_digest,
        "suggested_name": suggested_name,
        "approved_name": approved_name,
        "edit_reason": edit_reason,
        "decision": "approve",
        "owner_decision_reference": proposal_id,
        "owner_principal_id": owner_principal_id,
        "owner_key_fingerprint": owner_key_fingerprint,
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
        "decision_nonce": decision_nonce,
    }
    canonical_payload(payload, kind="name")
    return payload
