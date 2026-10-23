"""G2-I1-B D2: offline, synthetic Action/Resource RCP evaluation contract.

Only exact JSON builtin fixtures. No AWS calls, policies, credential handling or
transport. Coverage is NOT IAM Allow/Deny and never closes an unknown writer.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any

MAX_RESOURCES = 64
EXCEPTIONS = frozenset({
    "NONE", "OWNER_UNKNOWN", "MANAGEMENT_RESOURCE",
    "SERVICE_LINKED_ROLE", "AWS_MANAGED_KMS_KEY", "KMS_RETIRE_GRANT",
    "UNSUPPORTED_ACTION_RESOURCE", "UNKNOWN",
})


class ResourceContractError(ValueError):
    """Unsafe or unsupported synthetic evidence input."""


def _plain(value: Any, depth: int = 0) -> bool:
    if depth > 12:
        return False
    if value is None or type(value) in (str, int, bool):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return len(value) <= 128 and all(_plain(v, depth + 1) for v in value)
    if type(value) is dict:
        return len(value) <= 128 and all(
            type(k) is str and _plain(v, depth + 1) for k, v in value.items())
    return False


def _id(value: Any) -> bool:
    return type(value) is str and bool(value) and len(value) <= 256


def _digest(items: object) -> str:
    blob = json.dumps(items, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _source_proof(row: dict[str, Any]) -> bool:
    """Validate only the synthetic official-source record shape."""
    h = row.get("exception_source_sha256")
    return (all(_id(row.get(k)) for k in (
        "exception_evidence_id", "exception_source_url",
        "exception_checked_at_utc"))
        and type(h) is str and len(h) == 64
        and all(c in "0123456789abcdef" for c in h))


def _sar_index(types: list[dict[str, Any]], source: Any
               ) -> tuple[dict[str, dict[str, Any]], bool]:
    result: dict[str, dict[str, Any]] = {}
    valid = bool(types) and _id(source)
    for entry in types:
        if type(entry) is not dict:
            raise ResourceContractError("SAR type must be an object")
        name = entry.get("resource_type")
        if (not _id(name) or name in result
                or entry.get("required_or_optional") not in ("REQUIRED", "OPTIONAL")
                or not _id(entry.get("sar_evidence_id"))):
            valid = False
        if _id(name):
            result[name] = entry
    return result, valid


def _expected_index(expected: list[dict[str, Any]], sar: dict[str, Any],
                    declared: int, source: Any
                    ) -> tuple[dict[tuple[int, str, str], dict[str, Any]], bool]:
    index: dict[tuple[int, str, str], dict[str, Any]] = {}
    seen_resource: set[tuple[str, str]] = set()
    valid = bool(expected) and len(expected) == declared and _id(source)
    for item in expected:
        if type(item) is not dict:
            raise ResourceContractError("Expected resource must be object")
        n, typ, arn = (item.get("resource_index"), item.get("resource_type"),
                       item.get("resource_arn"))
        if type(n) is not int or not (0 <= n < MAX_RESOURCES) or not _id(typ) or not _id(arn):
            valid = False
            continue
        key = (n, typ, arn)
        if (key in index or (typ, arn) in seen_resource
                or not _id(item.get("evidence_id")) or typ not in sar):
            valid = False
        index[key] = item
        seen_resource.add((typ, arn))
    if {k[0] for k in index} != set(range(len(expected))):
        valid = False
    return index, valid


def _unknown(obj: dict[str, Any], eval_id: str) -> dict[str, Any]:
    return {
        "evaluation_id": eval_id,
        "resource_index": obj.get("resource_index"),
        "resource_type": obj.get("resource_type"),
        "resource_arn": obj.get("resource_arn"),
        "resource_owner_account": obj.get("resource_owner_account"),
        "rcp_resource_coverage": "UNKNOWN",
        "rcp_applicable": "UNKNOWN",
        "rcp_exception_code": "UNKNOWN",
        "rcp_exception_evidence_id": None,
        "exception_source_sha256": None,
        "evidence_id": [],
    }


def _decision(obj: dict[str, Any], action: dict[str, Any],
              typ: str, owner: str, code: str) -> tuple[str, str]:
    """A Resource exception never means that the actor is authorized."""
    if code in ("OWNER_UNKNOWN", "UNKNOWN"):
        return "UNKNOWN", "UNKNOWN"
    if code == "MANAGEMENT_RESOURCE":
        if (owner == action.get("management_account_id")
                and _id(action.get("management_account_evidence_id"))
                and _source_proof(obj)):
            return "NOT_COVERED", "EXEMPT"
    elif code == "SERVICE_LINKED_ROLE":
        if (action.get("service_linked_role") is True
                and _id(action.get("service_linked_role_evidence_id"))
                and _source_proof(obj)):
            return "NOT_COVERED", "EXEMPT"
    elif code == "AWS_MANAGED_KMS_KEY":
        if (obj.get("key_manager") == "AWS" and typ == "key"
                and action["action"].startswith("kms:")
                and _id(obj.get("key_manager_evidence_id"))
                and _source_proof(obj)):
            return "NOT_COVERED", "EXEMPT"
    elif code == "KMS_RETIRE_GRANT":
        if action["action"] == "kms:RetireGrant" and _source_proof(obj):
            return "NOT_COVERED", "EXEMPT"
    elif code == "UNSUPPORTED_ACTION_RESOURCE":
        if obj.get("rcp_supported") is False and _source_proof(obj):
            return "NOT_COVERED", "NOT_SUPPORTED"
    elif code == "NONE":
        if (obj.get("rcp_supported") is True
                and _id(obj.get("rcp_support_evidence_id"))
                and action.get("service_linked_role") is False
                and _id(action.get("service_linked_role_evidence_id"))
                and _id(action.get("management_account_id"))
                and _id(action.get("management_account_evidence_id"))
                and owner != action["management_account_id"]):
            return "COVERED", "APPLICABLE"
    return "UNKNOWN", "UNKNOWN"


def _evaluate_resource(
    obj: dict[str, Any], action: dict[str, Any],
    sar: dict[str, dict[str, Any]],
    expected: dict[tuple[int, str, str], dict[str, Any]],
    source_valid: bool,
) -> dict[str, Any]:
    n, typ, arn = obj.get("resource_index"), obj.get("resource_type"), obj.get("resource_arn")
    identity_ok = type(n) is int and _id(typ) and _id(arn)
    eval_id = (_digest((action["actor_id"], action["action"],
                        action["request_fingerprint_sha256"], n, arn, typ))
               if identity_ok else "invalid")
    result = _unknown(obj, eval_id)
    if not identity_ok or not source_valid:
        return result
    match = expected.get((n, typ, arn))
    code = obj.get("exception_code", "NONE")
    if (match is None or typ not in sar
            or not _id(obj.get("sar_evidence_id"))
            or obj["sar_evidence_id"] != sar[typ].get("sar_evidence_id")
            or not _id(obj.get("resource_evidence_id"))
            or obj.get("resource_owner_account") != match.get("resource_owner_account")
            or not _id(obj.get("resource_owner_account"))
            or type(code) is not str or code not in EXCEPTIONS):
        return result
    cov, applies = _decision(obj, action, typ, obj["resource_owner_account"], code)
    if cov == "UNKNOWN":
        return result
    result.update(
        rcp_resource_coverage=cov,
        rcp_applicable=applies,
        rcp_exception_code=code,
        rcp_exception_evidence_id=(obj.get("exception_evidence_id")
                                   if code != "NONE" else None),
        exception_source_sha256=(obj.get("exception_source_sha256")
                                 if code != "NONE" else None),
        evidence_id=[obj["sar_evidence_id"], obj["resource_evidence_id"]],
    )
    return result


def _aggregate(rows: list[dict[str, Any]], complete: bool) -> str:
    if not complete or not rows:
        return "UNKNOWN"
    outcomes = {x["rcp_resource_coverage"] for x in rows}
    if "UNKNOWN" in outcomes:
        return "UNKNOWN"
    if len(outcomes) == 2:
        return "MIXED"
    return next(iter(outcomes))


def evaluate_action(data: dict[str, Any]) -> dict[str, Any]:
    """Evidence-bound synthetic coverage only; writer reachability is UNKNOWN."""
    if type(data) is not dict or not _plain(data):
        raise ResourceContractError("Only bounded builtin JSON fixture objects")
    if any(not _id(data.get(k)) for k in (
            "actor_id", "action", "request_fingerprint_sha256")):
        raise ResourceContractError("Invalid action identity")
    sar_types, expected, observed = (
        data.get("authorized_resource_types"),
        data.get("expected_resources"),
        data.get("resource_evaluations"),
    )
    if (any(type(x) is not list or len(x) > MAX_RESOURCES
            for x in (sar_types, expected, observed))):
        raise ResourceContractError("Invalid resource collection")
    count = data.get("expected_authorized_resource_count")
    if type(count) is not int or not 0 <= count <= MAX_RESOURCES:
        raise ResourceContractError("Invalid expected resource count")
    sar, sar_valid = _sar_index(sar_types, data.get("authorization_reference_evidence_id"))
    expected_index, expected_valid = _expected_index(
        expected, sar, count, data.get("expected_resource_set_evidence_id"))
    rows: list[dict[str, Any]] = []
    seen_keys: set[tuple[int, str, str]] = set()
    seen_resources: set[tuple[str, str]] = set()
    unique = len(observed) == len(expected)
    for obj in observed:
        if type(obj) is not dict:
            raise ResourceContractError("Resource must be exact JSON object")
        n, typ, arn = obj.get("resource_index"), obj.get("resource_type"), obj.get("resource_arn")
        if type(n) is not int or not _id(typ) or not _id(arn):
            unique = False
        else:
            key = (n, typ, arn)
            if key in seen_keys or (typ, arn) in seen_resources:
                unique = False
            seen_keys.add(key)
            seen_resources.add((typ, arn))
        rows.append(_evaluate_resource(
            obj, data, sar, expected_index, sar_valid and expected_valid))
    complete = unique and sar_valid and expected_valid and seen_keys == set(expected_index)
    aggregate = _aggregate(rows, complete)
    return {
        "schema": "g2-d2-rcp-resource-evaluation-1",
        "actor_id": data["actor_id"],
        "action": data["action"],
        "request_fingerprint_sha256": data["request_fingerprint_sha256"],
        "authorization_reference_evidence_id":
            data.get("authorization_reference_evidence_id"),
        "authorized_resource_types": [
            {"resource_type": x.get("resource_type"),
             "required_or_optional": x.get("required_or_optional"),
             "sar_evidence_id": x.get("sar_evidence_id")} for x in sar_types
        ],
        "expected_authorized_resource_count": count,
        "expected_resource_set_evidence_id": data.get("expected_resource_set_evidence_id"),
        "resource_evaluations": rows,
        "aggregate_coverage": aggregate,
        "effective_write_reachability": "UNKNOWN",
        "g2_gate": "NOT_VERIFIED",
        "provenance": "SYNTHETIC_FIXTURE_ONLY",
    }


AWS_EVIDENCE_ACQUISITION = "NOT_EXECUTED"
AWS_WRITES = "BLOCKED"
