"""G2-I1-B D2: synthetic action/resource RCP evidence contract.

Only exact JSON-shaped builtins and static synthetic fixtures are accepted.
No AWS authorization API calls, policies, boto3, credentials or network.
Coverage is NOT a write-permission decision; uncertain writers remain OPEN.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

COVERAGES = frozenset({"COVERED", "NOT_COVERED", "UNKNOWN"})
EXCEPTIONS = frozenset({
    "NONE", "OWNER_UNKNOWN", "MANAGEMENT_RESOURCE",
    "SERVICE_LINKED_ROLE", "AWS_MANAGED_KMS_KEY",
    "KMS_RETIRE_GRANT", "UNSUPPORTED_ACTION_RESOURCE", "UNKNOWN",
})
MAX_RESOURCES = 64


class ResourceContractError(ValueError):
    """Invalid or unsafe synthetic Resource Evaluation input."""


def _plain(value: Any, depth: int = 0) -> bool:
    if depth > 12:
        return False
    if value is None or type(value) in (str, int, float, bool):
        return type(value) is not float or (value == value and abs(value) != float("inf"))
    if type(value) is list:
        return len(value) <= 128 and all(_plain(v, depth + 1) for v in value)
    if type(value) is dict:
        return len(value) <= 128 and all(
            type(k) is str and _plain(v, depth + 1) for k, v in value.items())
    return False


def _id(value: Any) -> bool:
    return type(value) is str and bool(value) and len(value) <= 256


def _canonical(items: object) -> str:
    return json.dumps(items, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False)


def _unknown_row(row: dict[str, Any], key: str, code: str) -> dict[str, Any]:
    return {
        "evaluation_id": key,
        "resource_index": row.get("resource_index"),
        "resource_type": row.get("resource_type"),
        "resource_arn": row.get("resource_arn"),
        "resource_owner_account": row.get("resource_owner_account"),
        "rcp_resource_coverage": "UNKNOWN",
        "rcp_applicable": "UNKNOWN",
        "rcp_exception_code": code,
        "evidence_id": [],
    }


def evaluate_action(data: dict[str, Any]) -> dict[str, Any]:
    """Calculate coverage, never IAM Deny/Allow or writer impossibility.

    Required expected_resources represent the evidence-backed closed set
    derived from a synthetic request binding. Without that set and its source
    evidence, aggregation is UNKNOWN, even if observed result is empty.
    """
    if type(data) is not dict or not _plain(data):
        raise ResourceContractError("Only bounded builtin JSON fixture objects")
    for key in ("actor_id", "action", "request_fingerprint_sha256"):
        if not _id(data.get(key)):
            raise ResourceContractError("Invalid identity or request fingerprint")
    expected = data.get("expected_resources")
    observed = data.get("resource_evaluations")
    sar_types = data.get("authorized_resource_types")
    if (type(expected) is not list or type(observed) is not list
            or type(sar_types) is not list
            or len(expected) > MAX_RESOURCES
            or len(observed) > MAX_RESOURCES
            or len(sar_types) > MAX_RESOURCES):
        raise ResourceContractError("Missing or oversized resource collections")
    declared = data.get("expected_authorized_resource_count")
    if type(declared) is not int or declared < 0 or declared > MAX_RESOURCES:
        raise ResourceContractError("Explicit expected resource count required")

    sar_map: dict[str, dict[str, Any]] = {}
    sar_valid = bool(sar_types) and _id(data.get("authorization_reference_evidence_id"))
    for item in sar_types:
        if type(item) is not dict:
            raise ResourceContractError("SAR type must be an object")
        typ = item.get("resource_type")
        if (not _id(typ) or typ in sar_map
                or item.get("required_or_optional") not in ("REQUIRED", "OPTIONAL")
                or not _id(item.get("sar_evidence_id"))):
            sar_valid = False
        if _id(typ):
            sar_map[typ] = item

    expected_lookup: dict[tuple[int, str, str], dict[str, Any]] = {}
    expected_valid = (bool(expected) and declared == len(expected)
                      and _id(data.get("expected_resource_set_evidence_id")))
    seen_resources: set[tuple[str, str]] = set()
    for e in expected:
        if type(e) is not dict:
            raise ResourceContractError("Expected resource must be object")
        i, typ, arn = (e.get("resource_index"), e.get("resource_type"),
                       e.get("resource_arn"))
        if (type(i) is not int or i < 0 or i >= MAX_RESOURCES
                or not _id(typ) or not _id(arn)):
            expected_valid = False
            continue
        key = (i, typ, arn)
        if (key in expected_lookup or (typ, arn) in seen_resources
                or not _id(e.get("evidence_id"))
                or typ not in sar_map):
            expected_valid = False
        expected_lookup[key] = e
        seen_resources.add((typ, arn))
    if {x[0] for x in expected_lookup} != set(range(len(expected))):
        expected_valid = False

    rows: list[dict[str, Any]] = []
    seen_obs: set[tuple[int, str, str]] = set()
    seen_arn_type: set[tuple[str, str]] = set()
    observed_valid = len(observed) == len(expected)
    for obj in observed:
        if type(obj) is not dict:
            raise ResourceContractError("Observed resource must be object")
        index = obj.get("resource_index")
        typ = obj.get("resource_type")
        arn = obj.get("resource_arn")
        key_tuple = (index, typ, arn)
        if not (type(index) is int and _id(typ) and _id(arn)):
            observed_valid = False
            key_string = "invalid"
        else:
            key_string = hashlib.sha256(_canonical((
                data["actor_id"], data["action"],
                data["request_fingerprint_sha256"], index, arn, typ
            )).encode("utf-8")).hexdigest()
            if key_tuple in seen_obs or (typ, arn) in seen_arn_type:
                observed_valid = False
            seen_obs.add(key_tuple)
            seen_arn_type.add((typ, arn))
        row = _unknown_row(obj, key_string, "UNKNOWN")
        match = (expected_lookup.get(key_tuple)
                 if type(index) is int and _id(typ) and _id(arn) else None)
        official_id = obj.get("exception_evidence_id")
        exception = obj.get("exception_code", "NONE")
        resource_owner = obj.get("resource_owner_account")
        if (match is None or not sar_valid or not expected_valid
                or not _id(obj.get("sar_evidence_id"))
                or not _id(typ)
                or obj.get("sar_evidence_id") != sar_map.get(typ, {}).get("sar_evidence_id")
                or obj.get("resource_owner_account") != match.get("resource_owner_account")
                or not _id(obj.get("resource_evidence_id"))
                or not _id(resource_owner)
                or type(exception) is not str or exception not in EXCEPTIONS):
            rows.append(row)
            continue
        # Unknown exception evidence never proves absence of RCP.
        if exception in ("OWNER_UNKNOWN", "UNKNOWN"):
            rows.append(row)
            continue

        cov = "UNKNOWN"
        applicable = "UNKNOWN"
        if exception == "MANAGEMENT_RESOURCE":
            if (resource_owner == data.get("management_account_id")
                    and _id(data.get("management_account_evidence_id"))
                    and _id(official_id)):
                cov, applicable = "NOT_COVERED", "EXEMPT"
        elif exception == "SERVICE_LINKED_ROLE":
            if (data.get("service_linked_role") is True
                    and _id(data.get("service_linked_role_evidence_id"))
                    and _id(official_id)):
                cov, applicable = "NOT_COVERED", "EXEMPT"
        elif exception == "AWS_MANAGED_KMS_KEY":
            if (obj.get("key_manager") == "AWS"
                    and _id(obj.get("key_manager_evidence_id"))
                    and _id(official_id)
                    and typ.startswith("key")):
                cov, applicable = "NOT_COVERED", "EXEMPT"
        elif exception == "KMS_RETIRE_GRANT":
            if data["action"] == "kms:RetireGrant" and _id(official_id):
                cov, applicable = "NOT_COVERED", "EXEMPT"
        elif exception == "UNSUPPORTED_ACTION_RESOURCE":
            if (obj.get("rcp_supported") is False and _id(official_id)):
                cov, applicable = "NOT_COVERED", "NOT_SUPPORTED"
        elif exception == "NONE":
            if (obj.get("rcp_supported") is True
                    and _id(obj.get("rcp_support_evidence_id"))
                    and data.get("service_linked_role") is False
                    and _id(data.get("service_linked_role_evidence_id"))
                    and _id(data.get("management_account_id"))
                    and _id(data.get("management_account_evidence_id"))
                    and resource_owner != data["management_account_id"]):
                cov, applicable = "COVERED", "APPLICABLE"
        row.update(rcp_resource_coverage=cov, rcp_applicable=applicable,
                   rcp_exception_code=exception if cov != "UNKNOWN" else "UNKNOWN",
                   evidence_id=[obj["sar_evidence_id"], obj["resource_evidence_id"]]
                   if cov != "UNKNOWN" else [])
        rows.append(row)

    if (not observed_valid or not expected_valid or not sar_valid
            or seen_obs != set(expected_lookup)
            or any(x["rcp_resource_coverage"] == "UNKNOWN" for x in rows)):
        aggregate = "UNKNOWN"
    else:
        coverages = {x["rcp_resource_coverage"] for x in rows}
        aggregate = ("MIXED" if len(coverages) > 1 else next(iter(coverages)))
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
             "sar_evidence_id": x.get("sar_evidence_id")}
            for x in sar_types
        ],
        "expected_authorized_resource_count": declared,
        "expected_resource_set_evidence_id": data.get("expected_resource_set_evidence_id"),
        "resource_evaluations": rows,
        "aggregate_coverage": aggregate,
        "effective_write_reachability": "UNKNOWN",
        "g2_gate": "NOT_VERIFIED",
        "provenance": "SYNTHETIC_FIXTURE_ONLY",
    }


AWS_EVIDENCE_ACQUISITION = "NOT_EXECUTED"
AWS_WRITES = "BLOCKED"
