"""Prepare unsigned, plan-bound Name approval payloads offline."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import NoReturn

from name_tag_approval import ApprovalRejected, NAMESPACES, canonical_payload


def _reject(code: str = "BLOCKED_NAME_REVIEW") -> NoReturn:
    raise ApprovalRejected(code)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _reject()
    return value


def _text(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        _reject()
    return value


def _canonical_arn(
    arn: str, *, account: str, region: str, kind: str, locator: str, evidence: str,
) -> str:
    services = {
        "instance": "ec2", "volume": "ec2", "snapshot": "ec2", "eni": "ec2",
        "eip": "ec2", "nat": "ec2", "endpoint": "ec2",
        "rds_instance": "rds", "rds_cluster": "rds", "opensearch": "es",
        "elbv2": "elasticloadbalancing", "apigw_stage": "apigateway",
        "cloudfront": "cloudfront", "athena_workgroup": "athena",
        "log_group": "logs", "lambda": "lambda", "wafv2": "wafv2",
        "s3_bucket": "s3",
    }
    service = services.get(kind)
    if service is None:
        _reject("UNSUPPORTED_KIND_FOR_REVIEW")
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2] or not parts[5]:
        _reject()
    _, partition, arn_service, arn_region, arn_account, resource = parts
    if partition not in {"aws", "aws-cn", "aws-us-gov"} or arn_service != service:
        _reject()

    if kind == "s3_bucket":
        if arn_account or "/" in resource or ":" in resource or not resource or resource != locator:
            _reject()
        if arn_region and arn_region != region:
            _reject()
        return partition

    if kind == "apigw_stage":
        if arn_account:
            _reject()
    elif arn_account != account:
        _reject()
    global_region = kind == "cloudfront" or (kind == "wafv2" and resource.startswith("global/"))
    if global_region:
        if region != "us-east-1" or arn_region not in {"", "us-east-1"}:
            _reject()
    elif arn_region != region:
        _reject()

    resource_ids = {
        "instance": ("instance/",), "volume": ("volume/",),
        "snapshot": ("snapshot/",), "eni": ("network-interface/",),
        "eip": ("elastic-ip/",), "nat": ("natgateway/",),
        "endpoint": ("vpc-endpoint/",),
        "rds_instance": ("db:",),
        "opensearch": ("domain/",), "log_group": ("log-group:",),
    }
    if kind in resource_ids:
        prefix = resource_ids[kind][0]
        if not resource.startswith(prefix) or resource[len(prefix):] != locator:
            _reject()
    elif kind == "rds_cluster":
        prefix = "cluster:"
        if not resource.startswith(prefix):
            _reject()
        arn_identifier = resource[len(prefix):]
        if arn_identifier != locator:
            if re.fullmatch(r"cluster-[a-z0-9]{14,}", locator, re.IGNORECASE) is None:
                _reject()
            resource_id = re.search(r"DbClusterResourceId=([A-Za-z0-9-]+)", evidence)
            if (resource_id is None or resource_id.group(1).casefold() != locator.casefold()
                    or f"ARN={arn}" not in evidence):
                _reject()
    elif kind == "elbv2":
        if not resource.startswith("loadbalancer/") or arn != locator:
            _reject()
    elif kind == "apigw_stage":
        match = re.fullmatch(r"/restapis/([^/]+)/stages/([^/]+)", resource)
        locator_parts = locator.split("|")
        if (match is None or len(locator_parts) != 3 or locator_parts[2] != arn
                or locator_parts[0] != match.group(1) or locator_parts[1] != match.group(2)):
            _reject()
    elif kind == "cloudfront":
        if not resource.startswith("distribution/") or arn != locator:
            _reject()
    elif kind in {"athena_workgroup", "lambda", "wafv2"}:
        expected_prefix = {"athena_workgroup": "workgroup/", "lambda": "function:"}.get(kind)
        if (expected_prefix is not None and not resource.startswith(expected_prefix)) or arn != locator:
            _reject()
        if kind == "wafv2" and re.fullmatch(r"(?:global|regional)/webacl/[^/]+/[^/]+", resource) is None:
            _reject()
    return partition


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
    evidence = _text(record, "evidence")
    partition = _canonical_arn(
        arn, account=account, region=region, kind=kind, locator=locator, evidence=evidence,
    )
    if record.get("status") != "proposed":
        _reject()
    confidence = _text(record, "confidence")
    if confidence.lower() not in {"high", "medium"}:
        _reject()
    name_state = record.get("name_state")
    if name_state not in {"ABSENT", "EMPTY"}:
        _reject()
    if name_state == "ABSENT" and (
        record.get("name_key_present") is not False or record.get("name_raw_value") is not None
    ):
        _reject()
    if name_state == "EMPTY" and (record.get("name_key_present") is not True or record.get("name_raw_value") != ""):
        _reject()
    evidence_digest = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    if record.get("evidence_digest") != evidence_digest:
        _reject()
    suggested_name = _text(record, "proposed_name")
    if not approved_name.strip():
        _reject()
    if approved_name != suggested_name and not edit_reason.strip():
        _reject()

    payload: dict[str, object] = {
        "schema_version": 1,
        "approval_namespace": NAMESPACES["name"],
        "plan_sha256": plan_digest,
        "account": account,
        "partition": partition,
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
        "decision": "APPROVED",
        "owner_decision_reference": "",
        "owner_principal_id": owner_principal_id,
        "owner_key_fingerprint": owner_key_fingerprint,
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
        "decision_nonce": decision_nonce,
    }
    canonical_payload(payload, kind="name")
    return payload
