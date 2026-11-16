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


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        _reject()
    return dict(value)


def _text(record: Mapping[str, object], key: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value:
        _reject()
    return value


def _validate_resource_arn(
    *, kind: str, resource: str, arn: str, locator: str, evidence: str,
) -> None:
    resource_prefixes = {
        "instance": "instance/", "volume": "volume/", "snapshot": "snapshot/",
        "eni": "network-interface/", "eip": "elastic-ip/", "nat": "natgateway/",
        "endpoint": "vpc-endpoint/", "rds_instance": "db:",
        "opensearch": "domain/", "log_group": "log-group:",
    }
    if kind in resource_prefixes:
        _require_prefix_locator(resource, locator, resource_prefixes[kind])
    elif kind == "rds_cluster":
        _validate_rds_cluster(resource, locator, arn, evidence)
    elif kind == "apigw_stage":
        _validate_apigw_stage(resource, locator, arn)
    else:
        _validate_direct_arn_resource(kind, resource, arn, locator)


def _require_prefix_locator(resource: str, locator: str, prefix: str) -> None:
    if not resource.startswith(prefix) or resource.removeprefix(prefix) != locator:
        _reject()


def _validate_direct_arn_resource(kind: str, resource: str, arn: str, locator: str) -> None:
    expected_prefixes = {
        "elbv2": "loadbalancer/", "cloudfront": "distribution/",
        "athena_workgroup": "workgroup/", "lambda": "function:",
    }
    prefix = expected_prefixes.get(kind)
    if prefix is not None and not resource.startswith(prefix):
        _reject()
    if arn != locator:
        _reject()
    if kind == "wafv2" and re.fullmatch(r"(?:global|regional)/webacl/[^/]+/[^/]+", resource) is None:
        _reject()


def _validate_rds_cluster(resource: str, locator: str, arn: str, evidence: str) -> None:
    prefix = "cluster:"
    if not resource.startswith(prefix):
        _reject()
    arn_identifier = resource.removeprefix(prefix)
    if arn_identifier == locator:
        return
    resource_id = re.search(r"DbClusterResourceId=([A-Za-z0-9-]+)", evidence)
    valid_locator = re.fullmatch(r"cluster-[a-z0-9]{14,}", locator, re.IGNORECASE)
    if (valid_locator is None or resource_id is None
            or resource_id.group(1).casefold() != locator.casefold()
            or f"ARN={arn}" not in evidence):
        _reject()


def _validate_apigw_stage(resource: str, locator: str, arn: str) -> None:
    match = re.fullmatch(r"/restapis/([^/]+)/stages/([^/]+)", resource)
    locator_parts = locator.split("|")
    if (match is None or len(locator_parts) != 3 or locator_parts[2] != arn
            or locator_parts[0] != match.group(1) or locator_parts[1] != match.group(2)):
        _reject()


def _validate_arn_scope(
    *, kind: str, region: str, account: str, arn_region: str, arn_account: str, resource: str,
) -> None:
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
    else:
        _validate_arn_scope(
            kind=kind, region=region, account=account, arn_region=arn_region,
            arn_account=arn_account, resource=resource,
        )
        _validate_resource_arn(
            kind=kind, resource=resource, arn=arn, locator=locator, evidence=evidence,
        )
    return partition


def _plan_record(plan_bytes: bytes, record: Mapping[str, object], plan_digest: str) -> dict[str, object]:
    if record.get("plan_sha256") != plan_digest:
        _reject()
    try:
        plan = _mapping(json.loads(plan_bytes.decode("utf-8", "strict")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _reject()
    if plan.get("schema_version") != 2:
        _reject()
    account = _text(record, "account")
    if re.fullmatch(r"\d{12}", account) is None or plan.get("account") != account:
        _reject()
    proposal_id = _text(record, "proposal_id")
    records = plan.get("records")
    if not isinstance(records, list):
        _reject()
    matches = [_mapping(candidate) for candidate in records
               if isinstance(candidate, Mapping)
               and _mapping(candidate).get("proposal_id") == proposal_id]
    if len(matches) != 1:
        _reject()
    selected_record = matches[0]
    for key in ("kind", "region", "locator", "resource_arn", "status", "confidence",
                "name_state", "proposed_name", "evidence"):
        if record.get(key) != selected_record.get(key):
            _reject()
    return selected_record


def _validate_review_state(record: Mapping[str, object], evidence: str) -> tuple[str, str, str]:
    if record.get("status") != "proposed":
        _reject()
    confidence = _text(record, "confidence")
    if confidence.lower() not in {"high", "medium"}:
        _reject()
    state = record.get("name_state")
    if state == "ABSENT":
        if record.get("name_key_present") is not False or record.get("name_raw_value") is not None:
            _reject()
    elif state == "EMPTY":
        if record.get("name_key_present") is not True or record.get("name_raw_value") != "":
            _reject()
    else:
        _reject()
    evidence_digest = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    if record.get("evidence_digest") != evidence_digest:
        _reject()
    return str(state), confidence, evidence_digest


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
    account = _text(record, "account")
    plan_record = _plan_record(plan_bytes, record, plan_digest)

    kind = _text(record, "kind")
    region = _text(record, "region")
    arn = _text(record, "resource_arn")
    locator = _text(record, "locator")
    evidence = _text(record, "evidence")
    partition = _canonical_arn(
        arn, account=account, region=region, kind=kind, locator=locator, evidence=evidence,
    )
    name_state, confidence, evidence_digest = _validate_review_state(record, evidence)
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
