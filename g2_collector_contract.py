"""G2-I1 mock-only collector contract: no AWS imports, sockets, or real adapter.

This is an executable *simulation* of a limited read-only acquisition plan.
It produces neither AWS evidence nor an I0 import authorization.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

from g2_evidence import inspect_json

ACCOUNT = re.compile(r"[0-9]{12}\Z")
REGION = re.compile(r"[a-z]{2}-[a-z]+-[0-9]\Z")
ALLOWED_OPERATIONS = frozenset({
    ("sts", "GetCallerIdentity"),
    ("iam", "GetAccountAuthorizationDetails"),
    ("organizations", "DescribeOrganization"),
    ("organizations", "ListParents"),
    ("organizations", "ListPoliciesForTarget"),
    ("sso-admin", "ListInstances"),
    ("cloudtrail", "ListTrails"),
    ("cloudtrail", "LookupEvents"),
    ("cloudtrail", "ListEventDataStores"),
})
MAX_PAGES = 4
MAX_PAGE_BYTES = 1_000_000
MAX_REGIONS = 8


class ContractError(ValueError):
    """Untrusted fixture or acquisition contract violation."""


class FixtureAccessDenied(Exception):
    """Synthetic access-denied response; never a real AWS exception."""


class FixtureFailure(Exception):
    """Synthetic API failure; never a real AWS exception."""


@dataclass(frozen=True)
class Probe:
    label: str
    evidence_id: str
    source: str
    service: str
    operation: str
    region: str
    arguments: dict[str, Any]
    pagination: str = "single"

    def __post_init__(self) -> None:
        if ((self.service, self.operation) not in ALLOWED_OPERATIONS
                or self.pagination not in {"single", "marker", "token"}
                or not isinstance(self.arguments, dict)):
            raise ContractError("Non-allowlisted read operation or pagination")


def _time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ContractError("Event window must be a UTC string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ContractError("Invalid UTC event window") from exc
    if dt.utcoffset() != timezone.utc.utcoffset(None):
        raise ContractError("Event window must be UTC")
    return dt


def build_plan(account: str, regions: tuple[str, ...],
               start_utc: str, end_utc: str, as_of_utc: str) -> tuple[Probe, ...]:
    """Build explicit bounded read-only probes; never infer region coverage."""
    if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
        raise ContractError("Invalid account")
    if (not regions or len(regions) > MAX_REGIONS or len(set(regions)) != len(regions)
            or any(not isinstance(r, str) or not REGION.fullmatch(r) for r in regions)):
        raise ContractError("Explicit distinct AWS regions required")
    start, end, as_of = _time(start_utc), _time(end_utc), _time(as_of_utc)
    if (not start < end or start < as_of - timedelta(days=90)
            or end > as_of):
        raise ContractError("Event History window must be within the 90 days before as_of_utc")
    queries = [
        Probe("iam_authorization", "G2-A01", "IAM", "iam",
              "GetAccountAuthorizationDetails", "global",
              {"Filter": ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]},
              "marker"),
        Probe("organization", "G2-A03", "ORGANIZATIONS", "organizations",
              "DescribeOrganization", "global", {}),
        Probe("organization_parent_direct", "G2-A03", "ORGANIZATIONS",
              "organizations", "ListParents", "global", {"ChildId": account}, "token"),
    ]
    for kind in ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"):
        queries.append(Probe("account_direct_" + kind.lower(), "G2-A03",
                             "ORGANIZATIONS", "organizations", "ListPoliciesForTarget",
                             "global", {"TargetId": account, "Filter": kind}, "token"))
    for region in regions:
        queries.extend([
            Probe("identity_center_instances_" + region, "G2-A02a",
                  "IDENTITY_CENTER", "sso-admin", "ListInstances", region, {}, "token"),
            Probe("trails_" + region, "G2-A05", "TRAIL_S3",
                  "cloudtrail", "ListTrails", region, {}, "token"),
            Probe("event_history_" + region, "G2-A05", "EVENT_HISTORY",
                  "cloudtrail", "LookupEvents", region,
                  {"StartTime": start_utc, "EndTime": end_utc}, "token"),
            Probe("lake_datastores_" + region, "G2-A05", "CLOUDTRAIL_LAKE",
                  "cloudtrail", "ListEventDataStores", region, {}, "token"),
        ])
    return tuple(queries)


def fixture_key(service: str, operation: str, region: str,
                arguments: dict[str, Any]) -> tuple[str, str, str, str]:
    """Exact request identity, including Filter, time window, and pagination token."""
    if (service, operation) not in ALLOWED_OPERATIONS or not isinstance(arguments, dict):
        raise ContractError("Not an allowed synthetic read request")
    try:
        serialized = json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ContractError("Malformed fixture request") from exc
    return service, operation, region, serialized


class FixturePort:
    """No network capability. Fixture responses are matched on the *full* request."""

    def __init__(self, responses: dict[tuple[str, str, str, str], list[object]]) -> None:
        self._responses = copy.deepcopy(responses)
        self.calls: list[tuple[str, str, str, dict[str, Any]]] = []

    def call(self, service: str, operation: str, region: str,
             arguments: dict[str, Any]) -> dict[str, Any]:
        key = fixture_key(service, operation, region, arguments)
        self.calls.append((service, operation, region, copy.deepcopy(arguments)))
        queue = self._responses.get(key, [])
        if not queue:
            raise FixtureFailure("No fixture for exact request arguments or token")
        item = queue.pop(0)
        if isinstance(item, (FixtureFailure, FixtureAccessDenied)):
            raise item
        if not isinstance(item, dict):
            raise ContractError("Fixture response must be an object")
        return copy.deepcopy(item)


COLLECTIONS = {
    ("organizations", "ListParents"): "Parents",
    ("organizations", "ListPoliciesForTarget"): "Policies",
    ("sso-admin", "ListInstances"): "Instances",
    ("cloudtrail", "ListTrails"): "Trails",
    ("cloudtrail", "LookupEvents"): "Events",
    ("cloudtrail", "ListEventDataStores"): "EventDataStores",
}
IAM_LISTS = ("UserDetailList", "GroupDetailList", "RoleDetailList", "Policies")


def validate_response(service: str, operation: str, request: dict[str, Any],
                      page: dict[str, Any]) -> None:
    """Required top-level AWS API collection shapes, not full AWS model validation."""
    if not isinstance(page, dict):
        raise ContractError("Fixture response must be an object")
    if (service, operation) == ("sts", "GetCallerIdentity"):
        account = page.get("Account")
        if not isinstance(account, str) or not ACCOUNT.fullmatch(account):
            raise ContractError("Malformed synthetic identity")
    elif (service, operation) == ("organizations", "DescribeOrganization"):
        org = page.get("Organization")
        if not isinstance(org, dict) or not isinstance(org.get("Id"), str) or not org["Id"]:
            raise ContractError("Missing organization identity")
    elif (service, operation) == ("iam", "GetAccountAuthorizationDetails"):
        if type(page.get("IsTruncated")) is not bool:
            raise ContractError("Missing or invalid IAM IsTruncated")
        if not any(k in page for k in IAM_LISTS):
            raise ContractError("IAM collections all missing")
        for field in IAM_LISTS:
            if field in page and (not isinstance(page[field], list)
                                  or any(not isinstance(x, dict) for x in page[field])):
                raise ContractError("Invalid IAM collection")
    else:
        field = COLLECTIONS.get((service, operation))
        if field is None:
            raise ContractError("Unrecognized synthetic response schema")
        collection = page.get(field)
        if not isinstance(collection, list) or any(not isinstance(x, dict) for x in collection):
            raise ContractError("Missing or malformed API result collection")
        if (service, operation) == ("organizations", "ListPoliciesForTarget"):
            expected = request.get("Filter")
            if any(x.get("Type") != expected for x in collection):
                raise ContractError("Policy type does not match requested SCP/RCP filter")
    if "NextToken" in page and page["NextToken"] is not None and not isinstance(page["NextToken"], str):
        raise ContractError("Non-string pagination token")


def _safe_bytes(page: dict[str, Any]) -> bytes:
    try:
        data = json.dumps(page, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(data) > MAX_PAGE_BYTES:
            raise ContractError("Fixture page exceeds size limit")
        inspect_json(data, ".json")
        return data
    except (TypeError, ValueError, RecursionError) as exc:
        raise ContractError("Unsafe/non-JSON fixture response") from exc


def _execute(port: FixturePort, probe: Probe) -> dict[str, Any]:
    request = dict(probe.arguments)
    hashes: list[str] = []
    visited: set[str] = set()
    status = "SIMULATED_PAGE_TERMINATED"
    reason = None
    for _ in range(MAX_PAGES):
        try:
            page = port.call(probe.service, probe.operation, probe.region, request)
            payload = _safe_bytes(page)
            validate_response(probe.service, probe.operation, request, page)
        except FixtureAccessDenied:
            status, reason = "ACCESS_DENIED", "SYNTHETIC_DENIAL"
            break
        except (FixtureFailure, ContractError):
            status, reason = "UNKNOWN", "INVALID_OR_FAILED_SYNTHETIC_RESPONSE"
            break
        hashes.append(hashlib.sha256(payload).hexdigest())
        if probe.pagination == "single":
            break
        if probe.pagination == "marker":
            truncated = page.get("IsTruncated")
            if type(truncated) is not bool:
                status, reason = "UNKNOWN", "INVALID_IAM_TRUNCATION"
                break
            token = page.get("Marker") if truncated else None
            if truncated and not token:
                status, reason = "PARTIAL", "TRUNCATED_WITHOUT_MARKER"
                break
            input_key = "Marker"
        else:
            token = page.get("NextToken")
            input_key = "NextToken"
        if token is None:
            break
        if not isinstance(token, str) or not token or len(token) > 4096 or token in visited:
            status, reason = "PARTIAL", "REPEATED_OR_INVALID_TOKEN"
            break
        visited.add(token)
        request[input_key] = token
    else:
        status, reason = "PARTIAL", "PAGE_LIMIT_REACHED"
    return {"label": probe.label, "evidence_id": probe.evidence_id,
            "source": probe.source, "region": probe.region,
            "operation": probe.service + ":" + probe.operation,
            "status": status, "reason": reason, "pages": len(hashes),
            "page_sha256": hashes, "pagination_complete": status == "SIMULATED_PAGE_TERMINATED",
            "provenance": "SYNTHETIC_FIXTURE_ONLY"}


def run_simulation(port: FixturePort, account: str, regions: tuple[str, ...],
                   start_utc: str, end_utc: str, as_of_utc: str) -> dict[str, Any]:
    """No AWS calls or I0 data writes. Fail identity before all other probes."""
    if type(port) is not FixturePort:
        raise ContractError("Only the exact synthetic FixturePort is accepted")
    plan = build_plan(account, regions, start_utc, end_utc, as_of_utc)

    def identity() -> tuple[bool, str | None]:
        try:
            data = port.call("sts", "GetCallerIdentity", "global", {})
            _safe_bytes(data)
            validate_response("sts", "GetCallerIdentity", {}, data)
        except (FixtureAccessDenied, FixtureFailure, ContractError):
            return False, None
        return data.get("Account") == account, data.get("Account")

    valid_start, observed = identity()
    if not valid_start:
        return {"status": "ABORTED_IDENTITY", "as_of_utc": as_of_utc, "expected_account": account,
                "observed_account": observed, "probes": [], "g2_gate": "NOT_VERIFIED",
                "snapshot_atomic": False, "aws_calls": 0}
    probes = [_execute(port, p) for p in plan]
    # Begin/end checks are modeled for IAM configuration only; NOT comprehensive.
    first_iam = probes[0]
    end_iam = _execute(port, plan[0])
    valid_end, end_account = identity()
    if not valid_end or end_account != account:
        consistency = "UNKNOWN"
    elif not first_iam["pagination_complete"] or not end_iam["pagination_complete"]:
        consistency = "UNKNOWN"
    elif first_iam["page_sha256"] != end_iam["page_sha256"]:
        consistency = "INCONSISTENT"
    else:
        consistency = "SIMULATED_IAM_MATCH_ONLY"
    return {
        "status": "MOCK_ONLY_PARTIAL_COVERAGE",
        "as_of_utc": as_of_utc,
        "expected_account": account, "observed_account": observed,
        "probes": probes, "begin_end_iam": {"begin": first_iam["status"],
                                          "end": end_iam["status"],
                                          "consistency": consistency},
        "g2_gate": "NOT_VERIFIED", "snapshot_atomic": False,
        "aws_calls": 0, "read_only_verified": False,
        "not_collected": [
            "IAM policy version and role trust expansion",
            "Identity Center permission sets, account assignments and Identity Store memberships",
            "Organizations inherited SCP/RCP across OU/root and management-account scope",
            "Trail S3 delivered raw objects and digest verification",
            "CloudTrail Lake query results (StartQuery not authorized)",
            "Resource tags, IaC consumers, all writer paths and session/federation context",
            "Complete begin/end resource-level consistency and ABA closure",
        ],
    }
