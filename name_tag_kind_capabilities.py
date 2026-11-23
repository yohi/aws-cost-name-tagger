"""Versioned, immutable 18-Kind capability and canonical identity registry.

Pure and offline: no network, no boto3 and no AWS calls. The registry data are
design-level candidates; a Kind is only ``IMPLEMENTED_OFFLINE`` (signable) when
this trusted module says so. ``CAPABILITY_NOT_PROVEN`` Kinds never yield an AWS
operation before signing. Syntax admission here is NOT a Host ownership proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

REGISTRY_VERSION = "kind-capability-registry/1"

STATUSES = frozenset((
    "UNSUPPORTED_BY_POLICY", "UNSUPPORTED_API", "CAPABILITY_NOT_PROVEN",
    "LIVE_GATE_PENDING", "IMPLEMENTED_OFFLINE",
))
CNP_REASON_CODES = frozenset((
    "IAM_CONDITION_NOT_PROVEN", "ARN_OWNER_NOT_PROVEN", "API_SDK_UNAVAILABLE",
    "NAME_EVIDENCE_NOT_PROVEN", "GLOBAL_SCOPE_NOT_PROVEN",
))

# Independent exact enumeration; parity with aws_cost_name_tagger_v3.SUPPORTED_KINDS
# is asserted in the test suite (kept independent to avoid a circular import).
REGISTRY_KINDS = (
    "instance", "volume", "snapshot", "eni", "eip", "nat", "endpoint",
    "rds_cluster", "rds_instance", "opensearch", "elbv2", "apigw_stage",
    "cloudfront", "athena_workgroup", "log_group", "lambda", "wafv2", "s3_bucket",
)

GLOBAL_SCOPE = "global"


@dataclass(frozen=True)
class CanonicalTargetIdentity:
    kind: str
    locator: str
    resource_arn: str
    partition: str
    owner_account: str
    scope_region: str
    arn_region: str
    arn_account: str
    ownership_proof_ref: str = ""  # syntax admission is NOT a Host ownership attestation


@dataclass(frozen=True)
class KindCapabilityDecision:
    kind: str
    service: str
    read_operations: tuple[str, ...]
    write_operation: str
    readback_operations: tuple[str, ...]
    sdk_request_contract: str
    iam_action: str
    resource_type: str
    tag_key_conditions: tuple[str, ...]
    tag_set_replacement: bool
    side_effect_requirements: tuple[str, ...]
    status: str
    reason_code: str
    evidence_refs: tuple[str, ...]
    version: str


# Design 5.1 uses KindCapability for the same vetted decision.
KindCapability = KindCapabilityDecision


@dataclass(frozen=True)
class PreSignKindTarget:
    identity: CanonicalTargetIdentity
    aws_operation: str | None
    capability_status: str
    reason_code: str


class KindCapabilityRegistry(Protocol):
    def resolve(self, kind: str, arn: str, operation: str) -> KindCapabilityDecision: ...


# --------------------------------------------------------------------------- data

_EC2_KEYS = ("aws:TagKeys=Name", "aws:RequestTag/Name")
_COMMON_SIDE = ("protected Host ownership proof", "G1 race check", "readback of Name key only")


def _d(kind, service, read, write, readback, contract, iam, rtype, conds, status,
       reason, side=_COMMON_SIDE, evidence=()):
    return KindCapabilityDecision(
        kind=kind, service=service, read_operations=tuple(read), write_operation=write,
        readback_operations=tuple(readback), sdk_request_contract=contract, iam_action=iam,
        resource_type=rtype, tag_key_conditions=tuple(conds), tag_set_replacement=False,
        side_effect_requirements=tuple(side), status=status, reason_code=reason,
        evidence_refs=tuple(evidence), version=REGISTRY_VERSION)


_EC2_CONTRACT = "create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])"
_CNP = "CAPABILITY_NOT_PROVEN"


def _ec2(kind, rtype, describe, reason, status=_CNP, evidence=()):
    return _d(kind, "ec2", (describe,), "ec2:CreateTags", (describe,), _EC2_CONTRACT,
              "ec2:CreateTags", rtype, _EC2_KEYS, status, reason, evidence=evidence)


_DECISION_LIST = (
    _ec2("instance", "instance", "describe_instances", "IAM_CONDITION_NOT_PROVEN"),
    _ec2("volume", "volume", "describe_volumes", "OFFLINE_CONTRACT_COMPLETE",
         status="IMPLEMENTED_OFFLINE",
         evidence=("existing Batch Volume offline contract (legacy ec2:CreateTags)",)),
    _ec2("snapshot", "snapshot", "describe_snapshots", "ARN_OWNER_NOT_PROVEN"),
    _ec2("eni", "network-interface", "describe_network_interfaces", "NAME_EVIDENCE_NOT_PROVEN"),
    _ec2("eip", "elastic-ip", "describe_addresses", "NAME_EVIDENCE_NOT_PROVEN"),
    _ec2("nat", "natgateway", "describe_nat_gateways", "NAME_EVIDENCE_NOT_PROVEN"),
    _ec2("endpoint", "vpc-endpoint", "describe_vpc_endpoints", "NAME_EVIDENCE_NOT_PROVEN"),
    _d("rds_cluster", "rds", ("describe_db_clusters", "list_tags_for_resource"),
       "rds:AddTagsToResource", ("describe_db_clusters", "list_tags_for_resource"),
       "add_tags_to_resource(ResourceName=arn,Tags=[{Key:'Name',Value:name}])",
       "rds:AddTagsToResource", "cluster", ("aws:TagKeys", "aws:RequestTag/Name"), _CNP,
       "IAM_CONDITION_NOT_PROVEN"),
    _d("rds_instance", "rds", ("describe_db_instances", "list_tags_for_resource"),
       "rds:AddTagsToResource", ("describe_db_instances", "list_tags_for_resource"),
       "add_tags_to_resource(ResourceName=arn,Tags=[{Key:'Name',Value:name}])",
       "rds:AddTagsToResource", "db", ("aws:TagKeys", "aws:RequestTag/Name"), _CNP,
       "IAM_CONDITION_NOT_PROVEN"),
    _d("opensearch", "opensearch", ("describe_domain", "list_tags"), "es:AddTags",
       ("describe_domain", "list_tags"),
       "add_tags(ARN=arn,TagList=[{Key:'Name',Value:name}])",
       "es:AddTags", "domain", (), _CNP, "IAM_CONDITION_NOT_PROVEN"),
    _d("elbv2", "elbv2", ("describe_load_balancers", "describe_tags"),
       "elasticloadbalancing:AddTags", ("describe_load_balancers", "describe_tags"),
       "add_tags(ResourceArns=[arn],Tags=[{Key:'Name',Value:name}])",
       "elasticloadbalancing:AddTags", "loadbalancer", (), _CNP, "IAM_CONDITION_NOT_PROVEN"),
    _d("apigw_stage", "apigateway", ("get_stage", "get_tags"), "apigateway:PATCH",
       ("get_stage", "get_tags"), "tag_resource(resourceArn=arn,tags={'Name':name})",
       "apigateway:PATCH", "stage", (), _CNP, "IAM_CONDITION_NOT_PROVEN"),
    _d("cloudfront", "cloudfront", ("get_distribution", "list_tags_for_resource"),
       "cloudfront:TagResource", ("get_distribution", "list_tags_for_resource"),
       "tag_resource(Resource=arn,Tags={'Items':[{Key:'Name',Value:name}]})",
       "cloudfront:TagResource", "distribution", ("aws:TagKeys", "aws:RequestTag/Name"),
       _CNP, "GLOBAL_SCOPE_NOT_PROVEN"),
    _d("athena_workgroup", "athena", ("get_work_group", "list_tags_for_resource"),
       "athena:TagResource", ("get_work_group", "list_tags_for_resource"),
       "tag_resource(ResourceARN=arn,Tags=[{Key:'Name',Value:name}])",
       "athena:TagResource", "workgroup", (), _CNP, "NAME_EVIDENCE_NOT_PROVEN"),
    _d("log_group", "logs", ("describe_log_groups", "list_tags_for_resource"),
       "logs:TagResource", ("describe_log_groups", "list_tags_for_resource"),
       "tag_resource(resourceArn=arn,tags={'Name':name})",
       "logs:TagResource", "log-group", (), _CNP, "IAM_CONDITION_NOT_PROVEN"),
    _d("lambda", "lambda", ("get_function", "list_tags"), "lambda:TagResource",
       ("get_function", "list_tags"), "tag_resource(Resource=arn,Tags={'Name':name})",
       "lambda:TagResource", "function", (), _CNP, "NAME_EVIDENCE_NOT_PROVEN"),
    _d("wafv2", "wafv2", ("get_web_acl", "list_tags_for_resource"), "wafv2:TagResource",
       ("get_web_acl", "list_tags_for_resource"),
       "tag_resource(ResourceARN=arn,Tags=[{Key:'Name',Value:name}])",
       "wafv2:TagResource", "webacl", (), _CNP, "GLOBAL_SCOPE_NOT_PROVEN"),
    _d("s3_bucket", "s3control", ("get_bucket_location", "list_tags_for_resource"),
       "s3control:TagResource", ("get_bucket_location", "list_tags_for_resource"),
       "s3control.tag_resource(AccountId=A,ResourceArn=arn,Tags=[{Key:'Name',Value:name}])",
       "s3:TagResource", "bucket", ("aws:TagKeys", "aws:RequestTag/Name"), _CNP,
       "ARN_OWNER_NOT_PROVEN",
       side=_COMMON_SIDE + ("independent bucket owner and region attestation",
                            "never s3:PutBucketTagging (whole-set replacement)")),
)
_DECISIONS: Mapping[str, KindCapabilityDecision] = MappingProxyType(
    {d.kind: d for d in _DECISION_LIST})
assert tuple(_DECISIONS) == REGISTRY_KINDS


def resolve_kind_capability(kind: str) -> KindCapabilityDecision:
    """Return the trusted, immutable capability decision for one Kind."""
    if not isinstance(kind, str) or kind not in REGISTRY_KINDS:
        raise ValueError("Unsupported Kind for capability registry")
    return _DECISIONS[kind]


# ------------------------------------------------------------------ identity rules

_PARTITIONS = frozenset(("aws", "aws-cn", "aws-us-gov"))
_REGION_RE = re.compile(r"[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}")
_ACCOUNT_RE = re.compile(r"[0-9]{12}")
_ASCII_SAFE_RE = re.compile(r"[\x21-\x7e]+")  # printable, no whitespace/control


def _hexid(prefix: str) -> str:
    return rf"{prefix}-[0-9a-f]{{8}}(?:[0-9a-f]{{9}})?"


@dataclass(frozen=True)
class _Rule:
    service: str
    resource_re: re.Pattern
    locator: Callable[[re.Match], str]
    template: Callable[[str, str, str, str], str] | None  # (partition, region, account, locator)
    scope_global: bool = False   # signed Scope region is the literal 'global'
    regionless: bool = False     # ARN region component must be empty
    accountless: bool = False    # ARN account component must be empty


def _simple(service, rtype, sep, pattern):
    rx = re.compile(rf"{re.escape(rtype)}{sep}(?P<loc>{pattern})")
    def tmpl(p, r, a, loc):
        return f"arn:{p}:{service}:{r}:{a}:{rtype}{sep}{loc}"
    return rx, (lambda m: m.group("loc")), tmpl


def _ec2_rule(rtype, prefix, accountless=False):
    rx, loc, tmpl = _simple("ec2", rtype, "/", _hexid(prefix))
    return _Rule("ec2", rx, loc, tmpl, accountless=accountless)


_NAME63 = r"(?=[A-Za-z0-9-]{1,63}\Z)[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

_LOCATOR_APIGW = re.compile(r"/restapis/(?P<api>[A-Za-z0-9]{10})/stages/(?P<stage>[A-Za-z0-9_-]{1,128})")
_APIGW_RE = _LOCATOR_APIGW
_ELB_RE = re.compile(
    r"loadbalancer/(?P<loc>(?:app|net|gwy)/[A-Za-z0-9](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?/[0-9a-f]{16})")
_WAF_RE = re.compile(
    rf"(?P<scope>regional|global)/webacl/(?P<name>[A-Za-z0-9_-]{{1,128}})/(?P<id>{_UUID})")
_CF_RE = re.compile(r"distribution/(?P<loc>E[A-Z0-9]{8,20})")
_S3_RE = re.compile(r"(?P<loc>(?!.*\.\.)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9])")


def _apigw_tmpl(p, r, a, loc):
    api, _, stage = loc.partition("/")
    return f"arn:{p}:apigateway:{r}::/restapis/{api}/stages/{stage}"


_RULES: Mapping[str, _Rule] = MappingProxyType({
    "instance": _ec2_rule("instance", "i"),
    "volume": _ec2_rule("volume", "vol"),
    "snapshot": _ec2_rule("snapshot", "snap", accountless=True),
    "eni": _ec2_rule("network-interface", "eni"),
    "eip": _ec2_rule("elastic-ip", "eipalloc"),
    "nat": _ec2_rule("natgateway", "nat"),
    "endpoint": _ec2_rule("vpc-endpoint", "vpce"),
    "rds_cluster": _Rule("rds", *_simple("rds", "cluster", ":", _NAME63)),
    "rds_instance": _Rule("rds", *_simple("rds", "db", ":", _NAME63)),
    "opensearch": _Rule("es", *_simple("es", "domain", "/", r"[a-z][a-z0-9-]{2,27}")),
    "elbv2": _Rule("elasticloadbalancing", _ELB_RE, lambda m: m.group("loc"), None),
    "apigw_stage": _Rule("apigateway", _APIGW_RE,
                         lambda m: f"{m.group('api')}/{m.group('stage')}", _apigw_tmpl,
                         accountless=True),
    "cloudfront": _Rule("cloudfront", _CF_RE, lambda m: m.group("loc"),
                        lambda p, r, a, loc: f"arn:{p}:cloudfront::{a}:distribution/{loc}",
                        scope_global=True, regionless=True),
    "athena_workgroup": _Rule("athena", *_simple("athena", "workgroup", "/", r"[A-Za-z0-9_.-]{1,128}")),
    "log_group": _Rule("logs", *_simple("logs", "log-group", ":", r"[A-Za-z0-9_./#-]{1,512}")),
    "lambda": _Rule("lambda", *_simple("lambda", "function", ":", r"[A-Za-z0-9_-]{1,64}")),
    "wafv2": _Rule("wafv2", _WAF_RE, lambda m: f"{m.group('name')}/{m.group('id')}", None),
    "s3_bucket": _Rule("s3", _S3_RE, lambda m: m.group("loc"),
                       lambda p, r, a, loc: f"arn:{p}:s3:::{loc}",
                       scope_global=True, regionless=True, accountless=True),
})
assert tuple(_RULES) == REGISTRY_KINDS

_GLOBAL_WAF_REGION = {"aws": "us-east-1"}  # CLOUDFRONT-scope WAFv2 endpoint region per partition


def _fail(msg: str):
    raise ValueError(msg)


def _check_region_for_partition(region: str, partition: str) -> None:
    if not _REGION_RE.fullmatch(region):
        _fail("Invalid ARN region")
    if partition == "aws-cn":
        ok = region.startswith("cn-")
    elif partition == "aws-us-gov":
        ok = region.startswith("us-gov-")
    else:
        ok = not region.startswith(("cn-", "us-gov-"))
    if not ok:
        _fail("ARN region does not belong to partition")


def canonical_target_identity(*, kind: str, locator: str, resource_arn: str,
                              partition: str, account: str, scope_region: str
                              ) -> CanonicalTargetIdentity:
    """Validate one exact canonical ARN with its Kind rule; refuse alias/wildcard."""
    rule = _RULES.get(kind) if isinstance(kind, str) else None
    if rule is None:
        _fail("Unsupported Kind for canonical identity")
    for value in (locator, resource_arn, partition, account, scope_region):
        if not isinstance(value, str):
            _fail("Identity fields must be strings")
    if partition not in _PARTITIONS:
        _fail("Unsupported or foreign partition")
    if not _ACCOUNT_RE.fullmatch(account):
        _fail("Signed account must be a 12-digit account id")
    if not _ASCII_SAFE_RE.fullmatch(resource_arn) or "*" in resource_arn or "?" in resource_arn:
        _fail("ARN must be a printable exact ARN without wildcards")
    parts = resource_arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        _fail("Malformed ARN")
    _, arn_partition, service, arn_region, arn_account, resource = parts
    if arn_partition != partition:
        _fail("ARN partition differs from signed partition")
    if service != rule.service:
        _fail("ARN service does not match Kind")
    match = rule.resource_re.fullmatch(resource)
    if match is None:
        _fail("ARN resource does not match Kind grammar")
    if rule.regionless:
        if arn_region:
            _fail("Kind requires a regionless ARN")
    else:
        _check_region_for_partition(arn_region, partition)
    if rule.accountless:
        if arn_account:
            _fail("Kind requires an accountless ARN")
    elif arn_account != account:
        _fail("ARN account differs from signed account")
    if kind == "wafv2" and match.group("scope") == "global":
        if arn_region != _GLOBAL_WAF_REGION.get(partition):
            _fail("CLOUDFRONT-scope WAFv2 ARN must use its global endpoint region")
    if rule.scope_global:
        if scope_region != GLOBAL_SCOPE:
            _fail("Kind requires signed scope region 'global'")
    elif scope_region != arn_region:
        _fail("Signed scope region must equal the ARN region")
    expected_locator = rule.locator(match)
    if locator not in (expected_locator, resource_arn):
        _fail("Locator does not identify the ARN resource")
    return CanonicalTargetIdentity(
        kind=kind, locator=locator, resource_arn=resource_arn, partition=partition,
        owner_account=account, scope_region=scope_region, arn_region=arn_region,
        arn_account=arn_account)


def project_unsigned_scope_region(*, kind: str, classified_region: str,
                                  canonical_arn: str) -> str:
    """Narrow scope-region projection: 'global' for global Kinds, else ARN region."""
    rule = _RULES.get(kind) if isinstance(kind, str) else None
    if rule is None:
        _fail("Unsupported Kind for scope projection")
    if rule.scope_global:
        return GLOBAL_SCOPE
    parts = canonical_arn.split(":", 5) if isinstance(canonical_arn, str) else []
    if len(parts) != 6 or not parts[3]:
        _fail("Canonical ARN has no region")
    if classified_region != parts[3]:
        _fail("Classified region differs from the canonical ARN region")
    return parts[3]


def project_pre_sign_kind_target(*, kind: str, locator: str, discovered_region: str,
                                 discovered_arn: str | None, partition: str, account: str,
                                 evidence: str, proposed_name: str | None
                                 ) -> PreSignKindTarget:
    """Single deterministic pre-sign projection: canonical identity plus vetted operation."""
    decision = resolve_kind_capability(kind)
    rule = _RULES[kind]
    if discovered_arn is not None:
        arn = discovered_arn
    elif isinstance(locator, str) and locator.startswith("arn:"):
        arn = locator
    elif rule.template is not None and isinstance(locator, str) and isinstance(
            discovered_region, str) and partition in _PARTITIONS:
        region = "" if rule.regionless else discovered_region
        account_part = "" if rule.accountless else account
        arn = rule.template(partition, region, account_part, locator)
    else:
        _fail("Canonical ARN is not derivable for this Kind without a discovered ARN")
    identity_scope = None
    if rule.scope_global:
        identity_scope = GLOBAL_SCOPE
    else:
        if discovered_region != (arn.split(":", 5)[3] if arn.count(":") >= 5 else None):
            _fail("Discovered region differs from the ARN region")
        identity_scope = discovered_region
    identity = canonical_target_identity(
        kind=kind, locator=locator, resource_arn=arn, partition=partition,
        account=account, scope_region=identity_scope)
    if decision.status != "IMPLEMENTED_OFFLINE":
        return PreSignKindTarget(identity, None, decision.status, decision.reason_code)
    if kind == "volume":  # legacy signable contract, unchanged
        return PreSignKindTarget(identity, decision.write_operation, decision.status,
                                 decision.reason_code)
    vetted = (isinstance(evidence, str) and evidence.strip()
              and isinstance(proposed_name, str) and proposed_name.strip()
              and decision.write_operation and decision.evidence_refs)
    if not vetted:
        return PreSignKindTarget(identity, None, _CNP, "NAME_EVIDENCE_NOT_PROVEN")
    return PreSignKindTarget(identity, decision.write_operation, decision.status,
                             decision.reason_code)
