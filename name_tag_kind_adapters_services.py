"""Eleven non-EC2 Kinds: per-service one-Name read/write/readback candidates (Design 4.2).

``apigw_stage`` stays Capability-Not-Proven (inherited parent-API tags and unproven IAM
method semantics); ``s3_bucket`` only uses pinned ``s3control`` TagResource and never
``put_bucket_tagging``. Nothing here promotes a production decision.
"""
from __future__ import annotations

import re
from types import MappingProxyType

from name_tag_kind_adapters import (
    AdapterRejected, AdapterSpec, AdapterUnavailable, SingleNameAdapter, _Mismatch,
    _Unknown, name_tag, one, pinned_operation_names, resource_part, same)

_ARN = lambda t: t.resource_arn  # noqa: E731
_ID = lambda t: resource_part(t).split(":", 1)[1]  # rds/log/lambda: type:ID  # noqa: E731
_SL = lambda t: resource_part(t).split("/", 1)[1]  # type/ID  # noqa: E731


def _need(obj, key):
    if not isinstance(obj, dict) or key not in obj:
        raise _Unknown()
    return obj[key]


def _rds(kind, describe, id_kwarg, list_key, arn_key):
    return AdapterSpec(
        kind, "rds", "add_tags_to_resource",
        lambda t: (("rds", describe, {id_kwarg: _ID(t)}),
                   ("rds", "list_tags_for_resource", {"ResourceName": _ARN(t)})),
        lambda t, r: (same(one(r[0][list_key])[arn_key], _ARN(t)), _need(r[1], "TagList"))[1],
        lambda t, n: {"ResourceName": _ARN(t), "Tags": name_tag(n)},
        required_ops=(("rds", describe), ("rds", "list_tags_for_resource")))


def _opensearch():
    return AdapterSpec(
        "opensearch", "opensearch", "add_tags",
        lambda t: (("opensearch", "describe_domain", {"DomainName": _SL(t)}),
                   ("opensearch", "list_tags", {"ARN": _ARN(t)})),
        lambda t, r: (same(_need(_need(r[0], "DomainStatus"), "ARN"), _ARN(t)),
                      _need(r[1], "TagList"))[1],
        lambda t, n: {"ARN": _ARN(t), "TagList": name_tag(n)},
        required_ops=(("opensearch", "describe_domain"), ("opensearch", "list_tags")))


def _elbv2():
    def extract(t, r):
        same(one(r[0]["LoadBalancers"])["LoadBalancerArn"], _ARN(t))
        desc = one(r[1]["TagDescriptions"])
        same(desc["ResourceArn"], _ARN(t))
        return _need(desc, "Tags")
    return AdapterSpec(
        "elbv2", "elbv2", "add_tags",
        lambda t: (("elbv2", "describe_load_balancers", {"LoadBalancerArns": [_ARN(t)]}),
                   ("elbv2", "describe_tags", {"ResourceArns": [_ARN(t)]})),
        extract, lambda t, n: {"ResourceArns": [_ARN(t)], "Tags": name_tag(n)},
        required_ops=(("elbv2", "describe_load_balancers"), ("elbv2", "describe_tags")))


_APIGW = re.compile(r"/restapis/(?P<api>[^/]+)/stages/(?P<stage>[^/]+)")


def _apigw_ids(t):
    m = _APIGW.fullmatch(resource_part(t))
    if m is None:
        raise _Unknown()
    return m.group("api"), m.group("stage")


def _apigw():
    def reads(t):
        api, stage = _apigw_ids(t)
        return (("apigateway", "get_stage", {"restApiId": api, "stageName": stage}),
                ("apigateway", "get_tags", {"resourceArn": _ARN(t)}))

    def extract(t, r):
        api, stage = _apigw_ids(t)
        same(_need(r[0], "stageName"), stage)
        own, effective = _need(r[0], "tags"), _need(r[1], "tags")
        # A Name visible only through get_tags (or with another value) is inherited from
        # the parent API; the stage's own state is then not provable -> UNKNOWN.
        if not isinstance(own, dict) or own.get("Name") != (effective or {}).get("Name") \
                or set(own) != set(effective):
            raise _Unknown()
        return effective

    return AdapterSpec(
        "apigw_stage", "apigateway", "tag_resource", reads, extract,
        lambda t, n: {"resourceArn": _ARN(t), "tags": {"Name": n}},
        required_ops=(("apigateway", "get_stage"), ("apigateway", "get_tags")))


def _cloudfront():
    def extract(t, r):
        dist = _need(r[0], "Distribution")
        same(dist["Id"], _SL(t))
        same(dist["ARN"], _ARN(t))
        items = _need(_need(r[1], "Tags"), "Items")
        return items
    return AdapterSpec(
        "cloudfront", "cloudfront", "tag_resource",
        lambda t: (("cloudfront", "get_distribution", {"Id": _SL(t)}),
                   ("cloudfront", "list_tags_for_resource", {"Resource": _ARN(t)})),
        extract, lambda t, n: {"Resource": _ARN(t), "Tags": {"Items": name_tag(n)}},
        required_ops=(("cloudfront", "get_distribution"),
                      ("cloudfront", "list_tags_for_resource")))


def _athena():
    return AdapterSpec(
        "athena_workgroup", "athena", "tag_resource",
        lambda t: (("athena", "get_work_group", {"WorkGroup": _SL(t)}),
                   ("athena", "list_tags_for_resource", {"ResourceARN": _ARN(t)})),
        lambda t, r: (same(_need(_need(r[0], "WorkGroup"), "Name"), _SL(t)),
                      _need(r[1], "Tags"))[1],
        lambda t, n: {"ResourceARN": _ARN(t), "Tags": name_tag(n)},
        required_ops=(("athena", "get_work_group"), ("athena", "list_tags_for_resource")))


def _log_group():
    def extract(t, r):
        matches = [g for g in _need(r[0], "logGroups")
                   if isinstance(g, dict) and g.get("logGroupName") == _ID(t)]
        group = one(matches)  # exact-name match, never the prefix siblings
        arn = group.get("arn")
        same(arn[:-2] if isinstance(arn, str) and arn.endswith(":*") else arn, _ARN(t))
        return _need(r[1], "tags")
    return AdapterSpec(
        "log_group", "logs", "tag_resource",
        lambda t: (("logs", "describe_log_groups", {"logGroupNamePrefix": _ID(t)}),
                   ("logs", "list_tags_for_resource", {"resourceArn": _ARN(t)})),
        extract, lambda t, n: {"resourceArn": _ARN(t), "tags": {"Name": n}},
        required_ops=(("logs", "describe_log_groups"), ("logs", "list_tags_for_resource")))


def _lambda():
    return AdapterSpec(
        "lambda", "lambda", "tag_resource",
        lambda t: (("lambda", "get_function", {"FunctionName": _ARN(t)}),
                   ("lambda", "list_tags", {"Resource": _ARN(t)})),
        lambda t, r: (same(_need(_need(r[0], "Configuration"), "FunctionArn"), _ARN(t)),
                      _need(r[1], "Tags"))[1],
        lambda t, n: {"Resource": _ARN(t), "Tags": {"Name": n}},
        required_ops=(("lambda", "get_function"), ("lambda", "list_tags")))


def _waf_parts(t):
    scope, _, name, ident = resource_part(t).split("/")
    return ("CLOUDFRONT" if scope == "global" else "REGIONAL"), name, ident


def _wafv2():
    def reads(t):
        scope, name, ident = _waf_parts(t)
        return (("wafv2", "get_web_acl", {"Name": name, "Scope": scope, "Id": ident}),
                ("wafv2", "list_tags_for_resource", {"ResourceARN": _ARN(t)}))

    def extract(t, r):
        same(_need(_need(r[0], "WebACL"), "ARN"), _ARN(t))
        info = _need(r[1], "TagInfoForResource")
        same(info["ResourceARN"], _ARN(t))
        return _need(info, "TagList")
    return AdapterSpec(
        "wafv2", "wafv2", "tag_resource", reads, extract,
        lambda t, n: {"ResourceARN": _ARN(t), "Tags": name_tag(n)},
        required_ops=(("wafv2", "get_web_acl"), ("wafv2", "list_tags_for_resource")))


_REGION_OF_LOCATION = {"": "us-east-1", None: "us-east-1", "EU": "eu-west-1"}


def _s3():
    account = lambda t: t.owner_account  # noqa: E731
    return AdapterSpec(
        "s3_bucket", "s3control", "tag_resource",
        lambda t: (("s3control", "list_tags_for_resource",
                    {"AccountId": account(t), "ResourceArn": _ARN(t)}),),
        lambda t, r: _need(r[0], "Tags"),
        lambda t, n: {"AccountId": account(t), "ResourceArn": _ARN(t), "Tags": name_tag(n)},
        required_ops=(("s3control", "list_tags_for_resource"), ("s3", "get_bucket_location")),
        needs_ownership_proof=True)


class S3ControlAdapter(SingleNameAdapter):
    """Client is a bundle exposing ``.s3`` and ``.s3control``; never put_bucket_tagging."""

    def __init__(self, spec, operation_names=pinned_operation_names):
        super().__init__(spec, operation_names)
        if "tag_resource" not in set(operation_names("s3control")):
            raise AdapterUnavailable("API_SDK_UNAVAILABLE", spec.kind)

    def _invoke(self, client, service, op, kwargs):
        if service not in ("s3", "s3control") or op == "put_bucket_tagging":
            raise AdapterRejected("OPERATION_FORBIDDEN", self.kind)
        return getattr(getattr(client, service), op)(**kwargs)

    def _preflight_write(self, client, target):
        # Independent region proof: bucket location must equal the s3control client region.
        try:
            loc = self._invoke(client, "s3", "get_bucket_location",
                               {"Bucket": resource_part(target)})["LocationConstraint"]
            bucket_region = _REGION_OF_LOCATION.get(loc, loc)
            client_region = client.s3control.meta.region_name
        except (AttributeError, KeyError, TypeError):
            raise AdapterRejected("ARN_OWNER_NOT_PROVEN", self.kind) from None
        if not isinstance(bucket_region, str) or bucket_region != client_region:
            raise AdapterRejected("ARN_OWNER_NOT_PROVEN", self.kind)


class ApiGatewayStageAdapter(SingleNameAdapter):
    def _preflight_write(self, client, target):
        if self.read_current(client, target).state == "UNKNOWN":
            raise AdapterRejected("TAG_STATE_UNKNOWN", self.kind)


SERVICE_SPECS = MappingProxyType({
    "rds_cluster": _rds("rds_cluster", "describe_db_clusters", "DBClusterIdentifier",
                        "DBClusters", "DBClusterArn"),
    "rds_instance": _rds("rds_instance", "describe_db_instances", "DBInstanceIdentifier",
                         "DBInstances", "DBInstanceArn"),
    "opensearch": _opensearch(), "elbv2": _elbv2(), "apigw_stage": _apigw(),
    "cloudfront": _cloudfront(), "athena_workgroup": _athena(), "log_group": _log_group(),
    "lambda": _lambda(), "wafv2": _wafv2(), "s3_bucket": _s3(),
})


def build_service_adapter(kind, operation_names=pinned_operation_names):
    spec = SERVICE_SPECS[kind]
    cls = {"s3_bucket": S3ControlAdapter, "apigw_stage": ApiGatewayStageAdapter}.get(
        kind, SingleNameAdapter)
    return cls(spec, operation_names)
