#!/usr/bin/env python3
"""CUR-driven AWS Name-tag proposals and read-only review workflow (v3.6 SAFETY HOLD).

All AWS name-tag mutation APIs are disabled pending an independently verified
atomic absent-or-empty-only write guarantee. Y stages approval proposals but never writes.

Python >= 3.10, boto3 >= 1.41.0. No additional dependencies.
"""
from __future__ import annotations

import argparse
import csv
import errno
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_THRESHOLD = 10.0
SCOPE_PATTERN = re.compile(r"^([a-z0-9][a-z0-9-]*?)-(prd|prod|stg|stage|dev|test|qa)(?=-|$)")
OPAQUE = re.compile(r"^(?:i|vol|snap|eni|eipalloc|nat|vpce)-[0-9a-f]{8,}$")
ID_PART = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
SHARED_PREFIXES = ("shared-service-", "saas-common-", "saas-data-lake-")
SAFETY_HOLD = ("AWS TAG WRITES DISABLED: Name=absent conditional creation is not "
               "proven atomic for supported service APIs; v3.6 produces reports only")


def shared_scope(value: str) -> bool:
    """Names of shared infrastructure do not prove single-product ownership."""
    s = (value or "").lower()
    if s.startswith("dh-"):
        s = s[3:]
    return any(s.startswith(p) for p in SHARED_PREFIXES)



def name_scope_prefix(value: str) -> str | None:
    """Parse a structured Name namespace, not the AWS Product tag.

    Product classification is performed separately from this tool.
    """
    s = (value or "").strip().lower().split(":")[-1]
    if s.startswith("dh-"):
        s = s[3:]  # conventional S3 bucket prefix in this account
    m = SCOPE_PATTERN.match(s)
    if not m:
        return None
    return m.group(0)  # e.g. 'scs2-prd' or 'coord-app-prod'


def meaningful(value: str) -> str | None:
    """Require a recognizable name namespace/environment, not a Product mapping."""
    s = (value or "").strip().lower()
    if not s or OPAQUE.fullmatch(s) or not ID_PART.fullmatch(s):
        return None
    return s if name_scope_prefix(s) else None


def suffix_name(base: str, *parts: str) -> str:
    clean = [re.sub(r"[^a-z0-9-]+", "-", p.lower()).strip("-") for p in parts]
    clean = [p for p in clean if p]
    target = "-".join([base] + clean)
    if len(target) > 256:
        raise ValueError("Name exceeds 256 characters; manual review required")
    return target


NAME_CANDIDATE_STATES = ("ABSENT", "EMPTY")
SUPPORTED_KINDS = frozenset((
    "instance", "volume", "snapshot", "eni", "eip", "nat", "endpoint",
    "rds_cluster", "rds_instance", "opensearch", "elbv2", "apigw_stage",
    "cloudfront", "athena_workgroup", "log_group", "lambda", "wafv2", "s3_bucket",
))


def tagmap(tags) -> dict:
    """Normalize AWS tag shapes without silently converting malformed Name to EMPTY.

    A missing Value or duplicate Name in a list is not an empty Name. Fail
    closed: resolver reports UNKNOWN rather than proposing from corrupt data.
    """
    if isinstance(tags, dict):
        return dict(tags)
    if not isinstance(tags, list):
        raise ValueError("AWS tag collection is missing or malformed")
    result = {}
    for entry in tags:
        if not isinstance(entry, dict) or not isinstance(entry.get("Key"), str):
            raise ValueError("AWS tag entry is malformed")
        key = entry["Key"]
        if key.casefold() == "name" and ("Value" not in entry or key in result):
            raise ValueError("Name tag value missing or duplicated")
        result[key] = entry.get("Value")
    return result


def name_state(tags) -> str:
    """Strict Name read: ABSENT, EMPTY, NONEMPTY or UNKNOWN.

    Whitespace-only Name is NONEMPTY and protected; case-variant Name tags,
    malformed types and unreadable tag sets are UNKNOWN (never actionable).
    """
    if tags is None:
        return "UNKNOWN"
    try:
        tags = tagmap(tags)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if any(isinstance(k, str) and k != "Name" and k.casefold() == "name"
           for k in tags):
        return "UNKNOWN"
    if "Name" not in tags:
        return "ABSENT"
    value = tags["Name"]
    if not isinstance(value, str):
        return "UNKNOWN"
    return "EMPTY" if value == "" else "NONEMPTY"


def has_name(tags) -> bool:
    """Whether the exact Name key exists (NOT a decision to protect or edit)."""
    return isinstance(tags, dict) and "Name" in tags


def name_of(tags) -> str | None:
    tags = tagmap(tags)
    value = tags.get("Name")
    return value if isinstance(value, str) else None


def rid_class(resource_id: str) -> tuple[str, str, str | None]:
    """Return (kind, locator, region), or unsupported. Service name is not trusted."""
    s = resource_id.strip()
    if s.startswith("arn:"):
        a = s.split(":", 5)
        if len(a) != 6:
            return "unsupported", s, None
        _, _, service, region, _account, rest = a
        if service == "ec2":
            typ, sep, rid = rest.partition("/")
            kinds = {"volume":"volume", "snapshot":"snapshot", "instance":"instance", "natgateway":"nat", "network-interface":"eni", "elastic-ip":"eip", "vpc-endpoint":"endpoint"}
            return kinds.get(typ,"unsupported"), rid if sep else rest, region
        if service == "rds":
            typ, _, ident = rest.partition(":")
            return {"cluster":"rds_cluster", "db":"rds_instance"}.get(typ,"unsupported"), ident, region
        if service == "es" and rest.startswith("domain/"):
            return "opensearch", rest.split("/",1)[1], region
        if service == "elasticloadbalancing" and rest.startswith("loadbalancer/"):
            return "elbv2", s, region
        if service == "apigateway" and rest.startswith("/restapis/"):
            m = re.fullmatch(r"/restapis/([^/]+)/stages/([^/]+)", rest)
            if m:
                return "apigw_stage", f"{m.group(1)}|{m.group(2)}|{s}", region
        if service == "cloudfront" and rest.startswith("distribution/"):
            return "cloudfront", s, "us-east-1"
        if service == "athena" and rest.startswith("workgroup/"):
            return "athena_workgroup", s, region
        if service == "logs" and rest.startswith("log-group:"):
            return "log_group", rest[len("log-group:"):].removesuffix(":*"), region
        if service == "wafv2" and "/webacl/" in rest:
            return "wafv2", s, "us-east-1" if rest.startswith("global/") else region
        if service == "lambda" and rest.startswith("function:"):
            return "lambda", s, region
        return "unsupported", s, region
    for prefix, kind in (("i-","instance"),("vol-","volume"),("snap-","snapshot"),("eni-","eni"),("eipalloc-","eip"),("nat-","nat"),("vpce-","endpoint")):
        if s.startswith(prefix) and OPAQUE.fullmatch(s):
            return kind, s, None
    if s and re.fullmatch(r"[a-z0-9][a-z0-9.-]{2,62}", s):
        return "s3_bucket", s, None
    return "unsupported", s, None


def fnum(x) -> float:
    try:
        return float(x) if x else 0.0
    except (ValueError, TypeError):
        return 0.0


def cost_of(row: dict) -> float:
    typ = row["line_item_line_item_type"]
    if typ == "DiscountedUsage":
        return fnum(row.get("reservation_effective_cost"))
    if typ == "SavingsPlanCoveredUsage":
        return fnum(row.get("savings_plan_savings_plan_effective_cost"))
    if typ in ("Usage", "SavingsPlanNegation"):
        # SavingsPlanNegation is deliberately excluded by caller; no double counting.
        return fnum(row.get("line_item_unblended_cost"))
    return 0.0


def cur_candidates(files: list[str], month: str | None, min_cost: float, max_resources: int, account: str, kind_filter: set[str] | None = None):
    # Two streaming passes avoid loading ~600k full CSV records into memory.
    periods = set()
    for filename in files:
        with gzip.open(filename, "rt", newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            for row in reader:
                period = row.get("bill_billing_period_start_date", "")[:7]
                if period:
                    periods.add(period)
    if month is None and not periods:
        raise ValueError("CUR input contains no billing rows; specify --month")
    active_month = month or max(periods)
    aggregates = defaultdict(float)
    provenance = defaultdict(lambda: {"services": set(), "billing_rows": 0, "currency": set()})
    for filename in files:
        with gzip.open(filename, "rt", newline="", encoding="utf-8-sig") as stream:
            for row in csv.DictReader(stream):
                if row["bill_billing_period_start_date"][:7] != active_month:
                    continue
                if row["line_item_usage_account_id"] != account:
                    continue
                if row["line_item_line_item_type"] not in ("Usage", "DiscountedUsage", "SavingsPlanCoveredUsage"):
                    continue
                if row.get("line_item_currency_code") != "USD":
                    raise ValueError("Non-USD CUR line item; currency conversion is not implemented")
                raw_id = row["line_item_resource_id"].strip()
                if not raw_id:
                    continue  # Fees, unallocated charges, and untaggable rows.
                kind, locator, arn_region = rid_class(raw_id)
                if raw_id.startswith("arn:"):
                    # CUR's usage account and the target ARN's owner must agree.
                    # API Gateway ARNs normally omit account; service exceptions
                    # must be handled individually, never with a guessed owner.
                    arn_account = raw_id.split(":", 5)[4]
                    if arn_account and arn_account != account:
                        continue
                if kind == "unsupported" or (kind_filter is not None and kind not in kind_filter):
                    continue
                region = arn_region or row.get("product_region_code", "")
                if not region and kind == "s3_bucket":
                    region = "global"
                if not region:
                    continue
                key = (kind, locator, region)
                aggregates[key] += cost_of(row)
                provenance[key]["services"].add(row["line_item_product_code"])
                provenance[key]["billing_rows"] += 1
                provenance[key]["currency"].add(row.get("line_item_currency_code", ""))
    ranked = sorted(aggregates.items(), key=lambda x: -x[1])
    ranked = [(k,v) for k,v in ranked if v >= min_cost][:max_resources]
    return active_month, [{"kind": k[0], "locator": k[1], "region": k[2],
        "effective_usage_cost_usd": round(v, 6),
        "source_services": sorted(provenance[k]["services"]),
        "billing_rows": provenance[k]["billing_rows"],
        "currency": sorted(provenance[k]["currency"])} for k,v in ranked]


class Investigator:
    def __init__(self, session, account: str, retries: int = 3):
        from botocore.config import Config
        self.session = session
        self.account = account
        self.config = Config(retries={"mode": "standard", "total_max_attempts": retries})
        self._clients = {}
        self._instances = {}
        self._volumes = {}
        self._vpcs = {}
        self._subnets = {}

    def client(self, service: str, region: str):
        if service in ("cloudfront", "s3"):
            region = "us-east-1"
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self.session.client(service, region_name=region, config=self.config)
        return self._clients[key]

    def instance(self, region: str, iid: str):
        key=(region,iid)
        if key not in self._instances:
            ec2 = self.client("ec2", region)
            result = ec2.describe_instances(InstanceIds=[iid])
            found = [i for res in result.get("Reservations",[]) for i in res.get("Instances",[]) if i["InstanceId"]==iid]
            if len(found)!=1:
                raise ValueError("Instance not unique/absent")
            self._instances[key]=found[0]
        return self._instances[key]

    def volume(self, region: str, vid: str):
        key=(region,vid)
        if key not in self._volumes:
            items=self.client("ec2",region).describe_volumes(VolumeIds=[vid]).get("Volumes",[])
            if len(items)!=1:
                raise ValueError("Volume not unique/absent")
            self._volumes[key]=items[0]
        return self._volumes[key]

    def subnet(self, region: str, subnet_id: str):
        key=(region,subnet_id)
        if key not in self._subnets:
            ss=self.client("ec2",region).describe_subnets(SubnetIds=[subnet_id]).get("Subnets",[])
            if len(ss)!=1:
                raise ValueError("Subnet not unique/absent")
            self._subnets[key]=ss[0]
        return self._subnets[key]

    def vpc(self, region: str, vpc_id: str):
        key=(region,vpc_id)
        if key not in self._vpcs:
            vs=self.client("ec2",region).describe_vpcs(VpcIds=[vpc_id]).get("Vpcs",[])
            if len(vs)!=1:
                raise ValueError("VPC not unique/absent")
            self._vpcs[key]=vs[0]
        return self._vpcs[key]

    def parent_instance(self, region, iid):
        obj=self.instance(region,iid)
        parent_tags=tagmap(obj.get("Tags", []))
        anchor=meaningful(name_of(parent_tags))
        if not anchor:
            raise ValueError(f"EC2 {iid} lacks a meaningful Name; cannot inherit")
        # Product may use a different identifier than the Name. Only the
        # parent Name is inherited; catalog mappings belong elsewhere.
        return anchor, f"EC2 {iid} Name={anchor}; Product(observed, not validated)={parent_tags.get('Product','(unset)')}"

    def volume_owner(self, region, vid):
        vol=self.volume(region,vid)
        direct=meaningful(name_of(vol.get("Tags",[])))
        if direct:
            return direct, f"EBS {vid} Name={direct}"
        attachments=vol.get("Attachments",[])
        ids=set(a.get("InstanceId") for a in attachments if a.get("InstanceId"))
        if len(ids)!=1:
            raise ValueError(f"EBS {vid} has {len(ids)} distinct current EC2 attachments; ambiguous")
        iid=next(iter(ids))
        anchor, path=self.parent_instance(region,iid)
        device=next((a.get("Device","") for a in attachments if a.get("InstanceId")==iid),"")
        if not device:
            raise ValueError("EBS attachment device unknown")
        device=device.split("/")[-1].replace("_","-")
        return suffix_name(anchor,"ebs",device,vid[-7:]), f"EBS {vid} -> attachment {iid} {device} -> {path}"

    def eip_owner(self, region, alloc_id):
        addr=self.client("ec2",region).describe_addresses(AllocationIds=[alloc_id]).get("Addresses",[])
        if len(addr)!=1:
            raise ValueError("EIP allocation not found/unique")
        a=addr[0]
        if a.get("InstanceId"):
            n, p=self.parent_instance(region,a["InstanceId"])
            return suffix_name(n,"eip",alloc_id[-7:]),f"EIP {alloc_id} -> {p}",a
        if a.get("NetworkInterfaceId"):
            nic=self.client("ec2",region).describe_network_interfaces(NetworkInterfaceIds=[a["NetworkInterfaceId"]]).get("NetworkInterfaces",[])
            if len(nic)==1 and nic[0].get("Attachment",{}).get("InstanceId"):
                iid=nic[0]["Attachment"]["InstanceId"]
                n,p=self.parent_instance(region,iid)
                return suffix_name(n,"eip",alloc_id[-7:]),f"EIP {alloc_id} -> ENI {a['NetworkInterfaceId']} -> {p}",a
        raise ValueError("EIP not directly linked to named EC2; NAT/managed ENI not guessed")

    def nat_owner(self, region, nat):
        # A subnet alone cannot establish naming scope. Require both subnet and
        # VPC to carry a consistent naming namespace; mark MEDIUM.
        subnet=self.subnet(region,nat["SubnetId"])
        vpc=self.vpc(region,nat["VpcId"])
        sn=meaningful(name_of(subnet.get("Tags",[])))
        vn=meaningful(name_of(vpc.get("Tags",[])))
        if not sn or not vn or name_scope_prefix(sn)!=name_scope_prefix(vn):
            raise ValueError("NAT subnet and VPC Names have conflicting namespaces")
        az=subnet.get("AvailabilityZone", "")
        return suffix_name(sn,"nat",az[-1:] if az else "az",nat["NatGatewayId"][-6:]),f"NAT {nat['NatGatewayId']} -> subnet {nat['SubnetId']} Name={sn} + VPC {nat['VpcId']} Name={vn}"

    def resolve(self, item: dict) -> dict:
        """Read live tags, trace lineage, and make a conservative proposal."""
        kind,loc,region=item["kind"],item["locator"],item["region"]
        res={"status":"manual_review", "proposed_name":"", "confidence":"none", "evidence":"", "write_target":"", "kind":kind,
             "name_state":"UNKNOWN", "name_key_present":None, "name_raw_value":None,
             "existing_name":""}
        try:
            tags=None; candidate=None; evidence=""; confidence="high"
            if kind in ("instance","volume","snapshot","eni","eip","nat","endpoint"):
                ec2=self.client("ec2",region)
                if kind=="instance":
                    o=self.instance(region,loc);tags=tagmap(o.get("Tags",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:
                        relations=[]
                        for key,label in (("aws:autoscaling:groupName","AutoScaling Group"),
                                          ("aws:cloudformation:stack-name","CloudFormation Stack")):
                            value=meaningful(tags.get(key,""))
                            if value:relations.append((value,f"{label}={value}"))
                        if not relations:
                            raise ValueError("EC2 instance missing Name and structured ASG/CloudFormation ownership")
                        if len({name_scope_prefix(x[0]) for x in relations})!=1:
                            raise ValueError("EC2 ASG and CloudFormation Stack Names have conflicting namespaces")
                        # ASG/CloudFormation is an actual owning relationship, not an opaque ID guess.
                        anchor=relations[0][0]
                        candidate=suffix_name(anchor,"ec2",loc[-7:])
                        evidence=f"EC2 {loc} -> " + ", ".join(x[1] for x in relations)
                        confidence="medium"  # team should confirm a distinct EC2 role
                if kind=="volume":
                    o=self.volume(region,loc);tags=tagmap(o.get("Tags",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:
                        base,evidence=self.volume_owner(region,loc)
                        # EBS without Name inherits uniquely attached EC2's Name.
                        candidate=base
                elif kind=="snapshot":
                    snaps=ec2.describe_snapshots(SnapshotIds=[loc],OwnerIds=["self"]).get("Snapshots",[])
                    if len(snaps)!=1 or snaps[0].get("OwnerId")!=self.account:
                        raise ValueError("snapshot is absent or not owned by target account")
                    o=snaps[0];tags=tagmap(o.get("Tags",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:
                        src=o.get("VolumeId","")
                        if not src: raise ValueError("snapshot missing source volume")
                        # Source volume's CURRENT attachment does not establish
                        # who owned the snapshot at its creation time.
                        raise ValueError(f"Snapshot {loc} source VolumeId={src}; historical owner evidence required")
                elif kind=="eni":
                    eni=ec2.describe_network_interfaces(NetworkInterfaceIds=[loc]).get("NetworkInterfaces",[])
                    if len(eni)!=1: raise ValueError("ENI not found")
                    o=eni[0];tags=tagmap(o.get("TagSet",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:
                        iid=o.get("Attachment",{}).get("InstanceId")
                        if not iid: raise ValueError("ENI not attached to EC2 instance")
                        base,path=self.parent_instance(region,iid)
                        idx=o["Attachment"].get("DeviceIndex")
                        if idx is None:raise ValueError("ENI device index unavailable")
                        candidate=suffix_name(base,"eni",f"eth{idx}",loc[-7:]); evidence=f"ENI {loc} -> {path}"
                elif kind=="eip":
                    obj=ec2.describe_addresses(AllocationIds=[loc]).get("Addresses",[])
                    if len(obj)!=1: raise ValueError("EIP not found")
                    tags=tagmap(obj[0].get("Tags",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:candidate,evidence,_=self.eip_owner(region,loc)
                elif kind=="nat":
                    nat=ec2.describe_nat_gateways(NatGatewayIds=[loc]).get("NatGateways",[])
                    if len(nat)!=1:raise ValueError("NAT not found")
                    o=nat[0];tags=tagmap(o.get("Tags",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:
                        candidate,evidence=self.nat_owner(region,o);confidence="medium"
                elif kind=="endpoint":
                    end=ec2.describe_vpc_endpoints(VpcEndpointIds=[loc]).get("VpcEndpoints",[])
                    if len(end)!=1:raise ValueError("VPC endpoint not found")
                    o=end[0];tags=tagmap(o.get("Tags",[]))
                    if name_state(tags) in NAME_CANDIDATE_STATES:
                        vpc=self.vpc(region,o["VpcId"])
                        vn=meaningful(name_of(vpc.get("Tags",[])))
                        ss=[self.subnet(region,id) for id in o.get("SubnetIds",[])]
                        names=[meaningful(name_of(s.get("Tags",[]))) for s in ss]
                        if not vn or not names or any(n is None or name_scope_prefix(n)!=name_scope_prefix(vn) for n in names):
                            raise ValueError("VPC endpoint shared/ambiguous; require uniformly named VPC and all subnets")
                        svc=o["ServiceName"].split(".")[-1]
                        candidate=suffix_name(vn,"vpce",svc,loc[-6:]);confidence="medium"
                        evidence=f"endpoint {loc} -> VPC {o['VpcId']} Name={vn} and {len(ss)} same-namespace subnets"
                res["write_target"]=loc
            elif kind in ("rds_cluster","rds_instance"):
                rds=self.client("rds",region)
                if kind=="rds_cluster":
                    if re.fullmatch(r"cluster-[a-z0-9]{14,}",loc,re.I):
                        # CUR normalizes IDs to lowercase but AWS RDS reports
                        # DbClusterResourceId with uppercase characters.
                        # AWS filters are case-sensitive: scan read-only pages
                        # and compare case-insensitively before proposing.
                        results=[];marker=None
                        for _ in range(1000):
                            query={"MaxRecords":100}
                            if marker:query["Marker"]=marker
                            page=rds.describe_db_clusters(**query)
                            results.extend(c for c in page.get("DBClusters",[])
                                           if c.get("DbClusterResourceId","").casefold()==loc.casefold())
                            marker=page.get("Marker")
                            if not marker:break
                        else:
                            raise ValueError("RDS cluster listing exceeded 1000 pages")
                    else:
                        results=rds.describe_db_clusters(DBClusterIdentifier=loc).get("DBClusters",[])
                    if len(results)!=1:raise ValueError("RDS cluster not found/unique")
                    o=results[0];arn=o["DBClusterArn"]
                    if loc.lower().startswith("cluster-") and loc.casefold()!=o.get("DbClusterResourceId","").casefold():
                        raise ValueError("CUR RDS cluster resource id differs from resolved cluster")
                    tags=tagmap(rds.list_tags_for_resource(ResourceName=arn).get("TagList",[]))
                    anchor=meaningful(o.get("DBClusterIdentifier",""))
                    if not anchor:
                        raise ValueError("RDS cluster identifier is opaque; inspect member names manually")
                    candidate=anchor if anchor.endswith("-rds") or "-db-" in anchor else suffix_name(anchor,"rds")
                    evidence=f"CUR cluster {loc} -> DescribeDBClusters {o['DBClusterIdentifier']} / DbClusterResourceId={o.get('DbClusterResourceId','')} / ARN={arn}"
                    res["write_target"]=arn
                else:
                    results=rds.describe_db_instances(DBInstanceIdentifier=loc).get("DBInstances",[])
                    if len(results)!=1:raise ValueError("RDS DB instance not found")
                    o=results[0];arn=o["DBInstanceArn"]
                    tags=tagmap(rds.list_tags_for_resource(ResourceName=arn).get("TagList",[]))
                    identity=o["DBInstanceIdentifier"]
                    anchor=meaningful(identity)
                    cluster_id=o.get("DBClusterIdentifier")
                    if cluster_id:
                        clusters=rds.describe_db_clusters(DBClusterIdentifier=cluster_id).get("DBClusters",[])
                        if len(clusters)!=1:
                            raise ValueError("RDS parent cluster missing or ambiguous")
                        parent=clusters[0]
                        members={m.get("DBInstanceIdentifier") for m in parent.get("DBClusterMembers",[])}
                        if identity not in members:
                            raise ValueError("RDS instance not listed among DBClusterMembers; refusing inference")
                        cluster_tags=tagmap(rds.list_tags_for_resource(ResourceName=parent["DBClusterArn"]).get("TagList",[]))
                        parent_name=meaningful(name_of(cluster_tags)) or meaningful(parent["DBClusterIdentifier"])
                        if not parent_name:
                            raise ValueError("RDS parent cluster has no identifiable Name/identifier")
                        if anchor and name_scope_prefix(anchor)!=name_scope_prefix(parent_name):
                            raise ValueError("RDS parent and child Name namespaces conflict")
                        if not anchor:
                            anchor=suffix_name(parent_name,"instance",o.get("DbiResourceId",identity)[-7:].lower())
                            confidence="medium"
                        evidence=(f"RDS {identity} -> DBClusterIdentifier={cluster_id} -> "
                                  f"DBClusterMembers includes {identity} -> "
                                  f"cluster Name={name_of(cluster_tags) or '(unset)'} "
                                  f"/ clusterId={parent['DBClusterIdentifier']} "
                                  f"/ instance Product={tags.get('Product','(unset)')}")
                    else:
                        evidence=f"RDS standalone DBInstanceIdentifier={identity} (no parent cluster)"
                    if not anchor:
                        raise ValueError("RDS instance and cluster lack a descriptive Name namespace")
                    candidate=anchor if anchor.endswith("-rds") or "-db-" in anchor else suffix_name(anchor,"rds")
                    # Product/Name mapping is external and never gates a proposal.
                    res["write_target"]=arn
            elif kind=="opensearch":
                os=self.client("opensearch",region)
                o=os.describe_domain(DomainName=loc)["DomainStatus"];arn=o["ARN"]
                tags=tagmap(os.list_tags(ARN=arn).get("TagList",[]))
                anchor=meaningful(o["DomainName"])
                if not anchor:raise ValueError("OpenSearch domain lacks a structured namespace")
                candidate=anchor if "opensearch" in anchor else suffix_name(anchor,"opensearch")
                evidence=f"DescribeDomain {loc} -> domain {o['DomainName']}";res["write_target"]=arn
            elif kind=="elbv2":
                c=self.client("elbv2",region)
                o=c.describe_load_balancers(LoadBalancerArns=[loc]).get("LoadBalancers",[])
                if len(o)!=1:raise ValueError("load balancer not found")
                tags=tagmap(c.describe_tags(ResourceArns=[loc])["TagDescriptions"][0]["Tags"])
                anchor=meaningful(o[0]["LoadBalancerName"])
                if not anchor:raise ValueError("LB name lacks a structured namespace")
                role={"application":"alb","network":"nlb","gateway":"gwlb"}.get(o[0]["Type"],"lb")
                candidate=anchor if anchor.endswith("-"+role) else suffix_name(anchor,role)
                evidence=f"LoadBalancer {loc} -> LoadBalancerName={o[0]['LoadBalancerName']}";res["write_target"]=loc
            elif kind=="apigw_stage":
                api_id,stage,arn=loc.split("|",2); c=self.client("apigateway",region)
                o=c.get_rest_api(restApiId=api_id)
                tags=tagmap(c.get_tags(resourceArn=arn).get("tags",{}))
                anchor=meaningful(o.get("name",""))
                if not anchor:raise ValueError("REST API name lacks a structured namespace")
                stage_anchor=meaningful(stage)
                if stage_anchor and name_scope_prefix(stage_anchor)==name_scope_prefix(anchor):
                    candidate=suffix_name(stage_anchor,"apigateway-stage")
                else:
                    candidate=suffix_name(anchor,"stage",stage)
                evidence=f"REST API stage {stage} -> GetRestApi({api_id}) name={o['name']}";res["write_target"]=arn
            elif kind=="cloudfront":
                c=self.client("cloudfront","us-east-1")
                distid=loc.rsplit("/",1)[-1]
                tags=tagmap(c.list_tags_for_resource(Resource=loc)["Tags"].get("Items",[]))
                conf=c.get_distribution_config(Id=distid)["DistributionConfig"]
                origins=[o["DomainName"].lower() for o in conf.get("Origins",{}).get("Items",[])]
                # Origins are provenance, not arbitrary opaque distribution ids.
                anchors=[]
                for origin in origins:
                    host=origin.removesuffix(".")
                    start=host.split(".")[0]
                    anchor=meaningful(start)
                    if not anchor:raise ValueError(f"CloudFront origin lacks a structured namespace: {host}")
                    anchors.append(anchor)
                if not anchors or len({name_scope_prefix(x) for x in anchors})!=1:
                    raise ValueError("CloudFront has no origins or conflicting Name namespaces")
                anchor=anchors[0] if len(anchors)==1 else name_scope_prefix(anchors[0])
                comment=conf.get("Comment","")
                aliases=conf.get("Aliases",{}).get("Items",[])
                role=""
                if "resize" in comment.lower():
                    role="image-resize" if ("image" in comment.lower()) else "resize"
                elif any(a.startswith("image.") or a.startswith("static.image.") for a in aliases):
                    role="image"
                # No arbitrary Comment->Product mapping. A Comment is weak evidence
                # of purpose, while actual origin remains the ownership anchor.
                candidate=suffix_name(anchor,*([role] if role else []),"cloudfront",distid[-7:].lower())
                evidence=(f"CloudFront {distid} -> origins={origins}; "
                          f"comment={comment!r}; aliases={aliases}; anchor={anchor}")
                res["write_target"]=loc
                confidence="medium" # CloudFront may be shared; require explicit approval
            elif kind=="athena_workgroup":
                c=self.client("athena",region)
                tags=tagmap(c.list_tags_for_resource(ResourceARN=loc).get("Tags",[]))
                wg=loc.rsplit("/",1)[-1];o=c.get_work_group(WorkGroup=wg)["WorkGroup"]
                anchor=meaningful(o["Name"])
                if not anchor:raise ValueError("Athena workgroup name is not product-identifiable")
                candidate=suffix_name(anchor,"athena-workgroup")
                evidence=f"Athena workgroup ARN -> WorkGroup.Name={o['Name']}";res["write_target"]=loc
            elif kind=="log_group":
                c=self.client("logs",region)
                # Complete LogGroup ARN requires account; do NOT append :*.
                arn=f"arn:aws:logs:{region}:{self.account}:log-group:{loc}"
                tags=tagmap(c.list_tags_for_resource(resourceArn=arn).get("tags",{}))
                anchor=meaningful(loc)
                if anchor is None and loc.startswith("/aws/lambda/"):
                    function=loc.rsplit("/",1)[-1]
                    conf=self.client("lambda",region).get_function_configuration(FunctionName=function)
                    anchor=meaningful(conf.get("FunctionName",""))
                    if anchor:evidence=f"log group {loc} -> lambda function {function}"
                if not anchor:raise ValueError("LogGroup cannot be linked to a structured resource name")
                candidate=anchor if anchor.endswith("-log") or anchor.endswith("-logs") else suffix_name(anchor,"logs")
                if not evidence:evidence=f"LogGroup explicitly named {loc}"
                res["write_target"]=arn
            elif kind=="lambda":
                c=self.client("lambda",region);conf=c.get_function_configuration(FunctionName=loc)
                tags=tagmap(c.list_tags(Resource=conf["FunctionArn"]).get("Tags",{}))
                anchor=meaningful(conf.get("FunctionName",""))
                if not anchor:raise ValueError("Lambda function name lacks a structured namespace")
                candidate=anchor if anchor.endswith("-lambda") else suffix_name(anchor,"lambda")
                evidence=f"Lambda {loc} -> function={conf['FunctionName']}";res["write_target"]=conf["FunctionArn"]
            elif kind=="wafv2":
                c=self.client("wafv2",region)
                tags=tagmap(c.list_tags_for_resource(ResourceARN=loc).get("TagInfoForResource",{}).get("TagList",[]))
                acl_name,idpart=loc.split("/webacl/",1)[-1].split("/",1)
                scope="CLOUDFRONT" if ":global/" in loc else "REGIONAL"
                webacl=c.get_web_acl(Name=acl_name,Scope=scope,Id=idpart)["WebACL"]
                if webacl.get("ARN")!=loc:
                    raise ValueError("WAF WebACL ARN does not match live returned ACL")
                anchor=meaningful(webacl["Name"])
                if not anchor:raise ValueError("WAF ACL name lacks a structured namespace")
                candidate=anchor if anchor.endswith("-waf") else suffix_name(anchor,"waf")
                evidence=f"WAF GetWebACL {webacl['Name']} id={idpart} ARN={loc}";res["write_target"]=loc
            elif kind=="s3_bucket":
                c=self.client("s3","us-east-1")
                # Neither CUR nor account ownership is sufficient: ExpectedBucketOwner is mandatory.
                try:
                    tags=tagmap(c.get_bucket_tagging(Bucket=loc,ExpectedBucketOwner=self.account).get("TagSet",[]))
                except Exception as e:
                    code=getattr(e,"response",{}).get("Error",{}).get("Code","")
                    if code in ("NoSuchTagSet","NoSuchTagSetError"):
                        tags={}
                    else:raise
                anchor=meaningful(loc)
                if not anchor:raise ValueError("Bucket name lacks a structured namespace")
                if anchor.startswith("dh-"): anchor=anchor[3:]
                candidate=anchor if anchor.endswith("-s3") else suffix_name(anchor,"s3")
                evidence=f"Bucket {loc} (ExpectedBucketOwner={self.account}) -> bucket naming convention"
                res["write_target"]=loc;confidence="medium"
            else:
                raise ValueError("Unsupported AWS service/resource type")
            observed = name_state(tags)
            res.update(name_state=observed,
                       name_key_present="Name" in tags if isinstance(tags, dict) else None,
                       name_raw_value=name_of(tags),
                       existing_name=name_of(tags) or "")
            if observed == "NONEMPTY":
                res.update(status="already_named", evidence=f"current nonempty Name protected; unchanged: {name_of(tags)}")
                return res
            if observed == "UNKNOWN":
                res.update(status="manual_review", evidence="Name tag state UNKNOWN: unreadable or malformed; no proposal")
                return res
            if not candidate or not meaningful(candidate):
                raise ValueError("Candidate lacks a structured Name namespace")
            if shared_scope(candidate):
                # A shared-service Name describes infrastructure only; it is
                # NOT an assertion of single-product ownership.
                confidence="medium"
                evidence += "; shared infrastructure: descriptive Name only, no product classification"
            res.update(status="proposed", proposed_name=candidate, confidence=confidence,evidence=evidence)
        except Exception as e:
            observed = name_state(tags)
            res.update(name_state=observed,
                       name_key_present="Name" in tags if isinstance(tags, dict) else None,
                       name_raw_value=name_of(tags) if isinstance(tags, dict) else None,
                       existing_name=(name_of(tags) or "") if isinstance(tags, dict) else "")
            if observed == "NONEMPTY":
                res.update(status="already_named", evidence=f"current nonempty Name protected; unchanged: {name_of(tags)}")
                return res
            from botocore.exceptions import BotoCoreError, ClientError
            if isinstance(e,(BotoCoreError,ClientError)):
                res["status"]="api_error"  # failed read MUST never fall back to guessing
            res["evidence"]=f"{type(e).__name__}: {e}"
        return res

    def write_name(self, item: dict):
        """Fail closed for ALL callers, including direct invocation.

        Unlike a read-then-write check, this disables overwriting under races.
        Adding tag write APIs requires a separately reviewed security change.
        """
        raise RuntimeError(SAFETY_HOLD)


def build_session(profile: str | None):
    import boto3
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def assert_account(session, expected: str):
    actual=session.client("sts").get_caller_identity()["Account"]
    if actual!=expected:
        raise SystemExit(f"ABORT: AWS STS account {actual} != expected {expected}")


@contextmanager
def _private_directory_fd(path: Path, *, create: bool = True):
    """Open every ancestor with O_NOFOLLOW, rooted at / (POSIX).

    Relative paths are made absolute without resolving symlinks. mkdir and
    open are anchored to the previously opened directory file descriptor,
    so a symlink substitution between checking and opening cannot redirect
    file creation. Existing directories are never chmod'd.
    """
    path = Path(path)
    if ".." in path.parts:
        raise ValueError(f"Output path must not contain '..': {path}")
    for feature in ("O_DIRECTORY", "O_NOFOLLOW"):
        if not hasattr(os, feature) or os.name != "posix":
            raise RuntimeError("Secure report output requires POSIX O_DIRECTORY and O_NOFOLLOW")
    absolute = path.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    dfd = os.open("/", flags)
    try:
        for component in absolute.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=dfd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, mode=0o700, dir_fd=dfd)
                except FileExistsError:
                    # A competing creator may have installed a symlink.
                    # In that case the O_NOFOLLOW open below rejects it.
                    pass
                try:
                    next_fd = os.open(component, flags, dir_fd=dfd)
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise ValueError(f"Output ancestor is not a real directory: {component}") from exc
                    raise
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError(f"Output ancestor is not a real directory: {component}") from exc
                raise
            os.close(dfd)
            dfd = next_fd
        yield dfd
    finally:
        os.close(dfd)


def ensure_private_output_dir(path: Path):
    """Reject symlinks in ALL ancestors; create absent directories as 0700."""
    with _private_directory_fd(path):
        pass


@contextmanager
def private_output(path: Path, *, newline=None, encoding="utf-8"):
    """O_EXCL/0600 and dirfd-based O_NOFOLLOW for the full output path."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with _private_directory_fd(path.parent) as dfd:
        fd = os.open(path.name, flags, 0o600, dir_fd=dfd)
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as stream:
            yield stream


def write_json(path: Path, data: dict):
    with private_output(path) as stream:
        stream.write(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def safe_csv(value):
    """Prevent spreadsheet formula execution when opening reports."""
    if not isinstance(value, str):
        return value
    if value.lstrip(" \t\r\n\ufeff").startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def safe_csv_row(row):
    return {key: safe_csv(value) for key, value in row.items()}


def preflight_outputs(paths):
    existing = [str(path) for path in paths if os.path.lexists(path)]
    if existing:
        raise SystemExit("ABORT: output already exists (never overwrite): " + ", ".join(existing))


def create_audit_journal(path: Path):
    """Create a private audit journal in a symlink-safe anchored directory."""
    path = Path(path)
    with _private_directory_fd(path.parent) as dfd:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dfd)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dfd)


def journal_event(path: Path, event: dict):
    """Append/fsync local audit event without following symlink components.

    This is a review-only journal. All AWS write APIs remain disabled.
    """
    path = Path(path)
    payload = json.dumps({"utc": datetime.now(timezone.utc).isoformat(), **event}, ensure_ascii=False, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
    with _private_directory_fd(path.parent, create=False) as dfd:
        fd = os.open(path.name, flags, dir_fd=dfd)
        try:
            data = payload.encode("utf-8")
            while data:
                written = os.write(fd, data)
                if written <= 0:
                    raise OSError("Audit journal short write")
                data = data[written:]
            os.fsync(fd)
        finally:
            os.close(fd)


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def proposal_key(rec: dict):
    """v3.6 identities cannot collide with the v3.5 review-key namespace.

    Include state and raw previous Name so ABSENT and EMPTY stay distinct.
    This is a local review identifier, not an execution authorization.
    """
    material=json.dumps({"schema":2,"namespace":"name-tagger-v3.6-readonly",
                         **{k:rec.get(k) for k in ("kind","locator","region","proposed_name",
                                                   "name_state","name_key_present","name_raw_value")}},
                        ensure_ascii=False,sort_keys=True,separators=(",",":"))
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def resource_arn(rec: dict, account: str) -> str:
    """Derive canonical report ARN from verified write target; never use this to write."""
    target = str(rec.get("write_target") or "")
    if target.startswith("arn:"):
        return target
    kind = rec.get("kind", "")
    region = rec.get("region", "")
    if kind in ("rds_instance", "rds_cluster"):
        rtype = "db" if kind == "rds_instance" else "cluster"
        if not target:
            target = str(rec.get("locator", ""))
        if target and not target.startswith(("db-", "cluster-")):
            return f"arn:aws:rds:{region}:{account}:{rtype}:{target}"
    ec2 = {
        "instance": "instance", "volume": "volume", "snapshot": "snapshot",
        "eni": "network-interface", "eip": "elastic-ip",
        "nat": "natgateway", "endpoint": "vpc-endpoint",
    }
    if kind in ec2:
        rid = target or str(rec.get("locator", ""))
        if rid:
            return f"arn:aws:ec2:{region}:{account}:{ec2[kind]}/{rid}"
    if kind == "log_group" and rec.get("locator"):
        return f"arn:aws:logs:{region}:{account}:log-group:{rec['locator']}"
    if kind == "s3_bucket" and rec.get("locator"):
        return f"arn:aws:s3:::{rec['locator']}"
    return str(rec.get("locator", "")) if str(rec.get("locator", "")).startswith("arn:") else ""


def write_action_csv(path: Path, records: list[dict], account: str, *, mode: str):
    """Audit-friendly report: list ARN, old/proposed Name, result, and evidence."""
    cols = ["utc", "account", "mode", "result", "resource_arn", "kind", "region",
            "resource_id", "name_state", "name_key_present", "name_raw_value",
            "name_before", "name_proposed", "name_after",
            "effective_usage_cost_usd", "confidence", "proposal_id", "detail"]
    timestamp = datetime.now(timezone.utc).isoformat()
    with private_output(path, newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for row in records:
            result = row.get("result", row.get("status", ""))
            new_name = row.get("name", row.get("proposed_name", ""))
            arn = row.get("resource_arn") or resource_arn(row, account)
            writer.writerow(safe_csv_row({
                "utc": timestamp, "account": account, "mode": mode,
                "result": result, "resource_arn": arn,
                "kind": row.get("kind", ""), "region": row.get("region", ""),
                "resource_id": row.get("locator", ""),
                "name_state": row.get("name_state", "UNKNOWN"),
                "name_key_present": row.get("name_key_present"),
                "name_raw_value": row.get("name_raw_value"),
                "name_before": row.get("existing_name", ""),
                "name_proposed": new_name,
                "name_after": row.get("name_after", "") if result in ("applied", "applied_verified") else "",
                "effective_usage_cost_usd": row.get("effective_usage_cost_usd", ""),
                "confidence": row.get("confidence", ""),
                "proposal_id": row.get("proposal_id", ""),
                "detail": row.get("detail", row.get("evidence", "")),
            }))
        fh.flush()
        os.fsync(fh.fileno())
    return path


def show_aws_identity(session, expected: str) -> dict:
    """Read-only STS + best-effort IAM GetRole; never assume role name proves privileges."""
    ident = session.client("sts").get_caller_identity()
    actual, principal = ident.get("Account", ""), ident.get("Arn", "")
    if actual != expected:
        raise SystemExit(f"ABORT: AWS account {actual} != expected {expected}; no changes")
    print("\n=== 認証主体（読み取り確認） ===")
    print(f"Account : {actual}")
    print(f"Principal ARN : {principal}")
    print(f"UserId : {ident.get('UserId', '')}")
    role_match = re.match(r"^arn:[^:]+:sts::\d+:assumed-role/([^/]+)/(.+)$", principal)
    if role_match:
        role_name, session_name = role_match.groups()
        print(f"IAM Role name : {role_name}")
        print(f"Role session : {session_name}")
        try:
            meta = session.client("iam").get_role(RoleName=role_name)["Role"]
            print(f"IAM Role ARN : {meta.get('Arn', '')}")
            print(f"IAM Role path : {meta.get('Path', '')}")
            print(f"Role max duration : {meta.get('MaxSessionDuration', '')} seconds")
            print(f"Role description : {meta.get('Description', '')}")
        except Exception as exc:
            # STS alone proves the current identity. IAM GetRole might be denied.
            print(f"IAM role metadata : unavailable ({type(exc).__name__}); STS identity confirmed")
    else:
        print("IAM assumed role : not detected; check this principal carefully")
    print("Effective permissions : NOT VERIFIED by STS or IAM GetRole")
    print("=============================\n")
    return ident


def offer_remote_login(args):
    """Login is explicitly human-initiated. AWS CLI manages auth without exposing tokens."""
    cmd = ["aws", "login", "--remote"]
    if getattr(args, "profile", None):
        cmd.extend(["--profile", args.profile])
    print("\nAWS CLI のリモートログイン：", " ".join(cmd), flush=True)
    method = getattr(args, "login", "ask")
    if method == "ask":
        if not sys.stdin.isatty():
            raise SystemExit("Interactive login choice requires a terminal; use --login skip or --login remote")
        choice = input("ログインを実行しますか？ [L=実行 / S=既存セッション / N=中止] (既定S): ").strip().lower() or "s"
    else:
        choice = {"remote": "l", "skip": "s"}[method]
    if choice == "n":
        print("キャンセル: AWS変更なし")
        return False
    if choice not in ("l", "s"):
        raise SystemExit("Invalid login choice; no AWS changes")
    if choice == "l":
        print("AWS CLI を起動します。ブラウザ上の認証コードは画面上で入力してください。")
        try:
            subprocess.run(cmd, check=True)
        except FileNotFoundError as exc:
            raise SystemExit("AWS CLI is not installed") from exc
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"AWS login failed (exit {exc.returncode}); no tag changes") from exc
    return True


def choose_mode(args) -> str:
    selected = getattr(args, "mode", None)
    if selected is None:
        if not sys.stdin.isatty():
            raise SystemExit("Interactive Y/N/dryrun choice requires a terminal; use --mode dryrun or --mode n")
        selected = input("動作を選択 [Y=候補レビュー記録(タグ変更なし) / N=中止 / dryrun=レポートのみ] (既定dryrun): ").strip().lower() or "dryrun"
    selected = selected.strip().lower()
    if selected not in ("y", "n", "dryrun"):
        raise SystemExit("Invalid mode; choose Y, N, or dryrun; no AWS changes")
    if selected == "y" and not sys.stdin.isatty():
        raise SystemExit("Y mode requires interactive terminal and explicit per-resource approvals")
    return selected


def run_interactive(args):
    """Human-controlled single entry point. Dryrun never invokes an AWS write API."""
    if not re.fullmatch(r"\d{12}", args.account):
        raise SystemExit("--account must be 12 digits")
    # Validate local paths before offering credentials or any network access.
    for filename in args.cur:
        if not Path(filename).is_file():
            raise SystemExit(f"CUR missing: {filename}")
    if not offer_remote_login(args):
        return
    session = build_session(args.profile)
    ident = show_aws_identity(session, args.account)
    selected = choose_mode(args)
    if selected == "n":
        print("N: 中止しました。AWSタグ・ローカル計画は未変更です。")
        return
    print(f"選択されたモード: {selected}")
    out = Path(args.output)
    if selected == "y":
        preflight_outputs([out.with_suffix(".selected.csv"),
                           out.with_suffix(".audit.jsonl"),
                           out.with_suffix(".audit.csv")])
    doc = plan(args, session=session, extra_mode="dryrun" if selected == "dryrun" else None)
    if selected == "dryrun":
        print(f"DRYRUN_REPORT={out.with_suffix('.result.csv')} | writes=0 | AWS変更なし")
        return
    assert selected == "y"
    selectable = [r for r in doc["records"] if r["status"] == "proposed"
                  and r["confidence"] in ({"high", "medium"} if args.allow_medium else {"high"})
                  and r["kind"] != "s3_bucket"]
    print(f"個別承認可能: {len(selectable)}件 / 上限 {args.max_writes}件")
    if not selectable:
        print("レビュー可能な候補なし。AWS変更なし")
        return
    selected_ids = set()
    for rec in selectable:
        if len(selected_ids) >= args.max_writes:
            print("レビュー候補の上限に達したため以降は選択されません")
            break
        arn = resource_arn(rec, args.account)
        print(f"\nARN: {arn}\nName: {rec['proposed_name']}\nCost: ${rec['effective_usage_cost_usd']:.2f} "
              f"Confidence: {rec['confidence']}\nEvidence: {rec['evidence']}")
        approval = input("この1件を承認しますか？ [y/N]: ").strip().lower()
        if approval == "y":
            selected_ids.add(rec["proposal_id"])
        elif approval not in ("", "n"):
            raise SystemExit("Invalid approval input; no AWS changes")
    preview = out.with_suffix(".selected.csv")
    with private_output(preview, newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=["approved", "proposal_id", "kind", "locator", "region", "name_state", "name_key_present", "name_raw_value", "proposed_name"])
        writer.writeheader()
        for rec in doc["records"]:
            writer.writerow(safe_csv_row({"approved": "YES" if rec["proposal_id"] in selected_ids else "",
                **{col: rec.get(col, "") for col in ("proposal_id", "kind", "locator", "region", "name_state", "name_key_present", "name_raw_value", "proposed_name")}}))
    if not selected_ids:
        print(f"選択された対象なし。REVIEW={preview} | AWS変更なし")
        return
    print(f"\n承認候補: {len(selected_ids)} 件。ファイル: {preview}")
    print("SAFETY HOLD: Y is REVIEW ONLY; no AWS tag changes will occur.")
    token = input(f"承認済み候補を保留レポートに記録する場合 'REVIEW {args.account}' と入力: ").strip()
    if token != f"REVIEW {args.account}":
        print(f"確認入力が一致しないため中止。REVIEW={preview} | AWS変更なし")
        return
    journal = out.with_suffix(".audit.jsonl")
    create_audit_journal(journal)
    journal_event(journal, {"event": "review_started", "account": args.account,
                            "principal_arn": ident.get("Arn", ""),
                            "plan_sha256": sha256(out), "writes_permitted": False})
    records = []
    for rec in doc["records"]:
        if rec["proposal_id"] not in selected_ids:
            continue
        row = {**rec, "name": rec["proposed_name"], "result": "blocked_by_safety_hold",
               "detail": SAFETY_HOLD, "name_after": ""}
        journal_event(journal, {"event": "write_blocked", "principal_arn": ident.get("Arn", ""),
                                "account": args.account, "resource_arn":resource_arn(rec,args.account),
                                "proposal_id":rec["proposal_id"], "name_proposed":rec["proposed_name"],
                                "name_state":rec["name_state"], "name_key_present":rec["name_key_present"],
                                "name_raw_value":rec["name_raw_value"], "reason":SAFETY_HOLD})
        records.append(row)
    report = out.with_suffix(".audit.csv")
    write_action_csv(report, records, args.account, mode="Y_REVIEW_ONLY")
    journal_event(journal, {"event":"review_completed", "count": len(records), "writes": 0})
    print(f"REVIEW_AUDIT={journal}; REVIEW_REPORT={report}; writes=0; AWS変更なし")


def publish_staged_reports(pairs: list[tuple[Path, Path]]):
    """Best-effort grouped publication using dirfd-anchored, nofollow links.

    This mitigates symlink substitution but does not make multi-file
    publication atomic. After SIGKILL or power loss, partial outputs can remain.
    """
    if not pairs:
        return
    preflight_outputs([dst for _, dst in pairs])
    sources = {Path(src).parent for src, _ in pairs}
    destinations = {Path(dst).parent for _, dst in pairs}
    if len(sources) != 1 or len(destinations) != 1:
        raise ValueError("All staged reports must share one source and destination directory")
    source_dir = next(iter(sources))
    dest_dir = next(iter(destinations))
    published = []
    with _private_directory_fd(source_dir, create=False) as src_fd:
        with _private_directory_fd(dest_dir, create=False) as dst_fd:
            try:
                for src, dst in pairs:
                    os.link(Path(src).name, Path(dst).name,
                            src_dir_fd=src_fd, dst_dir_fd=dst_fd, follow_symlinks=False)
                    published.append(Path(dst).name)
                os.fsync(dst_fd)
            except BaseException:
                for name in reversed(published):
                    os.unlink(name, dir_fd=dst_fd)
                raise


def write_review_csv(path: Path, records: list[dict]):
    columns=["approved","proposal_id","kind","locator","region","effective_usage_cost_usd",
             "status","name_state","name_key_present","name_raw_value","existing_name",
             "confidence","proposed_name","evidence"]
    with private_output(path, newline="", encoding="utf-8-sig") as fh:
        writer=csv.DictWriter(fh,fieldnames=columns,extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow(safe_csv_row({"approved":"",**record}))
        fh.flush()
        os.fsync(fh.fileno())


def plan(args, session=None, *, extra_mode=None):
    if not re.fullmatch(r"\d{12}",args.account):raise SystemExit("--account must be 12 digits")
    if not args.cur:raise SystemExit("Provide at least one --cur .csv.gz file")
    out=Path(args.output)
    review=out.with_suffix(".review.csv")
    report=out.with_suffix(".report.csv")
    result=out.with_suffix(".result.csv")
    destinations=[out, review, report] + ([result] if extra_mode == "dryrun" else [])
    preflight_outputs(destinations)
    kind_filter = None
    if args.kinds is not None:
        kind_filter = {kind.strip() for kind in args.kinds.split(",") if kind.strip()}
        if not kind_filter:
            raise ValueError("--kinds must include at least one supported kind")
        unknown = kind_filter - SUPPORTED_KINDS
        if unknown:
            raise ValueError(f"Unsupported --kinds value(s): {', '.join(sorted(unknown))}")
    month,candidates=cur_candidates(args.cur,args.month,args.min_cost,args.max_resources,args.account,kind_filter=kind_filter)
    session = session or build_session(args.profile)
    assert_account(session,args.account)
    investigator=Investigator(session,args.account, retries=3)
    records=[]
    for idx,item in enumerate(candidates,1):
        info=investigator.resolve(item)
        rec={**item,**info}
        rec["proposal_id"]=proposal_key(rec)
        rec["resource_arn"] = resource_arn(rec, args.account)
        records.append(rec)
        print(f"[{idx:>3}/{len(candidates)}] {item['effective_usage_cost_usd']:8.2f} {rec['status']:>14} {rec['kind']:16} {rec['proposed_name'] or rec['locator'][:55]}",file=sys.stderr)
    # A truncated ID suffix can collide. Never auto-propose the same Name
    # for two distinct write targets inside the same reviewed batch.
    byname=defaultdict(set)
    for rec in records:
        if rec["status"]=="proposed":
            byname[rec["proposed_name"]].add((rec["region"],rec["kind"],rec["write_target"]))
    for rec in records:
        if rec["status"]=="proposed" and len(byname[rec["proposed_name"]])>1:
            rec.update(status="manual_review",confidence="none",
                       evidence=f"Proposed Name collision in batch: {rec['proposed_name']}",proposed_name="")
            rec["proposal_id"]=proposal_key(rec)
    doc={"schema_version":2,"generated_at_utc":datetime.now(timezone.utc).isoformat(),"account":args.account,"period":month,
         "metric":"Usage/DiscountedUsage(RI effective)/SavingsPlanCoveredUsage(SP effective); excludes one-time fees, unallocated and no-resource charges",
         "min_cost_usd":args.min_cost,"count":len(records),"records":records}
    ensure_private_output_dir(out.parent)
    # NEW-003 mitigation: create the complete file set in a mode-0700 staging
    # directory; publish only after every file has been flushed and fsync'd.
    with tempfile.TemporaryDirectory(prefix=f".{out.stem}.stage-", dir=out.parent) as staging:
        stage=Path(staging)
        staged=[stage / name.name for name in destinations]
        write_json(staged[0],doc)
        write_review_csv(staged[1],records)
        write_action_csv(staged[2],records,args.account,mode="plan")
        if extra_mode == "dryrun":
            rows=[{**r,"result":"dryrun_not_modified" if r["status"] == "proposed" else r["status"]}
                  for r in records]
            write_action_csv(staged[3],rows,args.account,mode="dryrun")
        publish_staged_reports(list(zip(staged,destinations)))
    print(f"PLAN={out} SHA256={sha256(out)}\nREVIEW={review}\nREPORT={report}\nNo AWS tags were changed.")
    return doc


def apply(args):
    """Disabled in safety-hold release, including programmatic direct calls."""
    raise SystemExit("ABORT: " + SAFETY_HOLD)


def parse_cli(argv=None):
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    sub=ap.add_subparsers(dest="command",required=True)
    p=sub.add_parser("plan",help="Read CUR and AWS metadata; never write tags")
    p.add_argument("--cur",action="append",required=True,help="One gzipped CUR v2 CSV (repeat for many months)")
    p.add_argument("--month",help="Billing month YYYY-MM; defaults to latest detected")
    p.add_argument("--account",required=True,help="Strict 12-digit AWS account guard")
    p.add_argument("--profile",help="AWS profile (aws login supported with compatible Boto3/CRT)")
    p.add_argument("--min-cost",type=float,default=DEFAULT_THRESHOLD,help="Effective monthly-to-date cost minimum, USD")
    p.add_argument("--max-resources",type=int,default=100,help="Limit number of AWS metadata lookups")
    p.add_argument("--kinds", help="Comma-separated types, e.g. volume,snapshot,instance,eni; optional")
    p.add_argument("--output",default="name_tag_plan.json")
    p.set_defaults(func=plan)
    r=sub.add_parser("run",help="Interactive: remote login prompt -> role info -> Y/N/dryrun -> reports")
    r.add_argument("--cur",action="append",required=True,help="Gzipped CUR v2 CSV")
    r.add_argument("--month",help="Billing month YYYY-MM")
    r.add_argument("--account",required=True,help="Strict AWS account guard")
    r.add_argument("--profile",help="AWS CLI login profile (recommended)")
    r.add_argument("--login",choices=("ask","remote","skip"),default="ask",help="Prompt, launch aws login --remote, or reuse existing login")
    r.add_argument("--mode",type=str.lower,choices=("y","n","dryrun"),help="Noninteractive dryrun/N or interactive Y; omit for a prompt")
    r.add_argument("--min-cost",type=float,default=DEFAULT_THRESHOLD)
    r.add_argument("--max-resources",type=int,default=100)
    r.add_argument("--kinds")
    r.add_argument("--output",default="name_tag_plan.json")
    r.add_argument("--max-writes",type=int,default=20)
    r.add_argument("--allow-medium",action="store_true",help="Also present medium-confidence proposals for per-row approval")
    r.set_defaults(func=run_interactive)
    a=sub.add_parser("apply",help="DISABLED: no AWS mutations in v3.6 safety-hold release")
    a.add_argument("--plan",required=True)
    a.add_argument("--sha256",required=True,help="Exact SHA-256 printed during plan")
    a.add_argument("--review",required=True,help="CSV with approved=YES on individually reviewed rows")
    a.add_argument("--account",required=True)
    a.add_argument("--profile")
    a.add_argument("--max-writes",type=int,default=20)
    a.add_argument("--allow-medium",action="store_true",help="Also allow individually approved medium-confidence proposals")
    a.add_argument("--log",default="name_tag_apply_audit.json")
    a.set_defaults(func=apply)
    args=ap.parse_args(argv)
    if args.command in ("plan", "run"):
        if args.min_cost<0 or args.max_resources<=0:ap.error("--min-cost must be nonnegative and --max-resources > 0")
        if args.month and not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])",args.month):ap.error("Invalid --month")
        if args.command == "run" and args.max_writes <= 0:ap.error("--max-writes must be positive")
    else:
        if not re.fullmatch(r"[0-9a-f]{64}",args.sha256):ap.error("--sha256 must be a 64-character lowercase hex string")
        if args.max_writes<=0:ap.error("--max-writes must be positive")
    return args


if __name__=="__main__":
    try:
        args = parse_cli()
        args.func(args)
    except Exception:
        raise
