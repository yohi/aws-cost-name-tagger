#!/usr/bin/env python3
"""CUR-driven AWS Name-tag proposals and read-only review workflow (v3.6 SAFETY HOLD).

All AWS name-tag mutation APIs are disabled pending an independently verified
atomic absent-or-empty-only write guarantee. Y stages approval proposals but never writes.

Python >= 3.10, boto3 >= 1.41.0. No additional dependencies.
"""
from __future__ import annotations

import argparse
import codecs
import csv
import errno
import gzip
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

DEFAULT_THRESHOLD = 10.0
DEFAULT_REPORT_OUTPUT = ".aws-cost-name-tagger/name_tag_plan.json"
# Offline limits apply to each complete CUR scan, before session creation.
# They cap gzip expansion, parsed rows, file count, and in-memory cardinality.
MAX_CUR_FILES = 64
MAX_CUR_ROWS = 2_000_000
MAX_CUR_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
MAX_CUR_LINE_BYTES = 1024 * 1024
MAX_CUR_LOGICAL_RECORD_BYTES = 1024 * 1024
MAX_CUR_FIELDS = 512
MAX_CUR_DISTINCT_RESOURCES = 250_000
# PR #14: explicit application-level AWS read budgets. These counts cover SDK
# operation invocations by this process, not credential-provider network calls
# or the wall-clock duration of an in-flight request.
MAX_AWS_READ_CALLS = 500
MAX_AWS_READ_ELAPSED_SECONDS = 120
MAX_RDS_CLUSTER_PAGES = 25
ACCOUNT_ID_PATTERN = re.compile(r"\d{12}")
REVIEW_CSV_SUFFIX = ".review.csv"
REPORT_CSV_SUFFIX = ".report.csv"
ACCOUNT_ERROR_MESSAGE = "--account must be 12 digits"
AWS_READ_CONNECT_TIMEOUT_SECONDS = 5
AWS_READ_TIMEOUT_SECONDS = 10
# Capture the actual OS implementation functions at import time: offline fault
# injection tests intentionally mock os.link/unlink/mkdir/stat later.
_REQUIRED_REPORT_DIR_FD_APIS = (os.open, os.mkdir, os.stat, os.link, os.unlink)
_REQUIRED_REPORT_NOFOLLOW_APIS = (os.stat, os.link)
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


def tagmap(tags, *, expected_shape=None, allow_missing_non_name_value=False) -> dict:
    """Validate the AWS API's response shape before Name candidate inference.

    AWS ingestion sites MUST pass expected_shape='list' or 'map'. None is
    reserved for pure helpers examining an already-normalized tag collection.
    Several list-tag service models allow an absent Value for non-Name keys;
    only those call sites pass allow_missing_non_name_value=True. Such values
    become '' and are never Name candidates. Missing Name Value remains
    UNKNOWN, irrespective of the service model.
    """
    if expected_shape not in (None, "list", "map"):
        raise ValueError("Unsupported tag collection shape contract")
    if expected_shape == "list" and not isinstance(tags, list):
        raise ValueError("AWS tag response requires a list")
    if expected_shape == "map" and not isinstance(tags, dict):
        raise ValueError("AWS tag response requires a map")
    if isinstance(tags, dict):
        if any(not isinstance(key, str) or not key or not isinstance(value, str)
               for key, value in tags.items()):
            raise ValueError("AWS tag map must contain nonempty string keys and string values")
        return dict(tags)
    if not isinstance(tags, list):
        raise ValueError("AWS tag collection is missing or malformed")
    result = {}
    for entry in tags:
        if (not isinstance(entry, dict)
                or not isinstance(entry.get("Key"), str)
                or not entry["Key"]):
            raise ValueError("AWS tag entry has an invalid Key")
        key = entry["Key"]
        if key in result:
            raise ValueError("AWS tag key is duplicated")
        if "Value" not in entry:
            if key.casefold() == "name" or not allow_missing_non_name_value:
                raise ValueError("AWS tag Value is missing")
            value = ""
        else:
            value = entry["Value"]
            if not isinstance(value, str):
                raise ValueError("AWS tag Value must be a string")
        result[key] = value
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
    """An included CUR monetary field must be a finite number, never a guess."""
    if not isinstance(x, str) or not x.strip():
        raise ValueError("CUR monetary amount missing or not a numeric string")
    try:
        number = float(x)
    except (ValueError, OverflowError) as exc:
        raise ValueError("CUR monetary amount is not numeric") from exc
    if not math.isfinite(number):
        raise ValueError("CUR monetary amount is not finite")
    return number


def cost_of(row: dict) -> float:
    typ = row["line_item_line_item_type"]
    if typ == "DiscountedUsage":
        return fnum(row.get("reservation_effective_cost"))
    if typ == "SavingsPlanCoveredUsage":
        return fnum(row.get("savings_plan_savings_plan_effective_cost"))
    if typ == "Usage":
        return fnum(row.get("line_item_unblended_cost"))
    return 0.0


def _cur_file_identity(info) -> tuple:
    # Detect ordinary file replacement, truncation, rewrites, and hardlinks.
    # This is not a same-UID hostile mutation or network-filesystem proof.
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


class _CURStreamState:
    """Only the counters and decoder for one bounded CUR gzip scan.

    Quoting state spans physical lines, then resets only after a fully parsed
    logical CSV record. Keep this object private to a single scan/pass.
    """

    def __init__(self, compressed, budget, checksum):
        self.compressed = compressed
        self.budget = budget
        self.checksum = checksum
        self.decoder = codecs.getincrementaldecoder("utf-8-sig")("strict")
        self.expanded = 0
        self.reset_record()

    def reset_record(self):
        self.record_bytes = 0
        self.delimiter_count = 0
        self.in_quotes = False
        self.at_field_start = True

    def _advance_quoted(self, text, pos):
        if text[pos] == '"':
            if pos + 1 < len(text) and text[pos + 1] == '"':
                return pos + 2
            self.in_quotes = False
        return pos + 1

    def _count_field(self):
        self.delimiter_count += 1
        if self.delimiter_count >= MAX_CUR_FIELDS:
            raise ValueError("CUR logical record field limit exceeded")
        self.at_field_start = True

    def scan_delimiters(self, text):
        pos = 0
        while pos < len(text):
            char = text[pos]
            if self.in_quotes:
                pos = self._advance_quoted(text, pos)
                continue
            if char == ',':
                self._count_field()
            elif char == '"' and self.at_field_start:
                self.in_quotes = True
                self.at_field_start = False
            elif char not in ('\r', '\n'):
                self.at_field_start = False
            pos += 1

    def bounded_lines(self):
        while True:
            chunk = self.compressed.readline(MAX_CUR_LINE_BYTES + 1)
            if not chunk:
                tail = self.decoder.decode(b"", final=True)
                if tail:
                    yield tail
                return
            if len(chunk) > MAX_CUR_LINE_BYTES:
                raise ValueError("CUR physical line size limit exceeded")
            self.expanded += len(chunk)
            self.budget["bytes"] += len(chunk)
            self.record_bytes += len(chunk)
            if self.budget["bytes"] > MAX_CUR_UNCOMPRESSED_BYTES:
                raise ValueError("CUR decompressed byte budget exceeded")
            if self.record_bytes > MAX_CUR_LOGICAL_RECORD_BYTES:
                raise ValueError("CUR logical record byte limit exceeded")
            self.checksum.update(chunk)
            decoded = self.decoder.decode(chunk, final=False)
            self.scan_delimiters(decoded)
            yield decoded


def _cur_validate_header(reader):
    header = reader.fieldnames
    if header is None:
        raise ValueError("CUR CSV header is missing")
    if len(header) != len(set(header)) or any(not h for h in header):
        raise ValueError("CUR header has duplicate or empty column names")
    required = {
        "bill_billing_period_start_date", "line_item_usage_account_id",
        "line_item_line_item_type", "line_item_resource_id",
        "line_item_unblended_cost", "product_region_code",
        "line_item_product_code", "line_item_currency_code",
    }
    if not required.issubset(header):
        raise ValueError("CUR header missing required columns: " +
                         ", ".join(sorted(required - set(header))))


def _cur_consume_rows(reader, budget, accept_row, stream):
    count = 0
    for row in reader:
        count += 1
        budget["rows"] += 1
        if budget["rows"] > MAX_CUR_ROWS:
            raise ValueError("CUR row budget exceeded")
        if None in row or any(value is None for value in row.values()):
            raise ValueError("CUR record has extra or missing fields")
        accept_row(row)
        stream.reset_record()
    return count


def _scan_cur_file(path: Path, budget: dict, accept_row) -> tuple:
    """Stream a bounded gzip CSV once and return a decoded-content receipt.

    Preserve record- and physical-line bounds before csv.DictReader(strict=True),
    as well as the compressed inode/metadata and decoded-content receipts.
    """
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("CUR input must be a regular file")
    checksum = hashlib.sha256()
    with path.open("rb") as raw:
        opened = os.fstat(raw.fileno())
        if _cur_file_identity(opened) != _cur_file_identity(before):
            raise ValueError("CUR input changed before opening")
        with gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
            stream = _CURStreamState(compressed, budget, checksum)
            # Strict CSV decoding and all budgets still precede row acceptance.
            reader = csv.DictReader(stream.bounded_lines(), strict=True)
            _cur_validate_header(reader)
            stream.reset_record()
            count = _cur_consume_rows(reader, budget, accept_row, stream)
    after = path.stat()
    if (_cur_file_identity(before) != _cur_file_identity(after)
            or _cur_file_identity(opened) != _cur_file_identity(after)):
        raise ValueError("CUR input changed during scan")
    return (_cur_file_identity(after), stream.expanded, count, checksum.hexdigest())


def _cur_input_paths(files: list[str]) -> list[Path]:
    """Validate the complete CUR file set, including inode/path aliases."""
    if not files or len(files) > MAX_CUR_FILES:
        raise ValueError("CUR input file count out of bounds")
    paths = [Path(filename) for filename in files]
    seen_inodes = set()
    for path in paths:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("CUR input must be a regular file")
        identity = (info.st_dev, info.st_ino)
        if identity in seen_inodes:
            raise ValueError("Duplicate CUR input, including hardlink/path aliases")
        seen_inodes.add(identity)
    return paths


def _cur_scan_periods(paths: list[Path]) -> tuple:
    """First bounded pass: collect every month and each file's receipt."""
    periods = set()
    receipts = []
    first_budget = {"bytes": 0, "rows": 0}

    def record_month(row):
        period = row.get("bill_billing_period_start_date", "")
        if not isinstance(period, str):
            raise ValueError("CUR billing period missing")
        if period:
            if not re.match(r"^\d{4}-(?:0[1-9]|1[0-2])-\d{2}", period):
                raise ValueError("CUR billing period invalid")
            periods.add(period[:7])

    for path in paths:
        receipts.append(_scan_cur_file(path, first_budget, record_month))
    return periods, receipts


def _cur_selected_usage(row, active_month: str, account: str) -> bool:
    """Preserve the original selection order before currency enforcement."""
    period = row.get("bill_billing_period_start_date", "")
    if not isinstance(period, str):
        raise ValueError("CUR billing period missing")
    if len(period[:7]) != len(active_month) or not period.startswith(active_month):
        return False
    if row["line_item_usage_account_id"] != account:
        return False
    typ = row["line_item_line_item_type"]
    if typ not in ("Usage", "DiscountedUsage", "SavingsPlanCoveredUsage"):
        return False
    if row.get("line_item_currency_code") != "USD":
        raise ValueError("Non-USD CUR line item; currency conversion is not implemented")
    return True


def _cur_resource_key(row, account: str, kind_filter: set[str] | None):
    """Resolve the CUR target only after selected-row currency validation."""
    raw_id = row["line_item_resource_id"].strip()
    if not raw_id:
        return None
    kind, locator, arn_region = rid_class(raw_id)
    if raw_id.startswith("arn:"):
        arn_account = raw_id.split(":", 5)[4]
        if arn_account and arn_account != account:
            return None
    if kind == "unsupported" or (kind_filter is not None and kind not in kind_filter):
        return None
    region = arn_region or row.get("product_region_code", "")
    if not region and kind == "s3_bucket":
        region = "global"
    if not region:
        return None
    return kind, locator, region


def _cur_accumulate_usage(row, active_month, account, kind_filter, aggregates, provenance):
    """Update one selected target, retaining distinct-count and finite budgets."""
    if not _cur_selected_usage(row, active_month, account):
        return
    key = _cur_resource_key(row, account, kind_filter)
    if key is None:
        return
    amount = cost_of(row)
    if key not in aggregates and len(aggregates) >= MAX_CUR_DISTINCT_RESOURCES:
        raise ValueError("CUR distinct-resource budget exceeded")
    proposed_total = aggregates[key] + amount
    if not math.isfinite(proposed_total):
        raise ValueError("CUR aggregated amount is not finite")
    aggregates[key] = proposed_total
    provenance[key]["services"].add(row["line_item_product_code"])
    provenance[key]["billing_rows"] += 1
    provenance[key]["currency"].add(row["line_item_currency_code"])


def _cur_scan_aggregates(paths, receipts, active_month, account, kind_filter):
    """Second bounded pass: aggregate and compare each first-pass receipt."""
    aggregates = defaultdict(float)
    provenance = defaultdict(lambda: {"services": set(), "billing_rows": 0, "currency": set()})

    def aggregate_row(row):
        _cur_accumulate_usage(row, active_month, account, kind_filter,
                              aggregates, provenance)

    second_budget = {"bytes": 0, "rows": 0}
    for idx, path in enumerate(paths):
        second_receipt = _scan_cur_file(path, second_budget, aggregate_row)
        if receipts[idx] != second_receipt:
            raise ValueError("CUR content or metadata changed between passes")
    return aggregates, provenance


def _cur_ranked_candidates(aggregates, provenance, min_cost, max_resources):
    """Retain stable cost ranking, thresholding, cap and report projections."""
    ranked = sorted(aggregates.items(), key=lambda x: -x[1])
    ranked = [(k, v) for k, v in ranked if v >= min_cost][:max_resources]
    return [{"kind": k[0], "locator": k[1], "region": k[2],
        "effective_usage_cost_usd": round(v, 6),
        "source_services": sorted(provenance[k]["services"]),
        "billing_rows": provenance[k]["billing_rows"],
        "currency": sorted(provenance[k]["currency"])} for k, v in ranked]


def cur_candidates(files: list[str], month: str | None, min_cost: float,
                   max_resources: int, account: str, kind_filter: set[str] | None = None):
    """Two bounded, receipt-matched passes; no AWS access or report on error."""
    paths = _cur_input_paths(files)
    periods, receipts = _cur_scan_periods(paths)
    if month is None and not periods:
        raise ValueError("CUR input contains no billing rows; specify --month")
    active_month = month or max(periods)
    aggregates, provenance = _cur_scan_aggregates(
        paths, receipts, active_month, account, kind_filter)
    return active_month, _cur_ranked_candidates(
        aggregates, provenance, min_cost, max_resources)


def _accumulate_other_batch_cur_row(state,category,reason,exact_amount,exact_add):
    if category not in state.billing:
        raise ValueError("Unknown CUR population category")
    entry=state.billing[category]
    entry["billing_rows"]+=1
    entry["exact_cost"]=exact_add((entry["exact_cost"],exact_amount))
    reason_entry=state.reasons[(category,reason)]
    reason_entry["billing_rows"]+=1
    reason_entry["exact_cost"]=exact_add((reason_entry["exact_cost"],exact_amount))


def _accumulate_recognized_batch_cur_row(state,row,key,exact_amount,exact_add):
    if key is None:
        raise ValueError("CUR recognized identity missing")
    current=state.aggregates.get(key)
    legacy_amount=cost_of(row)
    legacy_total=legacy_amount if current is None else current.legacy_rank_cost+legacy_amount
    if not math.isfinite(legacy_total):
        raise ValueError("CUR aggregated amount is not finite")
    if current is None and len(state.aggregates)>=MAX_CUR_DISTINCT_RESOURCES:
        raise ValueError("CUR distinct-resource budget exceeded")
    exact_total=(exact_amount if current is None
                 else exact_add((current.exact_cost,exact_amount)))
    from name_tag_batch_population import CurCostAggregate
    state.aggregates[key]=CurCostAggregate(exact_total,legacy_total)
    state.provenance[key]["services"].add(row["line_item_product_code"])
    state.provenance[key]["billing_rows"]+=1
    state.provenance[key]["currency"].add(row["line_item_currency_code"])


def _accumulate_batch_cur_row(state,row):
    from name_tag_batch_population import classify_cur_row,decimal_cost_of,exact_add

    if not _cur_selected_usage(row,state.month,state.account):
        return
    exact_amount=decimal_cost_of(row)
    category,reason,key=classify_cur_row(
        row,account=state.account,kind_filter=state.kind_filter,rid_class=rid_class
    )
    if category!="CUR_RECOGNIZED":
        _accumulate_other_batch_cur_row(state,category,reason,exact_amount,exact_add)
        return
    _accumulate_recognized_batch_cur_row(state,row,key,exact_amount,exact_add)


def _cur_scan_batch_aggregates(paths, receipts, active_month, account, kind_filter):
    """Scan the same bounded CUR input for exact Batch accounting and legacy rank."""
    from decimal import Decimal

    state = _CurBatchAggregateState(active_month,account,kind_filter,{},
        defaultdict(lambda: {"services": set(), "billing_rows": 0, "currency": set()}),{
        "UNATTRIBUTABLE_CUR": {"billing_rows": 0, "exact_cost": Decimal(0)},
        "OUTSIDE_REQUESTED_KINDS": {"billing_rows": 0, "exact_cost": Decimal(0)},
        "UNSUPPORTED_KIND": {"billing_rows": 0, "exact_cost": Decimal(0)},
    },defaultdict(lambda: {"billing_rows": 0, "exact_cost": Decimal(0)}))

    second_budget = {"bytes": 0, "rows": 0}
    for index, path in enumerate(paths):
        receipt = _scan_cur_file(path, second_budget,lambda row:_accumulate_batch_cur_row(state,row))
        if receipts[index] != receipt:
            raise ValueError("CUR content or metadata changed between passes")
    return state.aggregates,state.provenance,state.billing,state.reasons


def cur_candidates_batch(
    files: list[str], month: str | None, min_cost: float,
    max_resources: int, account: str, kind_filter: set[str] | None = None,
):
    """Return Batch-selected candidates and exact pre-cap accounting from two bounded passes.

    The fifth element is the per-Kind pre-cap breakdown built from the same aggregates.
    """
    from name_tag_batch_population import build_kind_precap, exact_add, partition_cur_population
    from name_tag_batch_population import _canonical_decimal

    paths = _cur_input_paths(files)
    periods, receipts = _cur_scan_periods(paths)
    if month is None and not periods:
        raise ValueError("CUR input contains no billing rows; specify --month")
    active_month = month or max(periods)
    aggregates, provenance, billing, reasons = _cur_scan_batch_aggregates(
        paths, receipts, active_month, account, kind_filter)
    population = partition_cur_population(
        aggregates, min_cost=min_cost, max_resources=max_resources)
    selected_keys = population.pop("selected_keys")
    kind_precap = build_kind_precap(aggregates, selected_keys, min_cost=min_cost)
    candidates = []
    for key in selected_keys:
        aggregate = aggregates[key]
        candidates.append({
            "kind": key[0], "locator": key[1], "region": key[2],
            "effective_usage_cost_usd": _canonical_decimal(aggregate.exact_cost),
            "legacy_rank_cost": aggregate.legacy_rank_cost,
            "source_services": sorted(provenance[key]["services"]),
            "billing_rows": provenance[key]["billing_rows"],
            "currency": sorted(provenance[key]["currency"]),
        })
    for category, summary in billing.items():
        population[category.lower()] = {
            "known": True, "billing_rows": summary["billing_rows"],
            "cost_usd": _canonical_decimal(summary["exact_cost"]),
        }
    population["schema_version"] = 2
    population["accounting_complete"] = True
    reason_details = {
        f"{category}:{reason}": {
            "billing_rows": values["billing_rows"],
            "cost_usd": _canonical_decimal(values["exact_cost"]),
        }
        for (category, reason), values in sorted(reasons.items())
    }
    if _canonical_decimal(exact_add(
            candidate["effective_usage_cost_usd"] for candidate in candidates
    )) != population["lookup_selected"]["cost_usd"]:
        raise ValueError("Batch selected CUR total failed exact reconciliation")
    return active_month, candidates, population, reason_details, kind_precap


class AWSReadBudgetExceeded(RuntimeError):
    """Application read budget exhausted; no partial result may be published."""


class AWSReadBudget:
    """Share one monotonic deadline and request budget across STS/IAM/resources."""

    def __init__(self, *, max_calls=None, max_elapsed=None):
        self.max_calls = MAX_AWS_READ_CALLS if max_calls is None else max_calls
        self.max_elapsed = (MAX_AWS_READ_ELAPSED_SECONDS
                            if max_elapsed is None else max_elapsed)
        if self.max_calls < 1 or self.max_elapsed <= 0:
            raise ValueError("AWS read limits must be positive")
        self.started = time.monotonic()
        self.calls = 0
        self.exhausted = False

    def require_completion(self):
        """The last permitted call can finish without requiring a spare call."""
        if self.exhausted:
            raise AWSReadBudgetExceeded("AWS read budget already exhausted")
        if time.monotonic() - self.started >= self.max_elapsed:
            self.exhausted = True
            raise AWSReadBudgetExceeded("AWS read elapsed-time budget exceeded")

    def require_remaining(self):
        self.require_completion()
        if self.calls >= self.max_calls:
            self.exhausted = True
            raise AWSReadBudgetExceeded("AWS read API-call budget exceeded")

    def before_read(self, service, operation):
        self.require_remaining()
        self.calls += 1


class _BudgetedAWSClient:
    """Restrict every explicit SDK operation to reads; count calls before use."""

    def __init__(self, client, budget, service):
        self._client = client
        self._budget = budget
        self._service = service

    def __getattr__(self, operation):
        # No generic forwarding of arbitrary callable client methods: doing
        # so could silently expose a write path to the reviewer.
        if operation.startswith("_") or operation in ("get_paginator", "get_waiter"):
            raise AttributeError("Only direct, budgeted AWS reads are permitted")
        attr = getattr(self._client, operation)
        if not callable(attr):
            return attr
        if not operation.startswith(("describe_", "list_", "get_", "head_", "lookup_")):
            raise RuntimeError("AWS operation outside the read allowlist")
        def invoke(*args, **kwargs):
            self._budget.before_read(self._service, operation)
            return attr(*args, **kwargs)
        return invoke


class _BudgetedAWSSession:
    """Use one-attempt SDK clients to make explicit invocation counts bounded."""

    def __init__(self, session, budget=None):
        self._session = session
        self.read_budget = budget if budget is not None else AWSReadBudget()
        self._clients = {}

    def client(self, service, region_name=None, config=None):
        self.read_budget.require_remaining()
        key = (service, region_name)
        if key not in self._clients:
            from botocore.config import Config
            # Setting total_max_attempts=1 disables SDK retry amplification.
            # DNS, credential-provider refresh and in-flight socket deadlines
            # are NOT hard-realtime guaranteed by this invocation budget.
            safe_config = Config(
                retries={"mode": "standard", "total_max_attempts": 1},
                connect_timeout=AWS_READ_CONNECT_TIMEOUT_SECONDS,
                read_timeout=AWS_READ_TIMEOUT_SECONDS,
            )
            client = self._session.client(service, region_name=region_name,
                                          config=safe_config)
            self._clients[key] = _BudgetedAWSClient(client, self.read_budget, service)
        return self._clients[key]


def _budgeted_session(session):
    return session if isinstance(session, _BudgetedAWSSession) else _BudgetedAWSSession(session)


@dataclass(slots=True)
class _ResolutionContext:
    """Mutable accumulator for one resource-specific resolver pass."""

    kind: str
    locator: str
    region: str
    name_state_fn: Callable[[dict], str]
    candidate_states: tuple[str, ...]
    result: dict
    tags: dict | None = None
    candidate: str | None = None
    evidence: str = ""
    confidence: str = "high"


@dataclass(slots=True)
class _CurBatchAggregateState:
    month: str
    account: str
    kind_filter: set[str] | None
    aggregates: dict
    provenance: dict
    billing: dict
    reasons: dict


class Investigator:
    def __init__(self, session, account: str, retries: int = 3):
        from botocore.config import Config
        self.session = _budgeted_session(session)
        self.account = account
        # The session wrapper enforces one SDK attempt per explicit API call.
        self.config = Config(retries={"mode": "standard", "total_max_attempts": 1})
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
            response=self.client("ec2",region).describe_volumes(VolumeIds=[vid])
            if not isinstance(response, dict) or type(response.get("Volumes")) is not list:
                raise ValueError("Malformed DescribeVolumes response")
            items=response["Volumes"]
            if len(items)!=1 or type(items[0]) is not dict:
                raise ValueError("Volume not unique/absent or malformed")
            vol=items[0]
            if type(vol.get("VolumeId")) is not str or vol["VolumeId"] != vid:
                raise ValueError("Returned VolumeId differs from requested VolumeId")
            # C4: supplied positive provenance takes priority over even a NONEMPTY Name.
            if "OwnerId" in vol:
                owner=vol["OwnerId"]
                if (type(owner) is not str or
                        re.fullmatch(r"[0-9]{12}", owner, re.ASCII) is None or
                        owner != self.account):
                    raise ValueError("Volume OwnerId does not match verified account")
            if "VolumeArn" in vol:
                arn=vol["VolumeArn"]
                if type(arn) is not str:
                    raise ValueError("Malformed VolumeArn")
                parts=arn.split(":",5)
                if len(parts)!=6:
                    raise ValueError("Malformed VolumeArn")
                _,partition,service,arn_region,account,resource=parts
                # AWS partition is bound to the region, not inferred from the ARN.
                if region.startswith("cn-"):
                    expected_partition="aws-cn"
                elif region.startswith("us-gov-"):
                    expected_partition="aws-us-gov"
                elif region.startswith(("us-iso-","us-isob-","eu-isoe-","us-isof-")):
                    raise ValueError("Unsupported restricted partition for VolumeArn")
                else:
                    expected_partition="aws"
                if (parts[0]!="arn" or partition!=expected_partition or
                        service!="ec2" or arn_region!=region or
                        account!=self.account or resource!=f"volume/{vid}"):
                    raise ValueError("VolumeArn identity mismatch")
            self._volumes[key]=vol
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
        parent_tags=tagmap(obj.get("Tags", []), expected_shape="list", allow_missing_non_name_value=True)
        anchor=meaningful(name_of(parent_tags))
        if not anchor:
            raise ValueError(f"EC2 {iid} lacks a meaningful Name; cannot inherit")
        # Product may use a different identifier than the Name. Only the
        # parent Name is inherited; catalog mappings belong elsewhere.
        return anchor, f"EC2 {iid} Name={anchor}; Product(observed, not validated)={parent_tags.get('Product','(unset)')}"

    def volume_owner(self, region, vid):
        vol=self.volume(region,vid)
        direct=meaningful(name_of(tagmap(vol.get("Tags",[]), expected_shape="list", allow_missing_non_name_value=True)))
        if direct:
            return direct, f"EBS {vid} Name={direct}"
        # C9/C6 strict boolean and lifecycle gates apply ONLY to Name ABSENT/EMPTY.
        if type(vol.get("State")) is not str or vol["State"]!="in-use":
            raise ValueError("EBS Volume State must be in-use")
        if type(vol.get("MultiAttachEnabled")) is not bool or vol["MultiAttachEnabled"] is not False:
            raise ValueError("EBS MultiAttachEnabled must be exactly False")
        # C5-S: conflicting managed/visibility evidence cannot establish EC2 ownership.
        if "Operator" in vol:
            operator=vol["Operator"]
            if type(operator) is not dict or operator.get("Managed") is not False:
                raise ValueError("EBS Volume Operator is managed or malformed")
            if "Principal" in operator and (type(operator["Principal"]) is not str or operator["Principal"]!=""):
                raise ValueError("EBS Volume Operator Principal is not neutral")
            if "HiddenByDefault" in operator and (type(operator["HiddenByDefault"]) is not bool or operator["HiddenByDefault"] is not False):
                raise ValueError("EBS Volume Operator HiddenByDefault is contradictory")
        attachments=vol.get("Attachments")
        if type(attachments) is not list or not attachments:
            raise ValueError("EBS attachments missing, empty or malformed")
        owners=set()
        devices=set()
        for att in attachments:
            if type(att) is not dict:
                raise ValueError("Malformed EBS attachment record")
            iid=att.get("InstanceId")
            device=att.get("Device")
            if type(iid) is not str or re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})",iid,re.ASCII) is None:
                raise ValueError("Invalid EBS EC2 InstanceId")
            if type(device) is not str or re.fullmatch(r"\A/dev/[a-z][a-z0-9_-]{0,62}[a-z0-9]\Z", device, re.ASCII) is None:
                raise ValueError("Invalid raw EBS attachment Device")
            if type(att.get("State")) is not str or att["State"]!="attached":
                raise ValueError("EBS attachment State must be attached")
            if "VolumeId" in att and (type(att["VolumeId"]) is not str or att["VolumeId"]!=vid):
                raise ValueError("Attachment VolumeId mismatch")
            if "AssociatedResource" in att or "InstanceOwningService" in att:
                raise ValueError("EBS service managed attachment marker supplied")
            owners.add(iid)
            devices.add(device)
        if len(owners)!=1 or len(devices)!=1:
            raise ValueError("EBS attachment owner/device evidence ambiguous")
        iid=next(iter(owners))
        raw_device=next(iter(devices))
        # No parent read until every unfiltered attachment has passed all gates.
        anchor,path=self.parent_instance(region,iid)
        suffix_device=raw_device.split("/")[-1].replace("_","-")
        return suffix_name(anchor,"ebs",suffix_device,vid[-7:]), f"EBS {vid} -> attachment {iid} {suffix_device} -> {path}"

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
        sn=meaningful(name_of(tagmap(subnet.get("Tags",[]), expected_shape="list", allow_missing_non_name_value=True)))
        vn=meaningful(name_of(tagmap(vpc.get("Tags",[]), expected_shape="list", allow_missing_non_name_value=True)))
        if not sn or not vn or name_scope_prefix(sn)!=name_scope_prefix(vn):
            raise ValueError("NAT subnet and VPC Names have conflicting namespaces")
        az=subnet.get("AvailabilityZone", "")
        return suffix_name(sn,"nat",az[-1:] if az else "az",nat["NatGatewayId"][-6:]),f"NAT {nat['NatGatewayId']} -> subnet {nat['SubnetId']} Name={sn} + VPC {nat['VpcId']} Name={vn}"

    def _resolve_instance(self, state):
        loc,region=state.locator,state.region
        obj=self.instance(region,loc)
        state.tags=tagmap(obj.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) not in state.candidate_states:
            return
        relations=[]
        for key,label in (("aws:autoscaling:groupName","AutoScaling Group"),
                          ("aws:cloudformation:stack-name","CloudFormation Stack")):
            value=meaningful(state.tags.get(key,""))
            if value:
                relations.append((value,f"{label}={value}"))
        if not relations:
            raise ValueError("EC2 instance missing Name and structured ASG/CloudFormation ownership")
        if len({name_scope_prefix(value[0]) for value in relations})!=1:
            raise ValueError("EC2 ASG and CloudFormation Stack Names have conflicting namespaces")
        anchor=relations[0][0]
        state.candidate=suffix_name(anchor,"ec2",loc[-7:])
        state.evidence=f"EC2 {loc} -> "+", ".join(value[1] for value in relations)
        state.confidence="medium"

    def _resolve_volume(self, state):
        state.tags=tagmap(self.volume(state.region,state.locator).get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) in state.candidate_states:
            state.candidate,state.evidence=self.volume_owner(state.region,state.locator)

    def _resolve_snapshot(self, state, client):
        snapshots=client.describe_snapshots(SnapshotIds=[state.locator],OwnerIds=["self"]).get("Snapshots",[])
        if len(snapshots)!=1 or snapshots[0].get("OwnerId")!=self.account:
            raise ValueError("snapshot is absent or not owned by target account")
        obj=snapshots[0]
        state.tags=tagmap(obj.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) in state.candidate_states:
            source=obj.get("VolumeId","")
            if not source:
                raise ValueError("snapshot missing source volume")
            raise ValueError(f"Snapshot {state.locator} source VolumeId={source}; historical owner evidence required")

    def _resolve_eni(self, state, client):
        interfaces=client.describe_network_interfaces(NetworkInterfaceIds=[state.locator]).get("NetworkInterfaces",[])
        if len(interfaces)!=1:
            raise ValueError("ENI not found")
        obj=interfaces[0]
        state.tags=tagmap(obj.get("TagSet",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) not in state.candidate_states:
            return
        instance_id=obj.get("Attachment",{}).get("InstanceId")
        if not instance_id:
            raise ValueError("ENI not attached to EC2 instance")
        base,path=self.parent_instance(state.region,instance_id)
        index=obj["Attachment"].get("DeviceIndex")
        if index is None:
            raise ValueError("ENI device index unavailable")
        state.candidate=suffix_name(base,"eni",f"eth{index}",state.locator[-7:])
        state.evidence=f"ENI {state.locator} -> {path}"

    def _resolve_eip(self, state, client):
        addresses=client.describe_addresses(AllocationIds=[state.locator]).get("Addresses",[])
        if len(addresses)!=1:
            raise ValueError("EIP not found")
        address=addresses[0]
        state.tags=tagmap(address.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) in state.candidate_states:
            state.candidate,state.evidence,_=self.eip_owner(state.region,state.locator)

    def _resolve_nat(self, state, client):
        gateways=client.describe_nat_gateways(NatGatewayIds=[state.locator]).get("NatGateways",[])
        if len(gateways)!=1:
            raise ValueError("NAT not found")
        obj=gateways[0]
        state.tags=tagmap(obj.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) in state.candidate_states:
            state.candidate,state.evidence=self.nat_owner(state.region,obj)
            state.confidence="medium"

    def _resolve_endpoint(self, state, client):
        endpoints=client.describe_vpc_endpoints(VpcEndpointIds=[state.locator]).get("VpcEndpoints",[])
        if len(endpoints)!=1:
            raise ValueError("VPC endpoint not found")
        endpoint=endpoints[0]
        state.tags=tagmap(endpoint.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        if state.name_state_fn(state.tags) not in state.candidate_states:
            return
        vpc=self.vpc(state.region,endpoint["VpcId"])
        vpc_name=meaningful(name_of(tagmap(vpc.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)))
        subnets=[self.subnet(state.region,subnet_id) for subnet_id in endpoint.get("SubnetIds",[])]
        subnet_names=[meaningful(name_of(tagmap(subnet.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True))) for subnet in subnets]
        if not vpc_name or not subnet_names or any(name is None or name_scope_prefix(name)!=name_scope_prefix(vpc_name) for name in subnet_names):
            raise ValueError("VPC endpoint shared/ambiguous; require uniformly named VPC and all subnets")
        service=endpoint["ServiceName"].split(".")[-1]
        state.candidate=suffix_name(vpc_name,"vpce",service,state.locator[-6:])
        state.confidence="medium"
        state.evidence=f"endpoint {state.locator} -> VPC {endpoint['VpcId']} Name={vpc_name} and {len(subnets)} same-namespace subnets"

    def _find_rds_cluster(self,client,loc):
        if re.fullmatch(r"cluster-[a-z0-9]{14,}",loc,re.I):
            results=[]
            marker=None
            seen_markers=set()
            for _ in range(MAX_RDS_CLUSTER_PAGES):
                query={"MaxRecords":100}
                if marker is not None:
                    query["Marker"]=marker
                page=client.describe_db_clusters(**query)
                results.extend(cluster for cluster in page.get("DBClusters",[]) if cluster.get("DbClusterResourceId","").casefold()==loc.casefold())
                next_marker=page.get("Marker")
                if next_marker in (None,""):
                    break
                if not isinstance(next_marker,str) or next_marker in seen_markers:
                    raise ValueError("RDS cluster pagination marker invalid or repeated")
                seen_markers.add(next_marker)
                marker=next_marker
            else:
                raise ValueError("RDS cluster pagination page budget exceeded")
        else:
            return client.describe_db_clusters(DBClusterIdentifier=loc).get("DBClusters",[])
        return results

    def _resolve_rds_cluster(self, state, client):
        loc=state.locator
        results=self._find_rds_cluster(client,loc)
        if len(results)!=1:
            raise ValueError("RDS cluster not found/unique")
        obj=results[0]
        arn=obj["DBClusterArn"]
        if loc.lower().startswith("cluster-") and loc.casefold()!=obj.get("DbClusterResourceId","").casefold():
            raise ValueError("CUR RDS cluster resource id differs from resolved cluster")
        state.tags=tagmap(client.list_tags_for_resource(ResourceName=arn).get("TagList",[]),expected_shape="list",allow_missing_non_name_value=True)
        anchor=meaningful(obj.get("DBClusterIdentifier",""))
        if not anchor:
            raise ValueError("RDS cluster identifier is opaque; inspect member names manually")
        state.candidate=anchor if anchor.endswith("-rds") or "-db-" in anchor else suffix_name(anchor,"rds")
        state.evidence=f"CUR cluster {loc} -> DescribeDBClusters {obj['DBClusterIdentifier']} / DbClusterResourceId={obj.get('DbClusterResourceId','')} / ARN={arn}"
        state.result["write_target"]=arn

    def _resolve_rds_parent(self,state,client,obj,identity,anchor):
        cluster_id=obj.get("DBClusterIdentifier")
        if not cluster_id:
            return anchor,f"RDS standalone DBInstanceIdentifier={identity} (no parent cluster)",False
        clusters=client.describe_db_clusters(DBClusterIdentifier=cluster_id).get("DBClusters",[])
        if len(clusters)!=1:
            raise ValueError("RDS parent cluster missing or ambiguous")
        parent=clusters[0]
        members={member.get("DBInstanceIdentifier") for member in parent.get("DBClusterMembers",[])}
        if identity not in members:
            raise ValueError("RDS instance not listed among DBClusterMembers; refusing inference")
        cluster_tags=tagmap(client.list_tags_for_resource(ResourceName=parent["DBClusterArn"]).get("TagList",[]),expected_shape="list",allow_missing_non_name_value=True)
        parent_name=meaningful(name_of(cluster_tags)) or meaningful(parent["DBClusterIdentifier"])
        if not parent_name:
            raise ValueError("RDS parent cluster has no identifiable Name/identifier")
        if anchor and name_scope_prefix(anchor)!=name_scope_prefix(parent_name):
            raise ValueError("RDS parent and child Name namespaces conflict")
        generated=not anchor
        if generated:
            anchor=suffix_name(parent_name,"instance",obj.get("DbiResourceId",identity)[-7:].lower())
        evidence=(f"RDS {identity} -> DBClusterIdentifier={cluster_id} -> "
                  f"DBClusterMembers includes {identity} -> "
                  f"cluster Name={name_of(cluster_tags) or '(unset)'} "
                  f"/ clusterId={parent['DBClusterIdentifier']} "
                  f"/ instance Product={state.tags.get('Product','(unset)')}")
        return anchor,evidence,generated

    def _resolve_rds_instance(self, state, client):
        instances=client.describe_db_instances(DBInstanceIdentifier=state.locator).get("DBInstances",[])
        if len(instances)!=1:
            raise ValueError("RDS DB instance not found")
        obj=instances[0]
        arn=obj["DBInstanceArn"]
        state.tags=tagmap(client.list_tags_for_resource(ResourceName=arn).get("TagList",[]),expected_shape="list",allow_missing_non_name_value=True)
        identity=obj["DBInstanceIdentifier"]
        anchor=meaningful(identity)
        anchor,state.evidence,generated=self._resolve_rds_parent(state,client,obj,identity,anchor)
        if generated:
            state.confidence="medium"
        if not anchor:
            raise ValueError("RDS instance and cluster lack a descriptive Name namespace")
        state.candidate=anchor if anchor.endswith("-rds") or "-db-" in anchor else suffix_name(anchor,"rds")
        state.result["write_target"]=arn

    def _resolve_opensearch(self, state):
        client=self.client("opensearch",state.region)
        obj=client.describe_domain(DomainName=state.locator)["DomainStatus"]
        arn=obj["ARN"]
        state.tags=tagmap(client.list_tags(ARN=arn).get("TagList",[]),expected_shape="list")
        anchor=meaningful(obj["DomainName"])
        if not anchor:
            raise ValueError("OpenSearch domain lacks a structured namespace")
        state.candidate=anchor if "opensearch" in anchor else suffix_name(anchor,"opensearch")
        state.evidence=f"DescribeDomain {state.locator} -> domain {obj['DomainName']}"
        state.result["write_target"]=arn

    def _resolve_elbv2(self, state):
        client=self.client("elbv2",state.region)
        load_balancers=client.describe_load_balancers(LoadBalancerArns=[state.locator]).get("LoadBalancers",[])
        if len(load_balancers)!=1:
            raise ValueError("load balancer not found")
        load_balancer=load_balancers[0]
        state.tags=tagmap(client.describe_tags(ResourceArns=[state.locator])["TagDescriptions"][0]["Tags"],expected_shape="list",allow_missing_non_name_value=True)
        anchor=meaningful(load_balancer["LoadBalancerName"])
        if not anchor:
            raise ValueError("LB name lacks a structured namespace")
        role={"application":"alb","network":"nlb","gateway":"gwlb"}.get(load_balancer["Type"],"lb")
        state.candidate=anchor if anchor.endswith("-"+role) else suffix_name(anchor,role)
        state.evidence=f"LoadBalancer {state.locator} -> LoadBalancerName={load_balancer['LoadBalancerName']}"
        state.result["write_target"]=state.locator

    def _resolve_apigw_stage(self, state):
        api_id,stage,arn=state.locator.split("|",2)
        client=self.client("apigateway",state.region)
        api=client.get_rest_api(restApiId=api_id)
        state.tags=tagmap(client.get_tags(resourceArn=arn).get("tags",{}),expected_shape="map")
        anchor=meaningful(api.get("name",""))
        if not anchor:
            raise ValueError("REST API name lacks a structured namespace")
        stage_anchor=meaningful(stage)
        if stage_anchor and name_scope_prefix(stage_anchor)==name_scope_prefix(anchor):
            state.candidate=suffix_name(stage_anchor,"apigateway-stage")
        else:
            state.candidate=suffix_name(anchor,"stage",stage)
        state.evidence=f"REST API stage {stage} -> GetRestApi({api_id}) name={api['name']}"
        state.result["write_target"]=arn

    def _resolve_cloudfront(self, state):
        client=self.client("cloudfront","us-east-1")
        distribution_id=state.locator.rsplit("/",1)[-1]
        state.tags=tagmap(client.list_tags_for_resource(Resource=state.locator)["Tags"].get("Items",[]),expected_shape="list",allow_missing_non_name_value=True)
        config=client.get_distribution_config(Id=distribution_id)["DistributionConfig"]
        origins=[origin["DomainName"].lower() for origin in config.get("Origins",{}).get("Items",[])]
        anchors=[]
        for origin in origins:
            host=origin.removesuffix(".")
            anchor=meaningful(host.split(".")[0])
            if not anchor:
                raise ValueError(f"CloudFront origin lacks a structured namespace: {host}")
            anchors.append(anchor)
        if not anchors or len({name_scope_prefix(anchor) for anchor in anchors})!=1:
            raise ValueError("CloudFront has no origins or conflicting Name namespaces")
        anchor=anchors[0] if len(anchors)==1 else name_scope_prefix(anchors[0])
        comment=config.get("Comment","")
        aliases=config.get("Aliases",{}).get("Items",[])
        role=""
        if "resize" in comment.lower():
            role="image-resize" if "image" in comment.lower() else "resize"
        elif any(alias.startswith(("image.","static.image.")) for alias in aliases):
            role="image"
        state.candidate=suffix_name(anchor,*([role] if role else []),"cloudfront",distribution_id[-7:].lower())
        state.evidence=(f"CloudFront {distribution_id} -> origins={origins}; "
                        f"comment={comment!r}; aliases={aliases}; anchor={anchor}")
        state.result["write_target"]=state.locator
        state.confidence="medium"

    def _resolve_athena(self, state):
        client=self.client("athena",state.region)
        tag_page=client.list_tags_for_resource(ResourceARN=state.locator)
        if tag_page.get("NextToken") is not None:
            raise ValueError("Athena tag response is paginated; Name state UNKNOWN until all tags are read")
        state.tags=tagmap(tag_page.get("Tags",[]),expected_shape="list",allow_missing_non_name_value=True)
        workgroup_name=state.locator.rsplit("/",1)[-1]
        workgroup=client.get_work_group(WorkGroup=workgroup_name)["WorkGroup"]
        anchor=meaningful(workgroup["Name"])
        if not anchor:
            raise ValueError("Athena workgroup name is not product-identifiable")
        state.candidate=suffix_name(anchor,"athena-workgroup")
        state.evidence=f"Athena workgroup ARN -> WorkGroup.Name={workgroup['Name']}"
        state.result["write_target"]=state.locator

    def _resolve_log_group(self, state):
        client=self.client("logs",state.region)
        arn=f"arn:aws:logs:{state.region}:{self.account}:log-group:{state.locator}"
        state.tags=tagmap(client.list_tags_for_resource(resourceArn=arn).get("tags",{}),expected_shape="map")
        anchor=meaningful(state.locator)
        if anchor is None and state.locator.startswith("/aws/lambda/"):
            function=state.locator.rsplit("/",1)[-1]
            config=self.client("lambda",state.region).get_function_configuration(FunctionName=function)
            anchor=meaningful(config.get("FunctionName",""))
            if anchor:
                state.evidence=f"log group {state.locator} -> lambda function {function}"
        if not anchor:
            raise ValueError("LogGroup cannot be linked to a structured resource name")
        state.candidate=anchor if anchor.endswith(("-log","-logs")) else suffix_name(anchor,"logs")
        if not state.evidence:
            state.evidence=f"LogGroup explicitly named {state.locator}"
        state.result["write_target"]=arn

    def _resolve_lambda(self, state):
        client=self.client("lambda",state.region)
        config=client.get_function_configuration(FunctionName=state.locator)
        state.tags=tagmap(client.list_tags(Resource=config["FunctionArn"]).get("Tags",{}),expected_shape="map")
        anchor=meaningful(config.get("FunctionName",""))
        if not anchor:
            raise ValueError("Lambda function name lacks a structured namespace")
        state.candidate=anchor if anchor.endswith("-lambda") else suffix_name(anchor,"lambda")
        state.evidence=f"Lambda {state.locator} -> function={config['FunctionName']}"
        state.result["write_target"]=config["FunctionArn"]

    def _resolve_wafv2(self, state):
        client=self.client("wafv2",state.region)
        tag_page=client.list_tags_for_resource(ResourceARN=state.locator)
        marker=tag_page.get("NextMarker")
        if marker is not None and marker!="":
            raise ValueError("WAFv2 tag response is paginated; Name state UNKNOWN until all tags are read")
        state.tags=tagmap(tag_page.get("TagInfoForResource",{}).get("TagList",[]),expected_shape="list")
        acl_name,idpart=state.locator.split("/webacl/",1)[-1].split("/",1)
        scope="CLOUDFRONT" if ":global/" in state.locator else "REGIONAL"
        webacl=client.get_web_acl(Name=acl_name,Scope=scope,Id=idpart)["WebACL"]
        if webacl.get("ARN")!=state.locator:
            raise ValueError("WAF WebACL ARN does not match live returned ACL")
        anchor=meaningful(webacl["Name"])
        if not anchor:
            raise ValueError("WAF ACL name lacks a structured namespace")
        state.candidate=anchor if anchor.endswith("-waf") else suffix_name(anchor,"waf")
        state.evidence=f"WAF GetWebACL {webacl['Name']} id={idpart} ARN={state.locator}"
        state.result["write_target"]=state.locator

    def _resolve_s3_bucket(self, state):
        client=self.client("s3","us-east-1")
        try:
            state.tags=tagmap(client.get_bucket_tagging(Bucket=state.locator,ExpectedBucketOwner=self.account).get("TagSet",[]),expected_shape="list")
        except Exception as error:
            code=getattr(error,"response",{}).get("Error",{}).get("Code","")
            if code in ("NoSuchTagSet","NoSuchTagSetError"):
                state.tags={}
            else:
                raise
        anchor=meaningful(state.locator)
        if not anchor:
            raise ValueError("Bucket name lacks a structured namespace")
        if anchor.startswith("dh-"):
            anchor=anchor[3:]
        state.candidate=anchor if anchor.endswith("-s3") else suffix_name(anchor,"s3")
        state.evidence=f"Bucket {state.locator} (ExpectedBucketOwner={self.account}) -> bucket naming convention"
        state.result["write_target"]=state.locator
        state.confidence="medium"

    def _resolve_ec2_resource(self, state):
        client=self.client("ec2",state.region)
        match state.kind:
            case "instance": self._resolve_instance(state)
            case "volume": self._resolve_volume(state)
            case "snapshot": self._resolve_snapshot(state,client)
            case "eni": self._resolve_eni(state,client)
            case "eip": self._resolve_eip(state,client)
            case "nat": self._resolve_nat(state,client)
            case "endpoint": self._resolve_endpoint(state,client)
        state.result["write_target"]=state.locator

    def _resolve_rds_resource(self, state):
        client=self.client("rds",state.region)
        if state.kind=="rds_cluster":
            self._resolve_rds_cluster(state,client)
        else:
            self._resolve_rds_instance(state,client)

    def _resolve_service_resource(self, state):
        match state.kind:
            case "opensearch": self._resolve_opensearch(state)
            case "elbv2": self._resolve_elbv2(state)
            case "apigw_stage": self._resolve_apigw_stage(state)
            case "cloudfront": self._resolve_cloudfront(state)
            case "athena_workgroup": self._resolve_athena(state)
            case "log_group": self._resolve_log_group(state)
            case "lambda": self._resolve_lambda(state)
            case "wafv2": self._resolve_wafv2(state)
            case "s3_bucket": self._resolve_s3_bucket(state)
            case _:
                raise ValueError("Unsupported AWS service/resource type")

    def resolve(self, item: dict, *, name_state_fn=name_state,
                candidate_states=NAME_CANDIDATE_STATES) -> dict:
        kind,locator,region=item["kind"],item["locator"],item["region"]
        result={"status":"manual_review","proposed_name":"","confidence":"none",
                "evidence":"","write_target":"","kind":kind,
                "name_state":"UNKNOWN","name_key_present":None,
                "name_raw_value":None,"existing_name":""}
        state=_ResolutionContext(kind,locator,region,name_state_fn,candidate_states,result)
        try:
            if kind in ("instance","volume","snapshot","eni","eip","nat","endpoint"):
                self._resolve_ec2_resource(state)
            elif kind in ("rds_cluster","rds_instance"):
                self._resolve_rds_resource(state)
            else:
                self._resolve_service_resource(state)
            self._finish_resolution(state)
        except Exception as error:
            self._finish_resolution_error(state,error)
        return result

    def _finish_resolution(self,state):
        tags=state.tags
        observed=state.name_state_fn(tags)
        state.result.update(name_state=observed,
                            name_key_present="Name" in tags if isinstance(tags,dict) else None,
                            name_raw_value=name_of(tags),existing_name=name_of(tags) or "")
        if observed=="NONEMPTY":
            state.result.update(status="already_named",evidence=f"current nonempty Name protected; unchanged: {name_of(tags)}")
            return
        if observed=="UNKNOWN":
            state.result.update(status="manual_review",evidence="Name tag state UNKNOWN: unreadable or malformed; no proposal")
            return
        if not state.candidate or not meaningful(state.candidate):
            raise ValueError("Candidate lacks a structured Name namespace")
        if shared_scope(state.candidate):
            state.confidence="medium"
            state.evidence += "; shared infrastructure: descriptive Name only, no product classification"
        state.result.update(status="proposed",proposed_name=state.candidate,
                            confidence=state.confidence,evidence=state.evidence)

    def _finish_resolution_error(self,state,error):
        if isinstance(error,AWSReadBudgetExceeded):
            state.result.update(status="manual_review",proposed_name="",confidence="none",
                                name_state="UNKNOWN",name_key_present=None,name_raw_value=None,
                                existing_name="",evidence=f"{type(error).__name__}: {error}")
            return
        tags=state.tags
        observed=state.name_state_fn(tags)
        state.result.update(name_state=observed,
                            name_key_present="Name" in tags if isinstance(tags,dict) else None,
                            name_raw_value=name_of(tags) if isinstance(tags,dict) else None,
                            existing_name=(name_of(tags) or "") if isinstance(tags,dict) else "")
        if observed=="NONEMPTY":
            state.result.update(status="already_named",evidence=f"current nonempty Name protected; unchanged: {name_of(tags)}")
            return
        from botocore.exceptions import BotoCoreError, ClientError
        if isinstance(error,(BotoCoreError,ClientError)):
            state.result["status"]="api_error"
        state.result["evidence"]=f"{type(error).__name__}: {error}"

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
    session = _budgeted_session(session)
    actual=session.client("sts").get_caller_identity()["Account"]
    if actual!=expected:
        raise SystemExit(f"ABORT: AWS STS account {actual} != expected {expected}")


def _require_report_filesystem_support():
    """Fail closed before AWS access on unverified OS/API combinations.

    Current supported runtime is Ubuntu Linux. macOS/APFS (ACL and ownership
    behavior), other Linux distributions and other POSIX systems are not
    validated for secure publication in this release.
    """
    if sys.platform != "linux":
        raise RuntimeError("Secure report publishing is supported only on Ubuntu Linux")
    try:
        release = Path("/etc/os-release").read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("Cannot verify Ubuntu Linux for secure reports") from exc
    distro = next((line.split("=", 1)[1].strip().strip('"').strip("'")
                   for line in release.splitlines() if line.startswith("ID=")), "")
    if distro != "ubuntu":
        raise RuntimeError("Secure report publishing is supported only on Ubuntu Linux")

    if not all(hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
        raise RuntimeError("Secure report publishing requires O_DIRECTORY and O_NOFOLLOW")
    if any(fn not in os.supports_dir_fd for fn in _REQUIRED_REPORT_DIR_FD_APIS):
        raise RuntimeError("Secure report publishing requires dir_fd support for open/mkdir/stat/link/unlink")
    if any(fn not in os.supports_follow_symlinks for fn in _REQUIRED_REPORT_NOFOLLOW_APIS):
        raise RuntimeError("Secure report publishing requires nofollow stat/link support")


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
    _require_report_filesystem_support()
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


def report_output_paths(output: Path, *, mode: str | None = None) -> list[Path]:
    """Files that this invocation may create; never overwrite any of them."""
    out = Path(output)
    paths = [out, out.with_suffix(REVIEW_CSV_SUFFIX), out.with_suffix(REPORT_CSV_SUFFIX)]
    if mode == "dryrun":
        paths.append(out.with_suffix(".result.csv"))
    elif mode == "y":
        paths.extend((out.with_suffix(".selected.csv"),
                      out.with_suffix(".audit.jsonl"),
                      out.with_suffix(".audit.csv")))
    return paths


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
    # O_NONBLOCK makes a substituted FIFO fail promptly even when no reader
    # exists; an O_NOFOLLOW leaf check alone does not constrain file type.
    flags = (os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
             | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    with _private_directory_fd(path.parent, create=False) as dfd:
        fd = os.open(path.name, flags, dir_fd=dfd)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("Audit journal must be an existing regular file")
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
    partition = _partition_for_region(region)
    if kind in ("rds_instance", "rds_cluster"):
        rtype = "db" if kind == "rds_instance" else "cluster"
        if not target:
            target = str(rec.get("locator", ""))
        if target and not target.startswith(("db-", "cluster-")):
            return f"arn:{partition}:rds:{region}:{account}:{rtype}:{target}"
    ec2 = {
        "instance": "instance", "volume": "volume", "snapshot": "snapshot",
        "eni": "network-interface", "eip": "elastic-ip",
        "nat": "natgateway", "endpoint": "vpc-endpoint",
    }
    if kind in ec2:
        rid = target or str(rec.get("locator", ""))
        if rid:
            return f"arn:{partition}:ec2:{region}:{account}:{ec2[kind]}/{rid}"
    if kind == "log_group" and rec.get("locator"):
        return f"arn:{partition}:logs:{region}:{account}:log-group:{rec['locator']}"
    if kind == "s3_bucket" and rec.get("locator"):
        return f"arn:aws:s3:::{rec['locator']}"
    return str(rec.get("locator", "")) if str(rec.get("locator", "")).startswith("arn:") else ""


def _partition_for_region(region: str) -> str:
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def _project_pre_sign_identity(record: dict, partition: str, account: str) -> None:
    """Freeze canonical ARN, signed Scope region and vetted operation BEFORE proposal_key/Plan bytes.

    The resolver already ran against the original service endpoint region. A Kind that fails
    identity or capability stays an unsigned, non-signable preview (empty ARN, no operation).
    """
    from name_tag_kind_capabilities import project_pre_sign_kind_target

    kind, locator = record["kind"], record["locator"]
    target = str(record.get("write_target") or "")
    arn = target if target.startswith("arn:") else None
    if kind == "apigw_stage" and isinstance(locator, str) and locator.count("|") >= 2:
        arn = arn or locator.split("|", 2)[2]
        locator = arn
    try:
        projected = project_pre_sign_kind_target(
            kind=kind, locator=locator, discovered_region=record["region"],
            discovered_arn=arn, partition=partition, account=account,
            evidence=record.get("evidence"), proposed_name=record.get("proposed_name"))
    except ValueError as error:
        if record.get("status") == "proposed":
            record.update(status="manual_review", confidence="none", proposed_name="",
                          evidence=f"Canonical target identity rejected before signing: {error}")
        record["resource_arn"], record["aws_operation"] = "", None
        return
    record["resource_arn"] = projected.identity.resource_arn
    record["region"] = projected.identity.scope_region
    record["aws_operation"] = projected.aws_operation


def _reject_identity_collisions(records: list[dict]) -> None:
    """Duplicate post-projection identity (e.g. one global Kind seen via two regions) never reaches a Plan."""
    seen = set()
    for record in records:
        arn = record.get("resource_arn")
        if not arn:
            continue
        identity = (record["kind"], arn)
        if identity in seen:
            raise SystemExit("batch-plan identity collision after Kind projection; no Plan written")
        seen.add(identity)


def _batch_partition(candidates: list[dict]) -> str:
    """Select the single AWS partition represented by the Batch candidates."""
    partitions={_partition_for_region(str(candidate.get("region", "")))
                for candidate in candidates}
    if len(partitions)>1:
        raise SystemExit("batch-plan cannot mix AWS partitions")
    return next(iter(partitions),"aws")


def write_action_csv(path: Path, records: list[dict], account: str, *, mode: str,
                     scope_declarations: list[dict] | None = None):
    """Audit-friendly report: list ARN, old/proposed Name, result, and evidence."""
    cols = ["utc", "account", "mode", "result", "resource_arn", "kind", "region",
            "resource_id", "name_state", "name_key_present", "name_raw_value",
            "name_before", "name_proposed", "name_after",
            "effective_usage_cost_usd", "confidence", "proposal_id", "detail"]
    if mode == "batch-plan":
        cols.extend(("name_generation_state", "write_support", "scope_application",
                     "host_scope_verified"))
    timestamp = datetime.now(timezone.utc).isoformat()
    with private_output(path, newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=cols)
        writer.writeheader()
        for row in records:
            result = row.get("result", row.get("status", ""))
            new_name = row.get("name", row.get("proposed_name", ""))
            arn = row.get("resource_arn") or resource_arn(row, account)
            values = {
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
            }
            if mode == "batch-plan":
                values.update(_batch_plan_report_fields(
                    row, scope_declarations if scope_declarations is not None else [], account
                ))
            writer.writerow(safe_csv_row(values))
        fh.flush()
        os.fsync(fh.fileno())
    return path


def _arn_partition(arn, row: dict) -> str:
    parts = arn.split(":", 2) if isinstance(arn, str) else []
    if len(parts) == 3 and parts[0] == "arn" and parts[1]:
        return parts[1]
    return _partition_for_region(str(row.get("region", "")))


def _batch_plan_report_fields(row: dict, scope_declarations: list[dict], account: str) -> dict:
    proposed_name = row.get("proposed_name")
    evidence = row.get("evidence")
    if isinstance(proposed_name, str) and proposed_name:
        name_state = "GENERATED"
    elif isinstance(evidence,str) and evidence.startswith("Proposed Name collision in batch:"):
        name_state = "COLLISION"
    elif (row.get("status") == "manual_review" and isinstance(evidence,str)
          and "Candidate lacks a structured Name namespace" in evidence):
        name_state = "UNAVAILABLE"
    else:
        name_state = "NOT_EVALUATED"
    operation = row.get("aws_operation")
    from name_tag_kind_capabilities import REGISTRY_KINDS, resolve_kind_capability
    support = "UNSUPPORTED_API"
    if row.get("kind") in REGISTRY_KINDS:
        decision = resolve_kind_capability(row["kind"])
        if decision.status == "IMPLEMENTED_OFFLINE" and operation == decision.write_operation:
            support = "SUPPORTED_API"
    matches = [scope for scope in scope_declarations
               if scope.get("account") == account
               and scope.get("partition") == _arn_partition(row.get("resource_arn"), row)
               and scope.get("region") == row.get("region")
               and row.get("resource_arn") in scope.get("resource_arns", [])]
    scope_state = "DECLARED_ONLY" if len(matches) == 1 else "NOT_APPLIED"
    if row.get("status") != "proposed":
        scope_state = "NOT_APPLICABLE"
    return {"name_generation_state": name_state, "write_support": support,
            "scope_application": scope_state, "host_scope_verified": False}


def show_aws_identity(session, expected: str) -> dict:
    """Read-only STS + best-effort IAM GetRole; never assume role name proves privileges."""
    session = _budgeted_session(session)
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
        except AWSReadBudgetExceeded:
            # Budget exhaustion is NOT an optional IAM-metadata failure.
            # It must stop the entire interactive run before planning.
            raise
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


def _cur_kind_filter(args):
    kinds = getattr(args, "kinds", None)
    if kinds is None:
        return None
    result = {kind.strip() for kind in kinds.split(",") if kind.strip()}
    if not result:
        raise ValueError("--kinds must include at least one supported kind")
    unknown = result - SUPPORTED_KINDS
    if unknown:
        raise ValueError(f"Unsupported --kinds value(s): {', '.join(sorted(unknown))}")
    return result


def _run_cur_snapshot(args):
    """Produce an immutable candidate batch before credentials or AWS calls."""
    paths = [Path(path) for path in args.cur]
    initial = tuple(_cur_file_identity(path.stat()) for path in paths)
    month, candidates = cur_candidates(
        args.cur, args.month, args.min_cost, args.max_resources, args.account,
        kind_filter=_cur_kind_filter(args))
    final = tuple(_cur_file_identity(path.stat()) for path in paths)
    if initial != final:
        raise ValueError("CUR input changed during pre-login validation")
    return (month, candidates, final)


def _require_run_cur_unchanged(args, snapshot):
    paths = [Path(path) for path in args.cur]
    current = tuple(_cur_file_identity(path.stat()) for path in paths)
    if current != snapshot[2]:
        raise ValueError("CUR input changed since pre-login validation")


def run_interactive(args):
    """Human-controlled single entry point. Dryrun never invokes an AWS write API."""
    if not ACCOUNT_ID_PATTERN.fullmatch(args.account):
        raise SystemExit(ACCOUNT_ERROR_MESSAGE)
    # Check the private directory AND pre-existing output collisions before
    # login or STS. For a preselected mode, also check mode-specific files.
    out = Path(args.output)
    preflight_report_destination(out)
    preflight_outputs(report_output_paths(out, mode=getattr(args, "mode", None)))
    # Validate local paths before offering credentials or any network access.
    for filename in args.cur:
        if not Path(filename).is_file():
            raise SystemExit(f"CUR missing: {filename}")
    # Validate the *entire* CUR before login/STS/IAM and retain the frozen
    # candidate result. Never silently rebuild it after AWS access.
    prepared_cur = _run_cur_snapshot(args)
    if not offer_remote_login(args):
        return
    session = _budgeted_session(build_session(args.profile))
    ident = show_aws_identity(session, args.account)
    selected = choose_mode(args)
    if selected == "n":
        print("N: 中止しました。AWSタグ・ローカル計画は未変更です。")
        return
    print(f"選択されたモード: {selected}")
    # For interactive selections not known before login, check additional
    # outputs immediately after mode selection and before plan generation.
    preflight_outputs(report_output_paths(out, mode=selected))
    _require_run_cur_unchanged(args, prepared_cur)
    doc = plan(args, session=session, extra_mode="dryrun" if selected == "dryrun" else None,
               prepared_cur=prepared_cur)
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


class ReportPublishCleanupError(RuntimeError):
    """A publish failure followed by one or more incomplete cleanup attempts."""

    def __init__(self, primary_error, cleanup_errors, possibly_remaining):
        self.primary_error = primary_error
        self.cleanup_errors = tuple(cleanup_errors)
        self.possibly_remaining = tuple(possibly_remaining)
        super().__init__(
            f"Report publish failed: {primary_error!r}; "
            f"cleanup failed for {len(self.cleanup_errors)} path(s); "
            f"possibly remaining outputs: {self.possibly_remaining!r}"
        )


def _require_private_publish_directory(fd, purpose):
    """Trust contract for publication: private, caller-owned directory.

    Other UIDs cannot mutate entries in this directory through normal POSIX
    permissions. This is NOT isolation from another process with the same UID
    or a privileged process; parent path and ACL assumptions still apply.
    """
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise PermissionError(
            f"Report {purpose} directory must be owned by the effective UID "
            "and deny group/other access (private mode, e.g. 0700)"
        )


def preflight_report_destination(output_path: Path):
    """Validate the output directory before login, CUR or AWS metadata reads.

    New directories are created as 0700. Existing directories are never
    chmod'd; a non-private or foreign-owned destination fails closed.
    Collision handling remains in preflight_outputs and private_output.
    """
    output_path = Path(output_path)
    _require_report_filesystem_support()
    with _private_directory_fd(output_path.parent) as dfd:
        _require_private_publish_directory(dfd, "destination")


def publish_staged_reports(pairs: list[tuple[Path, Path]]):
    """Publish regular staged files to private directories, without overwrites.

    Existing destination directories with group/other access are rejected;
    callers must choose an owned private output directory. This contract does
    not defend against hostile same-UID/privileged processes or mutable
    ancestor paths. A pathname check alone cannot close those races.
    Multi-file crash/power-loss atomicity is NOT guaranteed.
    """
    if not pairs:
        return
    _require_report_filesystem_support()
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
            _require_private_publish_directory(src_fd, "staging")
            _require_private_publish_directory(dst_fd, "destination")
            # Pre-validate all sources while the private source directory is
            # anchored. os.link(follow_symlinks=False) alone accepts symlinks.
            for src, _ in pairs:
                source_meta = os.stat(
                    Path(src).name, dir_fd=src_fd, follow_symlinks=False
                )
                if not stat.S_ISREG(source_meta.st_mode):
                    raise ValueError(f"Refusing non-regular staged report: {Path(src).name}")
            try:
                for src, dst in pairs:
                    os.link(Path(src).name, Path(dst).name,
                            src_dir_fd=src_fd, dst_dir_fd=dst_fd, follow_symlinks=False)
                    published.append(Path(dst).name)
                os.fsync(dst_fd)
            except BaseException as primary:
                cleanup_errors = []
                possibly_remaining = []
                # Continue independent cleanup attempts even if one fails.
                for name in reversed(published):
                    try:
                        os.unlink(name, dir_fd=dst_fd)
                    except OSError as cleanup_error:
                        cleanup_errors.append((name, cleanup_error))
                        possibly_remaining.append(str(dest_dir / name))
                if cleanup_errors:
                    raise ReportPublishCleanupError(
                        primary, cleanup_errors, possibly_remaining
                    ) from primary
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


def _demote_colliding_proposals(records):
    """Demote proposed Names reused by distinct targets; mutate records in place."""
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


def plan_batch(args, *, scope_declarations, session=None):
    """Build a schema-3 Batch Plan from the bounded CUR and real resolver path."""
    from name_tag_batch_state import batch_name_state, build_batch_review_projection
    from name_tag_batch_state import validate_batch_draft
    from name_tag_batch_state import _validate_scope_declarations

    if not ACCOUNT_ID_PATTERN.fullmatch(args.account):
        raise SystemExit(ACCOUNT_ERROR_MESSAGE)
    if not args.cur or args.min_cost < 0 or args.max_resources <= 0:
        raise SystemExit("Invalid Batch CUR inputs or limits")
    max_send_attempts = getattr(args, "max_send_attempts", 20)
    if type(max_send_attempts) is not int or not 1 <= max_send_attempts <= 20:
        raise SystemExit("--max-send-attempts must be between 1 and 20")
    try:
        _validate_scope_declarations(scope_declarations)
    except (TypeError, ValueError) as error:
        raise SystemExit("Invalid Scope declarations") from error
    out = Path(args.output)
    review_path = out.with_suffix(REVIEW_CSV_SUFFIX)
    report_path = out.with_suffix(REPORT_CSV_SUFFIX)
    destinations = [out, review_path, report_path]
    preflight_report_destination(out)
    preflight_outputs(destinations)

    month, candidates, cur_population, reason_details, kind_precap = cur_candidates_batch(
        args.cur, args.month, args.min_cost, args.max_resources, args.account,
        kind_filter=_cur_kind_filter(args),
    )
    if any(str(candidate.get("region", "")).startswith("us-gov-") for candidate in candidates):
        raise SystemExit("batch-plan does not support GovCloud regions")
    partition=_batch_partition(candidates)
    session = _budgeted_session(session if session is not None else build_session(args.profile))
    assert_account(session, args.account)
    investigator = Investigator(session, args.account, retries=3)
    records = []
    for candidate in candidates:
        info = investigator.resolve(
            candidate, name_state_fn=batch_name_state,
            candidate_states=("ABSENT", "EMPTY", "WHITESPACE_ONLY"),
        )
        record = {**candidate, **info}
        _project_pre_sign_identity(record, partition, args.account)
        record["proposal_id"] = proposal_key(record)
        records.append(record)
    _reject_identity_collisions(records)
    _demote_colliding_proposals(records)
    if session.read_budget.exhausted:
        raise AWSReadBudgetExceeded("AWS read budget exhausted: no partial Batch Plan")
    doc = {
        "schema_version": 3,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "account": args.account,
        "partition": partition,
        "period": month,
        "metric": "Usage/DiscountedUsage(RI effective)/SavingsPlanCoveredUsage(SP effective)",
        "min_cost_usd": args.min_cost,
        "max_resources": args.max_resources,
        "kinds": sorted(_cur_kind_filter(args) or SUPPORTED_KINDS),
        "count": len(records),
        "records": records,
        "cur_population": cur_population,
        "cur_population_by_kind": kind_precap,
        "cur_population_reason_details": reason_details,
        "execution_limits": {"max_send_attempts": max_send_attempts},
        "scope_declarations": scope_declarations,
    }
    plan_bytes = (json.dumps(doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()
    review_bytes = build_batch_review_projection(plan_bytes)
    validate_batch_draft(plan_bytes, review_bytes)
    session.read_budget.require_completion()
    ensure_private_output_dir(out.parent)
    with tempfile.TemporaryDirectory(prefix=f".{out.stem}.stage-", dir=out.parent) as staging:
        stage = Path(staging)
        plan_stage, review_stage, report_stage = (stage / path.name for path in destinations)
        write_json(plan_stage, doc)
        with private_output(review_stage) as stream:
            stream.write(review_bytes.decode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        write_action_csv(report_stage, records, args.account, mode="batch-plan",
                         scope_declarations=scope_declarations)
        session.read_budget.require_completion()
        publish_staged_reports(list(zip((plan_stage, review_stage, report_stage), destinations)))
    return doc


def batch_plan_cli(args, *, session=None):
    from name_tag_batch_state import _unique_object

    path = Path(args.scope_declarations)
    if path.is_symlink() or not path.is_file():
        raise SystemExit("--scope-declarations must be a regular file")
    try:
        declaration_doc = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SystemExit("Invalid --scope-declarations JSON") from exc
    if (not isinstance(declaration_doc, dict)
            or set(declaration_doc) != {"scope_declarations"}
            or not isinstance(declaration_doc["scope_declarations"], list)):
        raise SystemExit("Scope declaration file must contain only scope_declarations")
    return plan_batch(
        args, scope_declarations=declaration_doc["scope_declarations"], session=session
    )


def plan(args, session=None, *, extra_mode=None, prepared_cur=None):
    if not ACCOUNT_ID_PATTERN.fullmatch(args.account):raise SystemExit(ACCOUNT_ERROR_MESSAGE)
    if not args.cur:raise SystemExit("Provide at least one --cur .csv.gz file")
    out=Path(args.output)
    review=out.with_suffix(REVIEW_CSV_SUFFIX)
    report=out.with_suffix(REPORT_CSV_SUFFIX)
    destinations=report_output_paths(out, mode=extra_mode)
    # Validate the output trust contract before CUR parsing and AWS session use.
    preflight_report_destination(out)
    preflight_outputs(destinations)
    kind_filter = _cur_kind_filter(args)
    if prepared_cur is None:
        month,candidates=cur_candidates(args.cur,args.month,args.min_cost,args.max_resources,args.account,kind_filter=kind_filter)
    else:
        _require_run_cur_unchanged(args, prepared_cur)
        month,candidates=prepared_cur[:2]
    session = _budgeted_session(session if session is not None else build_session(args.profile))
    assert_account(session,args.account)
    investigator=Investigator(session,args.account, retries=3)
    records=[]
    for idx,item in enumerate(candidates,1):
        info=investigator.resolve(item)
        rec={**item,**info}
        rec["proposal_id"]=proposal_key(rec)
        rec["resource_arn"] = resource_arn(rec, args.account)
        records.append(rec)
        # Candidate names are not emitted before full validation succeeds.
        # A later budget failure must leave neither a report nor leaked stderr
        # records of a plan that never completed.
    _demote_colliding_proposals(records)
    if session.read_budget.exhausted:
        raise AWSReadBudgetExceeded("AWS read budget exhausted: no partial candidate report")
    doc={"schema_version":2,"generated_at_utc":datetime.now(timezone.utc).isoformat(),"account":args.account,"period":month,
         "metric":"Usage/DiscountedUsage(RI effective)/SavingsPlanCoveredUsage(SP effective); excludes one-time fees, unallocated and no-resource charges",
         "min_cost_usd":args.min_cost,"count":len(records),"records":records}
    if prepared_cur is not None:
        _require_run_cur_unchanged(args, prepared_cur)
    session.read_budget.require_completion()
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
        # Offline serialization/fsync may consume the remaining deadline.
        # Do not publish previously validated proposals after it expires.
        session.read_budget.require_completion()
        publish_staged_reports(list(zip(staged,destinations)))
    for idx, rec in enumerate(records, 1):
        print(f"[{idx:>3}/{len(records)}] {rec['effective_usage_cost_usd']:8.2f} {rec['status']:>14} {rec['kind']:16} {rec['proposed_name'] or rec['locator'][:55]}", file=sys.stderr)
    print(f"PLAN={out} SHA256={sha256(out)}\nREVIEW={review}\nREPORT={report}\nNo AWS tags were changed.")
    return doc


def apply(args):
    """Disabled in safety-hold release, including programmatic direct calls."""
    raise SystemExit("ABORT: " + SAFETY_HOLD)


def _validate_cli_args(args, parser):
    if args.command in ("plan", "batch-plan", "run"):
        if args.min_cost < 0 or args.max_resources <= 0:
            parser.error("--min-cost must be nonnegative and --max-resources > 0")
        if args.month and not re.fullmatch(r"\d{4}-(?:0[1-9]|1[0-2])", args.month):
            parser.error("Invalid --month")
        if args.command == "batch-plan" and not 1 <= args.max_send_attempts <= 20:
            parser.error("--max-send-attempts must be between 1 and 20")
        if args.command == "run" and args.max_writes <= 0:
            parser.error("--max-writes must be positive")
        return
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        parser.error("--sha256 must be a 64-character lowercase hex string")
    if args.max_writes <= 0:
        parser.error("--max-writes must be positive")


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
    p.add_argument("--output",default=DEFAULT_REPORT_OUTPUT)
    p.set_defaults(func=plan)
    b=sub.add_parser("batch-plan",help="Read CUR/AWS metadata into a schema-3 Batch Plan; never write tags")
    b.add_argument("--cur",action="append",required=True)
    b.add_argument("--month")
    b.add_argument("--account",required=True)
    b.add_argument("--profile")
    b.add_argument("--min-cost",type=float,default=DEFAULT_THRESHOLD)
    b.add_argument("--max-resources",type=int,default=100)
    b.add_argument("--max-send-attempts",type=int,default=20)
    b.add_argument("--kinds")
    b.add_argument("--scope-declarations",required=True)
    b.add_argument("--output",default=DEFAULT_REPORT_OUTPUT)
    b.set_defaults(func=batch_plan_cli)
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
    r.add_argument("--output",default=DEFAULT_REPORT_OUTPUT)
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
    _validate_cli_args(args,ap)
    return args


if __name__=="__main__":
    try:
        args = parse_cli()
        args.func(args)
    except Exception:
        raise
