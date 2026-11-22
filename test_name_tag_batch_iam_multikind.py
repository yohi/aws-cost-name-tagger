"""Offline Task 4 tests: per-Kind least-privilege session policy. No STS, no AWS.

The non-volume Kinds below are TEST-ONLY fixtures patched in per test; no production
Registry decision is promoted by them.
"""
from __future__ import annotations

import contextlib
import dataclasses
import inspect
import json
import unittest
from types import MappingProxyType
from unittest import mock

import name_tag_batch_iam as iam
import name_tag_kind_capabilities as caps
import name_tag_kind_name_evidence as evidence_module
from name_tag_batch_approval import VerifiedBatchApproval, prepare_batch_approval
from name_tag_batch_iam import (
    IAMPolicyBlocked, KindPolicy, SessionPolicySpec, build_subset_session_policy,
    verified_kind_policy)
from name_tag_batch_state import validate_batch_draft
from test_name_tag_kind_name_evidence import (
    FixtureInstanceVerifier, INSTANCE_ARN as _FIXTURE_ARN, VOL_ARN, _instance_record, _plan,
    _scope, _volume_record, _yes, R)

LIMIT = 2048
INSTANCE_ARN = _FIXTURE_ARN.replace("456720798575", "123456789012")


@contextlib.contextmanager
def proven(kind="instance", *, extra_reads=(), **changes):
    """Test-only: mark one Kind IMPLEMENTED_OFFLINE with the fixture Name verifier."""
    base = caps.resolve_kind_capability(kind)
    decision = dataclasses.replace(
        base, status="IMPLEMENTED_OFFLINE", reason_code="OFFLINE_CONTRACT_COMPLETE",
        evidence_refs=("test-only fixture",),
        read_operations=base.read_operations + tuple(extra_reads), **changes)
    decisions = MappingProxyType({**caps._DECISIONS, kind: decision})
    with mock.patch.object(caps, "_DECISIONS", decisions), \
            mock.patch.dict(evidence_module._VERIFIERS, {kind: FixtureInstanceVerifier()}):
        yield decision


def build_batch(records=None):
    records = records or [_volume_record("p0"), _instance_record("p1")]
    arns = [r["resource_arn"] for r in records]
    plan = _plan(records, [_scope(arns)])
    csv = _yes(plan, records[0]["proposal_id"])
    for r in records[1:]:
        csv = csv.replace(f",{r['proposal_id']},".encode(), f"YES,{r['proposal_id']},".encode())
    draft = validate_batch_draft(plan, csv)
    prepared = prepare_batch_approval(
        plan, csv, owner_principal_id="owner", owner_key_fingerprint="SHA256:key",
        authorized_role_arn="arn:aws:iam::123456789012:role/Batch",
        issued_at_utc="2026-11-19T00:00:00Z", expires_at_utc="2026-11-20T00:00:00Z",
        batch_nonce="ab" * 16)
    indexes = tuple(row[0] for row in __import__("name_tag_batch_approval")._approved_tuples(draft))
    batch = VerifiedBatchApproval(
        b"fixture-envelope", prepared.canonical_payload_bytes, prepared.batch_id,
        MappingProxyType(dict(prepared.payload)), plan, csv,
        tuple(dict(r) for r in draft.approved_rows), indexes, "owner", "fixture-signature")
    by_kind = {row["kind"]: i for i, row in zip(indexes, draft.approved_rows)}
    return batch, by_kind


def registry():
    return {"volume": KindPolicy("ec2:CreateTags", "ec2:DescribeVolumes"),
            "instance": verified_kind_policy(caps.resolve_kind_capability("instance"))}


class MultiKindPolicyTests(unittest.TestCase):
    def test_mixed_kind_policy_never_cross_grants(self):
        with proven():
            batch, idx = build_batch()
            spec = build_subset_session_policy(
                batch, tuple(sorted(idx.values())), kind_registry=registry())
            policy = json.loads(spec.policy_bytes)
            writes = [s for s in policy["Statement"] if s["Sid"].startswith("ApprovedNameTagWrites")]
            self.assertEqual(len(writes), 2)  # one statement per action/resource-type triple
            for s in writes:
                self.assertNotEqual(s["Resource"], "*")
                self.assertEqual(len(s["Resource"]), 1)
                self.assertEqual(len(s["Action"]), 1)
            arns = {s["Resource"][0] for s in writes}
            self.assertEqual(arns, {VOL_ARN, INSTANCE_ARN})
            self.assertEqual({s["Resource"][0].split(":")[5].split("/")[0] for s in writes},
                             {"volume", "instance"})
            reads = [s for s in policy["Statement"] if s["Sid"] == "ReadOnlyForPreflightAndReadback"]
            self.assertEqual(reads[0]["Action"], ["ec2:DescribeInstances", "ec2:DescribeVolumes"])

    def test_unsupported_iam_condition_rejects_without_policy(self):
        # rds_instance claims aws:TagKeys but no action-specific documentation exists for it.
        with proven("rds_instance") as decision:
            with self.assertRaises(IAMPolicyBlocked) as ctx:
                verified_kind_policy(decision)
            self.assertIn("IAM_CONDITION_NOT_PROVEN", str(ctx.exception))
        with proven(tag_key_conditions=()) as decision:  # EC2 without a declared condition
            with self.assertRaises(IAMPolicyBlocked) as ctx:
                verified_kind_policy(decision)
            self.assertIn("IAM_CONDITION_NOT_PROVEN", str(ctx.exception))
        # Production Kind stays unproven: no policy.
        with self.assertRaises(IAMPolicyBlocked):
            verified_kind_policy(caps.resolve_kind_capability("rds_instance"))

    def test_apigw_put_http_not_assumed_iam_grant(self):
        production = caps.resolve_kind_capability("apigw_stage")
        self.assertEqual(production.status, "CAPABILITY_NOT_PROVEN")
        self.assertEqual(production.reason_code, "IAM_CONDITION_NOT_PROVEN")
        with self.assertRaises(IAMPolicyBlocked):
            verified_kind_policy(production)
        for action in ("apigateway:PATCH", "apigateway:PUT", "apigateway:POST"):
            with self.subTest(action), proven("apigw_stage", iam_action=action,
                                              write_operation=action) as decision:
                with self.assertRaises(IAMPolicyBlocked) as ctx:
                    verified_kind_policy(decision)
                self.assertIn("IAM_CONDITION_NOT_PROVEN", str(ctx.exception))
        self.assertNotIn("apigateway:", json.dumps(list(iam._PROVEN_CONDITION_ACTIONS)))

    def test_policy_size_excess_no_wildcard_fallback(self):
        pad = "describe_" + "a" * 3000
        with proven(extra_reads=(pad,)):
            batch, idx = build_batch()
            reg = registry()
            with self.assertRaises(IAMPolicyBlocked):
                build_subset_session_policy(batch, (idx["instance"],), kind_registry=reg)

    def test_existing_volume_policy_byte_stable(self):
        batch, idx = build_batch([_volume_record("p0")])
        spec = build_subset_session_policy(
            batch, (idx["volume"],),
            kind_registry={"volume": KindPolicy("ec2:CreateTags", "ec2:DescribeVolumes")})
        expected = json.dumps({
            "Version": "2012-10-17", "Statement": [
                {"Sid": "ApprovedNameTagWritesOnly", "Effect": "Allow", "Action": ["ec2:CreateTags"],
                 "Resource": [VOL_ARN],
                 "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["Name"]},
                               "Null": {"aws:TagKeys": "false"}}},
                {"Sid": "ReadOnlyForPreflightAndReadback", "Effect": "Allow",
                 "Action": ["ec2:DescribeVolumes"], "Resource": "*"}]},
            sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(spec.policy_bytes, expected)
        self.assertEqual(verified_kind_policy(caps.resolve_kind_capability("volume")),
                         KindPolicy("ec2:CreateTags", "ec2:DescribeVolumes"))


class SingletonHostPolicyTests(unittest.TestCase):
    """RG-PRC-005 / RG-PRC-007: the Host asks only for (selected_row_index,)."""

    def test_singleton_host_policy_uses_only_signed_index(self):
        with proven():
            batch, idx = build_batch()
            spec = build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())
            self.assertEqual(spec.row_indexes, (idx["instance"],))
            self.assertEqual(spec.write_arns, (INSTANCE_ARN,))
            self.assertEqual(spec.write_actions, ("ec2:CreateTags",))
            self.assertTrue(spec.policy_bytes.isascii())
            self.assertEqual(len(json.loads(spec.policy_bytes)["Statement"]), 2)
            with self.assertRaises(IAMPolicyBlocked):  # unsigned/unapproved index
                build_subset_session_policy(batch, (99,), kind_registry=registry())

    def test_host_policy_excludes_foreign_approved_rows(self):
        with proven():
            batch, idx = build_batch()
            spec = build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())
            self.assertNotIn(VOL_ARN.encode(), spec.policy_bytes)
            self.assertNotIn(b"DescribeVolumes", spec.policy_bytes)
            volume = build_subset_session_policy(batch, (idx["volume"],), kind_registry=registry())
            self.assertNotIn(INSTANCE_ARN.encode(), volume.policy_bytes)
            self.assertNotIn(b"DescribeInstances", volume.policy_bytes)

    def test_oversized_singleton_policy_blocks_no_fallback(self):
        with proven(extra_reads=("describe_" + "a" * 3000,)):
            batch, idx = build_batch()
            with self.assertRaises(IAMPolicyBlocked):
                build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())
            # No other row is chosen: the volume row is independent and still builds alone.
            ok = build_subset_session_policy(batch, (idx["volume"],), kind_registry=registry())
            self.assertEqual(ok.row_indexes, (idx["volume"],))

    def test_blocked_kind_cannot_be_skipped(self):
        with proven():
            batch, idx = build_batch()
            reg = registry()
        # Outside the fixture the production Registry (CNP) blocks the whole signed batch.
        for row in (idx["instance"], idx["volume"]):
            with self.assertRaises(IAMPolicyBlocked):
                build_subset_session_policy(batch, (row,), kind_registry=reg)
        with proven():
            with self.assertRaises(IAMPolicyBlocked):  # unregistered Kind: no silent skip
                build_subset_session_policy(batch, (idx["instance"],),
                                            kind_registry={"volume": reg["volume"]})
            with self.assertRaises(IAMPolicyBlocked):  # forged policy for the Kind
                build_subset_session_policy(
                    batch, (idx["instance"],),
                    kind_registry={"instance": KindPolicy("ec2:CreateTags", "ec2:DescribeInstances")})

    def test_offline_policy_builder_contract_unchanged(self):
        sig = inspect.signature(build_subset_session_policy)
        self.assertEqual(list(sig.parameters), ["batch", "row_indexes", "kind_registry"])
        self.assertEqual(sig.parameters["kind_registry"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual([f.name for f in dataclasses.fields(SessionPolicySpec)],
                         ["batch_id", "row_indexes", "policy_bytes", "policy_sha256",
                          "write_arns", "write_actions", "read_actions"])
        legacy = KindPolicy("ec2:CreateTags", "ec2:DescribeVolumes")
        self.assertEqual((legacy.write_action, legacy.read_action), ("ec2:CreateTags", "ec2:DescribeVolumes"))
        with self.assertRaises(IAMPolicyBlocked):
            build_subset_session_policy(build_batch([_volume_record("p0")])[0], (), kind_registry={})

    def _exact(self, target):
        with proven(extra_reads=("describe_a",)):
            batch, idx = build_batch([_instance_record("p1")])
            base = len(build_subset_session_policy(
                batch, (idx["instance"],), kind_registry=registry()).policy_bytes)
        return 1 + target - base

    def test_inline_policy_2048_ascii_boundary(self):
        pad = self._exact(LIMIT)
        with proven(extra_reads=("describe_" + "a" * pad,)):
            batch, idx = build_batch([_instance_record("p1")])
            spec = build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())
        self.assertEqual(len(spec.policy_bytes), LIMIT)
        self.assertTrue(spec.policy_bytes.isascii())
        self.assertEqual(len(spec.policy_bytes.decode("ascii")), len(spec.policy_bytes))

    def test_inline_policy_over_2048_blocks_before_sts(self):
        pad = self._exact(LIMIT + 1)
        with proven(extra_reads=("describe_" + "a" * pad,)):
            batch, idx = build_batch([_instance_record("p1")])
            with mock.patch.dict("sys.modules", {"boto3": None, "botocore": None}):
                with self.assertRaises(IAMPolicyBlocked):
                    build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())

    def test_no_pre_sts_packed_metric_required(self):
        names = [f.name.lower() for f in dataclasses.fields(SessionPolicySpec)]
        names += [p.lower() for p in inspect.signature(build_subset_session_policy).parameters]
        self.assertFalse([n for n in names if "packed" in n or "utilization" in n or "sts" in n.split("_")])
        source = inspect.getsource(iam)
        for forbidden in ("boto3", "assume_role", "PackedPolicySize", "SessionTokenUtilization"):
            self.assertNotIn(forbidden, source)

    def test_exact_singleton_action_arn_stable(self):
        with proven():
            batch, idx = build_batch()
            first = build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())
            second = build_subset_session_policy(batch, (idx["instance"],), kind_registry=registry())
        self.assertEqual(first, second)
        write = json.loads(first.policy_bytes)["Statement"][0]
        self.assertEqual(write["Action"], ["ec2:CreateTags"])
        self.assertEqual(write["Resource"], [INSTANCE_ARN])
        self.assertEqual(write["Condition"]["ForAllValues:StringEquals"]["aws:TagKeys"], ["Name"])


if __name__ == "__main__":
    unittest.main()
