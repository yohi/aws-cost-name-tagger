"""D2 RCP contract tests, including R4-OBS-001 schema closure."""
import copy
import hashlib
import unittest

from g2_d2_rcp import evaluate_action, ResourceContractError, AWS_WRITES


def resource(index, typ, name, *, owner="member-account", **kw):
    row = {
        "resource_index": index,
        "resource_type": typ,
        "resource_arn": "arn:synthetic:" + name,
        "resource_owner_account": owner,
        "resource_evidence_id": "synthetic-resource-proof",
        "sar_evidence_id": "synthetic-sar-row",
        "rcp_supported": True,
        "rcp_support_evidence_id": "synthetic-rcp-service-evidence",
        "exception_code": "NONE",
    }
    row.update(kw)
    if row["exception_code"] != "NONE" and row.get("exception_evidence_id") is not None:
        row.setdefault("exception_source_url", "https://docs.aws.amazon.com/synthetic-fixture")
        row.setdefault("exception_source_sha256", hashlib.sha256(b"synthetic-official-source").hexdigest())
        row.setdefault("exception_checked_at_utc", "2026-10-23T00:00:00Z")
    return row


def fixture(rows=None, *, action="synthetic:Action"):
    rows = list(rows if rows is not None else [resource(0, "type-a", "a")])
    payload = {
        "actor_id": "synthetic-role",
        "action": action,
        "request_fingerprint_sha256": "synthetic-request-hash",
        "authorization_reference_evidence_id": "synthetic-sar-snapshot",
        "authorized_resource_types": [
            {"resource_type": "type-a", "required_or_optional": "REQUIRED",
             "sar_evidence_id": "synthetic-sar-row"},
            {"resource_type": "type-b", "required_or_optional": "OPTIONAL",
             "sar_evidence_id": "synthetic-sar-row"},
            {"resource_type": "key", "required_or_optional": "OPTIONAL",
             "sar_evidence_id": "synthetic-sar-row"},
        ],
        "expected_resources": [
            {"resource_index": row["resource_index"],
             "resource_type": row["resource_type"],
             "resource_arn": row["resource_arn"],
             "resource_owner_account": row["resource_owner_account"],
             "evidence_id": "synthetic-expected-set-item"}
            for row in rows
        ],
        "expected_authorized_resource_count": len(rows),
        "expected_resource_set_evidence_id": "synthetic-request-binding-proof",
        "resource_evaluations": rows,
        "service_linked_role": False,
        "service_linked_role_evidence_id": "synthetic-role-proof",
        "management_account_id": "management-account",
        "management_account_evidence_id": "synthetic-organization-proof",
    }
    # A request-specific synthetic explanation is needed when SAR requires
    # a type that the closed request resource set does not contain.
    present = {row["resource_type"] for row in rows}
    payload["absent_required_resource_types"] = [
        {
            "resource_type": item["resource_type"],
            "reason": "ACTION_VARIANT_NOT_APPLICABLE",
            "evidence_id": "synthetic-request-specific-absence-proof",
            "request_fingerprint_sha256": payload["request_fingerprint_sha256"],
            "sar_evidence_id": item["sar_evidence_id"],
        }
        for item in payload["authorized_resource_types"]
        if item["required_or_optional"] == "REQUIRED"
        and item["resource_type"] not in present
    ]
    return payload


class ResourceEvaluationTests(unittest.TestCase):
    def test_all_covered_and_retains_required_optional_sar_attributes(self):
        out = evaluate_action(fixture())
        self.assertEqual(out["aggregate_coverage"], "COVERED")
        self.assertEqual(out["resource_evaluations"][0]["rcp_applicable"], "APPLICABLE")
        self.assertEqual(out["authorized_resource_types"][0]["required_or_optional"],
                         "REQUIRED")
        self.assertEqual(out["authorized_resource_types"][1]["required_or_optional"],
                         "OPTIONAL")
        self.assertEqual(out["effective_write_reachability"], "UNKNOWN")
        self.assertEqual(out["g2_gate"], "NOT_VERIFIED")

    def test_d2_003_sar_required_type_missing_requires_request_bound_reason(self):
        # SAR type-a REQUIRED; request only identifies optional type-b.
        request = fixture([resource(0, "type-b", "b")])
        self.assertEqual(evaluate_action(request)["aggregate_coverage"], "COVERED")
        for field, bad in (
            ("absent_required_resource_types", []),
            ("absent_required_resource_types", None),
        ):
            case = copy.deepcopy(request)
            case[field] = bad
            with self.subTest(field=field, bad=bad):
                self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")
        for field, bad in (
            ("request_fingerprint_sha256", "different-request"),
            ("sar_evidence_id", "different-sar"),
            ("evidence_id", None),
            ("reason", "UNVERIFIED"),
        ):
            case = copy.deepcopy(request)
            case["absent_required_resource_types"][0][field] = bad
            with self.subTest(field=field):
                self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")
        case = copy.deepcopy(request)
        case["absent_required_resource_types"].append(
            copy.deepcopy(case["absent_required_resource_types"][0]))
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_mixed_and_unknown_priority(self):
        first = resource(0, "type-a", "a")
        second = resource(
            1, "type-b", "b", rcp_supported=False,
            exception_code="UNSUPPORTED_ACTION_RESOURCE",
            exception_evidence_id="synthetic-official-sar-proof")
        self.assertEqual(evaluate_action(fixture([first, second]))["aggregate_coverage"],
                         "MIXED")
        second["exception_evidence_id"] = None
        self.assertEqual(evaluate_action(fixture([first, second]))["aggregate_coverage"],
                         "UNKNOWN")

    def test_all_not_covered_requires_official_evidence(self):
        rows = [
            resource(0, "type-a", "a", rcp_supported=False,
                     exception_code="UNSUPPORTED_ACTION_RESOURCE",
                     exception_evidence_id="sar-proof"),
            resource(1, "type-b", "b", rcp_supported=False,
                     exception_code="UNSUPPORTED_ACTION_RESOURCE",
                     exception_evidence_id="sar-proof"),
        ]
        self.assertEqual(evaluate_action(fixture(rows))["aggregate_coverage"],
                         "NOT_COVERED")

    def test_unknown_owner_and_no_implicit_coverage(self):
        row = resource(0, "type-a", "a", owner=None, exception_code="OWNER_UNKNOWN")
        self.assertEqual(evaluate_action(fixture([row]))["aggregate_coverage"], "UNKNOWN")

    def test_expected_count_and_closure_evidence_missing(self):
        orig = fixture()
        cases = []
        missing_count = copy.deepcopy(orig)
        missing_count["expected_authorized_resource_count"] = 2
        cases.append(missing_count)
        missing_source = copy.deepcopy(orig)
        missing_source["expected_resource_set_evidence_id"] = None
        cases.append(missing_source)
        no_rows = copy.deepcopy(orig)
        no_rows["expected_resources"] = []
        no_rows["resource_evaluations"] = []
        no_rows["expected_authorized_resource_count"] = 0
        cases.append(no_rows)
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_duplicate_indexes_and_duplicate_resource_arn_type(self):
        one = resource(0, "type-a", "shared")
        for second in (
            resource(0, "type-b", "different"),
            resource(1, "type-a", "shared"),
        ):
            with self.subTest(second=second):
                self.assertEqual(
                    evaluate_action(fixture([one, second]))["aggregate_coverage"],
                    "UNKNOWN")

    def test_missing_resource_and_unmatched_sar_type(self):
        case = fixture([resource(0, "type-a", "a"),
                        resource(1, "type-b", "b")])
        case["resource_evaluations"].pop()
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")
        case = fixture([resource(0, "type-z", "unrecognized")])
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_sar_type_missing_required_or_optional(self):
        case = fixture()
        case["authorized_resource_types"][0].pop("required_or_optional")
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_aws_managed_kms_key_exception(self):
        row = resource(
            0, "key", "kms", exception_code="AWS_MANAGED_KMS_KEY",
            key_manager="AWS",
            key_manager_evidence_id="synthetic-describe-key-proof",
            exception_evidence_id="official-rcp-exception-proof")
        result = evaluate_action(fixture([row], action="kms:Decrypt"))
        self.assertEqual(result["aggregate_coverage"], "NOT_COVERED")
        self.assertEqual(result["resource_evaluations"][0]["rcp_applicable"], "EXEMPT")
        row["key_manager"] = "CUSTOMER"
        self.assertEqual(
            evaluate_action(fixture([row], action="kms:Decrypt"))["aggregate_coverage"],
            "UNKNOWN")
        row["key_manager"] = "AWS"
        row["exception_evidence_id"] = None
        self.assertEqual(
            evaluate_action(fixture([row], action="kms:Decrypt"))["aggregate_coverage"],
            "UNKNOWN")

    def test_exception_requires_source_hash_and_date(self):
        row = resource(
            0, "key", "kms", exception_code="AWS_MANAGED_KMS_KEY",
            key_manager="AWS", key_manager_evidence_id="synthetic-key-proof",
            exception_evidence_id="official-rcp-exception-proof")
        for field in ("exception_source_url", "exception_source_sha256",
                      "exception_checked_at_utc"):
            case = copy.deepcopy(row)
            case.pop(field)
            with self.subTest(field=field):
                self.assertEqual(
                    evaluate_action(fixture([case], action="kms:Decrypt"))
                    ["aggregate_coverage"], "UNKNOWN")

    def test_d2_005_official_source_must_have_valid_https_url_and_utc_date(self):
        row = resource(
            0, "key", "kms", exception_code="AWS_MANAGED_KMS_KEY",
            key_manager="AWS", key_manager_evidence_id="synthetic-key-proof",
            exception_evidence_id="official-sar-proof")
        for field, bad in (
            ("exception_source_url", "not-a-url"),
            ("exception_source_url", "http://docs.aws.amazon.com/test"),
            ("exception_source_url", "https://not-amazon.example/test"),
            ("exception_checked_at_utc", "invalid-date"),
            ("exception_checked_at_utc", "2026-99-99T25:61:61Z"),
            ("exception_checked_at_utc", "2026-10-23T00:00:00+09:00"),
        ):
            case = copy.deepcopy(row)
            case[field] = bad
            with self.subTest(field=field, bad=bad):
                self.assertEqual(
                    evaluate_action(fixture([case], action="kms:Decrypt"))
                    ["aggregate_coverage"], "UNKNOWN")
        self.assertEqual(
            evaluate_action(fixture([row], action="kms:Decrypt"))
            ["aggregate_coverage"], "NOT_COVERED")

    def test_aws_managed_key_exception_requires_exact_kms_action_and_type(self):
        row = resource(
            0, "key", "kms", exception_code="AWS_MANAGED_KMS_KEY",
            key_manager="AWS", key_manager_evidence_id="synthetic-key-proof",
            exception_evidence_id="official-rcp-exception-proof")
        self.assertEqual(
            evaluate_action(fixture([row], action="synthetic:Action"))
            ["aggregate_coverage"], "UNKNOWN")
        row["resource_type"] = "key-other"
        case = fixture([row], action="kms:Decrypt")
        case["authorized_resource_types"].append(
            {"resource_type": "key-other", "required_or_optional": "OPTIONAL",
             "sar_evidence_id": "synthetic-sar-row"})
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_kms_retire_grant_action_specific_exception(self):
        row = resource(0, "key", "kms", exception_code="KMS_RETIRE_GRANT",
                       exception_evidence_id="official-kms-retire-proof")
        self.assertEqual(
            evaluate_action(fixture([row], action="kms:RetireGrant"))["aggregate_coverage"],
            "NOT_COVERED")
        self.assertEqual(
            evaluate_action(fixture([row], action="kms:Decrypt"))["aggregate_coverage"],
            "UNKNOWN")

    def test_management_resource_and_slr_exceptions(self):
        row = resource(0, "type-a", "a", owner="management-account",
                       exception_code="MANAGEMENT_RESOURCE",
                       exception_evidence_id="official-management-exception")
        self.assertEqual(evaluate_action(fixture([row]))["aggregate_coverage"],
                         "NOT_COVERED")
        row2 = resource(0, "type-a", "a", exception_code="SERVICE_LINKED_ROLE",
                        exception_evidence_id="official-slr-exception")
        case = fixture([row2])
        case["service_linked_role"] = True
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "NOT_COVERED")
        case["service_linked_role_evidence_id"] = None
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_error_inputs_fail_closed_without_executing_objects(self):
        for obj in (None, [], {"actor_id": object()},
                    fixture([resource(0, "type-a", "a")]) | {"unexpected": object()}):
            with self.subTest(obj=obj), self.assertRaises(ResourceContractError):
                evaluate_action(obj)

    def test_unknown_field_types_do_not_crash(self):
        case = fixture()
        case["resource_evaluations"][0]["exception_code"] = []
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")
        case = fixture()
        case["resource_evaluations"][0]["resource_type"] = []
        self.assertEqual(evaluate_action(case)["aggregate_coverage"], "UNKNOWN")

    def test_never_infers_writer_or_aws_evidence(self):
        self.assertEqual(AWS_WRITES, "BLOCKED")
        result = evaluate_action(fixture())
        self.assertEqual(result["provenance"], "SYNTHETIC_FIXTURE_ONLY")
        self.assertEqual(result["effective_write_reachability"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
