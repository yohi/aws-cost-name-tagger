"""Contract tests use only synthetic dictionaries; no AWS credentials or networking."""
import ast
from pathlib import Path
import unittest

import g2_collector_contract as c


ACCOUNT = "456720798575"
OTHER = "000000000000"
REGION = "ap-northeast-1"
START = "2026-10-01T00:00:00Z"
END = "2026-10-02T00:00:00Z"


def fixtures(account=ACCOUNT, regions=(REGION,), iam_begin=None, iam_end=None):
    first = {"IsTruncated": False, "RoleDetailList": [{"RoleName": "synthetic"}]}
    scripts = {
        ("sts", "GetCallerIdentity", "global"): [
            {"Account": account}, {"Account": account}],
        ("iam", "GetAccountAuthorizationDetails", "global"): [
            iam_begin if iam_begin is not None else first,
            iam_end if iam_end is not None else first,
        ],
    }
    for probe in c.build_plan(ACCOUNT, regions, START, END):
        key = (probe.service, probe.operation, probe.region)
        if key not in {("sts", "GetCallerIdentity", "global"),
                       ("iam", "GetAccountAuthorizationDetails", "global")}:
            scripts.setdefault(key, []).append({"NextToken": None})
    return scripts


def simulate(data=None, regions=(REGION,)):
    port = c.FixturePort(data if data is not None else fixtures(regions=regions))
    result = c.run_simulation(port, ACCOUNT, regions, START, END)
    return port, result


class I1MockOnlyTests(unittest.TestCase):
    def test_normal_simulation_never_proves_g2_or_calls_aws(self):
        port, result = simulate()
        self.assertEqual(result["status"], "MOCK_ONLY_PARTIAL_COVERAGE")
        self.assertEqual(result["g2_gate"], "NOT_VERIFIED")
        self.assertFalse(result["snapshot_atomic"])
        self.assertFalse(result["read_only_verified"])
        self.assertEqual(result["aws_calls"], 0)
        self.assertEqual(result["begin_end_iam"]["consistency"], "SIMULATED_IAM_MATCH_ONLY")
        self.assertEqual(len(result["probes"]), 9)
        self.assertEqual(len(port.calls), 12)
        self.assertGreater(len(result["not_collected"]), 6)
        self.assertTrue(all(p["provenance"] == "SYNTHETIC_FIXTURE_ONLY" for p in result["probes"]))
        self.assertTrue(all(p["status"] == "SIMULATED_PAGE_TERMINATED" for p in result["probes"]))

    def test_wrong_account_aborts_before_other_operations(self):
        port = c.FixturePort(fixtures(account=OTHER))
        result = c.run_simulation(port, ACCOUNT, (REGION,), START, END)
        self.assertEqual(result["status"], "ABORTED_IDENTITY")
        self.assertEqual(len(port.calls), 1)
        self.assertEqual(port.calls[0][0], "sts")

    def test_identity_access_denied_fails_closed(self):
        samples = fixtures()
        samples[("sts", "GetCallerIdentity", "global")] = [c.FixtureAccessDenied()]
        port, result = simulate(samples)
        self.assertEqual(result["status"], "ABORTED_IDENTITY")
        self.assertEqual(len(port.calls), 1)

    def test_end_account_changed_causes_unknown(self):
        samples = fixtures()
        samples[("sts", "GetCallerIdentity", "global")][1] = {"Account": OTHER}
        _, result = simulate(samples)
        self.assertEqual(result["begin_end_iam"]["consistency"], "UNKNOWN")

    def test_iam_configuration_change_marks_inconsistent(self):
        data = fixtures(iam_end={"IsTruncated": False, "RoleDetailList": [{"RoleName": "changed"}]})
        _, result = simulate(data)
        self.assertEqual(result["begin_end_iam"]["consistency"], "INCONSISTENT")
        self.assertEqual(result["g2_gate"], "NOT_VERIFIED")

    def test_iam_marker_two_pages_begin_and_end(self):
        data = fixtures()
        data[("iam", "GetAccountAuthorizationDetails", "global")] = [
            {"IsTruncated": True, "Marker": "NEXT", "UserDetailList": []},
            {"IsTruncated": False, "UserDetailList": [{"UserName": "synthetic"}]},
            {"IsTruncated": True, "Marker": "NEXT", "UserDetailList": []},
            {"IsTruncated": False, "UserDetailList": [{"UserName": "synthetic"}]},
        ]
        port, result = simulate(data)
        iam = result["probes"][0]
        self.assertEqual(iam["pages"], 2)
        self.assertTrue(iam["pagination_complete"])
        self.assertEqual(result["begin_end_iam"]["consistency"], "SIMULATED_IAM_MATCH_ONLY")
        calls = [x for x in port.calls if x[1] == "GetAccountAuthorizationDetails"]
        self.assertEqual(calls[1][3]["Marker"], "NEXT")
        self.assertEqual(calls[3][3]["Marker"], "NEXT")

    def test_iam_true_truncation_without_marker_is_partial(self):
        data = fixtures(iam_begin={"IsTruncated": True, "RoleDetailList": []})
        _, result = simulate(data)
        self.assertEqual(result["probes"][0]["status"], "PARTIAL")
        self.assertEqual(result["probes"][0]["reason"], "TRUNCATED_WITHOUT_MARKER")
        self.assertEqual(result["begin_end_iam"]["consistency"], "UNKNOWN")

    def test_iam_missing_truncation_flag_is_unknown(self):
        data = fixtures(iam_begin={"RoleDetailList": []})
        _, result = simulate(data)
        self.assertEqual(result["probes"][0]["status"], "UNKNOWN")
        self.assertEqual(result["probes"][0]["reason"], "INVALID_IAM_TRUNCATION")

    def test_empty_org_page_can_continue_with_token(self):
        data = fixtures()
        data[("organizations", "ListParents", "global")] = [
            {"Parents": [], "NextToken": "N1"},
            {"Parents": [{"Id": "r-synthetic"}]},
        ]
        port, result = simulate(data)
        check = next(x for x in result["probes"] if x["label"] == "organization_parent_direct")
        self.assertTrue(check["pagination_complete"])
        self.assertEqual(check["pages"], 2)
        calls = [x for x in port.calls if x[1] == "ListParents"]
        self.assertEqual(calls[1][3]["NextToken"], "N1")

    def test_repeated_next_token_is_partial(self):
        data = fixtures()
        data[("cloudtrail", "LookupEvents", REGION)] = [
            {"Events": [], "NextToken": "LOOP"},
            {"Events": [], "NextToken": "LOOP"},
        ]
        _, result = simulate(data)
        event = next(x for x in result["probes"] if x["label"].startswith("event_history_"))
        self.assertEqual(event["status"], "PARTIAL")
        self.assertEqual(event["reason"], "REPEATED_OR_INVALID_TOKEN")

    def test_page_limit_is_partial(self):
        data = fixtures()
        data[("cloudtrail", "LookupEvents", REGION)] = [
            {"Events": [], "NextToken": f"step-{k}"} for k in range(c.MAX_PAGES)
        ]
        _, result = simulate(data)
        event = next(x for x in result["probes"] if x["label"].startswith("event_history_"))
        self.assertEqual(event["status"], "PARTIAL")
        self.assertEqual(event["pages"], c.MAX_PAGES)
        self.assertEqual(event["reason"], "PAGE_LIMIT_REACHED")

    def test_access_denied_remains_explicit_in_coverage(self):
        data = fixtures()
        data[("organizations", "ListPoliciesForTarget", "global")] = [
            c.FixtureAccessDenied(), {"Policies": []},
        ]
        _, result = simulate(data)
        self.assertIn("ACCESS_DENIED", [x["status"] for x in result["probes"]])
        self.assertEqual(result["g2_gate"], "NOT_VERIFIED")

    def test_missing_fixture_is_unknown_not_no_resources(self):
        data = fixtures()
        del data[("sso-admin", "ListInstances", REGION)]
        _, result = simulate(data)
        sso = next(x for x in result["probes"] if x["source"] == "IDENTITY_CENTER")
        self.assertEqual(sso["status"], "UNKNOWN")
        self.assertFalse(sso["pagination_complete"])

    def test_secret_field_rejected_without_leaking_content(self):
        data = fixtures()
        data[("cloudtrail", "ListTrails", REGION)] = [{"secretAccessKey": "NOT-FOR-LOGGING"}]
        _, result = simulate(data)
        trail = next(x for x in result["probes"] if x["label"].startswith("trails_"))
        self.assertEqual(trail["status"], "UNKNOWN")
        self.assertNotIn("NOT-FOR-LOGGING", str(result))

    def test_oversized_fixture_is_unknown(self):
        data = fixtures()
        data[("cloudtrail", "ListTrails", REGION)] = [{"Blob": "X" * (c.MAX_PAGE_BYTES + 1)}]
        _, result = simulate(data)
        trail = next(x for x in result["probes"] if x["label"].startswith("trails_"))
        self.assertEqual(trail["status"], "UNKNOWN")

    def test_non_json_fixture_is_unknown(self):
        data = fixtures()
        data[("cloudtrail", "ListTrails", REGION)] = [{"result": object()}]
        _, result = simulate(data)
        trail = next(x for x in result["probes"] if x["label"].startswith("trails_"))
        self.assertEqual(trail["status"], "UNKNOWN")

    def test_account_region_and_window_are_strict(self):
        for acc, regions, start, end in [
            ("bad", (REGION,), START, END),
            (ACCOUNT, (), START, END),
            (ACCOUNT, (REGION, REGION), START, END),
            (ACCOUNT, ("bad-region",), START, END),
            (ACCOUNT, (REGION,), END, START),
            (ACCOUNT, (REGION,), "2026-01-01T00:00:00Z", END),
            (ACCOUNT, (REGION,), "nonsense", END),
        ]:
            with self.subTest(account=acc, regions=regions, start=start):
                with self.assertRaises(c.ContractError):
                    c.build_plan(acc, regions, start, end)

    def test_direct_non_allowlisted_operations_refused(self):
        port = c.FixturePort({})
        with self.assertRaises(c.ContractError):
            port.call("iam", "CreatePolicy", "global", {})
        with self.assertRaises(c.ContractError):
            c.Probe("evil", "G2-A01", "IAM", "ec2", "CreateTags",
                    REGION, {}, "single")

    def test_subclassed_port_cannot_inject_a_real_client(self):
        class Custom(c.FixturePort):
            pass
        with self.assertRaises(c.ContractError):
            c.run_simulation(Custom(fixtures()), ACCOUNT, (REGION,), START, END)

    def test_plan_is_allowlisted_and_bounded(self):
        plan = c.build_plan(ACCOUNT, (REGION, "us-east-1"), START, END)
        self.assertEqual(len(plan), 13)
        self.assertEqual(len(set(x.label for x in plan)), len(plan))
        self.assertTrue(all((p.service, p.operation) in c.ALLOWED_OPERATIONS for p in plan))
        self.assertTrue(all(p.operation not in {"StartQuery", "GetObject", "TagResource"} for p in plan))

    def test_mock_module_has_no_sdk_or_network_import(self):
        code = ast.parse(Path(c.__file__).read_text(encoding="utf-8"))
        forbidden = {"boto3", "botocore", "socket", "requests", "urllib", "subprocess", "http", "awscrt"}
        for node in ast.walk(code):
            if isinstance(node, ast.Import):
                self.assertFalse(forbidden.intersection(x.name.split(".")[0] for x in node.names))
            if isinstance(node, ast.ImportFrom) and node.module:
                self.assertNotIn(node.module.split(".")[0], forbidden)


if __name__ == "__main__":
    unittest.main()
