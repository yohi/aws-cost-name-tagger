"""Only synthetic responses: G2-I1 cannot access a real AWS account."""
import unittest
import g2_collector_contract as c

ACCOUNT = "456720798575"
OTHER = "000000000000"
REGION = "ap-northeast-1"
START = "2026-10-01T00:00:00Z"
END = "2026-10-02T00:00:00Z"
AS_OF = "2026-10-23T00:00:00Z"


def k(service, operation, region, arguments=None):
    return c.fixture_key(service, operation, region, arguments or {})


def default_page(probe):
    if probe.service == "iam":
        return {"IsTruncated": False, "RoleDetailList": []}
    if probe.operation == "DescribeOrganization":
        return {"Organization": {"Id": "o-synthetic"}}
    return {c.COLLECTIONS[(probe.service, probe.operation)]: []}


def fixtures(account=ACCOUNT, regions=(REGION,), iam_begin=None, iam_end=None):
    scripts = {k("sts", "GetCallerIdentity", "global"): [
        {"Account": account}, {"Account": account}]}
    for probe in c.build_plan(ACCOUNT, regions, START, END, AS_OF):
        request = k(probe.service, probe.operation, probe.region, probe.arguments)
        scripts.setdefault(request, []).append(default_page(probe))
    iam_key = k("iam", "GetAccountAuthorizationDetails", "global",
                {"Filter": ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]})
    first = default_page(c.build_plan(ACCOUNT, regions, START, END, AS_OF)[0])
    scripts[iam_key] = [iam_begin if iam_begin is not None else first,
                        iam_end if iam_end is not None else first]
    return scripts


def simulate(data=None, regions=(REGION,)):
    port = c.FixturePort(data if data is not None else fixtures(regions=regions))
    result = c.run_simulation(port, ACCOUNT, regions, START, END, AS_OF)
    return port, result


def probe_result(result, label):
    return next(x for x in result["probes"] if x["label"] == label)


class I1MockOnlyTests(unittest.TestCase):
    def test_normal_simulation_never_proves_g2_or_calls_aws(self):
        port, result = simulate()
        self.assertEqual(result["status"], "MOCK_ONLY_PARTIAL_COVERAGE")
        self.assertEqual(result["g2_gate"], "NOT_VERIFIED")
        self.assertFalse(result["snapshot_atomic"])
        self.assertFalse(result["read_only_verified"])
        self.assertEqual(result["aws_calls"], 0)
        self.assertEqual(result["as_of_utc"], AS_OF)
        self.assertEqual(result["begin_end_iam"]["consistency"], "SIMULATED_IAM_MATCH_ONLY")
        self.assertEqual(len(result["probes"]), 9)
        self.assertEqual(len(port.calls), 12)
        self.assertTrue(all(p["provenance"] == "SYNTHETIC_FIXTURE_ONLY" for p in result["probes"]))
        self.assertTrue(all(p["status"] == "SIMULATED_PAGE_TERMINATED" for p in result["probes"]))

    def test_wrong_account_stops_after_identity(self):
        port = c.FixturePort(fixtures(account=OTHER))
        result = c.run_simulation(port, ACCOUNT, (REGION,), START, END, AS_OF)
        self.assertEqual(result["status"], "ABORTED_IDENTITY")
        self.assertEqual(len(port.calls), 1)

    def test_identity_access_denied_stops(self):
        data = fixtures()
        data[k("sts", "GetCallerIdentity", "global")] = [c.FixtureAccessDenied()]
        port, result = simulate(data)
        self.assertEqual(result["status"], "ABORTED_IDENTITY")
        self.assertEqual(len(port.calls), 1)

    def test_invalid_identity_response_stops(self):
        data = fixtures()
        data[k("sts", "GetCallerIdentity", "global")] = [{"wrong": "value"}]
        _, result = simulate(data)
        self.assertEqual(result["status"], "ABORTED_IDENTITY")

    def test_end_identity_changed_remains_unknown(self):
        data = fixtures()
        data[k("sts", "GetCallerIdentity", "global")][1] = {"Account": OTHER}
        _, result = simulate(data)
        self.assertEqual(result["begin_end_iam"]["consistency"], "UNKNOWN")

    def test_iam_begin_end_differ_is_inconsistent(self):
        data = fixtures(iam_end={"IsTruncated": False, "RoleDetailList": [{"RoleName": "changed"}]})
        _, result = simulate(data)
        self.assertEqual(result["begin_end_iam"]["consistency"], "INCONSISTENT")

    def test_iam_marker_is_bound_to_full_request(self):
        data = fixtures()
        args = {"Filter": ["User", "Group", "Role", "LocalManagedPolicy", "AWSManagedPolicy"]}
        key0 = k("iam", "GetAccountAuthorizationDetails", "global", args)
        key1 = k("iam", "GetAccountAuthorizationDetails", "global", {**args, "Marker": "NEXT"})
        data[key0] = [{"IsTruncated": True, "Marker": "NEXT", "UserDetailList": []}] * 2
        data[key1] = [{"IsTruncated": False, "UserDetailList": [{"UserName": "fixture"}]}] * 2
        port, result = simulate(data)
        self.assertEqual(result["probes"][0]["pages"], 2)
        self.assertEqual(result["begin_end_iam"]["consistency"], "SIMULATED_IAM_MATCH_ONLY")
        calls = [x for x in port.calls if x[1] == "GetAccountAuthorizationDetails"]
        self.assertEqual(calls[1][3]["Marker"], "NEXT")
        self.assertEqual(calls[3][3]["Marker"], "NEXT")

    def test_iam_missing_marker_is_partial(self):
        _, result = simulate(fixtures(iam_begin={"IsTruncated": True, "RoleDetailList": []}))
        self.assertEqual(result["probes"][0]["status"], "PARTIAL")
        self.assertEqual(result["begin_end_iam"]["consistency"], "UNKNOWN")

    def test_iam_missing_truncation_is_unknown(self):
        _, result = simulate(fixtures(iam_begin={"RoleDetailList": []}))
        self.assertEqual(result["probes"][0]["status"], "UNKNOWN")
        self.assertFalse(result["probes"][0]["pagination_complete"])

    def test_iam_missing_all_collections_is_unknown(self):
        _, result = simulate(fixtures(iam_begin={"IsTruncated": False}))
        self.assertEqual(result["probes"][0]["status"], "UNKNOWN")

    def test_iam_wrong_collection_type_is_unknown(self):
        _, result = simulate(fixtures(iam_begin={"IsTruncated": False, "Policies": "invalid"}))
        self.assertEqual(result["probes"][0]["status"], "UNKNOWN")

    def test_organizations_empty_page_with_token_continues(self):
        data = fixtures()
        key0 = k("organizations", "ListParents", "global", {"ChildId": ACCOUNT})
        key1 = k("organizations", "ListParents", "global", {"ChildId": ACCOUNT, "NextToken": "N1"})
        data[key0] = [{"Parents": [], "NextToken": "N1"}]
        data[key1] = [{"Parents": [{"Id": "r-synthetic"}]}]
        port, result = simulate(data)
        check = probe_result(result, "organization_parent_direct")
        self.assertEqual(check["pages"], 2)
        self.assertTrue(check["pagination_complete"])
        self.assertEqual([x[3]["NextToken"] for x in port.calls if x[1] == "ListParents" and "NextToken" in x[3]], ["N1"])

    def test_scp_and_rcp_are_distinct_full_request_keys(self):
        data = fixtures()
        scp = k("organizations", "ListPoliciesForTarget", "global",
                {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
        rcp = k("organizations", "ListPoliciesForTarget", "global",
                {"TargetId": ACCOUNT, "Filter": "RESOURCE_CONTROL_POLICY"})
        self.assertNotEqual(scp, rcp)
        data[scp] = [{"Policies": [{"Type": "SERVICE_CONTROL_POLICY"}]}]
        data[rcp] = [{"Policies": [{"Type": "RESOURCE_CONTROL_POLICY"}]}]
        _, result = simulate(data)
        self.assertTrue(probe_result(result, "account_direct_service_control_policy")["pagination_complete"])
        self.assertTrue(probe_result(result, "account_direct_resource_control_policy")["pagination_complete"])

    def test_swapped_scp_rcp_responses_are_unknown(self):
        data = fixtures()
        scp = k("organizations", "ListPoliciesForTarget", "global",
                {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
        rcp = k("organizations", "ListPoliciesForTarget", "global",
                {"TargetId": ACCOUNT, "Filter": "RESOURCE_CONTROL_POLICY"})
        data[scp] = [{"Policies": [{"Type": "RESOURCE_CONTROL_POLICY"}]}]
        data[rcp] = [{"Policies": [{"Type": "SERVICE_CONTROL_POLICY"}]}]
        _, result = simulate(data)
        for label in ("account_direct_service_control_policy", "account_direct_resource_control_policy"):
            item = probe_result(result, label)
            self.assertEqual(item["status"], "UNKNOWN")
            self.assertFalse(item["pagination_complete"])

    def test_scp_request_mismatch_is_unknown(self):
        data = fixtures()
        scp = k("organizations", "ListPoliciesForTarget", "global",
                {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
        del data[scp]
        _, result = simulate(data)
        self.assertEqual(probe_result(result, "account_direct_service_control_policy")["status"], "UNKNOWN")

    def test_nexttoken_only_is_not_success_for_any_collection_api(self):
        for service, operation, region, label in (
            ("organizations", "ListParents", "global", "organization_parent_direct"),
            ("organizations", "ListPoliciesForTarget", "global", "account_direct_service_control_policy"),
            ("sso-admin", "ListInstances", REGION, "identity_center_instances_" + REGION),
            ("cloudtrail", "ListTrails", REGION, "trails_" + REGION),
            ("cloudtrail", "LookupEvents", REGION, "event_history_" + REGION),
            ("cloudtrail", "ListEventDataStores", REGION, "lake_datastores_" + REGION),
        ):
            with self.subTest(operation=operation):
                data = fixtures()
                probe = next(x for x in c.build_plan(ACCOUNT, (REGION,), START, END, AS_OF)
                             if x.label == label)
                data[k(service, operation, region, probe.arguments)] = [{"NextToken": None}]
                _, result = simulate(data)
                self.assertEqual(probe_result(result, label)["status"], "UNKNOWN")
                self.assertFalse(probe_result(result, label)["pagination_complete"])

    def test_invalid_policies_or_events_list_is_unknown(self):
        for label, collection in (("account_direct_service_control_policy", "Policies"),
                                  ("event_history_" + REGION, "Events")):
            with self.subTest(label=label):
                data = fixtures()
                probe = next(x for x in c.build_plan(ACCOUNT, (REGION,), START, END, AS_OF)
                             if x.label == label)
                data[k(probe.service, probe.operation, probe.region, probe.arguments)] = [{collection: "bad"}]
                _, result = simulate(data)
                self.assertEqual(probe_result(result, label)["status"], "UNKNOWN")
                self.assertFalse(probe_result(result, label)["pagination_complete"])

    def test_valid_empty_policies_and_events_are_terminal(self):
        _, result = simulate()
        self.assertTrue(probe_result(result, "account_direct_service_control_policy")["pagination_complete"])
        self.assertTrue(probe_result(result, "event_history_" + REGION)["pagination_complete"])

    def test_repeated_token_is_partial(self):
        data = fixtures()
        args = {"StartTime": START, "EndTime": END}
        data[k("cloudtrail", "LookupEvents", REGION, args)] = [
            {"Events": [], "NextToken": "LOOP"}]
        data[k("cloudtrail", "LookupEvents", REGION, {**args, "NextToken": "LOOP"})] = [
            {"Events": [], "NextToken": "LOOP"}]
        _, result = simulate(data)
        self.assertEqual(probe_result(result, "event_history_" + REGION)["status"], "PARTIAL")

    def test_page_limit_is_partial(self):
        data = fixtures()
        args = {"StartTime": START, "EndTime": END}
        key = k("cloudtrail", "LookupEvents", REGION, args)
        for index in range(c.MAX_PAGES):
            token = f"step-{index}"
            data[key] = [{"Events": [], "NextToken": token}]
            key = k("cloudtrail", "LookupEvents", REGION, {**args, "NextToken": token})
        _, result = simulate(data)
        item = probe_result(result, "event_history_" + REGION)
        self.assertEqual(item["status"], "PARTIAL")
        self.assertEqual(item["pages"], c.MAX_PAGES)

    def test_access_denied_remains_explicit(self):
        data = fixtures()
        scp = k("organizations", "ListPoliciesForTarget", "global",
                {"TargetId": ACCOUNT, "Filter": "SERVICE_CONTROL_POLICY"})
        data[scp] = [c.FixtureAccessDenied()]
        _, result = simulate(data)
        self.assertEqual(probe_result(result, "account_direct_service_control_policy")["status"], "ACCESS_DENIED")

    def test_missing_fixture_does_not_mean_empty(self):
        data = fixtures()
        del data[k("sso-admin", "ListInstances", REGION)]
        _, result = simulate(data)
        self.assertEqual(probe_result(result, "identity_center_instances_" + REGION)["status"], "UNKNOWN")

    def test_prohibited_secret_is_never_leaked(self):
        data = fixtures()
        data[k("cloudtrail", "ListTrails", REGION)] = [{"secretAccessKey": "BAD"}]
        _, result = simulate(data)
        self.assertEqual(probe_result(result, "trails_" + REGION)["status"], "UNKNOWN")
        self.assertNotIn("BAD", str(result))

    def test_oversize_or_nonjson_fixture_is_unknown(self):
        for bad in ({"Trails": [], "Blob": "X" * (c.MAX_PAGE_BYTES + 1)},
                    {"Trails": [], "Unexpected": object()}):
            data = fixtures()
            data[k("cloudtrail", "ListTrails", REGION)] = [bad]
            _, result = simulate(data)
            self.assertEqual(probe_result(result, "trails_" + REGION)["status"], "UNKNOWN")

    def test_calendar_window_is_bounded_to_fixed_as_of(self):
        invalid = [
            (START, END, "2024-10-23T00:00:00Z"),
            ("2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z", AS_OF),
            (START, "2026-11-01T00:00:00Z", AS_OF),
            (END, START, AS_OF),
            ("bad", END, AS_OF),
        ]
        for start, end, as_of in invalid:
            with self.subTest(start=start, end=end, as_of=as_of):
                with self.assertRaises(c.ContractError):
                    c.build_plan(ACCOUNT, (REGION,), start, end, as_of)
        self.assertTrue(c.build_plan(ACCOUNT, (REGION,), START, END, AS_OF))

    def test_plan_rejects_bad_account_or_regions(self):
        for account, regions in (("bad", (REGION,)), (ACCOUNT, ()),
                                 (ACCOUNT, (REGION, REGION)), (ACCOUNT, ("bad",))):
            with self.assertRaises(c.ContractError):
                c.build_plan(account, regions, START, END, AS_OF)

    def test_disallowed_write_is_rejected(self):
        port = c.FixturePort({})
        with self.assertRaises(c.ContractError):
            port.call("iam", "CreatePolicy", "global", {})
        with self.assertRaises(c.ContractError):
            c.Probe("evil", "G2-A01", "IAM", "ec2", "CreateTags", REGION, {})

    def test_port_subclass_is_not_accepted(self):
        class Custom(c.FixturePort):
            pass
        custom_port = Custom(fixtures())
        with self.assertRaises(c.ContractError):
            c.run_simulation(custom_port, ACCOUNT, (REGION,), START, END, AS_OF)

    def test_probes_do_not_expand_to_write_or_high_cost_apis(self):
        probes = c.build_plan(ACCOUNT, (REGION, "us-east-1"), START, END, AS_OF)
        self.assertEqual(len(probes), 13)
        self.assertTrue(all((p.service, p.operation) in c.ALLOWED_OPERATIONS for p in probes))
        self.assertNotIn("StartQuery", [p.operation for p in probes])
        self.assertNotIn("GetObject", [p.operation for p in probes])


if __name__ == "__main__":
    unittest.main()
