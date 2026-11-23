from __future__ import annotations

import unittest
from contextlib import ExitStack
from types import MappingProxyType
from types import SimpleNamespace
from unittest.mock import Mock, patch

from name_tag_batch_approval import VerifiedBatchRowAuthority
from name_tag_batch_credentials import IssuedBatchSession, OfflineFakeIssuer
from name_tag_batch_live import (
    AuthorizedBatchRuntimePolicy,
    AuthorizedBatchWritePort,
    LiveWriteBlocked,
    build_volume_create_tags_request,
    protected_registry_adapter,
)
from name_tag_batch_runtime import _execute_unclaimed_row
from name_tag_batch_state import NameObservation
from name_tag_ledger import FirstSendPermit


def _run_unclaimed_row(ledger: Mock, runtime: SimpleNamespace) -> bool:
    row = {
        "resource_arn": "arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901",
        "approved_name": "app-prod-ebs-xvda-5678901",
        "name_state": "ABSENT",
        "name_key_present": False,
        "name_raw_value": None,
    }
    with ExitStack() as patches:
        patches.enter_context(
            patch("name_tag_batch_runtime._current_authority", return_value=SimpleNamespace(row=row))
        )
        patches.enter_context(
            patch("name_tag_batch_runtime._evidence_for", return_value=SimpleNamespace(scope=object(), side_effects=()))
        )
        patches.enter_context(
            patch("name_tag_batch_runtime.build_subset_session_policy", return_value=object())
        )
        patches.enter_context(patch("name_tag_batch_credentials.OfflineFakeIssuer.issue", return_value=object()))
        patches.enter_context(patch("name_tag_batch_runtime.validate_issued_batch_session"))
        patches.enter_context(
            patch(
                "name_tag_batch_runtime.classify_batch_name",
                return_value=NameObservation("ABSENT", False, None),
            )
        )
        return _execute_unclaimed_row(SimpleNamespace(), 0, ledger, runtime, {})


class RegistryDispatchTests(unittest.TestCase):
    def test_volume_dispatches_to_adapter_without_any_client_or_authority(self) -> None:
        adapter = protected_registry_adapter("volume")
        self.assertEqual(adapter.kind, "volume")

    def test_cnp_and_unknown_kinds_stay_denied_by_default(self) -> None:
        for kind in ("instance", "s3_bucket", "apigw_stage", "wafv2", "not-a-kind"):
            with self.subTest(kind=kind), self.assertRaises(LiveWriteBlocked):
                protected_registry_adapter(kind)
        with self.assertRaises(LiveWriteBlocked) as blocked:
            protected_registry_adapter("s3_bucket")
        self.assertEqual(blocked.exception.code, "ARN_OWNER_NOT_PROVEN")

    def test_registry_dispatch_does_not_enable_the_live_port(self) -> None:
        protected_registry_adapter("volume")
        with self.assertRaises(LiveWriteBlocked) as blocked:
            AuthorizedBatchWritePort(object()).write_once(
                session=None, row=None, permit=None, runtime=None)
        self.assertEqual(blocked.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")


class VolumeRequestTests(unittest.TestCase):
    def test_volume_request_is_name_only_for_the_exact_volume(self) -> None:
        request = build_volume_create_tags_request(
            resource_arn=(
                "arn:aws:ec2:ap-northeast-1:123456789012:"
                "volume/vol-abcdef12345678901"
            ),
            approved_name="app-prod-ebs-xvda-5678901",
        )

        self.assertEqual(
            request,
            {
                "Resources": ["vol-abcdef12345678901"],
                "Tags": [{"Key": "Name", "Value": "app-prod-ebs-xvda-5678901"}],
            },
        )

    def test_foreign_arn_is_not_a_volume_request(self) -> None:
        with self.assertRaises(LiveWriteBlocked):
            build_volume_create_tags_request(
                resource_arn=(
                    "arn:aws:s3:::bucket/vol-abcdef12345678901"
                ),
                approved_name="app-prod-ebs-xvda-5678901",
            )

    def test_live_port_without_verified_runtime_policy_makes_no_call(self) -> None:
        calls: list[dict[str, object]] = []

        class FakeEC2Client:
            def create_tags(self, **request: object) -> None:
                calls.append(request)

        port = AuthorizedBatchWritePort(FakeEC2Client())

        with self.assertRaises(LiveWriteBlocked):
            port.write_once(session=None, row=None, permit=None, runtime=None)

        self.assertEqual(calls, [])

    def test_dataclass_construction_is_not_live_authority(self) -> None:
        calls: list[dict[str, object]] = []

        class FakeEC2Client:
            def create_tags(self, **request: object) -> None:
                calls.append(request)

        row = VerifiedBatchRowAuthority(None, 0, MappingProxyType({}), "row-id")
        permit = FirstSendPermit("row-id", "arn:aws:ec2:region:123456789012:volume/vol-abcdef12345678901", "name", "scope", "ec2:CreateTags", "execution", "token")
        session = IssuedBatchSession("batch-id", b"{}", "hash", (0,), "arn:aws:iam::123456789012:role/name")
        runtime = AuthorizedBatchRuntimePolicy(
            "batch-id", "row-id", "123456789012", "aws", "region",
            permit.resource_arn, permit.approved_name, "ec2:CreateTags",
            id(session), id(permit),
        )
        port = AuthorizedBatchWritePort(FakeEC2Client())

        with self.assertRaises(LiveWriteBlocked) as blocked:
            port.write_once(session=session, row=row, permit=permit, runtime=runtime)

        self.assertEqual(blocked.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertEqual(calls, [])

    def test_non_oserror_after_permit_consumption_stops_as_unknown(self) -> None:
        row = {
            "resource_arn": "arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901",
            "approved_name": "app-prod-ebs-xvda-5678901",
            "name_state": "ABSENT",
            "name_key_present": False,
            "name_raw_value": None,
        }
        authority = SimpleNamespace(row=row)
        evidence = SimpleNamespace(scope=object(), side_effects=())
        ledger = Mock()
        adapter = Mock()
        adapter.read_current.return_value = {}
        adapter.write_once.side_effect = TypeError("unexpected SDK adapter failure")
        issuer = Mock()
        issuer.issue.return_value = object()
        runtime = SimpleNamespace(adapter=adapter, credential_issuer=issuer)

        with (
            patch("name_tag_batch_runtime._current_authority", return_value=authority),
            patch("name_tag_batch_runtime._evidence_for", return_value=evidence),
            patch("name_tag_batch_runtime.build_subset_session_policy", return_value=object()),
            patch("name_tag_batch_runtime.validate_issued_batch_session"),
            patch(
                "name_tag_batch_runtime.classify_batch_name",
                return_value=NameObservation("ABSENT", False, None),
            ),
        ):
            must_stop = _execute_unclaimed_row(
                SimpleNamespace(), 0, ledger, runtime, {}
            )

        self.assertTrue(must_stop)
        issuer.issue.assert_called_once()
        adapter.write_once.assert_called_once()
        ledger.record_readback.assert_called_once_with(
            ledger.create_batch_intent.return_value,
            name_after=None,
            outcome="OUTCOME_UNKNOWN",
        )

    def test_readback_failure_stops_after_one_write(self) -> None:
        ledger = Mock()
        adapter = Mock()
        adapter.read_current.return_value = {}
        adapter.readback.side_effect = OSError("readback unavailable")
        runtime = SimpleNamespace(adapter=adapter, credential_issuer=OfflineFakeIssuer())

        must_stop = _run_unclaimed_row(ledger, runtime)

        self.assertTrue(must_stop)
        adapter.write_once.assert_called_once()
        adapter.readback.assert_called_once()
        ledger.record_readback.assert_called_once_with(
            ledger.create_batch_intent.return_value,
            name_after=None,
            outcome="OUTCOME_UNKNOWN",
        )

    def test_failed_unknown_persistence_keeps_permit_spent(self) -> None:
        ledger = Mock()
        ledger.record_readback.side_effect = RuntimeError("ledger unavailable")
        adapter = Mock()
        adapter.read_current.return_value = {}
        adapter.readback.side_effect = OSError("readback unavailable")
        runtime = SimpleNamespace(adapter=adapter, credential_issuer=OfflineFakeIssuer())

        with self.assertRaisesRegex(RuntimeError, "ledger unavailable"):
            _run_unclaimed_row(ledger, runtime)

        ledger.consume_first_send.assert_called_once()
        adapter.write_once.assert_called_once()
        ledger.create_batch_intent.assert_called_once()



class GrantGatedWritePortTests(unittest.TestCase):
    """Task 7 obligation (a): the port dispatches only by consuming a live one-shot grant."""

    def _grant(self, live=True):
        import name_tag_batch_iam_evidence as iam_evidence
        from name_tag_batch_iam_evidence import (
            LIVE_PROVENANCE, ProtectedEffectiveIamEvidenceVerifier, ProtectedHostRuntimeVerifier)
        from test_name_tag_batch_runtime_host import GrantHarness

        g = GrantHarness(self)
        if not live:
            grant, scope, permit = g.grant()
            return g, grant, scope, permit
        scope = g.scope()
        permit = g.permit()
        synthetic = g.evidence()
        fields = {name: getattr(synthetic, name) for name in iam_evidence._EVIDENCE_FIELDS}
        # TEST-ONLY mock-proven live evidence; no production producer exists.
        evidence = iam_evidence.ProtectedIamEvidence(
            iam_evidence._MINT, provenance=LIVE_PROVENANCE, **fields)
        iam_evidence._EVIDENCE[evidence] = LIVE_PROVENANCE
        deny = ProtectedEffectiveIamEvidenceVerifier(clock=g.clock).verify(
            g.issued, g.authority, g.capability, scope, evidence)
        grant = ProtectedHostRuntimeVerifier(clock=g.clock).authorize_once(
            g.authority, g.issued, scope, deny, permit)
        return g, grant, scope, permit

    def test_live_grant_consumed_once_at_dispatch(self):
        g, grant, scope, permit = self._grant()
        adapter = Mock()
        port = AuthorizedBatchWritePort("client", adapter=adapter, target=scope.target,
                                        clock=g.clock)
        port.write_once(session=g.issued, row=g.authority, permit=permit, runtime=grant)
        adapter.write_once.assert_called_once()
        args = adapter.write_once.call_args.args
        self.assertEqual(args[:3], ("client", scope.target, permit.approved_name))
        self.assertIsNot(args[3], grant)
        with self.assertRaises(LiveWriteBlocked):
            port.write_once(session=g.issued, row=g.authority, permit=permit, runtime=grant)
        adapter.write_once.assert_called_once()

    def test_synthetic_grant_never_reaches_registry_or_sdk(self):
        g, grant, scope, permit = self._grant(live=False)
        client = type("FakeSdkClient", (), {
            "__init__": lambda self: setattr(self, "calls", []),
            "create_tags": lambda self, **kwargs: self.calls.append(kwargs),
        })()
        port = AuthorizedBatchWritePort(
            client, adapter=protected_registry_adapter("volume"), target=scope.target,
            clock=g.clock)

        with self.assertRaises(LiveWriteBlocked):
            port.write_once(session=g.issued, row=g.authority, permit=permit, runtime=grant)

        self.assertEqual(client.calls, [])

    def test_missing_adapter_target_or_clock_blocks_with_fresh_grants(self):
        for missing in ("adapter", "target", "clock"):
            with self.subTest(missing=missing):
                g, grant, scope, permit = self._grant()
                adapter = Mock()
                kwargs = {"adapter": adapter, "target": scope.target, "clock": g.clock}
                kwargs[missing] = None
                port = AuthorizedBatchWritePort("client", **kwargs)

                with self.assertRaises(LiveWriteBlocked):
                    port.write_once(session=g.issued, row=g.authority, permit=permit,
                                    runtime=grant)

                adapter.write_once.assert_not_called()

    def test_real_registry_adapter_consumes_host_binding_before_sdk_write(self):
        g, grant, scope, permit = self._grant()

        class FakeSdkClient:
            def __init__(self):
                self.calls = []

            def create_tags(self, **kwargs):
                self.calls.append(kwargs)

        client = FakeSdkClient()
        port = AuthorizedBatchWritePort(
            client, adapter=protected_registry_adapter("volume"), target=scope.target,
            clock=g.clock)
        call = dict(session=g.issued, row=g.authority, permit=permit, runtime=grant)

        port.write_once(**call)
        with self.assertRaises(LiveWriteBlocked):
            port.write_once(**call)

        self.assertEqual(client.calls, [{
            "Resources": [scope.target.resource_arn.rsplit("/", 1)[1]],
            "Tags": [{"Key": "Name", "Value": permit.approved_name}],
        }])


if __name__ == "__main__":
    unittest.main()
