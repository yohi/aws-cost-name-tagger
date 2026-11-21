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


if __name__ == "__main__":
    unittest.main()
