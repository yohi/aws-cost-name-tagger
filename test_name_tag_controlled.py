from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import boto3
import botocore.session

from name_tag_controlled import execute_approved
from name_tag_approval import (
    EnrolledOwner,
    Kind,
    NAMESPACES,
    OwnerTrust,
    approval_digest,
    canonical_payload,
)
from name_tag_controlled import main, parse_cli
from name_tag_review import prepare_name_payload
from name_tag_batch_state import build_batch_review_projection
from test_helpers import sample_population


class ControlledCLITests(unittest.TestCase):
    def __init__(self, methodName: str = "runTest") -> None:
        super().__init__(methodName)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "owner_key"
        _ = subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        public_fields = self.key.with_suffix(".pub").read_text(encoding="utf-8").split()
        self.public_key = " ".join(public_fields[:2])
        fingerprint = subprocess.run(
            ["ssh-keygen", "-lf", str(self.key.with_suffix(".pub")), "-E", "sha256"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()[1]
        self.fingerprint = fingerprint
        self.allowed_signers = self.root / "allowed_signers"
        namespaces = ",".join((NAMESPACES["name"], NAMESPACES["execution"]))
        self.allowed_signers.write_text(
            f'owner@example.test namespaces="{namespaces}" {self.public_key}\n',
            encoding="utf-8",
        )
        self.allowed_signers.chmod(0o600)
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed_signers,
            pinned_sha256=hashlib.sha256(self.allowed_signers.read_bytes()).hexdigest(),
            enrolled={
                "owner@example.test": {
                    fingerprint: EnrolledOwner(fingerprint, "EXECUTOR"),
                }
            },
        )
        self.plan_path = self.root / "plan.json"
        self.plan_bytes = self._plan_bytes()
        _ = self.plan_path.write_bytes(self.plan_bytes)
        self.plan_path.chmod(0o600)

    def _plan_bytes(self) -> bytes:
        record = {
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0",
            "kind": "volume",
            "region": "us-east-1",
            "locator": "vol-0123456789abcdef0",
            "status": "proposed",
            "confidence": "High",
            "name_state": "ABSENT",
            "name_key_present": False,
            "name_raw_value": None,
            "proposed_name": "web-prod",
            "evidence": "DescribeVolumes: volume vol-0123456789abcdef0",
            "proposal_id": "proposal-1",
        }
        return json.dumps(
            {"schema_version": 2, "account": "123456789012", "records": [record]},
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _sign(self, data: bytes, namespace: str) -> bytes:
        message_path = self.root / f"message-{hashlib.sha256(data).hexdigest()}"
        _ = message_path.write_bytes(data)
        _ = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace, str(message_path)],
            check=True,
            capture_output=True,
        )
        signature_path = message_path.with_suffix(message_path.suffix + ".sig")
        signature = signature_path.read_bytes()
        signature_path.unlink()
        message_path.unlink()
        return signature

    def _name_payload(self) -> dict[str, object]:
        record = json.loads(self.plan_bytes)["records"][0]
        record["account"] = "123456789012"
        record["plan_sha256"] = hashlib.sha256(self.plan_bytes).hexdigest()
        record["evidence_digest"] = hashlib.sha256(record["evidence"].encode()).hexdigest()
        return prepare_name_payload(
            self.plan_bytes,
            record,
            approved_name="web-prod",
            edit_reason="",
            owner_principal_id="owner@example.test",
            owner_key_fingerprint=self.fingerprint,
            issued_at_utc=self.now.isoformat(),
            expires_at_utc=(self.now + timedelta(hours=1)).isoformat(),
            decision_nonce="name-cli-nonce",
        )

    def _signed_envelope(self, kind: Kind, payload: dict[str, object]) -> bytes:
        canonical = canonical_payload(payload, kind=kind)
        signature = self._sign(canonical, NAMESPACES[kind])
        content_key = "approval_id" if kind == "name" else "authorization_id"
        envelope = {
            "payload": payload,
            content_key: approval_digest(canonical),
            "signature_ref": base64.b64encode(signature).decode("ascii"),
        }
        return json.dumps(envelope, separators=(",", ":")).encode()

    def _write_input(self, path: Path, data: bytes) -> None:
        _ = path.write_bytes(data)
        path.chmod(0o600)

    def _execution_args(self, name_envelope: Path, operation: str, output: Path) -> list[str]:
        return [
            "prepare-execution", "--name-envelope", str(name_envelope),
            "--aws-operation", operation, "--scope-id", "scope-1",
            "--identity", "arn:aws:sts::123456789012:assumed-role/executor/session",
            "--code-version", "test", "--code-hash", "a" * 64,
            "--risk-acknowledgement", "owner-approved-risk",
            "--writer-evidence-ref", "writer-1", "--side-effect-evidence-ref", "side-1",
            "--owner-principal-id", "owner@example.test",
            "--owner-key-fingerprint", self.fingerprint, "--allowed-role", "EXECUTOR",
            "--issued-at-utc", self.now.isoformat(),
            "--expires-at-utc", (self.now + timedelta(hours=1)).isoformat(),
            "--execution-nonce", "exec-cli-nonce", "--output", str(output),
        ]

    def test_execute_approved_refuses_before_credentials(self):
        output = io.StringIO()
        args = argparse.Namespace()
        with (
            patch.object(boto3, "Session", side_effect=AssertionError("credentials reached")),
            patch.object(botocore.session, "get_session", side_effect=AssertionError("session reached")),
            patch.object(socket, "socket", side_effect=AssertionError("network reached")),
            patch.object(socket, "create_connection", side_effect=AssertionError("network reached")),
            redirect_stdout(output),
        ):
            result = execute_approved(args)
        self.assertNotEqual(result, 0)
        self.assertIn("AWS_WRITE_BLOCKED", output.getvalue())

    def test_batch_dryrun_is_reachable_from_controlled_cli(self):
        record={
            'proposal_id':'batch-proposal','kind':'volume','locator':'vol-0123456789abcdef0',
            'region':'us-east-1','resource_arn':'arn:aws:ec2:us-east-1:123456789012:volume/vol-0123456789abcdef0',
            'aws_operation':'ec2:CreateTags','status':'proposed','confidence':'high',
            'name_state':'ABSENT','name_key_present':False,'name_raw_value':None,
            'existing_name':'','proposed_name':'web-prd','effective_usage_cost_usd':'1',
            'evidence':'test metadata evidence',
        }
        document={
            'schema_version':3,'account':'123456789012','partition':'aws','count':1,
            'records':[record],'cur_population':sample_population(cost='1'),
            'execution_limits':{'max_send_attempts':1},
            'scope_declarations':[{'writer_control_scope_id':'batch-scope',
                'account':'123456789012','partition':'aws','region':'us-east-1',
                'resource_arns':[record['resource_arn']]}],
        }
        plan=self.root/'batch-plan.json'
        review=self.root/'batch-plan.review.csv'
        report=self.root/'batch-preview.json'
        plan_bytes=json.dumps(document,sort_keys=True).encode()
        self._write_input(plan,plan_bytes)
        self._write_input(review,build_batch_review_projection(plan_bytes))

        previous_directory=Path.cwd()
        os.chdir(self.root)
        try:
            with redirect_stdout(io.StringIO()):
                result=main(['batch-dryrun','--plan',plan.name,'--review',review.name,
                             '--report-out',report.name])
        finally:
            os.chdir(previous_directory)

        self.assertEqual(result,0)
        data=json.loads(report.read_bytes())
        self.assertEqual(data['authentication_state'],'UNSIGNED_PREVIEW')
        self.assertEqual(data['rows'][0]['resource_arn'],record['resource_arn'])
        self.assertFalse(data['execution_allowed'])

    def test_prepare_name_writes_unsigned_payload_without_overwrite(self):
        output_path = self.root / "unsigned-name.json"
        args = [
            "prepare-name", "--plan", str(self.plan_path), "--proposal-id", "proposal-1",
            "--approved-name", "web-prod", "--owner-principal-id", "owner@example.test",
            "--owner-key-fingerprint", self.fingerprint,
            "--issued-at-utc", self.now.isoformat(),
            "--expires-at-utc", (self.now + timedelta(hours=1)).isoformat(),
            "--decision-nonce", "name-cli-nonce", "--output", str(output_path),
        ]
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 0)
        payload = json.loads(output_path.read_bytes())
        self.assertEqual(payload["approved_name"], "web-prod")
        self.assertNotIn("signature_ref", payload)
        self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output_path.read_bytes(), canonical_payload(payload, kind="name"))
        before = output_path.read_bytes()
        with redirect_stdout(io.StringIO()):
            self.assertNotEqual(main(args), 0)
        self.assertEqual(output_path.read_bytes(), before)

    def test_verify_name_uses_enrolled_trust(self):
        payload = self._name_payload()
        envelope_path = self.root / "name-envelope.json"
        self._write_input(envelope_path, self._signed_envelope("name", payload))
        output = io.StringIO()
        with patch("name_tag_controlled._load_owner_trust", return_value=self.trust), redirect_stdout(output):
            result = main(["verify-name", "--envelope", str(envelope_path)])
        self.assertEqual(result, 0)
        self.assertIn("VERIFIED_NAME", output.getvalue())

    def test_verify_name_without_trust_fails_closed(self):
        envelope_path = self.root / "name-envelope.json"
        self._write_input(envelope_path, b"{}")
        output = io.StringIO()
        with patch("name_tag_controlled._load_owner_trust", return_value=None), redirect_stdout(output):
            result = main(["verify-name", "--envelope", str(envelope_path)])
        self.assertEqual(result, 2)
        self.assertIn("BLOCKED_OWNER_AUTHN", output.getvalue())

    def test_prepare_execution_binds_verified_name_and_single_operation(self):
        payload = self._name_payload()
        envelope_path = self.root / "name-envelope.json"
        output_path = self.root / "unsigned-execution.json"
        self._write_input(envelope_path, self._signed_envelope("name", payload))
        args = self._execution_args(envelope_path, "ec2:CreateTags:2016-11-15", output_path)
        with patch("name_tag_controlled._load_owner_trust", return_value=self.trust), redirect_stdout(io.StringIO()):
            self.assertEqual(main(args), 0)
        payload_out = json.loads(output_path.read_bytes())
        self.assertEqual(payload_out["resource_arn"], payload["resource_arn"])
        self.assertEqual(payload_out["approved_name"], payload["approved_name"])
        self.assertEqual(payload_out["aws_operation"], "ec2:CreateTags:2016-11-15")
        self.assertNotIn("signature_ref", payload_out)
        self.assertEqual(output_path.read_bytes(), canonical_payload(payload_out, kind="execution"))
        execution_envelope = self.root / "execution-envelope.json"
        self._write_input(execution_envelope, self._signed_envelope("execution", payload_out))
        with patch("name_tag_controlled._load_owner_trust", return_value=self.trust), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["verify-execution", "--envelope", str(execution_envelope)]), 0)

    def test_prepare_execution_rejects_other_operation(self):
        envelope_path = self.root / "name-envelope.json"
        self._write_input(envelope_path, self._signed_envelope("name", self._name_payload()))
        output_path = self.root / "unsupported.json"
        with patch("name_tag_controlled._load_owner_trust", return_value=self.trust), redirect_stdout(io.StringIO()):
            result = main(self._execution_args(envelope_path, "ec2:DeleteTags:2016-11-15", output_path))
        self.assertEqual(result, 2)
        self.assertFalse(output_path.exists())

    def test_cli_does_not_expose_safety_bypass_flags(self):
        for flag in ("--trust-public-key", "--disable-safety-hold", "--stub"):
            with self.subTest(flag=flag), self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
                parse_cli(["execute-approved", flag, "value"])

    def test_simulate_cli_requires_python_harness(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(["simulate"])
        self.assertEqual(result, 2)
        self.assertIn("AWS_WRITE_BLOCKED", output.getvalue())
