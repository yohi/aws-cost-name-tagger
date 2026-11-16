import base64
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from name_tag_approval import (
    ApprovalRejected,
    EnrolledOwner,
    OwnerTrust,
    approval_digest,
    canonical_payload,
    revalidate_verified_envelope,
    verify_envelope,
    NAMESPACES,
)


class ApprovalContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "owner"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
        )
        self.owner = "owner-1"
        self.role = "approval-owner"
        self.allowed = self.root / "allowed_signers"
        public_line = self.key.with_suffix(".pub").read_text().split()
        self.allowed.write_text(
            f'{self.owner} namespaces="{NAMESPACES["name"]},{NAMESPACES["execution"]}" '
            f'{public_line[0]} {public_line[1]}\n'
        )
        self.allowed.chmod(0o600)
        fingerprint = subprocess.check_output(
            ["ssh-keygen", "-lf", str(self.key.with_suffix(".pub")), "-E", "sha256"],
            text=True,
        ).split()[1]
        self.fingerprint = fingerprint
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed,
            pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={self.owner: {fingerprint: EnrolledOwner(fingerprint, self.role)}},
            expected_uid=os.getuid(),
        )

    def _name_payload(
        self,
        *,
        approved_name: str = "web-prod",
        edit_reason: str = "",
        expires_at: datetime | None = None,
    ) -> dict:
        return {
            "schema_version": 1,
            "approval_namespace": NAMESPACES["name"],
            "plan_sha256": "a" * 64,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "kind": "volume",
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-123",
            "locator": "vol-123",
            "name_state_at_plan": "ABSENT",
            "confidence": "high",
            "evidence_digest": "b" * 64,
            "suggested_name": "web-prod",
            "approved_name": approved_name,
            "edit_reason": edit_reason,
            "decision": "APPROVED",
            "owner_decision_reference": "ref-1",
            "owner_principal_id": self.owner,
            "owner_key_fingerprint": self.fingerprint,
            "issued_at_utc": datetime.now(timezone.utc).isoformat(),
            "expires_at_utc": (
                expires_at.isoformat()
                if expires_at is not None
                else (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            ),
            "decision_nonce": "nonce-1",
        }

    def _execution_payload(
        self,
        *,
        expires_at: datetime | None = None,
        allowed_role: str | None = None,
    ) -> dict:
        return {
            "schema_version": 1,
            "authorization_namespace": NAMESPACES["execution"],
            "name_approval_id": "c" * 64,
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-123",
            "approved_name": "web-prod",
            "aws_operation": "ec2:CreateTags:2016-11-15",
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "identity": "arn:aws:sts::123456789012:assumed-role/exec-role/session",
            "code_version": "v3.7.0",
            "code_hash": "d" * 64,
            "writer_control_scope_id": "scope-1",
            "risk_acknowledgement": "ack",
            "writer_control_evidence_refs": ["ev-1"],
            "side_effect_evidence_refs": ["se-1"],
            "owner_principal_id": self.owner,
            "owner_key_fingerprint": self.fingerprint,
            "allowed_role": allowed_role or self.role,
            "issued_at_utc": datetime.now(timezone.utc).isoformat(),
            "expires_at_utc": (
                expires_at.isoformat()
                if expires_at is not None
                else (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            ),
            "execution_nonce": "nonce-exec-1",
        }

    def _sign(self, data: bytes, namespace: str) -> bytes:
        message = self.root / "message"
        message.write_bytes(data)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace, str(message)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signature = message.with_suffix(message.suffix + ".sig").read_bytes()
        message.with_suffix(message.suffix + ".sig").unlink()
        return signature

    def _envelope(
        self,
        *,
        kind: str = "name",
        payload: dict | None = None,
        namespace: str | None = None,
        expires_at: datetime | None = None,
    ) -> bytes:
        if payload is None:
            if kind == "name":
                payload = self._name_payload(expires_at=expires_at)
            else:
                payload = self._execution_payload(expires_at=expires_at)
        namespace = namespace or NAMESPACES[kind]
        data = canonical_payload(payload, kind=kind)
        signature = self._sign(data, namespace)
        id_key = "approval_id" if kind == "name" else "authorization_id"
        envelope = {
            "payload": payload,
            id_key: approval_digest(data),
            "signature_ref": base64.b64encode(signature).decode(),
        }
        return json.dumps(envelope, separators=(",", ":")).encode()

    def test_canonical_name_payload_and_id(self):
        payload = {
            "schema_version": 1,
            "approval_namespace": NAMESPACES["name"],
            "plan_sha256": "a" * 64,
            "account": "123456789012",
            "partition": "aws",
            "region": "us-east-1",
            "kind": "volume",
            "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-123",
            "locator": "vol-123",
            "name_state_at_plan": "ABSENT",
            "confidence": "high",
            "evidence_digest": "b" * 64,
            "suggested_name": "web-prod",
            "approved_name": "web-prod",
            "edit_reason": "",
            "decision": "APPROVED",
            "owner_decision_reference": "ref-1",
            "owner_principal_id": "owner-1",
            "owner_key_fingerprint": "SHA256:" + "c" * 43,
            "issued_at_utc": "2026-11-16T00:00:00+00:00",
            "expires_at_utc": "2026-11-17T00:00:00+00:00",
            "decision_nonce": "nonce-1",
        }
        canonical = canonical_payload(payload, kind="name")
        expected = (
            b'{"account":"123456789012","approval_namespace":"aws-cost-name-tagger-name-approval-v1",'
            b'"approved_name":"web-prod","confidence":"high","decision":"APPROVED",'
            b'"decision_nonce":"nonce-1","edit_reason":"","evidence_digest":"' + b"b" * 64 + b'",'
            b'"expires_at_utc":"2026-11-17T00:00:00+00:00","issued_at_utc":"2026-11-16T00:00:00+00:00",'
            b'"kind":"volume","locator":"vol-123","name_state_at_plan":"ABSENT",'
            b'"owner_decision_reference":"ref-1","owner_key_fingerprint":"SHA256:' + b"c" * 43 + b'",'
            b'"owner_principal_id":"owner-1","partition":"aws","plan_sha256":"' + b"a" * 64 + b'",'
            b'"region":"us-east-1","resource_arn":"arn:aws:ec2:us-east-1:123456789012:volume/vol-123",'
            b'"schema_version":1,"suggested_name":"web-prod"}'
        )
        self.assertEqual(canonical, expected)
        # Reorder payload keys to test that canonicalization sorts deterministically.
        reordered = {k: payload[k] for k in reversed(list(payload.keys()))}
        self.assertEqual(canonical_payload(reordered, kind="name"), canonical)
        digest = approval_digest(canonical)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
        for forbidden in ("approval_id", "signature_ref"):
            with self.subTest(forbidden=forbidden), self.assertRaises(ApprovalRejected):
                canonical_payload({**payload, forbidden: "external"}, kind="name")

    def test_reject_noncanonical_payload(self):
        base = self._name_payload()
        for payload in (
            {**base, "extra": None},
            {**base, "schema_version": 1.0},
            {**base, "schema_version": "1"},
            {**base, "approved_name": "\ud800"},
            {**base, "approved_name": None},
            {**base, "approved_name": 123},
            {k: v for k, v in base.items() if k != "approval_namespace"},
            {**base, "approval_namespace": "wrong"},
        ):
            with self.subTest(payload=repr(payload)), self.assertRaises(ApprovalRejected):
                canonical_payload(payload, kind="name")

    def test_unknown_or_revoked_owner(self):
        unknown = OwnerTrust.from_allowed_signers(
            self.allowed,
            pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={},
        )
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                self._envelope(), kind="name", trust=unknown, now_utc=datetime.now(timezone.utc)
            )
        revoked = OwnerTrust.from_allowed_signers(
            self.allowed,
            pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={
                self.owner: {
                    self.fingerprint: EnrolledOwner(self.fingerprint, self.role, revoked=True)
                }
            },
        )
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                self._envelope(), kind="name", trust=revoked, now_utc=datetime.now(timezone.utc)
            )

    def test_namespace_swap_rejected(self):
        raw = self._envelope(namespace="wrong-namespace")
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                raw, kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
            )

    def test_edited_name_invalidates_old_signature(self):
        envelope = json.loads(self._envelope())
        envelope["payload"]["approved_name"] = "edited"
        envelope["approval_id"] = approval_digest(
            canonical_payload(envelope["payload"], kind="name")
        )
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                json.dumps(envelope).encode(),
                kind="name",
                trust=self.trust,
                now_utc=datetime.now(timezone.utc),
            )

    def test_expired_or_wrong_role_rejected(self):
        expired = datetime.now(timezone.utc) - timedelta(seconds=1)
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                self._envelope(expires_at=expired),
                kind="name",
                trust=self.trust,
                now_utc=datetime.now(timezone.utc),
            )
        # Execution envelope with mismatched allowed_role.
        exec_payload = self._execution_payload(allowed_role="other-role")
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                self._envelope(kind="execution", payload=exec_payload),
                kind="execution",
                trust=self.trust,
                now_utc=datetime.now(timezone.utc),
            )

    def test_missing_trust_anchor_blocks(self):
        with self.assertRaises(ApprovalRejected):
            OwnerTrust.from_allowed_signers(
                self.allowed, pinned_sha256="0" * 64, enrolled={}
            )

    def test_duplicate_json_keys_rejected_before_mapping(self):
        # Build a valid envelope, then inject a duplicate top-level key.
        raw = self._envelope()
        parsed = json.loads(raw)
        # Inject duplicate "approval_id" with the same value.
        text = raw.decode("utf-8")
        insert = text.find("," "signature_ref")
        duplicate = ',"approval_id":"' + parsed["approval_id"] + '"'
        injected = text[:insert] + duplicate + text[insert:]
        # Without duplicate-key rejection this would still be structurally valid and
        # the ID would match, so rejection proves the hook is active.
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                injected.encode(), kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
            )

    def test_nested_duplicate_json_keys_rejected(self):
        # Build a valid envelope with a duplicate key inside payload.
        raw = self._envelope()
        text = raw.decode("utf-8")
        # Insert a duplicate "approved_name" inside payload (same value).
        payload_start = text.find('"payload":{') + len('"payload":{')
        duplicate = '"approved_name":"web-prod",'
        injected = text[:payload_start] + duplicate + text[payload_start:]
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                injected.encode(), kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
            )

    def test_verified_payload_is_immutable_snapshot(self):
        verified = verify_envelope(
            self._envelope(), kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
        )
        with self.assertRaises(TypeError):
            verified.payload["approved_name"] = "changed"

    def test_original_input_mutation_does_not_change_verified_payload(self):
        raw = bytearray(self._envelope())
        verified = verify_envelope(
            raw, kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
        )
        raw[:] = b"x" * len(raw)
        self.assertEqual(verified.payload["approved_name"], "web-prod")
        self.assertNotEqual(verified.raw_envelope_bytes, bytes(raw))

    def test_forged_verified_envelope_rejected(self):
        verified = verify_envelope(
            self._envelope(), kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
        )
        forged = replace(verified, content_id="0" * 64)
        with self.assertRaises(ApprovalRejected):
            revalidate_verified_envelope(
                forged, kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
            )

    def test_mutated_signed_payload_fails_revalidation(self):
        verified = verify_envelope(
            self._envelope(), kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
        )
        object.__setattr__(verified, "raw_envelope_bytes", b"{}")
        with self.assertRaises(ApprovalRejected):
            revalidate_verified_envelope(
                verified, kind="name", trust=self.trust, now_utc=datetime.now(timezone.utc)
            )

    def test_execution_envelope_verifies(self):
        payload = self._execution_payload()
        verified = verify_envelope(
            self._envelope(kind="execution", payload=payload),
            kind="execution",
            trust=self.trust,
            now_utc=datetime.now(timezone.utc),
        )
        self.assertEqual(verified.kind, "execution")
        self.assertEqual(verified.payload["aws_operation"], "ec2:CreateTags:2016-11-15")

    def test_owner_key_fingerprint_must_match_signer(self):
        payload = self._name_payload()
        payload["owner_key_fingerprint"] = "SHA256:" + "0" * 43
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                self._envelope(payload=payload),
                kind="name",
                trust=self.trust,
                now_utc=datetime.now(timezone.utc),
            )

    def test_content_id_must_be_lowercase_hex(self):
        envelope = json.loads(self._envelope())
        envelope["approval_id"] = envelope["approval_id"].upper()
        with self.assertRaises(ApprovalRejected):
            verify_envelope(
                json.dumps(envelope).encode(),
                kind="name",
                trust=self.trust,
                now_utc=datetime.now(timezone.utc),
            )

    def test_permission_ownership_checks(self):
        with self.assertRaises(ApprovalRejected):
            OwnerTrust.from_allowed_signers(
                self.allowed,
                pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
                enrolled={self.owner: {self.fingerprint: EnrolledOwner(self.fingerprint, self.role)}},
                expected_uid=os.getuid() + 1,
            )
        self.allowed.chmod(0o666)
        try:
            with self.assertRaises(ApprovalRejected):
                OwnerTrust.from_allowed_signers(
                    self.allowed,
                    pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
                    enrolled={self.owner: {self.fingerprint: EnrolledOwner(self.fingerprint, self.role)}},
                )
        finally:
            self.allowed.chmod(0o600)

    def test_signer_fingerprint_ignores_ascii_and_non_ascii_comments(self):
        from name_tag_approval import _fingerprint_for_key_line

        raw = self._envelope()
        public_line = self.key.with_suffix(".pub").read_text().split()
        for comment in ("owner key", "鍵のコメント"):
            with self.subTest(comment=comment):
                line = f"{self.owner} {public_line[0]} {public_line[1]} {comment}"
                self.assertEqual(_fingerprint_for_key_line(line), self.fingerprint)

        self.allowed.write_text(
            f'{self.owner} namespaces="{NAMESPACES["name"]},{NAMESPACES["execution"]}" '
            f"{public_line[0]} {public_line[1]} 鍵のコメント\n"
        )
        self.allowed.chmod(0o600)
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed,
            pinned_sha256=hashlib.sha256(self.allowed.read_bytes()).hexdigest(),
            enrolled={self.owner: {self.fingerprint: EnrolledOwner(self.fingerprint, self.role)}},
            expected_uid=os.getuid(),
        )
        verified = verify_envelope(
            raw,
            kind="name",
            trust=self.trust,
            now_utc=datetime.now(timezone.utc),
        )
        self.assertEqual(verified.owner_principal_id, self.owner)

    def test_tampered_trust_file_is_rejected_before_fingerprint_process(self):
        raw = self._envelope()
        self.allowed.write_text("owner-1 ssh-ed25519 " + "A" * 40 + "\n")
        with patch("name_tag_approval.subprocess.run") as run:
            with self.assertRaises(ApprovalRejected):
                verify_envelope(
                    raw,
                    kind="name",
                    trust=self.trust,
                    now_utc=datetime.now(timezone.utc),
                )
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
