from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json
import os
import sqlite3
import shutil
import subprocess
import tempfile
import unittest
import uuid
from contextlib import closing,contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import name_tag_ledger_anchor as anchor
import name_tag_ledger_provision as provision
import name_tag_batch_migration as migration
import name_tag_batch_migration_apply as migration_apply
from name_tag_approval import EnrolledOwner, OwnerTrust
from name_tag_approval import NAMESPACES, approval_digest
from name_tag_batch_approval import (
    BATCH_NAMESPACE,
    canonical_bytes,
    BatchAuthRejected,
    derive_batch_row_authority,
    prepare_batch_approval,
    verify_batch_approval,
)
from name_tag_batch_state import build_batch_review_projection
from name_tag_ledger import (
    SCOPE_DECISION_NAMESPACE,
    _canonical_scope_payload,
    _side_effect_digest,
    initialize_scope,
    ledger_host_binding,
    open_ledger,
)
from name_tag_ledger_errors import LedgerError
from name_tag_scope import ScopeEvidence, SideEffectEvidence


class BatchLedgerMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ledger_directory = self.root / "runtime"
        self.ledger_directory.mkdir(mode=0o700)
        self.anchor_directory = self.root / "anchors"
        self.anchor_directory.mkdir(mode=0o700)
        for target, name, value in (
            (anchor, "LEDGER_ANCHOR_DIRECTORY", self.anchor_directory),
            (anchor, "_ANCHOR_OWNER_UID", os.geteuid()),
            (anchor, "require_root", lambda: None),
            (provision, "_require_root", lambda: None),
        ):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.ledger_path = self.ledger_directory / "ledger.db"
        provision.initialize_ledger(self.ledger_path, runtime_uid=os.geteuid())
        self.host_binding = ledger_host_binding(self.ledger_path)
        self.anchor_identity = anchor.read_ledger_anchor(
            self.ledger_path, self.host_binding
        )
        self.key_path = self.root / "migration-owner"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key_path)],
            check=True,
        )
        public_fields = self.key_path.with_suffix(".pub").read_text().split()
        self.public_key = " ".join(public_fields[:2])
        self.fingerprint = subprocess.check_output(
            ["ssh-keygen", "-lf", str(self.key_path.with_suffix(".pub")), "-E", "sha256"],
            text=True,
        ).split()[1]
        self.batch_key_path = self.root / "batch-owner"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.batch_key_path)],
            check=True,
        )
        batch_fields = self.batch_key_path.with_suffix(".pub").read_text().split()
        self.batch_public_key = " ".join(batch_fields[:2])
        self.batch_fingerprint = subprocess.check_output(
            ["ssh-keygen", "-lf", str(self.batch_key_path.with_suffix(".pub")), "-E", "sha256"],
            text=True,
        ).split()[1]
        self.allowed_signers = self.root / "migration-allowed-signers"
        self.allowed_signers.write_text(
            f'ledger-owner namespaces="{migration.MIGRATION_NAMESPACE}" {self.public_key}\n'
            f'batch-owner namespaces="{BATCH_NAMESPACE},{SCOPE_DECISION_NAMESPACE}" {self.batch_public_key}\n'
        )
        self.allowed_signers.chmod(0o600)
        self.trust = OwnerTrust.from_allowed_signers(
            self.allowed_signers,
            pinned_sha256=hashlib.sha256(self.allowed_signers.read_bytes()).hexdigest(),
            enrolled={
                "ledger-owner": {
                    self.fingerprint: EnrolledOwner(self.fingerprint, "ledger-migrator")
                },
                "batch-owner": {
                    self.batch_fingerprint: EnrolledOwner(self.batch_fingerprint, "batch-approver")
                },
            },
            expected_uid=os.getuid(),
        )

    def _envelope(self, *, expires_in: timedelta = timedelta(hours=1)) -> bytes:
        stat_result = self.ledger_path.stat()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        payload = {
            "schema_version": 1,
            "purpose": migration.MIGRATION_NAMESPACE,
            "ledger_path": str(self.ledger_path),
            "host_binding": self.host_binding,
            "ledger_instance_id": self.anchor_identity.ledger_instance_id,
            "ledger_device": stat_result.st_dev,
            "ledger_inode": stat_result.st_ino,
            "from_schema_version": 1,
            "to_schema_version": 2,
            "owner_principal_id": "ledger-owner",
            "owner_key_fingerprint": self.fingerprint,
            "allowed_role": "ledger-migrator",
            "issued_at_utc": now.isoformat().replace("+00:00", "Z"),
            "expires_at_utc": (now + expires_in).isoformat().replace("+00:00", "Z"),
            "migration_nonce": "a1" * 16,
        }
        payload_bytes = canonical_bytes(payload)
        signature = self._sign(self.key_path, payload_bytes, migration.MIGRATION_NAMESPACE)
        decision_id = hashlib.sha256(payload_bytes).hexdigest()
        return json.dumps({
            "payload": payload,
            "decision_id": decision_id,
            "signature_ref": base64.b64encode(signature).decode("ascii"),
        },separators=(",",":")).encode()

    def _sign(self, key_path: Path, message: bytes, namespace: str) -> bytes:
        message_path = self.root / f"message-{uuid.uuid4().hex}"
        message_path.write_bytes(message)
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", namespace, str(message_path)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        signature_path = message_path.with_suffix(message_path.suffix + ".sig")
        signature = signature_path.read_bytes()
        signature_path.unlink()
        message_path.unlink()
        return signature

    def _batch_inputs(self) -> tuple[bytes, bytes, bytes, datetime]:
        account = "123456789012"
        partition = "aws"
        region = "us-east-1"
        arns = [
            f"arn:aws:ec2:{region}:{account}:volume/vol-0123456789abcdef0",
            f"arn:aws:ec2:{region}:{account}:volume/vol-abcdef01234567890",
        ]
        records = []
        for index, arn in enumerate(arns):
            locator = arn.rsplit("/", 1)[1]
            records.append({
                "proposal_id": f"proposal-{index}", "kind": "volume", "locator": locator,
                "region": region, "resource_arn": arn, "aws_operation": "ec2:CreateTags",
                "status": "proposed", "confidence": "high", "name_state": "ABSENT",
                "name_key_present": False, "name_raw_value": None, "existing_name": "",
                "proposed_name": f"web-prd-ebs-xvda-{locator[-7:]}", "effective_usage_cost_usd": "1",
                "evidence": f"EBS {locator} -> attachment i-0123456789abcdef0 xvda -> EC2 i-0123456789abcdef0 Name=web-prd; Product(observed, not validated)=(unset)",
            })
        population = {
            "schema_version": 2, "accounting_complete": True,
            "cur_recognized": {"count": 2, "cost_usd": "2"},
            "below_min_cost": {"count": 0, "cost_usd": "0"},
            "above_min_cost": {"count": 2, "cost_usd": "2"},
            "lookup_selected": {"count": 2, "cost_usd": "2"},
            "max_resources_not_inspected": {"count": 0, "cost_usd": "0"},
            "unattributable_cur": {"known": True, "billing_rows": 0, "cost_usd": "0"},
            "outside_requested_kinds": {"known": True, "billing_rows": 0, "cost_usd": "0"},
            "unsupported_kind": {"known": True, "billing_rows": 0, "cost_usd": "0"},
        }
        plan = {
            "schema_version": 3, "account": account, "partition": partition,
            "period": "2026-11", "count": 2, "records": records,
            "cur_population": population,
            "execution_limits": {"max_send_attempts": 1},
            "scope_declarations": [{
                "writer_control_scope_id": "scope-1", "account": account,
                "partition": partition, "region": region, "resource_arns": arns,
            }],
        }
        plan_bytes = json.dumps(plan, ensure_ascii=False, sort_keys=True).encode()
        review_bytes = build_batch_review_projection(plan_bytes)
        for index in range(2):
            review_bytes = review_bytes.replace(f",proposal-{index},".encode(),
                                                f"YES,proposal-{index},".encode())
        now = datetime.now(timezone.utc).replace(microsecond=0)
        prepared = prepare_batch_approval(
            plan_bytes, review_bytes, owner_principal_id="batch-owner",
            owner_key_fingerprint=self.batch_fingerprint,
            authorized_role_arn=f"arn:aws:iam::{account}:role/BatchExecutor",
            issued_at_utc=now.isoformat().replace("+00:00", "Z"),
            expires_at_utc=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            batch_nonce="b2" * 16,
        )
        signature = self._sign(self.batch_key_path, prepared.canonical_payload_bytes, BATCH_NAMESPACE)
        envelope = json.dumps({
            "payload": prepared.payload, "batch_id": prepared.batch_id,
            "signature_ref": base64.b64encode(signature).decode("ascii"),
        }, separators=(",", ":")).encode()
        return plan_bytes, review_bytes, envelope, now

    def _initialize_batch_scope(self, ledger, arns: list[str]):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        effects = tuple(SideEffectEvidence(
            target_arn=arn, iam_abac_resource_tag_assessment="PASS",
            iac_assessment="PASS", event_automation_assessment="PASS",
            evidence_references=("evidence://iam", "evidence://iac", "evidence://events"),
            not_before_utc=now - timedelta(hours=1),
            not_after_utc=now + timedelta(hours=1),
        ) for arn in arns)
        scope = ScopeEvidence(
            account="123456789012", partition="aws", region="us-east-1",
            writer_control_scope_id="scope-1", controlled_arns=frozenset(arns),
            not_before_utc=now - timedelta(hours=1), not_after_utc=now + timedelta(hours=1),
            writer_evidence_digest="c" * 64, responsible_owner="batch-owner",
        )
        payload = {
            "schema_version": 1, "decision_namespace": SCOPE_DECISION_NAMESPACE,
            "action": "INITIALIZE", "scope_id": "scope-1",
            "account": scope.account, "partition": scope.partition, "region": scope.region,
            "target_arns": sorted(arns), "writer_evidence_digest": scope.writer_evidence_digest,
            "side_effect_evidence_digest": _side_effect_digest(effects),
            "host_binding": ledger._host_binding, "owner_principal_id": "batch-owner",
            "owner_key_fingerprint": self.batch_fingerprint, "allowed_role": "batch-approver",
            "issued_at_utc": now.isoformat(), "expires_at_utc": (now + timedelta(hours=1)).isoformat(),
            "decision_nonce": "scope-initialize-0123456789", "reason": "offline test scope",
            "hold_generation_id": None,
        }
        canonical = _canonical_scope_payload(payload)
        signature = self._sign(self.batch_key_path, canonical, SCOPE_DECISION_NAMESPACE)
        envelope = {
            "payload": payload, "decision_id": approval_digest(canonical),
            "signature_ref": base64.b64encode(signature).decode("ascii"),
        }
        initialize_scope(ledger, envelope, action="INITIALIZE", scope=scope, side_effects=effects)
        return scope, effects

    def test_signed_decision_migrates_only_the_exact_temporary_ledger(self) -> None:
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            connection.execute(
                "INSERT INTO used_decisions VALUES (?, ?, ?, ?)",
                ("existing-scope", "existing-decision", "existing-nonce", "2026-11-19T00:00:00+00:00"),
            )
            connection.commit()
        envelope = self._envelope()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        decision = migration.verify_ledger_migration_decision(
            envelope, trust=self.trust, now_utc=now
        )

        with patch.object(migration_apply, "load_current_protected_owner_trust", return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path, decision=decision)

        with closing(open_ledger(self.ledger_path, trusted_host=True, trust=None)) as ledger:
            with ledger._connection() as connection:
                version = connection.execute(
                    "SELECT value FROM ledger_meta WHERE key='schema_version'"
                ).fetchone()[0]
                history = connection.execute(
                    "SELECT decision_id FROM used_decisions WHERE scope_id='existing-scope'"
                ).fetchone()[0]
                batch_tables = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN "
                    "('batch_registry','batch_rows','batch_events','batch_row_dispositions','ledger_migration_receipts')"
                ).fetchone()[0]
        self.assertEqual(version, "2")
        self.assertEqual(history, "existing-decision")
        self.assertEqual(batch_tables, 5)
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            receipt=connection.execute(
                "SELECT migration_nonce,ledger_instance_id FROM ledger_migration_receipts"
            ).fetchone()
        self.assertEqual(receipt,("a1"*16,self.anchor_identity.ledger_instance_id))
        with patch.object(migration_apply, "load_current_protected_owner_trust", return_value=self.trust):
            with self.assertRaises(migration.BatchMigrationRejected) as replay:
                migration.upgrade_ledger_v1_to_batch_v2(
                    self.ledger_path,decision=decision
                )
        self.assertEqual(replay.exception.code,"BLOCKED_AUTH_REPLAY")

    def test_migration_rechecks_locked_file_identity_before_writing_marker(self) -> None:
        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        original_lock=migration_apply.IntentLedger._lock
        def replace_path_before_lock(ledger):
            replacement=self.root/'replacement-ledger.db'
            shutil.copy2(self.ledger_path,replacement)
            os.replace(replacement,self.ledger_path)
            original_lock(ledger)
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust), \
             patch.object(migration_apply.IntentLedger,"_lock",replace_path_before_lock):
            with self.assertRaises(LedgerError) as rejected:
                migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        self.assertEqual(rejected.exception.code,"BLOCKED_SCOPE_STATE_UNKNOWN")
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT value FROM ledger_meta WHERE key='schema_version'"
            ).fetchone(),('1',))
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM ledger_meta WHERE key LIKE 'migration_attempt:%'"
            ).fetchone(),(0,))

    def test_integrity_check_failure_rolls_back_schema_and_receipt_transaction(self) -> None:
        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        original_connection=migration_apply.IntentLedger._connection
        class IntegrityFailingConnection:
            def __init__(self,connection):self.connection=connection
            def execute(self,sql,*args):
                if sql=='PRAGMA integrity_check':
                    return type('Result',(),{'fetchone':lambda _self:('corrupt',)})()
                return self.connection.execute(sql,*args)
            @property
            def in_transaction(self):return self.connection.in_transaction
            def commit(self):return self.connection.commit()
            def rollback(self):return self.connection.rollback()
        @contextmanager
        def connection_with_failed_integrity_check(ledger):
            with original_connection(ledger) as connection:
                yield IntegrityFailingConnection(connection)
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust), \
             patch.object(migration_apply.IntentLedger,"_connection",connection_with_failed_integrity_check):
            with self.assertRaises(LedgerError):
                migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            self.assertEqual(connection.execute(
                "SELECT value FROM ledger_meta WHERE key='schema_version'"
            ).fetchone(),('1',))
            self.assertEqual(connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='ledger_migration_receipts'"
            ).fetchone(),(0,))

    def test_expired_or_wrong_role_migration_decision_is_rejected(self) -> None:
        expired = self._envelope(expires_in=timedelta(seconds=-1))
        with self.assertRaises(migration.BatchMigrationRejected):
            migration.verify_ledger_migration_decision(
                expired, trust=self.trust,
                now_utc=datetime.now(timezone.utc).replace(microsecond=0),
            )
        wrong_role = OwnerTrust.from_allowed_signers(
            self.allowed_signers,
            pinned_sha256=hashlib.sha256(self.allowed_signers.read_bytes()).hexdigest(),
            enrolled={"ledger-owner": {
                self.fingerprint: EnrolledOwner(self.fingerprint, "EXECUTOR")
            }},
            expected_uid=os.getuid(),
        )
        with self.assertRaises(migration.BatchMigrationRejected):
            migration.verify_ledger_migration_decision(
                self._envelope(), trust=wrong_role,
                now_utc=datetime.now(timezone.utc).replace(microsecond=0),
            )

    def test_exact_expiry_boundary_is_rejected_as_expired(self) -> None:
        envelope=self._envelope(expires_in=timedelta(hours=1))
        expires=migration._timestamp(json.loads(envelope)["payload"]["expires_at_utc"])
        with self.assertRaises(migration.BatchMigrationRejected):
            migration.verify_ledger_migration_decision(
                envelope,trust=self.trust,now_utc=expires)

    def test_signed_payload_unicode_encoding_error_is_a_migration_rejection(self) -> None:
        with patch.object(migration,"canonical_bytes",side_effect=UnicodeEncodeError(
                'utf-8','\ud800',0,1,'surrogate')):
            with self.assertRaises(migration.BatchMigrationRejected):
                migration.verify_ledger_migration_decision(
                    self._envelope(),trust=self.trust,
                    now_utc=datetime.now(timezone.utc).replace(microsecond=0))

    def test_schema_metadata_ledger_error_is_normalized_but_replay_is_preserved(self) -> None:
        envelope=self._envelope()
        with patch.object(migration,"_ledger_metadata_value",
                          side_effect=LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN")):
            with self.assertRaises(migration.BatchMigrationRejected):
                migration.verify_ledger_migration_decision(
                    envelope,trust=self.trust,
                    now_utc=datetime.now(timezone.utc).replace(microsecond=0))

    def test_real_ledger_batch_intent_and_send_cap_survive_restart(self) -> None:
        migration_decision = migration.verify_ledger_migration_decision(
            self._envelope(), trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0),
        )
        with patch.object(migration_apply, "load_current_protected_owner_trust", return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(
                self.ledger_path, decision=migration_decision
            )
        plan_bytes, csv_bytes, envelope, signed_at = self._batch_inputs()
        batch = verify_batch_approval(
            plan_bytes, csv_bytes, envelope, trust=self.trust, now_utc=signed_at
        )
        arns = [row["resource_arn"] for row in batch.approved_rows]
        ledger = open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
        self.addCleanup(ledger.close)
        scope, effects = self._initialize_batch_scope(ledger, arns)
        first_row = derive_batch_row_authority(
            batch, batch.approved_row_indexes[0], trust=self.trust, now_utc=signed_at
        )
        with patch("name_tag_batch_trust.load_current_protected_owner_trust", return_value=self.trust):
            initial_state=ledger.batch_execution_state(batch)
        self.assertEqual(initial_state.state,"UNREGISTERED")
        self.assertEqual(initial_state.outcomes,("UNCLAIMED","UNCLAIMED"))

        with patch("name_tag_batch_trust.load_current_protected_owner_trust", return_value=self.trust):
            handle = ledger.create_batch_intent(
                first_row, scope=scope, side_effects=effects
            )
            permit = ledger.consume_first_send(handle)
            ledger.record_readback(
                handle, name_after=permit.approved_name, outcome="APPLIED_VERIFIED"
            )
            with self.assertRaises(LedgerError):
                ledger.create_batch_intent(first_row,scope=scope,side_effects=effects)
            second_row = derive_batch_row_authority(
                batch, batch.approved_row_indexes[1], trust=self.trust, now_utc=signed_at
            )
            ledger.record_batch_presend_disposition(
                second_row, scope=scope, side_effects=effects,
                decision="NOT_ATTEMPTED_CAP", reason_code="SIGNED_CAP_REACHED",
            )
            ledger.complete_batch(batch)

        self.assertEqual(permit.resource_arn, arns[0])
        with ledger._connection() as connection:
            attempts = connection.execute(
                "SELECT send_attempts_consumed FROM batch_registry WHERE batch_id=?",
                (batch.batch_id,),
            ).fetchone()[0]
        self.assertEqual(attempts, 1)
        with patch("name_tag_batch_trust.load_current_protected_owner_trust", return_value=self.trust):
            state=ledger.batch_execution_state(batch)
        self.assertEqual(state.state,"COMPLETED")
        self.assertEqual(state.send_attempts_consumed,1)
        self.assertEqual(state.max_send_attempts,1)
        self.assertEqual(state.outcomes,("APPLIED_VERIFIED","NOT_ATTEMPTED_CAP"))
        altered=replace(batch,approved_row_indexes=(1,0),
                        approved_rows=tuple(reversed(batch.approved_rows)))
        with patch("name_tag_batch_trust.load_current_protected_owner_trust",
                   side_effect=BatchAuthRejected()):
            recovered=ledger.batch_execution_state(altered)
        self.assertEqual(recovered.outcomes,("APPLIED_VERIFIED","NOT_ATTEMPTED_CAP"))
        ledger.close()
        with closing(open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)) as reopened:
            with patch("name_tag_batch_trust.load_current_protected_owner_trust", return_value=self.trust):
                self.assertEqual(reopened.batch_execution_state(batch).state,"COMPLETED")

    def test_send_authority_expiring_under_lock_is_not_consumed(self) -> None:
        migration_decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=migration_decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arn=batch.approved_rows[0]["resource_arn"]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,[arn])
            authority=derive_batch_row_authority(
                batch,batch.approved_row_indexes[0],trust=self.trust,now_utc=signed_at)
            with patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust):
                handle=ledger.create_batch_intent(authority,scope=scope,side_effects=effects)
            expiry=datetime.fromisoformat(batch.payload['expires_at_utc'].replace('Z','+00:00'))
            with patch.object(ledger,"_now",side_effect=[signed_at,expiry]):
                with self.assertRaises(LedgerError) as rejected:
                    ledger.consume_first_send(handle)
            self.assertEqual(rejected.exception.code,'BLOCKED_OWNER_AUTHN')
            with ledger._connection() as connection:
                state=connection.execute('SELECT state FROM intents WHERE intent_id=?',(handle.intent_id,)).fetchone()
                counter=connection.execute('SELECT send_attempts_consumed FROM batch_registry WHERE batch_id=?',(batch.batch_id,)).fetchone()
            self.assertEqual(state,('WRITE_INTENT_RECORDED',))
            self.assertEqual(counter,(0,))

    def test_unknown_batch_readback_stops_batch_and_holds_scope(self) -> None:
        migration_decision = migration.verify_ledger_migration_decision(
            self._envelope(), trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0),
        )
        with patch.object(migration_apply, "load_current_protected_owner_trust", return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(
                self.ledger_path, decision=migration_decision
            )
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(
            plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at
        )
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            row=derive_batch_row_authority(
                batch,batch.approved_row_indexes[0],trust=self.trust,now_utc=signed_at
            )
            with patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust):
                handle=ledger.create_batch_intent(row,scope=scope,side_effects=effects)
                ledger.consume_first_send(handle)
                ledger.record_readback(handle,name_after=None,outcome="OUTCOME_UNKNOWN")
                state=ledger.batch_execution_state(batch)
                scope_state=ledger.effective_scope_state("scope-1")

        self.assertEqual(state.state,"STOPPED")
        self.assertEqual(state.outcomes[0],"OUTCOME_UNKNOWN")
        self.assertEqual(scope_state,"HOLD")

    def test_verified_batch_executes_once_through_real_temp_ledger_and_fake_adapter(self) -> None:
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )
        from name_tag_batch_credentials import OfflineFakeIssuer
        from unittest.mock import Mock

        migration_decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=migration_decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            adapter=FakeBatchSDKAdapter({arn:{} for arn in arns})
            credential_issuer=Mock(wraps=OfflineFakeIssuer())
            runtime=BatchOfflineRuntime(
                {"scope-1":BatchRuntimeEvidence(scope,effects)},adapter,
                credential_issuer=credential_issuer,
            )
            with (
                patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",return_value=self.trust),
            ):
                result=execute_batch_offline(
                    batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,
                    runtime=runtime)

        self.assertEqual(adapter.write_calls,1)
        credential_issuer.issue.assert_called_once()
        issued_batch, issued_subset = credential_issuer.issue.call_args.args
        self.assertEqual(issued_batch.batch_id, batch.batch_id)
        self.assertEqual(issued_batch.plan_bytes, plan_bytes)
        self.assertEqual(issued_batch.csv_bytes, csv_bytes)
        self.assertEqual(issued_subset.batch_id, batch.batch_id)
        self.assertEqual(issued_subset.row_indexes, batch.approved_row_indexes[:1])
        self.assertEqual(result.outcomes,("APPLIED_VERIFIED","NOT_ATTEMPTED_CAP"))
        self.assertEqual(result.batch_state,"COMPLETED")
        self.assertTrue(result.report["rows"][0]["execution_allowed"] is False)
        self.assertEqual(result.report["outcome_reconciliation"],{
            "APPLIED_VERIFIED":{"count":1,"cost_usd":"1"},
            "NOT_ATTEMPTED_CAP":{"count":1,"cost_usd":"1"},
        })
        self.assertEqual(result.report["outcome_reconciliation_total"],
                         {"count":2,"cost_usd":"2"})

    def test_missing_scope_evidence_at_cap_stops_and_reports_unattempted_row(self) -> None:
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )
        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row['resource_arn'] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            evidence={'scope-1':BatchRuntimeEvidence(scope,effects)}
            adapter=FakeBatchSDKAdapter({arn:{} for arn in arns})
            write_once=adapter.write_once
            def write_then_remove_scope(arn,name,*,session=None):
                write_once(arn,name,session=session)
                evidence.clear()
            adapter.write_once=write_then_remove_scope
            runtime=BatchOfflineRuntime(evidence,adapter)
            with (
                patch('name_tag_batch_trust.load_current_protected_owner_trust',return_value=self.trust),
                patch('name_tag_batch_runtime.load_current_protected_owner_trust',return_value=self.trust),
            ):
                result=execute_batch_offline(batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,
                                             ledger=ledger,runtime=runtime)
            stored_state=ledger.batch_execution_state(batch)
        self.assertEqual(adapter.write_calls,1)
        self.assertEqual(result.outcomes,('APPLIED_VERIFIED','NOT_ATTEMPTED_BATCH_STOP'))
        self.assertEqual(result.batch_state,'STOPPED')
        self.assertEqual(stored_state.state,'STOPPED')

    def test_runtime_scope_evidence_must_match_signed_plan_or_fail_closed(self) -> None:
        import dataclasses
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )
        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        past=datetime.now(timezone.utc)-timedelta(hours=1)
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            mismatches={
                "region":dataclasses.replace(scope,region="eu-west-1"),
                "account":dataclasses.replace(scope,account="210987654321"),
                "partition":dataclasses.replace(scope,partition="aws-cn"),
                "arn_missing":dataclasses.replace(scope,controlled_arns=frozenset(arns[1:])),
                "owner":dataclasses.replace(scope,responsible_owner="someone-else"),
                "digest":dataclasses.replace(scope,writer_evidence_digest="not-a-digest"),
                "expired":dataclasses.replace(scope,not_before_utc=past-timedelta(hours=1),not_after_utc=past),
            }
            # End-to-end: a self-consistent Ledger Scope does not prove the runtime
            # evidence matches the signed Plan; the Batch stops before any write.
            adapter=FakeBatchSDKAdapter({arn:{} for arn in arns})
            runtime=BatchOfflineRuntime(
                {"scope-1":BatchRuntimeEvidence(mismatches["region"],effects)},adapter)
            with (
                patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",return_value=self.trust),
            ):
                result=execute_batch_offline(
                    batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,runtime=runtime)
            self.assertEqual(adapter.write_calls,0)
            self.assertEqual(result.batch_state,"STOPPED")
            self.assertEqual(result.send_attempts_consumed,0)
            from name_tag_batch_runtime import _evidence_for
            from name_tag_ledger import LedgerError
            for label,bad_scope in mismatches.items():
                with self.subTest(f"direct-{label}"):
                    runtime=BatchOfflineRuntime(
                        {"scope-1":BatchRuntimeEvidence(bad_scope,effects)},
                        FakeBatchSDKAdapter({}))
                    with self.assertRaises(LedgerError):
                        _evidence_for(batch,runtime,batch.approved_rows[0])
            good=BatchOfflineRuntime({"scope-1":BatchRuntimeEvidence(scope,effects)},FakeBatchSDKAdapter({}))
            for row in batch.approved_rows:
                self.assertIs(_evidence_for(batch,good,row),good.evidence_by_scope["scope-1"])

    def test_fake_execution_skips_changed_name_and_sends_next_target_once(self) -> None:
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )

        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            adapter=FakeBatchSDKAdapter({arns[0]:{"Name":"operator-change"},arns[1]:{}})
            runtime=BatchOfflineRuntime({"scope-1":BatchRuntimeEvidence(scope,effects)},adapter)
            with (
                patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",return_value=self.trust),
            ):
                result=execute_batch_offline(
                    batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,runtime=runtime)

        self.assertEqual(adapter.write_calls,1)
        self.assertEqual(result.outcomes,("SKIPPED_NAME_CHANGED","APPLIED_VERIFIED"))
        self.assertEqual(result.batch_state,"COMPLETED")
        self.assertEqual(result.send_attempts_consumed,1)
        self.assertFalse(result.writes_complete)

    def test_fake_readback_failure_stops_remaining_batch_rows(self) -> None:
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )

        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            adapter=FakeBatchSDKAdapter({arn:{} for arn in arns},readback_failures=(arns[0],))
            runtime=BatchOfflineRuntime({"scope-1":BatchRuntimeEvidence(scope,effects)},adapter)
            with (
                patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",return_value=self.trust),
            ):
                result=execute_batch_offline(
                    batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,runtime=runtime)
                scope_state=ledger.effective_scope_state("scope-1")

        self.assertEqual(adapter.write_calls,1)
        self.assertEqual(result.outcomes,("OUTCOME_UNKNOWN","NOT_ATTEMPTED_BATCH_STOP"))
        self.assertEqual(result.batch_state,"STOPPED")
        self.assertEqual(scope_state,"HOLD")

    def test_second_execution_does_not_stop_a_batch_with_an_unresolved_send_owner(self) -> None:
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )
        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row['resource_arn'] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as owner_ledger:
            scope,effects=self._initialize_batch_scope(owner_ledger,arns)
            authority=derive_batch_row_authority(
                batch,batch.approved_row_indexes[0],trust=self.trust,now_utc=signed_at)
            with patch('name_tag_batch_trust.load_current_protected_owner_trust',return_value=self.trust):
                handle=owner_ledger.create_batch_intent(authority,scope=scope,side_effects=effects)
                owner_ledger.consume_first_send(handle)
            self.assertTrue(owner_ledger.batch_intent_owned_by_current_execution(
                batch,authority.row_index))
            with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
                self.assertFalse(ledger.batch_intent_owned_by_current_execution(
                    batch,authority.row_index))
                adapter=FakeBatchSDKAdapter({arn:{} for arn in arns})
                runtime=BatchOfflineRuntime({'scope-1':BatchRuntimeEvidence(scope,effects)},adapter)
                with (
                    patch('name_tag_batch_trust.load_current_protected_owner_trust',return_value=self.trust),
                    patch('name_tag_batch_runtime.load_current_protected_owner_trust',return_value=self.trust),
                ):
                    result=execute_batch_offline(batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,
                                                 ledger=ledger,runtime=runtime)
                self.assertEqual(ledger.batch_execution_state(batch).state,'ACTIVE')
        self.assertEqual(adapter.write_calls,0)
        self.assertEqual(result.outcomes,('OUTCOME_UNKNOWN','NOT_ATTEMPTED_BATCH_STOP'))
        self.assertEqual(result.batch_state,'ACTIVE')
        self.assertEqual(result.report['unresolved_send_owner'],'OTHER_EXECUTION')

    def test_controlled_cli_runs_only_the_injected_fake_adapter(self) -> None:
        import io
        from contextlib import redirect_stdout
        from name_tag_controlled import main as controlled_main

        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
        plan_path=self.root/"batch-plan.json"
        review_path=self.root/"batch-review.csv"
        envelope_path=self.root/"batch-envelope.json"
        runtime_path=self.root/"runtime-evidence.json"
        report_path=self.root/"batch-result.json"
        fixture_ledger_path=self.root/"simulation-fixture-ledger.sqlite"
        host_ledger_digest=hashlib.sha256(self.ledger_path.read_bytes()).hexdigest()
        for path,data in ((plan_path,plan_bytes),(review_path,csv_bytes),(envelope_path,envelope)):
            path.write_bytes(data);path.chmod(0o600)
        runtime_doc={
            "scopes":[{
                "account":scope.account,"partition":scope.partition,"region":scope.region,
                "writer_control_scope_id":scope.writer_control_scope_id,
                "controlled_arns":sorted(scope.controlled_arns),
                "not_before_utc":scope.not_before_utc.isoformat(),
                "not_after_utc":scope.not_after_utc.isoformat(),
                "writer_evidence_digest":scope.writer_evidence_digest,
                "responsible_owner":scope.responsible_owner,
            }],
            "side_effects":[{
                "scope_id":scope.writer_control_scope_id,"target_arn":effect.target_arn,
                "iam_abac_resource_tag_assessment":effect.iam_abac_resource_tag_assessment,
                "iac_assessment":effect.iac_assessment,
                "event_automation_assessment":effect.event_automation_assessment,
                "evidence_references":list(effect.evidence_references),
                "not_before_utc":effect.not_before_utc.isoformat(),
                "not_after_utc":effect.not_after_utc.isoformat(),
            } for effect in effects],
            "initial_tags":{arn:{} for arn in arns},"readback_failures":[],
        }
        runtime_path.write_text(json.dumps(runtime_doc));runtime_path.chmod(0o600)
        prior=Path.cwd();os.chdir(self.root)
        try:
            with (
                patch("name_tag_batch_cli.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust),
                redirect_stdout(io.StringIO()),
            ):
                result=controlled_main([
                    "batch-simulate","--plan",plan_path.name,"--review",review_path.name,
                    "--envelope",envelope_path.name,"--ledger-path",fixture_ledger_path.name,
                    "--runtime-evidence",runtime_path.name,"--report-out",report_path.name,
                ])
        finally:
            os.chdir(prior)

        report=json.loads(report_path.read_bytes())
        self.assertEqual(result,0)
        self.assertEqual(report["batch_state"],"COMPLETED")
        self.assertEqual(report["send_attempts_consumed"],1)
        self.assertEqual(report["max_send_attempts"],1)
        self.assertEqual(report["remaining_unattempted_cap"],1)
        self.assertFalse(report["execution_allowed"])
        self.assertEqual(report["execution_mode"],"ISOLATED_FIXTURE_ONLY")
        self.assertEqual(report["outcome_reconciliation"],{
            "APPLIED_VERIFIED":{"count":1,"cost_usd":"1"},
            "NOT_ATTEMPTED_CAP":{"count":1,"cost_usd":"1"},
        })
        self.assertTrue(fixture_ledger_path.is_file())
        self.assertEqual(hashlib.sha256(self.ledger_path.read_bytes()).hexdigest(),
                         host_ledger_digest)

    def test_owner_revocation_between_rows_stops_batch_without_second_send(self) -> None:
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )

        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        revoked=OwnerTrust.from_allowed_signers(
            self.allowed_signers,
            pinned_sha256=hashlib.sha256(self.allowed_signers.read_bytes()).hexdigest(),
            enrolled={
                "ledger-owner": {self.fingerprint: EnrolledOwner(self.fingerprint,"ledger-migrator")},
                "batch-owner": {self.batch_fingerprint: EnrolledOwner(self.batch_fingerprint,"batch-approver",True)},
            },expected_uid=os.getuid())
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            adapter=FakeBatchSDKAdapter({arn:{} for arn in arns})
            runtime=BatchOfflineRuntime({"scope-1":BatchRuntimeEvidence(scope,effects)},adapter)
            with (
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",
                      side_effect=[self.trust,self.trust,revoked]),
                patch("name_tag_batch_trust.load_current_protected_owner_trust",
                      side_effect=[self.trust,self.trust,self.trust,self.trust,
                                   self.trust,self.trust,revoked,revoked]),
            ):
                result=execute_batch_offline(
                    batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,runtime=runtime)

        self.assertEqual(adapter.write_calls,1)
        self.assertEqual(result.batch_state,"STOPPED")
        self.assertEqual(result.outcomes[1],"NOT_ATTEMPTED_BATCH_STOP")
        self.assertEqual(result.report["authentication_state"],"OWNER_AUTHN_REVOKED")

    def test_batch_state_rejects_tampered_persisted_row_identity(self) -> None:
        decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            authority=derive_batch_row_authority(
                batch,batch.approved_row_indexes[0],trust=self.trust,now_utc=signed_at)
            with patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust):
                ledger.create_batch_intent(authority,scope=scope,side_effects=effects)
            with ledger._connection() as connection:
                connection.execute(
                    "UPDATE batch_rows SET resource_arn=? WHERE batch_id=? AND row_index=?",
                    ("arn:aws:ec2:us-east-1:123456789012:volume/vol-fffffffffffffffff",
                     batch.batch_id,authority.row_index),
                )
                connection.commit()

            with patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust):
                with self.assertRaises(LedgerError):
                    ledger.batch_execution_state(batch)

    def test_issuer_failure_blocks_intent_permit_and_fake_write(self) -> None:
        from name_tag_batch_credentials import CredentialBlocked
        from name_tag_batch_executor import (
            BatchOfflineRuntime, BatchRuntimeEvidence, FakeBatchSDKAdapter,
            execute_batch_offline,
        )

        migration_decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=migration_decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        arns=[row["resource_arn"] for row in batch.approved_rows]
        with closing(open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)) as ledger:
            scope,effects=self._initialize_batch_scope(ledger,arns)
            adapter=FakeBatchSDKAdapter({arn:{} for arn in arns})
            reads=[]
            original_read=adapter.read_current
            adapter.read_current=lambda *a,**k:(reads.append(1),original_read(*a,**k))[1]
            runtime=BatchOfflineRuntime({"scope-1":BatchRuntimeEvidence(scope,effects)},adapter)
            with (
                patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_runtime.load_current_protected_owner_trust",return_value=self.trust),
                patch("name_tag_batch_credentials.OfflineFakeIssuer.issue",
                      side_effect=CredentialBlocked("forced")),
            ):
                result=execute_batch_offline(
                    batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,runtime=runtime)
            with ledger._connection() as connection:
                intents=connection.execute("SELECT COUNT(*) FROM intents").fetchone()[0]

        self.assertEqual(result.batch_state,"STOPPED")
        self.assertEqual(adapter.write_calls,0)
        self.assertEqual(reads,[])
        self.assertEqual(intents,0)
        self.assertEqual(result.send_attempts_consumed,0)

    def test_explicit_stop_marks_rows_unattempted_without_intent_or_skip(self) -> None:
        migration_decision=migration.verify_ledger_migration_decision(
            self._envelope(),trust=self.trust,
            now_utc=datetime.now(timezone.utc).replace(microsecond=0))
        with patch.object(migration_apply,"load_current_protected_owner_trust",return_value=self.trust):
            migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path,decision=migration_decision)
        plan_bytes,csv_bytes,envelope,signed_at=self._batch_inputs()
        batch=verify_batch_approval(plan_bytes,csv_bytes,envelope,trust=self.trust,now_utc=signed_at)
        ledger=open_ledger(self.ledger_path,trusted_host=True,trust=self.trust)
        self.addCleanup(ledger.close)

        with patch("name_tag_batch_trust.load_current_protected_owner_trust",return_value=self.trust):
            ledger.stop_batch(batch,reason_code="BLOCKED_NAME_UNKNOWN")
            state=ledger.batch_execution_state(batch)
        with ledger._connection() as connection:
            intents=connection.execute("SELECT COUNT(*) FROM intents").fetchone()[0]
            dispositions=connection.execute("SELECT COUNT(*) FROM batch_row_dispositions").fetchone()[0]

        self.assertEqual(state.state,"STOPPED")
        self.assertEqual(state.outcomes,("NOT_ATTEMPTED_BATCH_STOP","NOT_ATTEMPTED_BATCH_STOP"))
        self.assertEqual(intents,0)
        self.assertEqual(dispositions,0)


if __name__ == "__main__":
    unittest.main()
