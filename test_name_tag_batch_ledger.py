import sqlite3,tempfile,unittest
from contextlib import closing
from unittest.mock import patch
from pathlib import Path
import name_tag_batch_ledger
from name_tag_batch_ledger import OfflineFixtureBatchLedger, LedgerBlocked

class DurableFixtureTests(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory();self.addCleanup(self.d.cleanup)
        self.path=Path(self.d.name)/'batch_fixture.sqlite'
        self.ledger=OfflineFixtureBatchLedger.create_fixture(self.path)
        self.ledger.register('batch-a','nonce-a',max_send_attempts=1,row_count=2,scope_ids=['scope-a','scope-b'])
    def tearDown(self):
        self.ledger.close()
    def test_counter_atomic_and_cap_skip(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.assertEqual(self.ledger.counter('batch-a'),1)
        self.ledger.readback('batch-a',0,'APPLIED_VERIFIED')
        self.ledger.classify_cap('batch-a')
        self.assertEqual(self.ledger.dispositions('batch-a'),[(1,'NOT_ATTEMPTED_CAP')])
        self.assertEqual(self.ledger.state('batch-a'),'COMPLETED')
        with self.assertRaises(LedgerBlocked):self.ledger.admit('batch-a',1,'scope-b','row-1')
    def test_presend_skip_does_not_count_and_survives_restart(self):
        self.ledger.presend_skip('batch-a',0,'scope-a','row-0','SKIPPED_NAME_CHANGED')
        self.assertEqual(self.ledger.counter('batch-a'),0)
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.ledger.admit('batch-a',1,'scope-b','row-1')
        self.ledger.consume('batch-a',1)
        self.ledger.readback('batch-a',1,'APPLIED_VERIFIED')
        self.ledger.complete('batch-a')
        self.assertEqual(self.ledger.state('batch-a'),'COMPLETED')
        with self.assertRaises(LedgerBlocked):self.ledger.presend_skip('batch-a',0,'scope-a','row-0','SKIPPED_NAME_CHANGED')
    def test_cross_scope_unknown_stops_durably(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.readback('batch-a',0,'OUTCOME_UNKNOWN')
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.assertEqual(self.ledger.state('batch-a'),'STOPPED')
        self.ledger.release_scope('scope-a')
        with self.assertRaises(LedgerBlocked):self.ledger.admit('batch-a',1,'scope-b','row-1')
    def test_crash_after_consumed_stops_and_counter_preserved(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.assertEqual(self.ledger.counter('batch-a'),1)
        self.assertEqual(self.ledger.state('batch-a'),'STOPPED')
        with self.assertRaises(LedgerBlocked):self.ledger.admit('batch-a',1,'scope-b','row-1')
    def test_crash_after_consumed_holds_scope_for_later_batches(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.close();self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-a'])

        with self.assertRaises(LedgerBlocked):
            self.ledger.admit('batch-b',0,'scope-a','row-b')
        self.assertEqual(self.ledger.conn.execute("SELECT state FROM scopes WHERE scope_id='scope-a'").fetchone(),('HOLD',))
    def test_history_tamper_counter_rejected(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.close()
        con=sqlite3.connect(self.path);con.execute('UPDATE batch_registry SET send_attempts_consumed=0');con.commit();con.close()
        with self.assertRaises(LedgerBlocked):OfflineFixtureBatchLedger.open_fixture(self.path)
        # TearDown should not close an already closed connection
        self.ledger=OfflineFixtureBatchLedger.open_read_only_for_fixture(self.path)

    def test_create_fixture_rolls_back_partial_schema(self):
        path = Path(self.d.name) / 'partial_fixture.sqlite'
        ddl = 'CREATE TABLE should_rollback (id INTEGER); CREATE TABL invalid;'
        with patch.object(name_tag_batch_ledger, 'DDL', ddl):
            with self.assertRaises(sqlite3.OperationalError):
                OfflineFixtureBatchLedger.create_fixture(path)
        with closing(sqlite3.connect(path)) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        self.assertEqual(tables, [])

    def test_admission_rejects_after_cap_without_creating_intent(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.readback('batch-a',0,'APPLIED_VERIFIED')
        with self.assertRaises(LedgerBlocked):
            self.ledger.admit('batch-a',1,'scope-b','row-1')
        self.assertIsNone(self.ledger.conn.execute(
            'SELECT 1 FROM intents WHERE batch_id=? AND row_index=?',('batch-a',1)).fetchone())

    def test_presend_skip_rejects_after_cap(self):
        self.ledger.admit('batch-a',0,'scope-a','row-0')
        self.ledger.consume('batch-a',0)
        self.ledger.readback('batch-a',0,'APPLIED_VERIFIED')
        with self.assertRaises(LedgerBlocked):
            self.ledger.presend_skip('batch-a',1,'scope-b','row-1','SKIPPED_NAME_CHANGED')

    def test_consume_rejects_unresolved_intent_in_another_batch_same_scope(self):
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-a'])
        self.ledger.admit('batch-b',0,'scope-a','row-b')
        self.ledger.conn.execute(
            "INSERT INTO intents VALUES(?,?,?,?,?)",
            ('batch-a',0,'row-a','scope-a','SEND_ATTEMPT_CONSUMED'),
        )
        with self.assertRaises(LedgerBlocked):
            self.ledger.consume('batch-b',0)

    def test_admit_rejects_another_batch_admitted_intent_in_same_scope(self):
        self.ledger.admit('batch-a',0,'scope-a','row-a')
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-a'])
        with self.assertRaises(LedgerBlocked):
            self.ledger.admit('batch-b',0,'scope-a','row-b')

    def test_reconcile_holds_all_scopes_before_stopping_related_batches(self):
        self.ledger.register('batch-b','nonce-b',max_send_attempts=1,row_count=1,scope_ids=['scope-b'])
        self.ledger.admit('batch-b',0,'scope-b','row-b')
        self.ledger.consume('batch-b',0)
        self.ledger.close()
        self.ledger=OfflineFixtureBatchLedger.open_fixture(self.path)
        self.assertEqual(self.ledger.state('batch-a'),'STOPPED')
        self.assertEqual(self.ledger.state('batch-b'),'STOPPED')
        self.assertEqual(self.ledger.conn.execute(
            "SELECT state FROM scopes WHERE scope_id='scope-b'"
        ).fetchone(),('HOLD',))



# ---------------------------------------------------------------------------
# Task 7: real migrated Ledger v2 (no Fake Ledger) for the non-EC2 Batch validator.
# Every non-volume Kind below is a TEST-ONLY fixture patched in per test; no production
# Registry decision is promoted by it. No AWS, STS or network is used.
# ---------------------------------------------------------------------------
import base64 as _b64
from unittest import mock
import contextlib as _contextlib
import dataclasses as _dataclasses
import hashlib as _hashlib
import json as _json
import re as _re
from datetime import datetime as _dt, timedelta as _td, timezone as _tz
from types import MappingProxyType as _MPT, SimpleNamespace as _NS

import name_tag_kind_capabilities as _caps
import name_tag_kind_name_evidence as _evidence_module
import name_tag_ledger as _ledger_module
import test_name_tag_batch_migration as _mig
from name_tag_approval import approval_digest as _approval_digest
from name_tag_batch_approval import (
    BATCH_NAMESPACE as _BATCH_NS, derive_batch_row_authority as _derive,
    prepare_batch_approval as _prepare, verify_batch_approval as _verify)
from name_tag_batch_state import build_batch_review_projection as _projection
from name_tag_ledger import (
    SCOPE_DECISION_NAMESPACE as _SCOPE_NS, SUPPORTED_OPERATIONS as _SUPPORTED,
    _canonical_scope_payload, _side_effect_digest, initialize_scope as _init_scope,
    open_ledger as _open_ledger)
from name_tag_ledger_errors import LedgerError as _LedgerError
from name_tag_scope import ScopeEvidence as _Scope, SideEffectEvidence as _Effect
from test_helpers import sample_population as _population

ACCOUNT = "123456789012"
REGION = "us-east-1"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/Batch"
VOLUMES = (f"arn:aws:ec2:{REGION}:{ACCOUNT}:volume/vol-0123456789abcdef0",
           f"arn:aws:ec2:{REGION}:{ACCOUNT}:volume/vol-abcdef01234567890")
LAMBDA_FN = "shop-api"
LAMBDA_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{LAMBDA_FN}"


def volume_record(index: int, arn: str = VOLUMES[0]) -> dict:
    locator = arn.rsplit("/", 1)[1]
    return {
        "proposal_id": f"proposal-{index}", "kind": "volume", "locator": locator,
        "region": REGION, "resource_arn": arn, "aws_operation": "ec2:CreateTags",
        "status": "proposed", "confidence": "high", "name_state": "ABSENT",
        "name_key_present": False, "name_raw_value": None, "existing_name": "",
        "proposed_name": f"web-prd-ebs-xvda-{locator[-7:]}", "effective_usage_cost_usd": "1",
        "evidence": (f"EBS {locator} -> attachment i-0123456789abcdef0 xvda -> EC2 "
                     "i-0123456789abcdef0 Name=web-prd; Product(observed, not validated)=(unset)"),
    }


def lambda_record(index: int) -> dict:
    return {
        "proposal_id": f"proposal-{index}", "kind": "lambda", "locator": LAMBDA_FN,
        "region": REGION, "resource_arn": LAMBDA_ARN, "aws_operation": "lambda:TagResource",
        "status": "proposed", "confidence": "high", "name_state": "ABSENT",
        "name_key_present": False, "name_raw_value": None, "existing_name": "",
        "proposed_name": "shop-prod-lambda-api", "effective_usage_cost_usd": "1",
        "evidence": f"FIXTURE LAMBDA {LAMBDA_FN} tags app=shop env=prod",
    }


class FixtureLambdaVerifier:
    """TEST-ONLY deterministic Name formula for a Lambda function fixture."""

    def verify(self, plan_record, target):
        match = _re.fullmatch(rf"FIXTURE LAMBDA {_re.escape(target.locator)} tags "
                              r"app=([a-z]+) env=([a-z]+)", plan_record.get("evidence") or "")
        if match is None:
            raise _evidence_module.NameEvidenceNotProven("fixture evidence mismatch")
        name = f"{match.group(1)}-{match.group(2)}-lambda-{target.locator.split('-')[-1]}"
        return _evidence_module.VerifiedGeneratedName(
            target.kind, target.resource_arn, name,
            _hashlib.sha256(plan_record["evidence"].encode()).hexdigest())


@_contextlib.contextmanager
def proven_lambda():
    """TEST-ONLY: promote the lambda Registry decision and its Name verifier for one test."""
    decision = _dataclasses.replace(
        _caps.resolve_kind_capability("lambda"), status="IMPLEMENTED_OFFLINE",
        reason_code="OFFLINE_CONTRACT_COMPLETE", evidence_refs=("test-only fixture",),
        tag_key_conditions=("aws:TagKeys", "aws:RequestTag/Name"))
    with mock.patch.object(_caps, "_DECISIONS", _MPT({**_caps._DECISIONS, "lambda": decision})), \
            mock.patch.dict(_evidence_module._VERIFIERS, {"lambda": FixtureLambdaVerifier()}):
        yield decision


class RealLedgerV2Case(unittest.TestCase):
    """Shared real-Ledger-v2 harness (provisioned v1 -> signed migration -> v2)."""

    setUp_v1 = _mig.BatchLedgerMigrationTests.setUp
    _envelope = _mig.BatchLedgerMigrationTests._envelope
    _sign = _mig.BatchLedgerMigrationTests._sign

    def setUp(self) -> None:
        self.setUp_v1()
        decision = _mig.migration.verify_ledger_migration_decision(
            self._envelope(), trust=self.trust, now_utc=_dt.now(_tz.utc).replace(microsecond=0))
        with mock.patch.object(_mig.migration_apply, "load_current_protected_owner_trust",
                               return_value=self.trust):
            _mig.migration.upgrade_ledger_v1_to_batch_v2(self.ledger_path, decision=decision)
        self.now = _dt.now(_tz.utc).replace(microsecond=0)

    def trusted(self):
        """Current protected OwnerTrust is the test trust (stands in for the Host pin)."""
        stack = _contextlib.ExitStack()
        for target in ("name_tag_batch_trust.load_current_protected_owner_trust",
                       "name_tag_batch_runtime.load_current_protected_owner_trust",
                       "name_tag_batch_host_runtime.load_current_protected_owner_trust"):
            stack.enter_context(mock.patch(target, return_value=self.trust))
        return stack

    def make_batch(self, records, *, cap: int = 1, nonce: str = "b2" * 16, approve=None):
        arns = sorted({r["resource_arn"] for r in records})
        plan = {
            "schema_version": 3, "account": ACCOUNT, "partition": "aws", "period": "2026-11",
            "count": len(records), "records": records,
            "cur_population": _population(count=len(records), cost=str(len(records))),
            "execution_limits": {"max_send_attempts": cap},
            "scope_declarations": [{
                "writer_control_scope_id": "scope-1", "account": ACCOUNT, "partition": "aws",
                "region": REGION, "resource_arns": arns}],
        }
        plan_bytes = _json.dumps(plan, ensure_ascii=False, sort_keys=True).encode()
        csv = _projection(plan_bytes)
        for r in records:
            if approve is None or r["proposal_id"] in approve:
                csv = csv.replace(f",{r['proposal_id']},".encode(),
                                  f"YES,{r['proposal_id']},".encode())
        prepared = _prepare(
            plan_bytes, csv, owner_principal_id="batch-owner",
            owner_key_fingerprint=self.batch_fingerprint, authorized_role_arn=ROLE_ARN,
            issued_at_utc=self.now.isoformat().replace("+00:00", "Z"),
            expires_at_utc=(self.now + _td(hours=1)).isoformat().replace("+00:00", "Z"),
            batch_nonce=nonce)
        signature = self._sign(self.batch_key_path, prepared.canonical_payload_bytes, _BATCH_NS)
        envelope = _json.dumps({
            "payload": prepared.payload, "batch_id": prepared.batch_id,
            "signature_ref": _b64.b64encode(signature).decode("ascii")},
            separators=(",", ":")).encode()
        batch = _verify(plan_bytes, csv, envelope, trust=self.trust, now_utc=self.now)
        return batch

    def open(self):
        ledger = _open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
        self.addCleanup(ledger.close)
        return ledger

    def init_scope(self, ledger, arns, *, nonce: str = "scope-initialize-0123456789"):
        effects = tuple(_Effect(
            target_arn=arn, iam_abac_resource_tag_assessment="PASS", iac_assessment="PASS",
            event_automation_assessment="PASS",
            evidence_references=("evidence://iam", "evidence://iac", "evidence://events"),
            not_before_utc=self.now - _td(hours=1), not_after_utc=self.now + _td(hours=1))
            for arn in sorted(arns))
        scope = _Scope(
            account=ACCOUNT, partition="aws", region=REGION, writer_control_scope_id="scope-1",
            controlled_arns=frozenset(arns), not_before_utc=self.now - _td(hours=1),
            not_after_utc=self.now + _td(hours=1), writer_evidence_digest="c" * 64,
            responsible_owner="batch-owner")
        payload = {
            "schema_version": 1, "decision_namespace": _SCOPE_NS, "action": "INITIALIZE",
            "scope_id": "scope-1", "account": ACCOUNT, "partition": "aws", "region": REGION,
            "target_arns": sorted(arns), "writer_evidence_digest": scope.writer_evidence_digest,
            "side_effect_evidence_digest": _side_effect_digest(effects),
            "host_binding": ledger._host_binding, "owner_principal_id": "batch-owner",
            "owner_key_fingerprint": self.batch_fingerprint, "allowed_role": "batch-approver",
            "issued_at_utc": self.now.isoformat(),
            "expires_at_utc": (self.now + _td(hours=1)).isoformat(),
            "decision_nonce": nonce, "reason": "offline test scope", "hold_generation_id": None,
        }
        canonical = _canonical_scope_payload(payload)
        signature = self._sign(self.batch_key_path, canonical, _SCOPE_NS)
        _init_scope(ledger, {"payload": payload, "decision_id": _approval_digest(canonical),
                             "signature_ref": _b64.b64encode(signature).decode("ascii")},
                    action="INITIALIZE", scope=scope, side_effects=effects)
        return scope, effects

    def authority(self, batch, position: int = 0):
        return _derive(batch, batch.approved_row_indexes[position], trust=self.trust,
                       now_utc=self.now)

    def sql(self, query: str, params=()):
        with closing(sqlite3.connect(self.ledger_path)) as connection:
            return connection.execute(query, params).fetchall()

    def intents(self):
        return self.sql("SELECT state,outcome,aws_operation FROM intents ORDER BY created_at_utc")


@_contextlib.contextmanager
def tampered_rows(**changes):
    """Simulate a bypassed signature check: the Ledger's re-derived row carries ``changes``."""
    real = _ledger_module.derive_batch_row_authority

    def forged(batch, row_index, **kwargs):
        fresh = real(batch, row_index, **kwargs)
        return _dataclasses.replace(fresh, row=_MPT({**dict(fresh.row), **changes}))
    with mock.patch.object(_ledger_module, "derive_batch_row_authority", forged):
        yield


class NonEc2BatchValidatorTests(RealLedgerV2Case):
    def test_non_ec2_approved_kind_intent_first_permit(self):
        with proven_lambda(), self.trusted():
            batch = self.make_batch([lambda_record(0)])
            ledger = self.open()
            scope, effects = self.init_scope(ledger, [LAMBDA_ARN])
            handle = ledger.create_batch_intent(self.authority(batch), scope=scope,
                                                side_effects=effects)
            permit = ledger.consume_first_send(handle)
        self.assertEqual(permit.aws_operation, "lambda:TagResource")
        self.assertEqual(permit.resource_arn, LAMBDA_ARN)
        self.assertEqual(self.intents(), [("SEND_ATTEMPT_CONSUMED", None, "lambda:TagResource")])

    def _denied(self, batch_records, *, scope_arns, changes=None, scope_changes=None,
                proven=True, code=None):
        ctx = proven_lambda() if proven else _contextlib.nullcontext()
        with ctx, self.trusted():
            batch = self.make_batch(batch_records)
            ledger = self.open()
            scope, effects = self.init_scope(ledger, scope_arns)
            if scope_changes:
                scope = _dataclasses.replace(scope, **scope_changes)
            authority = self.authority(batch)
            with (tampered_rows(**changes) if changes else _contextlib.nullcontext()):
                with self.assertRaises(_LedgerError) as caught:
                    ledger.create_batch_intent(authority, scope=scope, side_effects=effects)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(self.intents(), [])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM batch_rows"), [(0,)])
        return caught.exception

    def test_non_ec2_wrong_signed_operation_denied(self):
        self._denied([lambda_record(0)], scope_arns=[LAMBDA_ARN],
                     changes={"aws_operation": "ec2:CreateTags"}, code="BLOCKED_OWNER_AUTHN")
        self._reset_ledger()
        self._denied([volume_record(0)], scope_arns=[VOLUMES[0]],
                     changes={"aws_operation": "lambda:TagResource"}, code="BLOCKED_OWNER_AUTHN")

    def _reset_ledger(self):
        self.doCleanups()
        self.setUp()

    def test_non_ec2_wrong_arn_denied(self):
        for changes in ({"resource_arn": VOLUMES[0]},
                        {"resource_arn": LAMBDA_ARN.replace(ACCOUNT, "210987654321")},
                        {"locator": "other-fn"}):
            with self.subTest(changes=changes):
                self._denied([lambda_record(0)], scope_arns=[LAMBDA_ARN], changes=changes,
                             code="BLOCKED_OWNER_AUTHN")
                self._reset_ledger()

    def test_non_ec2_wrong_scope_denied(self):
        self._denied([lambda_record(0)], scope_arns=[LAMBDA_ARN],
                     scope_changes={"region": "us-west-2"}, code="BLOCKED_SCOPE_MISMATCH")
        self._reset_ledger()
        self._denied([lambda_record(0)], scope_arns=[LAMBDA_ARN],
                     scope_changes={"controlled_arns": frozenset({VOLUMES[0]})},
                     code="BLOCKED_SCOPE_MISMATCH")
        self._reset_ledger()
        self._denied([lambda_record(0)], scope_arns=[LAMBDA_ARN],
                     scope_changes={"writer_control_scope_id": "scope-2"},
                     code="BLOCKED_SCOPE_STATE_UNKNOWN")

    def test_unapproved_or_unvetted_kind_denied(self):
        # Signed while the test-only promotion was active; at admission the vetted Registry
        # no longer approves lambda (production state) -> denied before any Intent.
        with proven_lambda():
            with self.trusted():
                batch = self.make_batch([lambda_record(0)])
                ledger = self.open()
                scope, effects = self.init_scope(ledger, [LAMBDA_ARN])
                authority = self.authority(batch)
        with self.trusted(), self.assertRaises(_LedgerError) as caught:
            ledger.create_batch_intent(authority, scope=scope, side_effects=effects)
        self.assertEqual(caught.exception.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self.intents(), [])

    def test_untrusted_or_blocked_registry_decision_denied(self):
        batch = _NS(payload={"account": ACCOUNT, "partition": "aws"})
        volume = dict(volume_record(0))
        lam = dict(lambda_record(0))
        validator = _ledger_module.IntentLedger._vetted_batch_write_operation
        self.assertEqual(validator(batch, volume), "ec2:CreateTags")
        with self.assertRaises(_LedgerError):
            validator(batch, lam)  # production: lambda is CAPABILITY_NOT_PROVEN
        with self.assertRaises(_LedgerError):
            validator(batch, {**volume, "kind": "unknown"})
        genuine = _caps.resolve_kind_capability("volume")
        for forged in (_dataclasses.replace(genuine, version="kind-capability-registry/0"),
                       _dataclasses.replace(genuine, tag_set_replacement=True),
                       _dataclasses.replace(genuine, status="CAPABILITY_NOT_PROVEN"),
                       _dataclasses.replace(genuine, write_operation="ec2:DeleteTags"),
                       _NS(**_dataclasses.asdict(genuine))):
            with self.subTest(forged=getattr(forged, "version", "ns")):
                with mock.patch.object(_caps, "_DECISIONS",
                                       _MPT({**_caps._DECISIONS, "volume": forged})):
                    with self.assertRaises(_LedgerError):
                        validator(batch, volume)
        apigw = _dataclasses.replace(_caps.resolve_kind_capability("apigw_stage"),
                                     status="IMPLEMENTED_OFFLINE")
        with mock.patch.object(_caps, "_DECISIONS", _MPT({**_caps._DECISIONS, "apigw_stage": apigw})):
            with self.assertRaises(_LedgerError):
                validator(batch, {**volume, "kind": "apigw_stage",
                                  "aws_operation": "apigateway:PATCH"})

    def test_forged_row_authority_denied(self):
        with self.trusted():
            batch = self.make_batch([volume_record(0)])
            ledger = self.open()
            scope, effects = self.init_scope(ledger, [VOLUMES[0]])
            authority = self.authority(batch)
            forged_type = _NS(**{f.name: getattr(authority, f.name)
                                 for f in _dataclasses.fields(authority)})
            forged_signature = _dataclasses.replace(
                authority, batch=_dataclasses.replace(batch, raw_envelope_bytes=b"{}"))
            for forged in (forged_type, forged_signature):
                with self.subTest(forged=type(forged).__name__):
                    with self.assertRaises(_LedgerError) as caught:
                        ledger.create_batch_intent(forged, scope=scope, side_effects=effects)
                    self.assertEqual(caught.exception.code, "BLOCKED_OWNER_AUTHN")
            handle = ledger.create_batch_intent(authority, scope=scope, side_effects=effects)
            ledger.consume_first_send(handle)
            with self.assertRaises(_LedgerError) as replay:
                ledger.create_batch_intent(authority, scope=scope, side_effects=effects)
        self.assertIn(replay.exception.code, ("BLOCKED_AUTH_REPLAY", "BLOCKED_INCOMPLETE_INTENT",
                                              "BLOCKED_SCOPE_STATE_UNKNOWN"))
        self.assertEqual(len(self.intents()), 1)

    def test_volume_ec2_create_tags_regression(self):
        with self.trusted():
            batch = self.make_batch([volume_record(0)])
            ledger = self.open()
            scope, effects = self.init_scope(ledger, [VOLUMES[0]])
            handle = ledger.create_batch_intent(self.authority(batch), scope=scope,
                                                side_effects=effects)
            permit = ledger.consume_first_send(handle)
            ledger.record_readback(handle, name_after=permit.approved_name,
                                   outcome="APPLIED_VERIFIED")
            ledger.complete_batch(batch)
            state = ledger.batch_execution_state(batch)
        self.assertEqual(permit.aws_operation, "ec2:CreateTags")
        self.assertEqual((state.state, state.outcomes), ("COMPLETED", ("APPLIED_VERIFIED",)))

    def test_registry_demoted_between_intent_and_permit_refuses_send(self):
        with proven_lambda(), self.trusted():
            batch = self.make_batch([lambda_record(0)])
            ledger = self.open()
            scope, effects = self.init_scope(ledger, [LAMBDA_ARN])
            handle = ledger.create_batch_intent(self.authority(batch), scope=scope,
                                                side_effects=effects)
            with tampered_rows(aws_operation="ec2:CreateTags"), \
                    self.assertRaises(_LedgerError):
                ledger.consume_first_send(handle)
        self.assertEqual(self.intents(), [("WRITE_INTENT_RECORDED", None, "lambda:TagResource")])

    def test_legacy_verified_envelope_allowlist_unchanged(self):
        import inspect
        self.assertEqual(_SUPPORTED, frozenset({"ec2:CreateTags:2016-11-15"}))
        source = inspect.getsource(_ledger_module.IntentLedger._revalidate_authorization)
        self.assertIn("aws_operation not in SUPPORTED_OPERATIONS", source)
        self.assertNotIn("_vetted_batch_write_operation", source)
        ledger = self.open()
        fresh = _NS(payload={"writer_control_scope_id": "s", "aws_operation": "lambda:TagResource"})
        with mock.patch.object(_ledger_module, "revalidate_verified_envelope", return_value=fresh):
            with self.assertRaises(_LedgerError) as caught:
                ledger._revalidate_authorization(object(), "s")
        self.assertEqual(caught.exception.code, "BLOCKED_OWNER_AUTHN")

    def test_ledger_v2_no_schema_change(self):
        before = self.sql("SELECT type,name,sql FROM sqlite_master ORDER BY name")
        with proven_lambda(), self.trusted():
            batch = self.make_batch([lambda_record(0)])
            ledger = self.open()
            scope, effects = self.init_scope(ledger, [LAMBDA_ARN])
            ledger.consume_first_send(ledger.create_batch_intent(
                self.authority(batch), scope=scope, side_effects=effects))
        self.assertEqual(self.sql("SELECT type,name,sql FROM sqlite_master ORDER BY name"), before)
        self.assertEqual(self.sql("SELECT value FROM ledger_meta WHERE key='schema_version'"),
                         [("2",)])


class RealLedgerPermitIdentityTests(RealLedgerV2Case):
    """Obligation (e): batch_send_permit_identity over a real migrated Ledger v2."""

    def test_permit_identity_only_for_current_execution_consumed_intent(self):
        with self.trusted():
            batch = self.make_batch([volume_record(0)])
            ledger = self.open()
            scope, effects = self.init_scope(ledger, [VOLUMES[0]])
            index = batch.approved_row_indexes[0]
            self.assertIsNone(ledger.batch_send_permit_identity(batch, index))
            handle = ledger.create_batch_intent(self.authority(batch), scope=scope,
                                                side_effects=effects)
            self.assertIsNone(ledger.batch_send_permit_identity(batch, index))
            permit = ledger.consume_first_send(handle)
            identity = ledger.batch_send_permit_identity(batch, index)
            other = _open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
            self.addCleanup(other.close)
            other_identity = other.batch_send_permit_identity(batch, index)
            ledger.record_readback(handle, name_after=permit.approved_name,
                                   outcome="APPLIED_VERIFIED")
            after = ledger.batch_send_permit_identity(batch, index)
        self.assertEqual(identity, (permit.authorization_id, permit.execution_id,
                                    _hashlib.sha256(permit.ownership_token.encode()).hexdigest()))
        self.assertNotIn(permit.ownership_token, repr(identity))
        self.assertIsNone(other_identity)
        self.assertIsNone(after)



class NoSendFinalizerLedgerTests(RealLedgerV2Case):
    """Refusal window B on the real Ledger: Intent exists, Permit never consumed."""

    def _intent(self, records=None, cap=1):
        batch = self.make_batch(records or [volume_record(0)], cap=cap)
        ledger = self.open()
        scope, effects = self.init_scope(ledger, [r["resource_arn"] for r in
                                                  (records or [volume_record(0)])])
        handle = ledger.create_batch_intent(self.authority(batch), scope=scope,
                                            side_effects=effects)
        return batch, ledger, handle

    def test_finalizer_atomically_marks_terminal_stops_batch_and_holds_scope(self):
        with self.trusted():
            batch, ledger, handle = self._intent()
            ledger._host_finalize_unsent_batch_intent(
                handle, reason_code="G2_NOT_VERIFIED", sdk_dispatches=0)
            state = ledger.batch_execution_state(batch)
            with self.assertRaises(_LedgerError):
                ledger.consume_first_send(handle)
        self.assertEqual((state.state, state.send_attempts_consumed, state.outcomes),
                         ("STOPPED", 0, ("NOT_ATTEMPTED_BATCH_STOP",)))
        self.assertEqual(self.intents(), [("TERMINAL", "NOT_ATTEMPTED_BATCH_STOP", "ec2:CreateTags")])
        self.assertEqual(self.sql("SELECT state FROM scopes WHERE scope_id='scope-1'"), [("HOLD",)])
        self.assertEqual(self.sql("SELECT event FROM intent_history ORDER BY id"),
                         [("WRITE_INTENT_RECORDED",), ("TERMINAL:NOT_ATTEMPTED_BATCH_STOP",)])

    def test_finalizer_refuses_consumed_permit_or_dispatch_and_changes_nothing(self):
        with self.trusted():
            batch, ledger, handle = self._intent()
            with self.assertRaises(_LedgerError):
                ledger._host_finalize_unsent_batch_intent(handle, reason_code="X", sdk_dispatches=1)
            ledger.consume_first_send(handle)
            with self.assertRaises(_LedgerError):
                ledger._host_finalize_unsent_batch_intent(handle, reason_code="X", sdk_dispatches=0)
            state = ledger.batch_execution_state(batch)
        self.assertEqual(self.intents(), [("SEND_ATTEMPT_CONSUMED", None, "ec2:CreateTags")])
        self.assertEqual((state.state, state.send_attempts_consumed), ("ACTIVE", 1))
        self.assertEqual(self.sql("SELECT state FROM scopes WHERE scope_id='scope-1'"),
                         [("CLEARED",)])

    def test_finalizer_owner_revoked_cannot_prove_and_leaves_intent_unresolved(self):
        from name_tag_batch_approval import BatchAuthRejected
        with self.trusted():
            batch, ledger, handle = self._intent()
        with mock.patch("name_tag_batch_trust.load_current_protected_owner_trust",
                        side_effect=BatchAuthRejected()):
            with self.assertRaises(_LedgerError) as caught:
                ledger._host_finalize_unsent_batch_intent(
                    handle, reason_code="BLOCKED_OWNER_AUTHN", sdk_dispatches=0)
        self.assertEqual(caught.exception.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self.intents(), [("WRITE_INTENT_RECORDED", None, "ec2:CreateTags")])

    def test_finalizer_transaction_failure_rolls_back_everything(self):
        with self.trusted():
            batch, ledger, handle = self._intent()
            real = ledger._connection

            class Failing:
                def __init__(self, inner):
                    self.inner = inner

                def __enter__(self):
                    conn = self.inner.__enter__()
                    outer = self

                    class Proxy:
                        def execute(self, sql, params=()):
                            if sql.startswith("UPDATE scopes SET state='HOLD'"):
                                raise sqlite3.OperationalError("disk I/O error")
                            return conn.execute(sql, params)

                        def commit(self):
                            return conn.commit()
                    return Proxy()

                def __exit__(self, *exc):
                    return self.inner.__exit__(*exc)
            with mock.patch.object(ledger, "_connection", lambda: Failing(real())):
                with self.assertRaises(_LedgerError) as caught:
                    ledger._host_finalize_unsent_batch_intent(
                        handle, reason_code="G2_NOT_VERIFIED", sdk_dispatches=0)
            state = ledger.batch_execution_state(batch)
        self.assertEqual(caught.exception.code, "BLOCKED_SCOPE_STATE_UNKNOWN")
        self.assertEqual(self.intents(), [("WRITE_INTENT_RECORDED", None, "ec2:CreateTags")])
        self.assertEqual(state.state, "ACTIVE")
        self.assertEqual(self.sql("SELECT state FROM scopes WHERE scope_id='scope-1'"),
                         [("CLEARED",)])

    def test_finalizer_foreign_execution_handle_refused(self):
        with self.trusted():
            batch, ledger, handle = self._intent()
            other = _open_ledger(self.ledger_path, trusted_host=True, trust=self.trust)
            self.addCleanup(other.close)
            with self.assertRaises(_LedgerError):
                other._host_finalize_unsent_batch_intent(
                    handle, reason_code="X", sdk_dispatches=0)
            forged = _dataclasses.replace(handle, ownership_token="f" * 32)
            with self.assertRaises(_LedgerError):
                ledger._host_finalize_unsent_batch_intent(forged, reason_code="X",
                                                          sdk_dispatches=0)
        self.assertEqual(self.intents(), [("WRITE_INTENT_RECORDED", None, "ec2:CreateTags")])


if __name__ == '__main__':
    unittest.main()
