"""Pure synthetic Batch execution for offline fixtures; never imports/calls boto3.

Do not wire this simulator to production authority, real Ledger or AWS clients.
An authenticated production executor is NOT supplied by this module.
"""
from __future__ import annotations
from dataclasses import dataclass
from collections.abc import Mapping,Sequence
from contextlib import closing
from datetime import datetime,timezone
from pathlib import Path
import json
import re
import sqlite3
from typing import TypedDict
from name_tag_batch_approval import VerifiedBatchApproval
from name_tag_batch_state import classify_batch_name
from name_tag_batch_ledger import OfflineFixtureBatchLedger,LedgerBlocked
from name_tag_ledger import IntentLedger
from name_tag_batch_fake import (
    BatchOfflineRuntime,
    BatchRunResult,
    BatchRuntimeEvidence,
    FakeBatchSDKAdapter,
)
from name_tag_batch_runtime import (
    execute_batch_offline as _execute_batch_offline,
)

@dataclass
class InMemoryNameAdapter:
    initial:dict
    unreadable_after_write:set|None=None

    def __post_init__(self):
        self.tags={k:dict(v) for k,v in self.initial.items()}
        self.unreadable_after_write=set(self.unreadable_after_write or ())
        self.write_calls=0
        self.written=set()
    def read_current(self,arn):
        if arn not in self.tags:raise OSError('Resource not in fixture')
        return dict(self.tags[arn])
    def write_once(self,arn,name):
        if arn not in self.tags:raise OSError('Foreign resource')
        self.write_calls+=1
        self.tags[arn]['Name']=name
        self.written.add(arn)
    def readback(self,arn):
        if arn in self.unreadable_after_write:raise OSError('Fixture readback unavailable')
        return self.read_current(arn)


class FixtureSimulationResult(TypedDict):
    authentication_state:str
    execution_allowed:bool
    batch_state:str
    stop_reason:str|None
    send_attempts_consumed:int
    max_send_attempts:int
    remaining_unattempted_cap:int
    outcomes:list[str]
    writes_complete:bool


def simulate_untrusted_fixture(
    batch_id:str,
    nonce:str,
    approved_rows:Sequence[Mapping[str,str|bool|None]],
    *,
    ledger:OfflineFixtureBatchLedger,
    adapter:InMemoryNameAdapter|FakeBatchSDKAdapter,
    cap:int,
)->FixtureSimulationResult:
    """Synthetic test harness. Its output is never Owner/AWS authorization evidence."""
    if (type(ledger) is not OfflineFixtureBatchLedger
            or type(adapter) not in (InMemoryNameAdapter, FakeBatchSDKAdapter)):
        raise LedgerBlocked('Fixture-only objects required')
    if not approved_rows or type(cap) is not int or not (1<=cap<=20):raise LedgerBlocked('Invalid fixture inputs')
    scopes=[]
    for row in approved_rows:
        _validate_fixture_approval(row)
        scopes.append(row['writer_control_scope_id'])
    ledger.register(batch_id,nonce,max_send_attempts=cap,row_count=len(approved_rows),scope_ids=scopes)
    initial_consumed=ledger.counter(batch_id)
    outcomes=[]
    state_recovery_required=False
    for i,row in enumerate(approved_rows):
        try:
            active=ledger.state(batch_id)=='ACTIVE'
        except (LedgerBlocked,sqlite3.Error):
            try:
                ledger.stop(batch_id,'BLOCKED_SCOPE_STATE_UNKNOWN')
            except (LedgerBlocked,sqlite3.Error):
                state_recovery_required=True
            outcomes.extend(['NOT_ATTEMPTED_BATCH_STOP']*(len(approved_rows)-i))
            break
        if not active:
            outcomes.extend(['NOT_ATTEMPTED_BATCH_STOP']*(len(approved_rows)-i))
            break
        if ledger.counter(batch_id)>=cap:
            ledger.classify_cap(batch_id)
            outcomes.extend(['NOT_ATTEMPTED_CAP']*(len(approved_rows)-i))
            break
        try:
            outcome,stop=_execute_fixture_row(batch_id,i,row,ledger,adapter)
        except (LedgerBlocked,sqlite3.Error):
            state_recovery_required=True
            outcomes.extend(['NOT_ATTEMPTED_BATCH_STOP']*(len(approved_rows)-i))
            break
        outcomes.append(outcome)
        if stop:
            outcomes.extend(['NOT_ATTEMPTED_BATCH_STOP']*(len(approved_rows)-i-1))
            break
    _finish_fixture_batch(batch_id,approved_rows,outcomes,ledger)
    try:
        batch_state,stop_reason=ledger.conn.execute(
            'SELECT state,stop_reason FROM batch_registry WHERE batch_id=?',(batch_id,)
        ).fetchone()
        send_attempts_consumed=ledger.counter(batch_id)
        remaining_unattempted_cap=sum(
            decision=='NOT_ATTEMPTED_CAP' for _,decision in ledger.dispositions(batch_id))
    except (LedgerBlocked,sqlite3.Error):
        batch_state='RECOVERY_REQUIRED'
        stop_reason='BLOCKED_SCOPE_STATE_UNKNOWN'
        send_attempts_consumed=initial_consumed+sum(outcome in ('APPLIED_VERIFIED','OUTCOME_UNKNOWN') for outcome in outcomes)
        remaining_unattempted_cap=outcomes.count('NOT_ATTEMPTED_CAP')
    if state_recovery_required:
        batch_state='RECOVERY_REQUIRED'
        stop_reason='BLOCKED_SCOPE_STATE_UNKNOWN'
    return {'authentication_state':'SYNTHETIC_TEST_ONLY','execution_allowed':False,
            'batch_state':batch_state,'stop_reason':stop_reason,
            'send_attempts_consumed':send_attempts_consumed,
            'max_send_attempts':cap,'remaining_unattempted_cap':remaining_unattempted_cap,
            'outcomes':outcomes,
            'writes_complete':batch_state=='COMPLETED' and len(outcomes)==len(approved_rows) and all(o=='APPLIED_VERIFIED' for o in outcomes)}


def validate_fixture_scope(batch:VerifiedBatchApproval,runtime:BatchOfflineRuntime)->None:
    """Match signed approved rows to synthetic Scope and side-effect evidence."""
    plan=json.loads(batch.plan_bytes)
    now=datetime.now(timezone.utc)
    for row in batch.approved_rows:
        scope_id=row.get('writer_control_scope_id')
        scope_evidence=runtime.evidence_by_scope.get(scope_id)
        if scope_evidence is None:
            raise LedgerBlocked('Fixture Scope is not present')
        scope=scope_evidence.scope
        arn=row.get('resource_arn')
        if (scope.writer_control_scope_id!=scope_id
                or scope.account!=plan.get('account')
                or scope.partition!=plan.get('partition')
                or scope.region!=row.get('region')
                or arn not in scope.controlled_arns
                or scope.responsible_owner!=batch.owner_principal_id
                or re.fullmatch(r'[0-9a-f]{64}',scope.writer_evidence_digest) is None
                or not scope.not_before_utc<=now<=scope.not_after_utc):
            raise LedgerBlocked('Fixture Scope does not match signed row')
        effects=[effect for effect in scope_evidence.side_effects if effect.target_arn==arn]
        if (len(effects)!=1
                or effects[0].iam_abac_resource_tag_assessment!='PASS'
                or effects[0].iac_assessment!='PASS'
                or effects[0].event_automation_assessment!='PASS'
                or not effects[0].evidence_references
                or any(not reference for reference in effects[0].evidence_references)
                or not effects[0].not_before_utc<=now<=effects[0].not_after_utc):
            raise LedgerBlocked('Fixture side-effect evidence is not valid for signed row')


def simulate_on_fixture_ledger(
    batch_id:str,
    nonce:str,
    approved_rows:Sequence[Mapping[str,str|bool|None]],
    *,
    ledger_path:Path,
    adapter:FakeBatchSDKAdapter|InMemoryNameAdapter,
    cap:int,
)->FixtureSimulationResult:
    """Create a fresh fixture Ledger; refuse to open any existing database."""
    with closing(OfflineFixtureBatchLedger.create_fixture(ledger_path)) as ledger:
        return simulate_untrusted_fixture(
            batch_id,nonce,approved_rows,ledger=ledger,adapter=adapter,cap=cap)


def _validate_fixture_approval(row):
    required=('resource_arn','writer_control_scope_id','name_state','name_key_present',
              'name_raw_value','approved_name','proposed_name','approved','status',
              'confidence','kind','aws_operation','evidence')
    if any(key not in row for key in required):
        raise LedgerBlocked('Incomplete fixture approval')
    if (row['approved']!='YES' or row['status']!='proposed'
            or row['confidence'] not in ('high','medium')
            or row['kind']!='volume' or row['aws_operation']!='ec2:CreateTags'):
        raise LedgerBlocked('Fixture row is not eligible for Name assignment')
    raw=row['name_raw_value']
    state=row['name_state']
    present=row['name_key_present']
    if not ((state=='ABSENT' and present is False and raw is None)
            or (state=='EMPTY' and present is True and raw=='')
            or (state=='WHITESPACE_ONLY' and present is True
                and isinstance(raw,str) and raw!='' and raw.strip()=='')):
        raise LedgerBlocked('Fixture Name state is not eligible for assignment')
    name=row['approved_name']
    if (not isinstance(name,str) or not name or name!=name.strip()
            or len(name)>256 or any(ord(char)<32 or ord(char)==127 for char in name)
            or name!=row['proposed_name']):
        raise LedgerBlocked('Fixture approval cannot replace the generated Name')
    if any(not isinstance(row[key],str) or not row[key] for key in ('resource_arn','writer_control_scope_id','evidence')):
        raise LedgerBlocked('Fixture identity/evidence is incomplete')


def _execute_fixture_row(batch_id,index,row,ledger,adapter):
    scope=row['writer_control_scope_id']
    arn=row['resource_arn']
    authority=f'test-fixture:{batch_id}:{index}'
    attempt_consumed=False
    try:
        observation=classify_batch_name(adapter.read_current(arn))
        if observation.state=='UNKNOWN':
            ledger.stop(batch_id,'BLOCKED_NAME_UNKNOWN')
            return 'NOT_ATTEMPTED_BATCH_STOP',True
        changed=(observation.state!=row['name_state'] or observation.name_raw_value!=row['name_raw_value'])
        if changed:
            ledger.presend_skip(batch_id,index,scope,authority,'SKIPPED_NAME_CHANGED')
            return 'SKIPPED_NAME_CHANGED',False
        ledger.admit(batch_id,index,scope,authority)
        ledger.consume(batch_id,index)  # durable BEFORE any write callback
        attempt_consumed=True
        outcome=_write_and_readback(arn,row['approved_name'],adapter)
        ledger.readback(batch_id,index,outcome)
        return outcome,outcome=='OUTCOME_UNKNOWN'
    except (LedgerBlocked,OSError,sqlite3.Error):
        if attempt_consumed:
            try:
                ledger.outcome_unknown_after_readback_failure(batch_id,index)
            except sqlite3.Error:
                # Keep the consumed intent as a restart-recovery barrier; never resend.
                return 'OUTCOME_UNKNOWN',True
            return 'OUTCOME_UNKNOWN',True
        try:
            if ledger.state(batch_id)=='ACTIVE':
                ledger.stop(batch_id,'BLOCKED_SCOPE_STATE_UNKNOWN')
        except (LedgerBlocked,sqlite3.Error):
            raise
        return 'NOT_ATTEMPTED_BATCH_STOP',True


def _write_and_readback(arn,name,adapter):
    try:
        adapter.write_once(arn,name)
        observation=classify_batch_name(adapter.readback(arn))
    except OSError:
        return 'OUTCOME_UNKNOWN'
    return 'APPLIED_VERIFIED' if observation.name_raw_value==name else 'OUTCOME_UNKNOWN'


def _finish_fixture_batch(batch_id,approved_rows,outcomes,ledger):
    if 'OUTCOME_UNKNOWN' in outcomes:return
    try:
        if ledger.state(batch_id)!='ACTIVE':return
    except (LedgerBlocked,sqlite3.Error):
        return
    if len(outcomes)==len(approved_rows):
        try:
            ledger.complete(batch_id)
        except (LedgerBlocked,sqlite3.Error):
            return


def execute_batch_offline(
    batch: VerifiedBatchApproval,
    *,
    plan_bytes: bytes,
    csv_bytes: bytes,
    ledger: IntentLedger,
    runtime: BatchOfflineRuntime,
) -> BatchRunResult:
    return _execute_batch_offline(
        batch,plan_bytes=plan_bytes,csv_bytes=csv_bytes,ledger=ledger,runtime=runtime
    )
