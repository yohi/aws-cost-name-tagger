"""Pure synthetic Batch execution for offline fixtures; never imports/calls boto3.

Do not wire this simulator to production authority, real Ledger or AWS clients.
An authenticated production executor is NOT supplied by this module.
"""
from __future__ import annotations
from dataclasses import dataclass
from name_tag_batch_state import classify_batch_name
from name_tag_batch_ledger import OfflineFixtureBatchLedger,LedgerBlocked

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


def simulate_untrusted_fixture(batch_id,nonce,approved_rows,*,ledger:OfflineFixtureBatchLedger,adapter:InMemoryNameAdapter,cap:int):
    """Synthetic test harness. Its output is never Owner/AWS authorization evidence."""
    if type(ledger) is not OfflineFixtureBatchLedger or type(adapter) is not InMemoryNameAdapter:
        raise LedgerBlocked('Fixture-only objects required')
    if not approved_rows or type(cap) is not int or not (1<=cap<=20):raise LedgerBlocked('Invalid fixture inputs')
    scopes=[]
    for row in approved_rows:
        if any(k not in row for k in ('resource_arn','writer_control_scope_id','name_state','name_raw_value','approved_name')):
            raise LedgerBlocked('Incomplete fixture')
        scopes.append(row['writer_control_scope_id'])
    ledger.register(batch_id,nonce,max_send_attempts=cap,row_count=len(approved_rows),scope_ids=scopes)
    outcomes=[]
    for i,row in enumerate(approved_rows):
        if ledger.state(batch_id)!='ACTIVE':break
        if ledger.counter(batch_id)>=cap:
            ledger.classify_cap(batch_id)
            outcomes.extend(['NOT_ATTEMPTED_CAP']*(len(approved_rows)-i))
            break
        scope=row['writer_control_scope_id']
        arn=row['resource_arn']
        authority=f'test-fixture:{batch_id}:{i}'
        try:
            current=adapter.read_current(arn)
            obs=classify_batch_name(current)
            if obs.state=='UNKNOWN':
                ledger.stop(batch_id,'BLOCKED_NAME_UNKNOWN')
                outcomes.append('BLOCKED_NAME_UNKNOWN')
                break
            if obs.state!=row['name_state'] or obs.name_raw_value!=row['name_raw_value']:
                ledger.presend_skip(batch_id,i,scope,authority,'SKIPPED_NAME_CHANGED')
                outcomes.append('SKIPPED_NAME_CHANGED')
                continue
            ledger.admit(batch_id,i,scope,authority)
            ledger.consume(batch_id,i)  # durable BEFORE any write callback
            try:
                adapter.write_once(arn,row['approved_name'])
                actual=classify_batch_name(adapter.readback(arn))
                outcome='APPLIED_VERIFIED' if actual.name_raw_value==row['approved_name'] else 'OUTCOME_UNKNOWN'
            except OSError:
                outcome='OUTCOME_UNKNOWN'
            ledger.readback(batch_id,i,outcome)
            outcomes.append(outcome)
            if outcome=='OUTCOME_UNKNOWN':break
        except (LedgerBlocked,OSError):
            if ledger.state(batch_id)=='ACTIVE':ledger.stop(batch_id,'BLOCKED_SCOPE_STATE_UNKNOWN')
            outcomes.append('BLOCKED_SCOPE_STATE_UNKNOWN')
            break
    if ledger.state(batch_id)=='ACTIVE':
        if ledger.counter(batch_id)>=cap and ledger.dispositions(batch_id)==[] and len(outcomes)<len(approved_rows):
            ledger.classify_cap(batch_id)
        elif len(outcomes)==len(approved_rows):
            ledger.complete(batch_id)
    return {'authentication_state':'SYNTHETIC_TEST_ONLY','execution_allowed':False,
            'batch_state':ledger.state(batch_id),'send_attempts_consumed':ledger.counter(batch_id),
            'outcomes':outcomes,
            'writes_complete':ledger.state(batch_id)=='COMPLETED' and len(outcomes)==len(approved_rows) and all(o=='APPLIED_VERIFIED' for o in outcomes)}


def execute_batch_offline(*_args,**_kwargs):
    """Fail-closed until full repository OwnerTrust/ScopeEvidence/Ledger integration."""
    raise LedgerBlocked('BLOCKED_OWNER_AUTHN: production offline executor not integrated')
