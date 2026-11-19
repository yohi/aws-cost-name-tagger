"""Reconcile one terminal outcome and exact cost for every signed Plan row."""
from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal,InvalidOperation
from typing import TypedDict

from name_tag_batch_population import _canonical_decimal,exact_add


class BatchOutcomeError(ValueError):
    """The row outcomes or their selected CUR totals are inconsistent."""


class BatchOutcomeRow(TypedDict,total=False):
    row_index:int
    approved:str|None
    status:str|None
    kind:str|None
    aws_operation:str|None
    write_support:str
    scope_application:str
    name_generation_state:str
    name_state:str|None
    outcome:str
    effective_usage_cost_usd:str


class BatchOutcomeReport(TypedDict,total=False):
    authentication_state:str
    rows:list[BatchOutcomeRow]
    cur_population:dict[str,dict[str,str|int|bool|None]]
    outcome_reconciliation:dict[str,dict[str,str|int]]
    outcome_reconciliation_total:dict[str,str|int]


_DURABLE_OUTCOMES=frozenset({
    'NOT_ATTEMPTED_CAP','NOT_ATTEMPTED_BATCH_STOP','SKIPPED_NAME_CHANGED',
    'APPLIED_VERIFIED','OUTCOME_UNKNOWN',
})


def _cost(value:str)->Decimal:
    try:
        amount=Decimal(value)
    except InvalidOperation as error:
        raise BatchOutcomeError('Invalid row cost') from error
    if not amount.is_finite() or _canonical_decimal(amount)!=value:
        raise BatchOutcomeError('Row cost is not canonical')
    return amount


def _status_outcome(row:BatchOutcomeRow)->str|None:
    if row.get('status')=='already_named':
        return 'ALREADY_NAMED'
    if row.get('status')=='proposed':
        if row.get('write_support')=='UNSUPPORTED_API':
            return 'WRITE_UNSUPPORTED'
        if row.get('write_support')=='OPERATION_UNRESOLVED':
            return 'WRITE_OPERATION_UNRESOLVED'
        if row.get('scope_application')!='APPLIED':
            return 'SCOPE_NOT_APPLIED'
    if row.get('name_generation_state')=='UNAVAILABLE':
        return 'NAME_GENERATION_UNAVAILABLE'
    if row.get('name_state')=='UNKNOWN':
        return 'NAME_STATE_UNKNOWN'
    if row.get('status')=='api_error':
        return 'METADATA_READ_FAILED'
    if row.get('status')=='manual_review':
        return 'MANUAL_REVIEW'
    return None


def _row_outcome(row:BatchOutcomeRow,authentication_state:str)->str:
    outcome=row.get('outcome')
    if outcome in _DURABLE_OUTCOMES:
        return outcome
    if outcome=='SKIPPED_IAM_UNSUPPORTED':
        return 'WRITE_UNSUPPORTED'
    if row.get('approved')=='YES' and authentication_state=='UNSIGNED_PREVIEW':
        return 'NOT_ATTEMPTED_UNSIGNED_PREVIEW'
    status_outcome=_status_outcome(row)
    if status_outcome is not None:
        return status_outcome
    if row.get('approved')=='YES':
        return ('NOT_ATTEMPTED_UNSIGNED_PREVIEW'
                if authentication_state=='UNSIGNED_PREVIEW'
                else 'NOT_ATTEMPTED_OWNER_VERIFIED')
    return 'UNAPPROVED'


def reconcile_batch_outcomes(
    report:BatchOutcomeReport,
    ledger_outcomes:Mapping[int,str]|None=None,
)->BatchOutcomeReport:
    rows=report.get('rows')
    population=report.get('cur_population')
    if type(rows) is not list or type(population) is not dict:
        raise BatchOutcomeError('Outcome report is missing signed rows or CUR population')
    outcomes=ledger_outcomes or {}
    for row_index,outcome in outcomes.items():
        if (type(row_index) is not int or row_index<0 or row_index>=len(rows)
                or outcome not in _DURABLE_OUTCOMES|{'SKIPPED_IAM_UNSUPPORTED'}
                or rows[row_index].get('approved')!='YES'):
            raise BatchOutcomeError('Invalid durable Batch row outcome')
        rows[row_index]['outcome']=outcome

    grouped:dict[str,list[BatchOutcomeRow]]={}
    for row in rows:
        category=_row_outcome(row,report.get('authentication_state',''))
        row['outcome']=category
        grouped.setdefault(category,[]).append(row)

    reconciliation={
        category:{
            'count':len(category_rows),
            'cost_usd':_canonical_decimal(exact_add(
                _cost(row['effective_usage_cost_usd']) for row in category_rows
            )),
        }
        for category,category_rows in sorted(grouped.items())
    }
    count=sum(item['count'] for item in reconciliation.values())
    cost=exact_add(_cost(item['cost_usd']) for item in reconciliation.values())
    selected=population['lookup_selected']
    if count!=len(rows) or cost!=_cost(selected['cost_usd']) or len(rows)!=selected['count']:
        raise BatchOutcomeError('Outcome categories do not reconcile to signed selected CUR costs')
    report['outcome_reconciliation']=reconciliation
    report['outcome_reconciliation_total']={
        'count':count,'cost_usd':_canonical_decimal(cost),
    }
    return report
