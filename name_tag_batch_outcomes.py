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
        outcome=row.get('outcome')
        if outcome in _DURABLE_OUTCOMES:
            category=outcome
        elif outcome=='SKIPPED_IAM_UNSUPPORTED':
            category='WRITE_UNSUPPORTED'
        elif (row.get('approved')=='YES'
              and report.get('authentication_state')=='UNSIGNED_PREVIEW'):
            category='NOT_ATTEMPTED_UNSIGNED_PREVIEW'
        elif row.get('status')=='already_named':
            category='ALREADY_NAMED'
        elif row.get('status')=='proposed' and row.get('write_support')=='UNSUPPORTED_API':
            category='WRITE_UNSUPPORTED'
        elif row.get('status')=='proposed' and row.get('write_support')=='OPERATION_UNRESOLVED':
            category='WRITE_OPERATION_UNRESOLVED'
        elif row.get('status')=='proposed' and row.get('scope_application')!='APPLIED':
            category='SCOPE_NOT_APPLIED'
        elif row.get('name_generation_state')=='UNAVAILABLE':
            category='NAME_GENERATION_UNAVAILABLE'
        elif row.get('name_state')=='UNKNOWN':
            category='NAME_STATE_UNKNOWN'
        elif row.get('status')=='api_error':
            category='METADATA_READ_FAILED'
        elif row.get('approved')=='YES':
            category=('NOT_ATTEMPTED_UNSIGNED_PREVIEW'
                      if report.get('authentication_state')=='UNSIGNED_PREVIEW'
                      else 'NOT_ATTEMPTED_OWNER_VERIFIED')
        elif row.get('status')=='manual_review':
            category='MANUAL_REVIEW'
        else:
            category='UNAPPROVED'
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
