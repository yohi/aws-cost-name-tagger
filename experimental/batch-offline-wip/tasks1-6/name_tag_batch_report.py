"""Offline no-send preview and fail-closed authenticated report entry."""
from __future__ import annotations
from decimal import Decimal,InvalidOperation
from hashlib import sha256
from datetime import datetime
from name_tag_batch_state import validate_batch_draft, BatchValidationError
from name_tag_batch_approval import VerifiedBatchApproval, revalidate_verified_batch, BatchAuthRejected

class ReportBlocked(ValueError):pass


def _sum_exact(a,b):
    # Decimal operands should be small canonical sums. For arbitrary scale use exact_add.
    from name_tag_batch_population import exact_add
    return exact_add([a,b])


def validated_cur_population(p):
    c=p.get('cur_population')
    required={'schema_version','accounting_complete','cur_recognized','below_min_cost','above_min_cost','lookup_selected','max_resources_not_inspected','unattributable_cur','outside_requested_kinds','unsupported_kind'}
    if type(c) is not dict or set(c)!=required or type(c.get('schema_version')) is not int or c['schema_version']!=2 or type(c['accounting_complete']) is not bool:
        raise ReportBlocked('Wrong CUR population schema')
    recognised=('cur_recognized','below_min_cost','above_min_cost','lookup_selected','max_resources_not_inspected')
    lines=('unattributable_cur','outside_requested_kinds','unsupported_kind')
    _validate_resource_population(c,recognised)
    _validate_billing_population(c,lines)
    if not _population_totals_match(c):
        raise ReportBlocked('CUR exact cost or count mismatch')
    if type(p.get('count')) is not int or p['count']!=len(p.get('records',[])) or p['count']!=c['lookup_selected']['count']:
        raise ReportBlocked('Selected Plan records mismatch')
    return c


def _validate_resource_population(population,names):
    for name in names:
        row=population[name]
        if type(row) is not dict or set(row)!={'count','cost_usd'} or type(row['count']) is not int or row['count']<0:
            raise ReportBlocked('Malformed resource population')
        _cost(row['cost_usd'])


def _validate_billing_population(population,names):
    for name in names:
        row=population[name]
        if type(row) is not dict or set(row)!={'known','billing_rows','cost_usd'} or type(row['known']) is not bool:
            raise ReportBlocked('Malformed billing population')
        _validate_billing_row(row)


def _validate_billing_row(row):
    if row['known']:
        if type(row['billing_rows']) is not int or row['billing_rows']<0:raise ReportBlocked('Bad billing row count')
        _cost(row['cost_usd'])
    elif row['billing_rows'] is not None or row['cost_usd'] is not None:
        raise ReportBlocked('Unknown must use null')


def _resource_totals_match(population,total,first,second):
    return (population[total]['count']==population[first]['count']+population[second]['count']
            and _cost(population[total]['cost_usd'])==_sum_exact(_cost(population[first]['cost_usd']),_cost(population[second]['cost_usd'])))


def _population_totals_match(population):
    return (_resource_totals_match(population,'cur_recognized','below_min_cost','above_min_cost')
            and _resource_totals_match(population,'above_min_cost','lookup_selected','max_resources_not_inspected'))


def _cost(s):
    if not isinstance(s,str):raise ReportBlocked('Cost must be string')
    try:x=Decimal(s)
    except InvalidOperation as e:raise ReportBlocked('Bad decimal') from e
    if not x.is_finite() or 'E' in s.upper() or ('.' in s and s.endswith('0')) or s in ('-0','+0'):
        raise ReportBlocked('Not canonical decimal')
    return x


def _report(draft,authentication_state):
    c=validated_cur_population(draft.plan)
    coverage=bool(c['accounting_complete'] and c['max_resources_not_inspected']['count']==0 and all(c[k]['known'] for k in ('unattributable_cur','outside_requested_kinds','unsupported_kind')))
    return {'authentication_state':authentication_state,
            'execution_allowed':False,
            'plan_sha256':sha256(draft.plan_bytes).hexdigest(),
            'csv_sha256':sha256(draft.csv_bytes).hexdigest(),
            'max_send_attempts':draft.plan['execution_limits']['max_send_attempts'],
            'approved_count':len(draft.approved_rows),
            'coverage_complete':coverage,'writes_complete':False,
            'cur_population':c}


def build_batch_dry_run(plan_bytes:bytes,csv_bytes:bytes):
    # Unsigned preview: no ledger, trust, STS, credentials or SDK imports.
    try:return _report(validate_batch_draft(plan_bytes,csv_bytes),'UNSIGNED_PREVIEW')
    except (BatchValidationError,ReportBlocked) as e:raise ReportBlocked(str(e)) from e


def make_authenticated_batch_report(batch:VerifiedBatchApproval,*,plan_bytes:bytes,csv_bytes:bytes,trust=None,now_utc:datetime|None=None):
    if type(batch) is not VerifiedBatchApproval or plan_bytes!=batch.plan_bytes or csv_bytes!=batch.csv_bytes:
        raise ReportBlocked('Foreign Plan/CSV bytes')
    if batch.payload.get('plan_sha256')!=sha256(plan_bytes).hexdigest() or batch.payload.get('csv_sha256')!=sha256(csv_bytes).hexdigest():
        raise ReportBlocked('Signed digest mismatch')
    if trust is None or now_utc is None:raise ReportBlocked('Fresh protected OwnerTrust required')
    try:revalidate_verified_batch(batch,trust=trust,now_utc=now_utc)
    except BatchAuthRejected as e:raise ReportBlocked('Fresh signature/Trust not verified') from e
    try:return _report(validate_batch_draft(plan_bytes,csv_bytes),'OWNER_VERIFIED_NOT_WRITE_AUTHORIZED')
    except BatchValidationError as e:raise ReportBlocked(str(e)) from e
