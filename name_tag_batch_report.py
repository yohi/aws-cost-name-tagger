"""Offline no-send preview and fail-closed authenticated report entry."""
from __future__ import annotations
from decimal import Decimal,InvalidOperation
from hashlib import sha256
from datetime import datetime
from types import MappingProxyType
from typing import Final
from name_tag_batch_state import validate_batch_draft, BatchValidationError
from name_tag_batch_state import derive_declared_row_scope
from name_tag_batch_approval import VerifiedBatchApproval, revalidate_verified_batch, BatchAuthRejected
from name_tag_batch_outcomes import BatchOutcomeError,reconcile_batch_outcomes

class ReportBlocked(ValueError):pass

_WRITE_OPERATIONS:Final=MappingProxyType({'volume':'ec2:CreateTags'})


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


def _validated_reason_details(plan):
    details=plan.get('cur_population_reason_details',{})
    if type(details) is not dict:
        raise ReportBlocked('Malformed CUR classification reason details')
    for key,value in details.items():
        if (type(key) is not str or ':' not in key or type(value) is not dict
                or set(value)!={'billing_rows','cost_usd'}
                or type(value['billing_rows']) is not int or value['billing_rows']<0):
            raise ReportBlocked('Malformed CUR classification reason detail')
        _cost(value['cost_usd'])
    return details


def _write_support(row):
    operation=_WRITE_OPERATIONS.get(row.get('kind'))
    if operation is None:
        return 'UNSUPPORTED_API'
    if row.get('aws_operation')==operation:
        return 'SUPPORTED_API'
    return 'OPERATION_UNRESOLVED'


def _scope_application(plan,row,arn,write_support):
    if row.get('status')!='proposed':
        return None,'NOT_APPLICABLE'
    if write_support!='SUPPORTED_API' or not isinstance(arn,str) or not arn:
        return None,'NOT_APPLIED'
    try:
        return derive_declared_row_scope(plan,row),'DECLARED_ONLY'
    except BatchValidationError as error:
        if str(error)=='No unique Scope declaration':
            return None,'NOT_APPLIED'
        raise ReportBlocked(str(error)) from error


def _name_generation_state(row):
    proposed_name=row.get('proposed_name')
    evidence=row.get('evidence')
    if isinstance(proposed_name,str) and proposed_name:
        return 'GENERATED'
    if (row.get('status')=='manual_review' and isinstance(evidence,str)
            and 'Candidate lacks a structured Name namespace' in evidence):
        return 'UNAVAILABLE'
    if isinstance(evidence,str) and evidence.startswith('Proposed Name collision in batch:'):
        return 'COLLISION'
    return 'NOT_EVALUATED'


def _report_row(row,row_index,plan):
    arn=row.get('resource_arn')
    write_support=_write_support(row)
    scope_id,scope_application=_scope_application(plan,row,arn,write_support)
    name_generation_state=_name_generation_state(row)
    report_row={
        'row_index':row_index,'proposal_id':row.get('proposal_id'),
        'kind':row.get('kind'),'locator':row.get('locator'),'region':row.get('region'),
        'resource_arn':arn,'writer_control_scope_id':scope_id,
        'aws_operation':row.get('aws_operation'),'name_state':row.get('name_state'),
        'name_key_present':row.get('name_key_present'),'name_raw_value':row.get('name_raw_value'),
        'existing_name':row.get('existing_name'),'proposed_name':row.get('proposed_name'),
        'name_generation_state':name_generation_state,'write_support':write_support,
        'scope_application':scope_application,'host_scope_verified':False,'approved':row.get('approved'),
        'status':row.get('status'),'confidence':row.get('confidence'),
        'effective_usage_cost_usd':row.get('effective_usage_cost_usd'),
        'outcome':'NOT_ATTEMPTED_UNSIGNED_PREVIEW','execution_allowed':False,
    }
    unavailable=None
    if name_generation_state=='UNAVAILABLE':
        unavailable={
            'proposal_id':row.get('proposal_id'),'kind':row.get('kind'),
            'locator':row.get('locator'),'resource_arn':arn,
            'effective_usage_cost_usd':row.get('effective_usage_cost_usd'),
            'reason':row.get('evidence'),
        }
    return report_row,unavailable


def _report(draft,authentication_state):
    c=validated_cur_population(draft.plan)
    reason_details=_validated_reason_details(draft.plan)
    coverage=bool(c['accounting_complete'] and c['max_resources_not_inspected']['count']==0 and all(c[k]['known'] for k in ('unattributable_cur','outside_requested_kinds','unsupported_kind')))
    rows=[]
    name_generation_unavailable=[]
    for row_index,row in enumerate(draft.rows):
        report_row,unavailable=_report_row(row,row_index,draft.plan)
        rows.append(report_row)
        if unavailable is not None:
            name_generation_unavailable.append(unavailable)
    report={'authentication_state':authentication_state,
            'execution_allowed':False,
            'plan_sha256':sha256(draft.plan_bytes).hexdigest(),
            'csv_sha256':sha256(draft.csv_bytes).hexdigest(),
            'max_send_attempts':draft.plan['execution_limits']['max_send_attempts'],
            'approved_count':len(draft.approved_rows),
            'coverage_complete':coverage,'writes_complete':False,'rows':rows,
            'name_generation_unavailable':name_generation_unavailable,
            'cur_population_reason_details':reason_details,
            'cur_population':c}
    return reconcile_batch_outcomes(report)


def build_batch_dry_run(plan_bytes:bytes,csv_bytes:bytes):
    # Unsigned preview: no ledger, trust, STS, credentials or SDK imports.
    try:return _report(validate_batch_draft(plan_bytes,csv_bytes),'UNSIGNED_PREVIEW')
    except (BatchValidationError,ReportBlocked,BatchOutcomeError) as e:raise ReportBlocked(str(e)) from e


def make_authenticated_batch_report(batch:VerifiedBatchApproval,*,plan_bytes:bytes,csv_bytes:bytes,trust=None,now_utc:datetime|None=None):
    if type(batch) is not VerifiedBatchApproval or plan_bytes!=batch.plan_bytes or csv_bytes!=batch.csv_bytes:
        raise ReportBlocked('Foreign Plan/CSV bytes')
    if batch.payload.get('plan_sha256')!=sha256(plan_bytes).hexdigest() or batch.payload.get('csv_sha256')!=sha256(csv_bytes).hexdigest():
        raise ReportBlocked('Signed digest mismatch')
    if trust is None or now_utc is None:raise ReportBlocked('Fresh protected OwnerTrust required')
    try:revalidate_verified_batch(batch,trust=trust,now_utc=now_utc)
    except BatchAuthRejected as e:raise ReportBlocked('Fresh signature/Trust not verified') from e
    try:return _report(validate_batch_draft(plan_bytes,csv_bytes),'OWNER_VERIFIED')
    except (BatchValidationError,BatchOutcomeError) as e:raise ReportBlocked(str(e)) from e
