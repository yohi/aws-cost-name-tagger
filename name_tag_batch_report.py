"""Offline no-send preview and fail-closed authenticated report entry."""
from __future__ import annotations
from decimal import Decimal,InvalidOperation
from hashlib import sha256
from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Final
from name_tag_batch_state import validate_batch_draft, BatchValidationError
from name_tag_batch_state import derive_declared_row_scope
from name_tag_batch_approval import VerifiedBatchApproval, revalidate_verified_batch, BatchAuthRejected
from name_tag_batch_outcomes import BatchOutcomeError,kind_outcome_partition,reconcile_batch_outcomes
from name_tag_kind_capabilities import (
    CNP_REASON_CODES, REGISTRY_KINDS, REGISTRY_VERSION, STATUSES, KindCapabilityDecision,
    resolve_kind_capability)

class ReportBlocked(ValueError):pass

_WRITE_OPERATIONS:Final=MappingProxyType({'volume':'ec2:CreateTags'})

COVERAGE_SCHEMA:Final='kind-capability-coverage/1'
PRECAP_FROM_SIGNED_PLAN:Final='SIGNED_PLAN_CUR_POPULATION_BY_KIND'
PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE:Final='PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE'
LIVE_ACCEPTANCE_NOT_RUN:Final='NOT_RUN'
# Mirrors name_tag_batch_live._LIVE_DISPATCH_BLOCKED (parity asserted in tests); kept local so
# the no-send preview never imports the Ledger/live modules.
_LIVE_NOT_DISPATCHABLE:Final=MappingProxyType({'s3_bucket':'TAG_SET_REPLACEMENT_NOT_PROVEN'})
# Outcomes that only an approved (signed, validated) proven-Kind row can carry.
_APPROVED_ROW_OUTCOMES:Final=frozenset({
    'NOT_ATTEMPTED_UNSIGNED_PREVIEW','NOT_ATTEMPTED_OWNER_VERIFIED','NOT_ATTEMPTED_CAP',
    'NOT_ATTEMPTED_BATCH_STOP','SKIPPED_NAME_CHANGED','APPLIED_VERIFIED','OUTCOME_UNKNOWN',
    'UNRESOLVED_WRITE_INTENT',
})
_REPORTED_OUTCOMES:Final=_APPROVED_ROW_OUTCOMES|frozenset({
    'UNAPPROVED','ALREADY_NAMED','WRITE_UNSUPPORTED','WRITE_OPERATION_UNRESOLVED',
    'SCOPE_NOT_APPLIED','NAME_GENERATION_UNAVAILABLE','NAME_STATE_UNKNOWN',
    'METADATA_READ_FAILED','MANUAL_REVIEW',
})


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


def _validated_reason_details(plan,population):
    from name_tag_batch_population import validate_reason_details
    details=plan.get('cur_population_reason_details',{})
    if 'cur_population_reason_details' not in plan:
        return details
    try:return validate_reason_details(details,population)
    except ValueError as error:raise ReportBlocked(str(error)) from error


def production_kind_decisions()->Mapping[str,KindCapabilityDecision]:
    """The trusted Registry decisions, in stable Registry order."""
    return MappingProxyType({kind:resolve_kind_capability(kind) for kind in REGISTRY_KINDS})


def _row_capability(row):
    kind=row.get('kind')
    if kind not in REGISTRY_KINDS:
        return None,None
    decision=resolve_kind_capability(kind)
    return decision.status,decision.reason_code


def _validated_decisions(decisions):
    if not isinstance(decisions,Mapping) or set(decisions)!=set(REGISTRY_KINDS):
        raise ReportBlocked('Kind decisions must cover exactly the 18 Registry Kinds')
    for kind in REGISTRY_KINDS:
        decision=decisions[kind]
        if (type(decision) is not KindCapabilityDecision or decision.kind!=kind
                or decision.status not in STATUSES or decision.version!=REGISTRY_VERSION
                or type(decision.reason_code) is not str or not decision.reason_code):
            raise ReportBlocked('Malformed Kind capability decision')
        if decision.status=='CAPABILITY_NOT_PROVEN' and decision.reason_code not in CNP_REASON_CODES:
            raise ReportBlocked('Ungrounded CAPABILITY_NOT_PROVEN reason')
        if decision.status in ('IMPLEMENTED_OFFLINE','LIVE_GATE_PENDING') and not decision.evidence_refs:
            raise ReportBlocked('Kind capability claims lack evidence')
    return decisions


def _validated_row_outcomes(row_outcomes,count):
    if (not isinstance(row_outcomes,Mapping) or any(type(i) is not int for i in row_outcomes)
            or set(row_outcomes)!=set(range(count))
            or any(row_outcomes[i] not in _REPORTED_OUTCOMES for i in range(count))):
        raise ReportBlocked('Row outcomes must name one known outcome for every signed row')
    return row_outcomes


def _offline_dispatch(decision):
    if decision.status!='IMPLEMENTED_OFFLINE':
        reason=decision.reason_code
    elif decision.tag_set_replacement:
        reason='UNSUPPORTED_BY_POLICY'
    else:
        from name_tag_kind_adapters import _PROMOTION_BLOCKS
        reason=_PROMOTION_BLOCKS.get(decision.kind) or _LIVE_NOT_DISPATCHABLE.get(decision.kind)
    return {'dispatchable':reason is None,'block_reason':reason}


def _checked_signed_rows(records,decisions,outcomes):
    """Reject forged signed content; never downgrade it to an unsupported/unapproved skip."""
    from name_tag_batch_population import exact_add as _exact_add
    selected={kind:[] for kind in REGISTRY_KINDS}
    rows=[]
    for index,record in enumerate(records):
        kind=record.get('kind') if type(record) is dict else None
        if kind not in REGISTRY_KINDS:
            raise ReportBlocked('Signed row Kind is not a Registry Kind')
        decision=decisions[kind]
        operation=record.get('aws_operation')
        if operation is not None and (operation!=decision.write_operation
                                      or decision.status!='IMPLEMENTED_OFFLINE'):
            raise ReportBlocked('Signed row operation is not a proven Kind write')
        if outcomes[index] in _APPROVED_ROW_OUTCOMES and (operation is None or record.get('status')!='proposed'):
            raise ReportBlocked('Attempt outcome claimed for an unsignable row')
        cost=_cost(record.get('effective_usage_cost_usd'))
        selected[kind].append(cost)
        rows.append({'kind':kind,'outcome':outcomes[index],
                     'effective_usage_cost_usd':record['effective_usage_cost_usd']})
    return {kind:{'count':len(costs),'cost_usd':_canonical(_exact_add(costs))}
            for kind,costs in selected.items()},rows


def _canonical(value):
    from name_tag_batch_population import _canonical_decimal
    return _canonical_decimal(value)


def report_kind_capability_coverage(
    plan:Mapping[str,object],
    decisions:Mapping[str,KindCapabilityDecision],
    row_outcomes:Mapping[int,str],
)->dict[str,object]:
    """18-Kind coverage: signed pre-cap source, capability axis and outcome axis kept apart.

    Kind pre-cap totals come ONLY from the signed Plan v3 ``cur_population_by_kind``; a
    historical Plan without it reports PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE (never zeros).
    Selected records/row outcomes add post-selection detail only. Live acceptance is NOT_RUN.
    """
    from name_tag_batch_population import KIND_PRECAP_STAGES,validate_signed_population
    if type(plan) is not dict:
        raise ReportBlocked('Plan must be a decoded Batch Plan object')
    try:
        population=validate_signed_population(plan)  # includes the Task 2 Kind pre-cap validator
    except (KeyError,TypeError,ValueError) as error:
        raise ReportBlocked(str(error)) from error
    checked=_validated_decisions(decisions)
    outcomes=_validated_row_outcomes(row_outcomes,len(plan['records']))
    selected,rows=_checked_signed_rows(plan['records'],checked,outcomes)
    partition=kind_outcome_partition(rows)
    breakdown=plan['cur_population_by_kind']['kinds'] if 'cur_population_by_kind' in plan else None
    status=PRECAP_FROM_SIGNED_PLAN if breakdown is not None else PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE
    kinds={}
    for kind in REGISTRY_KINDS:
        precap=None
        if breakdown is not None:
            precap={stage:dict(breakdown[kind][stage]) for stage in KIND_PRECAP_STAGES}
            if (precap['lookup_selected']['count']!=selected[kind]['count']
                    or _cost(precap['lookup_selected']['cost_usd'])!=_cost(selected[kind]['cost_usd'])):
                raise ReportBlocked('Signed selected rows contradict the Kind pre-cap breakdown')
        decision=checked[kind]
        kinds[kind]={
            'capability':{'status':decision.status,'reason_code':decision.reason_code,
                          'registry_version':decision.version},
            'offline_dispatch':_offline_dispatch(decision),
            'live_acceptance':LIVE_ACCEPTANCE_NOT_RUN,
            'precap_status':status,'precap':precap,
            'selected':selected[kind],
            'outcomes':partition.get(kind,{}),
        }
    return {
        'schema':COVERAGE_SCHEMA,'precap_status':status,
        'live_acceptance':LIVE_ACCEPTANCE_NOT_RUN,
        'precap_total':{stage:dict(population[stage]) for stage in KIND_PRECAP_STAGES},
        'selected_total':dict(population['lookup_selected']),
        'kinds':kinds,
    }


def _write_support(row):
    kind=row.get('kind')
    operation=_WRITE_OPERATIONS.get(kind)
    if operation is None and kind in REGISTRY_KINDS:
        decision=resolve_kind_capability(kind)
        if decision.status=='IMPLEMENTED_OFFLINE':  # vetted Registry Kind, not a name guess
            operation=decision.write_operation
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
    capability_status,capability_reason=_row_capability(row)
    report_row={
        'row_index':row_index,'proposal_id':row.get('proposal_id'),
        'kind':row.get('kind'),'locator':row.get('locator'),'region':row.get('region'),
        'resource_arn':arn,'writer_control_scope_id':scope_id,
        'aws_operation':row.get('aws_operation'),'name_state':row.get('name_state'),
        'name_key_present':row.get('name_key_present'),'name_raw_value':row.get('name_raw_value'),
        'existing_name':row.get('existing_name'),'proposed_name':row.get('proposed_name'),
        'name_generation_state':name_generation_state,'write_support':write_support,
        'scope_application':scope_application,'host_scope_verified':False,'approved':row.get('approved'),
        'capability_status':capability_status,'capability_reason_code':capability_reason,
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
    reason_details=_validated_reason_details(draft.plan,c)
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
    report=reconcile_batch_outcomes(report)
    report['kind_capability_coverage']=report_kind_capability_coverage(
        draft.plan,production_kind_decisions(),
        {index:row['outcome'] for index,row in enumerate(report['rows'])})
    return report


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
