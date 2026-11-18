"""Structural Batch draft validation: NEVER grants an execution authority."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal
import io, csv, json, re, hashlib

CSV_COLUMNS=('approved','proposal_id','kind','locator','region','effective_usage_cost_usd','status','name_state','name_key_present','name_raw_value','existing_name','confidence','proposed_name','evidence')
_NAME_STATES=('ABSENT','EMPTY','WHITESPACE_ONLY','NONEMPTY','UNKNOWN')

class BatchValidationError(ValueError):pass

@dataclass(frozen=True)
class NameObservation:
    state: Literal['ABSENT','EMPTY','WHITESPACE_ONLY','NONEMPTY','UNKNOWN']
    name_key_present: bool | None
    name_raw_value: str | None

@dataclass(frozen=True)
class BatchDraft:
    plan_bytes:bytes
    csv_bytes:bytes
    approved_rows:tuple[dict,...]
    rows:tuple[dict,...]
    plan:dict
    authentication_state:str='UNSIGNED_PREVIEW'
    execution_allowed:bool=False


def classify_batch_name(tags:object)->NameObservation:
    if tags is None:return NameObservation('UNKNOWN',None,None)
    if isinstance(tags,list):
        tags=_mapping_from_tag_list(tags)
        if tags is None:return NameObservation('UNKNOWN',None,None)
    if not isinstance(tags,dict) or any(not isinstance(k,str) or not isinstance(v,str) for k,v in tags.items()):
        return NameObservation('UNKNOWN',None,None)
    return _classify_name_mapping(tags)


def _mapping_from_tag_list(items):
    tags={}
    for item in items:
        if not isinstance(item,dict) or set(item)!={'Key','Value'} or not isinstance(item['Key'],str) or not isinstance(item['Value'],str) or item['Key'] in tags:
            return None
        tags[item['Key']]=item['Value']
    return tags


def _classify_name_mapping(tags):
    if any(k.casefold()=='name' and k!='Name' for k in tags):
        return NameObservation('UNKNOWN',None,None)
    if 'Name' not in tags:return NameObservation('ABSENT',False,None)
    raw=tags['Name']
    if raw=='':return NameObservation('EMPTY',True,raw)
    if raw.strip()=='':return NameObservation('WHITESPACE_ONLY',True,raw)
    return NameObservation('NONEMPTY',True,raw)


def batch_name_state(tags:object)->str:return classify_batch_name(tags).state


def _parse_plan(data:bytes)->dict:
    try:
        if type(data) is not bytes: raise ValueError('not bytes')
        p=json.loads(data.decode('utf-8'),object_pairs_hook=_unique_object)
        _validate_plan_structure(p)
        return p
    except (KeyError,TypeError,ValueError) as e:raise BatchValidationError('Invalid Batch Plan: '+str(e)) from e


def _validate_plan_structure(plan):
    if type(plan) is not dict or type(plan.get('schema_version')) is not int or plan['schema_version']!=3:raise ValueError('not Batch Plan v3')
    if type(plan.get('records')) is not list or type(plan.get('count')) is not int or len(plan['records'])!=plan['count']:raise ValueError('bad records')
    limits=plan['execution_limits']
    if type(limits) is not dict or set(limits)!={'max_send_attempts'} or type(limits['max_send_attempts']) is not int or not 1<=limits['max_send_attempts']<=20:raise ValueError('bad cap')
    _validate_scope_declarations(plan.get('scope_declarations'))
    from name_tag_batch_population import validate_signed_population
    validate_signed_population(plan)


def _validate_scope_declarations(scopes):
    if type(scopes) is not list or not scopes:raise ValueError('missing scopes')
    ids=[]
    members=set()
    for scope in scopes:
        if type(scope) is not dict or set(scope)!={'writer_control_scope_id','account','partition','region','resource_arns'}:raise ValueError('bad scope')
        scope_id=scope['writer_control_scope_id']
        resources=scope['resource_arns']
        if not isinstance(scope_id,str) or not scope_id or not re.fullmatch(r'\d{12}',scope['account']) or scope['partition'] not in ('aws','aws-cn','aws-us-gov') or not isinstance(scope['region'],str) or not scope['region']:raise ValueError('bad scope identity')
        if type(resources) is not list or not resources or resources!=sorted(set(resources)) or any(not isinstance(resource,str) or not resource.startswith('arn:') for resource in resources):raise ValueError('bad scope resources')
        ids.append(scope_id)
        _add_scope_members(members,scope,resources)
    if ids!=sorted(set(ids)):raise ValueError('unsorted/duplicate scopes')


def _add_scope_members(members,scope,resources):
    for arn in resources:
        identity=(scope['account'],scope['partition'],scope['region'],arn)
        if identity in members:raise ValueError('overlapping scopes')
        members.add(identity)


def _unique_object(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise ValueError('Duplicate JSON key')
        result[k]=v
    return result


def _csv_value(r,field):
    v=r.get(field)
    if field=='name_key_present':
        if v is True:return 'true'
        if v is False:return 'false'
        return ''
    return '' if v is None else str(v)


def build_batch_review_projection(plan_bytes:bytes)->bytes:
    p=_parse_plan(plan_bytes)
    output=io.StringIO(newline='')
    writer=csv.writer(output,lineterminator='\r\n',quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for r in p['records']:
        if type(r) is not dict:raise BatchValidationError('Invalid record')
        writer.writerow(['' if k=='approved' else _csv_value(r,k) for k in CSV_COLUMNS])
    return b'\xef\xbb\xbf'+output.getvalue().encode('utf-8')


def _read_review_csv(csv_bytes:bytes)->list[list[str]]:
    if type(csv_bytes) is not bytes or not csv_bytes.startswith(b'\xef\xbb\xbf') or csv_bytes.startswith(b'\xef\xbb\xbf\xef\xbb\xbf'):
        raise BatchValidationError('Expected exactly one UTF-8 BOM')
    try:
        body=csv_bytes[3:].decode('utf-8')
        reader=csv.reader(io.StringIO(body,newline=''),strict=True)
        rows=list(reader)
    except (UnicodeDecodeError,csv.Error) as e:raise BatchValidationError('Invalid CSV') from e
    if not rows or tuple(rows[0])!=CSV_COLUMNS or any(len(row)!=len(CSV_COLUMNS) for row in rows):raise BatchValidationError('CSV header or width mismatch')
    return rows[1:]


def derive_declared_row_scope(plan:dict,row:dict)->str:
    arn=row.get('resource_arn','')
    account=plan.get('account');partition=plan.get('partition');region=row.get('region')
    if type(arn) is not str or type(region) is not str:raise BatchValidationError('Bad ARN')
    parts=arn.split(':',5)
    if len(parts)!=6 or parts[:2]!=['arn',partition] or parts[3]!=region or parts[4]!=account:
        raise BatchValidationError('ARN/account/partition/region mismatch')
    if row.get('kind')=='volume' and (parts[2]!='ec2' or not re.fullmatch(r'volume/vol-[A-Za-z0-9]+',parts[5])):
        raise BatchValidationError('Malformed volume ARN')
    entries=[s for s in plan['scope_declarations'] if s['account']==account and s['partition']==partition and s['region']==region and arn in s['resource_arns']]
    if len(entries)!=1:raise BatchValidationError('No unique Scope declaration')
    return entries[0]['writer_control_scope_id']


def validate_approved_batch_row(p,r,approved:str):
    if approved!='YES':raise BatchValidationError('Not approved')
    if r.get('status')!='proposed' or r.get('confidence') not in ('high','medium'):
        raise BatchValidationError('Only proposed high/medium rows may be approved')
    state=r.get('name_state');presence=r.get('name_key_present');raw=r.get('name_raw_value')
    valid=(state=='ABSENT' and presence is False and raw is None) or (state=='EMPTY' and presence is True and raw=='') or (state=='WHITESPACE_ONLY' and presence is True and isinstance(raw,str) and raw!='' and raw.strip()=='')
    if not valid:raise BatchValidationError('Name cannot be overwritten')
    name=r.get('proposed_name')
    if not isinstance(name,str) or not name or name!=name.strip() or any(ord(c)<32 or ord(c)==127 for c in name):raise BatchValidationError('Invalid proposed Name')
    if not isinstance(r.get('proposal_id'),str) or not r['proposal_id'] or not isinstance(r.get('evidence'),str) or not r['evidence']:
        raise BatchValidationError('No proposal/evidence')
    if r.get('kind')!='volume' or r.get('aws_operation')!='ec2:CreateTags':
        raise BatchValidationError('Kind/API is not proven eligible')
    scope=derive_declared_row_scope(p,r)
    return {**r,'approved':'YES','approved_name':name,'writer_control_scope_id':scope}


def validate_batch_csv(plan_bytes:bytes,csv_bytes:bytes)->tuple[dict,...]:
    p=_parse_plan(plan_bytes);parsed=_read_review_csv(csv_bytes)
    if len(parsed)!=len(p['records']):raise BatchValidationError('CSV row count mismatch')
    ids=set();target=set();result=[]
    for record,cells in zip(p['records'],parsed,strict=True):
        c=dict(zip(CSV_COLUMNS,cells,strict=True))
        if c['approved'] not in ('','YES','NO'):raise BatchValidationError('Invalid approved cell')
        if any(c[f]!=_csv_value(record,f) for f in CSV_COLUMNS if f!='approved'):
            raise BatchValidationError('Non-approval CSV cell changed')
        proposal=record.get('proposal_id');identity=(record.get('resource_arn'),record.get('aws_operation'))
        if not proposal or proposal in ids or identity in target:raise BatchValidationError('Duplicate/missing proposal or target')
        ids.add(proposal);target.add(identity)
        result.append(validate_approved_batch_row(p,record,c['approved']) if c['approved']=='YES' else {**record,'approved':c['approved']})
    return tuple(result)


def validate_batch_draft(plan_bytes:bytes,csv_bytes:bytes)->BatchDraft:
    rows=validate_batch_csv(plan_bytes,csv_bytes)
    return BatchDraft(bytes(plan_bytes),bytes(csv_bytes),tuple(r for r in rows if r['approved']=='YES'),rows,_parse_plan(plan_bytes))
