"""Structural Batch draft validation: NEVER grants an execution authority."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Literal
import io, csv, json, re, hashlib
import name_tag_kind_capabilities as _caps

CSV_COLUMNS=('approved','proposal_id','kind','locator','region','effective_usage_cost_usd','status','name_state','name_key_present','name_raw_value','existing_name','confidence','proposed_name','evidence')
VOLUME_ID_PATTERN=r'vol-(?:[0-9a-f]{8}|[0-9a-f]{17})'
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
    if type(scopes) is not list:raise ValueError('scope declarations must be a list')
    ids=[]
    members=set()
    for scope in scopes:
        if type(scope) is not dict or set(scope)!={'writer_control_scope_id','account','partition','region','resource_arns'}:raise ValueError('bad scope')
        scope_id=scope['writer_control_scope_id']
        resources=scope['resource_arns']
        if not isinstance(scope_id,str) or not scope_id or not re.fullmatch(r'\d{12}',scope['account']) or scope['partition'] not in ('aws','aws-cn','aws-us-gov') or not isinstance(scope['region'],str) or not scope['region']:raise ValueError('bad scope identity')
        if type(resources) is not list or not resources or resources!=sorted(set(resources)) or any(not _valid_declared_arn(resource,scope) for resource in resources):raise ValueError('bad scope resources')
        ids.append(scope_id)
        _add_scope_members(members,scope,resources)
    if ids!=sorted(set(ids)):raise ValueError('unsorted/duplicate scopes')


_SPECIAL_SCOPE_SHAPES=(('ec2','snapshot/','snapshot'),('s3','','s3_bucket'),('cloudfront','distribution/','cloudfront'),('apigateway','/restapis/','apigw_stage'))


def _special_scope_kind(parts):
    """Kind whose canonical ARN is regionless/accountless; None means the legacy generic rule."""
    if len(parts)!=6 or parts[0]!='arn':return None
    for service,prefix,kind in _SPECIAL_SCOPE_SHAPES:
        if parts[2]==service and parts[5].startswith(prefix) and (service!='s3' or (not parts[3] and not parts[4])):
            return kind
    return None


def _syntax_identity_ok(kind,arn,partition,account,scope_region):
    """Syntax-only exact-Scope admission via the trusted Kind grammar; NOT a Host ownership proof."""
    try:
        _caps.canonical_target_identity(kind=kind,locator=arn,resource_arn=arn,partition=partition,account=account,scope_region=scope_region)
    except ValueError:
        return False
    return True


def _valid_declared_arn(arn,scope):
    if not isinstance(arn,str) or any(char.isspace() for char in arn) or '*' in arn:
        return False
    parts=arn.split(':',5)
    special=_special_scope_kind(parts)
    if special is not None:
        return _syntax_identity_ok(special,arn,scope['partition'],scope['account'],scope['region'])
    if (len(parts)!=6 or parts[0]!='arn' or parts[1]!=scope['partition']
            or not parts[2] or parts[3]!=scope['region'] or parts[4]!=scope['account']
            or not parts[5]):
        return False
    if parts[2]=='ec2' and parts[5].startswith('volume/'):
        return re.fullmatch('volume/'+VOLUME_ID_PATTERN,parts[5],re.ASCII) is not None
    return True


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
    value='' if v is None else str(v)
    if value.lstrip(' \t\r\n\ufeff').startswith(('=','+','-','@')) or value.startswith(('\t','\r','\n')):
        return "'"+value
    return value


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
    kind=row.get('kind')
    if kind!='volume':
        if kind not in _caps.REGISTRY_KINDS or row.get('aws_operation')!=_caps.resolve_kind_capability(kind).write_operation:
            raise BatchValidationError('Kind/API has no approved write implementation')
    elif row.get('aws_operation')!='ec2:CreateTags':
        raise BatchValidationError('Kind/API has no approved write implementation')
    arn=row.get('resource_arn','')
    account=plan.get('account');partition=plan.get('partition');region=row.get('region')
    if type(arn) is not str or type(region) is not str:raise BatchValidationError('Bad ARN')
    if kind!='volume':
        try:
            _caps.canonical_target_identity(kind=kind,locator=arn,resource_arn=arn,partition=partition,account=account,scope_region=region)
        except ValueError as error:
            raise BatchValidationError('ARN/account/partition/region mismatch') from error
    else:
        parts=arn.split(':',5)
        if len(parts)!=6 or parts[:2]!=['arn',partition] or parts[3]!=region or parts[4]!=account:
            raise BatchValidationError('ARN/account/partition/region mismatch')
        match=re.fullmatch('volume/('+VOLUME_ID_PATTERN+')',parts[5],re.ASCII) if parts[2]=='ec2' else None
        if match is None:
            raise BatchValidationError('Malformed volume ARN')
        if row.get('locator')!=match.group(1):
            raise BatchValidationError('Volume locator does not match ARN')
    entries=[s for s in plan['scope_declarations'] if s['account']==account and s['partition']==partition and s['region']==region and arn in s['resource_arns']]
    if len(entries)!=1:raise BatchValidationError('No unique Scope declaration')
    return entries[0]['writer_control_scope_id']


def _validate_name_eligibility(r,name):
    """Re-check the v3 volume Name generation contract; never trust non-empty evidence alone."""
    from aws_cost_name_tagger_v3 import meaningful
    locator=r.get('locator')
    if meaningful(name)!=name:
        raise BatchValidationError('Proposed Name is not a meaningful generated Name')
    evidence=r['evidence']
    match=(re.fullmatch(
        rf'EBS {re.escape(locator)} -> attachment (i-(?:[0-9a-f]{{8}}|[0-9a-f]{{17}})) '
        rf'([a-z][a-z0-9-]*[a-z0-9]) -> EC2 \1 Name=(\S+?);.*',evidence)
        if isinstance(locator,str) else None)
    device=match.group(2) if match else None
    anchor=match.group(3) if match else None
    expected=(f'{anchor}-ebs-{device}-{locator[-7:]}'
              if anchor is not None and device is not None else None)
    if (anchor is None or meaningful(anchor)!=anchor or expected!=name):
        raise BatchValidationError('Evidence does not support the generated Name')


def validate_approved_batch_row(p,r,approved:str):
    if approved!='YES':raise BatchValidationError('Not approved')
    if r.get('status')!='proposed' or r.get('confidence') not in ('high','medium'):
        raise BatchValidationError('Only proposed high/medium rows may be approved')
    state=r.get('name_state');presence=r.get('name_key_present');raw=r.get('name_raw_value')
    valid=(state=='ABSENT' and presence is False and raw is None) or (state=='EMPTY' and presence is True and raw=='') or (state=='WHITESPACE_ONLY' and presence is True and isinstance(raw,str) and raw!='' and raw.strip()=='')
    if not valid:raise BatchValidationError('Name cannot be overwritten')
    name=r.get('proposed_name')
    if not isinstance(name,str) or not name or len(name)>256 or name!=name.strip() or any(ord(c)<32 or ord(c)==127 for c in name):raise BatchValidationError('Invalid proposed Name')
    if not isinstance(r.get('proposal_id'),str) or not r['proposal_id'] or not isinstance(r.get('evidence'),str) or not r['evidence']:
        raise BatchValidationError('No proposal/evidence')
    _validate_name_eligibility(r,name)
    if r.get('kind')!='volume' or r.get('aws_operation')!='ec2:CreateTags':
        raise BatchValidationError('Kind/API is not proven eligible')
    scope=derive_declared_row_scope(p,r)
    return {**r,'approved':'YES','approved_name':name,'writer_control_scope_id':scope}


def validate_batch_csv(plan_bytes:bytes,csv_bytes:bytes)->tuple[dict,...]:
    p=_parse_plan(plan_bytes)
    return _validate_batch_csv_for_plan(p,csv_bytes)


def _validate_batch_csv_for_plan(p:dict,csv_bytes:bytes)->tuple[dict,...]:
    parsed=_read_review_csv(csv_bytes)
    if len(parsed)!=len(p['records']):raise BatchValidationError('CSV row count mismatch')
    ids=set();target=set();result=[]
    for record,cells in zip(p['records'],parsed,strict=True):
        c=dict(zip(CSV_COLUMNS,cells,strict=True))
        if c['approved'] not in ('','YES','NO'):raise BatchValidationError('Invalid approved cell')
        if any(c[f]!=_csv_value(record,f) for f in CSV_COLUMNS if f!='approved'):
            raise BatchValidationError('Non-approval CSV cell changed')
        proposal=record.get('proposal_id');arn=record.get('resource_arn');operation=record.get('aws_operation')
        identity=(arn,operation)
        confirmed_target=isinstance(arn,str) and bool(arn) and isinstance(operation,str) and bool(operation)
        if not isinstance(proposal,str) or not proposal or proposal in ids or (confirmed_target and identity in target):raise BatchValidationError('Duplicate/missing proposal or target')
        ids.add(proposal)
        if confirmed_target:target.add(identity)
        result.append(validate_approved_batch_row(p,record,c['approved']) if c['approved']=='YES' else {**record,'approved':c['approved']})
    return tuple(result)


def validate_batch_draft(plan_bytes:bytes,csv_bytes:bytes)->BatchDraft:
    plan=_parse_plan(plan_bytes)
    rows=_validate_batch_csv_for_plan(plan,csv_bytes)
    return BatchDraft(bytes(plan_bytes),bytes(csv_bytes),tuple(r for r in rows if r['approved']=='YES'),rows,plan)
