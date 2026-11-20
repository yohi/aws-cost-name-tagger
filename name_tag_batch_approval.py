"""Batch-only Owner approval, purpose-separated from Phase A name/execution envelopes.

No trust anchor enrollment, signing, role registration or AWS calls are performed.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from types import MappingProxyType
from typing import Any
import base64, json, re
from name_tag_batch_state import validate_batch_draft, BatchValidationError

BATCH_NAMESPACE='aws-cost-name-tagger-batch-approval-v1'
_FIELDS=frozenset({'schema_version','purpose','csv_sha256','plan_sha256','approved_rows_sha256','account','partition','authorized_role_arn','owner_principal_id','owner_key_fingerprint','allowed_role','issued_at_utc','expires_at_utc','batch_nonce'})

class BatchAuthRejected(ValueError):
    def __init__(self, message='BLOCKED_OWNER_AUTHN'):
        super().__init__(message)
        self.code='BLOCKED_OWNER_AUTHN'


def _canonical(v):
    if v is None:return 'null'
    if v is True:return 'true'
    if v is False:return 'false'
    if type(v) is int:return str(v)
    if type(v) is str:
        v.encode('utf-8','strict')
        return json.dumps(v,ensure_ascii=False,separators=(',',':'))
    if type(v) in (list,tuple):return '['+','.join(_canonical(x) for x in v)+']'
    if type(v) is dict:
        if any(type(k) is not str or not re.fullmatch(r'[A-Za-z]\w*',k,flags=re.ASCII) for k in v):
            raise BatchAuthRejected()
        return '{'+','.join(_canonical(k)+':'+_canonical(v[k]) for k in sorted(v))+'}'
    raise BatchAuthRejected()


def canonical_bytes(obj)->bytes:return _canonical(obj).encode('utf-8')

def _unique_pairs(pairs):
    result={}
    for k,v in pairs:
        if k in result:raise BatchAuthRejected()
        result[k]=v
    return result


def _reject_json_constant(value):
    raise BatchAuthRejected()

def _timestamp(s):
    if not isinstance(s,str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',s):raise BatchAuthRejected()
    try:return datetime.fromisoformat(s.replace('Z','+00:00'))
    except ValueError as e:raise BatchAuthRejected() from e


def _validate_payload(payload):
    if type(payload) is not dict or set(payload)!=_FIELDS or type(payload.get('schema_version')) is not int or payload['schema_version']!=1:
        raise BatchAuthRejected()
    if any(type(v) is not str for k,v in payload.items() if k!='schema_version'):
        raise BatchAuthRejected()
    if payload['purpose']!=BATCH_NAMESPACE or payload['allowed_role']!='batch-approver':raise BatchAuthRejected()
    for k in ('csv_sha256','plan_sha256','approved_rows_sha256'):
        if not re.fullmatch('[0-9a-f]{64}',payload[k]):raise BatchAuthRejected()
    if not re.fullmatch('[0-9a-f]{32,128}',payload['batch_nonce']):raise BatchAuthRejected()
    if not re.fullmatch(r'\d{12}',payload['account']):raise BatchAuthRejected()
    if payload['partition'] not in ('aws','aws-cn','aws-us-gov'):raise BatchAuthRejected()
    if not payload['authorized_role_arn'].startswith('arn:'+payload['partition']+':iam::'+payload['account']+':role/'):
        raise BatchAuthRejected()
    if not payload['owner_principal_id'] or not payload['owner_key_fingerprint']:raise BatchAuthRejected()
    if _timestamp(payload['issued_at_utc'])>=_timestamp(payload['expires_at_utc']):raise BatchAuthRejected()
    canonical_bytes(payload)


def _approved_tuples(draft):
    out=[]
    for i,r in enumerate(draft.rows):
        if r['approved']!='YES':continue
        out.append([i,r['proposal_id'],draft.plan['account'],draft.plan['partition'],r['region'],r['resource_arn'],r['name_state'],r['name_key_present'],r['name_raw_value'],r['approved_name'],r['aws_operation'],r['writer_control_scope_id'],'YES'])
    return out

@dataclass(frozen=True)
class PreparedBatchApproval:
    canonical_payload_bytes:bytes
    payload:dict
    batch_id:str
    namespace:str
    manifest:dict
    execution_allowed:bool=False

@dataclass(frozen=True)
class VerifiedBatchApproval:
    raw_envelope_bytes:bytes
    canonical_payload_bytes:bytes
    batch_id:str
    payload:MappingProxyType
    plan_bytes:bytes
    csv_bytes:bytes
    approved_rows:tuple
    approved_row_indexes:tuple[int,...]
    owner_principal_id:str
    signature_ref:str

@dataclass(frozen=True)
class VerifiedBatchRowAuthority:
    batch:VerifiedBatchApproval
    row_index:int
    row:MappingProxyType
    row_authority_id:str


def prepare_batch_approval(plan_bytes:bytes,csv_bytes:bytes,*,owner_principal_id:str,owner_key_fingerprint:str,authorized_role_arn:str,issued_at_utc:str,expires_at_utc:str,batch_nonce:str)->PreparedBatchApproval:
    try:draft=validate_batch_draft(plan_bytes,csv_bytes)
    except BatchValidationError as e:raise BatchAuthRejected() from e
    tuples=_approved_tuples(draft)
    if not tuples:raise BatchAuthRejected()
    payload={'schema_version':1,'purpose':BATCH_NAMESPACE,
      'csv_sha256':sha256(csv_bytes).hexdigest(),'plan_sha256':sha256(plan_bytes).hexdigest(),
      'approved_rows_sha256':sha256(canonical_bytes(tuples)).hexdigest(),'account':draft.plan['account'],
      'partition':draft.plan['partition'],'authorized_role_arn':authorized_role_arn,
      'owner_principal_id':owner_principal_id,'owner_key_fingerprint':owner_key_fingerprint,
      'allowed_role':'batch-approver','issued_at_utc':issued_at_utc,
      'expires_at_utc':expires_at_utc,'batch_nonce':batch_nonce}
    _validate_payload(payload)
    can=canonical_bytes(payload)
    manifest={'authentication_state':'UNSIGNED_PREVIEW','execution_allowed':False,
      'batch_id':sha256(can).hexdigest(),'owner_id_hint':owner_principal_id,
      'signing_namespace':BATCH_NAMESPACE,'plan_sha256':payload['plan_sha256'],
      'csv_sha256':payload['csv_sha256'],'approved_rows_sha256':payload['approved_rows_sha256'],
      'cur_population':draft.plan['cur_population'],
      'max_send_attempts':draft.plan['execution_limits']['max_send_attempts'],
      'expires_at_utc':expires_at_utc,
      'account':draft.plan['account'],'partition':draft.plan['partition'],
      'approved_count':len(draft.approved_rows),
      'excluded_count':len(draft.rows)-len(draft.approved_rows),
      'scope_id_semantics':'DECLARED_ONLY_NOT_HOST_VERIFIED',
      'approved_rows':[{**{k:r.get(k) for k in ('proposal_id','region','resource_arn','name_state','name_key_present','name_raw_value','existing_name','approved_name','aws_operation','writer_control_scope_id','effective_usage_cost_usd')},'account':draft.plan['account'],'partition':draft.plan['partition']} for r in draft.approved_rows]}
    return PreparedBatchApproval(can,payload,sha256(can).hexdigest(),BATCH_NAMESPACE,manifest)


def _verify_batch_owner_signature(payload,canonical_payload,envelope,trust,now_utc):
    from name_tag_approval import ApprovalRejected, OwnerTrust, _select_signer_lines, _verify_signature
    if not isinstance(trust,OwnerTrust) or type(now_utc) is not datetime or now_utc.tzinfo is None:
        raise BatchAuthRejected()
    now=now_utc.astimezone(timezone.utc)
    if not _timestamp(payload['issued_at_utc'])<=now<_timestamp(payload['expires_at_utc']):
        raise BatchAuthRejected()
    entries=trust._owners.get(payload['owner_principal_id'],{})
    allowed={fp for fp,owner in entries.items() if not owner.revoked and owner.role=='batch-approver'}
    if payload['owner_key_fingerprint'] not in allowed:
        raise BatchAuthRejected()
    lines=_select_signer_lines(trust._check_file(),payload['owner_principal_id'],allowed)
    signature=base64.b64decode(envelope['signature_ref'],validate=True)
    try:
        actual=_verify_signature(signature,canonical_payload,payload['owner_principal_id'],BATCH_NAMESPACE,lines)
    except ApprovalRejected as error:
        raise BatchAuthRejected() from error
    if actual!=payload['owner_key_fingerprint']:
        raise BatchAuthRejected()


def verify_batch_approval(plan_bytes:bytes,csv_bytes:bytes,signed_batch_envelope:bytes,*,trust:Any,now_utc:datetime)->VerifiedBatchApproval:
    """Require *real* existing protected OwnerTrust and OpenSSH verification. No fake fallback."""
    try:
        envelope=json.loads(signed_batch_envelope.decode('utf-8'),object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_json_constant)
        if type(envelope) is not dict or set(envelope)!={'payload','batch_id','signature_ref'}:raise BatchAuthRejected()
        payload=envelope['payload'];_validate_payload(payload)
        can=canonical_bytes(payload)
        if envelope['batch_id']!=sha256(can).hexdigest():raise BatchAuthRejected()
        if payload['plan_sha256']!=sha256(plan_bytes).hexdigest() or payload['csv_sha256']!=sha256(csv_bytes).hexdigest():raise BatchAuthRejected()
        draft=validate_batch_draft(plan_bytes,csv_bytes)
        approved_tuples=_approved_tuples(draft)
        if payload['approved_rows_sha256']!=sha256(canonical_bytes(approved_tuples)).hexdigest():raise BatchAuthRejected()
        if payload['account']!=draft.plan['account'] or payload['partition']!=draft.plan['partition']:raise BatchAuthRejected()
        _verify_batch_owner_signature(payload,can,envelope,trust,now_utc)
        frozen_rows=tuple(MappingProxyType(dict(row)) for row in draft.approved_rows)
        return VerifiedBatchApproval(bytes(signed_batch_envelope),can,envelope['batch_id'],MappingProxyType(dict(payload)),bytes(plan_bytes),bytes(csv_bytes),frozen_rows,tuple(row[0] for row in approved_tuples),payload['owner_principal_id'],envelope['signature_ref'])
    except (ValueError,TypeError,KeyError,ImportError,OSError,AttributeError) as e:
        raise BatchAuthRejected() from e


def revalidate_verified_batch(batch:VerifiedBatchApproval,*,trust:Any,now_utc:datetime)->VerifiedBatchApproval:
    if type(batch) is not VerifiedBatchApproval:raise BatchAuthRejected()
    fresh=verify_batch_approval(batch.plan_bytes,batch.csv_bytes,batch.raw_envelope_bytes,trust=trust,now_utc=now_utc)
    if fresh.batch_id!=batch.batch_id or fresh.canonical_payload_bytes!=batch.canonical_payload_bytes or fresh.owner_principal_id!=batch.owner_principal_id:
        raise BatchAuthRejected()
    return fresh


def derive_batch_row_authority(batch:VerifiedBatchApproval,row_index:int,*,trust:Any,now_utc:datetime)->VerifiedBatchRowAuthority:
    if type(batch) is not VerifiedBatchApproval or type(row_index) is not int:raise BatchAuthRejected()
    batch=revalidate_verified_batch(batch,trust=trust,now_utc=now_utc)
    draft=validate_batch_draft(batch.plan_bytes,batch.csv_bytes)
    if row_index<0 or row_index>=len(draft.rows) or draft.rows[row_index]['approved']!='YES':raise BatchAuthRejected()
    row=draft.rows[row_index]
    identity=[batch.batch_id,row_index,row['proposal_id'],draft.plan['account'],draft.plan['partition'],row['region'],row['resource_arn'],row['approved_name'],row['aws_operation'],row['writer_control_scope_id']]
    return VerifiedBatchRowAuthority(batch,row_index,MappingProxyType(dict(row)),sha256(canonical_bytes(identity)).hexdigest())
