"""OFFLINE policy construction, not effective IAM permission proof.

A resource-based policy/permissions boundary/SCP can alter effective access.
A signed Batch and policy spec alone never unlock an actual AWS writer.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping
import json, re
from name_tag_batch_approval import VerifiedBatchApproval, _approved_tuples, canonical_bytes
from name_tag_batch_state import validate_batch_draft

class IAMPolicyBlocked(ValueError):pass

@dataclass(frozen=True)
class KindPolicy:
    write_action:str
    read_action:str

@dataclass(frozen=True)
class SessionPolicySpec:
    batch_id:str
    row_indexes:tuple[int,...]
    policy_bytes:bytes
    policy_sha256:str
    write_arns:tuple[str,...]
    write_actions:tuple[str,...]
    read_actions:tuple[str,...]


def build_subset_session_policy(batch:VerifiedBatchApproval,row_indexes:tuple[int,...],*,kind_registry:Mapping[str,KindPolicy])->SessionPolicySpec:
    if type(batch) is not VerifiedBatchApproval or type(row_indexes) is not tuple or not row_indexes:
        raise IAMPolicyBlocked('Missing verified batch/subset')
    try:
        payload_bytes=canonical_bytes(dict(batch.payload))
        draft=validate_batch_draft(batch.plan_bytes,batch.csv_bytes)
        tuples=_approved_tuples(draft)
        approved_indexes=tuple(row[0] for row in tuples)
    except (KeyError,TypeError,ValueError) as e:
        raise IAMPolicyBlocked('Verified approval source data is invalid') from e
    if (batch.canonical_payload_bytes!=payload_bytes
            or sha256(payload_bytes).hexdigest()!=batch.batch_id
            or batch.payload.get('plan_sha256')!=sha256(batch.plan_bytes).hexdigest()
            or batch.payload.get('csv_sha256')!=sha256(batch.csv_bytes).hexdigest()
            or batch.payload.get('approved_rows_sha256')!=sha256(canonical_bytes(tuples)).hexdigest()
            or batch.approved_rows!=tuple(draft.approved_rows)):
        raise IAMPolicyBlocked('Verified rows do not match the Owner-approved source bytes')
    if (type(approved_indexes) is not tuple
            or len(approved_indexes)!=len(batch.approved_rows)
            or any(type(i) is not int or i<0 for i in approved_indexes)
            or len(set(approved_indexes))!=len(approved_indexes)
            or sorted(approved_indexes)!=list(approved_indexes)
            or batch.approved_row_indexes!=approved_indexes):
        raise IAMPolicyBlocked('Verified approved-row index mapping is invalid')
    rows_by_csv_index={i:draft.rows[i] for i in approved_indexes}
    if (any(type(i) is not int or i not in rows_by_csv_index for i in row_indexes)
            or len(set(row_indexes))!=len(row_indexes)
            or sorted(row_indexes)!=list(row_indexes)):
        raise IAMPolicyBlocked('Subset indexes must be sorted, unique and approved')
    write_actions=set();read_actions=set();arns=set()
    for i in row_indexes:
        policy,arn=_validate_policy_row(batch,rows_by_csv_index[i],kind_registry)
        write_actions.add(policy.write_action);read_actions.add(policy.read_action);arns.add(arn)
    policy={
      'Version':'2012-10-17',
      'Statement':[
       {'Sid':'ApprovedNameTagWritesOnly','Effect':'Allow','Action':sorted(write_actions),'Resource':sorted(arns),
        'Condition':{'ForAllValues:StringEquals':{'aws:TagKeys':['Name']}, 'Null':{'aws:TagKeys':'false'}}},
       {'Sid':'ReadOnlyForPreflightAndReadback','Effect':'Allow','Action':sorted(read_actions),'Resource':'*'}]
    }
    raw=json.dumps(policy,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    if len(raw)>2048:raise IAMPolicyBlocked('Session-policy plaintext limit exceeded')
    return SessionPolicySpec(batch.batch_id,row_indexes,raw,sha256(raw).hexdigest(),tuple(sorted(arns)),tuple(sorted(write_actions)),tuple(sorted(read_actions)))


def _validate_policy_row(batch,row,kind_registry):
    kind=row.get('kind')
    policy=kind_registry.get(kind)
    expected=KindPolicy('ec2:CreateTags','ec2:DescribeVolumes')
    if not isinstance(policy,KindPolicy) or kind!='volume' or policy!=expected:
        raise IAMPolicyBlocked('No proven Name-only policy for this service/kind')
    account=batch.payload.get('account')
    partition=batch.payload.get('partition')
    region=row.get('region')
    arn=row.get('resource_arn')
    if not all(isinstance(value,str) and value for value in (account,partition,region,arn)):
        raise IAMPolicyBlocked('Incomplete ARN scope')
    prefix=f'arn:{partition}:ec2:{region}:{account}:volume/'
    if not arn.startswith(prefix) or not re.fullmatch(r'vol-[0-9a-f]{8,}',arn[len(prefix):]):
        raise IAMPolicyBlocked('Foreign or malformed volume ARN')
    if row.get('aws_operation')!=policy.write_action or not row.get('approved_name'):
        raise IAMPolicyBlocked('Operation/Name not authorized')
    return policy,arn
