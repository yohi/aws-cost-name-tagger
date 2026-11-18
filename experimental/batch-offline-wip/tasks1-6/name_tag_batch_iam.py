"""OFFLINE policy construction, not effective IAM permission proof.

A resource-based policy/permissions boundary/SCP can alter effective access.
A signed Batch and policy spec alone never unlock an actual AWS writer.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping
import json, re
from name_tag_batch_approval import VerifiedBatchApproval

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
    if len(set(row_indexes))!=len(row_indexes) or sorted(row_indexes)!=list(row_indexes) or any(type(i) is not int or i<0 or i>=len(batch.approved_rows) for i in row_indexes):
        raise IAMPolicyBlocked('Subset indexes must be sorted, unique and approved')
    write_actions=set();read_actions=set();arns=set()
    for i in row_indexes:
        row=batch.approved_rows[i]
        kind=row.get('kind');policy=kind_registry.get(kind)
        if not isinstance(policy,KindPolicy) or kind!='volume' or policy!=KindPolicy('ec2:CreateTags','ec2:DescribeVolumes'):
            raise IAMPolicyBlocked('No proven Name-only policy for this service/kind')
        account=batch.payload.get('account');partition=batch.payload.get('partition');region=row.get('region')
        arn=row.get('resource_arn')
        if not all(isinstance(v,str) and v for v in (account,partition,region,arn)):
            raise IAMPolicyBlocked('Incomplete ARN scope')
        prefix=f'arn:{partition}:ec2:{region}:{account}:volume/'
        if not arn.startswith(prefix) or not re.fullmatch(r'vol-[A-Za-z0-9]+',arn[len(prefix):]):
            raise IAMPolicyBlocked('Foreign or malformed volume ARN')
        if row.get('aws_operation')!=policy.write_action or not row.get('approved_name'):
            raise IAMPolicyBlocked('Operation/Name not authorized')
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
