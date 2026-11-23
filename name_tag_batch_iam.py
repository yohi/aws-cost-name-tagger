"""OFFLINE policy construction, not effective IAM permission proof.

A resource-based policy/permissions boundary/SCP can alter effective access.
A signed Batch and policy spec alone never unlock an actual AWS writer.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping
import json, re
import name_tag_kind_capabilities as _caps
from name_tag_batch_approval import VerifiedBatchApproval, _approved_tuples, canonical_bytes
from name_tag_batch_state import VOLUME_ID_PATTERN, validate_batch_draft

class IAMPolicyBlocked(ValueError):pass

POLICY_PLAINTEXT_LIMIT=2048
IAM_CONDITION_NOT_PROVEN='IAM_CONDITION_NOT_PROVEN'
# Action-specific documented condition support. Only an action listed here may carry the
# Name-only aws:TagKeys guard; anything else yields no write policy. API Gateway actions are
# deliberately absent: the HTTP method does not prove the effective IAM action (NOTE-001).
_PROVEN_CONDITION_ACTIONS={'ec2:CreateTags':'aws:TagKeys=Name'}
_IAM_SERVICE_PREFIX={'ec2':'ec2'}
_READ_OPERATION=re.compile(r'[a-z][a-z0-9_]*')

@dataclass(frozen=True)
class KindPolicy:
    write_action:str
    read_action:str
    # Vetted extension; the two-argument legacy form (Volume) keeps these defaults.
    read_operations:tuple[str,...]=()
    resource_type:str=''
    tag_key_conditions:tuple[str,...]=()
    version:str=''

@dataclass(frozen=True)
class SessionPolicySpec:
    batch_id:str
    row_indexes:tuple[int,...]
    policy_bytes:bytes
    policy_sha256:str
    write_arns:tuple[str,...]
    write_actions:tuple[str,...]
    read_actions:tuple[str,...]


def _read_action(service,operation):
    prefix=_IAM_SERVICE_PREFIX.get(service)
    if prefix is None or not isinstance(operation,str) or not _READ_OPERATION.fullmatch(operation):
        raise IAMPolicyBlocked('Read operation has no vetted IAM action')
    return prefix+':'+''.join(part.capitalize() for part in operation.split('_'))


def verified_kind_policy(capability)->KindPolicy:
    """Compile the exact vetted per-Kind policy rights, or refuse without any policy."""
    if type(capability) is not _caps.KindCapabilityDecision or capability.status!='IMPLEMENTED_OFFLINE':
        raise IAMPolicyBlocked('Kind capability is not proven for a write policy')
    action=capability.iam_action
    if (action!=capability.write_operation
            or _PROVEN_CONDITION_ACTIONS.get(action) not in capability.tag_key_conditions):
        raise IAMPolicyBlocked(IAM_CONDITION_NOT_PROVEN)
    if not capability.read_operations:
        raise IAMPolicyBlocked('No vetted read operation')
    reads=tuple(_read_action(capability.service,op) for op in capability.read_operations)
    if capability.kind=='volume':  # legacy contract: serialization stays byte-stable
        return KindPolicy(action,reads[0])
    return KindPolicy(action,reads[0],tuple(sorted(set(reads))),capability.resource_type,
                      tuple(capability.tag_key_conditions),capability.version)


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
    write_actions=set();read_actions=set();arns=set();groups={}
    for i in row_indexes:
        policy,arn=_validate_policy_row(batch,rows_by_csv_index[i],kind_registry)
        write_actions.add(policy.write_action);arns.add(arn)
        read_actions.update(policy.read_operations or (policy.read_action,))
        # Only identical action/resource-type pairs share a statement: no Cartesian grants.
        groups.setdefault((policy.write_action,_arn_resource_type(arn)),set()).add(arn)
    statements=[]
    for n,key in enumerate(sorted(groups)):
        statements.append({'Sid':'ApprovedNameTagWritesOnly' if len(groups)==1 else f'ApprovedNameTagWrites{n+1}',
         'Effect':'Allow','Action':[key[0]],'Resource':sorted(groups[key]),
         'Condition':{'ForAllValues:StringEquals':{'aws:TagKeys':['Name']}, 'Null':{'aws:TagKeys':'false'}}})
    statements.append({'Sid':'ReadOnlyForPreflightAndReadback','Effect':'Allow','Action':sorted(read_actions),'Resource':'*'})
    policy={'Version':'2012-10-17','Statement':statements}
    raw=json.dumps(policy,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
    if len(raw)>POLICY_PLAINTEXT_LIMIT:raise IAMPolicyBlocked('Session-policy plaintext limit exceeded')
    return SessionPolicySpec(batch.batch_id,row_indexes,raw,sha256(raw).hexdigest(),tuple(sorted(arns)),tuple(sorted(write_actions)),tuple(sorted(read_actions)))


def _arn_resource_type(arn):
    return re.split(r'[/:]',arn.split(':',5)[5],maxsplit=1)[0]


def _validate_policy_row(batch,row,kind_registry):
    kind=row.get('kind')
    policy=kind_registry.get(kind)
    try:
        capability=_caps.resolve_kind_capability(kind)
    except ValueError as e:
        raise IAMPolicyBlocked('No proven Name-only policy for this service/kind') from e
    expected=verified_kind_policy(capability)  # blocks CNP/unproven-condition Kinds
    if not isinstance(policy,KindPolicy) or policy!=expected:
        raise IAMPolicyBlocked('No proven Name-only policy for this service/kind')
    account=batch.payload.get('account')
    partition=batch.payload.get('partition')
    region=row.get('region')
    arn=row.get('resource_arn')
    if not all(isinstance(value,str) and value for value in (account,partition,region,arn)):
        raise IAMPolicyBlocked('Incomplete ARN scope')
    if kind=='volume':
        prefix=f'arn:{partition}:ec2:{region}:{account}:volume/'
        if not arn.startswith(prefix) or not re.fullmatch(VOLUME_ID_PATTERN,arn[len(prefix):],re.ASCII):
            raise IAMPolicyBlocked('Foreign or malformed volume ARN')
    else:
        try:
            identity=_caps.canonical_target_identity(kind=kind,locator=row.get('locator'),resource_arn=arn,
                partition=partition,account=account,scope_region=region)
        except ValueError as e:
            raise IAMPolicyBlocked('Foreign or malformed ARN for Kind') from e
        if identity.scope_region==_caps.GLOBAL_SCOPE or _arn_resource_type(arn)!=policy.resource_type:
            raise IAMPolicyBlocked('ARN scope/resource type not authorized for Kind')
    if row.get('aws_operation')!=policy.write_action or not row.get('approved_name'):
        raise IAMPolicyBlocked('Operation/Name not authorized')
    return policy,arn
