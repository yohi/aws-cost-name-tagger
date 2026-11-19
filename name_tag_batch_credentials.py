"""Synthetic-only credential lineage for offline tests. NEVER calls AWS STS.

A production BatchCredentialIssuer still needs a separate Owner/runtime GO and
must use the exact host-only actual AssumeRole request plus protected receipt.
"""
from __future__ import annotations
from dataclasses import dataclass
from name_tag_batch_iam import SessionPolicySpec, KindPolicy, IAMPolicyBlocked, build_subset_session_policy
from name_tag_batch_approval import VerifiedBatchApproval
from hashlib import sha256
from typing import Mapping

class CredentialBlocked(RuntimeError):pass

@dataclass(frozen=True)
class IssuedBatchSession:
    batch_id:str
    policy_bytes:bytes
    policy_sha256:str
    row_indexes:tuple[int,...]
    role_arn:str
    provenance:str='OFFLINE_SYNTHETIC_NOT_STS'

class OfflineFakeIssuer:
    """No real STS client can be supplied; no network/API methods exist."""
    def issue(self,batch:VerifiedBatchApproval,subset:SessionPolicySpec,*,kind_registry:Mapping[str,KindPolicy],tamper_policy:bool=False)->IssuedBatchSession:
        if type(batch) is not VerifiedBatchApproval or type(subset) is not SessionPolicySpec or batch.batch_id!=subset.batch_id:
            raise CredentialBlocked('Foreign batch/receipt')
        try:
            expected=build_subset_session_policy(batch,subset.row_indexes,kind_registry=kind_registry)
        except IAMPolicyBlocked as e:
            raise CredentialBlocked('Invalid policy subset') from e
        if expected!=subset:
            raise CredentialBlocked('Policy does not match authorized subset')
        raw=subset.policy_bytes
        if tamper_policy:raw+=b'x'
        if sha256(raw).hexdigest()!=subset.policy_sha256:
            raise CredentialBlocked('Tampered policy')
        role=batch.payload.get('authorized_role_arn')
        if not isinstance(role,str) or not role.startswith('arn:'):
            raise CredentialBlocked('Missing role identity')
        return IssuedBatchSession(batch.batch_id,raw,subset.policy_sha256,subset.row_indexes,role)


def validate_issued_batch_session(
    batch:VerifiedBatchApproval,
    subset:SessionPolicySpec,
    issued:IssuedBatchSession,
)->None:
    """Recheck every synthetic issuance claim before an offline Intent is opened."""
    role=batch.payload.get('authorized_role_arn')
    if (type(batch) is not VerifiedBatchApproval
            or type(subset) is not SessionPolicySpec
            or type(issued) is not IssuedBatchSession
            or not isinstance(role,str)
            or issued.batch_id!=batch.batch_id
            or issued.policy_bytes!=subset.policy_bytes
            or issued.policy_sha256!=subset.policy_sha256
            or sha256(issued.policy_bytes).hexdigest()!=issued.policy_sha256
            or issued.row_indexes!=subset.row_indexes
            or issued.role_arn!=role
            or issued.provenance!='OFFLINE_SYNTHETIC_NOT_STS'):
        raise CredentialBlocked('Synthetic issued-session binding mismatch')
