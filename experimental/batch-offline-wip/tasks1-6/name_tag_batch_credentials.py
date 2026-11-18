"""Synthetic-only credential lineage for offline tests. NEVER calls AWS STS.

A production BatchCredentialIssuer still needs a separate Owner/runtime GO and
must use the exact host-only actual AssumeRole request plus protected receipt.
"""
from __future__ import annotations
from dataclasses import dataclass
from name_tag_batch_iam import SessionPolicySpec
from name_tag_batch_approval import VerifiedBatchApproval
from hashlib import sha256

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
    def issue(self,batch:VerifiedBatchApproval,subset:SessionPolicySpec,*,tamper_policy:bool=False)->IssuedBatchSession:
        if type(batch) is not VerifiedBatchApproval or type(subset) is not SessionPolicySpec or batch.batch_id!=subset.batch_id:
            raise CredentialBlocked('Foreign batch/receipt')
        raw=subset.policy_bytes
        if tamper_policy:raw+=b'x'
        if sha256(raw).hexdigest()!=subset.policy_sha256:
            raise CredentialBlocked('Tampered policy')
        role=batch.payload.get('authorized_role_arn')
        if not isinstance(role,str) or not role.startswith('arn:'):
            raise CredentialBlocked('Missing role identity')
        return IssuedBatchSession(batch.batch_id,raw,subset.policy_sha256,subset.row_indexes,role)
