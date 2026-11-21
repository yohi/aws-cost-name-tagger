"""Synthetic-only credential lineage for offline tests. NEVER calls AWS STS.

A production BatchCredentialIssuer still needs a separate Owner/runtime GO and
must use the exact host-only actual AssumeRole request plus protected receipt.
"""
from __future__ import annotations
from dataclasses import dataclass
from name_tag_batch_iam import SessionPolicySpec, KindPolicy, IAMPolicyBlocked, build_subset_session_policy
from name_tag_batch_approval import VerifiedBatchApproval, canonical_bytes
from hashlib import sha256
from typing import Mapping, Protocol
import json
from weakref import WeakValueDictionary

class CredentialBlocked(RuntimeError):pass

@dataclass(frozen=True)
class IssuedBatchSession:
    batch_id:str
    policy_bytes:bytes
    policy_sha256:str
    row_indexes:tuple[int,...]
    role_arn:str
    provenance:str='OFFLINE_SYNTHETIC_NOT_STS'
    owner_principal_id:str=''
    subset_sha256:str=''
    allowed_arns:tuple[str,...]=()
    allowed_actions:tuple[str,...]=()
    issuer_identity:str=''
    request_id:str=''
    request_bytes:bytes=b''
    response_id:str=''
    response_bytes:bytes=b''
    expiration_utc:str=''
    client_identity:str=''


class BatchCredentialIssuer(Protocol):
    """Issue sessions for the verified subset; returned sessions need provenance validation."""

    def issue(
        self,
        batch: VerifiedBatchApproval,
        subset: SessionPolicySpec,
        *,
        kind_registry: Mapping[str, KindPolicy],
    ) -> IssuedBatchSession: ...

# Identity registry: only sessions minted by OfflineFakeIssuer.issue are accepted
# by the offline adapter (an equal-valued externally built copy is not).
_ISSUED:WeakValueDictionary[int,IssuedBatchSession]=WeakValueDictionary()


@dataclass(frozen=True, slots=True)
class _OfflineIssuanceReceipt:
    owner_principal_id: str
    subset_sha256: str
    issuer_identity: str
    request_id: str
    request_bytes: bytes
    response_id: str
    response_bytes: bytes
    expiration_utc: str
    client_identity: str


def _offline_issuance_receipt(
    batch: VerifiedBatchApproval,
    subset: SessionPolicySpec,
) -> _OfflineIssuanceReceipt:
    """Construct synthetic lineage metadata without implying STS issuance."""
    if len(batch.approved_row_indexes) != len(batch.approved_rows):
        raise CredentialBlocked('Batch row mapping is invalid')
    rows_by_index = dict(zip(batch.approved_row_indexes, batch.approved_rows, strict=True))
    try:
        subset_identity = [
            [
                row_index,
                rows_by_index[row_index]['proposal_id'],
                rows_by_index[row_index]['resource_arn'],
                rows_by_index[row_index]['approved_name'],
                rows_by_index[row_index]['aws_operation'],
                rows_by_index[row_index]['writer_control_scope_id'],
            ]
            for row_index in subset.row_indexes
        ]
    except KeyError as error:
        raise CredentialBlocked('Subset does not match verified rows') from error
    subset_sha256 = sha256(canonical_bytes(subset_identity)).hexdigest()
    issuer_identity = 'OFFLINE_FAKE_ISSUER'
    expiration_utc = batch.payload.get('expires_at_utc')
    owner_principal_id = batch.owner_principal_id
    if not isinstance(expiration_utc, str) or not owner_principal_id:
        raise CredentialBlocked('Batch issue lineage is incomplete')
    request_payload = {
        'schema': 'aws-cost-name-tagger/offline-issue-request-v1',
        'issuer_identity': issuer_identity,
        'batch_id': batch.batch_id,
        'owner_principal_id': owner_principal_id,
        'subset_sha256': subset_sha256,
        'row_indexes': list(subset.row_indexes),
        'policy_sha256': subset.policy_sha256,
        'role_arn': batch.payload.get('authorized_role_arn'),
        'allowed_arns': list(subset.write_arns),
        'allowed_actions': list(subset.write_actions),
        'expiration_utc': expiration_utc,
    }
    request_bytes = canonical_bytes(request_payload)
    request_id = sha256(request_bytes).hexdigest()
    client_identity = sha256(
        canonical_bytes([issuer_identity, request_id, 'FAKE_EC2_CLIENT'])
    ).hexdigest()
    response_payload = {
        'schema': 'aws-cost-name-tagger/offline-issue-response-v1',
        'request_id': request_id,
        'assumed_role_arn': batch.payload.get('authorized_role_arn'),
        'access_key_identity': f'FAKE:{client_identity[:24]}',
        'expiration_utc': expiration_utc,
        'client_identity': client_identity,
    }
    response_bytes = canonical_bytes(response_payload)
    return _OfflineIssuanceReceipt(
        owner_principal_id,
        subset_sha256,
        issuer_identity,
        request_id,
        request_bytes,
        sha256(response_bytes).hexdigest(),
        response_bytes,
        expiration_utc,
        client_identity,
    )

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
        receipt = _offline_issuance_receipt(batch, subset)
        issued=IssuedBatchSession(
            batch.batch_id,
            raw,
            subset.policy_sha256,
            subset.row_indexes,
            role,
            owner_principal_id=receipt.owner_principal_id,
            subset_sha256=receipt.subset_sha256,
            allowed_arns=subset.write_arns,
            allowed_actions=subset.write_actions,
            issuer_identity=receipt.issuer_identity,
            request_id=receipt.request_id,
            request_bytes=receipt.request_bytes,
            response_id=receipt.response_id,
            response_bytes=receipt.response_bytes,
            expiration_utc=receipt.expiration_utc,
            client_identity=receipt.client_identity,
        )
        _ISSUED[id(issued)]=issued
        return issued


def validate_issued_batch_session(
    batch:VerifiedBatchApproval,
    subset:SessionPolicySpec,
    issued:IssuedBatchSession,
)->None:
    """Recheck every synthetic issuance claim before an offline Intent is opened."""
    if (
        type(batch) is not VerifiedBatchApproval
        or type(subset) is not SessionPolicySpec
        or type(issued) is not IssuedBatchSession
    ):
        raise CredentialBlocked('Synthetic issued-session binding mismatch')
    role=batch.payload.get('authorized_role_arn')
    receipt = _offline_issuance_receipt(batch, subset)
    if (not isinstance(role,str)
            or issued.batch_id!=batch.batch_id
            or issued.policy_bytes!=subset.policy_bytes
            or issued.policy_sha256!=subset.policy_sha256
            or sha256(issued.policy_bytes).hexdigest()!=issued.policy_sha256
            or issued.row_indexes!=subset.row_indexes
            or issued.role_arn!=role
            or issued.provenance!='OFFLINE_SYNTHETIC_NOT_STS'
            or _ISSUED.get(id(issued)) is not issued
            or issued.owner_principal_id!=receipt.owner_principal_id
            or issued.subset_sha256!=receipt.subset_sha256
            or issued.allowed_arns!=subset.write_arns
            or issued.allowed_actions!=subset.write_actions
            or issued.issuer_identity!=receipt.issuer_identity
            or issued.request_id!=receipt.request_id
            or issued.request_bytes!=receipt.request_bytes
            or issued.response_id!=receipt.response_id
            or issued.response_bytes!=receipt.response_bytes
            or issued.expiration_utc!=receipt.expiration_utc
            or issued.client_identity!=receipt.client_identity):
        raise CredentialBlocked('Synthetic issued-session binding mismatch')


def authorize_offline_session_operation(session:IssuedBatchSession|None,resource_arn:str,*,write:bool=False)->None:
    """Offline-fake check that an operation is bound to an issuer-minted session.

    Synthetic evidence only; it does not prove effective production IAM permissions.
    """
    if (type(session) is not IssuedBatchSession
            or _ISSUED.get(id(session)) is not session
            or session.provenance!='OFFLINE_SYNTHETIC_NOT_STS'
            or sha256(session.policy_bytes).hexdigest()!=session.policy_sha256):
        raise CredentialBlocked('Operation is not bound to an issued offline session')
    if not write:
        return
    try:
        statements=json.loads(session.policy_bytes)['Statement']
        allowed=next(st['Resource'] for st in statements if st.get('Sid')=='ApprovedNameTagWritesOnly')
    except (ValueError,KeyError,StopIteration,TypeError) as error:
        raise CredentialBlocked('Session policy is unreadable') from error
    if resource_arn not in (allowed if isinstance(allowed,list) else [allowed]):
        raise CredentialBlocked('Write target is outside the issued session subset')
