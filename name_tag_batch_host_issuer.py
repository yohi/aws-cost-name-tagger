"""Host-only protected STS issuer and bootstrap credential provider (Design §§5.1-5.2).

OFFLINE in this phase: no boto3/botocore import, no SDK client and no network. The STS
call goes only through a Host-owned injected ``StsTransport``; the production default
transport is unavailable and fails closed (``AWS_RUNTIME_NOT_AUTHORIZED``). Bootstrap
credentials come only from the verified systemd ``CREDENTIALS_DIRECTORY`` reported for the
service (never the environment hint, profile, IMDS or the SDK default chain).
"""
from __future__ import annotations

import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields as dataclass_fields
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Final, Protocol
from weakref import WeakKeyDictionary

from name_tag_batch_approval import canonical_bytes
from name_tag_batch_host_runtime import (
    HostOSProbe, HostRuntimeBlocked, HostSelection, ProtectedFileFacts, VerifiedHostContext,
    _NonCopyable, _blocked, _strict_json, require_aware_utc, require_verified_host)

BOOTSTRAP_CREDENTIAL_NAME: Final = "aws-bootstrap.json"
_MAX_CREDENTIAL_BYTES: Final = 16384
_BOOTSTRAP_MAX_LIFETIME: Final = timedelta(hours=12)
_BOOTSTRAP_MIN_REMAINING: Final = timedelta(minutes=2)
_TEMP_AKID = re.compile(r"ASIA[A-Z2-7]{16}")
_SECRET = re.compile(r"[A-Za-z0-9/+]{40}")
_TOKEN = re.compile(r"[A-Za-z0-9/+=]{16,8192}")
_ISO_Z = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def _parse_iso_z(value: object) -> datetime:
    if not isinstance(value, str) or _ISO_Z.fullmatch(value) is None:
        raise ValueError("timestamp must be YYYY-MM-DDTHH:MM:SSZ")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ProtectedBootstrapCredentials(_NonCopyable):
    """In-memory bootstrap triplet. Never serialized, logged, copied or persisted."""

    __slots__ = ("_access_key_id", "_secret", "_token", "_expiration", "_host", "__weakref__")

    def __init__(self, *, _mint: object, access_key_id: str, secret: str, token: str,
                 expiration: datetime, host: VerifiedHostContext) -> None:
        if _mint is not _MINT:
            raise _blocked("bootstrap credentials are minted only by the protected provider")
        object.__setattr__(self, "_access_key_id", access_key_id)
        object.__setattr__(self, "_secret", secret)
        object.__setattr__(self, "_token", token)
        object.__setattr__(self, "_expiration", expiration)
        object.__setattr__(self, "_host", host)

    def __setattr__(self, name, value):
        raise _blocked("bootstrap credentials are immutable")

    def __repr__(self) -> str:
        return f"ProtectedBootstrapCredentials(access_key_id={self._access_key_id!r}, <redacted>)"

    __str__ = __repr__

    @property
    def access_key_id(self) -> str:
        return self._access_key_id

    @property
    def expiration(self) -> datetime:
        return self._expiration

    @property
    def fingerprint(self) -> str:
        return _credential_fingerprint(self._access_key_id, self._secret, self._token)


_MINT: Final = object()
_BOOTSTRAP: WeakKeyDictionary = WeakKeyDictionary()


def _credential_fingerprint(access_key_id: str, secret: str, token: str) -> str:
    """One-way identity of a credential triplet; reveals no secret material."""
    return sha256(b"aws-cnt-credential-fingerprint-v1\x00" + "\x00".join(
        (access_key_id, sha256(secret.encode()).hexdigest(),
         sha256(token.encode()).hexdigest())).encode("ascii")).hexdigest()


def require_bootstrap_credentials(creds: object, host: VerifiedHostContext,
                                  now_utc: datetime) -> ProtectedBootstrapCredentials:
    if (type(creds) is not ProtectedBootstrapCredentials or _BOOTSTRAP.get(creds) is not host
            or creds._host is not host):
        raise _blocked("bootstrap credentials are not the protected provider's")
    if require_aware_utc(now_utc) + _BOOTSTRAP_MIN_REMAINING >= creds.expiration:
        raise _blocked("bootstrap credentials expired")
    return creds


class HostBootstrapCredentialProvider(Protocol):
    def load(self, host: VerifiedHostContext, *, now_utc: datetime
             ) -> ProtectedBootstrapCredentials: ...


class SystemdEncryptedCredentialProvider:
    """Reads ``LoadCredentialEncrypted=aws-bootstrap.json`` from the verified service dir."""

    def __init__(self, *, probe: HostOSProbe) -> None:
        self._probe = probe

    def load(self, host: VerifiedHostContext, *, now_utc: datetime
             ) -> ProtectedBootstrapCredentials:
        host = require_verified_host(host)
        now = require_aware_utc(now_utc)
        # The path comes from the verified Host context, never os.environ.
        path = host.credentials_directory + "/" + BOOTSTRAP_CREDENTIAL_NAME
        try:
            facts = self._probe.file_facts(path)
            raw = self._probe.read_protected(path)
        except HostRuntimeBlocked:
            raise
        except (OSError, ValueError) as error:
            raise _blocked("bootstrap credential unavailable") from error
        if (type(facts) is not ProtectedFileFacts or facts.path != path
                or facts.file_type != "file" or facts.symlink_free is not True
                or facts.owner_uid != host.service_uid or facts.mode & 0o077
                or not isinstance(raw, bytes) or len(raw) > _MAX_CREDENTIAL_BYTES
                or facts.sha256 != sha256(raw).hexdigest()):
            raise _blocked("bootstrap credential file is not the protected delivery")
        try:
            body = _strict_json(raw)
            if set(body) != {"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"}:
                raise ValueError("unexpected credential fields")
            akid, secret, token = body["AccessKeyId"], body["SecretAccessKey"], body["SessionToken"]
            if (not isinstance(akid, str) or _TEMP_AKID.fullmatch(akid) is None
                    or not isinstance(secret, str) or _SECRET.fullmatch(secret) is None
                    or not isinstance(token, str) or _TOKEN.fullmatch(token) is None):
                raise ValueError("credential format invalid")
            expiration = _parse_iso_z(body["Expiration"])
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise _blocked("bootstrap credential malformed") from error
        if not now + _BOOTSTRAP_MIN_REMAINING < expiration <= now + _BOOTSTRAP_MAX_LIFETIME:
            raise _blocked("bootstrap credential expired or not short-lived")
        creds = ProtectedBootstrapCredentials(
            _mint=_MINT, access_key_id=akid, secret=secret, token=token,
            expiration=expiration, host=host)
        _BOOTSTRAP[creds] = host
        return creds


# ---------------------------------------------------------------- RG-PRC-006 session name
_NONCE = re.compile(r"[0-9a-f]{32,128}")
STS_DURATION_SECONDS: Final = 900
_STS_EXPIRY_SKEW: Final = timedelta(minutes=5)
_ASSUMED_ROLE_ID = re.compile(r"AROA[A-Z0-9]{12,128}:(?P<session>[\w+=,.@-]{2,64})")
_RESPONSE_KEYS: Final = frozenset({
    "Credentials", "AssumedRoleUser", "PackedPolicySize", "SourceIdentity",
    "ResponseMetadata", "SessionTokenUtilization"})
NOT_OBSERVED: Final = "NOT_OBSERVED"


def derive_role_session_name(batch_nonce: str) -> str:
    """The only AssumeRole.RoleSessionName: 64 ASCII chars derived from the signed nonce."""
    if not isinstance(batch_nonce, str) or _NONCE.fullmatch(batch_nonce) is None:
        raise _blocked("signed batch nonce malformed", "BLOCKED_OWNER_AUTHN")
    digest = sha256(b"aws-cnt-role-session-v1\x00" + batch_nonce.encode("ascii")).hexdigest()
    return "cnt-" + digest[:60]


# ---------------------------------------------------------------- STS transport contract
class StsRefused(Exception):
    """A definitive STS service refusal (e.g. PackedPolicyTooLarge). Never retried."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9]{1,64}", code) \
            else "STS_REFUSED"


@dataclass(frozen=True)
class StsExchange:
    """What the Host transport actually serialized/sent and the parsed STS response."""

    sent_request_bytes: bytes
    response: Mapping[str, object]


class StsTransport(Protocol):
    def assume_role(self, *, request_bytes: bytes,
                    credentials: ProtectedBootstrapCredentials) -> StsExchange: ...


class ExplicitSdkClientFactory(Protocol):
    """Builds an SDK client from the explicit issued triplet only (never ambient config)."""

    def create(self, service: str, region: str, *, access_key_id: str,
               secret_access_key: str, session_token: str) -> object: ...


class IndependentEvidenceGate(Protocol):
    """Independent IAM/G1/G2 evidence, checked pre-STS and against the issued identity."""

    def check_pre_sts(self, selection: HostSelection, *, now_utc: datetime) -> None: ...
    def check_issued(self, issued: "HostIssuedSession", *, now_utc: datetime) -> None: ...


class FailClosedEvidenceGate:
    """Production default: live IAM/G1/G2 evidence is not available in this phase."""

    def check_pre_sts(self, selection: HostSelection, *, now_utc: datetime) -> None:
        raise _blocked("independent IAM/G1/G2 evidence NOT_VERIFIED")

    def check_issued(self, issued: "HostIssuedSession", *, now_utc: datetime) -> None:
        raise _blocked("independent IAM/G1/G2 evidence NOT_VERIFIED")


# ---------------------------------------------------------------- receipt and session
@dataclass(frozen=True)
class HostIssuanceReceipt:
    """Tamper-evident, expiring, secret-free binding of one actual STS exchange."""

    batch_id: str
    batch_nonce: str
    batch_nonce_sha256: str
    role_session_name: str
    host_id: str
    run_id: str
    row_index: int
    row_authority_id: str
    scope_id: str
    target_arn: str
    aws_operation: str
    name_evidence_sha256: str
    role_arn: str
    request_sha256: str
    policy_sha256: str
    response_sha256: str
    assumed_role_arn: str
    assumed_role_id: str
    account: str
    partition: str
    expiration_utc: str
    credential_fingerprint: str
    session_token_utilization: str
    attempt_id: str
    issued_at_utc: str
    schema: str = "aws-cnt-host-issuance-receipt-v1"
    live_status: str = "NOT_VERIFIED"

    def canonical_bytes(self) -> bytes:
        return canonical_bytes({f.name: getattr(self, f.name) for f in dataclass_fields(self)})

    @property
    def receipt_sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


_RECEIPT_KEY: Final = os.urandom(32)  # process-local; a receipt never survives the process


def _receipt_mac(receipt: HostIssuanceReceipt) -> str:
    return hmac.new(_RECEIPT_KEY, receipt.canonical_bytes(), sha256).hexdigest()


_RECEIPT_MACS: dict[str, str] = {}


def verify_receipt(receipt: object) -> bool:
    return (type(receipt) is HostIssuanceReceipt
            and hmac.compare_digest(_RECEIPT_MACS.get(receipt.receipt_sha256, ""),
                                    _receipt_mac(receipt)))


class HostIssuedSession(_NonCopyable):
    """Protected in-memory issued session; credentials never leave this object."""

    __slots__ = ("_receipt", "_policy_bytes", "_triplet", "_factory", "_host", "_selection",
                 "_expiration", "__weakref__")

    def __init__(self, *, _mint: object = None, receipt: HostIssuanceReceipt | None = None,
                 policy_bytes: bytes = b"", triplet: tuple[str, str, str] = ("", "", ""),
                 factory: ExplicitSdkClientFactory | None = None,
                 host: VerifiedHostContext | None = None, selection: HostSelection | None = None,
                 expiration: datetime | None = None) -> None:
        if _mint is not _SESSION_MINT:
            raise _blocked("issued sessions are minted only by the protected Host issuer")
        for name, value in (("_receipt", receipt), ("_policy_bytes", policy_bytes),
                            ("_triplet", triplet), ("_factory", factory), ("_host", host),
                            ("_selection", selection), ("_expiration", expiration)):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise _blocked("issued session is immutable")

    def __repr__(self) -> str:
        return (f"HostIssuedSession(batch_id={self._receipt.batch_id!r}, "
                f"row_index={self._receipt.row_index}, <credentials redacted>)")

    __str__ = __repr__

    provenance = "HOST_STS_ISSUED"
    live_status = "NOT_VERIFIED"

    @property
    def receipt(self) -> HostIssuanceReceipt:
        return self._receipt

    @property
    def policy_bytes(self) -> bytes:
        return self._policy_bytes

    @property
    def expiration(self) -> datetime:
        return self._expiration

    @property
    def selection(self) -> HostSelection:
        return self._selection

    def client_identity(self, service: str, region: str) -> str:
        return sha256(canonical_bytes([self._receipt.receipt_sha256, service, region])).hexdigest()

    def sdk_client(self, service: str, region: str, *, now_utc: datetime) -> object:
        """Read/write/readback clients from the same explicit triplet and session."""
        require_issued_session(self, self._host, now_utc)
        akid, secret, token = self._triplet
        return self._factory.create(service, region, access_key_id=akid,
                                    secret_access_key=secret, session_token=token)


_SESSION_MINT: Final = object()
_SESSIONS: WeakKeyDictionary = WeakKeyDictionary()
_INTENT_ADMITTED: WeakKeyDictionary = WeakKeyDictionary()
_NAME_BINDINGS: dict[str, tuple[str, str]] = {}


def require_issued_session(issued: object, host: object, now_utc: datetime | None
                           ) -> HostIssuedSession:
    """Only a registered session of this live Host run, unexpired, with a valid receipt."""
    host = require_verified_host(host)
    if (type(issued) is not HostIssuedSession or _SESSIONS.get(issued) is not host
            or issued._host is not host or not verify_receipt(issued._receipt)
            or issued._receipt.run_id != host.run_id or issued._receipt.host_id != host.host_id):
        raise _blocked("session is not a protected Host-issued session")
    if now_utc is not None and require_aware_utc(now_utc) >= issued._expiration:
        raise _blocked("issued session expired")
    return issued


# ---------------------------------------------------------------- RG-PRC-007 issuer
def _canonical_sts_request(role_arn: str, session_name: str, policy_bytes: bytes) -> bytes:
    request = {"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": role_arn,
               "RoleSessionName": session_name, "Policy": policy_bytes.decode("ascii"),
               "DurationSeconds": STS_DURATION_SECONDS}
    return json.dumps(request, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _redacted_response_sha256(response: Mapping[str, object]) -> str:
    """Digest of the actual response with secret values replaced by their own digests."""
    def scrub(value, key=""):
        if isinstance(value, Mapping):
            return {str(k): scrub(v, str(k)) for k, v in sorted(value.items(), key=lambda i: str(i[0]))}
        if isinstance(value, (list, tuple)):
            return [scrub(v) for v in value]
        if key in ("SecretAccessKey", "SessionToken") and isinstance(value, str):
            return "sha256:" + sha256(value.encode()).hexdigest()
        if isinstance(value, datetime):
            return _iso_z(value)
        if value is None or isinstance(value, (bool, int, str)):
            return value
        return repr(value)
    return sha256(json.dumps(scrub(response), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii")).hexdigest()


def _parse_expiration(value: object) -> datetime:
    if type(value) is datetime and value.tzinfo is not None and value.utcoffset() is not None:
        return value.astimezone(timezone.utc)
    return _parse_iso_z(value)


@dataclass(frozen=True)
class _VerifiedResponse:
    triplet: tuple[str, str, str]
    expiration: datetime
    assumed_role_arn: str
    assumed_role_id: str
    utilization: str
    response_sha256: str


def _verify_sts_response(exchange: object, *, request_bytes: bytes, role_arn: str,
                         session_name: str, now: datetime) -> _VerifiedResponse:
    if type(exchange) is not StsExchange or exchange.sent_request_bytes != request_bytes:
        raise _blocked("STS request actually sent differs from the protected request",
                       "AWS_WRITE_BLOCKED")
    response = exchange.response
    if not isinstance(response, Mapping) or not set(response) <= _RESPONSE_KEYS:
        raise _blocked("STS response malformed", "AWS_WRITE_BLOCKED")
    creds, user = response.get("Credentials"), response.get("AssumedRoleUser")
    if not isinstance(creds, Mapping) or not isinstance(user, Mapping):
        raise _blocked("STS response missing identity/credentials", "AWS_WRITE_BLOCKED")
    akid, secret, token = (creds.get("AccessKeyId"), creds.get("SecretAccessKey"),
                           creds.get("SessionToken"))
    if (not isinstance(akid, str) or _TEMP_AKID.fullmatch(akid) is None
            or not isinstance(secret, str) or _SECRET.fullmatch(secret) is None
            or not isinstance(token, str) or _TOKEN.fullmatch(token) is None):
        raise _blocked("STS credential triplet invalid", "AWS_WRITE_BLOCKED")
    try:
        expiration = _parse_expiration(creds.get("Expiration"))
    except ValueError as error:
        raise _blocked("STS expiration invalid", "AWS_WRITE_BLOCKED") from error
    if not now < expiration <= now + timedelta(seconds=STS_DURATION_SECONDS) + _STS_EXPIRY_SKEW:
        raise _blocked("STS expiration outside the bounded duration", "AWS_WRITE_BLOCKED")
    partition, account = role_arn.split(":")[1], role_arn.split(":")[4]
    role_name = role_arn.split("/")[-1]
    expected_arn = f"arn:{partition}:sts::{account}:assumed-role/{role_name}/{session_name}"
    arn, role_id = user.get("Arn"), user.get("AssumedRoleId")
    match = _ASSUMED_ROLE_ID.fullmatch(role_id) if isinstance(role_id, str) else None
    if arn != expected_arn or match is None or match.group("session") != session_name:
        raise _blocked("AssumedRoleUser does not match role/account/partition/session",
                       "AWS_WRITE_BLOCKED")
    utilization = response.get("SessionTokenUtilization", None)
    if utilization is None:
        observed = NOT_OBSERVED
    elif type(utilization) in (int, float) and 0 <= utilization <= 100:
        observed = str(utilization)
    else:
        raise _blocked("SessionTokenUtilization malformed", "AWS_WRITE_BLOCKED")
    return _VerifiedResponse((akid, secret, token), expiration, arn, role_id, observed,
                             _redacted_response_sha256(response))


class HostCredentialIssuer(Protocol):
    def issue(self, batch, subset, host: VerifiedHostContext, now_utc: datetime
              ) -> HostIssuedSession: ...


class HostBatchCredentialIssuer:
    """HostCredentialIssuer: the sole STS credential producer on the protected Host."""

    def __init__(self, *, provider: HostBootstrapCredentialProvider, transport: StsTransport,
                 evidence_gate: IndependentEvidenceGate | None = None,
                 client_factory: ExplicitSdkClientFactory | None = None) -> None:
        if provider is None or transport is None or client_factory is None:
            raise _blocked("no protected Host STS transport/provider/client factory")
        self._provider = provider
        self._transport = transport
        self._gate = evidence_gate or FailClosedEvidenceGate()
        self._factory = client_factory

    @staticmethod
    def _check_name_binding(journal, session_name: str, nonce_sha256: str, batch_id: str) -> None:
        bound = _NAME_BINDINGS.get(session_name)
        if bound is not None and bound != (nonce_sha256, batch_id):
            raise _blocked("derived session name bound to another nonce/Batch",
                           "BLOCKED_AUTH_REPLAY")
        for record in journal.scan():
            if (record["role_session_name"] == session_name
                    and (record["batch_nonce_sha256"], record["batch_id"])
                    != (nonce_sha256, batch_id)):
                raise _blocked("derived session name bound to another nonce/Batch",
                               "BLOCKED_AUTH_REPLAY")

    def issue(self, batch, subset, host: VerifiedHostContext, now_utc: datetime
              ) -> HostIssuedSession:
        from name_tag_batch_host_runtime import (
            ISSUANCE_REFUSED, ISSUANCE_UNRESOLVED, ISSUED_VERIFIED, _current_owner_batch,
            bound_journal, take_selection)
        from name_tag_batch_iam import (
            POLICY_PLAINTEXT_LIMIT, IAMPolicyBlocked, build_subset_session_policy,
            verified_kind_policy)

        # Phase 1 (pre-STS): every check that can be made before the network.
        host = require_verified_host(host)
        now = require_aware_utc(now_utc)
        selection = take_selection(subset, host)  # one-shot, Host-selected only
        fresh = _current_owner_batch(batch, now)
        if (fresh.batch_id != selection.batch.batch_id
                or fresh.canonical_payload_bytes != selection.batch.canonical_payload_bytes):
            raise _blocked("batch differs from the Host selection", "BLOCKED_OWNER_AUTHN")
        authority = selection.row_authority
        kind = authority.row["kind"]
        try:
            expected = build_subset_session_policy(
                fresh, (authority.row_index,),
                kind_registry={kind: verified_kind_policy(selection.capability)})
        except IAMPolicyBlocked as error:
            raise _blocked("selected policy no longer valid", "AWS_WRITE_BLOCKED") from error
        policy = subset.policy_bytes
        if (expected != subset or subset.row_indexes != (authority.row_index,)
                or not policy.isascii() or len(policy) > POLICY_PLAINTEXT_LIMIT
                or sha256(policy).hexdigest() != subset.policy_sha256):
            raise _blocked("policy is not the exact canonical singleton", "AWS_WRITE_BLOCKED")
        role_arn = fresh.payload["authorized_role_arn"]
        if role_arn != host.authorized_role_arn:
            raise _blocked("RoleArn differs from the Host-pinned role")
        nonce = fresh.payload["batch_nonce"]
        session_name = derive_role_session_name(nonce)
        nonce_sha256 = sha256(nonce.encode("ascii")).hexdigest()
        journal = bound_journal(host)
        self._check_name_binding(journal, session_name, nonce_sha256, fresh.batch_id)
        journal.assert_row_unattempted(fresh.batch_id, authority.row_index)
        self._gate.check_pre_sts(selection, now_utc=now)
        creds = require_bootstrap_credentials(self._provider.load(host, now_utc=now), host, now)
        request_bytes = _canonical_sts_request(role_arn, session_name, policy)
        attempt_id = sha256(canonical_bytes([fresh.batch_id, authority.row_index,
                                             host.run_id, os.urandom(16).hex()])).hexdigest()
        pending = journal.create_pending({
            "batch_id": fresh.batch_id, "batch_nonce_sha256": nonce_sha256,
            "plan_sha256": fresh.payload["plan_sha256"], "csv_sha256": fresh.payload["csv_sha256"],
            "row_index": authority.row_index, "row_authority_id": authority.row_authority_id,
            "scope_id": selection.scope_id, "host_id": host.host_id, "run_id": host.run_id,
            "role_arn": role_arn, "role_session_name": session_name,
            "policy_sha256": subset.policy_sha256,
            "name_evidence_sha256": selection.name_evidence_sha256, "attempt_id": attempt_id,
            "created_at_utc": _iso_z(now)})
        # Phase 2: exactly one AssumeRole; no fallback, no retry.
        try:
            exchange = self._transport.assume_role(request_bytes=request_bytes, credentials=creds)
        except StsRefused as refusal:
            journal.finalize(pending, status=ISSUANCE_REFUSED, updated_at_utc=_iso_z(now),
                             refusal_code=refusal.code)
            raise _blocked(f"STS refused: {refusal.code}", "AWS_WRITE_BLOCKED") from None
        except Exception:  # noqa: BLE001 - uncertain network outcome stays unresolved
            self._unresolved(journal, pending, now)
            raise _blocked("STS outcome unresolved", "AWS_WRITE_BLOCKED") from None
        # Phase 3 (post-STS, before Intent): verify the actual response binding.
        try:
            verified = _verify_sts_response(exchange, request_bytes=request_bytes,
                                            role_arn=role_arn, session_name=session_name, now=now)
        except HostRuntimeBlocked:
            self._unresolved(journal, pending, now)
            raise
        receipt = HostIssuanceReceipt(
            batch_id=fresh.batch_id, batch_nonce=nonce, batch_nonce_sha256=nonce_sha256,
            role_session_name=session_name, host_id=host.host_id, run_id=host.run_id,
            row_index=authority.row_index, row_authority_id=authority.row_authority_id,
            scope_id=selection.scope_id, target_arn=authority.row["resource_arn"],
            aws_operation=authority.row["aws_operation"],
            name_evidence_sha256=selection.name_evidence_sha256, role_arn=role_arn,
            request_sha256=sha256(request_bytes).hexdigest(), policy_sha256=subset.policy_sha256,
            response_sha256=verified.response_sha256, assumed_role_arn=verified.assumed_role_arn,
            assumed_role_id=verified.assumed_role_id, account=fresh.payload["account"],
            partition=fresh.payload["partition"], expiration_utc=_iso_z(verified.expiration),
            credential_fingerprint=_credential_fingerprint(*verified.triplet),
            session_token_utilization=verified.utilization, attempt_id=attempt_id,
            issued_at_utc=_iso_z(now))
        _RECEIPT_MACS[receipt.receipt_sha256] = _receipt_mac(receipt)
        journal.finalize(pending, status=ISSUED_VERIFIED, updated_at_utc=_iso_z(now),
                         receipt_sha256=receipt.receipt_sha256,
                         response_sha256=verified.response_sha256)
        _NAME_BINDINGS[session_name] = (nonce_sha256, fresh.batch_id)
        session = HostIssuedSession(
            _mint=_SESSION_MINT, receipt=receipt, policy_bytes=policy, triplet=verified.triplet,
            factory=self._factory, host=host, selection=selection,
            expiration=verified.expiration)
        _SESSIONS[session] = host
        try:
            self._gate.check_issued(session, now_utc=now)  # independent IAM for actual identity
        except BaseException:
            _SESSIONS.pop(session, None)
            raise
        return session

    @staticmethod
    def _unresolved(journal, pending, now: datetime) -> None:
        from name_tag_batch_host_runtime import ISSUANCE_UNRESOLVED

        try:
            journal.finalize(pending, status=ISSUANCE_UNRESOLVED, updated_at_utc=_iso_z(now))
        except HostRuntimeBlocked:
            pass  # the PENDING tombstone still blocks any reissue for this row


def revalidate_issued_before_intent(issued: object, *, ledger: object,
                                    host: VerifiedHostContext, now_utc: datetime):
    """Post-STS, pre-Intent: reread the exact first snapshot and signed authority.

    Returns the fresh VerifiedBatchRowAuthority for the single Task 7 atomic Intent
    admission. Allowed once per issued session; the journal never authorizes a send.
    """
    from name_tag_batch_host_runtime import (
        ISSUED_VERIFIED, _current_owner_batch, _current_row_authority, bound_journal,
        bound_ledger, read_batch_snapshot)

    host = require_verified_host(host)
    now = require_aware_utc(now_utc)
    issued = require_issued_session(issued, host, now)
    if _INTENT_ADMITTED.get(issued):
        raise _blocked("issued session already admitted to Intent", "BLOCKED_INTENT_REPLAY")
    if ledger is not bound_ledger(host):
        raise _blocked("Ledger is not the Host-bound Ledger", "BLOCKED_SCOPE_STATE_UNKNOWN")
    selection, receipt = issued.selection, issued.receipt
    records = bound_journal(host).records_for_row(receipt.batch_id, receipt.row_index)
    if (len(records) != 1 or records[0]["status"] != ISSUED_VERIFIED
            or records[0]["run_id"] != host.run_id or records[0]["attempt_id"] != receipt.attempt_id
            or records[0]["receipt_sha256"] != receipt.receipt_sha256
            or records[0]["row_authority_id"] != receipt.row_authority_id):
        raise _blocked("no exact same-run ISSUED_VERIFIED record")
    fresh = _current_owner_batch(selection.batch, now)
    if fresh.canonical_payload_bytes != selection.batch.canonical_payload_bytes:
        raise _blocked("signed batch changed", "BLOCKED_OWNER_AUTHN")
    snapshot = read_batch_snapshot(ledger, fresh, signed_cap=selection.signed_cap,
                                   row_count=len(fresh.approved_row_indexes))
    if snapshot != selection.snapshot:
        raise _blocked("Ledger state drifted after STS", "BLOCKED_SCOPE_STATE_UNKNOWN")
    for scope_id in sorted({row["writer_control_scope_id"] for row in fresh.approved_rows}):
        try:
            scope_state = ledger.effective_scope_state(scope_id)  # type: ignore[attr-defined]
        except Exception as error:  # noqa: BLE001
            raise _blocked("Scope state unreadable", "BLOCKED_SCOPE_STATE_UNKNOWN") from error
        if scope_state != "CLEARED":
            raise _blocked("signed Scope not CLEARED", "BLOCKED_SCOPE_HOLD")
    authority = _current_row_authority(fresh, receipt.row_index, now)
    if authority.row_authority_id != receipt.row_authority_id:
        raise _blocked("row authority changed after STS", "BLOCKED_OWNER_AUTHN")
    _INTENT_ADMITTED[issued] = True
    return authority
