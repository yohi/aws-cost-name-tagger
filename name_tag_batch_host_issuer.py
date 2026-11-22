"""Host-only protected STS issuer and bootstrap credential provider (Design §§5.1-5.2).

OFFLINE in this phase: no boto3/botocore import, no SDK client and no network. The STS
call goes only through a Host-owned injected ``StsTransport``; the production default
transport is unavailable and fails closed (``AWS_RUNTIME_NOT_AUTHORIZED``). Bootstrap
credentials come only from the verified systemd ``CREDENTIALS_DIRECTORY`` reported for the
service (never the environment hint, profile, IMDS or the SDK default chain).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Final, Protocol
from weakref import WeakKeyDictionary

from name_tag_batch_host_runtime import (
    HostOSProbe, HostRuntimeBlocked, ProtectedFileFacts, VerifiedHostContext, _NonCopyable,
    _blocked, _strict_json, require_aware_utc, require_verified_host)

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
