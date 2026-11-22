"""Offline Task 6 Host issuer tests. Fake OS/credential/STS transports only; zero network."""
from __future__ import annotations

import contextlib
import copy
import json
import os
import pickle
import unittest
from unittest import mock

import name_tag_batch_host_issuer as issuer_module
from name_tag_batch_host_issuer import (
    ProtectedBootstrapCredentials, SystemdEncryptedCredentialProvider)
from name_tag_batch_host_runtime import HostRuntimeBlocked
from test_name_tag_batch_host_runtime import NOW, SVC_UID, host_fixture

AKID = "ASIA" + "A" * 16
SECRET = "S" * 40
TOKEN = "T" * 300
CRED_FILE = "aws-bootstrap.json"


def _cred_bytes(**changes) -> bytes:
    body = {"AccessKeyId": AKID, "SecretAccessKey": SECRET, "SessionToken": TOKEN,
            "Expiration": "2026-11-19T13:00:00Z"}
    body.update(changes)
    return json.dumps({k: v for k, v in body.items() if v is not None}).encode()


def install_credentials(fx, data: bytes | None = None, *, owner=SVC_UID, mode=0o400,
                        symlink_free=True) -> None:
    fx.os.add_file(fx.os.cred_dir + "/" + CRED_FILE, _cred_bytes() if data is None else data,
                   owner=owner, mode=mode, symlink_free=symlink_free)


@contextlib.contextmanager
def no_ambient_sdk():
    """Any attempt to build an SDK client/session from ambient configuration fails loudly."""
    boom = AssertionError("ambient SDK credential chain used")
    with mock.patch("boto3.client", side_effect=boom), \
            mock.patch("boto3.resource", side_effect=boom), \
            mock.patch("boto3.session.Session", side_effect=boom), \
            mock.patch("botocore.session.Session", side_effect=boom), \
            mock.patch("botocore.session.get_session", side_effect=boom), \
            mock.patch.dict(os.environ, {"AWS_ACCESS_KEY_ID": "AKIAAMBIENTAMBIENT00",
                                         "AWS_SECRET_ACCESS_KEY": "ambient-secret",
                                         "AWS_PROFILE": "ambient",
                                         "CREDENTIALS_DIRECTORY": "/tmp/attacker"}):
        yield


class BootstrapCredentialTests(unittest.TestCase):
    def setUp(self):
        self.fx = host_fixture(self)
        self.provider = SystemdEncryptedCredentialProvider(probe=self.fx.os)

    def test_loads_exact_short_lived_triplet_from_verified_directory(self):
        install_credentials(self.fx)
        host = self.fx.verify()
        creds = self.provider.load(host, now_utc=NOW)
        self.assertIs(type(creds), ProtectedBootstrapCredentials)
        self.assertEqual(creds.access_key_id, AKID)
        self.assertNotIn(SECRET, repr(creds))
        self.assertNotIn(TOKEN, repr(creds))
        for attempt in (copy.copy, copy.deepcopy, pickle.dumps):
            with self.assertRaises(HostRuntimeBlocked):
                attempt(creds)

    def test_encrypted_credential_missing_expired_or_substituted_denied(self):
        cases = {
            "missing": None,
            "expired": dict(data=_cred_bytes(Expiration="2026-11-19T11:59:00Z")),
            "too_long_lived": dict(data=_cred_bytes(Expiration="2026-11-21T12:00:00Z")),
            "long_term_key": dict(data=_cred_bytes(AccessKeyId="AKIA" + "A" * 16)),
            "extra_field": dict(data=_cred_bytes(Region="us-east-1")),
            "missing_token": dict(data=_cred_bytes(SessionToken=None)),
            "duplicate_key": dict(data=b'{"AccessKeyId":"x","AccessKeyId":"y"}'),
            "wrong_owner": dict(owner=SVC_UID + 1),
            "group_readable": dict(mode=0o440),
            "symlink": dict(symlink_free=False),
        }
        for name, case in cases.items():
            with self.subTest(case=name):
                fx = host_fixture(self)
                if case is not None:
                    install_credentials(fx, **case)
                host = fx.verify()
                provider = SystemdEncryptedCredentialProvider(probe=fx.os)
                with self.assertRaises(HostRuntimeBlocked) as caught:
                    provider.load(host, now_utc=NOW)
                self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_environment_directory_hint_is_never_authority(self):
        host = self.fx.verify()
        self.fx.os.add_file("/tmp/attacker/" + CRED_FILE, _cred_bytes(), owner=SVC_UID, mode=0o400)
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/tmp/attacker"}):
            with self.assertRaises(HostRuntimeBlocked):
                self.provider.load(host, now_utc=NOW)

    def test_unverified_host_cannot_load_credentials(self):
        install_credentials(self.fx)
        with self.assertRaises(HostRuntimeBlocked):
            self.provider.load(object(), now_utc=NOW)  # type: ignore[arg-type]

    def test_default_credential_chain_never_used(self):
        install_credentials(self.fx)
        with no_ambient_sdk():
            host = self.fx.verify()
            creds = self.provider.load(host, now_utc=NOW)
        self.assertEqual(creds.access_key_id, AKID)
        self.assertFalse(hasattr(issuer_module, "boto3"))


if __name__ == "__main__":
    unittest.main()
