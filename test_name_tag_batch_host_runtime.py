"""Offline Task 6 Host runtime tests: bootstrap context, issuance tombstones, selector.

Every OS fact, credential file, Ledger and STS exchange here is a Fake double. No systemd,
socket, /var or /run path, network or AWS call is ever made.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import pickle
import stat
import tempfile
import unittest
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from unittest import mock

import name_tag_batch_host_runtime as host_runtime
from name_tag_batch_approval import (
    VerifiedBatchApproval, _approved_tuples, canonical_bytes, prepare_batch_approval)
from name_tag_batch_host_runtime import (
    HostRuntimeBlocked, IssuanceAttemptJournal, SystemdHostBootstrapVerifier,
    UnavailableHostOSProbe, VerifiedHostContext, require_verified_host)
from name_tag_batch_iam import KindPolicy
from name_tag_batch_state import build_batch_review_projection, validate_batch_draft
from name_tag_ledger import BatchExecutionState
from name_tag_ledger_errors import LedgerError
from test_helpers import sample_population

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)
ROLE_ARN = "arn:aws:iam::123456789012:role/Batch"
VOL0 = "arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-0123456789abcdef0"
VOL1 = "arn:aws:ec2:ap-northeast-1:123456789012:volume/vol-abcdef12345678901"
NONCE = "ab" * 16
KIND_REGISTRY = MappingProxyType({"volume": KindPolicy("ec2:CreateTags", "ec2:DescribeVolumes")})
MACHINE_ID = "1" * 32
BOOT_ID = "2" * 32
INVOCATION_ID = "3" * 32
SVC_UID = os.getuid()
SVC_GID = os.getgid()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record(pid: str, vol: str, suffix: str) -> dict:
    vol_id = vol.rsplit("/", 1)[1]
    return {
        "proposal_id": pid, "kind": "volume", "locator": vol_id, "region": "ap-northeast-1",
        "resource_arn": vol, "aws_operation": "ec2:CreateTags", "status": "proposed",
        "confidence": "high", "name_state": "ABSENT", "name_key_present": False,
        "name_raw_value": None, "existing_name": "",
        "proposed_name": f"app-prod-ebs-xvda-{suffix}", "effective_usage_cost_usd": "0.75",
        "evidence": (f"EBS {vol_id} -> attachment i-0123456789abcdef0 xvda -> EC2 "
                     "i-0123456789abcdef0 Name=app-prod; Product(observed, not validated)=(unset)"),
    }


def build_batch(*, cap: int = 2, nonce: str = NONCE, approve=("p0", "p1")) -> VerifiedBatchApproval:
    """Fixture VerifiedBatchApproval over exact Plan/CSV bytes (signature patched in tests)."""
    plan = json.dumps({
        "schema_version": 3, "account": "123456789012", "partition": "aws",
        "execution_limits": {"max_send_attempts": cap},
        "cur_population": sample_population(count=2, cost="1.5"), "count": 2,
        "scope_declarations": [{
            "writer_control_scope_id": "s1", "account": "123456789012", "partition": "aws",
            "region": "ap-northeast-1", "resource_arns": [VOL0, VOL1]}],
        "records": [_record("p0", VOL0, "abcdef0"), _record("p1", VOL1, "5678901")],
    }).encode()
    csv = build_batch_review_projection(plan)
    for pid in approve:
        csv = csv.replace(f",{pid},".encode(), f"YES,{pid},".encode())
    draft = validate_batch_draft(plan, csv)
    prepared = prepare_batch_approval(
        plan, csv, owner_principal_id="owner", owner_key_fingerprint="SHA256:key",
        authorized_role_arn=ROLE_ARN, issued_at_utc="2026-11-19T00:00:00Z",
        expires_at_utc="2026-11-20T00:00:00Z", batch_nonce=nonce)
    indexes = tuple(row[0] for row in _approved_tuples(draft))
    return VerifiedBatchApproval(
        b"fixture-envelope", prepared.canonical_payload_bytes, prepared.batch_id,
        MappingProxyType(dict(prepared.payload)), plan, csv,
        tuple(MappingProxyType(dict(r)) for r in draft.approved_rows), indexes,
        "owner", "fixture-signature")


@contextlib.contextmanager
def owner_verified():
    """Test-only: stand in for the real OpenSSH OwnerTrust verification (not exercised here)."""
    with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                           return_value=object()), \
            mock.patch("name_tag_batch_approval.revalidate_verified_batch",
                       side_effect=lambda batch, **_: batch):
        yield


# ---------------------------------------------------------------- Fake OS / Ledger
@dataclass
class FakeFile:
    facts: host_runtime.ProtectedFileFacts
    data: bytes = b""


class FakeHostOS:
    """Injected OS probe double. It reports facts; it never touches systemd or /run."""

    def __init__(self, state_dir: str, invocation_id: str = INVOCATION_ID) -> None:
        self.state_dir = state_dir
        self.cred_dir = "/fake-run/credentials/aws-cnt-batch.service"
        self.files: dict[str, FakeFile] = {}
        self.properties = dict(host_runtime.REQUIRED_UNIT_PROPERTIES)
        self.process = host_runtime.HostProcessFacts(
            platform="linux", init_system="systemd", pid=os.getpid(), uid=SVC_UID,
            gid=SVC_GID, user_name="aws-cnt", cgroup=host_runtime.SERVICE_CGROUP,
            unit_name=host_runtime.SERVICE_UNIT, unit_main_pid=os.getpid(),
            unit_active_state="active", invocation_id=invocation_id, boot_id=BOOT_ID,
            machine_id=MACHINE_ID, unit_properties=MappingProxyType(self.properties),
            credentials_directory=self.cred_dir)
        immutable = {}
        for role in ("unit", "executable", "config", "owner_trust", "scope_evidence"):
            path = f"/fake-etc/aws-cnt/{role}"
            data = f"pinned {role}".encode()
            self.add_file(path, data, owner=0, mode=0o644)
            immutable[role] = {"path": path, "sha256": _sha(data)}
        self.ledger_path = state_dir + "/ledger.sqlite"
        self.manifest = {
            "schema": "aws-cnt-host-manifest-v1", "immutable_files": immutable,
            "state_directory": state_dir, "ledger_path": self.ledger_path,
            "authorized_role_arn": ROLE_ARN,
        }
        self.manifest_path = "/fake-etc/aws-cnt/manifest.json"
        self.write_manifest()
        self.add_dir(state_dir, owner=SVC_UID, mode=0o700)
        self.add_file(self.ledger_path, b"", owner=SVC_UID, mode=0o600, digest=None)
        self.add_dir(self.cred_dir, owner=SVC_UID, mode=0o500)

    def write_manifest(self) -> None:
        data = canonical_bytes(self.manifest)
        self.add_file(self.manifest_path, data, owner=0, mode=0o644)
        self.manifest_sha256 = _sha(data)

    def add_file(self, path, data, *, owner, mode, digest="auto", symlink_free=True):
        self.files[path] = FakeFile(host_runtime.ProtectedFileFacts(
            path=path, file_type="file", owner_uid=owner, group_gid=0, mode=mode,
            symlink_free=symlink_free, sha256=_sha(data) if digest == "auto" else digest), data)

    def add_dir(self, path, *, owner, mode, symlink_free=True):
        self.files[path] = FakeFile(host_runtime.ProtectedFileFacts(
            path=path, file_type="dir", owner_uid=owner, group_gid=0, mode=mode,
            symlink_free=symlink_free, sha256=None))

    def process_facts(self):
        return self.process

    def file_facts(self, path):
        try:
            return self.files[path].facts
        except KeyError:
            raise FileNotFoundError(path) from None

    def read_protected(self, path):
        try:
            return self.files[path].data
        except KeyError:
            raise FileNotFoundError(path) from None


class FakeLedger:
    """Ledger double returning the real BatchExecutionState type; never a real database."""

    def __init__(self) -> None:
        self.state: object = None
        self.error: Exception | None = None
        self.scope_states: dict[str, str] = {"s1": "CLEARED"}
        self.calls: list[str] = []

    def batch_execution_state(self, batch):
        self.calls.append("batch_execution_state")
        if self.error is not None:
            raise self.error
        return self.state

    def effective_scope_state(self, scope_id):
        return self.scope_states.get(scope_id, "UNKNOWN")

    def create_batch_intent(self, *args, **kwargs):  # pragma: no cover - must never run
        self.calls.append("create_batch_intent")
        raise AssertionError("Task 6 never opens an Intent")


@dataclass
class HostFixture:
    tmp: tempfile.TemporaryDirectory
    os: FakeHostOS
    ledger: FakeLedger
    events: list = field(default_factory=list)
    verifier: SystemdHostBootstrapVerifier | None = None

    def fsync(self, fd):
        mode = os.fstat(fd).st_mode
        self.events.append("fsync_dir" if stat.S_ISDIR(mode) else "fsync_file")
        os.fsync(fd)

    def verify(self):
        return self.verifier.verify_process(now_utc=NOW)

    def repin(self) -> None:
        """Root re-provisions the manifest and its pin (test-only Host acceptance step)."""
        self.os.write_manifest()
        self.verifier = SystemdHostBootstrapVerifier(
            probe=self.os, manifest_path=self.os.manifest_path,
            manifest_sha256=self.os.manifest_sha256,
            ledger_opener=lambda path: self.ledger, fsync=self.fsync)

    @property
    def state_dir(self) -> str:
        return self.os.state_dir


def host_fixture(testcase: unittest.TestCase, *, restart_of: HostFixture | None = None
                 ) -> HostFixture:
    """A Fake Host; ``restart_of`` simulates a Host restart over the same StateDirectory."""
    if restart_of is None:
        tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(tmp.cleanup)
        state_dir = str(Path(tmp.name) / "state")
        os.mkdir(state_dir, 0o700)
    else:
        tmp, state_dir = restart_of.tmp, restart_of.state_dir
    fake_os = FakeHostOS(state_dir, INVOCATION_ID if restart_of is None else "4" * 32)
    fixture = HostFixture(tmp, fake_os, FakeLedger())
    if restart_of is not None:
        fixture.events = restart_of.events
    fixture.repin()
    return fixture


# ---------------------------------------------------------------- bootstrap
class HostBootstrapTests(unittest.TestCase):
    def test_host_bootstrap_validated_systemd_context_mock(self):
        fx = host_fixture(self)
        host = fx.verify()
        self.assertIs(type(host), VerifiedHostContext)
        self.assertIs(require_verified_host(host), host)
        self.assertEqual(host.service_unit, "aws-cnt-batch.service")
        self.assertEqual(host.run_id, INVOCATION_ID)
        self.assertEqual(host.authorized_role_arn, ROLE_ARN)
        self.assertEqual(host.manifest_sha256, fx.os.manifest_sha256)
        self.assertEqual(host.live_status, "NOT_VERIFIED")
        self.assertIs(host_runtime.bound_ledger(host), fx.ledger)

    def test_forged_uid_cgroup_unit_or_manifest_rejected(self):
        forgeries = [
            lambda o: setattr(o, "process", replace(o.process, uid=0)),
            lambda o: setattr(o, "process", replace(o.process, uid=SVC_UID + 1)),
            lambda o: setattr(o, "process", replace(o.process, user_name="root")),
            lambda o: setattr(o, "process", replace(o.process, cgroup="/user.slice/x.scope")),
            lambda o: setattr(o, "process", replace(o.process, unit_name="other.service")),
            lambda o: setattr(o, "process", replace(o.process, unit_main_pid=1)),
            lambda o: setattr(o, "process", replace(o.process, init_system="openrc")),
            lambda o: setattr(o, "process", replace(o.process, platform="darwin")),
            lambda o: setattr(o, "process", replace(o.process, boot_id="xyz")),
            lambda o: o.properties.update(NoNewPrivileges="no"),
            lambda o: o.properties.pop("ProtectSystem"),
            lambda o: o.add_file(o.manifest["immutable_files"]["executable"]["path"],
                                 b"drifted", owner=0, mode=0o644),
            lambda o: o.add_file(o.manifest["immutable_files"]["config"]["path"],
                                 b"pinned config", owner=SVC_UID, mode=0o644),
            lambda o: o.add_file(o.manifest["immutable_files"]["unit"]["path"],
                                 b"pinned unit", owner=0, mode=0o666),
            lambda o: o.add_file(o.manifest["immutable_files"]["owner_trust"]["path"],
                                 b"pinned owner_trust", owner=0, mode=0o644, symlink_free=False),
            lambda o: o.add_file(o.manifest_path, o.files[o.manifest_path].data + b" ",
                                 owner=0, mode=0o644),
            lambda o: o.add_dir(o.state_dir, owner=SVC_UID, mode=0o770),
            lambda o: o.add_file(o.ledger_path, b"", owner=SVC_UID, mode=0o644, digest=None),
            lambda o: o.add_dir(o.cred_dir, owner=SVC_UID + 1, mode=0o500),
        ]
        for n, forge in enumerate(forgeries):
            with self.subTest(n=n):
                fx = host_fixture(self)
                forge(fx.os)
                with self.assertRaises(HostRuntimeBlocked) as caught:
                    fx.verify()
                self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_manifest_with_swapped_pin_rejected(self):
        fx = host_fixture(self)
        fx.os.manifest["authorized_role_arn"] = "arn:aws:iam::123456789012:role/Other"
        fx.os.write_manifest()  # attacker rewrites manifest; the root pin stays the original
        with self.assertRaises(HostRuntimeBlocked):
            fx.verify()

    def test_env_or_dataclass_cannot_forge_host_context(self):
        fx = host_fixture(self)
        genuine = fx.verify()
        fields = {name: getattr(genuine, name) for name in VerifiedHostContext.__slots__
                  if not name.startswith("__")}
        forged = VerifiedHostContext(**fields)
        with mock.patch.dict(os.environ, {"AWS_CNT_TRUSTED_HOST": "1",
                                          "CREDENTIALS_DIRECTORY": "/tmp/x",
                                          "INVOCATION_ID": INVOCATION_ID}):
            for candidate in (forged, object(), None):
                with self.assertRaises(HostRuntimeBlocked):
                    require_verified_host(candidate)
        with self.assertRaises(HostRuntimeBlocked):
            copy.copy(genuine)
        with self.assertRaises(HostRuntimeBlocked):
            copy.deepcopy(genuine)
        with self.assertRaises(HostRuntimeBlocked):
            pickle.dumps(genuine)
        object.__setattr__(genuine, "run_id", "4" * 32)  # in-place tamper of a genuine context
        with self.assertRaises(HostRuntimeBlocked):
            require_verified_host(genuine)

    def test_host_service_not_installed_or_started_by_offline_tests(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("subprocess")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("subprocess")), \
                mock.patch("socket.socket", side_effect=AssertionError("socket")):
            fx = host_fixture(self)
            fx.verify()
            production = SystemdHostBootstrapVerifier(
                probe=UnavailableHostOSProbe(), manifest_path="/etc/aws-cnt/manifest.json",
                manifest_sha256="0" * 64)
            with self.assertRaises(HostRuntimeBlocked) as caught:
                production.verify_process(now_utc=NOW)
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")
        self.assertFalse(Path("/run/aws-cnt/host.sock").exists())

    def test_production_default_probe_fails_closed(self):
        verifier = host_runtime.production_bootstrap_verifier()
        with self.assertRaises(HostRuntimeBlocked) as caught:
            verifier.verify_process(now_utc=NOW)
        self.assertEqual(caught.exception.code, "AWS_RUNTIME_NOT_AUTHORIZED")

    def test_naive_time_and_corrupt_existing_tombstone_block_startup(self):
        fx = host_fixture(self)
        with self.assertRaises(HostRuntimeBlocked):
            fx.verifier.verify_process(now_utc=NOW.replace(tzinfo=None))
        root = Path(fx.os.state_dir) / "issuance-attempts" / ("a" * 64)
        root.mkdir(parents=True, mode=0o700)
        os.chmod(root.parent, 0o700)
        (root / f"0-{'b' * 64}.json").write_text("{not json")
        os.chmod(root / f"0-{'b' * 64}.json", 0o600)
        with self.assertRaises(HostRuntimeBlocked):
            fx.verify()


def state(name="UNREGISTERED", consumed=0, cap=2, outcomes=("UNCLAIMED", "UNCLAIMED")):
    return BatchExecutionState(name, consumed, cap, tuple(outcomes))


# ---------------------------------------------------------------- RG-PRC-005 selector
class SelectorTests(unittest.TestCase):
    def setUp(self):
        self.fx = host_fixture(self)
        self.host = self.fx.verify()
        self.batch = build_batch()
        self.fx.ledger.state = state()

    def select(self, batch=None, *, ledger=None, registry=KIND_REGISTRY, host=None):
        with owner_verified():
            return host_runtime.select_next_sts_subset(
                batch or self.batch, ledger=ledger or self.fx.ledger, kind_registry=registry,
                host=host or self.host, now_utc=NOW)

    def assertBlocked(self, code=None, **kwargs):
        with self.assertRaises(HostRuntimeBlocked) as caught:
            self.select(**kwargs)
        if code is not None:
            self.assertEqual(caught.exception.code, code)
        self.assertNotIn("create_batch_intent", self.fx.ledger.calls)
        return caught.exception

    def test_first_unregistered_selects_signed_singleton(self):
        from name_tag_batch_iam import build_subset_session_policy
        spec = self.select()
        self.assertEqual(spec.row_indexes, (0,))
        expected = build_subset_session_policy(self.batch, (0,), kind_registry=KIND_REGISTRY)
        self.assertEqual(spec, expected)
        self.assertEqual(spec.policy_sha256, hashlib.sha256(spec.policy_bytes).hexdigest())
        selection = host_runtime.peek_selection(spec, self.host)
        self.assertEqual(selection.snapshot, state())
        self.assertEqual(selection.row_authority.row_index, 0)
        self.assertEqual(self.fx.ledger.calls, ["batch_execution_state"])  # read-only preflight

    def test_unregistered_nonce_collision_or_claim_denied(self):
        self.fx.ledger.error = LedgerError("BLOCKED_AUTH_REPLAY")
        self.assertBlocked("BLOCKED_AUTH_REPLAY")

    def test_unregistered_scope_hold_or_incomplete_intent_denied(self):
        for scope_state in ("HOLD", "UNKNOWN"):  # Ledger reports HOLD for a pending Intent too
            with self.subTest(scope_state=scope_state):
                self.fx.ledger.scope_states["s1"] = scope_state
                self.assertBlocked("BLOCKED_SCOPE_HOLD")

    def test_corrupt_ledger_never_fabricates_unregistered(self):
        fabricated = [
            LedgerError("BLOCKED_SCOPE_STATE_UNKNOWN"),
            mock.Mock(state="UNREGISTERED", send_attempts_consumed=0, max_send_attempts=2,
                      outcomes=("UNCLAIMED", "UNCLAIMED")),
            None,
            state(consumed=1),
            state(cap=3),
            state(outcomes=("UNCLAIMED",)),
            state(outcomes=("UNCLAIMED", "APPLIED_VERIFIED")),
            state(name="BOGUS"),
        ]
        for n, value in enumerate(fabricated):
            with self.subTest(n=n):
                if isinstance(value, Exception):
                    self.fx.ledger.error, self.fx.ledger.state = value, None
                else:
                    self.fx.ledger.error, self.fx.ledger.state = None, value
                self.assertBlocked()
        self.fx.ledger.error, self.fx.ledger.state = None, state()
        self.assertBlocked(ledger=FakeLedger())  # a Ledger not bound by the Host bootstrap

    def test_active_batch_reconciles_cap_and_prior_rows(self):
        self.fx.ledger.state = state("ACTIVE", 1, outcomes=("APPLIED_VERIFIED", "UNCLAIMED"))
        self.assertEqual(self.select().row_indexes, (1,))
        self.fx.ledger.state = state("ACTIVE", 0, outcomes=("SKIPPED_NAME_CHANGED", "UNCLAIMED"))
        self.assertEqual(self.select().row_indexes, (1,))
        self.fx.ledger.state = state("ACTIVE", 1, cap=1, outcomes=("APPLIED_VERIFIED", "UNCLAIMED"))
        self.assertBlocked("SIGNED_CAP_REACHED", batch=build_batch(cap=1))  # no STS/new Intent
        for unresolved in ("WRITE_INTENT_RECORDED", "SEND_ATTEMPT_CONSUMED", "OUTCOME_UNKNOWN"):
            with self.subTest(unresolved=unresolved):
                self.fx.ledger.state = state("ACTIVE", 1, outcomes=(unresolved, "UNCLAIMED"))
                self.assertBlocked()  # never skip past an unresolved row
        self.fx.ledger.state = state("ACTIVE", 1, cap=2, outcomes=("APPLIED_VERIFIED", "APPLIED_VERIFIED"))
        self.assertBlocked()  # counter inconsistent with durable outcomes

    def test_stopped_replay_batch_no_sts(self):
        for name in ("STOPPED", "COMPLETED"):
            with self.subTest(state=name):
                self.fx.ledger.state = state(name, 1, outcomes=("APPLIED_VERIFIED", "NOT_ATTEMPTED_BATCH_STOP"))
                self.assertBlocked("BLOCKED_AUTH_REPLAY")

    def test_owner_revalidation_failure_blocks_before_ledger(self):
        from name_tag_batch_approval import BatchAuthRejected
        with mock.patch.object(host_runtime, "load_current_protected_owner_trust",
                               return_value=object()), \
                mock.patch("name_tag_batch_approval.revalidate_verified_batch",
                           side_effect=BatchAuthRejected()):
            with self.assertRaises(HostRuntimeBlocked) as caught:
                host_runtime.select_next_sts_subset(
                    self.batch, ledger=self.fx.ledger, kind_registry=KIND_REGISTRY,
                    host=self.host, now_utc=NOW)
        self.assertEqual(caught.exception.code, "BLOCKED_OWNER_AUTHN")
        self.assertEqual(self.fx.ledger.calls, [])

    def test_forged_indexes_registry_or_host_rejected(self):
        forged = replace(self.batch, approved_row_indexes=(1, 0))
        self.assertBlocked(batch=forged)
        self.assertBlocked(registry={})
        self.assertBlocked(registry={"volume": KindPolicy("ec2:*", "ec2:DescribeVolumes")})
        self.assertBlocked(host=object())

    def test_selection_is_host_bound_and_one_shot(self):
        spec = self.select()
        other = host_fixture(self).verify()
        with self.assertRaises(HostRuntimeBlocked):
            host_runtime.take_selection(spec, other)
        copy_spec = replace(spec)
        with self.assertRaises(HostRuntimeBlocked):
            host_runtime.take_selection(copy_spec, self.host)
        self.assertIsNotNone(host_runtime.take_selection(spec, self.host))
        with self.assertRaises(HostRuntimeBlocked):
            host_runtime.take_selection(spec, self.host)


if __name__ == "__main__":
    unittest.main()
