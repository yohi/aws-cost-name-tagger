"""G2-I1-B D2: SYNTHETIC single-authority egress contract. NO AWS/network.

No botocore, socket, credential, or real transport is present. This models
per-Grant ordering, cancellation, fencing and crash-unknown transitions only.
Passing its tests cannot establish physical HTTP/TLS/OS egress safety.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any


class OfflineContractError(ValueError):
    """Malformed synthetic contract or invalid test fixture."""


class SimulatedTransportCrash(Exception):
    """Only injected by the fixed offline transport."""


class SimulatedGrantCancelled(Exception):
    """Synthetic cancellation won the start-event race."""


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    plan_sha256: str
    context_id: str
    request_fingerprint: str
    epoch: int


@dataclass(frozen=True)
class SyntheticFencingEvidence:
    """Synthetic post-revocation fencing witness, NOT authentic AWS/OS proof."""

    grant_id: str
    gateway_id: str
    revoke_request_seq: int
    fenced_epoch: int
    evidence_id: str


class SyntheticTransport:
    """Fixed synthetic transport; increments a counter, NEVER sends bytes.

    gate_entered / gate_release are trusted test-only threading Events that
    allow a deterministic cancellation race while SAES holds its lock.
    """

    def __init__(self, outcome: str = "OK", *,
                 gate_entered: threading.Event | None = None,
                 gate_release: threading.Event | None = None,
                 pre_start_entered: threading.Event | None = None,
                 pre_start_release: threading.Event | None = None,
                 pre_mark_entered: threading.Event | None = None,
                 pre_mark_release: threading.Event | None = None):
        if outcome not in ("OK", "THROTTLED", "CRASH_BEFORE_START",
                           "CRASH_AFTER_START"):
            raise OfflineContractError("Unsupported fixed simulation outcome")
        if (gate_entered is None) != (gate_release is None):
            raise OfflineContractError("Both concurrency barriers are required")
        if gate_entered is not None and (
                type(gate_entered) is not type(threading.Event())
                or type(gate_release) is not type(threading.Event())):
            raise OfflineContractError("Trusted threading.Event barriers only")
        if (pre_start_entered is None) != (pre_start_release is None):
            raise OfflineContractError("Both pre-start barriers required")
        if pre_start_entered is not None and (
                type(pre_start_entered) is not type(threading.Event())
                or type(pre_start_release) is not type(threading.Event())):
            raise OfflineContractError("Trusted pre-start barriers only")
        if (pre_mark_entered is None) != (pre_mark_release is None):
            raise OfflineContractError("Both pre-mark barriers required")
        if pre_mark_entered is not None and (
                type(pre_mark_entered) is not type(threading.Event())
                or type(pre_mark_release) is not type(threading.Event())):
            raise OfflineContractError("Trusted pre-mark barriers only")
        self.pre_mark_entered = pre_mark_entered
        self.pre_mark_release = pre_mark_release
        self.pre_start_entered = pre_start_entered
        self.pre_start_release = pre_start_release
        self.outcome = outcome
        self.gate_entered = gate_entered
        self.gate_release = gate_release
        self.physical_send_count = 0

    def before_start(self) -> None:
        """Synthetic barrier AFTER admission and BEFORE first send."""
        if self.pre_start_entered is not None:
            self.pre_start_entered.set()
            if not self.pre_start_release.wait(timeout=5):
                raise SimulatedTransportCrash("Pre-start barrier timeout")

    def send_once(self, mark_send_started) -> str:
        """Atomically mark the first synthetic byte before post-start barrier."""
        if self.outcome == "CRASH_BEFORE_START":
            raise SimulatedTransportCrash("Unknown before I/O observation")
        if self.pre_mark_entered is not None:
            self.pre_mark_entered.set()
            if not self.pre_mark_release.wait(timeout=5):
                raise SimulatedTransportCrash("Pre-mark barrier timed out")
        mark_send_started()
        if self.gate_entered is not None:
            self.gate_entered.set()
            if not self.gate_release.wait(timeout=5):
                raise SimulatedTransportCrash("Synthetic barrier timed out")
        if self.outcome == "CRASH_AFTER_START":
            raise SimulatedTransportCrash("Unknown after I/O began")
        return self.outcome


class OfflineSAES:
    """In-memory simulation of one Grant authority and one egress sequencer.

    The lock is the synthetic serialization domain. In an actual distributed
    runtime, durable consensus, OS egress isolation and leader fencing remain
    entirely UNPROVEN. This class must never be used as a runtime adapter.
    """

    def __init__(self, *, grant_id: str, plan_sha256: str, context_id: str,
                 gateway_id: str, expires_at_tick: int, max_sends: int):
        for x in (grant_id, plan_sha256, context_id, gateway_id):
            if type(x) is not str or not x or len(x) > 256:
                raise OfflineContractError("Invalid synthetic identifier")
        if (type(expires_at_tick) is not int or expires_at_tick <= 0
                or type(max_sends) is not int or max_sends <= 0):
            raise OfflineContractError("Invalid synthetic expiration or budget")
        self.grant_id = grant_id
        self.plan_sha256 = plan_sha256
        self.context_id = context_id
        self.gateway_id = gateway_id
        self.expires_at_tick = expires_at_tick
        self.max_sends = max_sends
        self._lock = threading.RLock()
        self._event_lock = threading.RLock()
        self._cancel_requested = threading.Event()
        self._epoch = 0
        self._state = "ACTIVE"
        self._attempts: dict[str, str] = {}
        self._bindings: dict[str, tuple[str, str, str, str, int]] = {}
        self._revoke_request_seq: int | None = None
        self._synthetic_fencing_witness: SyntheticFencingEvidence | None = None
        self._records: list[dict[str, Any]] = []
        self._known_started = 0
        self._gateway_fencing_proven = True

    def _record(self, kind: str, attempt_id: str | None = None) -> int:
        with self._event_lock:
            self._records.append({
                "seq": len(self._records) + 1, "kind": kind,
                "grant_id": self.grant_id, "attempt_id": attempt_id,
                "revocation_epoch": self._epoch,
                "gateway_id": self.gateway_id,
                "provenance": "SYNTHETIC_IN_MEMORY_NOT_DURABLE",
            })
            return len(self._records)

    @property
    def ledger(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(record) for record in self._records)

    @property
    def revoke_request_seq(self) -> int | None:
        with self._event_lock:
            return self._revoke_request_seq

    @property
    def cancel_requested(self) -> bool:
        return self._cancel_requested.is_set()

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def known_started(self) -> int:
        with self._lock:
            return self._known_started

    def _grant_valid(self, tick: int) -> bool:
        return (type(tick) is int and tick >= 0
                and tick < self.expires_at_tick
                and self._state == "ACTIVE"
                and not self._cancel_requested.is_set()
                and self._gateway_fencing_proven)

    @staticmethod
    def _identity(attempt: Attempt) -> tuple[str, str, str, str, int]:
        return (attempt.attempt_id, attempt.plan_sha256, attempt.context_id,
                attempt.request_fingerprint, attempt.epoch)

    def queue_attempt(self, attempt: Attempt, *, tick: int) -> str:
        if type(attempt) is not Attempt:
            raise OfflineContractError("Exact synthetic Attempt required")
        if any(type(v) is not str or not v for v in (
                attempt.attempt_id, attempt.plan_sha256,
                attempt.context_id, attempt.request_fingerprint)) or type(attempt.epoch) is not int:
            raise OfflineContractError("Invalid synthetic request")
        with self._lock:
            if not self._grant_valid(tick):
                self._record("STOP_GRANT", attempt.attempt_id)
                return "STOP_GRANT"
            if (attempt.plan_sha256 != self.plan_sha256
                    or attempt.context_id != self.context_id
                    or attempt.epoch != self._epoch):
                self._record("STOP_POLICY", attempt.attempt_id)
                return "STOP_POLICY"
            if attempt.attempt_id in self._attempts:
                self._record("STOP_DUPLICATE", attempt.attempt_id)
                return "STOP_DUPLICATE"
            self._attempts[attempt.attempt_id] = "QUEUED"
            self._bindings[attempt.attempt_id] = self._identity(attempt)
            self._record("SEND_REQUESTED", attempt.attempt_id)
            return "QUEUED"

    def send_once(self, attempt: Attempt, transport: SyntheticTransport,
                  *, gateway_id: str, tick: int) -> str:
        if type(attempt) is not Attempt or type(transport) is not SyntheticTransport:
            raise OfflineContractError("Only exact fixed offline simulation objects")
        with self._lock:
            if (gateway_id != self.gateway_id
                    or not self._grant_valid(tick)
                    or attempt.epoch != self._epoch):
                self._record("STOP_GRANT", attempt.attempt_id)
                return "STOP_GRANT"
            if (attempt.plan_sha256 != self.plan_sha256
                    or attempt.context_id != self.context_id):
                self._record("STOP_POLICY", attempt.attempt_id)
                return "STOP_POLICY"
            if self._attempts.get(attempt.attempt_id) != "QUEUED":
                self._record("STOP_UNQUEUED", attempt.attempt_id)
                return "STOP_UNQUEUED"
            if self._bindings.get(attempt.attempt_id) != self._identity(attempt):
                self._attempts[attempt.attempt_id] = "REJECTED_BINDING"
                self._record("STOP_BINDING_MISMATCH", attempt.attempt_id)
                return "STOP_BINDING_MISMATCH"
            if self._known_started >= self.max_sends:
                self._record("STOP_BUDGET", attempt.attempt_id)
                return "STOP_BUDGET"
            self._record("SEND_ADMITTED", attempt.attempt_id)
            self._record("SEND_INTENT", attempt.attempt_id)
            # Atomicity here is an *in-memory model*, not an OS proof.
            # No lock is released between authorization and send simulation.
            self._attempts[attempt.attempt_id] = "STARTING"
            try:
                transport.before_start()
            except SimulatedTransportCrash:
                self._attempts[attempt.attempt_id] = "SEND_OUTCOME_UNKNOWN"
                self._state = "SUSPENDED"
                self._record("SEND_OUTCOME_UNKNOWN", attempt.attempt_id)
                return "SEND_OUTCOME_UNKNOWN"
            if self._cancel_requested.is_set():
                self._attempts[attempt.attempt_id] = "CANCELLED_BEFORE_SEND"
                self._record("CANCELLED_BEFORE_SEND", attempt.attempt_id)
                return "STOP_GRANT"
            def mark_first_byte() -> None:
                # Synthetic send linearization: counter and SEND_STARTED are
                # under the same event lock, before the post-start barrier.
                with self._event_lock:
                    transport.physical_send_count += 1
                    self._known_started += 1
                    self._attempts[attempt.attempt_id] = "STARTED"
                    self._record("SEND_STARTED", attempt.attempt_id)

            try:
                outcome = transport.send_once(mark_first_byte)
            except SimulatedTransportCrash:
                self._attempts[attempt.attempt_id] = "SEND_OUTCOME_UNKNOWN"
                self._state = "SUSPENDED"
                self._record("SEND_OUTCOME_UNKNOWN", attempt.attempt_id)
                return "SEND_OUTCOME_UNKNOWN"
            self._record("RESPONSE_" + outcome, attempt.attempt_id)
            return outcome

    def revoke(self) -> str:
        """Request cancellation; NEVER emit success ACK without fencing evidence.

        Repeated calls do not reset the unproven state or create new proofs.
        """
        with self._event_lock:
            if not self._cancel_requested.is_set():
                self._cancel_requested.set()
                self._revoke_request_seq = self._record("REVOKE_REQUESTED")
        with self._lock:
            if self._state == "REVOKED":
                return "REVOKED"
            self._state = "CANCEL_PENDING"
            self._gateway_fencing_proven = False
            for aid, state in self._attempts.items():
                if state in ("QUEUED", "STARTING"):
                    self._attempts[aid] = "CANCELLED_BEFORE_SEND"
                    self._record("CANCELLED_BEFORE_SEND", aid)
            self._record("FENCING_PENDING")
            return "CANCEL_PENDING"

    def simulate_gateway_fenced(self) -> SyntheticFencingEvidence:
        """Trusted offline-fixture event: model an independently isolated Gateway.

        Does NOT establish real network/OS fencing. Only a witness created
        after CANCEL_PENDING may be accepted by this one synthetic authority.
        """
        with self._lock:
            if self._state != "CANCEL_PENDING" or self._revoke_request_seq is None:
                raise OfflineContractError("Fencing witness requires pending revoke")
            if self._synthetic_fencing_witness is not None:
                return self._synthetic_fencing_witness
            witness = SyntheticFencingEvidence(
                grant_id=self.grant_id,
                gateway_id=self.gateway_id,
                revoke_request_seq=self._revoke_request_seq,
                fenced_epoch=self._epoch + 1,
                evidence_id="SYNTHETIC_GATEWAY_ISOLATED",
            )
            self._synthetic_fencing_witness = witness
            self._record("SYNTHETIC_FENCING_WITNESS_REGISTERED")
            return witness

    def finalize_revoke(self, evidence: SyntheticFencingEvidence | None) -> str:
        """Accept explicit request-bound synthetic fencing evidence, or stay pending.

        A checked data shape is not real proof of OS gateway fencing. Only a
        later runtime security review can substantiate that separate boundary.
        """
        if evidence is not None and type(evidence) is not SyntheticFencingEvidence:
            raise OfflineContractError("Fixed synthetic evidence type required")
        with self._lock:
            if self._state == "REVOKED":
                return "REVOKED"
            valid = (
                self._state == "CANCEL_PENDING"
                and self._cancel_requested.is_set()
                and evidence is not None
                and evidence is self._synthetic_fencing_witness
                and evidence.grant_id == self.grant_id
                and evidence.gateway_id == self.gateway_id
                and type(evidence.revoke_request_seq) is int
                and evidence.revoke_request_seq == self._revoke_request_seq
                and type(evidence.fenced_epoch) is int
                and evidence.fenced_epoch == self._epoch + 1
                and type(evidence.evidence_id) is str
                and bool(evidence.evidence_id)
                and len(evidence.evidence_id) <= 256
            )
            if not valid:
                self._record("FENCING_UNPROVEN")
                return "CANCEL_PENDING"
            self._gateway_fencing_proven = True
            self._epoch += 1
            self._record("FENCING_EVIDENCE_ACCEPTED")
            self._state = "REVOKED"
            self._record("REVOKE_COMMITTED")
            self._record("REVOKE_ACK_SUCCESS")
            return "REVOKED"

    def simulate_recovery(self) -> str:
        """Never re-admit unknown or cancelled attempts without a NEW Grant."""
        with self._lock:
            if self._state != "REVOKED":
                self._state = "SUSPENDED"
            self._record("RECOVERY_BLOCKED")
            return self._state

    def attempt_state(self, attempt_id: str) -> str:
        with self._lock:
            return self._attempts.get(attempt_id, "NOT_FOUND")


SAES_RUNTIME_PROOF = "NOT_PROVEN"
AWS_EVIDENCE_ACQUISITION = "NOT_EXECUTED"
AWS_WRITES = "BLOCKED"
