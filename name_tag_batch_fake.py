"""Explicitly synthetic, in-memory Batch adapter and runtime evidence values."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from name_tag_batch_credentials import IssuedBatchSession, authorize_offline_session_operation
from name_tag_batch_state import classify_batch_name
from name_tag_scope import ScopeEvidence, SideEffectEvidence

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


@dataclass(frozen=True, slots=True)
class BatchRuntimeEvidence:
    scope: ScopeEvidence
    side_effects: tuple[SideEffectEvidence, ...]


class FakeBatchSDKAdapter:
    """An in-memory service double; it has no AWS client or network path."""

    def __init__(
        self,
        initial_tags: Mapping[str, Mapping[str, str]],
        *,
        readback_failures: Sequence[str] = (),
        require_session: bool = False,
    ) -> None:
        self.require_session = require_session
        self.tags = {arn: dict(values) for arn, values in initial_tags.items()}
        self.readback_failures = frozenset(readback_failures)
        self.write_calls = 0
        self.written_arns: set[str] = set()

    def read_current(
        self, resource_arn: str, *, session: IssuedBatchSession | None = None,
        _bound: bool = True,
    ) -> dict[str, str]:
        if _bound and (session is not None or self.require_session):
            authorize_offline_session_operation(session, resource_arn)
        if resource_arn not in self.tags:
            raise OSError("Target is absent from offline adapter")
        return dict(self.tags[resource_arn])

    def write_once(
        self, resource_arn: str, approved_name: str, *,
        session: IssuedBatchSession | None = None,
    ) -> None:
        if session is not None or self.require_session:
            authorize_offline_session_operation(session, resource_arn, write=True)
        tags = self.read_current(resource_arn, _bound=False)
        observation = classify_batch_name(tags)
        if observation.state in ("NONEMPTY", "UNKNOWN") or resource_arn in self.written_arns:
            raise OSError("Offline adapter refused overwrite or replay")
        self.write_calls += 1
        self.written_arns.add(resource_arn)
        self.tags[resource_arn] = {**tags, "Name": approved_name}

    def readback(
        self, resource_arn: str, *, session: IssuedBatchSession | None = None,
    ) -> dict[str, str]:
        if session is not None or self.require_session:
            authorize_offline_session_operation(session, resource_arn)
        if resource_arn in self.readback_failures:
            raise OSError("Offline readback failure")
        return self.read_current(resource_arn, _bound=False)


@dataclass(frozen=True, slots=True)
class BatchOfflineRuntime:
    evidence_by_scope: Mapping[str, BatchRuntimeEvidence]
    adapter: FakeBatchSDKAdapter


@dataclass(frozen=True, slots=True)
class BatchRunResult:
    batch_state: str
    send_attempts_consumed: int
    max_send_attempts: int
    remaining_unattempted_cap: int
    outcomes: tuple[str, ...]
    writes_complete: bool
    report: Mapping[str, JsonValue]
