# Host-protected Batch Review Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the accepted live Batch authorization, concurrency, IPC, and report-durability findings.

**Architecture:** Keep public APIs and wire formats stable. Implement the fixes in three testable groups: live authorization/state handling, IPC admission/validation, and atomic report persistence. Each group adds regression tests first and is committed independently.

**Tech Stack:** Python 3.10+, `unittest`, SQLite Ledger, filesystem durability, threading.

**Spec:** `docs/superpowers/specs/2026-11-23-live-batch-review-findings-design.md`

## Global Constraints

- Preserve the signatures of `execute_batch_live`, `execute_batch_offline`, the IPC v1 wire format, and the Batch report digest.
- Preserve Host/Owner/Scope verification, the signed send cap, one-shot Permit semantics, and the existing exact string-status decisions.
- Do not allow uncertainty after a possible send to be represented as a pre-send refusal.
- All failures at the SDK dispatch boundary remain fail-closed and make zero SDK calls unless all Host-issued bindings are valid.
- Update SHA256 manifest entries for registered files changed by this work.

## Review Focus

- Same-Host concurrent execution: the second execution's unconsumed selection remains available while another call finishes.
- Malformed, reordered, duplicate, or incomplete Scope/grant evidence: reordering alone is accepted; invalid type, binding, or coverage is rejected before SDK dispatch.
- Unknown Ledger state and unresolved consumed Permit: uncertainty returns `OUTCOME_UNKNOWN`; STOP/HOLD retries without another send.
- Saturated Host IPC and spawn failure: no over-cap worker is spawned; reservations are released and the accept loop continues.
- Partial report publication and failed directory sync: no digest is returned before durable publication; retry is not blocked by a temp file.

---

### Task 1: Live authorization and execution-state safety

**Files:**
- Modify: `name_tag_batch_host_runtime.py`
- Modify: `name_tag_batch_iam_evidence.py`
- Modify: `name_tag_kind_adapters.py`
- Modify: `name_tag_batch_runtime.py`
- Test: `test_name_tag_batch_live.py`
- Test: `test_name_tag_batch_live_runtime.py`
- Test: `test_name_tag_batch_ledger.py`
- Update manifest entries for registered files changed in this task.

**Interfaces:**
- Preserve `execute_batch_live(batch, ledger, runtime)` and `execute_batch_offline(...)`.
- Keep runtime grants process-local and one-shot; the Registry adapter receives only an internal one-use dispatch binding produced after Host verifier validation.
- Compare re-confirmed Scope evidence against canonical `VerifiedHostScope.side_effects`, ordered by `target_arn`.

- [ ] **Step 1: Add failing tests**:
  - In `test_name_tag_batch_live_runtime.py`, run two same-Host `execute_batch_live` calls with controlled synchronization and prove one call's cleanup cannot invalidate the other's unconsumed selection.
  - Add Scope reconfirmation cases proving reordered valid evidence passes, while wrong element types, duplicate/missing targets, and changed content refuse.
  - In `test_name_tag_batch_live.py`, separate synthetic-grant denial from missing-binding cases. For missing adapter, target, and clock, obtain a fresh live grant per case. Add one successful dispatch through the real Registry adapter and a Fake SDK client, asserting exactly one SDK write; replay and synthetic grants assert zero writes.
  - In `test_name_tag_batch_live_runtime.py`, inject an initial `batch_execution_state` `LedgerError` and assert `HostOutcomeUnknown` includes the Batch ID. Add a STOPPED unresolved-consumed-Permit case that retries Scope HOLD without consuming or sending again.
  - Preserve the existing `BatchOfflineRuntime` rejection coverage in `test_name_tag_batch_live_runtime.py:287-294`, which already uses a valid signed Batch and Host-bound Ledger; do not add a duplicate test.
  - Tighten STS policy assertions to require exactly one write Resource ARN per request and the expected request count; do not use a truncating `zip`.
  - In `test_name_tag_batch_ledger.py`, use a canonical Stage ARN and matching locator, and prove the API Gateway test depends on `_PROMOTION_BLOCKS`.
- [ ] **Step 2: Run** `python -m unittest test_name_tag_batch_live test_name_tag_batch_live_runtime test_name_tag_batch_ledger -v`. Confirm each new regression fails for its intended reason.
- [ ] **Step 3: Implement** per-Host serialization around live execution; strict, order-independent Scope evidence reconfirmation; a one-use Host grant dispatch binding validated by the Registry adapter; initial-read `OUTCOME_UNKNOWN` mapping with Batch ID; and durable STOP/HOLD for unresolved consumed Permits in both ACTIVE and STOPPED states.
- [ ] **Step 4: Run** the same focused test command and confirm the new and existing tests pass.
- [ ] **Step 5: Update registered SHA256 manifest entries, run the manifest validator and `git diff --check`, then commit only Task 1 files** with a Japanese Conventional Commit message.

### Task 2: Host IPC admission and response validation

**Files:**
- Modify: `name_tag_batch_host_server.py`
- Modify: `name_tag_batch_ipc.py`
- Test: `test_name_tag_batch_host_server.py`
- Test: `test_name_tag_batch_ipc.py`
- Test: `test_name_tag_batch_live_runtime.py`

**Interfaces:**
- Preserve the IPC v1 framing and response wire format.
- Reserve a connection slot before worker creation; pass ownership of that reservation to the worker and release it exactly once.
- Handle capacity-exhausted BUSY inline without spawning a worker.

- [ ] **Step 1: Add failing tests** for slot reservation before `_spawn`, over-cap BUSY without worker creation, slot release for rejected and BUSY worker paths, `_spawn` failure closing the accepted connection and continuing the accept loop, and non-string response statuses raising `IPCError`. Capture `map_endpoint_result` in the accepted-endpoint test and assert one call with `(request.request_id, endpoint_result)` in addition to the response assertion.
- [ ] **Step 2: Run** `python -m unittest test_name_tag_batch_host_server test_name_tag_batch_ipc test_name_tag_batch_live_runtime -v`. Confirm the new tests fail for the intended reasons.
- [ ] **Step 3: Implement** pre-spawn slot reservation and release-once cleanup; send over-cap BUSY inline and close; catch spawn failure, release, close, and continue; validate status is a string before the existing `STATUSES` membership check.
- [ ] **Step 4: Run** the same focused test command and confirm the new and existing tests pass.
- [ ] **Step 5: Run `git diff --check` and commit only Task 2 files** with a Japanese Conventional Commit message.

### Task 3: Atomic and durable report publication

**Files:**
- Modify: `name_tag_batch_runtime.py`
- Test: `test_name_tag_batch_live_runtime.py`
- Update the `name_tag_batch_runtime.py` manifest entry.

**Interfaces:**
- Preserve `_persist_host_report(host, batch_id, report) -> str | None` and the report digest format.
- Return a digest only after report verification and all required file/directory syncs succeed.

- [ ] **Step 1: Add failing tests** for atomic publication via a same-directory temp file; injected write/fsync/replace failure and retry; cleanup of failed temp files; sync of the report file and each directory (`batch_dir`, `batch-reports`, `StateDirectory`); and reuse of an existing digest only after verification and all required syncs.
- [ ] **Step 2: Run** `python -m unittest test_name_tag_batch_live_runtime -v`. Confirm the durability and retry tests fail for the intended reasons.
- [ ] **Step 3: Implement** unique exclusive temp-file creation, complete write and file fsync, atomic replace, best-effort temp cleanup, exact file verification, and bottom-up directory fsync for both new and reused digest files.
- [ ] **Step 4: Run** the focused test command and confirm the new and existing report tests pass.
- [ ] **Step 5: Update the registered manifest entry, run the manifest validator and `git diff --check`, then commit only Task 3 files** with a Japanese Conventional Commit message.

### Task 4: Full verification and push

**Files:**
- Verify all implementation and test files from Tasks 1–3.
- Verify the design and implementation plan are committed without staging the pre-existing untracked plan `docs/superpowers/plans/2026-11-23-host-issuer-review-findings.md`.

- [ ] **Step 1: Run focused tests** for all touched modules: `python -m unittest test_name_tag_batch_live test_name_tag_batch_live_runtime test_name_tag_batch_ledger test_name_tag_batch_host_server test_name_tag_batch_ipc -v`.
- [ ] **Step 2: Run the full suite:** `python -m unittest discover -v`.
- [ ] **Step 3: Run repository validation:** `uv run --locked --no-build python scripts/validate_sha256_manifest.py` and `git diff --check`; inspect the final diff and staged paths.
- [ ] **Step 4: Commit the approved design and implementation plan** as a separate Japanese Conventional Commit, staging only the two documented paths.
- [ ] **Step 5: Push the verified commits to the current branch's configured remote.**
