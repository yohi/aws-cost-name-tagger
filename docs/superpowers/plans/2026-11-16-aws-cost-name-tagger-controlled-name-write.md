# AWS Cost Name Tagger — Controlled Name Write Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended by the skill) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **User instruction overrides any automatic review chain:** execute only the tasks explicitly authorized by the Human Owner; do not trigger repeated independent reviews or a following task automatically.

**Goal:** Produce reliable Name approvals for all 18 existing AWS resource kinds, and—only after separate policy and execution approvals—apply an approved Name to a safe target and verify it by AWS Readback.

**Architecture:** Reuse the existing CUR/metadata `plan()` and `Investigator.resolve()` without weakening their read-only behavior. Add distinct modules for canonical Owner-signed approvals, scope/side-effect validation, a durable single-host one-shot Intent ledger, a mockable executor and opt-in service adapters. Deliver a completely offline, fail-closed vertical slice first; any real AWS write path is a separate, explicitly authorized phase.

**Tech Stack:** Python >=3.10, `unittest`, `sqlite3`/`fcntl`/standard library, pinned `boto3[crt]==1.43.116` from `pyproject.toml`, OpenSSH `ssh-keygen -Y` for detached signatures, Ubuntu Linux secure filesystem assumptions, `uv` locked dependencies. No additional cloud services or Broker.

**Spec:** `docs/superpowers/specs/2026-11-16-aws-cost-name-tagger-controlled-name-write-design.md` at `yohi/aws-cost-name-tagger` commit `4129cffa1f3d0e02be47cfc5649d0e7d019e71ea` (Design R0.2.1). This plan is **proposed, not an adopted Design or AWS write authorization**.

## Global Constraints

- **Current authority:** `G1_NOT_PROVEN / G2_NOT_VERIFIED / SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED`. The Owner has not adopted R0.2.1, authorized Trust Anchor enrollment, approved a normative exception, or granted real AWS access. These are distinct future decisions.
- **Execution stop:** Until the Human Owner explicitly approves a subsequent implementation scope, *do not implement this plan*. In any authorized offline implementation, do not call live AWS APIs, change IAM, remove the Safety Hold, or accept an environment variable/CLI flag as a way around it.
- **Name semantics:** Only `ABSENT` or exactly `EMPTY` may be candidates; whitespace is `NONEMPTY`; `UNKNOWN`, duplicate/case-variant Name, truncated tag pages and malformed responses are blocked. Treat S3 as a candidate kind but never automatically enable its write adapter.
- **Granularity:** One verified Name approval, then a **separate** execution authorization for exactly one canonical ARN, one exact Name and one AWS operation. No batch grant while INV-N05 remains authoritative. `run --mode y` remains review-only; `apply()` and `Investigator.write_name()` remain hard blocked.
- **Signatures:** Name and execution are separate OpenSSH namespaces: `aws-cost-name-tagger-name-approval-v1` and `aws-cost-name-tagger-execution-v1`. Only canonical `payload` is signed; `approval_id` / `authorization_id` = lowercase SHA-256 of canonical payload bytes; `signature_ref` stays in the envelope. No CSV, raw digest, STS principal, Git author, or user-provided public key substitutes for an enrolled Owner Trust Anchor.
- **HOLD:** An untrusted/missing Trust Anchor is `BLOCKED_OWNER_AUTHN`. Writer-control evidence **and** IAM/ABAC/automation side-effect analysis (INV-N09) are independent requirements. Unverified or unsupported adapters remain blocked.
- **Ledger:** Single Ubuntu host, one trusted writer UID, strict cross-process lock and durable records. Old/incomplete Intents, replayed approvals/nonces, scope HOLD, corrupted/missing ledger and unproven scope mapping fail closed. In-memory `ALLOW_FIRST_SEND` is not a persistent capability. `SEND_ATTEMPT_CONSUMED` is durable *before* calling an AWS mutation method; crashing after consumption never restores send authority.
- **Failures:** On `OUTCOME_UNKNOWN` stop the current run (INV-N07), never retry a mutation or auto-rollback. Readback mismatch is `WRITER_CONTROL_SUSPECTED`, not proof of a competing writer; persist a scope HOLD. If HOLD persistence fails, block the host.
- **No new review loop:** Run the stated task tests and a single bounded self-check; record unresolved findings with evidence. Once the approved scope is complete, stop at the Human Owner checkpoint.

## File Structure (implementation proposal; no files changed by creating this plan)

| File | Responsibility |
|---|---|
| `name_tag_approval.py` | Exact typed envelope/payload validation, canonical bytes/IDs, OpenSSH signature verification against protected Owner trust config |
| `test_name_tag_approval.py` | Canonical vectors, role/namespace/expiry/replay-binding and bad-key tests |
| `name_tag_review.py` | Select an existing plan row, propose/justify edited Name, produce unsigned Name approval payload; all 18 kinds are eligible for review |
| `test_name_tag_review.py` | High/Medium, S3 review, rejection of UNKNOWN/NONEMPTY/evidence changes |
| `name_tag_scope.py` | Parse and validate external evidence of writer control and independent INV-N09 side effects; no self-declared PASS |
| `test_name_tag_scope.py` | Block unknown scope/side effects and invalid target identity |
| `name_tag_ledger.py` | Authoritative local SQLite/locking ledger for one-time grants, Intents and scope HOLD/release; no network |
| `test_name_tag_ledger.py` | Crash-boundary, replay, external-run and scope HOLD tests T-F004-01..16 |
| `name_tag_execution.py` | Mockable one-target orchestration and Readback classification; real writer entrypoint remains blocked |
| `test_name_tag_execution.py` | Gating, first send, readback, UNKNOWN, no retry and resource isolation |
| `name_tag_adapters.py` | **Initially one** EBS-volume request builder/readback validator behind Safety Hold; no callable live-write adapter in Phase A; all other kinds `WRITE_UNSUPPORTED` |
| `test_name_tag_adapters.py` | Fake SDK calls, exact `Name`-only request, account/ARN/Name consistency and unchanged non-Name tags |
| `name_tag_controlled.py` | Separate controlled-approval CLI, offline simulation and permanently blocked production execute entry until later Owner decision |
| `test_name_tag_controlled.py` | No-write CLI regression, invalid envelope and offline workflow |
| `README.md`, `.github/workflows/ci.yml`, `SHA256_MANIFEST.json` | Only when a later implementation task is authorized: document new offline commands; run new tests in CI; update impacted manifest digests without rewriting historical evidence |

All paths above are at repository root unless otherwise stated. Do **not** refactor the 1,856-line `aws_cost_name_tagger_v3.py` merely to host new behavior. Keep `g2_*` modules separate and read-only.

## Review Focus (five practical failure classes; each pinned to a task test)

1. Unpaired Unicode surrogate, floats, duplicate/unknown JSON keys and noncanonical signer input → **reject**, not a different digest (Task 1 `test_reject_noncanonical_payload`).
2. Edited Name reusing a prior approval, or a `proposal_id` in place of an execution ID → **reject** (Tasks 1–2 `test_edited_name_invalidates_old_signature`).
3. Scope writer control appears valid but an IAM/ABAC/EventBridge/IaC side-effect dependency is unavailable → **BLOCKED_SIDE_EFFECT_UNASSESSED** (Task 3 `test_side_effect_unknown_blocks`).
4. Crash after `SEND_ATTEMPT_CONSUMED` but before the SDK call, followed by a same-PID/same-ID restarted process → **no send** (Task 4 `test_consumed_crash_never_reopens`).
5. SDK timeout/readback mismatch, including stale/malformed Name response and unsafe tag-set replacement APIs → **no retry**, correct HOLD, no `APPLIED_VERIFIED` (Tasks 5–6 `test_mismatch_holds_scope` and `test_set_replacement_unsupported`).

---

## Phase A — Offline-only deliverables (eligible for *future separately approved* implementation)

### Task 1: Canonical, authenticated approval contract

**Files:** Create `name_tag_approval.py`, `test_name_tag_approval.py`.

**Interfaces:**
- Produces `canonical_payload(payload: Mapping[str, object], *, kind: Literal["name", "execution"]) -> bytes`, `approval_digest(canonical_bytes: bytes) -> str`.
- Produces `verify_envelope(envelope: Mapping[str, object], *, kind: Literal["name", "execution"], trust: OwnerTrust, now_utc: datetime) -> VerifiedEnvelope` and `ApprovalRejected(code: str)`; `VerifiedEnvelope` carries `payload`, `content_id`, `owner_principal_id`.
- `OwnerTrust` is constructed exclusively from a pinned, protected `allowed_signers` file and enrolled Owner ID/fingerprint/allowed role mapping; the executing user must not choose or write its trusted keys.
- For the supported canonical subset, only fixed ASCII field names, JSON string, `null`, boolean and *integer* fields (such as `schema_version=1`) are allowed. Reject floats, unpaired surrogates, unknown or duplicate keys and mixed types. Implement RFC 8785-compatible UTF-8 canonicalization for that constrained schema, with fixed-byte fixture vectors; never relabel unrestricted `json.dumps(sort_keys=True)` as complete RFC 8785.

- [ ] **Step 1: Write failing test** `test_name_tag_approval.py::ApprovalContractTests.test_canonical_name_payload_and_id`: fixed payload must yield stable canonical bytes and 64-character lowercase hex SHA-256; inserting `approval_id`/`signature_ref` inside payload is rejected.
- [ ] **Step 2: Run failure:** `uv run --locked --no-build python -m unittest -v test_name_tag_approval.ApprovalContractTests.test_canonical_name_payload_and_id`; expect FAIL (missing module/function).
- [ ] **Step 3: Implement** the exact interfaces above. Use `ssh-keygen -Y verify` with the appropriate `-n` namespace and enrolled `-I` signer ID; verify the *same* canonical bytes, expected role and Owner ID, key fingerprint, validity, name/execution type and digest. Do not accept caller-supplied signer files.
- [ ] **Step 4: Add and run** `test_reject_noncanonical_payload`, `test_unknown_or_revoked_owner`, `test_namespace_swap_rejected`, `test_edited_name_invalidates_old_signature`, `test_expired_or_wrong_role_rejected`, `test_missing_trust_anchor_blocks`. Use temporary OpenSSH keys for offline fixtures only; verify permission/ownership checks with mocks. `uv run --locked --no-build python -m unittest -v test_name_tag_approval` → PASS.
- [ ] **Step 5: Future execution only:** stage/commit exactly those two files with `git commit -m "feat: verify canonical Owner-signed approval envelopes"`; never commit automatically from this planning request.

### Task 2: Name review and an unsigned approval payload

**Files:** Create `name_tag_review.py`, `test_name_tag_review.py`; import the Task 1 canonical/validation definitions. No change to existing `run --mode y`.

**Interfaces:**
- `prepare_name_payload(plan_bytes: bytes, record: Mapping[str, object], *, approved_name: str, edit_reason: str, owner_principal_id: str, owner_key_fingerprint: str, issued_at_utc: str, expires_at_utc: str, decision_nonce: str) -> dict[str, object]`.
- Consume an existing v3.6 schema-2 plan and verify account, canonical ARN, kind, region, locator, `proposed` status, confidence High/Medium, `ABSENT`/`EMPTY`, evidence digest, and exact original plan bytes digest; use `proposal_id` for review lookup only.
- Set `approval_namespace=aws-cost-name-tagger-name-approval-v1` and schema 1; if `approved_name != suggested_name`, require a nonempty `edit_reason`. Produce *unsigned* payload for an Owner to sign outside the executor. `s3_bucket` is reviewable but remains non-executable.

- [ ] **Step 1: Write failing test** `test_prepare_name_payload_edits_require_reason_and_new_signature`: changed Name with missing reason raises; with reason, payload binds changed Name and differs in digest from previous value.
- [ ] **Step 2: Run failing test** `uv run --locked --no-build python -m unittest -v test_name_tag_review.NameReviewTests.test_prepare_name_payload_edits_require_reason_and_new_signature`; expect FAIL.
- [ ] **Step 3: Implement** `prepare_name_payload` and validations; do not replace CUR provenance with Product mapping or guess missing ARN.
- [ ] **Step 4: Run** tests `test_absent_empty_high_medium_allowed`, `test_nonempty_unknown_rejected`, `test_s3_candidate_can_be_reviewed_without_write_permission`, `test_edited_name_invalidates_old_signature`, `test_foreign_account_or_stale_evidence_rejected` via `uv run --locked --no-build python -m unittest -v test_name_tag_review`; expect PASS.
- [ ] **Step 5: Future execution only:** commit two task-owned files with `feat: prepare evidence-bound Name approval payloads`.

### Task 3: Independent writer-control and side-effect safety evidence

**Files:** Create `name_tag_scope.py`, `test_name_tag_scope.py`.

**Interfaces:**
- `ScopeEvidence`: fixed Account/Partition/Region, `writer_control_scope_id`, controlled ARN set, validity window, writer evidence digest, responsible Owner; `SideEffectEvidence`: target ARN, IAM/ABAC/ResourceTag, IaC, event/automation assessments, evidence references and validity.
- `check_target_safety(*, approval: VerifiedEnvelope, scope: ScopeEvidence, side_effects: SideEffectEvidence, now_utc: datetime) -> SafetyDecision`. `SafetyDecision` = `allowed: bool`, `code: str`, `scope_id: str | None`.
- Accept evidence only from a previously verified, scoped, immutable and Owner-authorized source; arbitrary JSON/CSV, operator free text or missing coverage cannot create a trusted PASS. Evidence-source enrollment/operational ownership is itself Owner HOLD, not an inference made by code.

- [ ] **Step 1: Write failing test** `test_side_effect_unknown_blocks`: valid-looking writer scope but unknown `aws:ResourceTag/Name` or EventBridge dependency → `BLOCKED_SIDE_EFFECT_UNASSESSED`.
- [ ] **Step 2: Run failure** `uv run --locked --no-build python -m unittest -v test_name_tag_scope.ScopeGuardTests.test_side_effect_unknown_blocks`; expect FAIL.
- [ ] **Step 3: Implement** fixed scope equality, target-ARN binding and independent evidence expiry/coverage checks. Do not introduce SAES, a Broker, live IAM inspection or G2 deployment.
- [ ] **Step 4: Run** `test_writer_unknown_blocks`, `test_side_effect_unknown_blocks`, `test_scope_mismatch_blocks`, `test_expired_evidence_blocks`, `test_verified_scope_and_side_effects_allow_offline_precheck` via `uv run --locked --no-build python -m unittest -v test_name_tag_scope`; expect PASS.
- [ ] **Step 5: Future execution only:** commit the two files with `feat: independently gate writer and Name side effects`.

### Task 4: Crash-safe single-host Intent and scope HOLD ledger

**Files:** Create `name_tag_ledger.py`, `test_name_tag_ledger.py`.

**Interfaces:**
- `open_ledger(path: Path, *, trusted_host: bool) -> IntentLedger` (reject symlink/untrusted filesystem/unsafe permissions). Within `IntentLedger` expose `create_intent(scope_id: str, authorization_id: str, nonce: str, resource_arn: str, approved_name: str) -> IntentHandle`, `consume_first_send(handle: IntentHandle) -> FirstSendPermit`, `effective_scope_state(scope_id: str) -> str`, `record_readback(handle: IntentHandle, *, name_after: str | None, outcome: str) -> None`, `hold_scope(scope_id: str, *, reason: str) -> None`.
- A `FirstSendPermit` must be process-local, unpickleable/nonpersistable and single-use; `IntentHandle` alone never grants send authority. `record_readback` on mismatch writes durable `HOLD` **before** ending the Intent.
- Use a secure single-host Linux advisory process lock across preflight, ledger transactions and the one eventual write invocation. Use SQLite rollback-journal mode with `synchronous=FULL` or stronger, checked transaction commits and protected directory/file ownership. Never leave a DB transaction open across the network call; commit `SEND_ATTEMPT_CONSUMED` **before** invoking the adapter. On lock failure, torn/corrupt DB, schema mismatch or missing historical state, fail closed; do not rebuild a fresh `CLEARED` DB. Owner scope-clearance is a separate signed, durable decision, and does not revive old nonce/authorization.

- [ ] **Step 1: Write failing test** `test_fresh_intent_can_consume_once`: fresh CLEARED scope with no prior incomplete intents → `create_intent`, `consume_first_send` succeeds once; second call raises `BLOCKED_INTENT_REPLAY`.
- [ ] **Step 2: Run failure** `uv run --locked --no-build python -m unittest -v test_name_tag_ledger.IntentLedgerTests.test_fresh_intent_can_consume_once`; expect FAIL.
- [ ] **Step 3: Implement** interfaces, durable state transitions and process-lifetime lock. Define `CURRENT_EXECUTION_INTENT` only while the same live, lock-owning execution context exists; on restart every incomplete Intent is `PRIOR_INCOMPLETE_INTENT`. Old `CLEARED` cannot override an incomplete Intent. Inability to map an affected scope blocks the whole host.
- [ ] **Step 4: Run** T-F004-01 through T-F004-16 (including subprocess kill/restart after record/consume/HOLD/terminal boundaries), plus `test_consumed_crash_never_reopens` and `test_torn_ledger_fail_closed`, with `uv run --locked --no-build python -m unittest -v test_name_tag_ledger`; expect PASS with **zero fake mutations** on all replay attempts.
- [ ] **Step 5: Future execution only:** commit the two files with `feat: keep one-shot Intents and scope HOLD durable across crashes`.

### Task 5: Mock-only guarded executor and Readback classification

**Files:** Create `name_tag_execution.py`, `test_name_tag_execution.py`. Consume Tasks 1, 3 and 4.

**Interfaces:**
- `class NameTagAdapter(Protocol): read_tags(resource_arn: str) -> Mapping[str, str]; write_name_only(resource_arn: str, approved_name: str) -> None; readback_tags(resource_arn: str) -> Mapping[str, str]`.
- `execute_once(name_approval: VerifiedEnvelope, authorization: VerifiedEnvelope, *, scope: ScopeEvidence, side_effects: SideEffectEvidence, ledger: IntentLedger, adapter: NameTagAdapter, runtime: RuntimeContext, offline_write_stub: bool = False) -> ExecutionResult`; `ExecutionResult.code` is one of `APPLIED_VERIFIED`, `BLOCKED_OWNER_AUTHN`, `BLOCKED_SIDE_EFFECT_UNASSESSED`, `BLOCKED_SCOPE_HOLD`, `BLOCKED_INCOMPLETE_INTENT`, `BLOCKED_INTENT_REPLAY`, `BLOCKED_SCOPE_STATE_UNKNOWN`, `WRITE_UNSUPPORTED`, `FAILED_READBACK`, `OUTCOME_UNKNOWN` or the existing per-resource blocked classifications.
- **Production invariant:** In Phase A, `offline_write_stub=False` *always* raises `AWS_WRITE_BLOCKED` **before credentials, SDK, filesystem Intent or network access**. The offline stub is a programmatically injected fake available to tests; CLI inputs/flags cannot activate it for a real AWS client.

- [ ] **Step 1: Write failing test** `test_mock_first_send_then_readback_verified`: two distinct Owner envelope IDs refer to one valid ARN/Name; safe scope and complete evidence; fake adapter is called exactly once, readback matches, `APPLIED_VERIFIED` emitted.
- [ ] **Step 2: Run failure** `uv run --locked --no-build python -m unittest -v test_name_tag_execution.ExecutorTests.test_mock_first_send_then_readback_verified`; expect FAIL.
- [ ] **Step 3: Implement** the ordered contract: verify both envelope signatures and exact binding → effective policy/identity/scope/side-effect guards → verified current resource ABSENT/EMPTY and evidence freshness → durable Intent → durable consume → one fake call → fresh Readback → terminal state; fail closed on any ambiguous read. No auto retry/rollback; `OUTCOME_UNKNOWN` stops this run; mismatch puts scope HOLD and does not claim conflict proof.
- [ ] **Step 4: Run** `test_missing_trust_never_creates_intent`, `test_real_runtime_unconditionally_blocked`, `test_unauthorized_name_or_arn_blocks`, `test_nonempty_or_unknown_blocks`, `test_mismatch_holds_scope`, `test_timeout_never_retries`, `test_failed_hold_persistence_blocks_host`, `test_old_intent_never_retries` using `uv run --locked --no-build python -m unittest -v test_name_tag_execution`; expect PASS.
- [ ] **Step 5: Future execution only:** commit the two files with `feat: orchestrate one approved fake Name write and readback`.

### Task 6: One service adapter with fake SDK (not a live write grant)

**Files:** Create `name_tag_adapters.py`, `test_name_tag_adapters.py`. Consume Task 5 `NameTagAdapter` interface.

**Interfaces:**
- `class EC2VolumeAdapter`: `__init__(client, *, account: str, region: str)`; `read_tags` and `readback_tags` match the adapter protocol; **Phase A `write_name_only(...)` unconditionally raises `AWS_WRITE_BLOCKED`, even on direct invocation**. The pure `build_volume_name_request(resource_arn: str, approved_name: str, *, account: str, region: str) -> dict[str, object]` constructs and validates request arguments without calling the SDK. `client` is injected and fake-only during Phase A; do not instantiate real credentials in tests.
- Scope: **`volume` only** for the first operational vertical slice. EC2 `CreateTags(Resources=[volume_id], Tags=[{"Key": "Name", "Value": approved_name}])` is the candidate write operation; it can overwrite a Name and therefore **must not be exposed to real AWS until the separately authorized G1 normative decision**. Validate canonical ARN, Account/Region, returned volume ID/state/attachment and tags. Use verified `read_tags`/`readback_tags` not an assumed successful API response.
- For other 17 kinds, choose `WRITE_UNSUPPORTED` without losing their existing candidate-generation path. For S3, never use `PutBucketTagging` to overwrite the tag set; `TagResource` is not automatically CAS-safe either. A future adapter is a separate approved task, not a TODO that blocks volume's offline tests.

- [ ] **Step 1: Write failing test** `test_volume_exact_name_only_request`: pure request builder emits exactly one target volume ID and one `Name` tag; a **separate test-only FakeVolumeAdapter** records one simulated call/readback; the Phase A production adapter direct-write call is rejected.
- [ ] **Step 2: Run failure** `uv run --locked --no-build python -m unittest -v test_name_tag_adapters.VolumeAdapterTests.test_volume_exact_name_only_request`; expect FAIL.
- [ ] **Step 3: Implement** read/Readback validation and a pure `CreateTags` argument builder only. The Phase A `EC2VolumeAdapter.write_name_only` must always reject before any SDK method invocation. Move the actual SDK write invocation to conditional Task 8, with `Config(retries={"total_max_attempts": 1})`; do not rewrite `Investigator.resolve()` or unblock `Investigator.write_name()`.
- [ ] **Step 4: Run** `test_volume_exact_name_only_request`, `test_set_replacement_unsupported`, `test_region_account_id_mismatch`, `test_malformed_or_paginated_tags_unknown`, `test_unimplemented_kind_blocked`, `test_direct_adapter_write_always_blocked` with `uv run --locked --no-build python -m unittest -v test_name_tag_adapters`; expect PASS.
- [ ] **Step 5: Future execution only:** commit two files with `feat: validate EBS Name request offline behind HOLD`.

### Task 7: Separate CLI, offline acceptance, and documentation

**Files:** Create `name_tag_controlled.py`, `test_name_tag_controlled.py`; only after approval modify `README.md`, `.github/workflows/ci.yml` and relevant entries in `SHA256_MANIFEST.json`.

**Interfaces:**
- CLI commands: `prepare-name` (produce unsigned payload from existing plan), `verify-name` (verify detached Owner signature), `prepare-execution` (exactly one name/ARN/operation), `verify-execution` (separate namespace), `simulate` (test-only injected fake through Python harness), `execute-approved` (always `AWS_WRITE_BLOCKED` while Phase A HOLD remains). Exact `argparse` handlers in this file: `prepare_name(args) -> int`, `verify_name(args) -> int`, `prepare_execution(args) -> int`, `verify_execution(args) -> int`, `execute_approved(args) -> int`.
- The CLI must not accept a `--trust-public-key`, `--disable-safety-hold`, or production `--stub` override. Files are created privately without overwrite. Owner signing is performed separately with the real Owner-controlled key; this tool does not store it.

- [ ] **Step 1: Write failing test** `test_execute_approved_refuses_before_credentials`: invoke the new entry point while patching boto3/session/socket constructors to fail if called; expect `AWS_WRITE_BLOCKED` and zero AWS/network calls.
- [ ] **Step 2: Run failure** `uv run --locked --no-build python -m unittest -v test_name_tag_controlled.ControlledCLITests.test_execute_approved_refuses_before_credentials`; expect FAIL.
- [ ] **Step 3: Implement** only the CLI handlers above. In offline flow accept plan input, produce unsigned payload, verify detached signatures using the enrolled trust config when available, prepare a *separate* execution envelope, then simulate via test-injected fake only. No real AWS connection even for credential lookup.
- [ ] **Step 4: Run** all seven new test modules plus existing `test_aws_cost_name_tagger_v3` using `uv run --locked --no-build python -m unittest -q test_name_tag_approval test_name_tag_review test_name_tag_scope test_name_tag_ledger test_name_tag_execution test_name_tag_adapters test_name_tag_controlled test_aws_cost_name_tagger_v3` → PASS. Preserve CI's Python 3.10/3.11/3.12 matrix and SHA manifest validation; update CI test invocation and hashes for changed tracked files when implementing. Run full existing CI-equivalent suites, not just newly written tests.
- [ ] **Step 5: Future execution only:** commit precisely Task 7's new files, README, CI, and updated manifest with `feat: add offline controlled Name approval workflow (writes held)`; provide an Owner checkpoint with achieved offline evidence and any BLOCKED items. **Stop here; do not start Phase B automatically.**

## Human Owner Checkpoint — Mandatory stop after Phase A

The offline work is useful when it can prepare and verify exact, separately signed approvals; reject unsafe scopes; prove fresh-Intent one-shot behavior with process-kill tests; and classify fake Readback without any real AWS mutation. This is **not** proof that an AWS tag is safe to mutate.

The Owner must independently decide whether to (a) adopt Design R0.2.1, (b) approve and enroll the OpenSSH Trust Anchor and permitted Owner roles, (c) change/except the existing G1 atomic-write norm for explicitly controlled targets, (d) accept writer-control and INV-N09 evidence for the selected ARN and (e) authorize an exact principal/ARN/Name/operation/time-window real AWS execution. No decision is implied by a passing offline test, plan approval, merge, or a pre-existing review CSV.

## Phase B — Separately authorized real AWS enablement, **NOT AUTHORIZED NOW**

### Task 8: Controlled first real Name update and Readback (conditional, one ARN)

**Files:** Only after the Owner's separate decision: modify `name_tag_controlled.py` and `name_tag_execution.py` to accept an immutable, explicitly approved runtime policy; modify `name_tag_adapters.py` **to introduce the actual SDK write method for the first time**, reusing the already-tested pure EBS request builder with a pinned one-attempt boto3 client; test in `test_name_tag_controlled.py`, `test_name_tag_execution.py`, `test_name_tag_adapters.py`. Update README/CI/manifest only for files actually changed.

**Interfaces:** `execute_approved(args) -> int` must verify the *independently authenticated* runtime policy and both Owner-signed envelopes, the STS Account/principal/role, exact volume ARN, Name, region, effective writer control, independently verified side-effect evidence, deadline, and one-time durable Intent ledger. A false/missing policy, incomplete proof or unsupported kind stays `AWS_WRITE_BLOCKED`.

- [ ] **Step 1: Write failing integration test** `test_no_owner_runtime_policy_no_network` and `test_real_client_exact_once_mocked`: without a pinned approved runtime policy there must be zero write SDK calls; with a *synthetic approved policy* and fake SDK, exactly one `CreateTags` call and Readback classification, including no retry on timeout.
- [ ] **Step 2: Run failure** `uv run --locked --no-build python -m unittest -v test_name_tag_controlled test_name_tag_execution test_name_tag_adapters`; expected FAIL before production runtime wiring.
- [ ] **Step 3: Implement** the minimal runtime policy check and real-client adapter behind all gates. No global `--enable-write` switch, default allowlist, or automatic Gate flip. Do not treat STS, IAM condition keys or two reads as atomic CAS; preserve the approved, explicitly scoped residual-risk contract and the prior G1 NOT PROVEN record.
- [ ] **Step 4: Complete offline regression and hostile boundary tests** (retry disabled, preflight before SDK, stale token, crash after consumption, readback mismatch/HOLD, bad policy/Trust Anchor/ARN, tagset no-overwrite) and present results to Owner. Run no live AWS API before an explicit operational grant.
- [ ] **Step 5: ONLY after the separate explicit real-AWS grant**, perform its precise one-resource, one-operation, one-time approved execution and fresh AWS Readback. Accept `APPLIED_VERIFIED` only on observed expected Name; otherwise report blocked/unknown without retry or rollback. Never automatically continue to another ARN or open another review loop.

## Exit criteria, residual risk, and handoff

- **Plan creation is complete when this document exists and its specification interfaces are consistent.** Plan creation itself changes no repository code, AWS tags, IAM, CI or GitHub refs.
- **Offline milestone** means accepted signatures, scope checks, Intent crash safety and a working fake adapter/Readback path; real tags remain unchanged.
- **Business success** requires a separately permitted actual AWS write followed by Readback; the plan alone cannot assert `APPLIED_VERIFIED`.
- **Residual risks:** AWS CreateTags cannot atomically compare the prior Name; noncooperating writers and external automation may alter tags; local-ledger durability is constrained to the trusted host; the Owner Trust Anchor, normative exception and live execution grant are currently NOT APPROVED.
- **No automatic continuation:** stop at the approved scope's Owner checkpoint. Suggest no independent review, new plan, or follow-up task without a concrete reason and explicit Owner decision.
