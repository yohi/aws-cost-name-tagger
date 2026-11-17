# AWS Cost Name Tagger — Batch Name Assignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) for tracking. **User override:** No automatic independent review chains, no follow-on task, Commit/Push, IAM change, Trust Anchor enrollment, or AWS mutation without an explicit Human Owner decision for that action. A bounded self-check suffices before the Owner checkpoint.

**Goal:** Enumerate CUR-billed resources without overstating coverage, and apply meaningful `Name` tags to eligible, individually constrained resources only after whole-CSV Owner authentication, IAM safety checks, one-time per-row authorization and Readback.

**Architecture:** Reuse existing CUR parsing, metadata investigators, protected OwnerTrust, scope/side-effect checks, crash-safe single-host ledger, and fake executor; create a **purpose-separated Batch path** rather than reinterpret legacy Phase A `VerifiedEnvelope(kind="execution")`. One Owner signature authenticates the exact review CSV/Plan and a fixed approved row set. A host-scoped STS session policy limits write actions to those exact ARNs and `Name`; verified per-row ledger admission and consumption occur before at most one API send. Unsupported kinds remain explicitly reported, never silently tagged.

**Tech Stack:** Python >=3.10, boto3 pinned in `pyproject.toml`, stdlib `unittest`, SQLite durable ledger, OpenSSH `ssh-keygen -Y verify`, STS `AssumeRole`, `uv run --locked --no-build`. No new approval service/UI or mandatory dependency.

**Spec:** `docs/superpowers/specs/2026-11-17-aws-cost-name-tagger-batch-name-assignment-design.md` at `yohi/aws-cost-name-tagger` **`350f17faaab63405015b6e5a207471b79d6f0524`**. This Batch plan is **new and separate** from `docs/superpowers/plans/2026-11-16-aws-cost-name-tagger-controlled-name-write.md` (existing Phase A / one-ARN contract).

**Status / Owner decisions (2026-11-18 JST):** Human Owner replied “すべて承認します” to the four decisions and drafting direction: treat Batch Design adoption, a proposed INV-N05 Batch contract change, G1 exception/Trust Anchor policy direction, and drafting a Batch plan as **approved in principle**. This chat approval is **not** a verified OpenSSH `BatchApprovalV1`, scoped G1 exception artifact, enrolled Trust Anchor, IAM proof, specific AWS ARN/role grant, or an AWS-write execution receipt. **Only plan authoring is performed now**; execute no plan tasks until separately directed. The historic Phase A implementation and all live gates remain as-is.

## Global Constraints

- Keep `SAFETY_HOLD_ACTIVE`, `AWS_WRITE_BLOCKED`, `G1_NOT_PROVEN`, `G2_NOT_VERIFIED`, `AWS_RUNTIME_NOT_AUTHORIZED` as **operationally active** until specific verified evidence and Owner-authorized changes satisfy each applicable gate. No flag, green CI, merged document, or chat-only statement disables a runtime gate.
- The current `name_tag_controlled.execute_approved()`, `aws_cost_name_tagger_v3.apply()`, and `name_tag_adapters.EC2VolumeAdapter.write_name_only()` stay hard-blocked; the original single-ARN `ExecutionAuthorization`, `VerifiedEnvelope`, and `IntentLedger.create_intent()` semantics remain intact.
- Preserve the existing `--min-cost`, `--max-resources=100`, `--max-writes=20`, `run --mode dryrun`, two-pass CUR receipts, read-call/time budgets, and deterministic, no-partial-report-on-budget-error behavior. A future Batch CLI can expose `--dry-run`, but not silently reinterpret legacy flags.
- Batch `Name` eligibility is `ABSENT`, `EMPTY`, or `WHITESPACE_ONLY`, with exact-case `Name`, **untrimmed raw value**, malformed/ambiguous as `UNKNOWN`. Recheck **exact state and raw value** before send. Nonblank existing Name is never overwritten intentionally. The EC2 `CreateTags` API itself has no atomic compare-and-set; G1 race acceptance is a **separately evidenced, bounded operational decision**, not an implementation assertion.
- The CSV header, row sequence, BOM, original Plan bytes, non-`approved` cell values, approved `approved=YES` rows, derived account/partition/region/ARN/Name/API/scope are authenticated. The approved CSV **exact bytes** are hashed; one purpose-specific Owner-signed `BatchApprovalV1` canonical payload binds all digests. No unsigned row can trigger an Intent.
- Reacquire the **current protected Trust configuration** (including enrollment, revocation, roles and `allowed_signers` SHA) at **each** row admission; validating a cached `OwnerTrust` signature alone is insufficient. `allowed_role="batch-approver"`; Batch namespace is distinct from Phase A.
- Durable `(batch_nonce, batch_id)` association is distinct from one-time `(batch_id,row_index)` / `row_authority_id`. Same Batch may admit a previously unused next row; used rows and nonces rebound to another Batch are forever rejected. `SEND_ATTEMPT_CONSUMED` persists before the one SDK attempt; no retry after crash, timeout, ambiguous outcome, or expired session.
- Pre-send Read and Readback use the **same** host-issued `IssuedBatchSession` credentials (Design option B). Read and write are separated by action statements and controlled call paths, **not** by an imaginary second IAM principal. Exact approved-ARN/Name write constraints must be provable against all effective grants; `Resource:"*"` for necessary Describe/List is allowed only in a **read-only** statement.
- On `OUTCOME_UNKNOWN`, Readback mismatch, unknown/missing/torn ledger, scope `HOLD`, lost issuance provenance, expired/revoked Owner, or unproven IAM effective denial: **zero subsequent sends**, no automatic session reissuance, no auto-rollback; classify remaining approved rows `NOT_ATTEMPTED_BATCH_STOP`.
- Existing Phase A Plan is **unchanged and normative for Phase A**. Proposed Batch names/signatures and any G1 exception must not be accepted by the old CLI/executor. Run only locally authorized offline tests when later instructed; no CI/AWS call as part of **writing this plan**.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `aws_cost_name_tagger_v3.py`, `test_aws_cost_name_tagger_v3.py` | Existing CUR scanning, budget handling and metadata resolver; expose pre-cap aggregates and reconciliation while leaving old CLI safe | Narrow modifications |
| `name_tag_batch_state.py`, `test_name_tag_batch_state.py` | Batch-only Name state/raw-value classifier and reviewed Plan/CSV projection | Create |
| `name_tag_batch_approval.py`, `test_name_tag_batch_approval.py` | Strict Batch schema, exact-CSV/Plan digest binding, Owner signature, row authority IDs, revalidation | Create |
| `name_tag_batch_trust.py`, `test_name_tag_batch_trust.py` | Reuse protected Phase A Trust loader and re-read *latest* protected enrollment/revocation/role at row admission | Create; minimal delegate in `name_tag_controlled.py` only if necessary |
| `name_tag_ledger.py`, `test_name_tag_ledger.py` | Shared locked SQLite transactions, Batch nonce/row uniqueness, Intent/Permit/Readback durability; preserve Phase A | Narrow additions; no replacement ledger |
| `name_tag_batch_iam.py`, `test_name_tag_batch_iam.py` | Pure API/kind allowlist and canonical STS inline policy construction, write/read separation and subset binding | Create |
| `name_tag_batch_credentials.py`, `test_name_tag_batch_credentials.py` | Host-only issuer interface, protected `IssuedBatchSession` provenance, SDK client construction; fake STS in offline tests | Create |
| `name_tag_batch_executor.py`, `test_name_tag_batch_executor.py` | Batch dry-run/fake/live ports; row pre-read, single consumption, Readback and stop/HOLD | Create |
| `name_tag_batch_report.py`, `test_name_tag_batch_report.py` | Disjoint outcome/cost reconciliation and final result lists | Create |
| `name_tag_controlled.py`, `test_name_tag_controlled.py`, `README.md` | Opt-in Batch CLI/report documentation; legacy CLI remains blocked | Narrow modifications |
| `name_tag_batch_live.py`, `test_name_tag_batch_live.py` | Gated concrete Name-only mutation port for service kinds *proven* to enforce ARN/Name restrictions | Create only after operational gate |

No new database service, web UI, signing infrastructure or IAM-admin application. Keep units small; do **not** refactor the legacy 1,665-line ledger for style alone. Use existing secure SQLite lock/transaction helpers rather than a second ledger.

## Review Focus (five failure classes, pinned to task tests)

1. CUR contains more than 100 above-threshold resources or reaches a read budget: `test_population_cap_cost_reconciles` / `test_cur_budget_never_claims_complete` (Task 1) require truthful count/cost, no false `coverage_complete`.
2. Blank Name contains full-width spaces, a tab or malformed case-variant keys: `test_whitespace_raw_exact_and_unknown_protected` (Task 2) requires exact raw-value guard, no accidental overwrite.
3. Approved CSV/Plan mutates or Owner role is revoked between rows: `test_csv_bytes_or_row_change_rejected` / `test_current_protected_trust_rechecked_per_row` (Task 3) require no Intent/send.
4. Crash after first row, then restart while the same Batch nonce exists: `test_same_batch_unused_row_allowed_used_row_rejected` / `test_consumed_crash_cannot_replay` (Task 4) allow only the unused next row with intact scope/history, never resend a used row.
5. A read-only `Resource:"*"` action, inherited resource-policy grant or foreign/expired STS credential is present: `test_wildcard_describe_never_expands_writes` / `test_foreign_credential_or_policy_binding_denied` (Task 5) require zero send; a post-send Readback failure stops the Batch (Task 6).

---

### Task 1: Reconcile the complete CUR population without relaxing budgets

**Files:** Modify `aws_cost_name_tagger_v3.py` near `_cur_accumulate_usage()` / `_cur_ranked_candidates()` / `cur_candidates()` / `plan()`, test `test_aws_cost_name_tagger_v3.py`.

**Interfaces:** Provide `partition_cur_population(aggregates: Mapping[tuple[str,str,str], float], *, min_cost: float, max_resources: int) -> CurPopulation` (Batch-only immutable result). Fields: `cur_recognized_count/cost`, `below_min_cost_count/cost`, `above_min_cost_count/cost`, `lookup_selected_count/cost`, `max_resources_not_inspected_count/cost`, and deterministic selected candidates; track `unattributable_cur` separately in the bounded CUR scan with an explicit known/unknown accounting flag. Keep `cur_candidates()` legacy output unless its existing callers are explicitly adapted. All pre-cap sums use original precision, rounded only on presentation.

- [ ] **Step 1: Write failing tests**: `test_population_cap_cost_reconciles` with 105 above-threshold resources and `max_resources=100` asserts selected=100, excluded-by-cap=5 and all cost subtotals reconcile; `test_min_cost_and_max_resources_are_disjoint` with below-threshold rows; `test_unattributable_cur_not_claimed_as_named_resource`; `test_cur_budget_never_claims_complete` when bounded scan fails.
- [ ] **Step 2: Run tests to confirm failure**: `uv run --locked --no-build python -m unittest -v test_aws_cost_name_tagger_v3` (targeted cases first); expected new tests fail because pre-cap accounting is not exposed.
- [ ] **Step 3: Implement the minimal aggregate partition and summary fields**, without extra AWS reads, changes to cost-ranking semantics, arbitrary budget increases or partial-success publication on scan failure.
- [ ] **Step 4: Re-run the same tests and existing CUR-focused tests**; PASS means every CUR-recognized key belongs to exactly one threshold/cap class, while incomplete input remains `UNKNOWN/INCOMPLETE`.
- [ ] **Step 5: Owner-authorized commit only**: `feat: account for CUR cost population before caps`. Stop if authorization to commit is absent.

### Task 2: Batch-only Name/raw-value and immutable Plan-to-CSV mapping

**Files:** Create `name_tag_batch_state.py`, `test_name_tag_batch_state.py`; minimal Batch reporting entry in `aws_cost_name_tagger_v3.py` or separate adapter (do not weaken legacy `name_state()`); test `test_name_tag_review.py` for Phase A compatibility.

**Interfaces:** `classify_batch_name(tags: object) -> NameObservation` with immutable `state: Literal["ABSENT","EMPTY","WHITESPACE_ONLY","NONEMPTY","UNKNOWN"]`, `name_key_present: bool | None`, `name_raw_value: str | None`. `build_batch_review_projection(plan_bytes: bytes) -> bytes` retains exact 14 legacy `.review.csv` columns and the UTF-8-SIG BOM. `validate_batch_csv(plan_bytes: bytes, csv_bytes: bytes) -> tuple[BatchReviewedRow,...]` rejects edits to any column except `approved`; only exact `YES` grants a row. Derive resource ARN/account/partition/operation from frozen Plan/scope/allowlist, not CSV-supplied identifiers.

- [ ] **Step 1: Add** `test_whitespace_raw_exact_and_unknown_protected` (absent, empty, half/full-width spaces, tab, mixed nonblank, present-null, variant `name`, malformed list) and `test_csv_only_approved_cell_editable` / `test_duplicate_unknown_column_and_row_reorder_denied` / `test_phase_a_name_state_unchanged`.
- [ ] **Step 2: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_state test_name_tag_review`; new tests fail; old Phase A behavior remains authoritative.
- [ ] **Step 3: Implement Batch classifier, exact raw-value/proposal binding and strict CSV projection**; ensure `proposal_id` uniqueness and raw values survive round-trip without stripping. Any ambiguous Name is a no-send row.
- [ ] **Step 4: Re-run** the above tests; PASS including Phase A regression.
- [ ] **Step 5: Owner-authorized commit only**: `feat: preserve batch Name state and strict review CSV identity`.

### Task 3: One whole-CSV Owner signature with fresh Trust revalidation

**Files:** Create `name_tag_batch_approval.py`, `name_tag_batch_trust.py`, `test_name_tag_batch_approval.py`, `test_name_tag_batch_trust.py`; minimally reuse protected loader from `name_tag_controlled._load_owner_trust()` without changing Phase A verification behavior.

**Interfaces:** `verify_batch_approval(plan_bytes: bytes, csv_bytes: bytes, signed_batch_envelope: bytes, *, trust: OwnerTrust, now_utc: datetime) -> VerifiedBatchApproval`; `derive_batch_row_authority(batch: VerifiedBatchApproval, row_index: int) -> VerifiedBatchRowAuthority`; `load_current_protected_owner_trust() -> OwnerTrust` reopens root/host-protected config, enrolled keys, roles, revocation map and pinned `allowed_signers` on **every** row admission. Frozen `VerifiedBatchApproval` retains raw signed bytes, `batch_id`, `batch_nonce`, exact Plan/CSV digests, immutable approved tuple set and owner ID. `row_authority_id = SHA256(canonical_UTF8_JSON([batch_id,row_index,proposal_id,account,partition,region,resource_arn,approved_name,aws_operation,scope_id]))`.

- [ ] **Step 1: Add** `test_csv_bytes_or_row_change_rejected`, `test_signature_wrong_namespace_or_role_denied`, `test_owner_id_fingerprint_not_self_attested`, `test_current_protected_trust_rechecked_per_row` (role revoked/changed after the first row), `test_approved_row_identity_and_raw_name_bound` and `test_cross_batch_row_authority_rejected`.
- [ ] **Step 2: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_approval test_name_tag_batch_trust` to see missing-interface failures.
- [ ] **Step 3: Implement strict `BatchApprovalV1`** with exactly the spec's payload keys, `allowed_role="batch-approver"`, SHA-256 digests of **exact CSV and Plan bytes**, approved ordered tuples, canonical UTF-8 JSON, distinct OpenSSH Batch namespace, pre-enrolled signer and deeply immutable verifier output. Use existing `OwnerTrust`/OpenSSH verification primitives, but not a forged Phase A `VerifiedEnvelope`. Reparse raw envelope and reverify using **fresh** protected trust immediately before each ledger admission; failure `BLOCKED_OWNER_AUTHN`, no Intent.
- [ ] **Step 4: Run new tests and** `uv run --locked --no-build python -m unittest -v test_name_tag_approval test_name_tag_controlled`; PASS includes no regression for old trust/role/namespace contracts.
- [ ] **Step 5: Owner-authorized commit only**: `feat: authenticate one batch CSV with protected OwnerTrust`.

### Task 4: Durable batch nonce/row replay on the existing host ledger

**Files:** Modify `name_tag_ledger.py` minimally; create `test_name_tag_batch_ledger.py`; keep `test_name_tag_ledger.py` and `test_name_tag_ledger_open.py` intact as regressions.

**Interfaces:** A separately admitted `create_batch_intent(row_authority: VerifiedBatchRowAuthority, *, scope: ScopeEvidence, side_effects: Sequence[SideEffectEvidence]) -> IntentHandle` using a host-bound latest-Trust provider from Task 3, never an untrusted runtime parameter. Maintain durable unique `(batch_nonce,batch_id)` registration and `(batch_id,row_index,row_authority_id)` row admission in the **existing** SQLite ledger/locking and host binding. Reuse existing `IntentHandle`, `FirstSendPermit`, durable `consume_first_send()` and `record_readback()` where semantics can be preserved. For Batch-only Intents, set a unique `authorization_id=row_authority_id`; preserve legacy Phase A schema paths and signature gate separately.

- [ ] **Step 1: Add** `test_same_batch_unused_row_allowed_used_row_rejected` (two signed YES rows: first terminal → second first-use allowed), `test_batch_nonce_rebind_denied`, `test_row_index_collision_and_cross_batch_substitution_denied`, `test_consumed_crash_cannot_replay`, `test_revocation_before_next_row_blocks_without_intent`, `test_missing_or_torn_history_never_reinitializes` and `test_scope_hold_stops_remaining_rows` using temporary protected test ledger only.
- [ ] **Step 2: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_ledger`; new tests fail as expected.
- [ ] **Step 3: Implement atomic registration and admission** under existing host lock/SQLite durability; batch nonce may already be associated with its **same** batch, but no previously admitted row may be recreated even when no SDK call happened. Before Intent, refresh Trust, inspect scope/side-effect coverage, verify rows and `batch_id`, reject incomplete prior Intent and expired Batch; consume once before the fake send; no automatic replay/reset after RELEASE.
- [ ] **Step 4: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_ledger test_name_tag_ledger test_name_tag_ledger_open`; PASS includes restart/crash boundary and existing Phase A tests.
- [ ] **Step 5: Owner-authorized commit only**: `feat: add batch one-shot ledger admission without changing phase A`.

### Task 5: Exact ARN/Name IAM policy and protected issued credential provenance

**Files:** Create `name_tag_batch_iam.py`, `name_tag_batch_credentials.py`, `test_name_tag_batch_iam.py`, `test_name_tag_batch_credentials.py`.

**Interfaces:** `build_subset_session_policy(batch: VerifiedBatchApproval, row_indexes: tuple[int,...], *, kind_registry: Mapping[str, KindPolicy]) -> SessionPolicySpec` with canonical `policy_bytes`, digest, exact allowlisted write ARNs/actions and **separate read-only** statements; reject duplicate/overlapping subsets and STS size-limit overruns. `BatchCredentialIssuer.issue(batch: VerifiedBatchApproval, subset: SessionPolicySpec) -> IssuedBatchSession` is a **trusted host-only** future runtime interface. `IssuedBatchSession` binds `batch_id`, subset index/hash, exact submitted `Policy` bytes/hash, bootstrap principal, `RoleArn`, `RoleSessionName`, STS `AssumedRoleUser`, credential access-key identity, expiry and protected read/write clients built from the **same** credential triplet. No default-provider fallback or secret persistence.

- [ ] **Step 1: Add** `test_wildcard_describe_never_expands_writes` (`ec2:DescribeVolumes` with `Resource:"*"` permitted solely for read), `test_other_key_foreign_arn_and_api_denied`, `test_unsupported_kind_and_condition_fails_closed`, `test_session_policy_not_omitted_on_error`, `test_foreign_credential_or_policy_binding_denied`, `test_expired_or_mixed_session_denied`, `test_getcalleridentity_not_policy_proof`, `test_issuer_only_calls_assume_role_with_exact_policy` using **fake STS clients**, and `test_session_size_limit_refuses_widening`.
- [ ] **Step 2: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_iam test_name_tag_batch_credentials`; new tests fail, **no real STS call**.
- [ ] **Step 3: Implement** policy generator and issuer/receipt for the **first proven kind** (`volume`/`ec2:CreateTags:2016-11-15`) without assuming other 17 resource kinds are write-safe. Use `ForAllValues:StringEquals` with `aws:TagKeys=["Name"]` plus nonempty-key guard where applicable, service-specific required conditions, exact approved ARNs, and zero configuration-write actions. For Read use the same session's `ec2:DescribeVolumes` as a separate read statement; account/partition/region/target must be verified. The issuer must submit exact `Policy` on `AssumeRole` and retain a protected in-process issue receipt; STS identity is corroboration, **not** session-policy attestation. A foreign resource-based grant or inability to prove effective write denial remains a runtime HOLD.
- [ ] **Step 4: Run** offline tests; PASS means static policy and lineage invariants, **not live AWS IAM proof**. Inspect AWS official Service Authorization Reference for each newly allowlisted kind; unsupported kinds stay `IAM制約による未対応`.
- [ ] **Step 5: Owner-authorized commit only**: `feat: bind scoped batch IAM policies to issued STS sessions`.

### Task 6: Batch executor, no-send dry-run, results and CLI (offline only)

**Files:** Create `name_tag_batch_executor.py`, `name_tag_batch_report.py`, `test_name_tag_batch_executor.py`, `test_name_tag_batch_report.py`; narrowly modify `name_tag_controlled.py`, `test_name_tag_controlled.py`, `README.md`.

**Interfaces:** `execute_batch_offline(batch: VerifiedBatchApproval, *, ledger: IntentLedger, adapter_factory: FakeAdapterFactory, report: BatchReportSink) -> BatchRunResult` accepts only explicitly injected fake clients and never constructs an AWS client. `build_batch_dry_run(plan_bytes: bytes, csv_bytes: bytes, *, report: BatchReportSink) -> BatchRunResult` is **no send**. `BatchRunResult` contains disjoint primary outcome/count/cost, `coverage_complete`, `writes_complete`, and separately extractable `Name自動生成不可` list. Add Batch CLI commands (`prepare-batch`, `verify-batch`, `batch-dryrun`, `batch-simulate`) with explicit input/output paths and no live write command initially; preserve old commands unchanged.

- [ ] **Step 1: Add** `test_no_signature_no_send`, `test_whitespace_raw_changed_before_send_no_send`, `test_two_approved_rows_each_sent_once_fake`, `test_unapproved_and_nonempty_skipped`, `test_postsend_readback_failure_stops_batch_and_holds_scope`, `test_missing_fresh_trust_prevents_next_row`, `test_max_writes_marks_unattempted`, `test_coverage_never_overreported`, `test_name_generation_failure_is_reported`, `test_dryrun_and_old_cli_zero_live_sdk_calls`.
- [ ] **Step 2: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_executor test_name_tag_batch_report test_name_tag_controlled`; new tests initially fail.
- [ ] **Step 3: Implement strict sequential fake execution**: revalidate Batch signature, current Trust, scope, issuance provenance (using fake issuer where necessary), actual Name state/raw value; create Batch row Intent; durably consume send; make **one fake Name-only call**; Readback and store result; stop Batch on `OUTCOME_UNKNOWN` or HOLD. Report all CUR/cap exclusions separately and use exactly one primary final class per recognized resource.
- [ ] **Step 4: Run** `uv run --locked --no-build python -m unittest discover -s . -p 'test_*.py'`; PASS plus independent static confirmation legacy `execute-approved`, `apply`, and `EC2VolumeAdapter.write_name_only` remain blocked.
- [ ] **Step 5: Owner-authorized commit only**: `feat: provide batch dry-run, offline executor and reconciled results`.

### Task 7: Gated real AWS Name write port and eligible-kind expansion (separate execution gate)

**Files:** Create `name_tag_batch_live.py`, `test_name_tag_batch_live.py`; modify `name_tag_batch_executor.py`, `name_tag_controlled.py` only for an isolated opt-in live entrypoint; keep `name_tag_adapters.EC2VolumeAdapter.write_name_only` and original `execute-approved` blocked.

**Interfaces:** `AuthorizedBatchWritePort.write_once(*, session: IssuedBatchSession, row: VerifiedBatchRowAuthority, permit: FirstSendPermit, runtime: AuthorizedBatchRuntimePolicy) -> None` is the **only** Batch SDK mutation boundary. The verifier-derived `AuthorizedBatchRuntimePolicy` is unforgeable by operator arguments and binds signed `batch_id`/row, exact service/SDK action, scope, issuance receipt, effective-write-denial evidence, code identity, bounded G1 exception and all required Owner gate documents. Do not construct it from a boolean or untrusted JSON. `BatchKindRegistry` only enables kinds with documented exact tag API/ARN granularity/Name-key IAM enforcement/Readback/side-effect checks; unsupported kinds remain visible in the report.

- [ ] **Step 1: Add offline mock tests** `test_no_live_port_without_verified_policy`, `test_foreign_arn_other_tag_or_action_denied`, `test_consumed_permit_required`, `test_pre_send_raw_name_change_denied`, `test_live_sdk_single_call_bound`, `test_credential_provenance_lost_denied`, `test_readback_unknown_stops_without_retry`, `test_service_allowlist_rejects_unsupported_kind`.
- [ ] **Step 2: Run** `uv run --locked --no-build python -m unittest -v test_name_tag_batch_live`; new tests fail while **no AWS credentials or calls** are available.
- [ ] **Step 3: Implement minimal live port** for `volume` first, via the approved `ec2:CreateTags` request builder and exactly the issued-session client; ensure `Resources=[verified_volume_id]` and `Tags=[{"Key":"Name","Value":approved_name}]`. Do not enable it until all Task 7 gates below are **verified**. Expand only to other service/kinds with the same kind-specific negative IAM/API evidence, rather than assuming all CUR-recognized kinds are writable or scheduling one review task per service.
- [ ] **Step 4: Run** only offline mock/regression tests until a separate **operational** Owner GO provides signed batch, exact ARN/account/role/subset, protected enrolled keys, scoped G1 decision, verified G2/writer-control/side-effect evidence, actual IAM effective-denial evidence, and a safe stop/rollback *procedure* (not automatic retry). No real AWS call may be a test substitute. Actual IAM policy creation, Trust Anchor enrollment, `AssumeRole`, and Name writing are separately permitted actions and require the concretely identified scope.
- [ ] **Step 5: Owner checkpoint, no automatic live execution or commit.** Report precisely which kinds are proven, which remain unsupported, and any evidence gap. Only then decide whether to opt in and authorize a specific live Batch with its own signed `BatchApprovalV1` and per-run credentials; never use the ChatGPT approval as a signature or as an ARN-set grant.

## Acceptance / stop gates

- **Offline functional exit (Tasks 1–6):** all bounded CUR populations/costs reconcile, `coverage_complete` never conceals caps, whitespace/raw-value and meaningful Name are protected, CSV Owner signature and latest protected Trust are enforced, two unused approved rows can execute fake-once in the same Batch, used rows cannot replay, generated IAM policies never widen write scope, Readback/unknown/HOLD stop the Batch, and 100% legacy Phase A write blocks stay intact. Offline test PASS is **not** implementation approval or AWS authorization.
- **Real-writer entry gate (Task 7):** fixed account/role/ARN subset/Name/API, actual verified Owner cryptographic Batch approval, valid current key/role/revocation, verified scoped G1 decision and G2 control evidence, trusted issuer/AssumeRole policy/credential provenance, independent effective IAM deny checks including inherited and resource-based grants, no competing-writer risk hidden, documented residual race exposure, audit + explicit stop procedure. **Any missing/unknown gate means zero live mutations.**
- **Hard stop:** permission to proceed with one work item is not permission to expand to more work items, extra review rounds, automatic replays, credential renewal, IAM changes, new PRs or next AWS target. No user-authorized AWS write occurs during this plan-authoring request.
- **Residual risk:** EBS `CreateTags` overwrites an existing key between Pre-send Read and Send; a narrowly scoped G1 exception may accept but cannot eliminate this race. IAM simulators alone cannot prove that session/resource policies never bypass the restriction. STS issues credentials, but `GetCallerIdentity` does not attest the inline session policy. Unknown future service behavior is reported as unsupported, never inferred safe.

## Human Owner checkpoint

This plan is an **implementation proposal**, not a signed authorization or an executable AWS operations schedule. In the current conversation the Owner indicated approval of the broad decisions; formal Batch approval, protected Trust enrollment, G1/G2 scope evidence, actual IAM modifications and concrete AWS writes still require the exact identities/artifacts demanded by the adopted security contract. The Owner can later authorize **Tasks 1–6 as a bounded offline implementation** and decide Task 7 separately. Prefer **Native** execution with one bounded self-check and an Owner stop point, not a repeated independent review chain. **Do not auto-start any task after creating this document.**

## AWS reference material (design only)

- [STS AssumeRole — inline session policy, credentials and role/session limitations](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [IAM policy evaluation, resource-based grants and explicit denies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
- [EC2 service-authorization: `CreateTags`, resource ARN and `aws:TagKeys`](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html)
- [EC2 IAM Describe operations and wildcard resource restrictions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html)
- [EC2 CreateTags — existing key is overwritten](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTags.html)
