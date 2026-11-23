# Batch Identity and Population Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep Batch Plan identity, selected CUR population, validation evidence, and CSV reports consistent.

**Architecture:** Normalize global resource identities before CUR selection, validate signed summaries against selected records, and preserve strict identity boundaries during projection, evidence verification, and reporting. Keep fixes in the existing modules and add focused regressions to their existing tests.

**Tech Stack:** Python, `unittest`, `decimal.Decimal`.

**Spec:** `docs/superpowers/specs/2026-11-23-batch-identity-and-population-integrity-design.md`

## Global Constraints

- Keep CUR source validation bounded by `MAX_COST_DIGITS`; permit intermediate/aggregate outputs up to `MAX_AGGREGATE_DIGITS`.
- Snapshot Scope declarations accept only the accountless canonical snapshot ARN. Reject account-bearing legacy declarations; do not normalize or silently migrate them.
- In Batch report mode, preserve an explicitly empty `resource_arn`; retain legacy ARN derivation only for non-Batch reports.
- Preserve existing overall signed population checks and actual post-projection identity collision rejection.

## Review Focus

- Regional S3 aliases must count once for threshold and resource-cap selection; test in the global CUR aggregation task.
- Duplicate identities discovered after projection must still fail closed; test alongside global selection.
- Selected records must reconcile per Kind as well as globally; test valid summaries and per-Kind count/cost tampering.
- Account-bearing snapshot legacy declarations must reject while canonical accountless declarations pass; test both in Scope validation.
- Explicit empty Batch ARN must not be derived, while non-Batch fallback stays intact; test both report modes.

---

### Task 1: Exact aggregate validation and per-Kind population reconciliation

**Files:**
- Modify: `name_tag_batch_population.py`
- Test: `test_name_tag_batch_population.py`

**Interfaces:**
- Preserve `exact_add(values) -> Decimal` and `validate_kind_precap(plan, population) -> None`.
- `validate_signed_population(plan)` continues to invoke per-Kind and overall population validation.

- [ ] **Step 1: Write failing tests** for aggregate values whose digit count is greater than `MAX_COST_DIGITS` but at most `MAX_AGGREGATE_DIGITS`, aggregate values beyond `MAX_AGGREGATE_DIGITS`, and plans whose per-Kind selected record count or cost disagrees with `lookup_selected`.
- [ ] **Step 2: Run** `python -m unittest test_name_tag_batch_population -v`. Confirm the new regressions fail against current behavior.
- [ ] **Step 3: Implement** validation of computed sums using aggregate bounds without weakening CUR source validation; compare each Kind's `lookup_selected` count and exact cost with the matching Plan records.
- [ ] **Step 4: Run** `python -m unittest test_name_tag_batch_population -v`; confirm new and existing population tests pass, including overall signed totals and historical plans without the optional per-Kind field.

### Task 2: Canonical global identity before CUR selection

**Files:**
- Modify: `aws_cost_name_tagger_v3.py`
- Test: `test_aws_cost_name_tagger_v3.py`
- Test: `test_name_tag_batch_identity_projection.py`

**Interfaces:**
- Preserve the `cur_candidates_batch(...)` return contract and `partition_cur_population(...)` input/output contract.
- Keep `_reject_identity_collisions(records)` as a final fail-closed check.

- [ ] **Step 1: Write failing tests** with one S3 bucket represented under different product region codes, proving it is thresholded and capped once and that population count/cost matches selected candidates. Add/retain a test proving real post-projection duplicate identities still reject.
- [ ] **Step 2: Run** `python -m unittest test_aws_cost_name_tagger_v3 test_name_tag_batch_identity_projection -v`; confirm the alias-selection regression fails and collision rejection remains covered.
- [ ] **Step 3: Implement** preselection normalization of global-scope resource keys and ensure candidate records and all population summaries derive from that normalized selection.
- [ ] **Step 4: Run** the same focused tests; confirm alias aggregation, population reconciliation, thresholds, limits, and collision rejection pass.

### Task 3: Projection, Scope declaration, evidence, and Batch report identity

**Files:**
- Modify: `aws_cost_name_tagger_v3.py`
- Modify: `name_tag_batch_state.py`
- Modify: `name_tag_kind_name_evidence.py`
- Test: `test_aws_cost_name_tagger_v3.py`
- Test: `test_name_tag_batch_state.py`
- Test: `test_name_tag_kind_name_evidence.py`

**Interfaces:**
- Preserve `_project_pre_sign_identity(record, partition, account) -> None`, `verified_generated_name(record, target) -> VerifiedGeneratedName`, and existing Scope declaration validation interfaces.
- Keep `write_action_csv(...)` behavior unchanged for non-Batch modes.

- [ ] **Step 1: Write failing tests** covering API Gateway Plan locator replacement before proposal-key generation; RDS cluster projection using ARN while retaining the CUR locator; accountless snapshot declaration acceptance and account-bearing legacy rejection; evidence locator mismatch rejection before verifier invocation; and Batch empty-ARN preservation versus non-Batch ARN fallback.
- [ ] **Step 2: Run** `python -m unittest test_aws_cost_name_tagger_v3 test_name_tag_batch_state test_name_tag_kind_name_evidence -v`; confirm each new regression fails.
- [ ] **Step 3: Implement** the identity-specific changes: use the projected ARN only for API Gateway record locator, use ARN as the RDS cluster projection input without mutating its record locator, enforce snapshot compatibility across Plan declarations, compare record and target locators before evidence verification, and restrict ARN fallback to non-Batch reports.
- [ ] **Step 4: Run** the same focused tests; confirm all identity, evidence, compatibility, and report regressions pass.

### Task 4: Full verification and delivery

**Files:**
- Verify all changed modules and tests from Tasks 1–3.

- [ ] **Step 1: Run** `python -m unittest test_name_tag_batch_population test_name_tag_batch_identity_projection test_name_tag_batch_state test_name_tag_kind_name_evidence test_aws_cost_name_tagger_v3 -v`.
- [ ] **Step 2: Run** `python -m unittest discover -v` and repository-configured lint/type checks, if present; resolve only failures attributable to this change.
- [ ] **Step 3: Review** the final diff and `git diff --check`; verify no unrelated files or generated outputs changed.
- [ ] **Step 4: Commit** the implementation and tests in focused Conventional Commit(s), then push the current branch and report the commit IDs and verification results.
