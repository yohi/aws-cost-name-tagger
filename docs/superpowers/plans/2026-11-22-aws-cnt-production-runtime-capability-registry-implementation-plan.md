# AWS-CNT Production Runtime Capability Registry Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (recommended Native execution) or superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking. All execution requires a separate Human Owner implementation GO.

**Goal:** Implement the offline-verifiable production runtime for all 18 CUR-recognized kinds, with service-specific Name-only adapters only where their safety contracts are supported, and preserve explicit blockers and counts/costs for other kinds, without enabling unapproved AWS writes.

**Architecture:** Extend the existing signed Batch Plan v3 / BatchApprovalV1, single protected Host/Ledger Coordinator, and Task 7 EBS boundary. A versioned Kind Capability Registry owns deterministic identity, evidence-backed eligibility, per-kind IAM and safe SDK adapter selection; a Host-only issuer and protected runtime verifier bind real STS issuance, effective deny evidence, and one consumed FirstSendPermit before any actual dispatch. A synthetic success path is never live authority.

**Tech Stack:** Python >=3.10; pinned boto3[crt]==1.43.116 / botocore from uv.lock; existing unittest, Decimal, OpenSSH OwnerTrust, SQLite host-bound IntentLedger, AWS SDK client protocols. No new network services or dependencies without separately scoped Owner approval.

**Spec:** `docs/superpowers/specs/2026-11-21-aws-cost-name-tagger-production-runtime-capability-registry-design.md` R0.1.1, feature branch HEAD `99d9f982eb5953266cbfca1389efe2767270ac64` at planning start. Historical Tasks 1–7 plan: `docs/superpowers/plans/2026-11-18-aws-cost-name-tagger-batch-implementation-plan.md` (read only; do not retroactively revise).

**Planning status:** `PLAN_PROPOSED / OWNER_DESIGN_ADOPTION_PENDING / IMPLEMENTATION_GO_HOLD`. Invoking writing-plans authorizes this document, **not** source changes or operational AWS rights. Revalidate branch HEAD and Design before any later implementation.

## Global Constraints

- Preserve Batch Plan `schema_version=3`, `cur_population.schema_version=2`, immutable 14-column BOM CSV (only `approved` is editable), `BatchApprovalV1` canonical bytes/namespace, approved-row tuples, Plan/CSV digests, signer role/revocation, and all existing Phase A contracts.
- Target 18 kinds exactly: `instance, volume, snapshot, eni, eip, nat, endpoint, rds_cluster, rds_instance, opensearch, elbv2, apigw_stage, cloudfront, athena_workgroup, log_group, lambda, wafv2, s3_bucket`.
- Existing `volume` remains offline-proven only. All new kinds begin `CAPABILITY_NOT_PROVEN` until the *specific* API, Name evidence, identity, IAM conditions and tests justify promotion to `IMPLEMENTED_OFFLINE`. Never treat offline status as production permission.
- Keep distinct `UNSUPPORTED_BY_POLICY` (proven safety incompatibility), `UNSUPPORTED_API` (proven lack of safe API), `CAPABILITY_NOT_PROVEN` (missing evidence), `LIVE_GATE_PENDING` (offline code done but host acceptance missing), and `IMPLEMENTED_OFFLINE`. Reason codes must be grounded, not silently defaulted.
- Name exact-case states `ABSENT`, `EMPTY`, `WHITESPACE_ONLY` are only eligible snapshots; `NONEMPTY` and `UNKNOWN` never permit overwrite. Preserve exact original `name_key_present` / `name_raw_value` and recheck before send.
- One Owner-approved immutable `Plan/CSV` pair and `VerifiedBatchRowAuthority` per row; one protected Scope declaration/independent proof, one durable Intent, one consumed FirstSendPermit, at most one Name-key mutation request, same-credential Readback. Never retry unknown sends.
- Signed `execution_limits.max_send_attempts` remains integer 1..20. Preserve cross-kind cap exhaustion, stop, Scope HOLD and host fail-closed semantics. The CUR distinct-resource budget remains 250,000 and count/Decimal partitions reconcile exactly.
- No unrestricted write `Resource:"*"`, no multi-resource/multi-tag writes, no ambient credentials, no caller-created authorization token, no silently replaced S3 tag set, no credential material in artifacts/logs/Ledger.
- Actual STS, IAM/Trust modifications, real AWS SDK traffic, G1/G2 proof or live acceptance are **not** performed during this implementation phase. Tests inject Fake transports. Leave `SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED / G1_NOT_PROVEN / G2_NOT_VERIFIED / AWS_RUNTIME_NOT_AUTHORIZED` effective until their distinct protected evidence and Owner GO exist.
- Only implement in the named feature branch or its explicitly approved isolated worktree. Separate Owner approval is needed before implementing; this plan creation is document-only.
- Use RED -> GREEN -> REFACTOR per task, run focused offline tests and existing regressions; do not spawn a new independent review per task. Commit boundaries in the plan are executable **only after** the implementation authorization, and do not confer Push/PR/Merge/AWS approval.

## Review Focus — likely adverse inputs and owning tests

1. CloudFront CUR region `us-east-1` colliding with another signed `global` identity: Task 2 `test_cloudfront_projection_collision_rejected_before_sign`; no double counting or post-sign rewrite.
2. API Gateway parent API's inherited Name tag vs stage-local tag: Task 5 `test_apigw_inherited_name_is_unknown_for_stage_write`; no send or invented ABSENT.
3. Mixed-kind subset policy causing an action/ARN Cartesian-product privilege: Task 4 `test_mixed_kind_policy_never_cross_grants`; no global write or alternate API privilege.
4. S3 Control model missing `tag_resource` or account-owner proof stale: Task 5 `test_s3_sdk_missing_or_owner_unproven_no_write`; never fall back to `put_bucket_tagging`.
5. Expired issuer/effective-IAM evidence or process crash between Permit consumption and result: Tasks 6–8 `test_runtime_evidence_expired_no_intent` and `test_crash_after_permit_outcome_unknown_no_resend`; durable STOP/HOLD.

---

## File responsibility map (fixed decisions)

| Responsibility | Create | Modify / reuse |
|---|---|---|
| 18-kind identity/decision registry and snapshot of candidate proofs | `name_tag_kind_capabilities.py`, `test_name_tag_kind_capabilities.py` | Current `SUPPORTED_KINDS` constant in `aws_cost_name_tagger_v3.py` remains the enumerated baseline |
| Pre-sign regional/global projection and full CUR cost conservation | `test_name_tag_batch_identity_projection.py` | `aws_cost_name_tagger_v3.py`, `name_tag_batch_population.py` (preserve raw CUR accounting; modify only if projection interface requires it), `test_aws_cost_name_tagger_v3.py` |
| Evidence-backed Name eligibility and signed scope | `name_tag_kind_name_evidence.py`, `test_name_tag_kind_name_evidence.py` | `name_tag_batch_state.py`, `test_name_tag_batch_state.py`, `test_name_tag_batch_approval.py`; `name_tag_batch_approval.py` only for bounded integration if needed |
| Per-kind policy builder and proof of no action/ARN cross grant | `test_name_tag_batch_iam_multikind.py` | `name_tag_batch_iam.py`, `test_name_tag_batch_iam.py` |
| Service-specific safe SDK read/write/readback | `name_tag_kind_adapters.py`, `name_tag_kind_adapters_ec2.py`, `name_tag_kind_adapters_services.py`, `test_name_tag_kind_adapters_ec2.py`, `test_name_tag_kind_adapters_services.py` | `name_tag_batch_live.py`, `test_name_tag_batch_live.py` |
| Host-only STS request/response/provenance and effective-IAM evidence verification | `name_tag_batch_host_issuer.py`, `name_tag_batch_host_runtime.py`, `name_tag_batch_iam_evidence.py`, `test_name_tag_batch_host_issuer.py`, `test_name_tag_batch_host_runtime.py` | `name_tag_batch_credentials.py` and its tests; Fake issuer remains isolated |
| Durable permit, Host live coordinator, no-replay/STOP | `test_name_tag_batch_live_runtime.py` | `name_tag_batch_runtime.py`, `name_tag_ledger.py` (only if needed without schema change), `test_name_tag_batch_runtime.py`, `test_name_tag_batch_ledger.py` |
| CLI, 18-kind reporting, offline E2E and safety docs | `test_name_tag_batch_cli_live.py`, `test_name_tag_batch_report_multikind.py`, `test_name_tag_batch_live_e2e.py` | `name_tag_batch_cli.py`, `name_tag_batch_report.py`, `name_tag_batch_outcomes.py`, `README.md`, `SHA256_MANIFEST.json` |

The implementation must not create a second signer, second ledger, or separate independent Batch authority. New small files are port/adapter boundaries around the existing Coordinator, not a new subsystem duplicating orchestration. Keep historical test fixtures working.

## Task 1 — Versioned 18 Kind Capability and Canonical Identity Registry

**Limited remediation baseline:** This Plan's original Spec pointer is the historical Design R0.1.1 at GitHub HEAD `99d9f982...`. Findings 001–004 are applied by the separately uncommitted **Design R0.1.2**; Design §10's 10 completion criteria remain identical. The two document patches must be applied together before later implementation.

**Finding 001 — mandatory Task 1 Registry output.** Define `PreSignKindTarget(identity: CanonicalTargetIdentity, aws_operation: str | None, capability_status: str, reason_code: str)` and `project_pre_sign_kind_target(*, kind: str, locator: str, discovered_region: str, discovered_arn: str | None, partition: str, account: str, evidence: str, proposed_name: str | None) -> PreSignKindTarget` in `name_tag_kind_capabilities.py`, matching Design §4.1.1. The Registry derives canonical ARN, signed Scope region and the **vetted** Kind write operation before signing. A merely candidate or CNP Kind produces `aws_operation=None` and remains unsigned/unapproved report-only. No post-sign projection or implicit operation promotion. The Volume legacy signable contract is preserved; other kinds need a deterministic Name verifier and later IAM/Adapter proof before production promotion.

**Task 1 RED/GREEN additions:** `test_presign_operation_cnp_is_none`, `test_snapshot_accountless_arn_s3_cloudfront_global_wafv2_region_matrix`, `test_vetted_nonvolume_pre_sign_operation_only_after_evidence`, and `test_original_volume_signed_identity_unchanged`. Task 1 GREEN implements Registry behavior only; it does not depend on Task 2's Scope parser or later Task 3 approval. Do not create a second signed schema.

**Files:** Create `name_tag_kind_capabilities.py`, `test_name_tag_kind_capabilities.py`. Reuse `aws_cost_name_tagger_v3.SUPPORTED_KINDS`, Design ``4–4.3.

**Interfaces:**

~~~python
@dataclass(frozen=True)
class CanonicalTargetIdentity:
    kind: str
    locator: str
    resource_arn: str
    partition: str
    owner_account: str
    scope_region: str
    arn_region: str
    arn_account: str
    ownership_proof_ref: str = ""  # syntax admission is NOT a Host ownership attestation

@dataclass(frozen=True)
class KindCapabilityDecision:
    kind: str
    service: str
    read_operations: tuple[str, ...]
    write_operation: str
    readback_operations: tuple[str, ...]
    sdk_request_contract: str
    iam_action: str
    resource_type: str
    tag_key_conditions: tuple[str, ...]
    tag_set_replacement: bool
    side_effect_requirements: tuple[str, ...]
    status: str
    reason_code: str
    evidence_refs: tuple[str, ...]
    version: str

# Design §5.1 uses KindCapability for the same vetted decision;
# keep one type rather than two competing runtime representations.
KindCapability = KindCapabilityDecision

class KindCapabilityRegistry(Protocol):
    def resolve(self, kind: str, arn: str,
                operation: str) -> KindCapabilityDecision: ...

def resolve_kind_capability(kind: str) -> KindCapabilityDecision: ...
def canonical_target_identity(*, kind: str, locator: str, resource_arn: str,
                              partition: str, account: str, scope_region: str
                              ) -> CanonicalTargetIdentity: ...
~~~

Registry data is immutable, versioned, and checked for exact 18 kind parity. The `status` is a trusted code decision (not caller-set or Owner approval), initially CNP except current offline Volume. Identity parser refuses wildcard/alias/foreign partition and validates service-specific ARN grammar. Explicit exceptions: CloudFront account-qualified but regionless ARN with signed scope `global`; S3 regionless+accountless bucket ARN with signed scope `global` and *no inferred live owner*; EC2 accountless snapshot; API Gateway accountless Stage; WAF global endpoint uses actual ARN region `us-east-1` rather than invented `global`.

- [ ] **Step 1 — RED:** Create `test_name_tag_kind_capabilities.py` with `test_exact_18_kinds_and_default_cnp`, `test_global_and_accountless_arn_matrix`, `test_wildcard_cross_account_and_alias_rejected`. Include each of 18 positive canonical ARN examples and paired malformed/foreign cases.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_kind_capabilities -v`; expected import/function/assertion failures only.
- [ ] **Step 3 — GREEN:** Implement the two exact entry points and immutable data types above; use a local kind-to-rule map, never a generic ARN `split`-only allow.
- [ ] **Step 4 — Verify GREEN:** Repeat the focused unittest; expect PASS, no AWS calls or network imports.
- [ ] **Step 5 — Commit after separately approved implementation GO:** `git add name_tag_kind_capabilities.py test_name_tag_kind_capabilities.py && git commit -m "feat(batch): register 18 scoped kind capabilities"`.

## Task 2 — CloudFront Pre-sign Projection; CUR Identity and Global Scope

**Finding 001 / Finding 002 / Finding 003 — mandatory Task 2 GREEN boundary (does not depend on Task 3).** Extend the Task 2 Files set to include the **minimal syntax-only** `name_tag_batch_state.py:_valid_declared_arn`, `derive_declared_row_scope` and `test_name_tag_batch_state.py` adaptations. These changes recognize **only** the Kind-allowlisted regionless/accountless ARN shapes for an exact signed Scope: `snapshot` accountless EC2 ARN with actual regional Scope; `s3_bucket` global accountless ARN; `cloudfront` global regionless ARN (but account-qualified); `apigw_stage` accountless regional Stage ARN; WAFv2 `CLOUDFRONT` ARN preserves real `us-east-1` Region (not global Scope region) and WAF regional ARN retains its Region. Scope declaration uniqueness and signed Plan account equality stay strict. This *parser* is implemented and tested within Task 2; Task 3 does **not** own or repeat it. The original Task 3 Files mention of `_valid_declared_arn` and `derive_declared_row_scope` is a legacy scope note, superseded by this Task 2 boundary.

**Task 2 pre-sign sequence:** Raw CUR classification and resource aggregation are unchanged. `cur_candidates_batch` passes all deduplicated Kind aggregates to `partition_cur_population` before threshold/cap filtering. `Investigator.resolve` uses the original service endpoint region; `plan_batch` then calls Task 1 `project_pre_sign_kind_target` **before** `proposal_key` and Plan/CSV serialization. Populate `record['resource_arn']`, `record['region']=scope_region`, `record['aws_operation']` together; do **not** retain the current Volume-only `aws_operation=None` fallback for a genuinely vetted non-Volume Kind. CNP/unsupported Kind retains `None` and is non-signable. The existing `project_unsigned_scope_region` helper is at most an internal narrow region projection used by Task 1; it is **not** the full source of ARN/operation authority. `_batch_partition` uses raw CUR partition evidence, not `_partition_for_region('global')`. Reject duplicate scope membership and conflicting post-projection identity before Plan generation, never after signing.

**Task 2 authenticated Kind pre-cap input contract:** New `cur_candidates_batch` records 18 Kind partitions from the same `CurCostAggregate`/exact Decimal values *before* `--min-cost` and `--max-resources`; return them to `plan_batch` together with existing totals. New Plan v3 gains optional top-level `cur_population_by_kind={'schema_version':1,'kinds':{kind:{stage:{'count':int,'cost_usd':canonical_decimal_str}}}}` for stages `cur_recognized`, `below_min_cost`, `above_min_cost`, `lookup_selected`, `max_resources_not_inspected`. The 18 Kind keys are exact; omitted-from-filter Kind totals are genuinely zero. Validate two identities per Kind and sum of every stage across Kinds = corresponding original `cur_population` stage. The optional field is included in existing `plan_sha256`; `cur_population.schema_version=2`, Batch Plan v3, 14 CSV columns and BatchApprovalV1 remain unchanged. Historical signed Plans lacking this field verify but do **not** claim Kind pre-cap coverage. Invalid new field rejects the whole Plan before approval.

**Task 2 additional RED tests before GREEN:** `test_scope_parser_global_cloudfront_green_before_task3`, `test_snapshot_accountless_owner_scope_syntax`, `test_s3_global_and_waf_regional_scope_no_alias`, `test_presign_nonvolume_arn_region_operation_triplet`, `test_cnp_unsigned_preview_operation_none`, `test_18_kind_precap_below_cost_and_uninspected_reconcile`, `test_precap_field_tamper_rejected`, `test_legacy_plan_v3_without_kind_breakdown_accepted`. GREEN must pass these and existing Task 2 tests with Task 3 still unimplemented. Never use a future approval-stage verifier merely to make the Scope parser pass.

**Files:** Modify `aws_cost_name_tagger_v3.py` (`rid_class` ~194, `resource_arn` ~1581, `plan_batch` ~2032); touch `name_tag_batch_population.py` only for a bounded explicit projection hook, **not** its accounting taxonomy. Create `test_name_tag_batch_identity_projection.py`; extend `test_aws_cost_name_tagger_v3.py` and `test_name_tag_batch_population.py` only as necessary.

**Interface:**

~~~python
def project_unsigned_scope_region(*, kind: str, classified_region: str,
                                  canonical_arn: str) -> str: ...
~~~

Keep `rid_class("arn:...:cloudfront::A:distribution/ID") -> (..., "us-east-1")` for the existing CUR resolver. `cur_candidates_batch` and `name_tag_batch_population.classify_cur_row` remain responsible for CUR identity/cost with pre-cap population unchanged. Inside `plan_batch`: resolve using current region and fixed global client endpoint; then **before** `proposal_key`, `resource_arn`/`aws_operation`, `build_batch_review_projection` and Plan bytes, project just the signed record/Scope region to `global`. The selected record, unique exact signed Scope declaration and later row identity all use `global`. Keep `_batch_partition` based on original pre-projection partition evidence, **not** `_partition_for_region("global")`. No hidden region rewriting in verifier or after signature.

- [ ] **Step 1 — RED:** Add `test_cloudfront_presign_scope_global_and_arn_region_empty`, `test_cloudfront_projection_collision_rejected_before_sign`, `test_cur_pre_cap_counts_costs_unchanged`, `test_wafv2_global_endpoint_not_scope_global` and regression for existing Volume region.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_batch_identity_projection -v`; expect specifically new projection failures.
- [ ] **Step 3 — GREEN:** Add the projection helper to `name_tag_kind_capabilities.py`; adapt `plan_batch` only at the pre-sign record-construction boundary; keep `name_tag_batch_population.py` unchanged unless testing shows a necessary compatibility adapter.
- [ ] **Step 4 — Verify GREEN:** Rerun focused projection + existing `test_name_tag_batch_population`; all PASS, including signed Plan v3 uniqueness/Scope checks.
- [ ] **Step 5 — Commit after implementation GO:** Stage only changed implementation/test files; `git commit -m "feat(batch): freeze global kind identity before approval"`.

## Task 3 — Evidence-backed Name Generation and Approved Row Eligibility

**Findings 001/002 — Task 3 only owns evidence and signed eligibility.** Reuse the already GREEN Task 2 canonical Scope parser, without migrating parser work back into Task 3. Extend `validate_approved_batch_row` with a per-Kind evidence-backed name verifier selected by the signed Kind/operation/ARN. For a representative **future-supportable** non-Volume Kind (e.g. EC2 `instance`), use a bounded *test-only* proven capability/evidence fixture and signed exact Plan v3/CSV to show `plan_batch → prepare_batch_approval → verify_batch_approval → derive_batch_row_authority`; in Task 4/5 extend the same fixture to the Kind IAM policy/Adapter. This test-only fixture **must not** promote an unproven production Registry decision. A CNP Kind may remain an unapproved unsigned Preview/report row, but `approved=YES` for it rejects the *entire* approval; counterfeit CSV, wrong operation, mutated ARN/region/Name or ambiguous evidence never becomes a Skip. No new editable CSV fields or changes to BatchApprovalV1/approved tuples.

**Task 3 additional RED/GREEN tests:** `test_nonvolume_presign_to_verified_row_authority`, `test_nonvolume_fake_row_to_kind_iam_and_adapter_after_tasks4_5` (integrated in Tasks 4/5 and 9, not required for Task 3 GREEN), `test_cnp_approved_yes_rejects_whole_draft`, `test_signed_nonvolume_arn_scope_operation_tamper_rejected`, and `test_volume_evidence_legacy_unchanged`. Task 3 GREEN is independent of later Adapter code: the eventual IAM/Adapter trace is closed by Tasks 4/5/9, not faked at Task 3.

**Files:** Create `name_tag_kind_name_evidence.py`, `test_name_tag_kind_name_evidence.py`; modify `name_tag_batch_state.py` (`_valid_declared_arn` ~96, `derive_declared_row_scope` ~159, `_validate_name_eligibility` ~179, `validate_approved_batch_row` ~198). Extend `test_name_tag_batch_state.py`, `test_name_tag_batch_approval.py`. Keep `name_tag_batch_approval.py` wire bytes and `_approved_tuples` unchanged.

**Interfaces:**

~~~python
@dataclass(frozen=True)
class VerifiedGeneratedName:
    kind: str
    resource_arn: str
    generated_name: str
    evidence_digest: str

class KindNameEvidenceVerifier(Protocol):
    def verify(self, plan_record: Mapping[str, object],
               target: CanonicalTargetIdentity) -> VerifiedGeneratedName: ...

def verified_generated_name(record: Mapping[str, object],
                            target: CanonicalTargetIdentity) -> VerifiedGeneratedName: ...
~~~

Per-kind verifiers must deterministically rederive Name **from the existing immutable Plan record/evidence formula**, not from nonempty text or user-supplied proposed Name. Preserve current Volume EBS formula. Only kind/operation pairs with proven registry capability and evidence verifier become signable; otherwise approved=YES rejects **whole Plan/CSV** before a row authority, while unsigned unapproved CNP is reported normally. Exact Plan v3, 14 CSV columns, digests, Owner signer verification and name-state/snapshot raw rules stay byte-compatible.

- [ ] **Step 1 — RED:** Tests `test_volume_evidence_formula_unchanged`, `test_kind_evidence_forged_or_unverifiable_rejects_whole_approval`, `test_unsigned_unproven_kind_still_reportable`, `test_global_scope_must_have_unique_signed_declaration`, `test_signed_plan_v3_and_csv_projection_byte_compatible`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_kind_name_evidence test_name_tag_batch_state test_name_tag_batch_approval -v`; only newly introduced assertions fail initially.
- [ ] **Step 3 — GREEN:** Implement verifier dispatch and deterministic kind-specific parsers for demonstrably supported existing evidence; add identity rule to fixed approved-row Scope selection. Leave unprovable evidence as `NAME_EVIDENCE_NOT_PROVEN`, never relax approval to an unverified guess.
- [ ] **Step 4 — Verify GREEN:** Repeat focused tests, then `test_name_tag_batch_state` / `test_name_tag_batch_approval` fully; all PASS.
- [ ] **Step 5 — Commit after implementation GO:** `git commit -m "feat(batch): bind approved names to kind evidence and scope"` with explicit changed paths.

## Task 4 — Per-kind IAM Least-Privilege Session Policy

**Files:** Modify `name_tag_batch_iam.py` (`KindPolicy` ~17, `build_subset_session_policy` ~32, `_validate_policy_row` ~77). Create `test_name_tag_batch_iam_multikind.py`; extend `test_name_tag_batch_iam.py`.

**Interfaces:** Preserve public signature and return type:

~~~python
def build_subset_session_policy(batch: VerifiedBatchApproval,
    row_indexes: tuple[int, ...], *,
    kind_registry: Mapping[str, KindPolicy]) -> SessionPolicySpec: ...

def verified_kind_policy(capability: KindCapabilityDecision) -> KindPolicy: ...
~~~

Extend `KindPolicy` compatibly (existing positional constructor `KindPolicy("ec2:CreateTags","ec2:DescribeVolumes")` must continue working). Represent per-action validated resource ARN type, read operations, approved tag-key conditions and evidence version; do **not** generate cross-product rights by putting multiple actions and unrelated-kind ARNs into one statement. Group only identical action/condition/resource-type triples or use exact row statements. Do not assume global `aws:TagKeys` condition support; if action-specific condition cannot be documented, build no write policy and record `IAM_CONDITION_NOT_PROVEN`. Enforce 2,048-byte inline policy budget (and block if actual packed-size evidence is missing), exact subset, no Resource `*` write fallback.

**NOTE-001:** API Gateway REST `TagResource` uses HTTP `PUT /tags/{url-encoded-resource-arn}` in the API contract; IAM service authorization lists its `TagResource` with candidates `apigateway:PATCH` / `apigateway:POST` / `apigateway:PUT` and defines a separate `Tags` ARN `arn:{P}:apigateway:{R}::/tags/{UrlEncodedResourceARN}`. The Stage ARN is `arn:{P}:apigateway:{R}::/restapis/{ApiId}/stages/{Stage}`. HTTP method alone **does not prove** the effective IAM action or scoped resource. The implementing engineer must reconcile API operation, IAM action, exact Tags and Stage resource restrictions, and tag-key enforcement against the official current API/service-authorization docs and pinned SDK model. Until exact Name-only effective denial is proven: `apigw_stage = CAPABILITY_NOT_PROVEN`; never hardcode `apigateway:PATCH` as established or enable broad `apigateway:PUT`.

- [ ] **Step 1 — RED:** Tests `test_mixed_kind_policy_never_cross_grants`, `test_unsupported_iam_condition_rejects_without_policy`, `test_apigw_put_http_not_assumed_iam_grant`, `test_policy_size_excess_no_wildcard_fallback`, `test_existing_volume_policy_byte_stable`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_batch_iam_multikind -v`; new cases fail.
- [ ] **Step 3 — GREEN:** Add exact operation/resource/condition compiler and update `_validate_policy_row` to consult vetted Registry and signed row. Preserve Volume policy serialization when its old contract remains applicable; no fake policy can prove live IAM.
- [ ] **Step 4 — Verify GREEN:** `uv run --locked --no-build python -m unittest test_name_tag_batch_iam_multikind test_name_tag_batch_iam -v`; PASS.
- [ ] **Step 5 — Commit after implementation GO:** `git commit -m "feat(batch): compile per-kind bounded session permissions"` with explicitly staged paths.

## Task 5 — Service-specific One-Name Read, Write and Readback Adapters

**Files:** Create `name_tag_kind_adapters.py` (interface + dispatch), `name_tag_kind_adapters_ec2.py` (7 EC2 kinds), `name_tag_kind_adapters_services.py` (11 other kinds), `test_name_tag_kind_adapters_ec2.py`, `test_name_tag_kind_adapters_services.py`. Modify `name_tag_batch_live.py` only for protected Registry dispatch while keeping `build_volume_create_tags_request` and the current deny-by-default behavior. Extend `test_name_tag_batch_live.py`.

**Interfaces:**

~~~python
class KindWriteAdapter(Protocol):
    def read_current(self, client: object,
                     target: CanonicalTargetIdentity) -> NameObservation: ...
    def write_once(self, client: object, target: CanonicalTargetIdentity,
                   name: str, grant: VerifiedRuntimeGrant) -> None: ...
    def readback(self, client: object,
                 target: CanonicalTargetIdentity) -> NameObservation: ...

def adapter_for_capability(decision: KindCapabilityDecision) -> KindWriteAdapter: ...
~~~

Retain `name_tag_batch_state.NameObservation` with exact key presence/raw/state and independently verify response resource identity. `read_current`/`readback` reject ambiguous, duplicate, malformed, partial or paginated/incomplete tag sets (not ABSENT). Only a vetted adapter may build a **single-resource, single-Name-key** update; never accept caller-injected arbitrary SDK kwargs. The write method accepts a protected grant for structural compatibility but the actual send is authorized/consumed by the Host verifier at the dispatch boundary (Task 6/7), not by the mere presence of its dataclass.

Implement SDK candidate shapes from Design `4.2, table-driven with tests for all 18. Evaluate service/condition/owner availability and promote only those with independently supportable offline contracts. For CNP kinds, `adapter_for_capability` must reject with reason rather than claim successful support.

S3 must prefer pinned-model `s3control.tag_resource(AccountId=A,ResourceArn=bucket_arn,Tags=[{Key:'Name',Value:name}])` with `s3control.list_tags_for_resource` and independent owner/region evidence. If pinned botocore lacks either operation, or region/owner/IAM policy cannot be proved, keep CNP and prohibit `s3.put_bucket_tagging`. API Gateway must also reject inherited parent-API tag ambiguity and remain CNP pending Task 4 proof.

- [ ] **Step 1 — RED:** `test_ec2_exact_one_name_request_per_7_kinds`, `test_remaining_11_candidate_shapes_or_explicit_cnp`, `test_tags_malformed_or_paginated_is_unknown`, `test_apigw_inherited_name_is_unknown_for_stage_write`, `test_s3_sdk_missing_or_owner_unproven_no_write`, `test_s3_put_bucket_tagging_never_used`, `test_extra_tag_or_resource_rejected`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_kind_adapters_ec2 test_name_tag_kind_adapters_services -v`; expected failures from not-yet-implemented adapters.
- [ ] **Step 3 — GREEN:** Implement shared adapter contract, EC2 implementations and per-service implementations, with explicit CNP decision paths. Require model introspection in the pinned botocore runtime; no unverified fallback or public SDK client construction before Host grant.
- [ ] **Step 4 — Verify GREEN:** Run both new adapter modules and `test_name_tag_batch_live`; all PASS; no AWS calls.
- [ ] **Step 5 — Commit after implementation GO:** `git commit -m "feat(batch): add evidence-gated kind SDK adapters"` with changed paths only.

## Task 6 — Host Issuer, Protected Runtime Grant and Effective-IAM Evidence

**Finding 004 — fixed protected bootstrap and no architecture choice.** The only supported live Host is a manually Owner-authorized Linux **system-level systemd** `aws-cnt-batch.service`, dedicated `aws-cnt` UID/GID, one existing `name_tag_batch_runtime.py` Coordinator and the original Host-bound SQLite Ledger. The unit/executable/config/trust/Scope/evidence/ledger must be protected by a root-managed pinned manifest, controlled paths/permissions, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `UMask=0077`, `StateDirectory=aws-cnt` and `RuntimeDirectory=aws-cnt`; the actual Host will later prove these protections under G2. Do not install/start the unit in this offline implementation. Define `HostBootstrapVerifier.verify_process(*, now_utc: datetime) -> VerifiedHostContext`, `HostBootstrapCredentialProvider.load(host: VerifiedHostContext, *, now_utc: datetime) -> ProtectedBootstrapCredentials` in `name_tag_batch_host_runtime.py` / `name_tag_batch_host_issuer.py` as Design §5.2. Verification must check actual service/process/cgroup and pinned root-controlled files/digests, stable Host/run and Ledger identity, protected OwnerTrust and Scope; not just UID, env, dataclass or process arg. If unsupported Linux/systemd or any proof missing: fail closed before any Intent or STS.

**Only credential source:** systemd `LoadCredentialEncrypted=aws-bootstrap.json:<root-managed encrypted path>` provides an exact short-lived `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration` through a verified service-local `CREDENTIALS_DIRECTORY`. This path hint is not proof of service authority. Bootstrap STS client must use those explicit protected bytes only; bypass boto3 default environment/profile/IMDS credential chain. Expired, substituted or absent credential file blocks before AssumeRole; no ambient fallback, retry or implicit rotate. Real OS service setup, credential provisioning, STS traffic, IAM/Trust and G1/G2 acceptance remain Owner HOLD and NOT_VERIFIED.

**Task 6 RED/GREEN additions:** `test_host_bootstrap_validated_systemd_context_mock`, `test_forged_uid_cgroup_unit_or_manifest_rejected`, `test_env_or_dataclass_cannot_forge_host_context`, `test_encrypted_credential_missing_expired_or_substituted_denied`, `test_default_credential_chain_never_used`, `test_host_service_not_installed_or_started_by_offline_tests`, and `test_actual_sts_request_receipt_only_mocked`. Task 6 GREEN wires a **single** Host-only protected issuer with Fake OS/STS transports; real Host proof remains NOT_VERIFIED.

**Files:** Create `name_tag_batch_host_issuer.py`, `name_tag_batch_host_runtime.py`, `name_tag_batch_iam_evidence.py`, `test_name_tag_batch_host_issuer.py`, `test_name_tag_batch_host_runtime.py`. Extend `name_tag_batch_credentials.py` (preserve `BatchCredentialIssuer` and `OfflineFakeIssuer`) and `test_name_tag_batch_iam.py` / `test_name_tag_batch_runtime_host.py`.

**Interfaces:** Implement these **exact** Design `5.1 contracts as real protocols with concrete protected-host implementations:

~~~python
class HostCredentialIssuer(Protocol):
    def issue(self, batch: VerifiedBatchApproval, subset: SessionPolicySpec,
              host: VerifiedHostContext, now_utc: datetime) -> HostIssuedSession: ...

class HostScopeVerifier(Protocol):
    def resolve(self, signed_scope_id: str, target: CanonicalTargetIdentity,
                host: VerifiedHostContext, now_utc: datetime) -> VerifiedHostScope: ...

class EffectiveIamEvidenceVerifier(Protocol):
    def verify(self, issued: HostIssuedSession, row: VerifiedBatchRowAuthority,
               capability: KindCapabilityDecision, scope: VerifiedHostScope,
               evidence: ProtectedIamEvidence) -> VerifiedDenyEvidence: ...

class ProtectedBatchRuntimeVerifier(Protocol):
    def authorize_once(self, row: VerifiedBatchRowAuthority,
                       issued: HostIssuedSession, scope: VerifiedHostScope,
                       deny: VerifiedDenyEvidence,
                       permit: FirstSendPermit) -> VerifiedRuntimeGrant: ...
~~~

Define `VerifiedHostContext`, `HostIssuedSession`, `VerifiedHostScope`, `ProtectedIamEvidence`, `VerifiedDenyEvidence` and nonserializable `VerifiedRuntimeGrant` in these three new modules. They are **Host-issued protected references**, not freely constructible proof by fields or dataclasses. Use process-local private issuance/grant registries bound to protected OS Host/OwnerTrust/Scope/Ledger authorization; arbitrary copied Python objects, ambient credentials, fake receipts and externally supplied process flags must fail.

A concrete issuer builds the **actual** `AssumeRole` request with exact approved policy bytes, sends only through a Host-owned injected STS transport, checks response role/account/expiry/identity and binds request+response digests, credential fingerprint and explicit SDK client factory to the same triplet. It must never reassemble a policy *after* issuance to claim a match. A separate effective-IAM evidence verifier validates protected, current role/boundary/SCP/RCP/resource-policy/session-grant provenance, exact approved allow, foreign ARN/other key/other API deny, validity window and drift. No Boolean/simulator/STS GetCallerIdentity alone can satisfy it. Offline tests exercise a mock issuer/proof producer but never mark live-proven.

- [ ] **Step 1 — RED:** `test_actual_sts_request_bytes_bound_to_response_receipt`, `test_copy_or_synthetic_session_rejected`, `test_foreign_arn_tagkey_and_alternate_api_evidence_rejected`, `test_runtime_evidence_expired_no_intent`, `test_host_without_protected_issuer_returns_aws_runtime_not_authorized`, `test_no_secrets_in_receipt_ledger_logs`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_batch_host_issuer test_name_tag_batch_host_runtime -v`; new assertions fail.
- [ ] **Step 3 — GREEN:** Implement injected STS request/response verification and protected one-shot grant registry; strictly separate synthetic verifier from production verifier. The real-host evidence producer is **not** built by pretending that Fake results are genuine: the protected verifier must fail closed until verified live evidence is supplied in a separately authorized acceptance.
- [ ] **Step 4 — Verify GREEN:** Rerun host tests plus `test_name_tag_batch_runtime_host`; all PASS and zero real STS traffic.
- [ ] **Step 5 — Commit after implementation GO:** `git commit -m "feat(batch): bind host sts and IAM evidence to one-shot grant"`.

## Task 7 — Integrate Host Gate with Existing Durable Batch/Ledger Coordinator

**Files:** Modify `name_tag_batch_runtime.py`, `name_tag_batch_live.py`; modify `name_tag_ledger.py` **only if** its existing fields cannot preserve the required association without schema change (a schema migration is **not** pre-authorized). Create `test_name_tag_batch_live_runtime.py`; extend `test_name_tag_batch_runtime.py`, `test_name_tag_batch_ledger.py` and `test_name_tag_batch_live.py`.

**Interface:** Keep existing `execute_batch_offline(batch: VerifiedBatchApproval, ledger: IntentLedger, runtime: BatchOfflineRuntime)` behavior/signature. Add a Host-only typed entry point:

~~~python
def execute_batch_live(batch: VerifiedBatchApproval, ledger: IntentLedger,
                       runtime: VerifiedHostRuntime
                       ) -> BatchRunResult: ...
~~~

Implement `VerifiedHostRuntime` in `name_tag_batch_host_runtime.py` with protected issuer/verifier, Scope/SideEffect, SDK client factory, adapter registry and a private, explicit opt-in state. The entry point must share existing sequential row authority, Batch cap/STOP/HOLD, Intent, Permit and Readback machinery rather than implementing an independent signer or second ledger. `AuthorizedBatchWritePort.write_once` changes from unconditional refusal **only** when the protected verifier consumes a genuine one-shot grant at the same dispatch; legacy constructed `AuthorizedBatchRuntimePolicy` remains denied.

Order: current signature/revocation + exact row/Scope + independent Host IAM/G1/G2 evidence before **any** Intent; same credential pre-send raw Name read; revalidate all protected gates immediately before durable `consume_first_send`; then **one** send and same-credential Readback; durable terminal/unknown report. Fail before Permit = zero send, no invented `APPLIED_VERIFIED`. Failure after Permit = `OUTCOME_UNKNOWN`, whole Batch STOP/HOLD, no replay. Persist an evidence digest/reference only in an already protected field or compatible adjacent audit record; raw secrets never stored. If real Ledger v2 schema needs a migration for this property, stop that schema change for a separate Owner decision while continuing unrelated code; never auto-run migration.

- [ ] **Step 1 — RED:** `test_live_denies_offline_fake_and_caller_constructed_policy`, `test_valid_mock_proven_host_one_permit_one_send_readback`, `test_expired_or_revoked_before_permit_zero_send`, `test_crash_after_permit_outcome_unknown_no_resend`, `test_hold_failure_blocks_host`, `test_cross_kind_signed_cap_preserved`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_batch_live_runtime -v`; expected failures in new live wiring only.
- [ ] **Step 3 — GREEN:** Wire Host policy/adapter into the existing Coordinator without opening the public Phase A writer; use existing Ledger `create_batch_intent`, `consume_first_send`, `record_readback` and `stop_batch` as immutable send guards. Broaden current Volume-only `aws_operation` check exclusively through proven registry validation, not a wildcard.
- [ ] **Step 4 — Verify GREEN:** Run new tests plus `test_name_tag_batch_runtime`, `test_name_tag_batch_ledger`, `test_name_tag_batch_live`; all PASS.
- [ ] **Step 5 — Commit after implementation GO:** `git commit -m "feat(batch): add protected host coordinator dispatch"` with explicit allowed files only; stop if migration is required.

## Task 8 — Explicit Opt-in CLI without Local Self-Authorization

**Finding 004 — CLI-to-Host authority is fixed.** `batch-live` is solely an **untrusted local client** to the fixed systemd-owned AF_UNIX socket `/run/aws-cnt/host.sock`, never a direct invocation of a caller-constructed `VerifiedHostRuntime` or local SDK client. The existing `execute_batch_live_from_host(... runtime: VerifiedHostRuntime, ledger: IntentLedger)` function sketch is **Host-internal only**, not the CLI interface. Add `ProtectedHostCommandEndpoint.execute_signed_batch(*, plan_bytes: bytes, csv_bytes: bytes, owner_envelope_bytes: bytes, host: VerifiedHostContext) -> BatchRunResult` implemented inside the same protected service Coordinator; the CLI transmits exact Plan/CSV/Owner envelope bytes with bounded request and never sends credentials, permits, grants, custom socket addresses, environment-chosen Host identity or executable path. A root-controlled unit, current OwnerTrust, Scope, IAM, G1/G2 and Ledger prove authority only within the service. `SO_PEERCRED` and UNIX socket permissions are defense in depth, not authorization. The service/socket are **never** created/started by the offline code or tests; missing socket means blocked, not self-bootstrap.

**Task 8 RED/GREEN additions:** `test_batch_live_missing_socket_fail_closed`, `test_batch_live_cli_cannot_create_grant_or_sdk_client`, `test_cli_supplied_host_runtime_path_ignored_and_rejected`, `test_unix_socket_peer_check_not_owner_approval`, `test_old_offline_commands_unchanged`, and `test_host_only_endpoint_uses_existing_coordinator`. All tests use fake local IPC; no real service or AWS access.

**Files:** Modify `name_tag_batch_cli.py`, `README.md`; create `test_name_tag_batch_cli_live.py`; extend `test_name_tag_batch_cli.py`.

**Interface:**

~~~python
def execute_batch_live_from_host(*, plan_bytes: bytes, csv_bytes: bytes,
                                 envelope_bytes: bytes,
                                 runtime: VerifiedHostRuntime,
                                 ledger: IntentLedger) -> BatchRunResult: ...
~~~

Add a separate `batch-live` subcommand with required Plan/Review/Envelope and private report-out, plus explicit `--live-opt-in`. A CLI argument, path to a self-created runtime file, fake fixture, local environment variable or unconditional `--live-opt-in` **never** creates a VerifiedHostRuntime/Trust/Grant. The CLI calls the Host-only protected runtime entry point which independently resolves current protected trust, Scope and IAM evidence; refuse until the environment and Owner gates have actually been established. Keep `batch-dryrun`, `prepare-batch`, `verify-batch`, `batch-simulate` entirely offline and backward compatible. No unattended batch-live launch or force flag.

- [ ] **Step 1 — RED:** `test_default_cli_never_calls_aws_or_sts`, `test_live_opt_in_flag_alone_denied`, `test_invalid_or_unsigned_live_plan_rejected`, `test_fake_runtime_file_cannot_enable_live`, `test_dryrun_and_simulate_unchanged`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_batch_cli_live -v`; new cases fail.
- [ ] **Step 3 — GREEN:** Implement explicit routing to protected Host runner, reuse `_read_private` / output path guards, ensure no secret serialization. Document exact offline vs live authorization and manual STOP.
- [ ] **Step 4 — Verify GREEN:** Run `test_name_tag_batch_cli_live test_name_tag_batch_cli`; all PASS.
- [ ] **Step 5 — Commit after implementation GO:** `git commit -m "feat(batch): add opt-in protected live cli boundary"`.

## Task 9 — 18 Kind Reporting, Fake E2E, Regression and Integrity

**Finding 001 / Finding 003 — signed pre-cap source and final non-Volume trace.** `report_kind_capability_coverage(plan, decisions, row_outcomes)` **must** obtain Kind pre-cap totals only from Plan v3 `cur_population_by_kind` as validated in Task 2. The selected `plan.records` and `row_outcomes` provide post-selection details only; never attempt to infer a Kind's missing pre-cap costs from selected rows. Missing optional breakdown in a legacy signed Plan returns `PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE` without zero-filling. Reject extra/missing 18 keys on new Plans, invalid Decimal/cost or any per-Kind / total stage disagreement with existing `cur_population.schema_version=2`. Kind capability status and outcome partition are independent; every recognized resource is counted once at each stage. No changes to signed Plan v3/BatchApprovalV1 semantics.

**Task 9 RED/GREEN additions:** `test_18_kind_presign_to_owner_verified_nonvolume_iam_adapter_trace` (Fake only, eligible representative Kind), `test_precap_18_kind_sum_matches_global_decimal`, `test_below_threshold_and_uninspected_nonvolume_included`, `test_tampered_by_kind_count_or_cost_rejects`, `test_legacy_signed_plan_without_kind_breakdown_reports_unavailable`, `test_new_plan_breakdown_is_signed_under_existing_plan_sha256`, and `test_fake_host_bootstrap_does_not_imply_g2_pass`. Complete all 4 findings with existing Phase A/Batch 1–7 regressions and Manifest integrity; keep Safety Hold.

**Files:** Modify `name_tag_batch_report.py`, `name_tag_batch_outcomes.py`, `aws_cost_name_tagger_v3.py` (`_batch_plan_report_fields` only as needed), `SHA256_MANIFEST.json`; create `test_name_tag_batch_report_multikind.py`, `test_name_tag_batch_live_e2e.py`; extend `test_name_tag_batch_report.py`, `test_name_tag_batch_population.py`, `test_name_tag_batch_runtime.py` if necessary.

**Interfaces:**

~~~python
def reconcile_batch_outcomes(
    report: BatchOutcomeReport,
    ledger_outcomes: Mapping[int, str] | None = None
) -> BatchOutcomeReport: ...  # preserve existing signature

def report_kind_capability_coverage(
    plan: Mapping[str, object],
    decisions: Mapping[str, KindCapabilityDecision],
    row_outcomes: Mapping[int, str]) -> dict[str, object]: ...
~~~

Keep existing `cur_recognized=below_min_cost+above_min_cost` and `above_min_cost=lookup_selected+max_resources_not_inspected`, excluded-billing and reason-detail reconciliation. For each kind keep independent **capability** and **attempt/outcome** axes; no selected-resource count/cost duplicated into other stages. Distinguish signed invalid input (reject entire draft), legitimate unapproved unsupported/unproven row (reasoned report), and approved signed row with runtime stale Scope/Name/IAM (blocked/skip/STOP according to phase). `APPLIED_VERIFIED` requires consumed Permit and same-session actual readback, never a mock-only status imported as live.

Use Fake STS + Fake SDK for `Plan -> unsigned Preview -> approved CSV -> signature -> verified row -> protected injected Host -> Intent -> consumed Permit -> one write -> Readback -> report`, plus CNP, tags replacement, stale proof, no-replay and cap cases. Fake successful writes remain labeled synthetic; genuine Host acceptance is NOT_RUN.

- [ ] **Step 1 — RED:** `test_all_18_kind_count_decimal_cost_reconciles`, `test_unsupported_vs_unproven_vs_not_run_are_distinct`, `test_signed_forgery_not_downgraded_to_unsupported_skip`, `test_one_kind_block_does_not_enable_others`, `test_fake_e2e_same_session_cap_and_unknown`, `test_no_fake_result_claims_live_acceptance`.
- [ ] **Step 2 — Confirm RED:** `uv run --locked --no-build python -m unittest test_name_tag_batch_report_multikind test_name_tag_batch_live_e2e -v`; new cases fail.
- [ ] **Step 3 — GREEN:** Implement kind-coverage projection and safe outcome reconciliation; integrate with existing Plan/CSV report and stop behavior. Never add an unauthorized report-only approval bypass.
- [ ] **Step 4 — Verify GREEN:** Run new reports/E2E and full offline suite, e.g. `TMPDIR=/var/tmp uv run --locked --no-build python -m unittest discover -s . -p 'test_*.py' -q`; expect all PASS. Verify original Volume, Phase A, Tasks 1–7 and host-denial regressions.
- [ ] **Step 5 — Integrity:** Update *only* registered changed-file `sha256`/`bytes` in `SHA256_MANIFEST.json`, preserving fixed source identity and historical evidence; validate all entries against filesystem using the repository's existing CI algorithm, with no mismatches. `git diff --check` PASS; no actual AWS/STS client invoked.
- [ ] **Step 6 — Commit after implementation GO:** `git commit -m "feat(batch): reconcile multikind coverage and offline acceptance"` using explicitly staged files; leave other worktree changes untouched.

## Acceptance Mapping to Design R0.1.1 `10

| Design completion criterion | Evidence to require from implementation |
|---|---|
| 1. All 18 kinds explicitly registered | Task 1 complete kind set and per-kind parser tests |
| 2. API/IAM/Name/Readback decisions evidence-backed or honestly unproven | Tasks 1, 4, 5 candidate documentation, pinned-model tests and CNP reasons |
| 3. Production adapters for safely supported kinds | Tasks 3, 4, 5; one-Name SDK request and strict Readback |
| 4. Host Issuer/STS/Runtime Policy/CLI code complete | Tasks 6–8; protected injected Host boundary, no Fake authority |
| 5. Forged/expired/missing evidence yields no AWS mutation | Tasks 6–8 negative path tests |
| 6. Offline normal/refusal/fault E2E PASS | Tasks 7–9 |
| 7. Full regression + Manifest PASS | Task 9 exact checks |
| 8. All 18 kinds' count/cost/reason reporting | Task 9 exact Decimal conservation |
| 9. No real AWS operation, Safety Hold active | All tasks, CLI tests and final report |
| 10. Explicit remaining real-Host evidence and Owner GO | Final handoff below; no automatic execution |

## Nonfunctional / Safety Acceptance

- **Provenance:** current OwnerTrust and revocation rechecked; signed SHA-256 material and exact ARN/operation/Name/Scope match issuer and protected receipt; grant consumed only once in one Host process; reject all copy/serialization attempts.
- **Data integrity:** durable atomic Intent/Permit/attempt cap with no replay; `OUTCOME_UNKNOWN` and STOP/HOLD survive exceptions; no implicit Ledger migration or reset.
- **Determinism:** stable per-kind registry ordering and pre-sign projection; UTF-8 BOM CSV preserved; canonical signed JSON/row hash identical for unchanged historic Volume input.
- **Bounded resources:** 250,000 distinct CUR resource cap, 1–20 signed sends, 2,048-byte policy plaintext size, existing read budget/timeouts and SDK pagination safety; no unbounded discovery/assumption.
- **Confidentiality:** no raw STS tokens/keys, Owner signing material, protected runtime evidence or secrets exposed in JSON reports/CLI/logs; private output permissions maintained.
- **Environment separation:** no live AWS calls/test credentials in CI; no default network egress or implicit credentials; Fake-only `OFFLINE_SYNTHETIC_NOT_STS` cannot mint live grants.
- **API safety:** no overwrite of meaningful Name; no multi-tag, multi-resource, delete or tag-set replacement; no silent fallback to alternate API; G1 races are explicitly residual until separately accepted.

## Final Owner Checkpoint; Stop

Output a concise completion report after all planned offline implementation steps are verified: implemented kinds, unproven/unsupported kinds and reasons, test counts, Manifest evidence, branch+commit identities, source change scope, held safety gates, remaining external Host/IAM/G1/G2 evidence, unapproved operations.

Success state is **`PRODUCTION_IMPLEMENTATION_COMPLETE / OFFLINE_TDD_PASS / LIVE_ACCEPTANCE_NOT_VERIFIED`**, never AWS live safety PASS. The final Owner decision on implementation completeness and whether to schedule distinct real-Host acceptance is not delegated to the test suite.

If a mandatory Host boundary cannot be implemented without weakening the trust model or migrating a protected Ledger, stop only that dangerous path and report the concrete blocking dependency; do not invent proof or recursively launch review/remediation. If independent safe paths are complete, preserve their progress and stop at an Owner checkpoint.

No source modifications, test executions, real STS, IAM/Trust changes, real AWS writes, Safety Hold release, PR or Merge follow automatically from this plan. A green design/planning document does not authorize implementation.

**Required next Owner decision:** formally adopt Design R0.1.1 (with NOTE-001/002 handled as above), approve this Plan, and separately authorize an explicitly bounded offline implementation phase. Until then: `IMPLEMENTATION_HOLD`.
