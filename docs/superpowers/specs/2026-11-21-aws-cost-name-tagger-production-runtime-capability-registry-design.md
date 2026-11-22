# AWS Cost Name Tagger — Production Runtime Completion Design R0.1

- Date: 2026-11-21 (JST)
- Repository: \`yohi/aws-cost-name-tagger\`
- Base: \`master@bffc5d97e5ccd53bc094785bcda70476b2be2fd7\`
- Status: **PROPOSED — Human Owner Design Adoption Pending**
- Development approach: Superpowers First / TDD / Single Implementation Phase
- Authority: This document records the brainstorming design proposal. Commit/Push does **not** authorize implementation, Trust enrollment, IAM modifications, STS calls, live AWS mutation, Safety Hold release, or operational Gate approval.

## 1. Project Goal

Identify chargeable resources from AWS CUR and enable meaningful \`Name\` tag assignments where service APIs and independently proven least-privilege boundaries permit, while preserving existing meaningful \`Name\` tags.

All **18 recognized kinds** are in the assessment and implementation scope. Implement an eligible live write adapter for a kind only when its API, IAM, tag-preservation, and Readback safety contract can be established. For every unsupported or unverified kind, report a reason, affected resource count, and exact Decimal cost. Do not treat an unsafe or unproven kind as authorized.

Original success remains actual, safely controlled AWS tagging, **not** mere completion of design, offline tests, or code. This implementation phase deliberately stops before real-host/live-AWS acceptance.

## 2. Scope and Boundaries

Kinds:

- EC2: \`instance\`, \`volume\`, \`snapshot\`, \`eni\`, \`eip\`, \`nat\`, \`endpoint\`
- Databases: \`rds_cluster\`, \`rds_instance\`
- Other: \`opensearch\`, \`elbv2\`, \`apigw_stage\`, \`cloudfront\`, \`athena_workgroup\`, \`log_group\`, \`lambda\`, \`wafv2\`, \`s3_bucket\`

In scope: production-oriented source code, registration and classification of each kind's capability, per-kind adapters where safety is supportable, runtime enforcement, Host/Issuer/STS interfaces, IAM and G1/G2 evidence gates, CLI opt-in control, audit/report paths, and offline TDD/integration regression tests.

Out of scope for this phase: live Host acceptance, actual STS issuance, enrollment of Trust Anchors, IAM deployment/change, real AWS tag mutation, permission to clear Safety Hold, automatic PR/Merge, and operational Owner approval. These are separate authorizations.

Existing Phase A and Batch Tasks 1–7 must retain their safety contracts, known boundaries, and fail-closed behavior.

## 3. Selected Approach and Alternatives

**Selected: A — Kind Capability Registry.** Keep one common execution/authentication/ledger runtime and declare per-kind capability constraints and service-specific adapters. This maximizes reuse and makes unsupported/unverified kinds visible.

Considered but not selected:

- **B — Resource Groups Tagging API first:** fewer apparent API variants, but actual service coverage, required service-specific IAM permissions, and write side effects vary; not an automatic safety shortcut.
- **C — Independent writer per service:** simpler local implementations but repeats Owner/Scope/Ledger/STS safety logic and increases divergence risk.

No new web approval service or separate Ledger is required by the selected approach.

## 4. Architecture

\`\`\`text
CUR discovery
  -> Batch Plan + Review CSV
  -> Owner signed approval
  -> Host-only Batch Runtime / Coordinator
       OwnerTrust / current Batch authority
       Protected Scope + SideEffect evidence
       Host-bound Ledger + Intent + FirstSendPermit + signed attempt cap
       Host-only Credential Issuer + protected issuance receipt
       Effective IAM + G1/G2 evidence gates
       -> Kind Capability Registry
            -> eligible adapter: Pre-send Read -> single Write -> Readback
            -> unsupported/unverified: reason + count + exact cost
  -> Durable outcomes + auditable Batch Report
\`\`\`

The Registry **describes capabilities**; it cannot independently grant a write. Eligibility must also be revalidated against the approved row, current Host/Scope/Owner/Issuer/IAM evidence and the consumed Ledger Permit.

## 5. Kind Capability Registry Contract

For each of the 18 kinds, record:

- Kind/service and canonical resource identity
- ARN/account/partition/region constraints and resource-ID normalization
- Pre-send Read API and identity verification
- Exact update API, write action and request shape
- Readback API, identity verification and result semantics
- Actual IAM ARN-level enforcement and supported tag-key/value conditions
- Whether the update is **key-scoped** or **entire tag-set replacement**
- Name preservation, side effects and race exposure
- Required Host/IAM/G1/G2 evidence and their freshness
- Offline implementation state, live evidence state and explicit reason code

Separate these capability states:

- \`IMPLEMENTED_OFFLINE\`: adapter and offline safety tests complete; **not live-authorized**
- \`UNSUPPORTED_BY_POLICY\`: project safety requirements cannot be met by the candidate API
- \`UNSUPPORTED_API\`: no safe supported write operation identified
- \`CAPABILITY_NOT_PROVEN\`: evidence insufficient; do not claim impossibility
- \`LIVE_GATE_PENDING\`: code exists, but runtime Host/Owner/IAM/G1/G2 proof is outstanding

Avoid treating absence of evidence as actual observed API failure. A registry row or a static documentation claim never lifts any runtime HOLD.

Prefer native service APIs. Resource Groups Tagging API is permissible only if its service-specific permission, exact-ARN scope, tag preservation and Readback have the same proven safety bounds.

For instance, S3 \`PutBucketTagging\` replaces the bucket's tag set: do **not** use it as a Name-only mutation without a provably safe contract for all unrelated existing tags and concurrent changes. A read/merge/write sequence alone is not atomic preservation evidence.

## 6. Shared Security Runtime

Reuse current \`OwnerTrust\`, \`VerifiedBatchApproval\`, \`VerifiedBatchRowAuthority\`, \`ScopeEvidence\`, \`SideEffectEvidence\`, the Host-bound \`IntentLedger\`, \`FirstSendPermit\`, and signed attempt caps.

The Host-only issuer must bind the **actual** STS request to its **actual** response: Batch ID, approved row subset, exact policy bytes/hash, role, issuer identity, ARN/operation bounds, assumed-role identity, credential/client identity, expiration, and protected request/response receipt. Same issued credential triplet is used for Pre-send Read, Write and Readback. The production implementation can be offline-tested using an injected mock transport, but real issuance is not claimed.

Never use ambient credentials, caller-created session receipts, copied fake identities, Boolean allow flags, or arbitrary user-provided dataclasses as authorization. Do not persist raw AWS secrets in the Ledger or logs. Missing or ambiguous issuer lineage is \`AWS_WRITE_BLOCKED\`.

A trusted Host Runtime Policy is derived only by the protected verifier after fresh Owner/Scope/Ledger/Issuer/effective-IAM checks. Python object identity or a constructor token is insufficient to prove the OS/Host trust boundary.

## 7. Writer Execution Contract

For each approved eligible row:

1. Revalidate current Owner signature, signer role, expiry and revocation.
2. Bind exact signed Plan/CSV bytes and row, Name, Account/Partition/Region, ARN, API and Scope.
3. Recheck capability, row eligibility, G1/G2 and independent effective IAM evidence.
4. Recheck protected issuer/session provenance and issued-policy/subset/client identity.
5. Pre-send Read using that issued session; reject unknown, changed or meaningful existing Name.
6. Persist the one-shot Intent, then consume the Ledger Permit and signed attempt budget durably.
7. Send exactly one Name-only request through the allowlisted adapter and issued client.
8. Read back with the **same** issued session.
9. Durably record verified, skipped, failed or unknown outcome with per-kind reason.

After Permit consumption, uncertain SDK results, non-\`OSError\` exceptions, credential loss, failed Readback or Ledger persistence errors must **never** permit an automatic replay. Record \`OUTCOME_UNKNOWN\` and STOP/HOLD where possible; if persistence cannot be trusted, apply Host-wide Fail-Closed.

If an AWS API lacks atomic conditional Name update, the Pre-send Read/Write race is a residual G1 risk. A scoped, explicit G1 decision is required for live entry; the code must not claim atomic protection or silently accept this risk.

## 8. IAM and Operational Gates

Required proof before live dispatch:

- Current cryptographically valid Owner-approved Batch/row
- Exact authorized Account/Region/ARN, Name, API and allowlisted kind
- Protected Scope and SideEffect evidence; current Ledger state and consumed Permit
- Scoped G1 risk decision and genuine G2 real-Host evidence
- Host-only issuer, actual STS request/response lineage and SDK client identity
- Independent effective IAM denial evidence for foreign ARNs, other tag keys and alternate APIs
- Bounded attempts, logging, explicit stop and recovery procedures

Account for inherited policies, boundaries, SCPs, trust paths, resource policies and grants directed at assumed-role sessions. STS session policy or a simulator alone is not proof of an absolute deny.

Any missing, stale, inconsistent or inapplicable gate means **zero live mutation calls**. A capability alone, synthetic session or green CI result is not authorization.

## 9. Reporting and Coverage

For all 18 kinds, preserve the pre-cap CUR-recognized population, selected/inspected/approved/capped portions, exact Decimal cost and classification. Each row/outcome is counted without overlap; totals reconcile to original CUR input.

At minimum distinguish:

- Applied and Readback-verified
- Meaningful Name already present or changed before send
- Name not generatable
- Owner unapproved
- Scope mismatch or blocked
- Unsupported due to IAM/policy constraints
- Unsupported due to API/tag-set semantics
- Capability not proven / live evidence pending
- Not attempted because of signed caps
- Unknown after an attempted send
- Other authenticated STOP reasons

Do not label capped, uninspected, unsupported or unverifiable rows as completed writes. Reporting must not lift Safety Hold or cause an execution side effect.

## 10. TDD in One Implementation Phase

Work sequentially using RED -> GREEN -> minimal REFACTOR:

1. Registry shape, full 18-kind coverage, negative capability decisions
2. Batch Plan/Approval/Report handling of all recognized kinds without broadening executable eligibility
3. Safe per-kind request, read/readback adapters and service-specific IAM rules
4. Host-only credential issuance, exact STS mock-request/response binding and runtime gates
5. Shared Writer and failure/rollback-stop behavior
6. Explicit opt-in CLI with default fail-closed; audit recording
7. Fake STS/SDK end-to-end success, rejection, timeout and uncertainty tests
8. Full regression, manifest integrity and safety-hold assertions

Use existing code wherever possible; do not create an independent review task after each slice. An inability to prove one service kind should not stop independently safe work on other kinds.

## 11. Implementation Completion Criteria

1. Registry explicitly handles all 18 recognized kinds.
2. For each kind, the candidate API/IAM/Readback/side-effect decision has evidence or is honestly \`CAPABILITY_NOT_PROVEN\`. Unproven kinds remain blocked.
3. Safe candidate kinds have production-oriented adapters, protected runtime paths and offline tests; unsafe kinds return explicit reason/cost/count.
4. Host/Issuer/STS/Runtime Policy/CLI production code and offline enforceable gates are implemented without enabling live execution.
5. Missing, expired or forged evidence yields zero mutation calls.
6. Mock/Fake positive, negative, replay and fault-injection E2E tests pass; legacy Phase A and Batch regressions pass.
7. Manifest hashes/bytes reconcile for all registered files and \`git diff --check\` passes.
8. Full 18-kind report reconciles counts/Decimal costs and separates offline implementation from live proof.
9. No actual AWS/STS/IAM/Trust/Host mutation occurs in the implementation phase; Safety Hold remains active.
10. Outstanding environmental evidence and operational Owner approval are reported explicitly.

Completion label if all conditions hold: \`PRODUCTION_IMPLEMENTATION_COMPLETE / OFFLINE_TDD_PASS / LIVE_ACCEPTANCE_NOT_VERIFIED\`.

## 12. Stop Conditions and Human Owner Checkpoint

Stop the affected write path if satisfying it would require bypassing Owner approval, weakening IAM/Name protection, accepting an unproven tag-set overwrite, expanding privileges, trusting fabricated provenance, or assuming an unavailable Host guarantee. Independent safe kinds can still progress.

Implementation completion is **not** live acceptance, Gate clearance, release approval, or permission to mutate any AWS target. The following remain operationally active until their distinct evidence and Owner authorization exist:

\`\`\`text
SAFETY_HOLD_ACTIVE
AWS_WRITE_BLOCKED
G1_NOT_PROVEN
G2_NOT_VERIFIED
AWS_RUNTIME_NOT_AUTHORIZED
\`\`\`

Do not automatically start follow-on review, remediation, implementation, Commit, Push, PR, Merge or AWS activity. Stop at a Human Owner decision checkpoint. The scope of this document ends at the Design R0.1 proposal.
