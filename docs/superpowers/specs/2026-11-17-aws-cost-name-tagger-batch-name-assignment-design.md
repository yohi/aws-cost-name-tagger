# AWS Cost Name Tagger — Batch Name Assignment Design (Draft)

- Date: 2026-11-17 (JST)
- Repository: `yohi/aws-cost-name-tagger`
- Source baseline: `9cf9718c5379347a285058a2f1d64c07df0576af`
- Status: **Draft for Human Owner adoption**. Committing this document does not approve Phase B, enable AWS writes, alter IAM, or lift Safety Hold.
- Scope: requirements and a minimal design proposal only. No implementation, test execution, credentials, or AWS operations are authorized by this document.

## 1. Purpose and success criteria

Use CUR-based cost discovery to identify chargeable AWS resources and assign a meaningful `Name` tag **as comprehensively as the supported APIs and least-privilege boundaries permit**, while preserving existing meaningful Name values.

Success requires:

1. Enumerate resources above the existing configurable `--min-cost` threshold and report the coverage of the discovered population.
2. Generate candidate Names using existing inference logic; skip non-generatable candidates and report them explicitly.
3. Require a separate, explicit Human Owner approval phase using the existing review CSV `approved=YES` convention.
4. Freeze and authenticate the **whole approved CSV** (target identity, Name, operation, approval decisions and other execution-relevant fields) before any changes; run only the approved entries.
5. Limit the AWS execution principal's *effective permissions* to the specifically authorized resource ARNs and the `Name` tag, on APIs that enforce that property.
6. Re-read Name immediately before mutation; never overwrite a Name containing a non-whitespace character.
7. Read back each attempted Name change and report verified, skipped, failed, and uncertain outcomes, with no automatic retry.

Completion means an auditable result or reason for every cost-discovered resource in the selected input and threshold scope. It does **not** mean every billing line can receive an AWS `Name` tag.

## 2. Eligibility and scope

Reuse the current CUR import, service/resource identification, `--kinds`, `--min-cost`, and Name proposal implementation. Keep the existing default `--min-cost` value and the existing `--mode dryrun` behavior.

A resource is eligible for a proposed update only when the observed `Name` value is:

- missing/None (tag key absent),
- an empty string `""`, or
- a string consisting only of whitespace (including half/full-width spaces and tabs; equivalent to Python `name.strip() == ""`).

If `Name` contains any non-whitespace character, skip without modifying it (including `" web-prod "`). Unknown or malformed tag state, an ambiguous resource identity, or a failed read must **block that resource**; do not infer that Name is absent.

Where the inference engine cannot produce a Name, **do not ask for manual entry or write a tag**. Include the resource in a final `Name自動生成不可リソース一覧` with service, resource ID/ARN if known, billed cost, and the reason.

Resources below `--min-cost` are excluded from write consideration; report their count and total cost separately, so filtering is visible rather than mistaken for full coverage.

## 3. Approaches considered

- **A — Single Owner approval for the reviewed CSV (selected):** use the existing per-row `approved=YES` decisions, then bind the full approved CSV content to one verifiable Owner approval. Simple operator experience for many resources while retaining immutable per-resource execution scope.
- **B — Separate Owner execution approval for every resource (not selected):** aligns with existing Phase A single-ARN authorization but adds excessive signing and review work when covering many chargeable resources.

The existing Phase A plan currently requires one ARN / Name / operation per authorization; **A is a deliberate proposed change to this contract, not a permission to bypass it**. Preserve existing fail-closed controls until the new authorization scope is explicitly adopted and implemented.

## 4. End-to-end workflow

1. **Discover and propose:** extract above-threshold costed resources; read existing tag/metadata state; generate and classify candidate Names.
2. **Dry-run:** present all proposed changes and skipped/unsupported resources without any AWS mutation. Retain `run --mode dryrun`, and expose a clear `--dry-run` on the eventual batch execution path (not yet implemented).
3. **Review CSV:** present ARN/resource identity, AWS service, proposed Name, operation, cost, and reasons; reviewer marks selected rows `approved=YES`. Blank or other values are not approval.
4. **Owner sign-off:** authenticate the complete, exact approved CSV identity/content (e.g., canonical serialization or exact bytes and a SHA-256 digest with a verified, purpose-bound Owner signature), together with allowed account/role, target set, Name values, operations, and bounded validity. An unsigned digest, mutable CSV, `approved=YES` alone, or a CLI flag is **not** authority.
5. **Preflight:** revalidate approval provenance, CSV integrity, AWS principal, configured resource ARN/Name API allowlist, IAM effective-permission restrictions, scope and safety evidence. A changed CSV or an unmatched target/operation is rejected.
6. **Execute sequentially:** for each approved row, acquire current state, recheck Name is missing/empty/whitespace-only, establish existing no-replay/Intent protections, then make at most one supported service-specific Name-only mutation. Do not auto retry or rollback.
7. **Readback and report:** re-fetch Name and report `APPLIED_VERIFIED` only when it matches the approved value; otherwise mark failure/unknown and do not auto resend. Record audit evidence and per-resource skip reasons.

A single CSV-level approval covers a **fixed set of individually constrained requests**, not unrestricted permissions to mutate future CUR discoveries or add rows after approval.

## 5. IAM least-privilege as a hard gate

Use a dedicated execution principal with **effective** write permissions for only the approved resource ARNs and the `Name` tag. Minimize read permissions to those needed for preflight and Readback. Do not grant create/delete/configuration privileges, permissions to mutate other tag keys, or wildcard resource write access for convenience. Review inherited policies, permission boundaries and any applicable explicit denies; an application check alone is not sufficient.

For each service/resource kind, establish before enablement:

- the exact update API and exact resource-level ARN support;
- IAM tag-key conditions actually enforced by that API (e.g., `aws:TagKeys` where supported);
- whether the API performs key-scoped update or tag-set replacement;
- whether other tags and out-of-scope resources can be proven unmodifiable by the execution principal;
- a safe Readback mechanism.

**Fail closed on unsupported/unsafe services:** do not use tag-set replacement APIs or broad write privileges merely to increase coverage. Report those resources as `IAM制約による未対応` with their cost. Service-specific behavior must be verified; the initial EC2/EBS Name-only path is not proof that all other kinds are safe.

The desired coverage of existing supported kinds is a **discovery/reporting** target; write support is enabled per kind only where the least-privilege requirement holds.

## 6. Output and observability

Produce the normal proposal/report and a final run summary (CSV/JSON where the current reporting path supports it), identifying, for every relevant resource:

- cost, service/kind, ARN/resource ID, proposed Name and approval status (where available);
- `APPLIED_VERIFIED` after Readback, or a specific failure/`OUTCOME_UNKNOWN`;
- skipped: already meaningful Name, not approved, not eligible, invalid/unknown Name state;
- `Name自動生成不可` as a separately extractable list;
- unsupported IAM/service/API constraint and reason;
- excluded by `--min-cost` (at least count and total excluded cost).

Do not label an unattempted write successful, and do not silently drop excluded/unsupported resources.

## 7. Non-goals and residual risks

Do not create a new review UI, approval service, signing infrastructure, or broad IAM role. Do not reimplement Phase A. No manual Name entry for unsupported proposals, automatic retry, automatic rollback, or universal tag writing.

A pre-write Name check plus a subsequent update is **not an atomic compare-and-set** for services such as EC2 CreateTags. Competing writers or automation can alter Name between those steps. The existing G1 atomic-write norm therefore requires an explicit, narrowly scoped Human Owner decision before any real write path is enabled. Keep ledger and fail-closed behavior where relevant; do not automatically add new infrastructure or review loops.

## 8. Implementation boundary / Owner checkpoint

Current Phase A artifacts (approval verification, scope checks, ledger, fake execution, candidate generation and read-only reports) remain reusable. The current production `execute-approved` and EC2 adapter write methods remain blocked.

**Stop at this design document.** Subsequent work, only with explicit Human Owner approval, should cover the smallest implementation delta for CSV-level authorization, per-service least-privilege filtering, batch processing, `--dry-run`, and Readback/reporting. Validate with offline positive/negative tests before considering a separately authorized AWS runtime trial.

Preserve active gates unless separately and explicitly decided:

```text
SAFETY_HOLD_ACTIVE
AWS_WRITE_BLOCKED
G1_NOT_PROVEN
G2_NOT_VERIFIED
AWS_RUNTIME_NOT_AUTHORIZED
```

Publishing this draft, a green CI run, or a later merge does not imply Trust Anchor enrollment, change to IAM, normative exception, release of a Safety Hold, or authorization for a live AWS write.
