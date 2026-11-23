# Host issuer review findings

## Goal

Close the verified host issuance, durable journal, protected Scope evidence, and one-shot grant gaps identified in review while preserving existing fail-closed behavior and public interfaces wherever practical.

## Decisions

- Revalidate the selected Scope immediately before STS issuance. The pre-STS evidence-gate contract must guarantee a call-time check of the current Scope state, and tests must cover a Scope transitioning to HOLD after selection. A non-CLEARED state must prevent both PENDING creation and STS.
- After a successful STS exchange, capture one response-received timestamp and use it for the response expiration lower bound, `check_issued`, receipt issuance time, and the durable issued record. Preserve expiration upper-bound validation relative to the original request timestamp.
- Retain Python 3.10 support for the host runtime context while preserving weak-reference registration and identity equality (`eq=False`).
- Ensure journal directory ancestry is synchronized on retries even when the directory already exists. Finalization temporary files are not records; only a recognized temp associated with a valid canonical tombstone may be safely reconciled. Missing/malformed counterparts and unknown entries remain fail-closed, and the row remains non-reissuable.
- Preserve verified side-effect evidence for every ARN in `Scope.controlled_arns` in the verified host-scope value passed to `create_batch_intent`; keep ownership proof bound only to the selected target.
- Make runtime grant row-key check and registration atomic, including deny-evidence consumption and grant registration, so concurrent callers cannot both receive a grant.
- Tighten test fixtures to prove each deny case differs from the approved `(ARN, action, "Name")` triple in exactly one component; isolate process-local name bindings in the restart replay test; remove host filesystem dependence from the offline socket/startup test; use nonzero fixture UID/GID values independent of the executing account while preserving production root rejection.

## Behavior and boundaries

1. **Scope and STS timing:** `issue()` retains all current authorization checks. Immediately before creating the durable attempt and calling STS, the current Scope is revalidated through the pre-STS gate contract. A HOLD/UNKNOWN result blocks before journal or network side effects. Request time continues to govern the STS expiration upper bound. One timestamp sampled after a successful exchange governs the lower bound and all post-response issuance timestamps.
2. **Python compatibility:** Replace `weakref_slot=True` with a Python 3.10-compatible weak-reference mechanism for `VerifiedHostContext`; do not change host identity or weak-key registry semantics.
3. **Durable journal:** Directory creation/retry paths sync the parent directory before PENDING can be treated as durable. `scan()` distinguishes legitimate finalization temp names from canonical records, validates their associated canonical tombstone and temp record, and does not expose them as records. Only safely attributable finalization leftovers may be reconciled; ambiguous or unknown files block. The canonical tombstone remains the authoritative row-attempt denial.
4. **Scope evidence and grants:** Resolve and validate one side-effect evidence item per controlled ARN and retain the complete verified set. The selected target still receives its own ownership proof. Runtime grant issuance serializes row-key uniqueness and one-shot evidence/grant registry updates; a rejected path does not leave a grant available.
5. **Regression tests:** Add focused tests for post-selection Scope drift, response-received timestamp consistency and preserved upper bound, retry parent fsync, temp-file reconciliation and orphan rejection, all-controlled-ARN evidence, concurrent same-row grant attempts, exact deny-case deltas, restart journal-only replay denial, host-independent socket/startup assertions, and non-root fixed test IDs.

## Tests and acceptance

- New regression tests fail against the current implementation and pass after the corresponding changes.
- Existing issuer, host runtime, and runtime evidence tests continue to pass.
- Run focused tests for all touched modules, then the full test suite and SHA-256 manifest validation.
- Review the final diff for minimal scope, run `git diff --check`, commit the implementation, and push the current branch after verification.
- Do not change production root rejection, expiry upper-bound semantics, row tombstone replay protection, or selected-target ownership-proof binding.
