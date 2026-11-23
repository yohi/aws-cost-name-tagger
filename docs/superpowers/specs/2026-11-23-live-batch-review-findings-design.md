# Host-protected Batch review findings

## Goal

Close the accepted live Batch authorization, concurrency, IPC, and report-durability findings while preserving the existing public APIs and fail-closed behavior.

## Scope

This change is limited to the existing Host-protected Batch execution flow and its regression tests. It does not promote additional AWS resource kinds, alter authorization policy, or change the offline execution API.

## Decisions

1. **Host selections and direct execution concurrency**
   - Serialize `execute_batch_live` calls per verified Host. Different Hosts may still execute concurrently.
   - Keep selection cleanup at the end of an execution; per-Host serialization ensures one call cannot clear another call's unconsumed selections.
2. **Scope side-effect evidence**
   - During pre-Permit reconfirmation, validate every item is exactly `SideEffectEvidence`, reject duplicate/missing/extra targets, normalize by `target_arn`, then compare against the verified scope's canonical `side_effects`.
   - Ordering alone is not a change; type or content changes remain a refusal.
3. **Live runtime grants**
   - Preserve the one-shot grant checks that bind the Host-issued grant to the row, consumed Permit, target, and expiry.
   - Carry an internal one-use dispatch binding from the validated live-grant consumer to `SingleNameAdapter`; the adapter must verify live Host provenance plus target/name/Permit binding before the SDK call.
   - Synthetic, composed, altered, expired, or reused grants must not call the SDK.
4. **Ledger certainty and unresolved sends**
   - If the initial execution-state read raises `LedgerError`, return `OUTCOME_UNKNOWN` with the Batch ID because the durable send state is not known.
   - Preserve the existing pre-send `BLOCKED` behavior when a successful read confirms the Batch is `UNREGISTERED`.
   - For a consumed Permit with an unresolved Intent, persist STOP and Scope HOLD for both `ACTIVE` and `STOPPED` Batch states. Any failure to persist required state remains `OUTCOME_UNKNOWN`; never consume another Permit or resend.
5. **Host IPC connection admission**
   - Reserve a connection slot immediately after `accept()` and before spawning a worker.
   - Count a reserved connection through peer rejection, request handling, and any response produced by that worker; release exactly once on completion.
   - When all slots are occupied, send the pre-accept BUSY response inline and close the accepted socket without creating a worker.
   - If `_spawn` fails, release the reservation, close the socket, and continue the accept loop.
   - Validate that an IPC response status is a string before checking membership in `STATUSES`; retain the current decision for valid strings.
6. **Atomic and durable reports**
   - Write the complete report to a unique temporary file in `batch_dir`, fsync the file, and atomically publish it at the digest path.
   - Clean up failed temporary files when possible; unique temporary names ensure cleanup failure does not block retry.
   - Verify a newly published or reused digest file, then sync the file and directory ancestry in order: `batch_dir`, `batch-reports`, `StateDirectory`. Return a digest only after all required syncs succeed.
7. **Regression test precision**
   - Assert `_run_accepted` calls `map_endpoint_result` exactly once with the request ID and endpoint result.
   - Assert exact STS write `Resource` ARNs and the expected number of STS requests.
   - Separate synthetic-grant rejection from missing-binding cases; each missing adapter, target, or clock case receives a fresh live grant.
   - Exercise the live API rejection with a valid signed Batch and Host-bound Ledger so only the offline runtime is invalid.
   - Use a canonical API Gateway Stage ARN and matching locator so the test reaches `_PROMOTION_BLOCKS` and fails if that block is removed.
   - For successful adapter dispatch, use the real Registry adapter and a fake SDK client.

## Compatibility and security invariants

- Preserve the signatures of `execute_batch_live`, `execute_batch_offline`, the IPC v1 wire format, and the Batch report digest.
- Preserve Host/Owner/Scope verification, the signed send cap, one-shot Permit semantics, and the existing exact string-status decisions.
- Do not allow uncertainty after a possible send to be represented as a pre-send refusal.
- All failures at the SDK dispatch boundary remain fail-closed and make zero SDK calls unless all Host-issued bindings are valid.

## Verification and delivery

- Add regression tests before changing production code and confirm each fails for the intended reason.
- Run focused tests for touched modules, then `python -m unittest discover -v`.
- Run `uv run --locked --no-build python scripts/validate_sha256_manifest.py` and `git diff --check`.
- Update SHA256 manifest entries for registered files changed by this work.
- Commit the three logical areas separately using Japanese Conventional Commit messages, then push the current branch after verification.
