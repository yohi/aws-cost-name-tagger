# AWS Cost Name Tagger — Tasks 1–6 offline implementation work-in-progress

**Source decision:** `yohi/aws-cost-name-tagger`, reviewed HEAD `23f995f1a481523b7b43f403166a234239d95c95`.

**Human Owner authorization:** Batch Design adopted. Bounded offline implementation and offline tests for Tasks 1–6 approved; this does NOT approve an existing Ledger migration, IAM/Trust updates, AWS or STS operations, Task 7, GitHub commit/push, PR creation or Merge.

**Snapshot status: PARTIAL / HISTORICAL SOURCE.** The files here preserve the original standalone WIP; adapted copies now live at the repository root. This directory is not an execution path. Its `manifest.json` and `test-results.txt` describe the original snapshot only and are not evidence for the current root implementation. The original WIP left host-bound Ledger admission, signed schema migration, runtime ScopeEvidence, and `batch-simulate` integration incomplete; these are now integrated and offline-tested at the repository root. The Safety Hold remains active, and no existing Ledger or AWS resource has been migrated or modified.

## Implemented and isolated-test coverage

| Task | Offline WIP | Missing for plan completion |
| --- | --- | --- |
| 1, CUR | Original-decimal parser, exact coefficient/scale addition, legacy-float ordering partition, out-of-scope / unsupported / unattributable taxonomy, schema-2 population validation | Integrate with the repository's bounded two-pass CUR scanner and Plan writer; test 105/100/5 and legacy suite |
| 2, Name / CSV | `classify_batch_name`, strict Name/raw tuple, unique declared Scope/ARN checks, 14-column BOM CSV and approved-row filtering | Inject `batch_name_state` into real `Investigator.resolve`; integrate actual Batch Plan generation and all service/kind validators |
| 3, Owner signature | Canonical unsigned `BatchApprovalV1`, `approved_rows_sha256`, manifest, fail-closed `verify_batch_approval` that requires protected existing OwnerTrust/OpenSSH | Integration with existing key/role/revocation loader and actual signed fixtures; test per-row fresh Trust |
| 4, Ledger | Disposable SQLite **test fixture only** for durable cap, cross-scope STOP, cap dispositions, consumed history and restart behavior | Extend **existing protected host-bound Ledger** with Owner-approved v1→v2 migration contract and production transaction invariants. Do not run migration without separate Owner GO |
| 5, IAM / credentials | Exact volume ARN + Name-key policy, separate `Resource:*` read statement, synthetic-only issuer | Verify full effective IAM/side-effect evidence and implement protected real host-only issuance under a distinct future authorization; NO STS call now |
| 6, offline report/executor | `UNSIGNED_PREVIEW` and strict Plan/CSV binding, synthetic in-memory executor and report, offline CLI `prepare-batch`/`batch-dryrun` | Genuine authenticated executor wired to protected Trust, real existing Ledger, current independent ScopeEvidence and offline fake SDK. `verify-batch` and `batch-simulate` CLI intentionally remain blocked |

**Critical safety design:** No boto3 import, STS client call, AWS write API or provisioned-host Ledger migration in this bundle. `OfflineFixtureBatchLedger` must **never be substituted** for `name_tag_ledger.IntentLedger`; `InMemoryNameAdapter` must never be used as a runtime AWS write adapter. `OfflineFakeIssuer` produces no real STS credentials. The `execute_batch_offline` entry deliberately fails closed until trusted integration exists. Unsigned Preview and fabricated fixture results cannot be promoted to Owner approval.

## Run isolated tests

```bash
cd tasks1-6
python -m unittest discover -v
```

These tests validate only the included standalone modules, **not** the original repository tests or all implementation-plan acceptance criteria. Do not interpret their success as Production/Task7/AWS-Write readiness.

The offline CLI resolves every input and output path against its invocation directory and rejects paths (including symlinks) that resolve outside it. Run the CLI from the private directory containing the Plan, review CSV, and intended outputs.

## Preserve the existing holds

```text
SAFETY_HOLD_ACTIVE
AWS_WRITE_BLOCKED
G1_NOT_PROVEN
G2_NOT_VERIFIED
AWS_RUNTIME_NOT_AUTHORIZED
```

**Historical checkpoint:** At the time this snapshot was created, it had not been applied to a repository checkout. The current implementation status and verification evidence are maintained in the repository-root worktree and final task report, not in this snapshot. Do not treat this fixture bundle as production code or start follow-on tasks from it.
