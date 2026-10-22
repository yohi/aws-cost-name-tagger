# G2 Evidence Acquisition — I0 Offline Foundation

**Status:** IMPLEMENTED FOR OFFLINE INPUT ONLY / NO AWS CONNECTION / NOT AN EXECUTION GRANT  
**Date:** 2026-10-22 JST  
**Baseline:** `master d4b3ec819fb70dab1e15b355143b78a93210904d`  
**Normative design:** `docs/gates/G2_OFFLINE_EVIDENCE_BUNDLE_CONTRACT_R1_2026-10-22.md` (contents R1.1)

## Purpose and authorization boundary

This I0 implementation provides a **local-only evidence receipt, integrity verification, and restricted shared-ZIP exporter**. It **does not collect data from AWS**; IAM, SCP, CloudTrail, Identity Center, CloudTrail Lake, and resource API data must be obtained separately with appropriate authorization and a read-only collector, which is *not yet implemented*. It does not use or request AWS credentials, contact AWS, alter IAM, or enable `apply()` / `write_name()`.

A local import does **not** certify that supplied files originated from AWS or that API pagination/regions/policy versions are complete. Every imported record is marked `PARTIAL` / `OFFLINE_USER_SUPPLIED_UNVERIFIED`; the manifest remains `snapshot_atomic: false` and `snapshot_consistency_status: NOT_ATTEMPTED`. `verify` checks byte integrity only, not collection completeness or security of a particular principal.

### Supported CLI

| Command | Function | Status boundary |
|---|---|---|
| `init` | Create private bundle directory (0700) and empty manifest | `NOT_ATTEMPTED` |
| `ingest` | Import manually supplied JSON / JSONL into `raw_secure/` with SHA-256, byte length and evidence metadata | `PARTIAL`; unverified provenance |
| `verify` | Cross-check raw files against manifest and SHA256SUMS; reject unexpected files, modified bytes, symlinks, over-broad local permissions | `INTEGRITY_VERIFIED_ONLY` |
| `export-shared` | Produce a fresh ZIP exclusively from externally reviewed, digest-approved files in `redacted_shared/` | No independent redaction/security certification |
| `verify-shared` | Check ZIP CRC and entries; fail on `raw_secure/`, other directories, traversal, duplicates, symlinks and oversized members | ZIP structure only |

**Defensive restrictions:** No output bundles or share ZIPs within any detectable Git working tree (including worktrees with a `.git` file); no archive overwrites; raw files and manifest created with mode 0600. Paths and source API names are constrained; simple key-based scanner rejects credential-like fields before local JSON/JSONL import and before optional JSON share export. **This scanner is not a comprehensive secret detector.** Only use pre-screened sources; stop if prohibited secrets may be present. Encryption at rest, retention, access-control policy, source authenticity and actual approval authenticity are external obligations.

## Local example (synthetic data only)

Use a directory **outside the Git repository**, e.g. a private encrypted volume. No command below touches AWS.

```bash
python g2_evidence.py init /tmp/g2-demo-20261022 \
  --account 456720798575 \
  --baseline d4b3ec819fb70dab1e15b355143b78a93210904d

printf '%s\n' '{"example":"synthetic-offline-input"}' > /tmp/g2-example.json

python g2_evidence.py ingest /tmp/g2-demo-20261022 /tmp/g2-example.json \
  --id G2-A01 --name iam_example.json \
  --source IAM --api iam:GetAccountAuthorizationDetails \
  --region global --pages 1 --pagination-complete

python g2_evidence.py verify /tmp/g2-demo-20261022
```

The `--api`, `--pages` and `--pagination-complete` values are user-reported metadata; they do not verify that an AWS call happened. The example data must **never** be used as production IAM evidence.

### Shared ZIP export (requires a separate human review)

1. Independently sanitize and review the output; place only that derivative under `/tmp/g2-demo-20261022/redacted_shared/`. Never copy any raw file directly as if it had been redacted.
2. Compute the **derivative** SHA-256 and produce an **external**, operator-maintained approval JSON. The program does not generate approvals:

```json
{
  "reviewed_by": "reviewer-identifier",
  "approved_at_utc": "2026-10-22T10:00:00Z",
  "files": [
    {
      "path": "redacted_shared/summary.json",
      "sha256": "REPLACE_WITH_REAL_64_CHAR_HEX_SHA256"
    }
  ]
}
```

3. Save this approval list to a protected path outside the working tree and execute:

```bash
python g2_evidence.py export-shared /tmp/g2-demo-20261022 \
  /tmp/g2-demo-share.zip \
  --approval-file /tmp/g2-demo-approval.json --confirm-reviewed

python g2_evidence.py verify-shared /tmp/g2-demo-share.zip
```

The approval file is **self-declared metadata**, not a digital signature. Operator review and secure transfer policy remain mandatory. `verify-shared` cannot detect confidential text under permitted filenames; the response expressly returns `content_redaction_verified: false`.

### What is not implemented in I0

- **No AWS API collectors:** STS account matching, IAM authorization details, SSO/Identity Center assignments, Organizations policy path, CloudTrail Event History, S3 Trail `*.json.gz` (not supported by JSON import), Lake queries, automation census and resource tag reads. An AWS evidence acquisition implementation requires a separate review/authorization. `GetObject`/Lake source names in a local manifest are **user assertions**, not observed calls.
- **No consistent snapshot evidence:** BEGIN/END cross-check of policy versions, resource tags, Identity Center assignments, SCP inheritance or ABA detection. Any complete/consistent result must come from a reviewed future collector; I0 forbids upgrading this state.
- **No automatic redaction or authoritative transformation log:** redacted files must be produced and checked externally. The G2 R1.1 `derived_manifest.json` provenance contract and cryptographic linkage need a separate reviewed implementation before a G2 COMPLETE claim.
- **No assertion of Identity Center or CloudTrail coverage** from imported files; missing, denied or uncollected regions/sources remain UNKNOWN. This includes Event History/Trail S3/Lake being independent.
- **No ZIP with raw evidence** and no public repository ingestion of IAM/CloudTrail results.

## Tests and CI

`python -m unittest -v test_g2_evidence` runs the offline security regression suite; `.github/workflows/g2-offline.yml` runs it with only Python's standard library and an explicit AST check against AWS SDK imports. The original v3.6 Safety Hold CI and `SHA256_MANIFEST.json` baseline are not modified. The legacy manifest protects its original fixed v3.6 file set; it is **not** a checksum attestation for the new G2 files.

## Gate positions

`G1 NOT PROVEN` / `G2 EVIDENCE ACQUISITION NOT EXECUTED` / `G2 NOT VERIFIED` / `G3/G4 NOT COMPLETED` / `G5/G6 NOT APPROVED` / **AWS WRITE BLOCKED / Safety Hold maintained**.

This foundation should undergo independent review before being relied upon for custody of real sensitive evidence.
