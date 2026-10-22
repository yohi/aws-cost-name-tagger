# G2 Evidence Acquisition — I0 Offline Foundation

**Status:** I0 REVIEW REMEDIATION R1 — IMPLEMENTED FOR OFFLINE INPUT ONLY / NO AWS CONNECTION / NOT AN EXECUTION GRANT  
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
| `verify` | Cross-check raw files, strictly pinned Manifest/Scope/entry schema and SHA256SUMS; reject unexpected files, modified bytes, symlinks, unsafe Git moves and broad permissions | `INTEGRITY_VERIFIED_ONLY` |
| `recover` | Explicitly reconcile an interrupted `ingest` journal: validated rollback if RAW was never written or exact-byte roll-forward if RAW is intact | Never certifies evidence or silently deletes corrupted RAW |
| `export-shared` | Produce a fresh ZIP exclusively from externally reviewed, digest-approved files in `redacted_shared/` | No independent redaction/security certification |
| `verify-shared` | Strict canonical entry paths, CRC, ordinary-file types, comments and extra fields, archive size, and byte-for-byte canonical ZIP reserialization; reject unapproved hidden headers/trailers | ZIP structure only |

**Defensive restrictions:** The trusted CLI restricts all user-provided paths to dedicated private workspace areas. Every bundle operation rechecks that it is outside any detectable Git worktree (including worktrees with a `.git` file). ZIP output uses atomic no-clobber linking to avoid a race with another creator. Private files are opened with exclusive 0600 permissions at creation; verification rechecks RAW and metadata permissions. ZIP paths must use one canonical spelling; comments, extra fields, non-regular files and hidden ZIP prefix/trailer data are rejected. Paths and source API names are constrained; a key-based scanner rejects credential-like fields before local JSON/JSONL import and optional JSON share export. **This scanner is not a comprehensive secret detector.** Only use pre-screened sources; stop if prohibited secrets may be present. Encryption at rest, retention, access-control policy, source authenticity and actual approval authenticity remain external obligations.

**Interrupted ingest protocol (FND-006):** `ingest` preflights `verify`, creates a protected exclusive `04_INGEST_PENDING.json` journal containing old/new manifest and SHA256SUMS hashes and a single evidence record, then writes RAW, Manifest and SHA256SUMS in order. An interruption leaves the journal and `verify` refuses to proceed. Only an explicit `recover` verifies the journal's old/new hashes: if RAW never arrived and old metadata is intact it drops the pending journal; if RAW is intact it deterministically rolls metadata forward. Corruption, unexpected metadata, or a partial RAW refuses recovery and preserves evidence for manual quarantine. This is a **fail-closed process-interruption protocol**, not a cross-file ACID transaction or proof of storage durability during power loss. Do not delete or overwrite a journal to bypass validation.

## Trusted CLI workspace and synthetic example

The CLI requires an operator-controlled **absolute** \`G2_EVIDENCE_WORKSPACE\` environment variable. This is a local private workspace selected by the operator, not a path accepted from a remote request or LLM-provided argument. It must be outside all Git worktrees and use mode 0700 on POSIX. Pre-create four private subdirectories: \`bundles/\`, \`incoming/\`, \`approvals/\`, and \`exports/\`. Every CLI path is an absolute **direct child** in its appropriate area. Path traversal, symbolic links, relative paths, and arbitrary filesystem locations are refused before an operation begins. Direct use of the Python library must still be restricted to trusted local callers; a CLI workspace is **not a sandbox** and does not defend against a fully malicious same-user process.

\`\`\`bash
# Use a trusted private volume OUTSIDE the repository:
export G2_EVIDENCE_WORKSPACE=/tmp/g2-private-20261022
mkdir -m 700 "$G2_EVIDENCE_WORKSPACE"
mkdir -m 700 "$G2_EVIDENCE_WORKSPACE"/{bundles,incoming,approvals,exports}

python g2_evidence.py init "$G2_EVIDENCE_WORKSPACE/bundles/demo" \
  --account 456720798575 \
  --baseline d4b3ec819fb70dab1e15b355143b78a93210904d

printf '%s\n' '{"example":"synthetic-offline-input"}' \
  > "$G2_EVIDENCE_WORKSPACE/incoming/example.json"

python g2_evidence.py ingest "$G2_EVIDENCE_WORKSPACE/bundles/demo" \
  "$G2_EVIDENCE_WORKSPACE/incoming/example.json" \
  --id G2-A01 --name iam_example.json \
  --source IAM --api iam:GetAccountAuthorizationDetails \
  --region global --pages 1 --pagination-complete

python g2_evidence.py verify "$G2_EVIDENCE_WORKSPACE/bundles/demo"

# Only if verify reports a pending interrupted import:
# python g2_evidence.py recover "$G2_EVIDENCE_WORKSPACE/bundles/demo"
\`\`\`

The \`--api\`, \`--pages\` and \`--pagination-complete\` arguments are self-reported offline metadata, **not** evidence of actual AWS calls. The example is synthetic and must not be used for production IAM evidence.

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

3. Place the approval file inside the private \`approvals/\` directory (mode 0600). Export only to \`exports/\`:

\`\`\`bash
python g2_evidence.py export-shared \
  "$G2_EVIDENCE_WORKSPACE/bundles/demo" \
  "$G2_EVIDENCE_WORKSPACE/exports/demo-share.zip" \
  --approval-file "$G2_EVIDENCE_WORKSPACE/approvals/demo-approval.json" \
  --confirm-reviewed

python g2_evidence.py verify-shared \
  "$G2_EVIDENCE_WORKSPACE/exports/demo-share.zip"
\`\`\`

The approval file must be stored as a private (0600 on POSIX), non-symlink file. It is **self-declared metadata**, not a digital signature. Operator review and secure transfer policy remain mandatory. `verify-shared` cannot detect confidential text under permitted filenames; the response expressly returns `content_redaction_verified: false`.

### What is not implemented in I0

- **No AWS API collectors:** STS account matching, IAM authorization details, SSO/Identity Center assignments, Organizations policy path, CloudTrail Event History, S3 Trail `*.json.gz` (not supported by JSON import), Lake queries, automation census and resource tag reads. An AWS evidence acquisition implementation requires a separate review/authorization. `GetObject`/Lake source names in a local manifest are **user assertions**, not observed calls.
- **No consistent snapshot evidence:** BEGIN/END cross-check of policy versions, resource tags, Identity Center assignments, SCP inheritance or ABA detection. Any complete/consistent result must come from a reviewed future collector; I0 forbids upgrading this state.
- **No automatic redaction or authoritative transformation log:** redacted files must be produced and checked externally. The G2 R1.1 `derived_manifest.json` provenance contract and cryptographic linkage need a separate reviewed implementation before a G2 COMPLETE claim.
- **No assertion of Identity Center or CloudTrail coverage** from imported files; missing, denied or uncollected regions/sources remain UNKNOWN. This includes Event History/Trail S3/Lake being independent.
- **No ZIP with raw evidence** and no public repository ingestion of IAM/CloudTrail results.

## Tests and CI

`python -m unittest -v test_g2_evidence` runs the offline security regression suite (including independent-review FND-001..006 regressions); `.github/workflows/g2-offline.yml` runs it with only Python's standard library and an explicit AST check against AWS SDK imports. The original v3.6 Safety Hold CI and `SHA256_MANIFEST.json` baseline are not modified. The legacy manifest protects its original fixed v3.6 file set; it is **not** a checksum attestation for the new G2 files.

## Gate positions

`G1 NOT PROVEN` / `G2 EVIDENCE ACQUISITION NOT EXECUTED` / `G2 NOT VERIFIED` / `G3/G4 NOT COMPLETED` / `G5/G6 NOT APPROVED` / **AWS WRITE BLOCKED / Safety Hold maintained**.

This foundation remains **REVISION_REQUIRED until a fresh independent review** accepts the remediation and the external SonarCloud Quality Gate is investigated. GitHub Actions unit tests do not substitute for the SonarCloud Security Rating. SonarCloud's PR issue endpoint separately identified seven `pythonsecurity:S8707` issues claiming CLI argument path-traversal flows (`init`, `ingest`, `read_json`, `verify_shared`, `export_shared`). The CLI now confines its arguments to an operator-configured private workspace with separate input, approval, bundle and output areas; independent review and an actual SonarCloud PASS are still required. Sonar's claimed HTTP-request source should be evaluated against this local-CLI-only threat model rather than presumed to represent a deployed HTTP handler.

This foundation should undergo independent review before being relied upon for custody of real sensitive evidence.
