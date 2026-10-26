# Issue #23 P1 - SonarQube Cloud Coverage Cutover Contract R0

Date: 2026-10-26 JST
Reference master HEAD: 20d1fa9b7e11e10a120ff9afb00899485ea968c8
Reference master tree: 6ed0f39b96c0d86c12268d3ab84570bfcc8593f2
Status: R1_LIMITED_CORRECTIONS_DRAFT / DESIGN_ONLY / ANALYSIS_METHOD_UNVERIFIED / A0_CONFIRMATION_STOP / NO_SCANNER_OR_SECRET_CHANGE

## 1. Direct evidence versus unverified settings

VERIFIED:
- PR #25 merged. The unprivileged master CI (GitHub run 40296026980) emitted stdlib trace-based generic line coverage XML at `offline-line-coverage/sonar-generic-coverage.xml`. CI: Python 3.10/3.11/3.12, converter 28 tests each, app 168 tests x2 each, SHA manifest 14/14 each. Separate G2 run 40296026971: 110/110 x2. The master source tree is `6ed0f39b96c0d86c12268d3ab84570bfcc8593f2`.
- Offline generic XML SHA256: `71118fc8f0f281a6db1278635834b68a2ab9b82838ae2e715ed365ea5880d0cb`; 1212 hit / 1406 eligible lines (86.2% executed-line metric only, not branch or MC/DC).
- Repository CI has no SonarScanner invocation, SONAR_TOKEN, or sonar-project.properties. SonarCloud itself nonetheless analyzed master and PRs. Its public master measures did not provide a coverage percentage. GitHub master ruleset 25668708 contains PR required/non-fast-forward/deletion rules but no listed required-status-check rule; reading separate branch protection returned 403.

UNVERIFIED:
- SonarQube Cloud project Administration > Analysis Method actual setting (AUTO_ON, AUTO_OFF), project administrator identity/authority, organizational override, plan tier (Free/Team/Enterprise), token types actually permitted, hosted project region (EU/US), scanner secrets/tokens, branch protection status-check requirements, and fork PR policy.
- SonarCloud import of the prepared XML: not attempted, not proven.
- Public analysis behavior is consistent with automatic analysis but cannot establish the admin setting.

OFFICIAL SONAR CONTRACT:
- Automatic Analysis does not ingest coverage.
- Automatic and CI-based scanner analysis may not run simultaneously on a project; scanner execution will fail if automatic mode is enabled.
- Generic Coverage XML v1 is imported with `sonar.coverageReportPaths=offline-line-coverage/sonar-generic-coverage.xml`. The Python-specific `sonar.python.coverage.reportPaths` is for Cobertura and is not interchangeable.
- Sonar reported line metrics and denominators can differ from Python stdlib trace figures because of analyzer and file-scope differences.

Sources:
https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/ci-based-analysis/overview-of-integrated-cis
https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/concepts
https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/test-coverage/generic-test-data

## 2. Explicit security threat model

GitHub Security Lab advisory GHSL-2026-208, published 2026-10-22, describes exfiltration of `SONAR_TOKEN` from a privileged `workflow_run` scanning an external fork's attacker-controlled `sonar.properties`. A changed `sonar.host.url` redirected an authenticated bootstrap request. See:
https://securitylab.github.com/advisories/GHSL-2026-208_kptdev_kpt_repository/

Mandatory negative contract:
- No Sonar token in Python tests, uv installation, trace conversion, G2 tests, or any job running contributor-controlled executable code.
- No privileged `workflow_run` consumer of fork PR artifacts; no `pull_request_target` checkout of untrusted code.
- No scanner invoking PR-supplied `sonar.properties`, `sonar-project.properties`, arbitrary server URL or unsigned/variable scanner. The trusted effective Sonar endpoint and region MUST be version-aware and frozen at A1: for current scanners, confirm EU default or set `sonar.region=us` for a verified US instance; do NOT automatically force `sonar.host.url` on newer scanners. For older supported scanners, pin `sonar.host.url=https://sonarcloud.io` only per official version-specific guidance. Independently test property/environment/CLI precedence for the exact scanner release with a dummy credential before any real token is granted.
- Token privilege and availability MUST be proven at A0. Scoped Organization Tokens (SOT) are Team/Enterprise only; SOT can be restricted to one project with Execute Analysis and a selected expiry. Free-plan Personal Access Tokens (PAT) cannot be assumed project-scoped or equivalently constrained. Under this first-release strict least-privilege contract, if project-limited analysis credentials cannot actually be obtained, STOP before A1 approval or scanner activation; only a newly reviewed explicit contract with compensating controls and separate Owner risk acceptance may change that condition. Record token owner, intended scope, expiry/rotation/revocation capability, and permission evidence without recording token bytes. Store approved token only as a GitHub secret, never in an issue, log, repository or chat.
- Immutable SHA pins for checkout, artifact download and scanner actions, plus independently verified scanner release/distribution digest and transitive bootstrap behavior. Job-level GITHUB_TOKEN permissions MUST be minimal: `contents: read` for checkout, `actions: read` only if needed to fetch same-run artifact or GitHub control-plane metadata; all other permissions `none`. Scanner secret only at the final scanner step.
- Do not restore untrusted caches, invoke repository scripts or install project dependencies within a privileged scanning job. A scanner necessarily parses project source; parser vulnerabilities remain a residual risk.
- Fork pull requests are out of scope for privileged CI scanning until their independent secret/no-secret status strategy is reviewed.

## 3. Candidate first-release scanner architecture (NOT IMPLEMENTED)

Recommended initial scope: trusted master PUSH only, not PRs, forks or workflow_run. Keep the existing CI test matrix unprivileged. A separate scanner job may depend on all matrix tests in the SAME Safety Hold CI run, downloading the Python 3.12 artifact by its exact name after successful completion. No scanner code may be merged active until Gate A0/A1 approval.

The scanner job shall:
1. Run only on `github.event_name == 'push'`, `github.ref == 'refs/heads/master'` and `needs: offline-tests` success; never on a PR or fork.
2. Checkout the exact trusted GitHub master SHA with `persist-credentials: false` and `fetch-depth: 0`; ensure checkout SHA/tree equal the workflow run head and the coverage evidence tree.
3. First verify the SAME-run artifact against authenticated, trusted GitHub control-plane metadata: repository/workflow identity, push/master event, completed successful run ID and run attempt, trusted head SHA, successful Python 3.12 producer job ID, unique artifact ID/name, GitHub-reported archive digest and archive retention state. Hash the downloaded ZIP BYTES and compare to the independently queried GitHub digest, not merely an embedded receipt. The ZIP must be inspected before any ordinary extraction; use an independently pinned safe archive verifier with bounded memory and size/entry quotas. Refuse duplicate normalized paths, absolute/traversal/Windows paths, symlinks/hardlinks, nonregular members, unexpected files, encryption, suspicious compression ratios or corrupted CRC. Only after successful verification, extract the exact allowlisted files to an isolated nonprivileged directory and validate per-file SHA-256 against `coverage-evidence.json`, original Git tree/source identity, XML source mapping and nonzero eligible rows. Self-reported hashes inside the ZIP alone are NOT independent provenance; a compromised producer can forge XML and evidence JSON together. See detailed trust contract in Section 6.
4. Invoke only the exact A1-frozen scanner action/CLI release and digest after the artifact is independently checked. Provide `SONAR_TOKEN` ONLY to the scanner step. Pin project key `yohi_aws-cost-name-tagger` and organization `yohi` (both admin-confirmed), plus A0-verified EU/US region and A1-frozen VERSION-SPECIFIC connection parameters, and `sonar.coverageReportPaths=offline-line-coverage/sonar-generic-coverage.xml`. Stop if the effective destination or property precedence differs from A1.
5. Verify scanner log import of generic coverage, path mapping to `aws_cost_name_tagger_v3.py`, correct master revision and nonempty, interpretable Sonar coverage measures. A green Quality Gate alone is NOT proof of import.

Security tradeoff: master-only scanning intentionally does not replace SonarCloud PR analysis when automatic mode is disabled. The Human Owner must approve a temporary loss of PR analysis or commission a separate secure PR-scanning design, and review required-check policy before disabling Automatic Analysis.

Do not assume that turning off Automatic Analysis before scanner implementation or activating a scanner before turning it off is harmless. Sequence a controlled cutover with explicit STOP/rollback; do not operate both mechanisms together.

## 4. Gates and owner decision record

A0 / MODE CONFIRMATION - BLOCKING / HUMAN OWNER OR SONAR PROJECT ADMIN:
- Observe the authenticated project page Administration > Analysis Method. Record AUTO_ON/AUTO_OFF, observer, date/time, project key, available administrative privileges.
- Record Sonar master/PR Quality Gate and New Code definition, GitHub branch protection/ruleset required check names, whether fork PRs are permitted and must retain PR analysis. Also record project region (EU/US), actual subscription tier (Free/Team/Enterprise), token types enabled for that tier and whether strict one-project `Execute Analysis` scope and revocation/expiry requirements can be met.
- Record secret/token creation authority and agreed owner/expiry/scope. Do not create or reveal token at A0.
- Record yes/no approval for a master-only first release and its PR-analysis limitation.
- Until documented: `A0_MODE_CONFIRMATION_STOP`.

A1 / INDEPENDENT SECURITY DESIGN REVIEW - BLOCKING:
- Freeze, BEFORE independent A1 acceptance, a concrete signed/hashed A1 Scanner Lock Record (see Section 7) containing exact action commit SHAs, scanner CLI version and immutable release/digest, selected EU/US endpoint/region settings, property precedence, all trusted scripts/dependencies, secret scope/usage and same-run ZIP validation contract. A1 independently reviews and accepts this fixed record and the master-only trigger; an unspecified scanner version or untested host precedence is A1_STOP.
- Test/assess malicious fork PR configuration, forged artifacts, input paths, mismatched SHA/tree, absent report, old/expired token, automatic analysis still enabled, and loss of PR branch protection checks. No finding may be silently dismissed.

A2 / SEPARATE IMPLEMENTATION PR - OWNER AUTHORIZATION REQUIRED:
- Implement a separate scanner PR ONLY from A1-approved frozen Scanner Lock Record. Independently compare exact SHA/digests, effective settings, job permissions, privileged trust boundary and validation implementation with that frozen contract; any differing version/action/config returns to A1, not silently updated in A2. Stage scanner inert/disabled until explicit A3 cutover; never merge an active scanner during Automatic Analysis ON. Build/review under fixed HEAD/tree with SHA256 Manifest, Safety Hold and G2 preserved.

A3 / CONTROLLED CUTOVER AND EVIDENCE ACCEPTANCE - OWNER AUTHORIZATION:
- Follow the explicit S0/S1/S2/S3 + STOP/RESTORE state-transition contract in Section 8. Obtain a fresh Owner go/no-go at each sensitive transition and record the old mode, check policy, authorized toggle and rollback; verify Automatic Analysis OFF before any scanner attempt. Parallel Automatic+CI scans are forbidden.
- Require scanner import logs, Sonar project revision, nonempty master imported coverage metrics and reconciliation to offline 1212/1406 including any denominator difference.
- Confirm Sonar PR checks are restored or explicitly deferred in the approved branch policy.
- On any STOP, immediately disable further scanner dispatch first, drain/cancel in-flight runs, and follow the preauthorized rollback; only after scanner activity is proven stopped may Owner consider re-enabling Automatic Analysis. Never equate coverage analytics with AWS write authorization.

## 5. Current findings and STOP

Owner/Admin-observed Analysis Method: UNKNOWN.
Current Sonar token scope/existence and subscription tier: UNKNOWN. First-release SOT eligibility: NOT VERIFIED.
Full branch protection required-check status: UNKNOWN (API returned 403).
Trusted PR scanning strategy: NOT APPROVED.
Project hosted region EU/US: UNKNOWN. Scanner action/CLI version, SHA, transitive digest and region connection: NOT SELECTED; A1 Scanner Lock Record NOT FROZEN.
Security independent review: NOT STARTED.
Cloud CI coverage import: NOT ESTABLISHED.
Current design verdict: `R1_CORRECTIONS_DRAFTED / A0_MODE_CONFIRMATION_STOP / A1_LOCK_RECORD_PENDING / NO_EXECUTION_GRANT`.
AWS Gate invariants: `SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED / G1_NOT_PROVEN / G2_NOT_VERIFIED`.

## 6. FND-26-R1-002 - Artifact identity, independent trust anchor and safe inspection

**Fixed contract for first-release design only; implementation is not granted.** The artifact is NOT authoritative because a file inside it names its own hash or HEAD. A malicious or misconfigured producer can forge both XML and coverage-evidence.json. Independent trust derives first from GitHub's authenticated control-plane records combined with a protected master source revision and a successful, appropriately restricted producer job. The GitHub digest checks transport/object integrity; it does NOT attest that the producing code was benign or that trace execution counts are truthful.

### Control-plane check BEFORE downloading or opening ZIP

- Authenticate GitHub API calls in a trusted, pinned validator job and restrict expected repo to yohi/aws-cost-name-tagger, default branch to master, workflow to .github/workflows/ci.yml and event to a successful push; reject PR, fork, workflow_run, wrong workflow, mismatched repository, deleted/expired artifact, reruns whose run attempt is ambiguous, or changed/stale HEAD.
- Bind caller context to workflow run_id and run_attempt from trusted GitHub event metadata, and bind to the repository's immutable push head commit and Git tree (not a branch name resolved at a later time). Query the originating workflow run, its successful Python 3.12 offline-tests producer job (job ID and completed conclusion) and unique artifact ID/name. Confirm the specific producer belongs to that same run/attempt. Do not accept artifact name alone as identity.
- Request artifact metadata and the ZIP byte stream by immutable artifact ID; require a present GitHub API digest (currently SHA-256), compare with the full downloaded archive bytes and the logged GitHub upload receipt. An in-artifact SHA manifest is not an external anchor. If any digest/identity cannot be obtained with the exact pinned API/client, STOP; never silently drop a check.
- Trusted master commit and GitHub platform control plane are assumptions that must be reviewed at A1, not equivalent to a signed end-to-end producer attestation. If the Owner requires stronger provenance than these assumptions, add separately verified signed provenance/attestations in a new design review before A2.

### Verify archive in a bounded quarantine BEFORE extraction

- Never auto-extract a downloaded artifact into the checked-out source tree or a token-bearing working directory. A vetted pinned fetch client must deliver RAW ZIP bytes to a separate quarantine with mode 0700; verify full byte digest before parsing. This explicitly avoids vulnerable extraction-first versions of actions/download-artifact (GitHub advisory GHSA-cxww-7g56-2vh6 / CVE-2024-42471).
- Require an exact known file allowlist matching the existing artifact producer (currently five regular files: coverage-evidence.json plus four files inventoried in JSON). Any producer layout change must revise and independently review this contract; no wildcard entry acceptance.
- Reject absolute, drive-letter, UNC, NUL, backslash, percent-decoded traversal ambiguities, repeated separators, empty segments, '.' or '..', Unicode/case-fold normalized duplicates, duplicate ZIP central-directory names, extra ZIP members, symlinks, hardlinks, device entries and inconsistent ZIP local/central metadata. Canonical relative paths must stay below quarantine. Do not follow filesystem links.
- Enforce hard limits **before and while decompressing**: archive compressed size <= 5 MiB; entry count exactly 5; each uncompressed regular file <= 5 MiB; total expanded bytes <= 20 MiB; per-entry expansion ratio <= 200; reject encrypted archives, ZIP64 or unsupported compression methods unless a separately reviewed safe parser contract explicitly supports them. These conservative caps exceed the currently observed ~70 KiB artifact, but are proposed hard gates, not claimed as tested.
- Stream/bound decompress, independently check CRC and final sizes, then write only allowlisted paths with exclusive create into an empty, no-follow staging directory; never permit overwrites or execute files. No secrets present in parsing/decompression stages. On failure, remove only files owned by this invocation; preserve pre-existing content, publish nothing.
- Independently validate the extracted JSON schema, unique inventory paths, exactly four per-file SHA-256 values and byte sizes, XML schema/line numbers/relative production path, ZIP-to-JSON correspondence, and trusted control-plane head/tree versus reported git_checkout_tree. Explicitly account for synthetic PR merge refs (though first-release scanner runs only on master push). No scanner until all proofs PASS.
- The validator/parser implementation itself, quotas, Zip Slip negative tests, tampered control-plane receipt tests, duplicate/symlink/zip-bomb cases, forced-extraction failure and cleanup behavior are **A1 design freeze** and **A2 independent implementation acceptance** conditions, not achievements of PR #26.

Sources:
- https://github.com/advisories/GHSA-cxww-7g56-2vh6
- https://docs.github.com/en/rest/actions/artifacts
- https://github.com/actions/attest

## 7. FND-26-R1-001, -004, -005 - A0 Token/Region proof -> A1 frozen scanner record -> A2 exact implementation

### A0 prerequisite evidence (Owner/admin-observed, no changes)

1. Record project Analysis Method AUTO_ON/AUTO_OFF, project URL/project key and organization ID, **hosted region EU or US**, current Sonar plan **Free/Team/Enterprise**, admin privileges and the identity of the observer. Public dashboard URL or successful PR analysis is insufficient evidence of region/mode or the plan.
2. Verify token type allowed by this plan. Official SonarQube Cloud Scoped Organization Token (SOT) is **Team/Enterprise only**, supports custom single-project scope, Execute Analysis and selected expiry. A Personal Access Token (PAT) has the issuing user's permissions and is not equivalent to a project-scoped SOT; do not assume PAT can be made single-project by an environment variable. If strict one-project scope cannot be fulfilled, **A0_STOP / NO_SCANNER_TOKEN** until a separate security design and explicit Human Owner risk decision are independently approved; no silent fallback to broad PAT.
3. Record (without credentials) planned token owner, actual least privilege and revocation, expiry and rotation mechanism; record required GitHub check contexts and external-fork/PR analysis policy. Do not create, copy or test real credentials during A0.
4. Record EU/US region. Official Cloud modern scanner guidance: **EU** is default, needs no explicit server setting; **US** requires sonar.region=us (CLI >= 7.1, GitHub Scan Action >= 5.1.0, or other supported version-specific minimum). New scanners generally SHOULD NOT set sonar.host.url; legacy scanner configurations require a trusted https://sonarcloud.io URL and separate official compatibility proof.

Official references:
- https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/managing-organization/scoped-organization-tokens
- https://docs.sonarsource.com/sonarqube-cloud/managing-your-account/managing-tokens
- https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/analysis-parameters/parameters-not-settable-in-ui

### Pre-A1 record preparation and freeze (non-executable)

After A0 is complete, the implementation-design agent must deliver a separate **A1 Scanner Lock Record R0** with:
- Exact Action repository and immutable commit SHA for checkout, download/fetch, and Sonar scanner; exact scanner CLI version, distribution artifact identifier and SHA-256 digest, bootstrap/dependency resolution and supported runtime; no moving tags or auto-latest.
- Exact region/connection parameters for this version, authoritative scanner property precedence (project files, env vars, command arguments), allowlisted effective network destination and a dummy-token/local-only host precedence regression test plan. On versions that use sonar.region, explicitly prohibit an unreviewed host.url override. Reject fork-supplied sonar.* files, server URL, proxies, JVM options or repository scripts in scanner trust context.
- Locked project/org identifiers; analysis scope and Generic XML report path; source tree and coverage artifact correlation; trusted validation client/library and ZIP parser versions/digests, exact expected member set, quotas and failure/cleanup rules.
- Master-only event condition and analysis method cutover prerequisites; job token permissions (contents:read, only necessary actions:read), separate Sonar secret exposure exclusively to scanner step, token SOT availability/evidence and risk policy, PR-status-check impact and rollback.
- SHA-256 of this Lock Record and a Human Owner approval signature/decision linked to its fixed content. This is a specification artifact, NOT an active scanner job.

**A1 independent reviewer MUST compare those fixed exact versions/digests to upstream source, run the precedence/region test with fake credentials in isolation, and verify all artifact and host trust boundaries.** A1 must reject UNSPECIFIED, FLOATING, AUTO_UPGRADED or untested values. A1 acceptance freezes the record; any change needs an updated record and a NEW independent A1 decision.

**A2 separate implementation PR MUST demonstrate byte/config compatibility with the A1-frozen record at a pinned Git HEAD/tree**, with an independent reviewer checking action SHAs, scanner distribution hash, connection behavior, workflow trigger/job needs, scan scope, permission/secret isolation, artifact ZIP behavior, security negative tests and SHA256 Manifest. Discrepancy means A1_REOPEN_STOP. A2 may stage DISABLED scanner code on a trusted branch; it MUST NOT deploy a scanner that auto-executes while automatic analysis remains ON.

## 8. FND-26-R1-003 - Owner-controlled analysis state machine and rollback

States, each requiring an auditable evidence/Owner decision (NO transitions are executed by this document):

| State | Automatic Analysis | CI Scanner | Required gate evidence |
| --- | --- | --- | --- |
| S0 AUTO BASELINE | A0-observed ON, or current UNKNOWN until measured | ABSENT/OFF | Existing Sonar PR/master checks, required-check policy, project/region/token facts recorded. If mode unknown, HOLD in S0. |
| S1 STAGED / INERT | Remains ON if it was ON | Scanner implementation exists but is **DISABLED**, no token use and no invocation | A0 complete, A1 frozen/approved, A2 independently accepted at fixed HEAD; scanner job cannot be triggered yet. Exact enable/disable control and rollback tested without secret. |
| S2 CUTOVER IN PROGRESS | OFF, confirmed by authenticated admin at transition | Enabled for approved **master push only** | Owner explicitly accepts PR-check impact and authorizes switching; verify mode OFF *before* first real scanner invocation, token binding, required-check arrangements and in-flight scan status. Single controlled first run. |
| S3 CI ACCEPTED | OFF, confirmed | Master-only scanner ACTIVE | Verified scanner logs of generic report import, Sonar master revision/head match, real coverage metrics and denominator reconciliation, approved status-check policy, secret handling checks. |

- The S0->S1 transition is allowed only after A0 + A1 design approval and independently accepted **inert** A2 implementation. If A0 finds AUTO_OFF already, still prove scanner is absent/inert and record a state-specific transition decision; do not fake an AUTO_ON baseline.
- The S1->S2 transition requires a new, explicit Human Owner change approval and operator, change window, prior state, disable/enable mechanism, exact planned workflow trigger, expected Sonar checks, and restore decision. Owner/admin first verifies Automatic Analysis OFF, confirms scanner was previously inert, then enables the scanner. If confirmation cannot be obtained, **DO NOT enable scanner**.
- S2->S3 requires **proof of actual Sonar ingestion**, including scanner import sensor logs, correct report path/production source mapping, project ID/region, exact commit revision and nonempty meaningful Sonar master coverage measures. Offline 1212/1406 != automatically Sonar master coverage; document any scope/denominator difference. No mere green Quality Gate is sufficient.
- STOP from ANY state upon mismatched region/token, failed provenance, wrong run/producer/digest, archive hazard, unsafe fork execution, scanner invoked during automatic ON, missing data import, unauthorized settings, broken required check or expired credential. Upon STOP: first disable scanner dispatch and revoke/disable token as appropriate; cancel/drain in-flight CI scanner runs and obtain **no-scanner-active** evidence; never re-enable Automatic while a scanner can still run.
- RESTORE (R): with explicit Owner/admin decision, once scanners are provably disabled and no privileged scan remains running, restore only the recorded prior analysis method and check policy; verify fresh master/PR checks and their exact context names, and record rollback evidence. If prior method was UNKNOWN, rollback is BLOCKED until Owner establishes a safe target (no guessed automatic ON). Restoration failure -> SAFETY_STOP and Human Owner escalation, not repeated toggling.
- STOP in S1 or S0 does not authorize Sonar mode changes. STOP in S2 is not automatically rollback: it first fences scanner execution, then obtains approval for restore. Never allow parallel AUTO/CI operation in any intermediate or recovered state.

## 9. R1 limited correction register and current unresolved authority

| Finding | Reviewer severity | Proposed limited correction | Implementation status |
| --- | --- | --- | --- |
| FND-26-R1-001 | Moderate | A0 prerequisite -> A1 exact SHA/version/precedence Lock Record freeze -> A2 independent fixed-contract conformance | DRAFTED, INDEPENDENT R2 PENDING |
| FND-26-R1-002 | Moderate | Trusted GitHub run/job/artifact/digest binding, ZIP pre-extract isolated inspection, quotas, explicit self-attestation limitations | DRAFTED, INDEPENDENT R2 PENDING |
| FND-26-R1-003 | Moderate | S0/S1/S2/S3 + STOP/RESTORE, fenced scans and Owner-mediated cutover/rollback | DRAFTED, INDEPENDENT R2 PENDING |
| FND-26-R1-004 | Minor | Confirm Sonar plan/token availability; Team/Enterprise SOT vs Free PAT; fail closed if least privilege unavailable | DRAFTED, INDEPENDENT R2 PENDING |
| FND-26-R1-005 | Minor | A0 EU/US region, A1 scanner-specific sonar.region/host.url compatibility and precedence proof | DRAFTED, INDEPENDENT R2 PENDING |

None of these findings may be marked CLOSED by this implementer. This is a static design proposal, not executable scanner/ZIP-parser security proof, Sonar admin confirmation, or token authorization.

Remaining unverified: Analysis Method, region, subscription tier/token scope, full GitHub required checks, scanner/Action version and immutable SHAs, A1 signed Lock Record, independent R2, any scanner run or coverage import.

Verdict: R1_LIMITED_CORRECTIONS_DRAFTED / A0_MODE_CONFIRMATION_STOP / INDEPENDENT_R2_PENDING / NO_EXECUTION_GRANT.
SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED / G1_NOT_PROVEN / G2_NOT_VERIFIED remain enforced.
