# Issue #23 P1 - SonarQube Cloud Coverage Cutover Contract R0

Date: 2026-10-26 JST
Reference master HEAD: 20d1fa9b7e11e10a120ff9afb00899485ea968c8
Reference master tree: 6ed0f39b96c0d86c12268d3ab84570bfcc8593f2
Status: DESIGN_ONLY / ANALYSIS_METHOD_UNVERIFIED / A0_CONFIRMATION_STOP / NO_SCANNER_OR_SECRET_CHANGE

## 1. Direct evidence versus unverified settings

VERIFIED:
- PR #25 merged. The unprivileged master CI (GitHub run 40296026980) emitted stdlib trace-based generic line coverage XML at `offline-line-coverage/sonar-generic-coverage.xml`. CI: Python 3.10/3.11/3.12, converter 28 tests each, app 168 tests x2 each, SHA manifest 14/14 each. Separate G2 run 40296026971: 110/110 x2. The master source tree is `6ed0f39b96c0d86c12268d3ab84570bfcc8593f2`.
- Offline generic XML SHA256: `71118fc8f0f281a6db1278635834b68a2ab9b82838ae2e715ed365ea5880d0cb`; 1212 hit / 1406 eligible lines (86.2% executed-line metric only, not branch or MC/DC).
- Repository CI has no SonarScanner invocation, SONAR_TOKEN, or sonar-project.properties. SonarCloud itself nonetheless analyzed master and PRs. Its public master measures did not provide a coverage percentage. GitHub master ruleset 25668708 contains PR required/non-fast-forward/deletion rules but no listed required-status-check rule; reading separate branch protection returned 403.

UNVERIFIED:
- SonarQube Cloud project Administration > Analysis Method actual setting (AUTO_ON, AUTO_OFF), project administrator identity/authority, organizational override, scanner secrets/tokens, branch protection status-check requirements, and fork PR policy.
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
- No scanner invoking a PR-supplied `sonar.properties`, `sonar-project.properties`, arbitrary server URL or unsigned/variable scanner. Host `https://sonarcloud.io` and project identifiers must be pinned in trusted execution, with precedence verified in review. Do not trust that environment variables override project files without checking the exact scanner version.
- Token scoped to this project, minimum necessary analysis permission, expiring and revocable, saved exclusively as a GitHub secret. Never paste token into GitHub issues, CI logs, documentation or this project repository.
- Immutable SHA pins for checkout, artifact download and scanner actions; validated scanner distribution/version. GitHub GITHUB_TOKEN permissions set to contents:read.
- Do not restore untrusted caches, invoke repository scripts or install project dependencies within a privileged scanning job. A scanner necessarily parses project source; parser vulnerabilities remain a residual risk.
- Fork pull requests are out of scope for privileged CI scanning until their independent secret/no-secret status strategy is reviewed.

## 3. Candidate first-release scanner architecture (NOT IMPLEMENTED)

Recommended initial scope: trusted master PUSH only, not PRs, forks or workflow_run. Keep the existing CI test matrix unprivileged. A separate scanner job may depend on all matrix tests in the SAME Safety Hold CI run, downloading the Python 3.12 artifact by its exact name after successful completion. No scanner code may be merged active until Gate A0/A1 approval.

The scanner job shall:
1. Run only on `github.event_name == 'push'`, `github.ref == 'refs/heads/master'` and `needs: offline-tests` success; never on a PR or fork.
2. Checkout the exact trusted GitHub master SHA with `persist-credentials: false` and `fetch-depth: 0`; ensure checkout SHA/tree equal the workflow run head and the coverage evidence tree.
3. Download artifact `offline-line-coverage-python-3-12` from the SAME workflow run, fail closed on missing/duplicate/unexpected files, symlinks or tampered paths; verify file bytes/SHA-256 against `coverage-evidence.json`, XML file identity, positive coverage rows and source revision. Use pinned, trusted validation code/inline logic not obtained from arbitrary PR artifacts.
4. Invoke the vetted pinned scanner action only after all validation. Provide `SONAR_TOKEN` ONLY to the scanner step. Pin project key `yohi_aws-cost-name-tagger`, organization `yohi` (both to be reconfirmed by admin), host `https://sonarcloud.io` and `sonar.coverageReportPaths=offline-line-coverage/sonar-generic-coverage.xml` from a trusted configuration.
5. Verify scanner log import of generic coverage, path mapping to `aws_cost_name_tagger_v3.py`, correct master revision and nonempty, interpretable Sonar coverage measures. A green Quality Gate alone is NOT proof of import.

Security tradeoff: master-only scanning intentionally does not replace SonarCloud PR analysis when automatic mode is disabled. The Human Owner must approve a temporary loss of PR analysis or commission a separate secure PR-scanning design, and review required-check policy before disabling Automatic Analysis.

Do not assume that turning off Automatic Analysis before scanner implementation or activating a scanner before turning it off is harmless. Sequence a controlled cutover with explicit STOP/rollback; do not operate both mechanisms together.

## 4. Gates and owner decision record

A0 / MODE CONFIRMATION - BLOCKING / HUMAN OWNER OR SONAR PROJECT ADMIN:
- Observe the authenticated project page Administration > Analysis Method. Record AUTO_ON/AUTO_OFF, observer, date/time, project key, available administrative privileges.
- Record Sonar master/PR Quality Gate and New Code definition, GitHub branch protection/ruleset required check names, whether fork PRs are permitted and must retain PR analysis.
- Record secret/token creation authority and agreed owner/expiry/scope. Do not create or reveal token at A0.
- Record yes/no approval for a master-only first release and its PR-analysis limitation.
- Until documented: `A0_MODE_CONFIRMATION_STOP`.

A1 / INDEPENDENT SECURITY DESIGN REVIEW - BLOCKING:
- Review exact action commit pins and scanner version, token-host precedence, trust boundary between unprivileged CI and privileged scanner, same-run artifact provenance/ZIP safety, and master-only trigger.
- Test/assess malicious fork PR configuration, forged artifacts, input paths, mismatched SHA/tree, absent report, old/expired token, automatic analysis still enabled, and loss of PR branch protection checks. No finding may be silently dismissed.

A2 / SEPARATE IMPLEMENTATION PR - OWNER AUTHORIZATION REQUIRED:
- Add and independently review scanner/config and validation only after A0/A1. Never merge an active scanner during Automatic Analysis ON. Build/review under fixed HEAD/tree with SHA256 Manifest, Safety Hold and G2 preserved.

A3 / CONTROLLED CUTOVER AND EVIDENCE ACCEPTANCE - OWNER AUTHORIZATION:
- Record prior analysis mode and rollback. Disable Automatic Analysis and activate CI-based scanner in an authorized sequence without concurrent analyses.
- Require scanner import logs, Sonar project revision, nonempty master imported coverage metrics and reconciliation to offline 1212/1406 including any denominator difference.
- Confirm Sonar PR checks are restored or explicitly deferred in the approved branch policy.
- On any STOP, prevent scanner/token exposure and follow Owner-approved rollback. Never equate coverage analytics with AWS write authorization.

## 5. Current findings and STOP

Owner/Admin-observed Analysis Method: UNKNOWN.
Current Sonar token scope/existence: UNKNOWN.
Full branch protection required-check status: UNKNOWN (API returned 403).
Trusted PR scanning strategy: NOT APPROVED.
Scanner action/CLI version: NOT SELECTED.
Security independent review: NOT STARTED.
Cloud CI coverage import: NOT ESTABLISHED.
Current design verdict: `DESIGN_R0_PREPARED / A0_MODE_CONFIRMATION_STOP / NO_EXECUTION_GRANT`.
AWS Gate invariants: `SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED / G1_NOT_PROVEN / G2_NOT_VERIFIED`.
