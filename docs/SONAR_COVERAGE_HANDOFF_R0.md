# Issue #23 P1 - Offline Coverage Handoff R0

Status: OFFLINE_REPORT_ONLY / NO_SONAR_SCANNER / NO_ADMIN_CHANGE / NO_AWS_RUNTIME

## Data boundary

CI uses Python standard-library trace in Python 3.12 and converts only aws_cost_name_tagger_v3.cover into Sonar generic coverage v1 XML. The original Python source and each annotation line must match exactly, and invalid/empty/truncated inputs fail closed. The XML covers only aws_cost_name_tagger_v3.py. This is executed-line evidence, not branch or MC/DC coverage or proof of any security Gate.

The XML is staged in offline-line-coverage/sonar-generic-coverage.xml and included in the existing artifact. Its SHA-256 is recorded alongside trace-summary.txt and the .cover annotation in coverage-evidence.json, together with Git checkout HEAD and tree. No credentials or network are used to produce this local XML.

## Analysis method and controlled next step

No SonarScanner or sonar-project.properties exists on the current master; Sonar analyzes PRs automatically. This is consistent with automatic analysis, but the current project-level Analysis Method has NOT been verified by an authenticated Sonar administrator.

Sonar states that automatic analysis and CI-based scanners cannot run concurrently. Automatic analysis does not support coverage import. Switch to CI-based analysis only after Human Owner verifies the actual setting and approves the transition, rollback and security contract.

Scanner design must constrain SONAR_TOKEN to a trusted execution context, pin scanner version/host and action SHA, avoid leaking tokens via fork PRs or untrusted workflow_run, validate the report SHA/tree/path first, then set sonar.coverageReportPaths=offline-line-coverage/sonar-generic-coverage.xml. Do not use sonar.python.coverage.reportPaths for this generic format (that parameter expects Cobertura XML). Verify scanner logs and imported metrics after the authorized cutover.

Sources:
https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/ci-based-analysis/overview-of-integrated-cis
https://docs.sonarsource.com/sonarqube-cloud/analyzing-source-code/test-coverage/overview
https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/test-coverage/generic-test-data

STOP on source/trace mismatch, invalid XML, missing manifest entries, provenance/tree mismatch, or missing authorizations for Sonar analysis mode changes. SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED / G1_NOT_PROVEN / G2_NOT_VERIFIED remains in force.
