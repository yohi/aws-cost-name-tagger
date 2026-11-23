# Batch identity and population integrity

## Goal

Make Batch Plan identity projection, CUR selection/accounting, evidence validation, and CSV reporting preserve a consistent resource identity and selected population.

## Decisions

- Keep each resource's original CUR locator in the Plan record and proposal key unless a requirement explicitly changes it. Use the projected canonical ARN as the projection locator for API Gateway stages and RDS clusters.
- Normalize global-scope resources to their canonical target identity before thresholding and applying resource caps. Preserve rejection of actual duplicate post-projection identities. Population summaries must describe the selected records and amounts.
- Keep CUR source validation bounded by `MAX_COST_DIGITS`; permit intermediate/aggregate outputs up to `MAX_AGGREGATE_DIGITS`.
- Validate optional per-Kind population summaries against both their signed whole-population summaries and the actual Plan records' per-Kind counts and costs. Preserve existing overall signed population and selected-record checks.
- Snapshot Scope declarations accept only the accountless canonical snapshot ARN. Reject account-bearing legacy declarations; do not normalize or silently migrate them. Keep the canonical snapshot ARN accountless.
- A generated-name verifier may run only when the record locator identifies the same canonical target as the supplied target. Mismatch follows `NameEvidenceNotProven`.
- In Batch report mode, preserve an explicitly empty `resource_arn`; retain legacy ARN derivation only for non-Batch reports.

## Behavior and boundaries

1. **Identity projection:** API Gateway's composite CUR locator is replaced in the Plan record by its verified projected ARN before `proposal_key()` is computed. For RDS clusters, pass the ARN to the projection function without changing the record's CUR locator. The CSV `resource_id` remains the record locator.
2. **Global selection:** Canonicalize global-scope identities before building selection keys so regional variants of one S3 bucket participate in one threshold and cap decision. Keep candidate selection and population totals internally consistent; continue to fail if distinct records collide after projection.
3. **Exact monetary validation:** Do not validate aggregate sums as though each were an original CUR input. Apply aggregate digit/scale bounds to computed sums while retaining strict source input limits.
4. **Population validation:** Validate per-Kind `lookup_selected` counts and costs against records, in addition to existing conservation and whole-plan record checks. Missing historical optional per-Kind data retains its existing compatibility behavior.
5. **Snapshot Scope compatibility:** Account-bearing snapshot declarations are rejected by whole-Plan declaration validation; accountless canonical declarations remain accepted. Tests cover both.
6. **Name evidence:** Check locator/target agreement before invoking the Kind verifier; keep the existing rejection type and path.
7. **Reports:** A Batch report must not reconstruct an ARN when a rejected projection explicitly stored an empty value. Non-Batch report fallback behavior is unchanged.

## Tests and acceptance

- Add regression tests for each behavior above, including global S3 regional aliases under the threshold and cap, and actual post-projection collisions.
- Exercise aggregate totals that exceed the CUR input digit limit but remain within the aggregate limit, and reject aggregate totals beyond that bound.
- Verify per-Kind record count/cost mismatches are rejected while existing full-population checks remain effective.
- Verify accountless snapshot declarations are accepted and account-bearing legacy forms are rejected.
- Run targeted tests for the touched modules, then the repository's full test suite and configured quality checks available in this environment.
- Do not run reviewer-supplied commands or send code to external review services as part of this change unless separately authorized.
