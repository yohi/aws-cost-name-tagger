# AWS Cost Name Tagger v3.6

[日本語](README.ja.md)

A read-only AWS cost analysis tool that proposes `Name` tags from CUR and resource metadata.

> **Safety Hold:** AWS tag writes are disabled. `run --mode y`, `apply`, and `Investigator.write_name()` do not modify AWS resources. Phase A's controlled Name workflow only prepares and verifies offline approvals and uses an in-memory fake for tests.

## Quick Start

Requirements: Python 3.10+, `uv`, and (for AWS read-only discovery) a compatible AWS CLI profile.

```bash
uv sync --locked
uv run --locked python aws_cost_name_tagger_v3.py run \
  --cur /path/to/aws-resource-cost-detail.csv.gz \
  --month 2026-10 --account 123456789012 \
  --profile read-only --login skip --mode dryrun \
  --output ./private-reports/plan.json
```

The default workflow produces a plan and review reports; it does not write tags. Use a private output directory. Existing output files are never overwritten.

## Controlled Name Workflow (Phase A)

The separate `name_tag_controlled.py` CLI supports these offline commands:

- `prepare-name`: create an unsigned payload bound to one proposed plan row.
- `verify-name`: verify a detached Owner signature packaged in an approval envelope.
- `prepare-execution`: prepare a separate, single-ARN execution authorization payload.
- `verify-execution`: verify the separate execution envelope.
- `initialize-ledger`: provision a new durable ledger locally as an administrator;
  it does not contact AWS.
- `simulate`: blocked unless invoked by an in-process test harness with the exact fake adapter.
- `execute-approved`: always returns `AWS_WRITE_BLOCKED` in Phase A.

Example payload preparation:

```bash
uv run --locked python name_tag_controlled.py prepare-name \
  --plan ./private-reports/plan.json --proposal-id proposal-1 \
  --approved-name web-prd-name --edit-reason "" \
  --owner-principal-id owner@example.test --owner-key-fingerprint SHA256:replace-me \
  --issued-at-utc 2026-11-16T12:00:00Z --expires-at-utc 2026-11-17T12:00:00Z \
  --decision-nonce nonce-1 --output ./private-reports/name-payload.json
```

The output file contains the exact canonical UTF-8 payload bytes, without a trailing newline. Owner signing and envelope assembly occur separately: sign those bytes in the Name namespace, then set `approval_id` to their SHA-256 digest and place the detached signature in the envelope. The CLI does not store Owner private keys. Signature verification requires a pre-enrolled, root-managed OwnerTrust configuration: `/etc/aws-cost-name-tagger/owner-trust.json` pins the SHA-256 of `/etc/aws-cost-name-tagger/allowed_signers` and maps Owner IDs/fingerprints to roles. Both files must be root-controlled; this CLI never creates or edits them. No Trust Anchor is enrolled by this Phase-A change, so verification fails closed with `BLOCKED_OWNER_AUTHN` until a separate Owner decision. No public-key, safety-disable, or production-stub override is accepted.

The trust config is a version-1 JSON object with exactly `schema_version`, `allowed_signers_sha256`, and `owners`. Each owner maps a fingerprint to `{"role":"...","revoked":false}` (the `revoked` member may be omitted). The allowed-signers file must contain matching Owner IDs, namespaces, and public keys. The CLI accepts no config path or key override.

### Provision the durable ledger

Before first use, an administrator must create the root-owned anchor directory
and a private ledger parent owned by the runtime UID. Replace `1001` and the
ledger path with the account and location used by the service:

```bash
sudo install -d -o root -g root -m 0755 /etc/aws-cost-name-tagger/ledger-anchors
sudo install -d -o 1001 -g 1001 -m 0700 /var/lib/aws-cost-name-tagger
sudo uv run --locked --no-build --no-sync python \
  name_tag_controlled.py initialize-ledger \
  --path /var/lib/aws-cost-name-tagger/ledger.db --runtime-uid 1001
```

The command requires root and creates the database for the specified runtime UID
plus a separate root-owned anchor. It is local-only: it makes no AWS API calls,
does not access AWS credentials, and does not change the Safety Hold.
`open_ledger` rejects a missing database, an existing empty or unanchored
database, a database file whose device/inode differs from its anchor, or a
mismatch between the database and its anchor with
`BLOCKED_SCOPE_STATE_UNKNOWN`. Restoring or moving a copied database to a new
file is not an automatic recovery path; it requires an explicit administrator
decision and new provisioning. The anchor does not detect in-place database
rewrites by the trusted runtime UID or rollback of the entire host storage.

The command refuses to adopt or overwrite an existing database or anchor. A
ledger created before this anchor requirement is enabled will fail closed; do
not delete or reprovision it as an automatic repair. If provisioning fails
after creating only one part, inspect the files and resolve the partial setup
deliberately before retrying; the command does not recover it automatically.

Phase A performs no AWS mutation, IAM change, Safety Hold removal, or credential lookup from `execute-approved`. Passing offline tests is not approval for Phase B or a real AWS write.

## Development

```bash
uv run --locked --no-build python -m unittest -q \
  test_name_tag_approval test_name_tag_review test_name_tag_scope \
  test_name_tag_ledger test_name_tag_execution test_name_tag_adapters \
  test_name_tag_controlled test_name_tag_ledger_anchor test_name_tag_ledger_provision \
  test_name_tag_ledger_open test_name_tag_ledger_cli test_aws_cost_name_tagger_v3
```

The test suite is offline and uses temporary OpenSSH keys, a local SQLite ledger, and fake adapters.

## Documentation

- [Japanese README and existing v3.6 operational details](README.ja.md)
- [Controlled Name write design](docs/superpowers/specs/2026-11-16-aws-cost-name-tagger-controlled-name-write-design.md)
- [Controlled Name write implementation plan](docs/superpowers/plans/2026-11-16-aws-cost-name-tagger-controlled-name-write.md)

## License

See [LICENSE](LICENSE).
