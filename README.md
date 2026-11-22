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

## Batch Plan and Owner Review (Offline Execution Held)

`aws_cost_name_tagger_v3.py batch-plan` uses the bounded CUR scan and existing
read-only metadata resolver to produce a Batch Plan v3 and its 14-column review
CSV. Unlike the Phase A Plan path, this Batch-only path retains exact decimal CUR
totals, records pre-cap population counts, and treats `WHITESPACE_ONLY` as a
candidate without changing Phase A Name behavior. The command accepts a local
Scope-declaration JSON document; those declarations are signed intent only and
do not prove a registered runtime Scope:

```bash
uv run --locked python aws_cost_name_tagger_v3.py batch-plan \
  --cur /path/to/aws-resource-cost-detail.csv.gz \
  --month 2026-10 --account 123456789012 --profile read-only \
  --scope-declarations ./private-reports/scope-declarations.json \
  --output ./private-reports/batch-plan.json
```

The Owner edits only the `approved` CSV column. `name_tag_controlled.py` exposes
`prepare-batch`, `batch-dryrun`, and `verify-batch` for unsigned payload creation,
row-level unsigned preview, and protected Owner signature verification. The
verified report remains non-executing (`execution_allowed=false`).
`batch-simulate` is synthetic-only: it creates a new, isolated fixture Ledger,
refuses an existing Ledger path, uses only the in-memory fake adapter, and marks
its report `execution_allowed=false`. It never opens the host-bound Ledger or
contacts AWS/STS. No Batch command enables AWS writes or lifts the Safety Hold.

### Offline versus live authorization

Offline commands (`prepare-batch`, `batch-dryrun`, `verify-batch`,
`batch-simulate`) only read local files, verify signatures, or use an isolated
fixture Ledger. They never connect to the Host service or AWS.

`name_tag_batch_cli.py batch-live` is only an untrusted local client of the
protected Host service. It requires `--live-opt-in`, the exact Plan, review CSV
and signed Batch envelope, and a new private `--report-out` file:

```bash
uv run --locked --no-build python name_tag_batch_cli.py batch-live \
  --plan plan.json --review review.csv --envelope batch-envelope.json \
  --report-out live-summary.json --live-opt-in
```

The client sends the exact bytes once over the fixed socket
`/run/aws-cnt/host.sock` (IPC v1) and reads one reply on the same connection.
It has no socket, Host runtime, grant, row, subset, policy or request-id option,
and it ignores environment variables. It never verifies the Owner, opens the
Ledger, or creates STS/SDK clients. `--live-opt-in`, local UID, `SO_PEERCRED`
and socket permissions do not grant authority. Only the Host service decides,
after it re-verifies current OwnerTrust, Scope, IAM, G1/G2 and Ledger state.

The client never retries or reconnects. Read the reply status as follows:

- `COMPLETE`: the accepted command reached a verified durable Host report. It
  does not mean that every row was applied.
- `BLOCKED`: the Host refused the command or could not continue safely, or the
  socket is missing. Earlier rows may already be `APPLIED_VERIFIED`.
- `UNKNOWN`: the outcome or reply could not be established (timeout, lost or
  partial reply). Writes may have happened. Do not resubmit.

`--report-out` holds only a bounded local summary (`status`, `code`,
`batch_id`, `report_sha256`). It is not the Host report and is never used for
recovery. A repeated command for the same Batch, even with a new request ID,
gets no second send from the Host Ledger.

Manual STOP: the CLI cannot stop, resume or alter a Batch. To stop work, stop
the protected Host service (`aws-cnt-batch.service`) as an administrator; any
post-Permit outcome that is not durably known is kept as `OUTCOME_UNKNOWN` with
Batch STOP and Scope HOLD and is never replayed.

### Report recovery after UNKNOWN

Never resubmit `batch-live` after `UNKNOWN`. A root-controlled local
administrator runs the read-only reader instead:

```bash
uv run --locked --no-build python name_tag_batch_report_reader.py \
  --plan plan.json --review review.csv --envelope batch-envelope.json \
  --read-authorization report-read.json --report-out owner-report.json
```

1. The Owner signs a fresh Batch-scoped read authorization in the namespace
   `aws-cost-name-tagger-batch-report-read-v1`. Its payload is created with
   `prepare_report_read_authorization()`, is valid for at most 15 minutes and
   names the `batch_id` from the original signed envelope. Set
   `expected_report_sha256` to the reply digest, or `null` if the reply was
   lost.
2. The reader checks that signature against the current OwnerTrust, role
   (`batch-approver`) and revocation. The Owner key must be enrolled for this
   namespace in the root-managed allowed-signers file. It also re-verifies the
   original Batch envelope. Namespace separation relies on the
   allowed-signers `namespaces=` option: an Owner line without it accepts
   signatures in any namespace, so give every Owner line an explicit
   `namespaces="..."` list.
3. It finds the Host StateDirectory from the root-pinned Host manifest, reads
   `batch-reports/<batch_id>/index.json`, and opens only the report that index
   names. It checks the exact stored-bytes digest, the embedded Batch ID and the
   signed Plan/CSV digests.
4. It writes a new private (`0600`) Owner report with per-row durable outcomes,
   attempts and cap, Batch state, refusal reason, and earlier
   `APPLIED_VERIFIED` rows. If the report is missing or does not match, the
   result is `NOT_VERIFIED` with the protected Ledger status when available. It
   never infers zero writes.

The reader performs no STS, Intent, Permit or write, opens no socket and never
uses a caller-chosen file path.

Two implementation details differ from the wording of Design R0.1.2. The
Design text is Owner-adopted and is not revised here:

- Host reports are stored under the root-pinned StateDirectory as
  `<StateDirectory>/batch-reports/<batch_id>/<report_sha256>.json`, with
  `batch-reports/<batch_id>/index.json` naming the current report. The Design
  mentions `/var/lib/aws-cnt/reports`.
- `report_sha256` is a domain-separated SHA-256 over the exact stored bytes:
  `SHA-256("aws-cnt-host-batch-report-v1" || 0x00 || stored_bytes)`. It is
  not a plain SHA-256 of the file.

A repeated command for the same Batch rewrites `index.json` to name the newest
report. Verifying an older report with its digest then gives `NOT_VERIFIED`.
This fails safe and is not changed in this phase.

### 18-Kind capability coverage report

Unsigned previews, Owner-verified reports and Host reports include
`kind_capability_coverage`. It covers all 18 Registry Kinds in Registry order,
and each Kind reports two separate axes:

- Capability: `IMPLEMENTED_OFFLINE`, `LIVE_GATE_PENDING`,
  `CAPABILITY_NOT_PROVEN`, `UNSUPPORTED_API` or `UNSUPPORTED_BY_POLICY`, with
  its reason code and any offline dispatch block. For example, S3 is never
  dispatchable because tag-set replacement is unproven, and API Gateway is
  blocked because its IAM condition is unproven.
- Outcome: the exact count and Decimal cost of the Kind's selected rows by
  outcome. Each row is counted once.

Kind pre-cap counts and costs come only from the signed Plan v3 field
`cur_population_by_kind`. The stages are `cur_recognized`, `below_min_cost`,
`above_min_cost`, `lookup_selected` and `max_resources_not_inspected`. They
must reconcile exactly with `cur_population` and with the selected records.

- A historical signed Plan without the field reports
  `PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE`. It is never filled with zeros.
- A forged operation, or an attempt outcome on a row that cannot be signed,
  rejects the whole report. Such a row is never reported as an unsupported
  skip.
- `live_acceptance` is always `NOT_RUN`. A Fake or offline success is not live
  acceptance.

Only `volume` is `IMPLEMENTED_OFFLINE` in the production Registry. The other
17 Kinds remain `CAPABILITY_NOT_PROVEN`. Tests promote `instance` or `lambda`
only through test-only fixtures.

### Safety gates still held

`SAFETY_HOLD_ACTIVE`, `AWS_WRITE_BLOCKED`, `G1_NOT_PROVEN`, `G2_NOT_VERIFIED`
and `AWS_RUNTIME_NOT_AUTHORIZED` stay in effect. In this phase the Host
listener, endpoint and report reader production wiring fail closed with
`AWS_RUNTIME_NOT_AUTHORIZED`, and no Host service is installed. Passing offline
tests is not approval for a live write.

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
The anchor file is mode `0640` and group-readable by the runtime UID's primary
group; it is not world-readable.
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
  test_name_tag_ledger_open test_name_tag_ledger_cli \
  test_name_tag_batch_population test_name_tag_batch_state test_name_tag_batch_approval \
  test_name_tag_batch_trust test_name_tag_batch_ledger test_name_tag_batch_iam \
  test_name_tag_batch_executor test_name_tag_batch_report test_name_tag_batch_cli \
  test_name_tag_batch_migration \
  test_aws_cost_name_tagger_v3
```

The test suite is offline and uses temporary OpenSSH keys, a local SQLite ledger, and fake adapters.

## Documentation

- [Japanese README and existing v3.6 operational details](README.ja.md)
- [Controlled Name write design](docs/superpowers/specs/2026-11-16-aws-cost-name-tagger-controlled-name-write-design.md)
- [Controlled Name write implementation plan](docs/superpowers/plans/2026-11-16-aws-cost-name-tagger-controlled-name-write.md)

## License

See [LICENSE](LICENSE).
