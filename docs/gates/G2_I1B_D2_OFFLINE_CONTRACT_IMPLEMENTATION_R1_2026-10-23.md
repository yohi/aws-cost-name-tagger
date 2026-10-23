# G2-I1-B D2 — Offline Synthetic Contract Implementation R1

**Date:** 2026-10-23 JST  
**Base:** master `3362af4b5c43a668123fbee53b8339ecd3061a7d` (PR #7 merged)  
**Branch:** `feature/g2-i1b-d2-offline-contract` / PR #8  
**Disposition:** `OFFLINE_CONTRACT_IMPLEMENTED / FRESH_INDEPENDENT_CODE_REVIEW_PENDING`.  
**Owner AWS Execution Authorization:** NOT_GRANTED. **G1:** NOT PROVEN. **G2:** NOT VERIFIED. **AWS WRITE:** BLOCKED.

## 1. What is actually implemented

- `g2_d2_saes.py` — In-memory single-Grant **synthetic** authority and egress sequencer. A fixed `SyntheticTransport` increments a counter without creating sockets, SDK clients, real HTTP requests, or credentials. Models `SEND_REQUESTED`/`SEND_ADMITTED`/`SEND_INTENT`/`SEND_STARTED`, cancellation, `REVOKE_COMMITTED` and `REVOKE_ACK_SUCCESS`; rejects replay, wrong plan/context/gateway, expiry and exhausted synthetic send budget.
- `test_g2_d2_saes.py` — deterministic trusted `threading.Event` barriers at both post-admission/pre-send and post-send-start. Race outcomes: cancellation before byte start → synthetic send count 0; send start before cancellation → revert ACK waits for egress sequencer. Throttled request then revocation → retry send count 0. Gateway fencing uncertainty → `CANCEL_PENDING` and no success ACK; crash before/after simulated send evidence → `SEND_OUTCOME_UNKNOWN` and auto-resume blocked.
- `g2_d2_rcp.py` — fully synthetic JSON-builtin-only `ActionEvaluation` / `ResourceEvaluation[]`. Inputs contain SAR Resource Type `REQUIRED|OPTIONAL` annotations, evidence-backed expected Resource sets, canonical per-resource evaluation IDs and typed RCP exclusions. Output retains each Resource's `rcp_resource_coverage` and parent `aggregate_coverage`. An incomplete/duplicate/mismatched set or unknown result dominates aggregate as `UNKNOWN`.
- `test_g2_d2_rcp.py` — expected-count/source evidence, duplicate ARN/type, duplicate index, empty expected collection, missing SAR attribute, KMS AWS-managed key vs customer managed key, `kms:RetireGrant`, service-linked role, management-account resource and unsupported Action/Resource coverage counterexamples. The exception's source URL, SHA256, timestamp and evidence ID must be present for a synthetic exclusion to be accepted.
- `g2_static_guard.py` and `test_g2_static_guard.py` — fixed four-file AST scan; execution code is not allowed to import boto3/botocore, socket, HTTP clients, subprocesses or dynamic-import paths.
- `.github/workflows/g2-offline.yml` — old I0/I1 tests plus both new D2 test modules, both **normal** and **Docker --network none --read-only** runs.

**R4-OBS-001 D2 schema resolution:** `OWNER_UNKNOWN` is a defined exception code; the Action-level SAR type list retains required/optional and SAR source IDs; expected count is checked against the explicit bounded, evidence-backed expected set; duplicates and incomplete sets yield UNKNOWN. This is a **synthetic schema correction**, not a real SAR acquisition proof.

## 2. What the passing D2 tests can and cannot show

| Obligation | D2 result | Critical limitation |
|---|---|---|
| SAES in-memory event ordering | Can be tested with deterministic synthetic barriers | No real distributed consensus, no OS socket serialization |
| Cancel-before-start → no synthetic send | Can be tested | A local Event is not an authenticated Owner cancellation signal |
| Send-before-cancel → ACK waits | Can be tested under one in-process reentrant lock | No durable authority or Gateway crash fencing proof |
| SDK retries / physical HTTP send | **NOT_IMPLEMENTED** | SyntheticTransport has zero AWS/HTTP capability; no Botocore implementation |
| Durable SEND_INTENT / SEND_STARTED ledger | **NOT_PROVEN** | In-memory records are explicitly `SYNTHETIC_IN_MEMORY_NOT_DURABLE` |
| Crash gap / SEND_OUTCOME_UNKNOWN | Synthetic state modeled | No actual process/host crash and no persistent recovery journal |
| Resource-level RCP with UNKNOWN priority | Can be tested with synthetic fixtures | No live Service Authorization Reference download or effective IAM decision |
| Official RCP exception source | Synthetic source-shape validated | Synthetic URLs/hashes are fixture values, not real independent official-source verification |
| G2 real evidence completeness | **NOT_EXECUTED** | No AWS calls, no account coverage, no RAW acquisition |
| Strict runtime revocation | **NOT_PROVEN** | No Botocore/TLS/OS end-to-end mediation or egress fencing |

The `SAES` implementation is **not** a production Grant Authority or network transport. In particular, it uses `threading.RLock` and `threading.Event` for a controlled *single-process model*. It does not prove that sending the first HTTP byte, cancellation's durable linearization point, distributed Gateway fencing, or Owner success ACK can be made atomic in a real environment. For the later runtime phase, design approval, network isolation, TLS/SDK adapter selection, durable/replicated ordering, replay prevention and independent adversarial runtime tests remain mandatory.

## 3. Safety and design dependencies

- **No AWS execution path introduced.** Existing `apply()` and `write_name()` Safety Hold unchanged. No AWS SDK client, profile, credential adapter, sts identity call, Secret retrieval or network access in D2 modules.
- **No direct D2 integration with I1 FixturePort.** The previously reviewed I1 fixture pipeline is separate; D2 accepts exact builtin JSON data for RCP and exact synthetic transport/attempt objects for SAES.
- **No real authorization claims.** Fields `g2_gate="NOT_VERIFIED"`, `effective_write_reachability="UNKNOWN"` and `provenance="SYNTHETIC_FIXTURE_ONLY"` are immutable result labels; offline PASS never raises G2 to VERIFIED.
- **No implicit resumption.** A synthetic crash creates outcome UNKNOWN and blocks the old Grant. Real restart/replay semantics remain a future implementation and independent review responsibility.
- **Restricted CI:** Network-disabled Docker tests are additional evidence of the CI command's network isolation; they cannot prove no network capability in every host/container configuration.

## 4. D2 acceptance and independent review request

1. Fix and review all failures of the checked-in offline test suite, shared static guard and Docker network-none run on a **fixed PR HEAD**.
2. Reassess whether the deterministic pre-start and post-start barriers actually distinguish cancellation-versus-send outcomes and whether the ledger's event order is coherent.
3. Validate every R4-OBS-001 schema field, expected set closure, unknown propagation and AWS managed KMS / `kms:RetireGrant` synthetic exceptions. Confirm no unsupported generic Resource coverage promotion.
4. Audit the trusted fixture boundary: no arbitrary Python object execution, SDK or network access; no real AWS credentials in CI. Flag any deceptive `PROVEN` interpretation of synthetic in-memory behavior.
5. Identify remaining gaps separating a runnable real AWS Collector from the current code: durable SAES and gateway fencing, authentic Owner revocation, TLS/OS send mediation, exception source authenticity, raw evidence custody and scope closure.
6. Reviewer judgment: `LIMITED_PASS_OFFLINE_CONTRACT` or `REVISION_REQUIRED`, **never Runtime PROVEN or OWNER AUTHORIZED**.

**Final fixed status:** D2 offline work does not alter `G1 NOT PROVEN / G2 NOT VERIFIED / AWS EVIDENCE ACQUISITION NOT EXECUTED / OWNER EXECUTION NOT GRANTED / AWS WRITE BLOCKED`.
