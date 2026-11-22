# AWS Cost Name Tagger — Production Runtime Completion Design R0.1.2

- Date: 2026-11-21 (JST)
- Limited remediation: 2026-11-22 (JST), RG-PRC-001…004 and PLAN-001…004; PLAN-004 remaining IPC contract specified after commit `29afd5f48e63ad3d0191c5c96f0bd469c66dcdf6` (PLAN-004 IPC contract committed in this document update)
- Repository: `yohi/aws-cost-name-tagger`
- Base: `master@bffc5d97e5ccd53bc094785bcda70476b2be2fd7`
- Status: **PROPOSED — Human Owner Design Approval Pending**
- Development: Superpowers First / TDD / Single Implementation Phase
- Authority: Brainstormingの設計案。文書のCommit・Pushは設計採択、実装、AWS操作、Safety Hold解除の承認ではない。

## 1. Project Goal

AWS CURで認識する課金対象リソースについて、既存の意味あるNameタグを保護しながら、サービスごとの安全条件を満たす範囲で、実際のNameタグ付与を可能にする。

対象18種類すべてについて、書き込み対応可否を根拠付きで判定する。安全な書き込みを成立させられない種別については、無理に対応させず、理由・対象件数・費用を報告する。

最終GOALは安全な実AWSタグ付与であり、コードやオフラインテストの完成だけで達成とは扱わない。

## 2. Scope

対象種別:

- EC2: `instance`, `volume`, `snapshot`, `eni`, `eip`, `nat`, `endpoint`
- データベース: `rds_cluster`, `rds_instance`
- その他: `opensearch`, `elbv2`, `apigw_stage`, `cloudfront`, `athena_workgroup`, `log_group`, `lambda`, `wafv2`, `s3_bucket`

今回の工程は、本番用コード、実行時安全ゲート、CLI、レポート、オフライン統合テストまでを含む。

実Hostでの運用受入、実STS発行、実IAM変更、実AWSへの書き込みは含まない。Phase A、Batch Tasks 1–7の既存安全契約を維持する。

## 3. Approaches and Selected Architecture

**選択：A — Capability Registry方式。** 18種類それぞれのAPI、IAM制約、Name保護、Readbackを宣言し、共通Runtimeから実行する。共通のOwner認証・STS・Ledger・G1/G2安全機構を再実装せず、対応不能・未検証の理由を明示できるため採用。

比較した代替案:

- B — Resource Groups Tagging API優先方式: 共通化しやすいが、実際のサービス対応、サービス固有IAM権限、副作用の判定が複雑。
- C — サービス別独立Writer方式: 局所的には明快だが、認証・Ledger・STSの重複が増える。

```text
CUR Discovery
    ↓
Batch Plan / Review CSV
    ↓
Owner Signature / Verification
    ↓
Host-only Batch Runtime
    ├── OwnerTrust
    ├── Scope / SideEffect Evidence
    ├── Host-bound Ledger / Permit
    ├── Credential Issuer
    └── Runtime Policy Gate
              ↓
       Kind Capability Registry
              ↓
      ┌───────┴────────┐
      │                │
 Supported Adapter   Unsupported / Unverified
      │                │
 Pre-send Read       Reason + Count + Cost
      ↓
 Consume Permit
      ↓
 Single Name-only Write
      ↓
 Readback / Durable Outcome
      ↓
 Batch Report
```

## 4. Kind Capability Registry

18種類すべてについて、以下の情報を持つRegistryを実装する。

- Kindとサービス識別子
- ARN形式とAccount / Partition / Region検証規則
- 対象リソースの識別方法
- Pre-send Read API
- Nameタグ書き込みAPI
- Readback API
- IAM write action
- IAM resource ARN制約
- `Name`以外のタグ変更を禁止できる条件
- APIが単一タグ更新か、タグ集合置換か
- 必要な証拠と残余リスク
- 書き込み対応状態と理由コード

Capability状態:

- `IMPLEMENTED_OFFLINE`: 書き込み契約とMockテストが完成。実AWS許可ではない。
- `UNSUPPORTED_BY_POLICY`: プロジェクトの安全条件に適合しない。
- `UNSUPPORTED_API`: 対応する安全なAPIがない。
- `CAPABILITY_NOT_PROVEN`: API/IAM/副作用の証拠不足。不可能と断定しない。
- `LIVE_GATE_PENDING`: コード実装済みだが実環境の承認・証拠が不足。

不明と不可能、コード実装済みと運用許可済みを混同しない。

Native APIを原則とし、Resource Groups Tagging APIは、サービス固有権限を含め安全条件を証明できる場合に限って採用する。

Capabilityの存在だけで書き込みを許可しない。

S3旧`PutBucketTagging`のようにタグ集合全体を置換するAPIについては、他のタグを変更しないことを保証できなければ、書き込み禁止とする。Read→Merge→Writeだけで原子的な既存タグ保護が成立するとは見なさない。

### 4.1 Canonical identity and independent Scope proof — RG-PRC-001

**Do not weaken the existing signed objects.** Existing Batch Plan `schema_version=3`, `scope_declarations=[{writer_control_scope_id,account,partition,region,resource_arns}]`, 14-column UTF-8-BOM review CSV, `BatchApprovalV1`, `approved_rows_sha256` and `VerifiedBatchRowAuthority` remain unchanged. Every exact canonical target ARN belongs to exactly one signed Scope declaration. The declaration `region` stays **nonempty** and represents the *scope placement* rather than a claim that all ARN region components are nonempty; its value is `global` for an explicitly global kind. Plan identity `(account,partition,scope_region,resource_arn)` and every approved row remain immutable after signing. An older Volume-only signed Batch gains no new authority by installing this registry.

Introduce an **internal deterministic, versioned `KindIdentityRule`** selected by the immutable Plan kind; no new editable Plan/CSV input and no wildcard ARN normalization. Its output is:

```python
@dataclass(frozen=True)
class CanonicalTargetIdentity:
    kind: str
    locator: str
    resource_arn: str         # exact API/IAM canonical ARN, never a wildcard
    partition: str
    owner_account: str        # signed intended account at syntax time; Host MUST prove ownership
    scope_region: str         # nonempty: actual region or literal 'global'
    arn_region: str           # may be empty only for explicitly enumerated rules
    arn_account: str          # may be empty only for explicitly enumerated rules
    ownership_proof_ref: str  # absent during syntax-only admission; Host verifier owns the live reference
```

Separate **syntactic** admission (deterministic canonical identity + unique signed declaration) from **independent runtime** attestation (ownership, region/endpoint, same ARN, ScopeEvidence and protected Ledger `CLEARED`). The syntactic stage verifies every `scope_declaration.account` equals signed Plan account and every `scope_declaration.region` equals `scope_region`; it **must not** claim proof merely because a signed row contains that account. Runtime proof checks exact `(kind, locator, ARN, partition, owner_account, scope_region, writer_control_scope_id)`, the protected owner's identity, current controlled ARN membership, Scope validity, SideEffect digest, and Ledger state at admission and again before the Permit is consumed. Proof cannot come solely from CUR, the Plan, a client argument, or `GetCallerIdentity`.

Mandatory nonregional/accountless ARN rules (regional account-qualified kinds keep strict equality by default):

| Kind | Canonical ARN shape | Signed scope region | Ownership/endpoint requirement |
|---|---|---|---|
| `cloudfront` | `arn:{P}:cloudfront::{A}:distribution/{Id}` | `global` | ARN account must match signed `{A}`; independently obtain protected, account-bound distribution identity evidence using the appropriate global CloudFront endpoint. Do not treat the blank ARN region as a mismatch or as a wildcard. |
| `s3_bucket` (general purpose) | `arn:{P}:s3:::{Bucket}` | `global` | Neither ARN region nor account encodes ownership. Independently attest exact bucket-owner account (e.g. owner-scoped inventory evidence, **not** merely account supplied to an API), actual bucket region and correct S3 Control endpoint; bind both to the protected Scope and signed Plan account. No confirmed owner => block. |
| `snapshot` | `arn:{P}:ec2:{R}::snapshot/{SnapshotId}` where the EC2 API/policy requires the accountless snapshot ARN | `{R}` | Explicit kind exception for accountless ARN only, with snapshot-owner/region evidence from a trusted Host read. Never infer ownership from blank account. If the required format or proof differs by partition/API, `CAPABILITY_NOT_PROVEN`. |
| `apigw_stage` | `arn:{P}:apigateway:{R}::/restapis/{ApiId}/stages/{Stage}` | `{R}` | Accountless API Gateway management ARN; bind API/Stage ownership to the signed account with independent Host evidence, not ARN syntax. |
| `wafv2` | `arn:{P}:wafv2:{R}:{A}:{regional\|global}/webacl/{Name}/{Id}` | the rule's actual `{R}` | Global CloudFront-scope WAFv2 is addressed via the appropriate regional endpoint (normally `us-east-1` in `aws`); do not replace its ARN region with `global`. Validate Scope field and WAF Scope (`REGIONAL`/`CLOUDFRONT`) separately. |

The complete registry must specify remaining kinds' exact canonical ARN grammar and normalization, not accept a generic `split(':')` or caller-supplied Region fallback. For EC2, IDs (including allocation IDs) are parsed to their own ARN resource type, never guessed from CUR service name. ARN equality is byte-exact after **one** deterministic pre-sign projection; aliases are rejected instead of silently rewritten. Cross-account values, duplicate Scope ownership, unknown global/region mapping, different buckets sharing ambiguous identities, unresolved snapshots and unproven endpoint ownership return `BLOCKED_SCOPE_MISMATCH` / `BLOCKED_SCOPE_STATE_UNKNOWN` / `CAPABILITY_NOT_PROVEN` with **zero Intent / Permit / Write**. A supported shape is not itself permission to write.

### 4.1.1 Deterministic pre-sign target projection — Finding 001

**The Registry is connected to `plan_batch()` before signing, not solely to IAM/Adapter dispatch.** For each CUR candidate, keep the existing CUR kind/locator/region and cost aggregation as raw discovery inputs. After bounded read-only `Investigator.resolve()`, but **before** `proposal_key()`, final `resource_arn`, `aws_operation`, CSV projection, signed Scope matching or Plan serialization, call the versioned Registry to deterministically obtain the one canonical target identity and *supported* operation. This is a single pre-sign projection; nothing may rewrite the signed Plan, row region, ARN or operation later. Define the internal contract:

```python
@dataclass(frozen=True)
class PreSignKindTarget:
    identity: CanonicalTargetIdentity
    aws_operation: str | None   # None unless API/IAM/Name evidence is vetted for approved-row admission
    capability_status: str
    reason_code: str

def project_pre_sign_kind_target(*, kind: str, locator: str,
                                 discovered_region: str, discovered_arn: str | None,
                                 partition: str, account: str,
                                 evidence: str, proposed_name: str | None
                                 ) -> PreSignKindTarget: ...
```

The projection sets `record['resource_arn'] = identity.resource_arn`, `record['region'] = identity.scope_region`, and `record['aws_operation'] = aws_operation` **before** `proposal_key(record)` and signed Plan generation. The initial `aws_operation=None` for unproven/unsupported kinds remains a valid **unapproved Preview** state; it never yields an approved `VerifiedBatchRowAuthority`. Once a non-Volume kind's Name evidence, API/IAM contract and account/Scope ownership rules are genuinely proven, the Registry provides the *only* supported operation for signing (not an undocumented candidate). A signed legacy Volume Plan is not reprojected on readback or verification. No editable CSV columns are added.

The projection's nonregional/accountless cases are exact: `snapshot` accountless EC2 snapshot ARN only if proven by the designated rule and independent owner evidence; `s3_bucket` and `cloudfront` signed `scope_region='global'` with their respective accountless/account-qualified regionless ARN; WAFv2 `CLOUDFRONT` ARN retains the actual regional ARN component/endpoint (typically `us-east-1`), while REGIONAL WAF uses its regional ARN. Uncertain account, endpoint, original ARN/locator ambiguity or conflicting scoped identities are rejected or reported `CAPABILITY_NOT_PROVEN` **without approval**. The newly projected row must match exactly one predeclared signed Scope; do not create a Scope from untrusted CUR text.

**Non-Volume vertical test:** use an independent Fake and a demonstrably validated eligible kind (for example a vetted `instance` with deterministic Name evidence and per-resource IAM constraints): `cur_candidates_batch` → `plan_batch` (canonical ARN, region, operation) → immutable Plan v3 and 14-column CSV → Owner signature verification → `VerifiedBatchRowAuthority` → Kind IAM policy → vetted Adapter. Negative tests cover candidate operation with CNP evidence, mutated signed ARN/Region/operation, duplicate Scope, and cross-account target. Fake acceptance does not authorize AWS.

### 4.2 Kind-level API candidate decision register — RG-PRC-002

This is an explicit **candidate register**, not a claim that all candidate IAM conditions have been proven. API call spelling follows AWS SDK's snake_case model operation naming; arguments are the *security-critical minimum*, and all output-derived identity and Name tags require strict validation. `R` = Pre-send Read and identical-session Readback. Every `W` is a **single Name-key request**; service API `*Tags*` methods may overwrite the value **for `Name`**, but may not alter other tag keys. Exception: tagged-set **replacement** APIs are disallowed. Additional mandatory identity verification API is shown where relevant.

| Kind (service client) | Resource identity / ARN form (P, R, A = partition, region, account) | R (same SDK client credentials) | W SDK operation / minimum request shape |
|---|---|---|---|
| `instance` (`ec2`) | `arn:{P}:ec2:{R}:{A}:instance/{i-*}` | `describe_instances(InstanceIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `volume` (`ec2`) | `arn:{P}:ec2:{R}:{A}:volume/{vol-*}` | `describe_volumes(VolumeIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `snapshot` (`ec2`) | `arn:{P}:ec2:{R}::snapshot/{snap-*}` — special owner proof | `describe_snapshots(SnapshotIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `eni` (`ec2`) | `arn:{P}:ec2:{R}:{A}:network-interface/{eni-*}` | `describe_network_interfaces(NetworkInterfaceIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `eip` (`ec2`) | `arn:{P}:ec2:{R}:{A}:elastic-ip/{eipalloc-*}` | `describe_addresses(AllocationIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `nat` (`ec2`) | `arn:{P}:ec2:{R}:{A}:natgateway/{nat-*}` | `describe_nat_gateways(NatGatewayIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `endpoint` (`ec2`) | `arn:{P}:ec2:{R}:{A}:vpc-endpoint/{vpce-*}` | `describe_vpc_endpoints(VpcEndpointIds=[id])` | `create_tags(Resources=[id],Tags=[{Key:'Name',Value:name}])` |
| `rds_cluster` (`rds`) | `arn:{P}:rds:{R}:{A}:cluster:{Id}` | `describe_db_clusters(DBClusterIdentifier=id)` + `list_tags_for_resource(ResourceName=arn)` | `add_tags_to_resource(ResourceName=arn,Tags=[{Key:'Name',Value:name}])` |
| `rds_instance` (`rds`) | `arn:{P}:rds:{R}:{A}:db:{Id}` | `describe_db_instances(DBInstanceIdentifier=id)` + `list_tags_for_resource(ResourceName=arn)` | `add_tags_to_resource(ResourceName=arn,Tags=[{Key:'Name',Value:name}])` |
| `opensearch` (`opensearch`, legacy `es`) | `arn:{P}:es:{R}:{A}:domain/{Name}` | `describe_domain(DomainName=name)` + `list_tags(ARN=arn)` | `add_tags(ARN=arn,TagList=[{Key:'Name',Value:name}])` |
| `elbv2` (`elbv2`) | `arn:{P}:elasticloadbalancing:{R}:{A}:loadbalancer/{app\|net\|gwy}/{name}/{id}` | `describe_load_balancers(LoadBalancerArns=[arn])` + `describe_tags(ResourceArns=[arn])` | `add_tags(ResourceArns=[arn],Tags=[{Key:'Name',Value:name}])` |
| `apigw_stage` (`apigateway`) | `arn:{P}:apigateway:{R}::/restapis/{ApiId}/stages/{Stage}` | `get_stage(restApiId=id,stageName=stage)` + `get_tags(resourceArn=arn)` | `tag_resource(resourceArn=arn,tags={'Name':name})` |
| `cloudfront` (`cloudfront`) | `arn:{P}:cloudfront::{A}:distribution/{Id}` | `get_distribution(Id=id)` + `list_tags_for_resource(Resource=arn)` | `tag_resource(Resource=arn,Tags={'Items':[{Key:'Name',Value:name}]})` |
| `athena_workgroup` (`athena`) | `arn:{P}:athena:{R}:{A}:workgroup/{Name}` | `get_work_group(WorkGroup=name)` + `list_tags_for_resource(ResourceARN=arn)` | `tag_resource(ResourceARN=arn,Tags=[{Key:'Name',Value:name}])` |
| `log_group` (`logs`) | `arn:{P}:logs:{R}:{A}:log-group:{Name}` (no policy-wildcard suffix for TagResource) | `describe_log_groups(logGroupNamePrefix=name)` exact-match + `list_tags_for_resource(resourceArn=arn)` | `tag_resource(resourceArn=arn,tags={'Name':name})` |
| `lambda` (`lambda`) | `arn:{P}:lambda:{R}:{A}:function:{Name}` (do not silently include qualifier) | `get_function(FunctionName=arn)` + `list_tags(Resource=arn)` | `tag_resource(Resource=arn,Tags={'Name':name})` |
| `wafv2` (`wafv2`) | `arn:{P}:wafv2:{R}:{A}:{regional\|global}/webacl/{Name}/{Id}` | `get_web_acl(Name=name,Scope=scope,Id=id)` + `list_tags_for_resource(ResourceARN=arn)` | `tag_resource(ResourceARN=arn,Tags=[{Key:'Name',Value:name}])` |
| `s3_bucket` (`s3control`, **new candidate**) | `arn:{P}:s3:::{Bucket}` (general purpose only) | owner inventory + `get_bucket_location(Bucket=bucket)` (`s3` read) + `s3control.list_tags_for_resource(AccountId=A,ResourceArn=arn)` | `s3control.tag_resource(AccountId=A,ResourceArn=arn,Tags=[{Key:'Name',Value:name}])` |

**Request shape validation:** require *exactly one* approved resource and *exactly one* `Name` tag, no batch/multi-resource invocation; reject additional SDK kwargs, alternate update/delete APIs, alias ARN/resource ID, ambiguous tags, unexpected paginated results, wrong current Name, and mismatched Readback identity. Each adapter must assert the actual SDK model supports the intended operation in the pinned runtime dependency version, especially the newer **S3 Control `TagResource`**; lack of that operation is `CAPABILITY_NOT_PROVEN`, never fallback to `put_bucket_tagging`. SDK operation spelling is not proof that the IAM action uses the same name (notably API Gateway).

### 4.3 IAM / tag preservation / evidence matrix

`CNP` = `CAPABILITY_NOT_PROVEN`, `IO` = existing Volume `IMPLEMENTED_OFFLINE`; all require live Owner/G1/G2/IAM evidence before actual dispatch. IAM values below are **candidate action identifiers** to validate against the service-authorization reference, including exact ARN type, per-action service-specific `aws:TagKeys`/`aws:RequestTag/Name` support and resource-/condition-level effective denial. **Do not** assume universal tag-key conditions because the same operation writes one key in an injected Fake. `K` = key-scoped add/update candidate (no whole-tag-set replacement); `E` = evidence to require *in addition to common protected Scope/Owner/Issuer/IAM proofs*.

| Kind | Candidate write IAM / exact resource scope | Request tag-key IAM conditions / Name-only preservation | Replacement / E | Initial status and remaining unproven condition |
|---|---|---|---|---|
| `instance` | `ec2:CreateTags` / instance ARN | `aws:TagKeys=['Name']`, `aws:RequestTag/Name` where supported; K | No / E: exact instance identity, G1 race | CNP: per-kind effective IAM and SDK acceptance |
| `volume` | `ec2:CreateTags` / exact volume ARN | existing generated subset policy `aws:TagKeys`, plus effective deny proof; K | No / E: exact volume and G1 | **IO**: Task 7 offline only; actual Host/IAM/G1/G2 pending |
| `snapshot` | `ec2:CreateTags` / accountless snapshot ARN candidate | same EC2 key guards only if proven on snapshot IAM type; K | No / E: snapshot ownership and G1 | CNP: ARN owner rule / effective deny |
| `eni` | `ec2:CreateTags` / network-interface ARN | EC2 tag-key controls candidate; K | No / E: ENI identity and G1 | CNP: IAM/Name evidence verifier |
| `eip` | `ec2:CreateTags` / elastic-ip ARN | EC2 tag-key controls candidate; K | No / E: allocation identity and G1 | CNP: IAM/Name evidence verifier |
| `nat` | `ec2:CreateTags` / natgateway ARN | EC2 tag-key controls candidate; K | No / E: NAT identity and G1 | CNP: IAM/Name evidence verifier |
| `endpoint` | `ec2:CreateTags` / vpc-endpoint ARN | EC2 tag-key controls candidate; K | No / E: endpoint identity and G1 | CNP: IAM/Name evidence verifier |
| `rds_cluster` | `rds:AddTagsToResource` / cluster ARN | `aws:TagKeys`/`aws:RequestTag/Name` action-specific checks; K | No / E: live cluster identity, G1 | CNP: effective key/ARN policy and Name inference proof |
| `rds_instance` | `rds:AddTagsToResource` / db ARN | same as above; K | No / E: db identity, G1 | CNP: effective key/ARN policy and Name inference proof |
| `opensearch` | `es:AddTags` candidate / exact domain ARN | service-specific condition support to prove; K | No / E: legacy/new endpoint mapping, G1 | CNP: IAM action/tag-key/Name inference proof |
| `elbv2` | `elasticloadbalancing:AddTags` / exact load balancer ARN | service-specific condition support to prove; K | No / E: LB type + G1 | CNP: IAM action/tag-key/Name inference proof |
| `apigw_stage` | `apigateway:PATCH` **candidate** / exact management Stage ARN | method-to-IAM mapping + tag-key enforcement not proven; K | No / E: API/Stage ownership, stage ARN and G1 | CNP: method IAM semantics and accountless ARN proof |
| `cloudfront` | `cloudfront:TagResource` / exact distribution ARN | `aws:TagKeys`/request-tag support candidate; K | No / E: global endpoint/owner + G1 | CNP: global Scope and effective IAM proof |
| `athena_workgroup` | `athena:TagResource` / exact workgroup ARN | IAM Name-key support to prove; K | No / E: workgroup identity + G1 | CNP: IAM/Name verifier |
| `log_group` | `logs:TagResource` / exact log-group ARN | IAM Name-key support to prove; K | No / E: exact ARN (avoid trailing `:*`) + G1 | CNP: IAM ARN matching + Name verifier |
| `lambda` | `lambda:TagResource` / unqualified function ARN | IAM Name-key support to prove; K | No / E: function qualifier and G1 | CNP: IAM/Name verifier |
| `wafv2` | `wafv2:TagResource` / exact WebACL ARN | IAM Name-key support to prove; K | No / E: regional/global endpoint + G1 | CNP: correct scope/endpoint + IAM conditions |
| `s3_bucket` | **`s3:TagResource`** via `s3control` / exact bucket ARN | AWS docs list `aws:RequestTag/Name` and `aws:TagKeys` for general-purpose buckets; K candidate | No for TagResource / E: independently proven owner, region, ABAC side effects, G1 | CNP: SDK pinned support, effective tag-key/ARN/IAM/ownership proofs |

**Explicitly prohibited fallback:** `s3.put_bucket_tagging` / `s3:PutBucketTagging` performs a whole-tag-set replacement and cannot be treated as key-only. It is `UNSUPPORTED_BY_POLICY` for the existing Name-only contract, even if an offline test preserves tags under no concurrency. For the **new** S3 Control `TagResource` candidate, keep the *kind* `CAPABILITY_NOT_PROVEN` until its AWS/IAM/Host tests establish safe use. Distinguish the API fallback's policy rejection from the kind's unproven status.

**Evidence and status rule:** Candidate API documentation and model introspection are *design evidence* only. To promote a kind to `IMPLEMENTED_OFFLINE`, the implementation must have a deterministic identity parser, evidence-checked Name inference, per-kind read/update/readback adapter, exact-resource and `Name`-key guard, Fake success/failure cases and regressions. To enter *live dispatch*, require protected host/STS/G1/G2/effective deny proof independently; do not conflate these axes. An unproven IAM condition, service-account ownership or API operation requires `CAPABILITY_NOT_PROVEN` with `reason_code` and one of `IAM_CONDITION_NOT_PROVEN`, `ARN_OWNER_NOT_PROVEN`, `API_SDK_UNAVAILABLE`, `NAME_EVIDENCE_NOT_PROVEN`, `GLOBAL_SCOPE_NOT_PROVEN`, etc. If **proven** impossible to meet policy, classify `UNSUPPORTED_BY_POLICY`; if **proven** no suitable API exists, `UNSUPPORTED_API`. State and reason are not mutable approval overrides.

AWS official references (as of this design review, recheck at implementation against the pinned SDK model):

- EC2 CreateTags, IAM keys: https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html
- RDS tagging: https://docs.aws.amazon.com/service-authorization/latest/reference/list_rds.html
- CloudFront distribution ARN / TagResource: https://docs.aws.amazon.com/service-authorization/latest/reference/list_cloudfront.html
- S3 **new** TagResource and ListTagsForResource: https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_TagResource.html and https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_ListTagsForResource.html
- S3 bucket conditions / IAM resource types: https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging.html and https://docs.aws.amazon.com/service-authorization/latest/reference/list_s3.html
- S3 legacy replacement: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html
- API Gateway management authorization: https://docs.aws.amazon.com/service-authorization/latest/reference/list_apigateway.html
- IAM evaluation and resource-based session policies: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
- Resource Groups Tagging API service support: https://docs.aws.amazon.com/resourcegroupstagging/latest/APIReference/supported-services.html

## 5. Shared Security Runtime

OwnerTrust、Batch Approval、Scope、Ledger、Permit、Issuerは共通化する。

Host-only Credential Issuerは、実STSの要求・応答、正確なPolicy bytes/hash、対象ARN、Session identity、期限、資格情報の来歴を保護された同一Host境界内で束縛する。

Pre-send Read、Write、Readbackには同じIssuedBatchSessionを使用する。

Ambient credentials、未検証のSession、コピーしたreceipt、任意に生成したRuntime Policyは拒否する。

Runtime Policyは信頼済みHostの検証処理からのみ発行可能にする。実効IAMの証拠がない場合、発行・書き込みを拒否する。

Session Policyだけを実効IAMの完全な証明としない。Python上のオブジェクト識別子、dataclass、Booleanだけで実Host信頼を証明しない。

資格情報の生値をLedgerやログに永続化しない。

### 5.1 Single protected Host architecture and trust chain — RG-PRC-003

**One Host-only Coordinator within the existing Batch Runtime, not a new network service.** The operator/CLI supplies only immutable Plan/CSV, detached Owner signature and bounded requested subset. The Host entrypoint executes in a protected OS process on the designated Host (protected executable/configuration identity, owner/mode, privileged credential source and private trust-store/ledger paths checked by Host bootstrap). It must *independently* attest protection/instance identity and load the pinned OwnerTrust and Scope evidence from trusted Host storage. A process-argument flag, environment variable, dataclass, `trusted_host=True`, UID check alone, test-mode `OfflineFakeIssuer`, or Host string copied from the Plan is not trusted attestation. If protection cannot be evidenced, production entrypoint remains disabled. Reuse the existing Coordinator and Ledger; no RPC that accepts caller-minted policy/credentials.

**Sole credential producer:** `HostBatchCredentialIssuer`, invoked only after current signed approval, protected Scope, accepted capability and subset policy verification. It uses an explicit **Host-protected bootstrap credentials provider** with fixed authorized source/principal/Role — never SDK default profile/environment/IMDS-chain fallback — and issues the exact `AssumeRole(RoleArn=signed_role,RoleSessionName=bound_nonce,Policy=exact_policy,DurationSeconds=bounded_ttl,...)` request. Protect and bind canonical request bytes/hash, Batch ID, sorted approved row-index subset, operation/ARN/Name/Signed Scope IDs, policy bytes/hash, host boot/run identifier, actual STS response metadata (AssumedRoleUser ARN/ID and expiration), and returned temporary credential fingerprint into a **Host-issued, tamper-evident, expiring issuance receipt**. Verify the actual call used exactly those bytes, not a reconstructed equivalent. The Host maintains the protected receipt/credential/client registry; a caller cannot create or copy a valid grant. Secret key/session token are held in protected Host memory only, never in signed artifacts, CLI output, report or Ledger.

Create read/write/readback SDK clients from the **same credential triplet and execution session**, using explicit client credentials and pinned account/region/endpoint per Kind. Read-only `GetCallerIdentity` confirms the assumed caller principal/account but **does not attest** the inline STS Policy or the absence of resource-policy permissions; compare it with the protected issuance response and use separate effective-IAM evidence.

**Sole runtime gate:** `ProtectedBatchRuntimeVerifier` reads independently protected current `ScopeEvidence`, `SideEffectEvidence`, Ledger state, current OwnerTrust/revocation, issuer receipt and `EffectiveIamDenyEvidence`; it issues a **process-local, non-serializable, one-shot `VerifiedRuntimeGrant`** bound to `(Host/run, Batch, row-authority-id, signed row tuple, exact ARN/Name/API, Scope, Permit identity/state, issuance receipt, client identity, validated capability version, proof digest, expiry)`. Constructing a dataclass with these values is *not* valid; grant verification must consult the protected Host-side registry. The grant cannot be supplied over CLI or stored as a reusable token.

`EffectiveIamDenyEvidence` is a separately sourced, protected evidence bundle, **not a Boolean**. Its contract includes: role/session principal, account/partition, exact Role/Trust/identity policies and their versions/digests, attached boundaries, SCP/RCP applicability, resource-based policies and session-principal grants, exact approved ARN/action/tag-key allow, nonapproved ARN / other tag key / alternate write-API deny cases, evidence source, capture time/expiry and verifier result. The verifier must reconcile potential grants, explicit denies, request-tag condition applicability and current drift. A policy simulator alone, a Session Policy alone, or a green Fake test **cannot** mark the evidence live-proven. The evidence producer and live acceptance procedure remain separately Owner-authorized. Until genuine evidence is available, `AWS_RUNTIME_NOT_AUTHORIZED` / `G2_NOT_VERIFIED` remain blocking.

Suggested implementation interfaces (design contracts, **not** new source files or permission to call AWS):

```python
class HostCredentialIssuer(Protocol):
    def issue(self, batch: VerifiedBatchApproval, subset: SessionPolicySpec,
              host: VerifiedHostContext, now_utc: datetime) -> HostIssuedSession: ...
class HostScopeVerifier(Protocol):
    def resolve(self, signed_scope_id: str, target: CanonicalTargetIdentity,
                host: VerifiedHostContext, now_utc: datetime) -> VerifiedHostScope: ...
class EffectiveIamEvidenceVerifier(Protocol):
    def verify(self, issued: HostIssuedSession, row: VerifiedBatchRowAuthority,
               capability: KindCapability, scope: VerifiedHostScope,
               evidence: ProtectedIamEvidence) -> VerifiedDenyEvidence: ...
class ProtectedBatchRuntimeVerifier(Protocol):
    def authorize_once(self, row: VerifiedBatchRowAuthority, issued: HostIssuedSession,
                       scope: VerifiedHostScope, deny: VerifiedDenyEvidence,
                       permit: FirstSendPermit) -> VerifiedRuntimeGrant: ...
```

**Ordering:** Trust/Scope/capability/issuer/subset/IAM acceptance must pass **before Ledger Intent**; after Intent and immediately before Permit consumption revalidate protected authority/Scope and fresh evidence; the one-shot grant is checked immediately at the SDK dispatch boundary and consumed, with no reusable session grant. The host executor owns both grant minting and the SDK invocation; `AuthorizedBatchWritePort` must reject all caller-fabricated runtimes. Missing, expired, mismatched, revoked, protected-state read failures and unknown process termination yield no send before Permit; after Permit use durable `OUTCOME_UNKNOWN`, Batch STOP/HOLD and no replay. An inability to durably STOP/HOLD blocks the Host. No automatic bootstrap credential recovery or fail-open retry.

### 5.2 Fixed protected Host bootstrap — Finding 004

**Single architecture, not implementation discretion:** The only production Host entry is a manually Owner-authorized, system-level Linux **systemd service**, `aws-cnt-batch.service`, running as a dedicated unprivileged `aws-cnt` OS account. The service has one Coordinator inside the **existing** `name_tag_batch_runtime.py`, the one host-bound SQLite Ledger, and the existing protected OwnerTrust/Scope/IAM evidence. No second signer, ledger, writable remote service or direct CLI-to-SDK execution is introduced. The service is **not installed, enabled, started or connected** by this document. A non-systemd host is unsupported pending a distinct Owner decision; a caller invoking the Python module directly cannot self-assert service provenance.

Provisioning contract for later separately authorized Host acceptance: root-managed `aws-cnt-batch.service` unit and immutable executable/config/manifest with pinned exact digests, dedicated service UID/GID and protected access permissions, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `UMask=0077`, `StateDirectory=aws-cnt`, `RuntimeDirectory=aws-cnt`, and protected ledger/trust/evidence paths. If required host hardening cannot be verified, **Fail-Closed**; specifying a unit option is not proof that the OS enforced it. The sole fixed local UNIX socket `/run/aws-cnt/host.sock` is **self-bound by the verified `aws-cnt-batch.service` process**, never by a `.socket` unit, and never by CLI socket activation. The Host verifies bootstrap before binding and is the sole listener. A missing or occupied path blocks startup; it does not authorize automatic removal/replacement of an existing socket. The `batch-live` CLI is an *untrusted local client* to this fixed socket and may submit only the exact Plan/CSV/Owner envelope and a bounded request; it cannot send credentials, substitute proof, grant, output paths or a socket location. Socket permission and `SO_PEERCRED` checks are supplemental controls, **not** Owner approval or a substitute for signed-row verification. The service re-verifies all Owner/Scope/Issuer/IAM/Permit gates before any dispatch.

**Single trust root and bootstrap interface:** A Host-only `verify_host_bootstrap(now_utc: datetime) -> VerifiedHostContext` owns an unforgeable process-local registry entry and must validate the live service/cgroup identity, root-controlled unit/config/executable manifest and trusted digests, protected file ownership/mode/no-symlink path components, stable Host/run ID, private protected Ledger identity and current OwnerTrust/Scope source bindings. Merely matching a UID, an environment variable, an object constructor, or a fabricated `VerifiedHostContext` is insufficient. No validated boot context => no Host Credential Issuer, no Intent, no Permit and no AWS call.

**Only STS bootstrap credential source:** `HostBootstrapCredentialProvider.load(host: VerifiedHostContext, now_utc: datetime) -> ProtectedBootstrapCredentials` reads the **systemd encrypted credential** `LoadCredentialEncrypted=aws-bootstrap.json:<root-provisioned encrypted path>` delivered exclusively into the service's verified `CREDENTIALS_DIRECTORY`, parses an exact short-lived `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration` tuple, validates freshness/format/declared bootstrap principal and protects it in process memory. This directory's environment variable is only a location hint, never an authority claim. No ambient boto3 credential chain, `AWS_*` key fallback, shared config/profile, IMDS fallback, automatic renewal or cached expired credentials. Construct the Host-owned STS client **only with explicitly supplied validated credential bytes**, and only after protected Host and Owner checks; bind the actual AssumeRole request/response to the protected issuance receipt under §5.1. Missing, expired, substituted or inaccessible encrypted credentials fail closed. Credential provisioning/rotation, unit hardening, trust setup, IAM changes, real STS and Host G1/G2 attestation remain **NOT_VERIFIED / Owner HOLD**.

```python
class HostBootstrapVerifier(Protocol):
    def verify_process(self, *, now_utc: datetime) -> VerifiedHostContext: ...
class HostBootstrapCredentialProvider(Protocol):
    def load(self, host: VerifiedHostContext, *, now_utc: datetime
             ) -> ProtectedBootstrapCredentials: ...
class ProtectedHostCommandEndpoint(Protocol):
    def execute_signed_batch(self, *, plan_bytes: bytes, csv_bytes: bytes,
                             owner_envelope_bytes: bytes,
                             host: VerifiedHostContext) -> BatchRunResult: ...
```

**Offline vs real proof:** Inject filesystem/service/credential transport doubles in tests to exercise denied bootstrap, forged UID/cgroup/unit, symlink/permission/digest drift, substituted `CREDENTIALS_DIRECTORY`, missing/expired credentials, copied runtime grants, incorrect peer and crash states. These Fake verifications assert only *code behavior*. Real process isolation, protected credential delivery, absence of ambient access, effective IAM denies and G1/G2 must be independently evidenced during a later specifically approved Host acceptance. Preserve `SAFETY_HOLD_ACTIVE`, `AWS_WRITE_BLOCKED`, `G1_NOT_PROVEN`, `G2_NOT_VERIFIED` and `AWS_RUNTIME_NOT_AUTHORIZED` in this implementation phase.

#### 5.2.1 Host-owned AF_UNIX listener and fixed wire contract — PLAN-004 remainder

**One transport / one entry:** The only supported command transport is Linux `AF_UNIX`, `SOCK_STREAM`, at the **literal** `/run/aws-cnt/host.sock`. The system-level unit `aws-cnt-batch.service` starts the protected Host process directly and **that process binds and listens** after `HostBootstrapVerifier.verify_process` succeeds. Do not configure or rely on `aws-cnt-batch.socket`, systemd socket activation, a TCP listener, an alternative socket path, CLI-supplied file descriptor, or an ad-hoc Python process. Host process/startup identity remains subject to the root-pinned unit/executable/manifest and cgroup/OwnerTrust/Ledger checks in §5.2.

**Filesystem/peer contract:** Root provisions the dedicated `aws-cnt` service UID and `aws-cnt-ipc` client access group; the service gets `User=aws-cnt`, `Group=aws-cnt`, `SupplementaryGroups=aws-cnt-ipc`, `RuntimeDirectory=aws-cnt`, `RuntimeDirectoryMode=0750`, `UMask=0077`. Only after protected bootstrap, the Host verifies `/run/aws-cnt` is a real, non-symlink directory, owner `aws-cnt`, and not group/world writable, then sets its group to `aws-cnt-ipc` and mode `0750`. The service exclusively binds the absent path with an `AF_UNIX/SOCK_STREAM` socket, sets socket owner `aws-cnt`, group `aws-cnt-ipc`, mode `0660`, verifies inode/type/ownership and listens with backlog `8`. Any permission, inode, type, symlink, path-collision or ownership anomaly **blocks**; never silently unlink a potentially stale socket or create a world-writable directory. The service uses a single serial Coordinator with only one active Batch; extra accepted connections return `IPC_BUSY` without Ledger Intent. `SO_PEERCRED` obtains Linux kernel peer UID/GID/PID and applies the configured operator admission policy; it is supplemental local access control and **never** Owner signature, permitted row or Host authorization.

**Protocol:** `AWS-CNT-BATCH-IPC/1`, using one request and at most one response per connection. Each frame is `uint32_be(payload_length)` (exactly four bytes, **length excludes header**) followed by exactly that many strict UTF-8 bytes encoding one JSON object. Request `payload_length` must be `1..67108864` bytes (64 MiB); response `payload_length` must be `1..65536` bytes (64 KiB). The server checks advertised length **before allocation**, bounds reads, rejects truncated headers/bodies, extra trailing bytes/frames, invalid UTF-8, duplicate/unknown JSON keys, NaN/Infinity, wrong field types, oversized decoded inputs and noncanonical Base64 (strict alphabet/padding; decode then re-encode must match). No streaming, compression, file descriptor passing, user-provided command path, socket path, environment or identity override. The request has **exactly**:

```json
{"protocol_version":1,"command":"execute_signed_batch","request_id":"0123456789abcdef0123456789abcdef","plan_b64":"<canonical padded base64>","review_csv_b64":"<canonical padded base64>","owner_envelope_b64":"<canonical padded base64>"}
```

`request_id` is exactly 32 lowercase hexadecimal characters and is a correlation value **not an authorization or durable replay key**. Base64-encoded fields decode into the **exact original** Plan bytes (max 32 MiB), 14-column BOM review CSV bytes (max 12 MiB), and Owner signed envelope bytes (max 256 KiB); the signed/approved data are **never parsed and reserialized as an alternative authority**. Empty input or any size/encoding mismatch fails before Owner verification/Intent. The Host derives the canonical signed `batch_id`, operation, row authority and Scope exclusively through existing strict Plan/CSV/Owner verification. It rejects commands other than `execute_signed_batch`.

**Timeout contract:** The untrusted CLI connect timeout is `3 s`, Host read timeout for the complete four-byte header `5 s`, Host total request-body deadline `30 s`, Host response-write deadline `5 s`, and CLI total response deadline `120 s`; use monotonic deadlines, no automatic reconnect/retry and no unbounded buffering. Reaching a deadline returns a blocked/unknown transport result and closes that connection. The Host executes a validated command to a durable Ledger outcome independent of client availability; the CLI deadline does **not** cancel, resubmit or roll back any committed Intent/Permit. Full per-row reports are retained only in protected Host-owned storage; the bounded response is a status summary and digest, not a second ledger or an authority source.

**Correction A — bounded end-of-request / formal IPC acceptance:** A conforming `UnixBatchHostClient` sends **exactly one** four-byte big-endian length header and exactly its declared strict v1 payload bytes with `sendall`, then invokes `shutdown(SHUT_WR)` on **that same connection**. It does not close its read half: it awaits the Host response on the existing connection and never opens a second connection automatically. The Host consumes the four-byte header within the existing 5 s deadline; after validating the declared size before allocation, it consumes the **entire declared body and EOF together within the existing 30 s cumulative monotonic body deadline**. After the declared body, it performs a bounded one-byte read to distinguish **zero-byte EOF (required)** from any extra byte (rejected `IPC_INVALID_FRAME`); a second frame, trailing whitespace/bytes, truncated header/body, missing EOF or no EOF by the deadline (`IPC_TIMEOUT`) is rejected **before Owner verification, Ledger Intent, Permit, STS or SDK**. Only after complete framing, EOF, strict JSON/Base64 validation and peer admission can the server mark `IPC_REQUEST_ACCEPTED` locally and enter `ProtectedHostCommandEndpoint.execute_signed_batch`. This marker is an internal control-flow boundary, **not** a signed approval, durable execution status, or additional Ledger authority. AF_UNIX stream EOF alone cannot distinguish a peer that half-closed from one that fully closed after the exact bytes; therefore the Host's acceptance depends on a complete valid stream and EOF, **not** any unverifiable claim that the peer remained connected.

**Correction B — post-acceptance disconnect independence:** Before formal IPC acceptance, truncated, malformed or EOF-missing input is never executed. **After** formal IPC acceptance, a client close, read-side abort, timeout or failed response write **does not cancel the Host command, modify the current Owner/Scope/Issuer/IAM decision, consume extra Permits, or rewrite a durable Ledger outcome**. The Host independently re-verifies the current Owner signature and protected gates and lets the existing single Coordinator/Ledger complete or stop under their normal rules; if a verified terminal outcome and same-session Readback were durably recorded, it remains that outcome even when the reply is lost. The CLI classifies lost, truncated, invalid or timed-out response as local `UNKNOWN`, never `COMPLETE`, `APPLIED_VERIFIED` or proof of no-send. **Only** when Permit has been consumed and the send/Readback disposition is not durably known does the Host persist `OUTCOME_UNKNOWN`, STOP the Batch, HOLD the affected Scope and forbid replay; failure to persist STOP/HOLD is Host-wide Fail-Closed. Client disconnection **alone** does not cause `OUTCOME_UNKNOWN`. No resubmission/reconnect is automatic; a changed `request_id` cannot authorize replay or a new send. An invalid pre-accept request can receive a bounded safe `BLOCKED` response if writable, otherwise the Host closes it and the client reports `UNKNOWN`.

**Response contract:** The only response envelope has exactly `protocol_version` (`1`), echoed `request_id`, `status` (`COMPLETE | BLOCKED | UNKNOWN`), `code` (one allowlisted reason string), `batch_id` (`null` or 64 lowercase hex), and `report_sha256` (`null` or 64 lowercase hex). `COMPLETE` means a **durable terminal disposition was recorded**, not that a Name was applied; `BLOCKED` means no successful execution authority was established; `UNKNOWN` means command outcome cannot be asserted. A response without an independently validated, durable `APPLIED_VERIFIED` row must never be interpreted as a successful AWS write. Pre-dispatch protocol failures map to `IPC_UNSUPPORTED_VERSION`, `IPC_INVALID_FRAME`, `IPC_REQUEST_TOO_LARGE`, `IPC_BAD_PAYLOAD`, `IPC_TIMEOUT`, `IPC_PEER_REJECTED`, or `IPC_BUSY`, with no Intent/Permit/STS/SDK. Protected Owner/Scope/Runtime failures retain existing `BLOCKED_OWNER_AUTHN`, `BLOCKED_SCOPE_MISMATCH`, `AWS_RUNTIME_NOT_AUTHORIZED`, etc. and never reveal secrets. If a complete safely bounded error response cannot be written, close the socket; the CLI must classify it `UNKNOWN` (not success).

**Explicit anti-replay semantics (consistent with Corrections A/B):** For each formally IPC-accepted request the Host independently re-verifies current OwnerTrust signature/role/revocation and exact signed Plan/CSV/Scope/Capability/IAM/Issuer/Runtime gates; each approved row is rechecked at admission and just before Permit consumption. The **single existing durable** SQLite `IntentLedger` alone controls Batch identity, signed attempt cap, Intent, Permit and terminal outcomes. Reject concurrent or repeated execution for an already admitted/attempted Batch, even with a changed `request_id`; it is correlation only. Protocol/peer/Owner/Host failures **before IPC acceptance or authority admission** establish no Intent or send; a denied Host safety gate before Permit establishes no new send. A client disconnect **after IPC acceptance** is never by itself a reason to stop, re-send, or demote a durably verified outcome; Host-side failure or missing durable readback **after Permit** triggers `OUTCOME_UNKNOWN`/STOP/HOLD and no replay. A lost reply maps to client-local `UNKNOWN` irrespective of the durably recorded Host outcome. No client-supplied `report_sha256` or status affects Host authority.

**Host wiring (one Coordinator, no public bypass):**

```python
@dataclass(frozen=True)
class HostIPCRequest:
    protocol_version: int
    request_id: str
    plan_bytes: bytes
    csv_bytes: bytes
    owner_envelope_bytes: bytes

@dataclass(frozen=True)
class HostIPCResponse:
    protocol_version: int
    request_id: str
    status: str
    code: str
    batch_id: str | None
    report_sha256: str | None

class BatchHostIPCCodec(Protocol):
    def read_request(self, stream: object) -> HostIPCRequest: ...
    def write_response(self, stream: object, response: HostIPCResponse) -> None: ...

class ProtectedHostIPCServer(Protocol):
    def serve(self, *, bootstrap: HostBootstrapVerifier,
              endpoint: ProtectedHostCommandEndpoint) -> None: ...

class UnixBatchHostClient(Protocol):
    def execute(self, *, plan_bytes: bytes, csv_bytes: bytes,
                owner_envelope_bytes: bytes, request_id: str) -> HostIPCResponse: ...
```

The **Host** implementation resides in `name_tag_batch_host_server.py`: bootstrap check → self-bind/listen → peer and bounded frame checks → strict IPC decode in `name_tag_batch_ipc.py` → protected `OwnerTrust` verification → Host-only `ProtectedHostCommandEndpoint.execute_signed_batch` in `name_tag_batch_host_runtime.py` → the **existing** `name_tag_batch_runtime.py` Coordinator/`IntentLedger` (Task 7) → durable outcome → bounded response. The endpoint obtains the current Host context from the protected process registry, not a client object; the `host` parameter of the existing §5.2 Protocol is an **internal** already-verified reference only. The **CLI** in `name_tag_batch_cli.py` calls only `UnixBatchHostClient` using the fixed socket path, and never imports/constructs Host credentials, Ledger, grant or SDK on the `batch-live` path. Tasks 6 and 8 implement this server/client split and Fake IPC tests; Task 7 supplies the existing-Registry/Ledger live execution underneath. No new signer, authority database or batch coordinator.

**Verification boundary:** Offline tests use injected Fake streams, socket/syscall/peer/OS-bootstrap transports, fake protected command endpoint, fake STS and fake Ledger, asserting framing, listener bootstrap, strict rejection, no retry, disconnect-before/after-Permit classification and Host-only Coordinator delegation. They never bind `/run/aws-cnt/host.sock`, install/start systemd services or call STS/AWS. Root-managed unit provisioning, socket permissions/cgroup provenance on a real Host, encrypted credential delivery, effective IAM denial and G1/G2 remain `NOT_VERIFIED` and require separate Owner authorization. The same `SAFETY_HOLD_ACTIVE` and `AWS_RUNTIME_NOT_AUTHORIZED` remain intact.

## 6. Write Execution Contract

書き込み対象の各行で以下を保証する。

1. 最新のOwner署名・失効状態を再検証する。
2. Plan/CSV、対象ARN、Name、API、Scopeを照合する。
3. 署名済み行のEligibilityを検証する。
4. CapabilityとIAM証拠を検証する。
5. 同一Issuer Sessionで直前のName状態を再取得する。
6. 既存の意味あるNameがあれば書き込まない。
7. LedgerでIntentを永続化する。
8. FirstSendPermitを一度だけ消費する。
9. 許可済みAPIへName-only要求を一度だけ送信する。
10. 同じSessionでReadbackする。
11. 成功・拒否・不明を耐久化して報告する。

送信結果不明、Readback失敗、Session失効、Ledger障害では再送しない。Permit消費後の非`OSError`例外も `OUTCOME_UNKNOWN` として扱い、STOP/HOLDを耐久化できない場合はHost-wide Fail-Closedとする。

APIに原子的な条件付き更新がない場合、Pre-send ReadとWriteの間の競合を完全に解消したと主張しない。対応するG1リスク判断が成立しなければ書き込み禁止とする。

### 6.1 Existing Batch-module integration and typed contracts — RG-PRC-004

Existing Phase A and Batch Tasks 1–7 are the baseline, **not** a parallel new Batch signer/ledger. Preserve fixed Batch Plan `schema_version=3`, `cur_population.schema_version=2`, exactly the current 14 review CSV fields, `BatchApprovalV1` namespace/payload, canonical exact bytes/hashes, signer role/revocation, signed `max_send_attempts`, row authority derivation, Scope HOLD behavior and no-retry outcomes.

| Existing module | Required bounded change (future implementation; no source edits in this remediation) | Required hard rejection or safe classification |
|---|---|---|
| `name_tag_batch_state.py` | Extend fixed Kind/Operation/Canonical ARN/Scope parser, and `validate_approved_batch_row` via immutable `KindNameEvidenceVerifier` dispatch. Keep Plan/CSV and `derive_declared_row_scope()` semantics and unique signed declaration. | Malformed/unknown/duplicated approved row, invalid Name evidence, unapproved kind/operation or unverifiable scope => **whole draft rejection** before authority. |
| `name_tag_batch_approval.py` | Keep exact Plan/CSV digest, `BatchApprovalV1`, `_approved_tuples`, row-index/ID mapping and trusted signer verification. Newly eligible kinds bind the same approved tuple fields and protected Scope ID. | Bad signature/role/revocation, changed bytes or forged `approved=YES` => `BLOCKED_OWNER_AUTHN`; no silent selective Skip. |
| `name_tag_batch_iam.py` | Replace Volume-only policy mapping with verified per-kind `KindPolicy` and **action-specific** exact resource ARN, tag-key condition, read action, SDK policy-size budget and sorted subset builder. Distinguish policy specification from independently proven effective IAM. | Unknown operation/condition/owner ARN or required policy too large => `CAPABILITY_NOT_PROVEN`/`IAMPolicyBlocked`; no Resource:`*` write fallback. |
| `name_tag_batch_runtime.py` | Reuse the existing sequential Coordinator; inject protected Host issuer/verifier and Kind adapter registry, retain preflight before Intent, Intent/Permit/send order, G1/G2 checks, STOP/HOLD/`OUTCOME_UNKNOWN` and signed attempt cap. Retain `execute_batch_offline` Fake-only behavior. | Unsupported **unapproved** rows are report-only; approved but unverifiable authority rejects admission. Post-Permit uncertainty stops Batch; no automatic retry. |
| `name_tag_ledger.py` | Reuse protected Host-bound SQLite single authoritative Ledger and its row/scope state. Store only references/digests for kind, credential receipt, IAM evidence, exact ARN/API and outcomes; no secrets. Any schema change requires explicit migration design and separate Owner approval. | Scope HOLD, reuse, changed signed tuple, cap exhaustion, missing host guarantee => no new Permit/send. No implicit migration. |
| `name_tag_batch_report.py` | Replace `_WRITE_OPERATIONS={'volume':...}` with immutable Registry-derived projection; include each Kind's capability status, reason and 18-kind population/Decimal cost without broadening authorization. Distinguish `DECLARED_ONLY` from actual Host Scope verification. | Unavailable evidence classified accurately; invalid signed/Plan inputs still reject report authentication; never emit fabricated `APPLIED_VERIFIED`. |
| `name_tag_batch_live.py` | Keep EBS request builder/deny boundary; add **separate** vetted Kind adapters behind `AuthorizedBatchWritePort` and protected `VerifiedRuntimeGrant`, restricted to one Name-key service call and same-credential Readback. | Any legacy caller-constructed `AuthorizedBatchRuntimePolicy`, absent grant, extra resource/Tag key, or unsafe replacement => `AWS_RUNTIME_NOT_AUTHORIZED` / `WRITE_UNSUPPORTED`. |
| `name_tag_batch_credentials.py` (existing adjacent boundary) | Keep `OfflineFakeIssuer`/synthetic receipt distinctly untrusted for production. Add host-only actual STS issuer and protected response receipt as §5.1, avoiding shared writable provenance registry. | `OFFLINE_SYNTHETIC_NOT_STS` can never satisfy protected Host authorization. |

**Kind Name evidence:** Eligibility remains `approved=YES`, immutable Plan `status='proposed'`, confidence `high|medium`, exact-case `ABSENT|EMPTY|WHITESPACE_ONLY` plus exact `name_key_present/name_raw_value` and generated `proposed_name`. Per-Kind `KindNameEvidenceVerifier.verify(plan_record, canonical_target) -> VerifiedGeneratedName` deterministically parses/validates its **existing immutable evidence text** and re-derives the exact proposed Name, source identity and naming formula. Preserve the current Volume EBS-attachment formula and rejection semantics. For any other Kind with no deterministic verifier or ambiguous raw evidence, mark `NAME_EVIDENCE_NOT_PROVEN`; do not allow Owner signing merely because the evidence string is nonempty. No editable CSV Name override, no ad-hoc manual Name or post-sign inference. If a future evidence schema requires new fields, it is a separate signed-format version decision, not silent extension of Batch Plan v3.

**Three separate error domains:** (a) Malformed or forged signed source, unauthorized approved Kind, incorrect Scope declaration or mutated immutable tuple => **reject whole approval** before `VerifiedBatchRowAuthority`, Intent, Permit or SDK. (b) Properly classified unsupported/unproven Kind in an **unapproved** row => valid Preview/Report with `UNSUPPORTED_BY_POLICY`, `UNSUPPORTED_API`, `CAPABILITY_NOT_PROVEN`, precise reason/count/Decimal cost and `execution_allowed=false` for that row. (c) Valid signed approved row but changed Name, stale Host/Scope/G1/G2/IAM evidence or runtime side effect => per-resource pre-send blocked/skipped outcome, with Batch STOP/HOLD when the existing safety contract requires; a forged approval may not be downgraded to a successful "unsupported" Skip. A failure **after Permit** is not a safe pre-send Skip: persist `OUTCOME_UNKNOWN`, stop Batch, and do not auto-retry.

Immutable interface sketch:

```python
class KindNameEvidenceVerifier(Protocol):
    def verify(self, plan_record: Mapping, target: CanonicalTargetIdentity) -> VerifiedGeneratedName: ...
class KindWriteAdapter(Protocol):
    def read_current(self, client: object, target: CanonicalTargetIdentity) -> NameObservation: ...
    def write_once(self, client: object, target: CanonicalTargetIdentity,
                   name: str, grant: VerifiedRuntimeGrant) -> None: ...
    def readback(self, client: object, target: CanonicalTargetIdentity) -> NameObservation: ...
class KindCapabilityRegistry(Protocol):
    def resolve(self, kind: str, arn: str, operation: str) -> KindCapabilityDecision: ...
```

`NameObservation` includes exact raw Name key presence/value, classified state and verified resource identity; `UNKNOWN` is never `ABSENT`. `KindCapabilityDecision` includes full §4 fields, provenance/condition evidence and reason. The existing `VerifiedBatchRowAuthority` and `FirstSendPermit` types are reused, not re-created by an adapter.

## 7. IAM / Runtime Gates

実行時には少なくとも以下を要求する。

- Ownerの有効な署名済みBatch
- 正確なAccount / Region / ARN / Operation
- 保護されたScopeとSideEffect Evidence
- G1の対象限定判断
- G2の実Host証拠
- Host-only Issuerの保護された来歴
- 実STS SessionとClient Identity
- 対象外ARN、他Tag Key、別APIに対する実効IAM拒否証拠
- Ledger Permitと署名済みattempt cap
- 停止・監査・結果不明時の安全処理

IAMの継承Policy、Permission Boundary、SCP、Resource-based Policy、Assumed-role Sessionへの権限付与による迂回を考慮する。

証拠欠落・不一致・期限切れはFail-Closed。コード上のGate実装と、実環境でのGate成立証明を別々に扱う。

## 8. Reporting

全18種類について、CUR母集団、対象件数、Decimal費用、Capability状態を集計する。

結果は相互排他的に分類し、既存の費用・件数照合と整合させる。

特に次を区別する。

- Name付与成功・Readback確認済み
- Name既存・変更済み
- Name生成不可
- Owner未承認
- Scope不一致
- IAM制約による未対応
- API・タグ集合置換による未対応
- 証拠不足による未検証
- 上限到達による未実行
- 送信結果不明
- その他の安全停止

未検証のものを成功・完全対応として表示しない。

### 8.1 Reporting invariants for additional kinds — RG-PRC-002/004

The Registry's coverage table is keyed by the exact 18 immutable Kind identifiers, not by inferred service text. Each selected CUR resource has exactly one **stage classification** plus a separate immutable **capability assessment**; use disjoint population partitions and `Decimal` sums, never sum stages twice. `cur_recognized = below_min_cost + above_min_cost`; `above_min_cost = lookup_selected + max_resources_not_inspected` remain intact, as do existing excluded-billing-line and reason-detail totals. For each Kind, track pre-cap resource count/cost, selected, eligible, unsigned/unapproved, unsupported, unproven, cap-not-attempted, attempted, verified and unknown. Reconcile each stage to fixed population and do not conflate `CAPABILITY_NOT_PROVEN` with `UNSUPPORTED_BY_POLICY`, `NOT_RUN` or actually observed API failure. `APPLIED_VERIFIED` requires a signed row, consumed Permit, issued identity and same-session Readback. Report exactly why a Kind is disabled, even if other kinds proceed.

### 8.2 Authenticated 18-kind pre-cap accounting — Finding 003

`cur_candidates_batch()` must calculate per-kind resource partitions **from the same exact-Decimal, deduplicated CUR aggregates before applying `--min-cost` and `--max-resources`**. Selected `plan.records` alone cannot recover excluded/uninspected kinds. The original `cur_population` object remains `schema_version=2` and is neither reinterpreted nor backfilled. New Plans v3 contain one additional **optional, read-only, top-level** `cur_population_by_kind` field; it is included automatically in the existing exact `plan_sha256`, so no change to Plan schema version, 14-column CSV or `BatchApprovalV1` fields is required. New Plan generation always emits it; historical signed Plans lacking it continue to verify without reinterpretation and must report `PRECAP_KIND_BREAKDOWN_NOT_AVAILABLE` rather than fabricated zeros.

```python
# Exact optional Plan v3 field (read-only, SHA-protected as ordinary Plan bytes):
cur_population_by_kind = {
    'schema_version': 1,
    'kinds': {
        kind: {
            stage: {'count': int, 'cost_usd': str}
            for stage in ('cur_recognized', 'below_min_cost', 'above_min_cost',
                          'lookup_selected', 'max_resources_not_inspected')
        }
        for kind in SUPPORTED_KINDS
    },
}
```

Every recognized resource maps to exactly one Kind before threshold/cap selection. Emit all 18 Kind keys in deterministic ordering, including genuine zero entries when the request's Kind filter excludes a Kind; this does not add an out-of-filter cost. Validate finite, canonical exact-Decimal strings, nonnegative counts, mutually exclusive partitions, and for each Kind `cur_recognized = below_min_cost + above_min_cost` and `above_min_cost = lookup_selected + max_resources_not_inspected`. Across all 18 Kinds, each stage's count and cost **must equal** the corresponding existing overall `cur_population` stage, without modifying unattributable/outside-filter billing lines. A malformed, inconsistent or extraneous optional field invalidates the Plan **before approval**. Pre-cap totals cannot be inferred later from the selected rows or from an unsigned report.

Reporting interface is `report_kind_capability_coverage(plan: Mapping[str, object], decisions: Mapping[str, KindCapabilityDecision], row_outcomes: Mapping[int, str]) -> dict[str, object]`; it consumes `plan['cur_population_by_kind']` as the **only signed per-kind pre-cap source**, uses selected signed records for post-selection details, and preserves capability assessment and execution outcome as separate axes. It rejects unknown stage arithmetic and duplicate costs rather than declaring coverage complete.

## 9. TDD Strategy

1工程内で小さなRED → GREEN → REFACTORを繰り返す。

実装順序:

1. Registryと18種類の判定テスト
2. Batch Plan / Approval / Reportの全Kind対応
3. サービス別AdapterとIAM契約
4. Host Issuer / Runtime Policy / STS境界
5. 共通Live WriterとPre-send Read / Readback
6. CLIの明示Opt-in・監査・停止制御
7. Fake STS / Fake SDKによるオフラインE2E
8. 全体回帰・Manifest整合性

各段階で独立レビューや新しいTaskを作らない。既存Phase AのSafety Holdを変更しない。

### 9.1 Bounded TDD acceptance and existing-plan compatibility — RG-PRC-001…004

Offline tests must include table-driven 18-kind canonical ARN/locator, service/operation/request-shape and declared/independent Scope mapping; CloudFront/S3 account/region-empty ARN handling; forged/mismatched ownership and conflicting scopes; snapshots and API Gateway accountless ARNs; WAF regional/global scope; S3 `s3control.tag_resource` candidate and pinned SDK absence; explicit rejection of S3 `put_bucket_tagging`; multi-key/multi-resource forbidden requests; every Kind's key-only vs tag-set replacement; unsupported/unproven **unsigned** reporting vs invalid **signed** approval rejection; Name inference evidence mismatch; counterfeit/copied issuances; policy-size excess; stale Host/Scope/IAM/receipt and expired token; same-session read/write/readback; pre-Permit zero-Intent refusal; post-Permit unknown no-retry/STOP/HOLD; cross-kind attempt cap and Decimal report reconciliation. Existing volume, OwnerTrust, Batch signature, Phase A and Task 7 regressions remain required.

**Finding 001–004 acceptance additions (no extra independent review loop):** Task 1 proves exact 18-kind pre-sign projection rules and all four global/accountless cases; Task 2 proves `name_tag_batch_state._valid_declared_arn()` and `derive_declared_row_scope()` pass their canonical global/accountless syntax **without** depending on Task 3 Name evidence; Task 3 proves one supported non-Volume Kind's signed Plan→Owner verification→row authority path and CNP unsigned report-only behavior; Task 2/9 prove all 18 pre-cap Count/Decimal totals match the immutable CUR aggregate and signed Plan source, including below-threshold and max-resources-uninspected entries; Tasks 6–8 prove systemd bootstrap failures cause zero Intent/Permit/STS/Write and that CLI/env/UID alone never establish Host authority. Offline success leaves real Host acceptance `NOT_VERIFIED`. **PLAN-004 IPC acceptance:** Task 6 Fake listener/codec validates exact v1 framing, peer and protected bootstrap before the Owner signer and Coordinator; Task 8 Fake CLI verifies no direct Host/SDK invocation, bounded timeouts, errors, no auto-retry and unknown disconnect; Task 7 distinguishes client-only disconnect with durable Readback (no outcome change) from post-Permit missing durable outcome (only the latter gives `OUTCOME_UNKNOWN`/STOP/HOLD). No Host installation or real traffic.

**Existing-plan compatibility:** `docs/superpowers/plans/2026-11-18-aws-cost-name-tagger-batch-implementation-plan.md` remains the historical implementation plan for Tasks 1–7 and the **Volume-first** implementation. This R0.1.x Design adds a *future* single-phase extension, not a retroactive change to the executed Tasks 1–7. A later explicitly approved `writing-plans` output must derive individual TDD steps from §§4–9, bind new interfaces/production Host proofs, note all 18 Kind decisions, preserve existing Plan v3/BatchApprovalV1 semantics, and clearly leave live AWS acceptance outside its done criteria. **The current Implementation Plan is amended together with this Design; the historical Tasks 1–7 plan is unchanged.** A new plan must not silently declare live IAM proof from Fake tests or rewrite existing Plan history.

## 10. Completion Criteria

次をすべて満たすこと。

1. 18種類すべてがRegistryで明示的に扱われる。
2. 各KindのAPI・IAM・Name保護・Readback・副作用について、根拠付きの対応可否が確定する。証拠不足は未検証として正しく扱う。
3. 安全条件が成立するKindについて、本番用Adapterが実装される。
4. Host Issuer、STS、Runtime Policy、CLIの本番用コードが完成する。
5. 不正・欠落・期限切れの証拠では実AWS呼出しを拒否する。
6. Mock/Fakeでの正常・拒否・障害系E2EがPASSする。
7. 全体回帰テストとManifest検証がPASSする。
8. 全18種類の結果を件数・費用・理由付きで報告できる。
9. 実AWS操作は未実施であり、Safety Holdは維持される。
10. 実Host受入に必要な環境依存証拠・未承認事項が明示される。

**Scope of completion:** Design §10の10条件を一切変更しない。Kind実装はRegistryから `IMPLEMENTED_OFFLINE` に到達したものだけを完成として数え、他Kindは安全上の理由と根拠を記録して未対応/未検証のままでもよい。実AWSでの全Kind成功率は完了条件ではない。Production用コード実装完了、保護された実行境界の設計、実Hostでその境界が成立することの証明、実AWS Write成功は**別の判定**である。

不足した実環境証拠を理由に、本番実装コードの完成判定を無制限に延期しない。ただし、実装すべきAdapterや安全ゲートが未完成の場合は、単なる文書上の説明で完了扱いしない。

## 11. Stop Conditions

安全ゲートの迂回、既存Name保護の破壊、署名の弱体化、無制限権限、意図しないタグ集合の置換が必要となる場合は、その経路を停止する。

その他の独立した安全なKindの実装は継続できる。

## 12. Final Deliverable / Human Owner Checkpoint

```text
PRODUCTION_IMPLEMENTATION_COMPLETE
OFFLINE_TDD_PASS
LIVE_ACCEPTANCE_NOT_VERIFIED
SAFETY_HOLD_ACTIVE
AWS_WRITE_BLOCKED
G1_NOT_PROVEN
G2_NOT_VERIFIED
AWS_RUNTIME_NOT_AUTHORIZED
```

実装完了後はHuman Owner Checkpointで停止する。

Commit、Push、PR、Merge、実AWS受入、IAM/Trust変更、Safety Hold解除はそれぞれ別途承認を必要とする。

新規Findingだけを理由に設計・訂正・独立レビューの循環を開始しない。

この文書はDesign R0.1.2案を記録するものであり、未承認の実装Taskを開始するものではない。