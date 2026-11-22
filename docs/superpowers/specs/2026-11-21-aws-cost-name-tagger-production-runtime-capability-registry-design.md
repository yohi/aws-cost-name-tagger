# AWS Cost Name Tagger — Production Runtime Completion Design R0.1

- Date: 2026-11-21 (JST)
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

S3 Bucketのようにタグ集合全体を置換するAPIについては、他のタグを変更しないことを保証できなければ、書き込み禁止とする。Read→Merge→Writeだけで原子的な既存タグ保護が成立するとは見なさない。

## 5. Shared Security Runtime

OwnerTrust、Batch Approval、Scope、Ledger、Permit、Issuerは共通化する。

Host-only Credential Issuerは、実STSの要求・応答、正確なPolicy bytes/hash、対象ARN、Session identity、期限、資格情報の来歴を保護された同一Host境界内で束縛する。

Pre-send Read、Write、Readbackには同じIssuedBatchSessionを使用する。

Ambient credentials、未検証のSession、コピーしたreceipt、任意に生成したRuntime Policyは拒否する。

Runtime Policyは信頼済みHostの検証処理からのみ発行可能にする。実効IAMの証拠がない場合、発行・書き込みを拒否する。

Session Policyだけを実効IAMの完全な証明としない。Python上のオブジェクト識別子、dataclass、Booleanだけで実Host信頼を証明しない。

資格情報の生値をLedgerやログに永続化しない。

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

この文書はDesign R0.1案を記録するものであり、未承認の実装Taskを開始するものではない。
