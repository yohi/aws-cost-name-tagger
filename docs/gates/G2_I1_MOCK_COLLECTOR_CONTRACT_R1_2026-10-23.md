# G2-I1 — Offline Mock Collector Contract and Coverage (R1)

**基準日:** 2026-10-23（JST）  
**Base:** `master f0fa1dbacdc5e3f5cba0cc3be5cc12e795e0ad74`  
**依存規範:** `docs/gates/G2_OFFLINE_EVIDENCE_BUNDLE_CONTRACT_R1_2026-10-22.md`（本文R1.1）  
**状態:** **MOCK CONTRACT IMPLEMENTED / REAL AWS ADAPTER NOT IMPLEMENTED / NOT AN EXECUTION GRANT**  
**Gates:** G1 NOT PROVEN; G2 NOT VERIFIED; Evidence Acquisition NOT EXECUTED; AWS WRITE BLOCKED.

## 1. 実装境界

`g2_collector_contract.py` はAWS SDK、ソケット、HTTPクライアントをインポートせず、ネットワーク／ストレージを操作しない。AWS実アカウントに対するアクセスを実行するコードは**含まれない**。

- `build_plan(account, regions, start_utc, end_utc)`：明示的な12桁アカウント、重複しない最大8リージョン、90日以内かつUTCのイベント期間から、限定された取得計画を構築。
- `FixturePort`：**合成辞書レスポンスだけ**を順番に返す、ネットワーク機能のないモック。実SDK・独自サブクラスの注入は `run_simulation` で拒否。
- `run_simulation`：STSの合成identityが対象アカウントに一致するまでは、他サービスのprobeを実行しない。各結果は非機密のメタデータとページSHA-256だけを返す。
- IAM `IsTruncated` / `Marker` と、Organizations・Identity Center・CloudTrailの `NextToken` は**異なるページ規則**として扱う。空ページでも次トークンがあれば継続し、重複・不足・不正トークン・4ページ上限は`PARTIAL`または`UNKNOWN`（Fail Closed）。
- 開始・終了のSTSおよびIAM照合を模擬。IAMページハッシュが異なる場合は`INCONSISTENT`、一致しても`SIMULATED_IAM_MATCH_ONLY`に限定し、原子的なスナップショットやABA非発生を証明しない。
- 応答にはAWSからのRAW、IAMポリシー本文、CloudTrailイベント詳細を出さず、ハッシュと収集区分・模擬ステータスのみを持たせる。仮の資格情報らしいキーを含むfixtureは拒否する。

### 既定で許可する**合成実行対象**（実AWSに問い合わせるわけではない）

| Evidence | 模擬API | 収集範囲の限界 |
|---|---|---|
| STS pre/post | `GetCallerIdentity` | 合成Account検証のみ。実効ReadOnly証明にならない |
| G2-A01 | IAM `GetAccountAuthorizationDetails` | 全IAM管理ポリシーのdefault version取得・role trustと権限継承グラフは未構築 |
| G2-A03 | Organizations `DescribeOrganization`, `ListParents`, `ListPoliciesForTarget`（SCP/RCP） | **対象アカウントへ直接**付与されたpolicyと直近parentのみ。OU/rootへの継承やpolicy本文は**未取得** |
| G2-A02a | IAM Identity Center `ListInstances` | Permission Set、Account Assignment、Identity Storeの連結は未実装 |
| G2-A05 Event History | CloudTrail `LookupEvents` | 90日上限で、指定リージョン・期間のみ。Event History全件を保証しない |
| G2-A05 Trail S3 | CloudTrail `ListTrails` | Trail設定一覧のみ。配信S3ログ原本、digest、selector、時刻境界は未取得 |
| G2-A05 Lake | CloudTrail `ListEventDataStores` | Store一覧のみ。Lakeクエリ `StartQuery` は**対象外** |

`GetObject`、`StartQuery`、IAM変更・タグ変更・リソース作成の操作は全て非許可。合成レスポンスの `pagination_complete=true` は**モック内のトークンが終端したことだけ**を意味し、実AWS取得のCOMPLETEとは無関係。

## 2. 残留するG2 R1.1ギャップ

- Identity CenterのPermission Set、ユーザー・グループ、Account Assignments、権限セットに対応するrole、外部IdPおよびSTSセッションポリシーはUNKNOWN。
- SCP/RCPのOU/root継承、Organizations管理アカウント等による確認、各policy本文、リソースベースpolicyやIAM権限境界の実効評価は未実施。
- CloudTrailは**Event History / Trail配信S3原本 / 既存Lake**を別系統として管理する必要があるが、I1は各系統の存在・イベント取得の一部しか模擬していない。重複・欠損・配送遅延の統合評価は未実装。
- 既存58件のNameタグ状態、API GatewayのABAC継承タグ、IaC・自動化・他writerの完全な調査は未実装。
- IAM以外のBEGIN/END状態照合、収集中変更・ABA、スナップショット整合性の証明は未実施。
- **I0の`raw_secure/`と連結しない。** I0のManifestは`OFFLINE_USER_SUPPLIED_UNVERIFIED`として固定されており、合成Collectorの結果を`AWS_VERIFIED`とするインポート機能は意図的に存在しない。

## 3. テストとレビューの条件

`python -m unittest -v test_g2_collector_contract`は、アカウント不一致での停止、IAMの二段階ページング、空ページを伴うOrganizationsページング、AccessDenied、反復トークン、4ページ上限、IAMスナップショット差分、未知の取得元・秘匿フィールドの拒否などを合成fixtureで検証する。

G2専用CIはI0テストとこのI1テストを結合し、双方のモジュールに対してAWS SDK／ネットワークモジュールの直接importを禁止する。既存Safety Hold CI、既存タグ処理、`SHA256_MANIFEST.json`は変更しない。

**次のI1-B/I2の実作業**には、AWSの認可済み読み取りアダプター、収集期間・対象・保存先の正式Owner判断、STS本人性、SCP等の権限範囲、各サービスのAPI出力フォーマットと完全ページング、AWS原本保護、BEGIN/END再照合、I0 Manifestとの厳格な接合、独立レビューが必要。実AWSの収集は現PRの範囲外とする。

## 4. 公式APIの根拠

- [IAM GetAccountAuthorizationDetails — IsTruncated/Marker](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [Organizations ListPoliciesForTarget — empty pageでもNextToken継続](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPoliciesForTarget.html)
- [IAM Identity Center ListAccountAssignments — NextToken](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListAccountAssignments.html)
- [CloudTrail LookupEvents](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)

**結論:** I1で実装したのは「AWS実証」の代用ではなく、読み取り契約における失敗・不完全・競合の判定を模擬し、AWS接続前に検証できるモック基盤のみ。
