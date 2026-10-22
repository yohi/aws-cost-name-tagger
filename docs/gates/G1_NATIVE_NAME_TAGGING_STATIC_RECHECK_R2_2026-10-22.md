# G1 — Native Conditional Name Tagging / Fresh Static Feasibility R2

**調査日:** 2026-10-22（JST）  
**Repository / 固定基準:** `yohi/aws-cost-name-tagger` / master `2e8f048a81366849b7324a3fa25739a72332b347`  
**規範:** `aws_cost_name_tagger_write_architecture_r1_1.md`（原文はv3.5に言及するが、現在の実装はv3.6）  
**区分:** 公式公開仕様の再確認に基づく技術調査。正式Reviewer/Owner/Gate判定ではない。  
**AWS実環境アクセス・API書込・IAM変更・ソース変更:** なし。  
**結論:** **G1 = NOT PROVEN / AWS WRITE = BLOCKED / SAFETY HOLD 継続**

## 1. 固定した不変条件

- **INV-N01:** `Name` が未存在 `ABSENT` または**厳密に空文字** `EMPTY` の場合に限って候補とし、タグ更新が行われる瞬間にもその条件が成立することを**AWSサービス側の原子的保証**（または全writerを支配する検証済み同等保証）として証明しなければならない。
- `NONEMPTY` は空白だけを含む場合もすべて上書き禁止、`UNKNOWN` も拒否。
- `Name` 以外のタグ値とキーは変更不可。個々のARN・Name値・操作・承認は1対1。レビューCSVの `Y` はAWS書き込み許可ではない。
- 二重read、`DryRun=True`、IAM policy simulator、CloudTrail監査、DynamoDBロックだけでこの条件を満たしたと判断しない。
- **v3.6**では `Investigator.write_name()` と `apply()` が無条件に書き込みを拒否する。R1.1の「現行v3.5」記述は歴史的注記であり、実装状態としては古い。

## 2. 条件付き書込として必要な操作契約

`WriteName(ARN, proposed_name, expected_name_state)` が以下を満たす必要がある。

| 書込瞬間のName状態 | 期待する結果 |
|---|---|
| ABSENT | 他者の非空Nameを消さずにName追加可能 |
| EMPTY（キーあり値`""`） | 同じく変更可能 |
| NONEMPTY（`" "`等を含む） | **拒否、値不変** |
| UNKNOWN | **拒否、値不変** |
| read後に別writerがABSENT/EMPTY→NONEMPTY | **原子的条件不一致として拒否** |
| read後に別writerがNONEMPTY→EMPTY | 承認根拠の再検証なしの書込禁止 |
| 応答不明・通信中断 | 自動再試行禁止。G3のOUTCOME_UNKNOWNへ |

核心は「IAM認可時に現在値を見られる」ことではなく、**更新と同一の原子境界で期待条件を評価している**こと。

## 3. サービス別 API 公開契約の再確認

対象件数は**前回のv3.6ドライラン解析R1から引用**したものであり、今回AWS再取得や計画ファイルの再生成はしていない。前回は全118件、提案58件（ABSENT=58、EMPTY=0、NONEMPTY=60、UNKNOWN=0）。EMPTYについてはAWS現物の証拠がまだない。

| ID | 候補（前回） | 既存リソースのAPI | 確認できた上書き挙動 / 原子的CAS根拠 | G1 |
|---|---:|---|---|---|
| S01 EC2/EBS volume | 28 | EC2 `CreateTags` | AWS公式APIに「同じkeyの値を上書き」と明記。要求にexpected tag state / `If-Match`がない | NOT PROVEN |
| S02 RDS Instance | 12 | RDS `AddTagsToResource` | 同じkey追加で旧値を上書き。CAS/期待値パラメータ未確認 | NOT PROVEN |
| S03 ELBv2 | 6 | ELB `AddTags` | 同一keyは値を更新。CASなし | NOT PROVEN |
| S04 CloudFront | 4 | CloudFront `TagResource` | 付与APIあり。タグ用`If-Match`・期待値パラメータなし（公開構文からの限定判定） | NOT PROVEN |
| S05 S3 general purpose bucket | 4 | S3 `TagResource` / 旧 `PutBucketTagging` | `TagResource`は既存タグ更新が可能。`PutBucketTagging`は全タグ集合を置換。どちらもABSENT/EMPTY限定CASなし | NOT PROVEN |
| S06 Athena workgroup | 1 | Athena `TagResource` | 既存keyの値を上書きすることが公式に明記 | NOT PROVEN |
| S07 CloudWatch Logs log group | 1 | Logs `TagResource` | 既存keyは値置換と明記 | NOT PROVEN |
| S08 WAFv2 | 1 | WAFv2 `TagResource` | タグAPIは存在。期待状態に対するCAS契約は確認できない | NOT PROVEN |
| S09 API Gateway stage | 1 | API Gateway `TagResource` | 追加も更新もできる。`ConflictException`はNameの期待値不一致を保証しない | NOT PROVEN |
| **合計** | **58** | | **原子的なABSENT/EMPTY限定保証が確認できたサービス: 0/9** | **BLOCKED** |

**注意:** 「公開契約が確認できない」ことは「AWS内部で原理的に不可能」という証明ではない。9件はAPI種別の行数であり候補リソースは58件。EC2インスタンス、RDSクラスター、OpenSearch、Lambdaなど、前回候補外の種別はこの58件向けの実行対象に加えない。

### 特に注意すべき更新

- S3一般用途バケットは `TagResource` / `UntagResource` / `ListTagsForResource` を提供する。旧`PutBucketTagging`の集合上書きを避けられても、`TagResource`による**同一Nameキーの値の上書き**が可能なのでG1は変わらない。
- S3の`aws:ResourceTag/`条件によるABACは、一般用途バケットでABAC有効化が必要な場合がある。ABACの利用可能性とCAS保証を混同しない。
- API Gateway Stageは親REST APIのタグを継承し、直接設定のタグが優先される。現在値と観測先を定義せずに「未設定」と断定しない。

## 4. IAM条件・外部ロックを使う案の評価

| 案 | 有効なこと | このGateで不足すること |
|---|---|---|
| `aws:TagKeys` | 送信タグキー制限 | 書込前の既存Name状態を守らない |
| `aws:RequestTag/Name` | 送信するName値の制限 | 既存Nameの比較条件ではない |
| `aws:ResourceTag/Name` + `Null` | **認可時**のタグコンテキスト条件の候補 | サービス／アクションのサポート、ABSENTとEMPTYの区別、更新との原子的直列化が未証明 |
| Deny / SCP / Tag Policy | 一部主体の書込制約 | 管理者・サービス主体を含む全writer統制がG2未証明。CAS契約は作れない |
| 事前read × 2、短期TTL | 誤操作の確率低減 | 最終readからタグ書込まで競合できる |
| 外部Broker / DynamoDB条件付きロック | 協調するwriterの排他 | ロック不参加のAWS Console/IaC/サービスを排除できない |
| CloudTrail / AWS Config | 事後検出と証拠採取 | 既存Nameを一瞬たりとも上書きしない保証にはならない |
| Resource Explorer/Tag Editor一括操作 | UIで複数資源をタグ付け | 既存タグ値の更新を防止するCASではない |
| リソース新規作成時のタグ付与 | 新しく作る資源の命名ポリシー改善 | **既存58件のName補完**の原子的問題を解かない |

IAM `Null` は認可コンテキスト内にキーが存在するかを評価する。なお IAM 条件キー名の大小文字と実タグキーの区別に注意し、`Name` / `name` / `NAME` の混在はUNKNOWN扱いで拒否する。原子的安全性を説明する仮想ポリシーJSONは**この調査の採用仕様としては提示しない**。

## 5. G1の反証可能な受入証拠

| Evidence | PASSに必要なもの | 現状 |
|---|---|---|
| G1-P01 API契約 | ABSENT/EMPTYを独立に扱う、タグ更新と同一の原子的前提条件がAWS公式に記載 | **NOT PROVEN** |
| G1-P02 対応サービス表 | リソースkind、API version、要求条件、条件違反時のエラーまで固定 | **NOT PROVEN** |
| G1-P03 レース | 別writerがread後に非空Nameを設定しても確実に保護される実証 | **NOT TESTED** |
| G1-P04 非協調writer | Console、IaC、別IAM主体、サービス主体、作成時タグ伝播の対象全体 | **G2依存** |
| G1-P05 非Name不変 | 同じ要求で他タグが維持される | 部分的（API仕様のみ） |
| G1-P06 障害・再試行 | timeout/5xx/不明時、同一変更の再送なし | G3/G4依存 |
| G1-P07 独立判定 | 公式契約・実証・Owner Gate承認 | **PENDING** |

**提案:** G1-P01の公開契約が取れない間は、実AWSに書込実験してもG1をPASSとしない。試験環境で偶然一度競合を回避できたことは契約上の保証の代用にならない。AWS Support等の一次回答や将来のAPI追加は「証拠候補」だが、文書化・独立検証まではNOT PROVEN。

## 6. 意思決定の分岐（Owner決裁ではない）

- **A. 厳格保証維持（現行の推奨）:** v3.6読取・提案・レビューを継続。書込は永久に自動復活させない。安全なCAS契約が確認できたサービスだけ将来個別Gate再審査。
- **B. 運用上の低リスクへ要件変更:** 事前read／人間承認／監査等により**上書き確率を下げるがゼロ保証はない**別仕様を新規提案。要件緩和の明示的Owner決裁と別のG1再定義なしには採用しない。
- **C. 命名ソースをIaC／作成時付与へ移す:** 将来新規リソースに有効な設計。ただし既存58件は未解決のまま。

G2を深掘りすることは重要だが、**G2が完了してもG1の未証明を自動的に解消しない。**

## 7. 一次資料（2026-10-22の公開文書確認）

- [EC2 CreateTags](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTags.html)
- [RDS AddTagsToResource](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_AddTagsToResource.html)
- [RDS / Aurora resource tagging](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.html)
- [ELB AddTags](https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AddTags.html)
- [CloudFront TagResource](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_TagResource.html)
- [S3 TagResource](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_TagResource.html)
- [S3 PutBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html)
- [S3 bucket tagging / ABAC](https://docs.aws.amazon.com/AmazonS3/latest/userguide/buckets-tagging.html)
- [Athena tagging](https://docs.aws.amazon.com/athena/latest/ug/tags.html)
- [CloudWatch Logs TagResource](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_TagResource.html)
- [WAFv2 TagResource](https://docs.aws.amazon.com/waf/latest/APIReference/API_TagResource.html)
- [API Gateway TagResource](https://docs.aws.amazon.com/apigateway/latest/api/API_TagResource.html)
- [API Gateway tagging/inheritance](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-tagging-supported-resources.html)
- [IAM condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
- [IAM tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html)
- [DynamoDB conditional writes: scope is DynamoDB items](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html)
- [Resource Explorer bulk tagging](https://docs.aws.amazon.com/resource-explorer/latest/userguide/managing-resources.html)
- [CloudFormation tagging](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-resource-tags.html)

## 8. 作業境界

本書を追加しても G1 GateはPASSしない。既存の `aws_cost_name_tagger_write_architecture_r1_1.md` の規範を変更せず、`write_name()` /`apply()`を一切変更せず、AWSへタグ操作を一切実行しない。
