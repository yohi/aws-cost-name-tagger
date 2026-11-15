# AWS Cost Name Tagger — Controlled Name Write Design R0.2

- **作成日:** 2026-11-16（JST）
- **リポジトリ:** [yohi/aws-cost-name-tagger](https://github.com/yohi/aws-cost-name-tagger)
- **固定参照:** `master` / `497ad6a3f08e9207f39c92a29dfabc549afa127b`
- **文書状態:** `DESIGN_DRAFT / DOCUMENT_APPROVAL_PENDING`
- **想定配置先（未Commit）:** `docs/superpowers/specs/2026-11-16-aws-cost-name-tagger-controlled-name-write-design.md`
- **作業境界:** 本文書の作成のみ。AWS API呼出、IAM変更、コード変更、Commit/Push/PR、Safety Hold解除を行わない。
- **承認の出所:** 2026-11-16のHuman Ownerとのbrainstormingで決定した方式B・対象C・High/Medium・根拠付き修正・資源単位Fail-Closed・実行別承認、および限定書き込み設計R0.1への承認を入力条件とする。**このR0.2本文自体は未承認。**

## 1. Why / Project Goal Charter

### 1.1 本来の業務目的

既存のコスト分類フローが利用できるよう、AWSで`Name`タグが存在しない／空文字のリソースに、識別子・メタデータ・親子関係等で説明できる適切な`Name`を付与する。**完成の指標はレビュー件数ではなく、承認済みのリソースへNameが実際に付与され、AWS Readbackで検証できた件数・対象コストである。**

ここでいう`Name`はAWSリソースの固有プロパティではなく、タグキー`Name`を指す。

### 1.2 目標（What）

1. 既存の18リソース種別すべてをName候補の検討対象とする（全種別への即時書込を意味しない）。
2. `ABSENT`または厳密な`EMPTY`だけを候補にする。`NONEMPTY`（空白文字も含む）・`UNKNOWN`は書込禁止。
3. High/Medium候補を根拠と不確実性付きで提示し、Human Ownerが値を承認／根拠付きで修正し、最終値を再承認する。
4. Nameの承認とAWS実行承認を分離する。実行承認は特定対象・確定Name・特定主体・一実行だけに有効。
5. 他のName書込み主体を統制でき、サービス別の安全条件が成立する対象だけを、付与直前の再確認を経て更新する。
6. 付与後のReadbackと監査記録で、成功・保留・失敗・結果不明を区別する。

### 1.3 対象外（Non-goals）

- 既存の下流コスト分類、`Product`/aliasマッピング、原価配賦フローの変更。
- G2の一般目的の実行基盤、SAES/RCPの拡張、網羅的IAM/CloudTrail証明プラットフォームの開発。
- Sonar Code Smellを全解消するためのリファクタリングや追加の独立レビュー連鎖。
- 全18種別の一斉書込解禁、Name候補の完全自動承認、判断不能なリソースへの強制命名。
- AWS上の物理HTTP送信が厳密に一度きりであることや、非協調writerとの競合ゼロという証明。

### 1.4 失敗とみなす状態（Anti-goals）

- `Name`の既存非空値やName以外のタグを意図的に上書きする。
- 直前の読み取り成功、CI PASS、文書PASSをもって競合ゼロ・AWS実行承認済みと扱う。
- レビュー用`Y`や古い承認CSVを、そのままAWS書き込み許可とみなす。
- 結果不明のAPI要求を自動再送する、または自動ロールバックで他者の更新を消す。
- 目標未達のまま証拠文書・静的解析・追加レビューだけを増殖させる。

## 2. 現状と再利用する資産

- `aws_cost_name_tagger_v3.py`の`cur_candidates()`はCUR CSV.gzから上限付き候補選択を実施する。
- `Investigator.resolve()`は既存タグ・識別子・関係を読み、`proposed_name`、`confidence`、`evidence`、`write_target`、`name_state`を記録する。
- `plan()`は`schema_version=2`の計画・レビューCSVを作成する。`proposal_key()`は**ローカルレビューID**であり、AWS実行承認ではない。現行の材料には`account`が含まれないため、実行承認用には別のアカウント紐付き識別子を設ける。
- `run --mode y`は対話的な選択を記録するだけで、Name修正入力はまだなく、S3を選択対象から除外する。
- `Investigator.write_name()`と`apply()`は無条件拒否。`SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED`を維持する。
- 既存の非公開ディレクトリ、`O_EXCL`、`O_NOFOLLOW`、`fsync`、監査ジャーナル、AWS読み取り予算を再利用できる。ただし複数ファイル一括公開の電源断原子性は保証されない。
- G1静的再調査は「AWS側原子的なABSENT/EMPTY限定条件付き書込み」を**未証明**としており、今回の低リスク運用方式はG1の従来契約と異なる。旧GateをPASSに変更しない。

## 3. アプローチ比較（Superpowers brainstorming）

| 案 | 内容 | 利点 | 限界・結論 |
|---|---|---|---|
| **A：統制対象への限定書込み** | 他の書込み主体を把握・統制し、Ownerの2段階承認、直前read、単回更新、Readback | 既存実装を最大限再利用でき、本来の目的に進める | 非協調writerが残れば競合ゼロは保証できない。**Owner選択済みの採用案** |
| B：協調ロック/新規Broker | 全参加writerが共通ロックを遵守 | 統制済みwriter間の排他に有用 | AWS Consoleや非協調主体は保護できず基盤開発が目的化する。今回不採用 |
| C：原子的CAS保証があるAPIだけ | タグ更新瞬間の期待状態をAWS側で判定 | 強い非上書き保証 | 既存G1調査では対象APIで保証が確認されず、業務成果が引き続き停止。今回不採用 |

**採用理由:** Aが「Nameを実際に付与する」というGoalに最も近く、リソース単位Fail-Closed・対象限定・明示的Owner承認という既決事項と整合する。Aは旧G1契約への無言の適合宣言ではない。

## 4. ユーザー体験と処理フロー

```text
現行 plan / Investigator.resolve()  [AWS READ ONLY]
  -> 候補セット + 根拠 + High/Medium + Name状態
  -> Owner Nameレビュー（採用・根拠付き修正・却下）
  -> 不変なName承認スナップショット（承認した値を固定）
  -> 別操作：今回の対象・値・identity・残余リスクを表示
  -> Ownerがその1回のAWS実行を明示承認
  -> 実行前の共通ガード（Safety Holdが適用中なら停止）
  -> 各リソース：統制確認／同一性／状態／証拠／API対応可否を再確認
  -> intentを永続記録 -> タグ更新要求（対象1件・Nameのみ）
  -> AWS readback -> 適用成功／拒否／結果不明を永続記録
  -> 結果レポート（下流コスト分類は既存フロー）
```

既存`run --mode y`は**レビュー専用**として維持する。新しい書込コマンド（仮称`execute-approved`）は別に設け、`apply()`の拒否を維持する。名前の「候補承認」を入力しただけで書込コマンドへ進まない。実際のユーザー操作のコマンド名・画面細部は実装段階で決めてよいが、2段階承認は変更不可。

## 5. モジュールと責務

1. **Candidate Provider**: 既存`plan()`と`Investigator.resolve()`を再利用。既存アルゴリズムを一斉に書き直さない。
2. **Name Decision Layer**: High/Medium、元候補、根拠、不確実性を表示。Ownerの値修正、理由、最終再承認を記録。`none`、`UNKNOWN`、`NONEMPTY`は自動選択不可。
3. **Approval Snapshot**: `plan_sha256`と承認対象（Account、Partition、Region、kind、canonical resource ARN、locator、期待Name状態、確定Name、根拠指紋、Owner判断）を固定。変更した名前には新しい承認IDを採番し、以前の承認IDを無効化する。
4. **Single-run Authorization**: Name承認と別に、今回の対象ID集合・Name値・実行Account/Principal・実行コード版・実行回数1・期限/nonceを束ねる。使用済み・期限切れ・値不一致なら拒否。CSVの`approved=YES`や単なるファイルハッシュを本人認証・権限委譲の証拠とはみなさない。
5. **Guarded Executor**: 共通前提、対象ごとの`prepare/read/write/readback`を管理。サービス別adapterをallowlistから選ぶ。未知または未検証サービスは書かずに保留。
6. **Write Intent Journal**: 単一実行の進行・AWS Request ID・Readbackの結果を追記し、各送信前のintentを`fsync`で確定する。クラッシュ時には送信済みか不明な対象を再送しない。複数CSVの原子的公開に実行安全性を依存させない。

**実装境界（提案）:** 既存`aws_cost_name_tagger_v3.py`の読み取り・分類ロジックを極力変更せず、Name承認の拡張と隔離された書き込み側モジュールを追加する。G2モジュールへ実AWS用writerを混入させない。

## 6. 個別承認・実行承認のデータ契約

### 6.1 Name承認レコード（概念スキーマ）

```json
{
  "schema_version": 1,
  "plan_sha256": "<exact-plan-digest>",
  "account": "<12-digit-account>",
  "partition": "aws",
  "region": "<validated-resource-region>",
  "kind": "volume",
  "resource_arn": "<canonical-verified-resource-arn>",
  "locator": "<verified-resource-id>",
  "name_state_at_plan": "ABSENT",
  "confidence": "high",
  "evidence_digest": "<canonical-evidence-digest>",
  "suggested_name": "<original-proposal>",
  "approved_name": "<owner-final-name>",
  "edit_reason": "<required-if-changed>",
  "decision": "APPROVED",
  "owner_decision_reference": "<verifiable-human-decision-reference>",
  "approval_id": "<digest-bound-to-all-fields>"
}
```

このJSONは説明用であり、文字列中の`<...>`はプレースホルダー。Owner本人性の保証方式は実行環境に依存するため、単なる自由入力文字列を強い認証と呼ばない。`account`・Name値・証拠が変更されれば新しい承認が必要。S3などNameを提案できるが書き込めない種別もNameレビューに含められる。

### 6.2 一回限り実行承認

`authorization`は`approval_id[]`、対象ARNとNameの正規化集合のdigest、実行Identity（STS Principal ARNだけで権限が証明されたとは扱わない）、コード版、実行窓、リスク受容・書込み主体統制証拠参照、実行nonceを紐付ける。Ownerに**書く予定の全対象と最終Name**を再表示し、別操作で承認を得る。実行開始前に使用済み状態を永続化し、クラッシュ後に同じ承認を再実行しない。承認した一部対象が失敗しても別対象へ自動的に拡張しない。

## 7. 安全性の規範

### 7.1 Name状態と識別子

- `ABSENT` / 厳密な`EMPTY`だけが処理候補。`" "`、`"\t"`を含む`NONEMPTY`は絶対に意図的更新しない。
- `Name`と大文字小文字だけ違うキー、重複タグキー、未取得タグページ、取得失敗は`UNKNOWN`で保留。
- Account、Partition、Region、ARN、個別IDをAPIレスポンス・承認スナップショットと一致照合する。Regionを持たないS3やGlobalサービスではサービス別の正規化規則を適用し、曖昧なら停止。
- Nameの文字集合・長さ・命名規約はサービス別に事前検証。Owner修正は識別根拠の補強であり、AWSタグ制限や承認済みリソース集合の逸脱を許さない。
- 対象の識別情報やName推定根拠が承認時から変わった場合、その対象は失効・保留（自動的な新候補への差替えなし）。

### 7.2 「他のwriterを統制できる」の条件

対象ごと、または独立に証明可能な対象群ごとに、少なくとも次を確認する。

1. Nameを更新し得るAWS Console利用者、IaC（CloudFormation/Terraform等）、CI/CD、Lambda・他の自動化、AWSサービス側のタグ伝播などの候補を洗い出す。
2. 予定実行窓でそれらを停止／制限できることを、人間が確認可能な事実に紐づける。実効IAM/SCP/RCPや運用上の変更凍結の**適用範囲と限界**を明示する。
3. 対象の管理責任者と実行Identity、実行可能時間帯、変更凍結の維持方法、解除手順を記録する。統制できない主体が1つでも想定されれば、対象を`BLOCKED_WRITER_CONTROL`にする。
4. 通信エラーや停止時に統制が失われた場合、影響する未実行対象の書込を停止する。他の独立した対象には伝播させない。

**残余リスク:** 実行直前のName読み取りと更新は原子的操作ではない。未知のwriter、管理者権限、AWS内部の反映遅延等があれば、他者のNameを結果的に上書きする可能性が残る。リスクを明示し、統制確認なしにゼロリスクと主張しない。`aws:TagKeys`はタグキー制約であり、比較条件付き更新の証明ではない。

### 7.3 サービス別Adapterの許可条件

- `read_tags`が完全・一意・権限付きにName状態を読める。
- `write_name_only`が既存のName以外のタグ集合を変更しないAPI要求である。送信ペイロードは原則`Name`1キー、対象リソース1件に限定。
- `readback_tags`で同一対象のNameを再取得できる。API戻り値だけで成功と断定しない。
- 操作名・SDKモデル・IAMアクション・リソースARN・Global/Regionalの差異はadapterごとに固定し、未確認なら該当種別を`WRITE_UNSUPPORTED`にする。
- タグ集合を置換するAPIは、他タグの競合喪失リスクがあるため初回の許可対象外とする。

#### 候補18種別と初期書込み状態

| Kind | 候補生成 | 書込みadapterの候補 / 追加条件 | 初期状態 |
|---|---|---|---|
| `instance` | 既存 | EC2 `CreateTags`、ASG/CFn所属と実行窓を確認 | 未有効化 |
| `volume` | 既存 | EC2 `CreateTags`、EBS owner/device一意性 | 未有効化 |
| `snapshot` | 既存の保留判定 | 作成時点の所有関係の根拠が不足しやすい | **推定不成立なら保留** |
| `eni` | 既存 | EC2 `CreateTags`、EC2 Attachment・DeviceIndexを再確認 | 未有効化 |
| `eip` | 既存 | EC2 `CreateTags`、割当・関連付けを再確認 | 未有効化 |
| `nat` | 既存 | EC2 `CreateTags`、関連ネットワーク情報を再確認 | 未有効化 |
| `endpoint` | 既存 | EC2 `CreateTags`、VPC/SubnetのName関係を再確認 | 未有効化 |
| `rds_cluster` | 既存 | RDS `AddTagsToResource`、クラスタID/ARN照合 | 未有効化 |
| `rds_instance` | 既存 | RDS `AddTagsToResource`、クラスタメンバー照合 | 未有効化 |
| `opensearch` | 既存 | Serviceのタグ追加APIとARN/ドメイン照合 | 未有効化 |
| `elbv2` | 既存 | ELB `AddTags`、LB ARN/Type照合 | 未有効化 |
| `apigw_stage` | 既存 | API Gateway `TagResource`、親APIとStageの**直接タグ／継承タグ**を区別する | 未有効化 |
| `cloudfront` | 既存 | CloudFront `TagResource`、Global ARN/Origin照合 | 未有効化 |
| `athena_workgroup` | 既存 | Athena `TagResource`、全タグページが読み切れていること | 未有効化 |
| `log_group` | 既存 | CloudWatch Logs `TagResource`、完全ARN照合 | 未有効化 |
| `lambda` | 既存 | Lambda `TagResource`、Function ARN照合 | 未有効化 |
| `wafv2` | 既存 | WAFv2 `TagResource`、Global/Regional scope・ARN・全ページ照合 | 未有効化 |
| `s3_bucket` | 既存（現行Yから除外） | S3 Control `TagResource`の利用可否・bucketのABAC/操作条件を**個別確認**。`PutBucketTagging`は既存タグ集合を全置換するため禁止 | **API未確定なら書込保留** |

「未有効化」は書き込めると証明された意味ではない。18種類は**Name候補の網羅範囲**であり、adapterの選定・受入は各対象の安全条件に従う。未実装のadapterを理由に既存の`plan`を停止しない。

### 7.4 一回限り送信と状態不明

- SDKの通常自動retryは無効。書込みは1リソースにつき一つの明示的な更新要求のみ。送信・受理・変更の「物理的なexactly-once」を保証するとは記載しない。
- **送信前に**`WRITE_INTENT_RECORDED`を耐久記録し、`fsync`失敗なら送信禁止。クラッシュ・timeout・応答不明は`OUTCOME_UNKNOWN`として再送禁止。
- `Readback`で確定Nameが一致すれば`APPLIED_VERIFIED`とできるが、他者の中間更新がなかったことまでは証明しない。結果不一致や読取不能は成功扱いせず保留。
- 自動復旧・自動ロールバックは行わない。Ownerが現況を確認して新しい計画と新しい承認で対処する。

### 7.5 リソース単位Fail-Closedと共通停止

| 失敗・差異 | 扱い |
|---|---|
| ある対象のNameがNONEMPTY・UNKNOWN、証拠差分、更新不可 | 対象のみ`BLOCKED_RESOURCE`、他の独立対象は継続可能 |
| 対象の書込API timeout、応答不明、Readback不一致 | 対象のみ`OUTCOME_UNKNOWN`/`FAILED_READBACK`、**再送禁止** |
| 実行Identity/Account不一致、承認集合改ざん、監査ジャーナル書込不能 | 関連する実行全体を停止 |
| 他writerの統制喪失、対象群に共通する権限/設定異常 | **影響する対象群**を停止。無関係な対象群は条件を再確認できれば継続可能 |
| すでに更新成功した対象 | 自動ロールバックしない。結果と残余リスクを保持 |

## 8. 実行状態と監査

```text
PROPOSED -> NAME_APPROVED -> EXEC_AUTHORIZED
  -> PRECHECK_PASSED -> WRITE_INTENT_RECORDED
  -> WRITE_REQUEST_ATTEMPTED -> READBACK
  -> APPLIED_VERIFIED
  |  BLOCKED_RESOURCE / BLOCKED_SCOPE
  |  FAILED_WRITE / FAILED_READBACK / OUTCOME_UNKNOWN
```

- 必須監査：承認前後のName、理由、根拠参照、候補ID、承認ID、実行許可ID、Account/Principal、対象ARN、Name状態、AWS operation、AWS request ID（取得できた場合）、時刻、Readback観測値、エラー分類。
- 機密情報・認証トークンをログに出さない。既存のprivateディレクトリの保護と排他的ファイル操作を維持する。
- 実行の重複防止には権威あるローカル単一writer台帳を使う（同一ホスト・信頼されたUIDの範囲）。別ホスト/複数operator/同一UID敵対者を完全排他する設計には拡張しない。それらを統制できないなら初回実行対象から除外する。
- Read予算・時間予算の不足が見込まれる場合は送信前に停止。実行中のdeadlineは物理HTTP処理の厳密な期限ではない。

## 9. セキュリティGateとOwner決定

- **現行の規範状態:** `G1_NOT_PROVEN / G2_NOT_VERIFIED / SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED`。
- 本設計Aは「統制された他writer＋残余競合リスク受容」を前提とし、旧G1の**AWS側原子的条件付き更新**を証明するものではない。
- Designの承認、実装の受入、AWS実行承認は別の行為。Design承認だけで`write_name()`/`apply()`を有効化しない。
- 既存の厳格G1/G2ポリシーと矛盾する本方式の実運用には、Human Ownerが**対象・安全代替条件・残余リスクを明記した限定的な規範更新／適用例外**を別途明示決定する必要がある。未決定なら書込みはFail-Closed。旧記録のG1/G2を虚偽のPASSに書き換えない。
- 実装はAWS資格情報なしのmock/stubで先行できる。実AWSへのread-only接続も別の明示的な許可なしに開始しない。

## 10. エラー・テスト・受入条件

### 10.1 最小のオフライン受入テスト

1. ABSENT・EMPTYだけ候補、NONEMPTY（スペース含む）・UNKNOWN・case variant・ページ未取得を拒否。
2. High/MediumはOwner個別承認対象、`none`は候補承認できない。修正Nameには理由・再承認が必須。
3. Account/ARN/Regionの差異、旧plan、証拠差異、修正済Nameの旧承認流用、別principal/未使用に見せた使用済grantを拒否。
4. Name承認だけ、`run --mode y`、従来`apply`で**write API呼出ゼロ**。
5. 偽のwriter統制証拠／TTL切れ／統制喪失の場合はその対象群の書込ゼロ。
6. サービス別APIをmock化し、Name以外のタグを変更しない。S3全タグ集合上書きとAPI Gateway継承タグの取り違えを拒否。
7. 更新前の実際のNameがNONEMPTY、UNKNOWN、別リソース、関係変化なら、その対象を書かない。
8. intent永続化失敗では送信ゼロ。timeout/5xx/クラッシュ相当のunknown outcomeで同一承認を自動再送しない。
9. Readback一致／不一致／読み取り失敗を区別。別リソースの失敗は独立対象に影響しない。
10. 共通Identity不一致・台帳異常では影響実行全体を停止。

### 10.2 本来の業務目的での完了条件

- **候補精度:** 既存18種別を候補検討対象とし、根拠・信頼度・保留理由を説明できる。
- **レビュー完結:** High/MediumのNameをOwnerが編集・承認し、変更値が後続の実行対象に正確に保持される。
- **限定実行の安全性:** 実行対象・Identity・writer統制・書込みAPIが承認条件に一致する場合に限り、対象1件ずつ安全に実行できる。既存Nameの偶発的競合上書きの残余リスクは明記する。
- **結果の実証:** 別途明示承認された初回AWS実行では、少なくとも1件の`APPLIED_VERIFIED`をAWS Readbackで確認する。成功できない場合はSTOP理由を残し、架空の成功を報告しない。
- **成果測定:** Name未設定リソース数、提案率、承認率、適用検証率、対象コスト（金額は利用可能なCUR範囲のみ）を報告し、下流分類処理を再開発しない。

### 10.3 停止条件

現行のSafety Holdが有効、正式な限定リスク受容がない、writer統制が不明、リソース/Name状態が不明、service adapter未対応、Owner承認不備、実行Identityが異なる、監査台帳が安全に維持できない場合は**AWS書込み経路だけを停止**。安全なオフライン候補生成とNameレビューは継続できる。

## 11. 残余リスク・未決事項・次の判断

| 項目 | 状態と処置 |
|---|---|
| 非協調writerと更新タイミング競合 | **残余リスク**。初回は統制可能対象に限定。ゼロ保証と表記しない |
| サービス別更新APIの実用可否 | **未検証**。対象種別のadapterごとに限定確認。確認できなければ当該資源のみ保留 |
| 既存G1/G2規範との適合 | **規範更新/限定例外が別途必要**。Design承認とは区別 |
| Owner本人性/承認ログの信頼性 | **実行環境依存・方式未確定**。自由入力やSHA-256だけを本人証明にしない |
| 監査のクラッシュ安全性 | ローカル同一ホスト/信頼UIDの範囲に限定。物理送信exactly-onceではない |
| 実際のAWS許可・初回対象 | **未承認**。実行許可を要する。ドキュメント段階で実AWS証拠と混同しない |

**本設計の停止地点:** この文書のHuman Owner承認。承認後も、実装計画の作成・コード変更・AWS操作・IAM変更・CI実行・PR作成・Gate解除を自動開始しない。次の作業はHuman Ownerが範囲を指定したときのみ進める。追加のFindingが生まれただけで新しいレビュー/訂正ループに進まない。

## 12. 参照

- [現行コード（固定HEAD）](https://github.com/yohi/aws-cost-name-tagger/blob/497ad6a3f08e9207f39c92a29dfabc549afa127b/aws_cost_name_tagger_v3.py)
- [README（固定HEAD）](https://github.com/yohi/aws-cost-name-tagger/blob/497ad6a3f08e9207f39c92a29dfabc549afa127b/README.md)
- [G1静的再調査](https://github.com/yohi/aws-cost-name-tagger/blob/497ad6a3f08e9207f39c92a29dfabc549afa127b/docs/gates/G1_NATIVE_NAME_TAGGING_STATIC_RECHECK_R2_2026-10-22.md)
- [G2実装準備評価](https://github.com/yohi/aws-cost-name-tagger/blob/497ad6a3f08e9207f39c92a29dfabc549afa127b/docs/gates/G2_I1B_IMPLEMENTATION_READINESS_ASSESSMENT_R1_2026-10-24.md)
- [AWS EC2 CreateTags](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTags.html)
- [AWS IAM aws:TagKeys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- [AWS S3 PutBucketTagging](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html)
- [AWS S3 Control TagResource](https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_TagResource.html)
- [API Gateway Stageタグ継承](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-tagging-supported-resources.html)
- [Superpowers brainstorming skill](https://github.com/obra/superpowers/blob/main/skills/brainstorming/SKILL.md)
