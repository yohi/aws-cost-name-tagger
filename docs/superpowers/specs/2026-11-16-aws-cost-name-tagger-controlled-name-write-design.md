# AWS Cost Name Tagger — Controlled Name Write Design R0.2.1（限定訂正案）

- **作成日:** 2026-11-16（JST）
- **リポジトリ:** [yohi/aws-cost-name-tagger](https://github.com/yohi/aws-cost-name-tagger)
- **固定参照:** `master` / `497ad6a3f08e9207f39c92a29dfabc549afa127b`
- **文書状態:** `DOCUMENT_REMEDIATION_DRAFT / HUMAN_OWNER_CHECKPOINT_PENDING`（R0.2採択・規範変更・AWS実行は未承認）
- **Reviewed HEAD:** `a1204ff0223ff5e36dfc987fade1c530be2a1c0e`（対象Design R0.2を固定）
- **反映対象パス:** `docs/superpowers/specs/2026-11-16-aws-cost-name-tagger-controlled-name-write-design.md`（このR0.2.1案は未Commit・未Push）
- **作業境界:** ACT-RG-F001〜F004の**オフライン文書限定訂正案**。AWS API呼出、IAM変更、ソース変更、Commit/Push/PR、Safety Hold解除は禁止。
- **承認の出所:** 2026-11-16のHuman Ownerとのbrainstormingで決定した方式B・対象C・High/Medium・根拠付き修正・資源単位Fail-Closed・実行別承認、および限定書き込み設計R0.1への承認を入力条件とする。**本Design R0.2/R0.2.1自体の採択、旧規範の更新、AWS実行は未承認。**

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
  -> 信頼済みOwner署名を検証できるName承認スナップショット
  -> 別操作：単一ARN・確定Name・identity・残余リスクを表示
  -> Ownerがその1 ARN / Name / 操作への実行承認を別署名
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
3. **Approval Snapshot / Owner認証（ACT-RG-F001）**: `plan_sha256`と単一ARNの承認対象（Account、Partition、Region、kind、canonical resource ARN、locator、期待Name状態、確定Name、根拠指紋、Owner判断）を固定し、**Owner登録済み署名鍵による署名**を検証する。Name修正時は内容とIDを更新し、旧署名を無効化する。署名がなくてもレビュー用候補は作れるが、実行対象にはできない。
4. **Single-run Authorization（ACT-RG-F001/F003）**: Name承認と別のOwner署名で、**1 ARN＋1 Name値＋1 AWS操作**、承認ID、実行Account/Principal、実行コード版、実行回数1、期限/nonceを拘束する。使用済み・期限切れ・値不一致なら拒否。旧`INV-N05`に従い複数ARNをまとめる実行許可は**規範変更が別途承認されるまで禁止**。CSVの`approved=YES`、自由入力、ファイルハッシュ、STS呼出結果だけをOwner認証・権限委譲の証拠とはみなさない。
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
  "owner_decision_reference": "<audit-reference-not-authentication>",
  "owner_principal_id": "<enrolled-owner-id>",
  "owner_key_fingerprint": "<pinned-approved-public-key-fingerprint>",
  "issued_at_utc": "<utc-timestamp>",
  "expires_at_utc": "<utc-timestamp>",
  "decision_nonce": "<unpredictable-unique-nonce>",
  "approval_id": "<digest-of-canonical-signed-payload>",
  "signature_ref": "<detached-owner-signature>"
}
```

このJSONは説明用であり、文字列中の`<...>`はプレースホルダー。`signature_ref`は署名対象ペイロードから除外したdetached署名参照とする。`approval_id`は署名対象を識別するdigestであり、それ自体は認証ではない。`account`・Name値・証拠が変更されれば新しいOwner署名が必要。S3などNameを提案できるが書き込めない種別もNameレビューに含められる。

**本人確認・作成/検証権限の採用方式（ACT-RG-F001）:** 新規Brokerやクラウド認証サービスを必須にせず、既存OpenSSHの署名・検証機構（例：`ssh-keygen -Y sign/-Y verify`）を利用する方式をこのDesignの**採用候補**とする。信頼元はHuman Ownerが別途本人確認して登録を明示承認した**Owner ID→公開鍵fingerprint→許可role**の固定allowlist（`allowed_signers`相当）だけであり、実行者から自由に指定された公開鍵、承認CSVの氏名欄、Git commit author、STS Principalを信頼根拠にしない。Owner私有鍵の管理者のみが承認を作成可能で、実行主体は署名を検証するだけ。候補ファイルの作成・コピー権限と、**有効なOwner承認を発行できる権限**を明確に分離する。

署名対象は**UTF-8・RFC 8785（JCS）相当の一意なcanonical JSON**とし、署名および検証で同じcanonicalizerを使用する。`signature_ref`等の包絡情報は署名対象から除外するが、対象全フィールド、承認種別、schema version、`owner_principal_id`、期限、nonceは必ず署名範囲に入れる。Name承認では専用namespace `aws-cost-name-tagger-name-approval-v1` を用い、実行承認の署名との取り違えを拒否する。検証時は公開鍵の登録済みfingerprint、ID、許可role、期限、署名、canonical payload digest、plan/ARN/Name/根拠の一致をすべて照合する。鍵の失効・ローテーション・Owner権限変更時は旧鍵の新規実行許可を拒否する。

**Trust Anchorの運用上のHOLD:** 署名方式の採用候補を記載しても、Owner鍵の実在・本人紐付け・登録/失効手順・保護されたallowlistの所在・実行ホストへの安全な配布は**未承認/未検証**である。将来、実行者が変更できないOS権限の管理領域にOwner信頼情報を事前配置し、書換え・symlink置換・許可roleの改ざんを検出できる状態がOwner承認されるまでは `BLOCKED_OWNER_AUTHN` として**AWS書込みゼロ**。同一UIDから改ざんできる署名検証設定しかない場合もHOLDする。

### 6.2 一回限り実行承認

`authorization`は**単一の`approval_id`、単一の`resource_arn`、単一の`approved_name`、単一の`aws_operation`**（操作のサービス/API版を固定）、実行Account/Partition/Region、実行Identity（STS Principal ARNだけで権限が証明されたとは扱わない）、コード版/ハッシュ、承認作成時刻・期限、リスク受容・writer統制証拠参照・副作用分析証拠参照、固有の`execution_nonce`・`authorization_id`をcanonical payloadに含める。Name承認と異なるnamespace `aws-cost-name-tagger-execution-v1` で、登録済みOwner鍵の**別署名**を検証する。Name承認の署名を実行署名として使い回せない。検証は、署名の暗号学的妥当性、信頼済みOwner ID/role、失効・期限、Name承認と全対象属性の照合を含む。

Ownerには**この1件のARN・最終Name・更新API・実行Identityと残余リスク**を再表示して実行承認を得る。検証済み署名だけでは再利用を防げないため、承認ID・nonce・送信意図を同一ホストの**信頼された単一ライター・永続台帳**で照合し、未使用→使用済みへの耐久遷移が確定しなければAWS変更要求を出さない。台帳が改ざん・競合・不一致・消失の場合は `BLOCKED_AUTH_REPLAY`。クラッシュ後に同じ承認を再実行しない。台帳を別ホストから共有できない場合、複数ホスト/複数operatorを許可しない。

**旧INV-N05との関係（ACT-RG-F003）:** 現行規範は「1回の認可＝1 ARN＋1 Name＋1操作」。よってR0.2にあった`approval_id[]`・ARN集合digest・複数対象の単一実行許可は**採択されていない将来案**として停止する。複数ARNを一括の実行許可に含めることは、Ownerが旧規範を明示改訂するまで `BLOCKED_NORMATIVE_CHANGE` とする。個別承認済みの別ARNを、暗黙に同じ実行許可へ合流させない。実装者がこの制約を勝手に緩めない。

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
4. 通信エラーや停止時に統制が失われた場合、影響する未送信対象の書込を停止する。同一統制範囲の未送信対象は**再評価が完了するまでHOLD**。独立した統制範囲だけを候補として残すが、旧`INV-N07`に抵触する自動継続は行わない。

**別Gate：Nameタグ変更の副作用（旧INV-N09／ACT-RG-F002）:** writer統制が成立しても、Name追加・変更を条件として権限評価するIAM/ABAC/ResourceTag条件、SCP/RCPやリソースポリシー、IaC drift判定、EventBridge・Lambda・Webhook等のイベント起動、自動タグ付け・設定修復・CI/CD・運用スクリプト、既存の課金関連ルールへの影響は**独立に**確認する。対象ARNで適用される条件・処理、Name追加で変化する判断/副作用、依存するリソースと監視・復旧担当を、確認可能な設定/責任者の根拠とともに記録する。対象へ適用される条件・処理を確認できない、または副作用を安全に評価できない場合は `BLOCKED_SIDE_EFFECT_UNASSESSED`（当該ARNのみ、共通する仕組みであればその影響範囲）とし、例外的な未確認のままの書込みを許さない。**writer統制PASSをINV-N09の代替としない。**

**残余リスク:** 実行直前のName読み取りと更新は原子的操作ではない。未知のwriter、管理者権限、AWS内部の反映遅延等があれば、他者のNameを結果的に上書きする可能性が残る。リスクを明示し、統制確認なしにゼロリスクと主張しない。`aws:TagKeys`はタグキー制約であり、比較条件付き更新の証明ではない。

### 7.3 サービス別Adapterの許可条件

- `read_tags`が完全・一意・権限付きにName状態を読める。
- `write_name_only`が既存のName以外のタグ集合を変更しないAPI要求である。送信ペイロードは原則`Name`1キー、対象リソース1件に限定。
- `readback_tags`で同一対象のNameを再取得できる。API戻り値だけで成功と断定しない。
- `writer_control_evidence` **と** `side_effect_evidence`（旧`INV-N09`）を別々に照合し、いずれかの証拠欠損・期限切れ・適用外は送信禁止。副作用判定をサービス別APIの成功可能性だけで代用しない。
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
- `Readback`で確定Nameが一致すれば`APPLIED_VERIFIED`とできるが、他者の中間更新がなかったことまでは証明しない。**Name不一致・想定外の値変化は`WRITER_CONTROL_SUSPECTED`（競合の証明ではない）**として、同一writer統制範囲の未送信対象を**即座にHOLD**。原因確認と統制健全性の再評価が完了するまで解除不可。Readback不能は結果未確定として`OUTCOME_UNKNOWN`を優先する。
- API timeout・通信断・クラッシュ・Readback不能で`OUTCOME_UNKNOWN`となった場合、旧`INV-N07`を維持し**当該実行の後続送信をすべて停止**。現行は1 ARN/1実行なので自動後続送信は設けない。独立範囲への継続は新規の明示的Owner判断と独立承認による別実行に限り、元の承認を再利用しない。
- 自動復旧・自動ロールバックは行わない。Ownerが現況を確認して新しい計画と新しい承認で対処する。

### 7.5 リソース単位Fail-Closedと共通停止

| 失敗・差異 | 扱い |
|---|---|
| ある対象のNameがNONEMPTY・UNKNOWN、証拠差分、adapter非対応 | 当該ARNを`BLOCKED_RESOURCE`。別ARNは独立した承認でのみ実行可能 |
| Name変更によるIAM/ABAC・イベント・自動化等の副作用未確認（旧`INV-N09`） | 当該ARNを`BLOCKED_SIDE_EFFECT_UNASSESSED`。共通影響があれば影響範囲全体をHOLD |
| API timeout、応答不明、クラッシュ、Readback不能で結果未確定 | `OUTCOME_UNKNOWN`。**旧`INV-N07`に従い当該実行の後続送信を全面停止**し、再送禁止 |
| Readback Name不一致・想定外のName変化 | `FAILED_READBACK` + `WRITER_CONTROL_SUSPECTED`。当該ARNと**同一writer統制範囲**の未送信対象をHOLD。原因未確定のまま継続不可 |
| 実行Identity/Account不一致、Owner署名/信頼元/台帳の不一致・改ざん、監査ジャーナル書込不能 | 関連する実行全体を停止 |
| 他writerの統制喪失、対象群に共通する権限/設定異常 | **影響範囲全体**をHOLD。無関係な対象範囲への再開は、独立性確認・新しい別承認・Owner判断が必須 |
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

- 必須監査：承認前後のName、理由、根拠参照、候補ID、Owner ID/登録鍵fingerprint/署名検証結果、承認ID、実行許可ID/nonce・消費状態、Account/Principal、単一対象ARN、Name状態、副作用分析証拠参照、writer統制範囲ID、AWS operation、AWS request ID（取得できた場合）、時刻、Readback観測値、停止対象範囲、エラー分類。
- 機密情報・認証トークンをログに出さない。既存のprivateディレクトリの保護と排他的ファイル操作を維持する。
- 実行の重複防止には権威あるローカル単一writer台帳を使う（同一ホスト・信頼されたUIDの範囲）。別ホスト/複数operator/同一UID敵対者を完全排他する設計には拡張しない。それらを統制できないなら初回実行対象から除外する。
- Read予算・時間予算の不足が見込まれる場合は送信前に停止。実行中のdeadlineは物理HTTP処理の厳密な期限ではない。

## 9. セキュリティGateとOwner決定

- **現行の規範状態:** `G1_NOT_PROVEN / G2_NOT_VERIFIED / SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED`。
- 本設計Aは「統制された他writer＋残余競合リスク受容」を前提とし、旧G1の**AWS側原子的条件付き更新**を証明するものではない。
- **Designの採択、Owner認証用Trust Anchorの承認・登録、旧`INV-N05/N07`等の規範更新、実装の受入、AWS実行承認はそれぞれ別の行為**。R0.2の採択・規範変更・実AWS実行はいずれも未承認。Design承認だけで`write_name()`/`apply()`を有効化しない。
- 既存の厳格G1/G2ポリシーと矛盾する本方式の実運用には、Human Ownerが**対象・安全代替条件・残余リスクを明記した限定的な規範更新／適用例外**を別途明示決定する必要がある。未決定なら書込みはFail-Closed。旧記録のG1/G2を虚偽のPASSに書き換えない。
- **旧規範との関係:** `INV-N05`の単一ARN単一操作を維持し、複数対象の1許可はHOLD。`INV-N07`の結果不明後続停止を維持し、独立性だけを理由に同一実行内の後続送信を許さない。R0.2の広い停止範囲変更案は**未承認の規範変更提案**として発効させない。これらの保留は旧`INV-N01`の原子的非上書き保証の例外・立証とは無関係。
- **F001 HOLD:** Owner署名方式は採用候補として固定したが、Trust Anchorの本人確認・登録・失効・保護は未承認。署名検証が成立しない間、AWS変更API呼出は0件。
- **F002 HOLD:** 旧`INV-N09`に基づくNameタグの認可/イベント/自動化への影響確認が未完了の対象には書かない。writer統制と副作用確認の両方を必須とする。
- **F004 HOLD:** Readback不一致は競合確定と扱わず、writer統制異常の兆候として同一統制範囲をHOLD。解除は統制の再確認とOwner判断が必要。
- **実装計画との整合:** 今回の差分にはImplementation Planが存在しないため、**計画書との仕様・用語・型/インターフェース・エラー処理・試験・非機能要件の比較は未評価（NOT_APPLICABLE_FOR_THIS_CHANGE）**。将来の計画では本Designを入力条件とし、実装計画を今回新規作成しない。
- 実装はAWS資格情報なしのmock/stubで先行できる。実AWSへのread-only接続も別の明示的な許可なしに開始しない。

## 10. エラー・テスト・受入条件

### 10.1 最小のオフライン受入テスト

1. ABSENT・EMPTYだけ候補、NONEMPTY（スペース含む）・UNKNOWN・case variant・ページ未取得を拒否。
2. High/MediumはOwner個別承認対象、`none`は候補承認できない。修正Nameには理由・再承認が必須。
3. Account/ARN/Regionの差異、旧plan、証拠差異、修正済Nameの旧承認流用、別principal/未使用に見せた使用済grantを拒否。
3a. 名称承認と実行承認について、署名なし・署名改ざん・未登録/失効鍵・Owner ID不一致・namespace混同・期限切れ・nonce再利用・台帳改ざん・任意公開鍵差替えをすべて拒否。CSV/digest/自由入力/STS表示のみでは書込0件。
3b. 1つの実行承認に2 ARN、2 Name、複数AWS操作を格納した場合は`BLOCKED_NORMATIVE_CHANGE`。旧`INV-N05`を満たす単一対象以外を許可しない。
4. Name承認だけ、`run --mode y`、従来`apply`で**write API呼出ゼロ**。
5. 偽のwriter統制証拠／TTL切れ／統制喪失の場合はその対象群の書込ゼロ。
5a. Name変更が適用されるIAM/ABAC/ポリシー/イベント/自動化の条件・副作用が不明なら、writer統制が有効でも`BLOCKED_SIDE_EFFECT_UNASSESSED`。共通副作用は共通影響範囲をHOLD。
6. サービス別APIをmock化し、Name以外のタグを変更しない。S3全タグ集合上書きとAPI Gateway継承タグの取り違えを拒否。
7. 更新前の実際のNameがNONEMPTY、UNKNOWN、別リソース、関係変化なら、その対象を書かない。
8. intent永続化失敗では送信ゼロ。timeout/5xx/クラッシュ相当のunknown outcomeで同一承認を自動再送せず、旧`INV-N07`に従い**同一実行の後続送信は0件**。
9. Readback一致／不一致／読み取り失敗を区別。不一致を`WRITER_CONTROL_SUSPECTED`として同一writer統制範囲の未送信対象をHOLDする（writer競合の証明とはしない）。独立した対象のみ、別のOwner判断/承認下で実行可能とする。
10. 共通Identity不一致・台帳異常では影響実行全体を停止。

### 10.2 本来の業務目的での完了条件

- **候補精度:** 既存18種別を候補検討対象とし、根拠・信頼度・保留理由を説明できる。
- **レビュー完結:** High/MediumのNameをOwnerが編集・承認し、変更値が後続の実行対象に正確に保持される。
- **限定実行の安全性:** 実行対象・Identity・writer統制・書込みAPIが承認条件に一致する場合に限り、対象1件ずつ安全に実行できる。既存Nameの偶発的競合上書きの残余リスクは明記する。
- **結果の実証:** 別途明示承認された初回AWS実行では、少なくとも1件の`APPLIED_VERIFIED`をAWS Readbackで確認する。成功できない場合はSTOP理由を残し、架空の成功を報告しない。
- **成果測定:** Name未設定リソース数、提案率、承認率、適用検証率、対象コスト（金額は利用可能なCUR範囲のみ）を報告し、下流分類処理を再開発しない。

### 10.3 停止条件

現行のSafety Holdが有効、正式な限定リスク受容がない、**Owner署名の信頼済みTrust Anchorが未登録/未検証**、旧規範に反する複数ARNの実行許可、writer統制が不明、**旧`INV-N09`の副作用分析が未確認**、リソース/Name状態が不明、service adapter未対応、Owner承認不備、実行Identityが異なる、監査台帳が安全に維持できない場合は**AWS書込み経路だけを停止**。Readback不一致時は同一writer統制範囲の未送信対象もHOLDする。安全なオフライン候補生成とNameレビューは継続できる。

## 11. 残余リスク・未決事項・次の判断

| 項目 | 状態と処置 |
|---|---|
| 非協調writerと更新タイミング競合 | **残余リスク**。初回は統制可能対象に限定。ゼロ保証と表記しない |
| サービス別更新APIの実用可否 | **未検証**。対象種別のadapterごとに限定確認。確認できなければ当該資源のみ保留 |
| 既存G1/G2規範との適合 | **規範更新/限定例外が別途必要**。Design承認とは区別 |
| Owner本人性/承認ログの信頼性（F001） | **OpenSSHの署名検証方式を採用候補として明示**。Owner本人確認による鍵登録・許可role・保管/失効/ローテーションがOwner未承認・未配置なので `BLOCKED_OWNER_AUTHN` |
| Name変更の副作用（F002、旧`INV-N09`） | IAM/ABAC、イベント、自動化、IaCへの影響を対象ごとに確認。未確認は `BLOCKED_SIDE_EFFECT_UNASSESSED`（共通影響があれば共通範囲をHOLD） |
| 複数ARN承認・Unknown後の継続（F003、旧`INV-N05/N07`） | 現行は**単一ARN・単一Name・単一操作**、OUTCOME_UNKNOWN後の後続停止を厳守。緩和はOwnerの別規範決裁がない限り発効しない |
| Readback不一致・writer健全性（F004） | `WRITER_CONTROL_SUSPECTED`として同一統制範囲HOLD。競合の事実は未証明、独立範囲の再開は別判断 |
| 監査のクラッシュ安全性 | ローカル同一ホスト/信頼UIDの範囲に限定。物理送信exactly-onceではない |
| 実際のAWS許可・初回対象 | **未承認**。実行許可を要する。ドキュメント段階で実AWS証拠と混同しない |

**本設計の停止地点（Human Owner Checkpoint）:** ACT-RG-F001〜F004をDesign R0.2.1の**文書案**に反映した段階で終了する。Ownerが必要に応じ、(1) R0.2.1 Design採択、(2) 署名方式とTrust Anchor登録、(3) 旧規範の変更要否、(4) 将来の限定AWS実行を**別々に**判断する。現時点ではすべて未承認。本案の作成だけで変更は発効せず、実装計画の作成・コード変更・AWS操作・IAM変更・CI実行・Commit/Push・PR作成・Gate解除を自動開始しない。新しいFindingを理由にレビュー/訂正ループを自動開始しない。

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
