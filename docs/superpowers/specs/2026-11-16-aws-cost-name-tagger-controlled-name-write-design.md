# AWS Cost Name Tagger — Controlled Name Write Design R0.2.1（限定訂正案）

- **作成日:** 2026-11-16（JST）
- **リポジトリ:** [yohi/aws-cost-name-tagger](https://github.com/yohi/aws-cost-name-tagger)
- **固定参照:** `master` / `497ad6a3f08e9207f39c92a29dfabc549afa127b`
- **文書状態:** `DOCUMENT_REMEDIATION_COMMITTED / HUMAN_OWNER_DESIGN_ADOPTION_PENDING`（Design採択・規範変更・AWS実行は未承認）
- **Reviewed HEAD:** `b8b78209578bd0b878e4a0f155d966bd112e1973`（今回のF001/F004限定訂正の基準）
- **反映対象パス:** `docs/superpowers/specs/2026-11-16-aws-cost-name-tagger-controlled-name-write-design.md`（R0.2.1はGitHubへCommit・Push済み。今回のF001/F004限定訂正も同一ファイルに反映）
- **作業境界:** ACT-RG-F001/F004の**ドキュメント限定訂正**とHuman Ownerが許可した同一featureブランチへのCommit・Pushのみ。AWS API呼出、IAM変更、ソース・CI変更、PR/Merge、Safety Hold解除は禁止。
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
  "payload": {
    "schema_version": 1,
    "approval_namespace": "aws-cost-name-tagger-name-approval-v1",
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
    "decision_nonce": "<unpredictable-unique-nonce>"
  },
  "approval_id": "<sha256-lowercase-hex-of-canonical-payload-bytes>",
  "signature_ref": "<detached-owner-signature>"
}
```

このJSONは概念スキーマであり、文字列中の`<...>`はプレースホルダー。**署名対象の`NameApprovalPayload`は`payload`オブジェクトの全フィールドだけ**で構成し、`approval_id`および`signature_ref`は`NameApprovalEnvelope`の外側フィールドとする。両者を`payload`へ再挿入しない。S3などNameを提案できるが書き込めない種別もNameレビューに含められる。

**ID算出・署名・検証の順序（ACT-RG-F001）:** (1) Ownerが`payload`の全項目（`schema_version`・`approval_namespace`・Owner ID・鍵fingerprint・Account/ARN/Name/根拠・時刻・nonceを含む）を確定する。(2) RFC 8785（JCS）準拠のcanonical JSONをUTF-8バイト列`B = JCS_UTF8(payload)`として1回定義する。(3) `approval_id = lowercase_hex(SHA256(B))`を算出する。(4) `B`だけをOpenSSHの専用署名namespace `aws-cost-name-tagger-name-approval-v1`で署名し、detached `signature_ref`を作る。(5) `{payload, approval_id, signature_ref}`をEnvelopeとして保管する。検証時は同じ`payload`から`B`とIDを独立再計算し、登録済みOwner鍵で同じ`B`の署名を照合する。正規化・再計算・署名・Owner本人性・期限・nonce・対象情報のいずれかが不明または不一致なら書込み禁止。IDは一意な内容識別子であって認証そのものではない。署名対象の全フィールドという表現は**Payload内の全フィールド**を指し、Envelope全体を指さない。未知フィールド、重複キー、曖昧な型や非決定的なcanonicalizationは拒否する。

**本人確認・作成/検証権限の採用方式（ACT-RG-F001）:** 新規Brokerやクラウド認証サービスを必須にせず、既存OpenSSHの署名・検証機構（例：`ssh-keygen -Y sign/-Y verify`）を利用する方式をこのDesignの**採用候補**とする。信頼元はHuman Ownerが別途本人確認して登録を明示承認した**Owner ID→公開鍵fingerprint→許可role**の固定allowlist（`allowed_signers`相当）だけであり、実行者から自由に指定された公開鍵、承認CSVの氏名欄、Git commit author、STS Principalを信頼根拠にしない。Owner私有鍵の管理者のみが承認を作成可能で、実行主体は署名を検証するだけ。候補ファイルの作成・コピー権限と、**有効なOwner承認を発行できる権限**を明確に分離する。

署名と検証は同一のRFC 8785準拠canonicalizerを使い、OpenSSHの`-n`署名namespaceと`payload.approval_namespace`を一致照合する。実行承認のnamespaceとの取り違えを拒否する。検証時は公開鍵の登録済みfingerprint、ID、許可role、期限、署名、canonical payload digest、plan/ARN/Name/根拠の一致をすべて照合する。鍵の失効・ローテーション・Owner権限変更時は旧鍵の新規実行許可を拒否する。

**Trust Anchorの運用上のHOLD:** 署名方式の採用候補を記載しても、Owner鍵の実在・本人紐付け・登録/失効手順・保護されたallowlistの所在・実行ホストへの安全な配布は**未承認/未検証**である。将来、実行者が変更できないOS権限の管理領域にOwner信頼情報を事前配置し、書換え・symlink置換・許可roleの改ざんを検出できる状態がOwner承認されるまでは `BLOCKED_OWNER_AUTHN` として**AWS書込みゼロ**。同一UIDから改ざんできる署名検証設定しかない場合もHOLDする。

### 6.2 一回限り実行承認

実行承認も`ExecutionAuthorizationPayload`と`ExecutionAuthorizationEnvelope`を分離する。署名対象の`payload`には、`schema_version=1`、`authorization_namespace=aws-cost-name-tagger-execution-v1`、**単一のName承認`approval_id`**、**単一の`resource_arn`・`approved_name`・`aws_operation`**（サービス/API版を固定）、実行Account/Partition/Region、実行Identity（STS Principal ARNだけで権限が証明されたとは扱わない）、実行コード版/ハッシュ、`writer_control_scope_id`、リスク受容・writer統制証拠・副作用分析証拠の参照、Owner ID/登録鍵fingerprint・許可role、発行時刻・期限、固有の`execution_nonce`を含める。

`authorization_id`と`signature_ref`は**Envelope側だけ**に格納する。生成手順を`E = JCS_UTF8(execution_payload)`、`authorization_id = lowercase_hex(SHA256(E))`、次にOpenSSHの専用namespace `aws-cost-name-tagger-execution-v1`で**同じ`E`を署名**、最後に`{payload, authorization_id, signature_ref}`を保存する、と固定する。Name承認の`approval_id`は既に検証済みのIDを**実行Payload内で参照する値**であり、実行承認の自己IDではない。検証では署名済み`E`・再計算した`authorization_id`・namespace・Owner信頼鍵/role/期限/nonce・Name承認と全対象属性の一致を必須とし、`authorization_id`や`signature_ref`自体を`execution_payload`に含めて循環させない。OpenSSH署名、IDのdigest、CSV、自由入力だけではOwner権限や非再利用性を証明しない。

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
- **writer統制範囲の永続HOLD（ACT-RG-F004）:** ReadbackのName不一致・想定外のName変化を検出した実行は、署名済み実行Payloadに拘束された`writer_control_scope_id`の状態を、同一ホストの権威ある単一writer永続台帳で`HOLD`へ遷移させる。関連ARNは承認時に固定したスコープ対応へ紐付け、スコープ名の付替えや新IDの発行でHOLDを回避してはならない。`HOLD`の耐久記録を`fsync`等で確定するまで、以降の送信を許可しない。記録に失敗した場合は台帳健全性`UNKNOWN`として**同一ホストの全AWS書込み経路をFail-Closed**とする。既に送信した操作は自動取消・自動ロールバックしない。
- API timeout・通信断・クラッシュ・Readback不能で`OUTCOME_UNKNOWN`となった場合、旧`INV-N07`を維持し**当該実行の後続送信をすべて停止**。現行は1 ARN/1実行なので自動後続送信は設けない。独立範囲への継続は新規の明示的Owner判断と独立承認による別実行に限り、元の承認を再利用しない。
- 自動復旧・自動ロールバックは行わない。Ownerが現況を確認して新しい計画と新しい承認で対処する。

**クラッシュ復旧時の未完了Intent Gate（ACT-RG-F004限定訂正）:** AWS変更APIを許可する前に、権威ある単一ホストの永続台帳で対象`writer_control_scope_id`の最新状態と未完了Intentの有無を、単一writer排他境界内で照合する。ここで`CURRENT_EXECUTION_INTENT`は、**同一プロセス・同一実行・同一排他区間内で新規作成・耐久化され、送信を行う主体が一時的な実行内所有コンテキストを保持するIntent**に限る。`PRIOR_INCOMPLETE_INTENT`は、過去実行、再起動前、別実行、または当該操作に属さない未完了Intentである。PID・永続実行ID・Intent内の自己申告値が一致するだけではCURRENTと判定しない。所有コンテキストの再起動後の復元は禁止する。

**正当な新規Intentの初回送信条件:** (1) scopeが`CLEARED`で台帳全体が健全、(2) 新規作成前の同scopeの`PRIOR_INCOMPLETE_INTENT`が0件、(3) 単一writer排他下で承認済みARN・Name・`authorization_id`・nonce・scopeを固定した新規Intentの耐久化が完了、(4) 送信直前の再照合でも他の未完了Intentが0件でscope状態が不変、(5) 同Intentの送信権を`SEND_ATTEMPT_CONSUMED`として**AWS呼出前に耐久記録済み**、(6) 同じ排他実行の一時的所有コンテキストにより、**その1回の呼出しがまだ発行されていない**ことを検証できる場合に限り、`ALLOW_FIRST_SEND`を付与する。この例外は新規Intent自身の初回送信だけに適用し、過去の未完了Intentや別実行・再起動後の要求には適用しない。台帳の照合・Intent登録・送信権消費・初回呼出しの割当を同一排他実行で直列化し、SDK自動retry、二回目の呼出し、別主体による送信を禁止する。Intent登録または送信権消費の耐久化に失敗すれば送信ゼロ。`SEND_ATTEMPT_CONSUMED`を耐久化した後にクラッシュした場合、AWSへ送ったか不明でも送信権は復活しない。AWS側の物理的exactly-onceは保証しない。

クラッシュ・送信応答不明・Readback不能・Readback不一致・結果の終端記録前の異常終了は、当該Intentを**未完了**として扱う。特にReadback不一致検出後、scopeの`HOLD`を`fsync`する前にクラッシュして旧`CLEARED`が残っても、先行する耐久Intentから実効的に送信禁止とする。Readback不一致時は、**scopeの`HOLD`を耐久確定するより前にIntentを終端完了扱いへ移してはならない**。結果一致の確認後でも終端記録が未完了なら未完了Intentとして停止する。未完了Intentの影響scopeを特定できなければホスト全体をFail-Closed。旧承認・nonce・Intentの再利用、自動再送、自動ロールバックは禁止する。

### 7.5 リソース単位Fail-Closedと共通停止

| 失敗・差異 | 扱い |
|---|---|
| ある対象のNameがNONEMPTY・UNKNOWN、証拠差分、adapter非対応 | 当該ARNを`BLOCKED_RESOURCE`。別ARNは独立した承認でのみ実行可能 |
| Name変更によるIAM/ABAC・イベント・自動化等の副作用未確認（旧`INV-N09`） | 当該ARNを`BLOCKED_SIDE_EFFECT_UNASSESSED`。共通影響があれば影響範囲全体をHOLD |
| API timeout、応答不明、クラッシュ、Readback不能で結果未確定 | `OUTCOME_UNKNOWN`。**旧`INV-N07`に従い当該実行の後続送信を全面停止**し、再送禁止 |
| Readback Name不一致・想定外のName変化 | `FAILED_READBACK` + `WRITER_CONTROL_SUSPECTED`。同一`writer_control_scope_id`の**永続HOLD**を記録し、その範囲の未送信対象を後続の別実行も含めて停止。競合の証明とは扱わない |
| スコープHOLD台帳の欠落・破損・未初期化・不一致・読取不能、またはHOLDの永続化失敗 | `BLOCKED_SCOPE_STATE_UNKNOWN`。欠落を`CLEARED`と推定せず、同一ホストの送信を停止。状態と統制範囲の検証が回復するまで解除不可 |
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


**writer統制範囲の永続状態契約（ACT-RG-F004）:** 認可の使い回し防止用台帳と同じ**単一ホスト・権威ある単一writerの永続台帳**で、実行をまたぐ`writer_control_scope_id`ごとの状態を管理する。スコープ識別はAccount/Partition/Region・統制されるwriter集合/対象境界に紐付けて固定し、承認済みの対象ARNとの対応を記録する。台帳は保護されたローカルファイルと排他的アクセス・永続化を前提とし、別の認証基盤・Broker・クラウドサービスを追加しない。**台帳の永続性が確認できない環境、複数ホストの同期がない環境、並列実行を排他できない環境ではAWS送信を禁止**する。

| 永続状態 | 定義と次回実行時の扱い |
|---|---|
| `CLEARED` | Ownerが統制証拠を確認し、当該scopeの初期有効化/解除を明示判断し、耐久記録された状態。ほかの実行Gateが成立するときだけ送信候補 |
| `HOLD` | Readback不一致・想定外のName変化または統制喪失が検出され、影響対象群への送信を禁止する状態。実行をまたいで保持 |
| `UNKNOWN` | 未登録・台帳欠落・破損・不整合・読取不能・排他失敗・永続化不能等。**Fail-Closed**であり、黙って`CLEARED`を生成しない |

**送信前チェックと解除手順:** 各実行は署名済み`writer_control_scope_id`と台帳上の固定対象対応を一致確認する。初回の実行開始時および各AWS変更API送信の直前に、単一writerの排他境界内で**最新の耐久状態**を読み、`CLEARED`以外なら送信ゼロとする。異常観測後は`HOLD`の永続化を完了してから当該実行を終了する。異常時に`HOLD`を記録できなければホストの台帳自体を`UNKNOWN`として全送信禁止にする。`HOLD → CLEARED`は、原因とwriter統制健全性の再確認を示す証拠とHuman Ownerの**独立した明示判断**を揃え、台帳に解除根拠・承認者・時刻を耐久記録した場合だけ許可する。解除は旧Name承認・実行承認・nonceの再利用を意味しない。無関係スコープの別実行でも同じ権威台帳を照合し、範囲の独立性を立証できない場合は送信しない。

**未完了Intentを含む実効scope状態の判定（ACT-RG-F004限定訂正）:** 権威ある台帳は、scope状態だけでなく、同一ホストで実行をまたいで保持されるIntentの存在・対応scope・未完了/終端状態も管理する。スコープ状態とIntent履歴が**両方とも完全に検証可能**であることを送信許可の前提とし、Intent履歴の欠落・破損・読取不能を「未完了Intentなし」と推定しない。初回起動・再起動・新たな実行開始時と**各AWS変更API送信直前**に、単一writer排他下で最新の永続状態を検証する。 **新規Intentの登録前は未完了0件を要求し、登録後の初回送信判定では§7.4で定義した`CURRENT_EXECUTION_INTENT`1件のみを例外として扱う。** `ALLOW_FIRST_SEND`は永続scope状態ではなく、同一排他実行内だけの一時的判定である。`SEND_ATTEMPT_CONSUMED`は永続的な送信権消費を表し、初回呼出し済みの一時的所有コンテキストは再使用不可。起動・再起動後には永続ID等からCURRENTを復元せず、未完了IntentはすべてPRIORとして扱う。

| 保存済みscope状態 | 関連する未完了Intent | 実行コンテキスト | 実効判定 / 送信可否 |
|---|---|---|---|
| `CLEARED` | 0件（履歴の完全性を検証済み） | 新規実行 | 他の全Gate成立時のみ新規Intentの作成候補 |
| `CLEARED` | 現在実行の新規Intent1件のみ | 同一排他実行・初回呼出し未発行・`SEND_ATTEMPT_CONSUMED`耐久記録済み | `ALLOW_FIRST_SEND`。**当該初回呼出し1回のみ** |
| `CLEARED` | 過去・別実行の未完了Intentが1件以上 | 任意 | `BLOCKED_INCOMPLETE_INTENT`。送信禁止 |
| `CLEARED` | 自分のIntentでも、同じ実行から初回呼出しを既に発行済み | 二回目・再送要求 | `BLOCKED_INTENT_REPLAY`。送信禁止 |
| `HOLD` | 任意 | 任意 | `BLOCKED_SCOPE_HOLD`。送信禁止 |
| `UNKNOWN` | 任意 | 任意 | `BLOCKED_SCOPE_STATE_UNKNOWN`。送信禁止 |
| 台帳・Intent・scope対応が欠落、破損、不整合、読取不能 | 不明 | 任意 | `BLOCKED_SCOPE_STATE_UNKNOWN`。影響範囲不明ならホスト全体送信禁止 |

**復旧と解除:** 過去の未完了Intentを検出したら、影響するscopeを実行をまたいで停止し、影響範囲を特定できない場合にはホスト全体を停止する。§7.4に従って単一排他実行内で新規作成した自分のIntentだけは初回送信条件を満たす場合に限り例外とする。別scopeを送信候補にできるのは、台帳全体が健全で影響範囲の独立性を確認でき、別途有効な承認がある場合だけ。未完了Intent/HOLDの解除には、AWS現況・writer統制健全性の再確認、Human Ownerの**独立した明示承認**、解除根拠・対象scope・承認者・時刻の**耐久記録**をすべて要する。解除を記録する前に旧Intentの未完了状態を消去したり、旧`CLEARED`のみで復旧させたりしない。解除済みの履歴も再利用禁止の証跡として保持し、旧Name承認・実行承認・nonce・Intentでの再送を認めない。単一ホストの台帳が正常性を保証できない間は、新しいBroker等を導入せずにFail-Closedを維持する。

## 9. セキュリティGateとOwner決定

- **現行の規範状態:** `G1_NOT_PROVEN / G2_NOT_VERIFIED / SAFETY_HOLD_ACTIVE / AWS_WRITE_BLOCKED`。
- 本設計Aは「統制された他writer＋残余競合リスク受容」を前提とし、旧G1の**AWS側原子的条件付き更新**を証明するものではない。
- **Designの採択、Owner認証用Trust Anchorの承認・登録、旧`INV-N05/N07`等の規範更新、実装の受入、AWS実行承認はそれぞれ別の行為**。R0.2の採択・規範変更・実AWS実行はいずれも未承認。Design承認だけで`write_name()`/`apply()`を有効化しない。
- 既存の厳格G1/G2ポリシーと矛盾する本方式の実運用には、Human Ownerが**対象・安全代替条件・残余リスクを明記した限定的な規範更新／適用例外**を別途明示決定する必要がある。未決定なら書込みはFail-Closed。旧記録のG1/G2を虚偽のPASSに書き換えない。
- **旧規範との関係:** `INV-N05`の単一ARN単一操作を維持し、複数対象の1許可はHOLD。`INV-N07`の結果不明後続停止を維持し、独立性だけを理由に同一実行内の後続送信を許さない。R0.2の広い停止範囲変更案は**未承認の規範変更提案**として発効させない。これらの保留は旧`INV-N01`の原子的非上書き保証の例外・立証とは無関係。
- **F001 HOLD:** Owner署名方式は採用候補として固定したが、Trust Anchorの本人確認・登録・失効・保護は未承認。署名検証が成立しない間、AWS変更API呼出は0件。
- **F002 HOLD:** 旧`INV-N09`に基づくNameタグの認可/イベント/自動化への影響確認が未完了の対象には書かない。writer統制と副作用確認の両方を必須とする。
- **F004 HOLD:** Readback不一致は競合確定と扱わず、writer統制異常の兆候として同一統制範囲をHOLD。解除は統制の再確認とOwner判断が必要。
- **実装計画との整合（F007）:** Implementation Planは `docs/superpowers/plans/2026-11-16-aws-cost-name-tagger-controlled-name-write.md` に存在する。現行PlanのTask 4（Owner署名に基づくscope初期登録・HOLD解除、耐久台帳）、Task 5（RuntimeContext型、オフラインstubとGuarded Executor）、Task 8（認証済みRuntime Policy、FirstSendPermitと実SDK Adapter境界）を、本Design §6〜§10の承認Payload、scope/ARN集合・証拠、Intent消費、HOLD/解除、エラー分類、クラッシュ復旧試験、環境保護・永続化・実AWS書込み禁止の非機能条件との整合確認対象とする。Planの存在・訂正・整合確認は**Design採択、Trust Anchor登録、規範変更、実装着手またはAWS実行の承認を意味しない**。
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

**ACT-RG-F004 クラッシュ復旧の追加オフライン受入テスト（mock/stub・送信APIは模擬）:**

| ID | 故障注入・状況 | 期待結果 |
|---|---|---|
| T-F004-01 | Intentを耐久記録した直後、送信前にクラッシュ | 再起動後も未完了Intentを検知。旧承認・nonceによる送信0件 |
| T-F004-02 | AWS更新要求の送信後、Readback前にクラッシュ | 当該scopeは`BLOCKED_INCOMPLETE_INTENT`、自動再送0件 |
| T-F004-03 | Readback不一致後、scope HOLDの`fsync`前にクラッシュ | 保存済みの旧`CLEARED`があっても未完了Intentを優先し送信0件 |
| T-F004-04 | HOLDの耐久記録後、Intentの終端記録前にクラッシュ | `BLOCKED_SCOPE_HOLD`を維持し、別実行も送信0件 |
| T-F004-05 | Intent台帳・scope対応の欠落/破損/読取不能 | 範囲を確定できなければホスト全体`BLOCKED_SCOPE_STATE_UNKNOWN` |
| T-F004-06 | 同一scopeの別実行が送信を試みる | HOLD/未完了Intentの照合により送信0件 |
| T-F004-07 | 独立scopeに別の有効承認がある | 台帳健全性・範囲独立・他Gate成立時のみ新たな実行候補 |
| T-F004-08 | Owner承認なし、または解除耐久化前にHOLD解除を試みる | 解除拒否・送信0件 |
| T-F004-09 | Ownerによる解除を耐久化した後に旧nonce/実行承認を再利用 | 再利用拒否。新しい個別承認を要求 |

**ACT-RG-F004 正常初回送信と旧Intent拒否の追加オフラインテスト（mock/stubのみ）:**

| ID | 試験 | 期待結果 |
|---|---|---|
| T-F004-10 | 台帳健全・scope `CLEARED`・過去未完了Intentなし。新規Intentを耐久化して送信権を消費 | 正当な初回AWS更新要求をmockで**1回だけ許可** |
| T-F004-11 | 過去の未完了Intentが残るscopeで新規Intent作成・送信を試みる | `BLOCKED_INCOMPLETE_INTENT`、送信0件 |
| T-F004-12 | 再起動後、同じIntent ID・永続実行ID・PID相当値を使って送信する | CURRENTと認めず送信0件 |
| T-F004-13 | 同一実行で初回呼出し後、同じIntentの二回目を試みる | `BLOCKED_INTENT_REPLAY`、追加送信0件 |
| T-F004-14 | `SEND_ATTEMPT_CONSUMED`耐久化直後、AWS呼出前にクラッシュ | 復旧後は送信権を復元せず、再送0件 |
| T-F004-15 | `SEND_ATTEMPT_CONSUMED`の永続化失敗 | 初回送信も禁止、送信0件 |
| T-F004-16 | 新規Intent登録後、初回送信直前にscope状態が`HOLD`に変化 | `ALLOW_FIRST_SEND`不成立、送信0件 |

受入テストは、Intent確定・変更要求・Readback・HOLD記録・Intent終端・解除記録の各永続化境界にクラッシュを挿入し、再起動後の送信可否を判定する。実AWS接続、ソース/CI変更、本番での故障試験は本Design限定訂正の範囲外。

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
