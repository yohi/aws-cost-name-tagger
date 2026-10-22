# AWS Cost Name Tagger — Safe Name Addition Architecture R1.1

**文書種別:** 設計候補・独立審査前（DESIGN ONLY）  
**作成日:** 2026-10-21（JST）  
**対象AWSアカウント:** `456720798575`  
**実装・デプロイ・AWS変更:** **禁止／未実施**  
**Owner承認・書き込みGate:** **PENDING / BLOCKED**  
**R1.1変更内容:** 人間Ownerの要件補正 — `Name` 未存在に加えて、`Name` の値が**厳密に空文字 `""`** の場合もName設定候補とする。**AWS書き込みは引き続き禁止。**

### R1 → R1.1 仕様差分（2026-10-21）

| 現在のNameタグ状態 | Name候補の扱い | 将来の書き込みに必要な条件 |
|---|---|---|
| `Name` キーなし（ABSENT） | **候補に含める** | `ABSENT` に対する原子的な条件付き書き込み保証 |
| `Name=""`（EMPTY：キーあり、値は長さ0） | **候補に含める** | `EMPTY` に対する原子的な条件付き書き込み保証 |
| `Name="scs2-prd-web-ec2"` 等（NONEMPTY） | **対象外・既存値保護** | 書き込み禁止 |
| `Name=" "` 等（空白文字を含む、長さ1以上） | **既存値として保護／要手動確認** | 自動上書き禁止（文字列trimで空とはみなさない） |
| 値が異常・取得結果が曖昧（UNKNOWN） | **保留** | 書き込み禁止 |

**注意:** これは書き込みを許可する決裁ではない。現在のv3.5では `has_name()` がキー存在だけを検査するため `Name=""` は `already_named` となる。R1.1の意味論は、将来の別途レビュー済み読み取り側改訂までv3.5に反映されていない。

## 1. 結論と設計上の制約

**既存の非空 `Name` タグを絶対に上書きしない**ことを最上位の不変条件とする。タグが**未存在（ABSENT）**、または存在して値が**厳密に空文字（EMPTY）**の場合は新しいNameの設定候補とする。`Name=" "` はEMPTYではない。競合を含めて非空既存値を保護できない書き込み経路は、サービス・リソース単位で **BLOCKED** とする。現行 v3.5 の `plan`、`run --mode dryrun`、レビュー記録用 `Y` の機能は維持し、`apply()` と `write_name()` の Safety Hold を解除しない。

AWS公式仕様によれば、EC2 `CreateTags` および RDS のタグ追加操作は、同じキーが存在すれば値を上書きする。`aws:TagKeys` はリクエストのキーを制限するが、既存の `Name` キーに対して「未存在または値が空文字の場合だけ書く」という原子的な条件付き更新を保証するものではない。二重読み取り、外部ロック、CloudTrail事後監査を組み合わせても、外部の書き込み主体との競合を **AWSタグ更新と同じ原子操作** として防げるとは限らない。

**設計判断 R1.1:** 原子的な **ABSENT-or-EMPTY-only write** がサービスAPIの保証（または全書き込み主体を統制した検証済みの同等保証）として証明されるまで、AWS Nameタグ設定を再有効化しない。**「実運用上ほぼ安全」と「絶対に上書きしない」は区別する。**

## 2. 固定した入力と実証済みの範囲

- v3.5 Safety Hold ZIP（ローカル受領物）のSHA-256：`1a88b2d9986bb767306ef107b323a4ee65f82eeaa5bba1915ac15afd37110172`
- 高額リソース：90件（Nameあり60件／提案30件）。
- EBS：28件（提案28件）。
- 新規Name候補合計：**58件**、うちhigh 46件／medium 12件。人間の承認記録は0件。
- 親クラスターのName未設定で `high` とされるRDS：6件。`high` を正式承認と解釈しない。
- v3.5のレポートでは58件が `dryrun_not_modified`。これは提出されたレポートの整合性を示すもので、CloudTrailによる「変更が絶対になかった」の証明ではない。
- `Product` タグとNameプレフィックスの対応、`storecms`/`storecms2`・`ogne`/`coord-app`・`ros`/`ros-sftp`/`ros-for-ec` のマッピングは**別工程**。Name提案・安全書き込み認可の必要条件にしない。

## 3. 脅威モデルと不変条件

### 脅威・障害シナリオ

1. 読み取り後、別のAWS主体（コンソール・別スクリプト・IaC・サービス）が同じリソースに `Name` を追加する。
2. 直接書き込み関数を呼ぶ、または承認済みリストを改ざんして想定外のARNや名前を与える。
3. 正しいアカウントを認証した後、セッションが切り替わる・認証主体が変わる。
4. AWS側で処理が成功した直後にプロセス・ディスク・通信が異常終了する。
5. タグAPIの自動リトライが、結果不明の変更を再送する。
6. 親EC2やRDS所属関係が候補生成後に変更され、提案Nameの根拠が失効する。
7. Name付与によって、タグベースのIAM条件や外部自動化が間接的に反応する。

### 不変条件

- **INV-N01**: `Name` が **ABSENT または EMPTY（値が厳密に `""`）** のときに限り設定候補とする。**NONEMPTY（空白のみを含む）は上書き禁止**。書き込み時にも原子的にこの条件が成立し、競合する他者の非空Nameを上書きしないことが必須。状態不明は拒否。
- **INV-N02**: AWSリクエストに含めるタグキーは `Name` **だけ**。大文字小文字違いの類似キーが存在する場合は保留。
- **INV-N03**: IAM主体、AWSアカウント、リージョン、ARN、Name候補、根拠の完全性が一致しなければ拒否。
- **INV-N04**: 根拠が変更・消失した場合は承認を失効させる。Productマッピング結果は根拠の代替としない。
- **INV-N05**: 1回の認可は **1 ARN + 1 Name値 + 1操作** のみ。暗黙の一括適用は不可。
- **INV-N06**: 書き込み前に永続監査記録が成立しなければAWS変更APIを実行しない。
- **INV-N07**: 書き込み結果が不明な場合、同一変更を自動再試行しない。後続も止める。
- **INV-N08**: 承認なし・dryrun・ロール未検証・Gate不成立時は、変更系API呼び出し **0件**。
- **INV-N09**: `Name` が他システムの認可や自動化条件に使われるリソースは、影響分析が完了するまでBLOCKED。
- **INV-N10**: `ABSENT` と `EMPTY` と `NONEMPTY` を、収集・計画・承認・監査で区別する。`name_before=""` だけでABSENTとEMPTYを同一視しない。キー有無、取得した生値、状態分類を保持する。

### v3.5 読み取り専用実装への影響（未実装）

現在のv3.5は次の通り、**R1.1の候補条件をまだ満たさない**。本書で改訂を決めても、AWSへの書き込みを認可・再実装したことにはならない。

1. `has_name(tags)` はキーの存在だけを返し、`Name=""` を `already_named` と判定する。将来の読み取り専用版では、`name_state` を明示的に導入し、ABSENT/EMPTYを `proposed`（根拠があれば）または `manual_review` とする。
2. 現行 `existing_name=""` はABSENT/EMPTYを区別できないため、`name_key_present`・`name_state`・取得値をレポートに追加する。`proposal_id` の再計算および過去プランとの混同防止を設計する。
3. 以前のdryrun件数（高額90、EBS28、Name候補58）は **旧条件に基づく実績**。空文字タグの現存数は未調査のため、R1.1で候補が何件増えるかを推測しない。
4. `run --mode y`・`apply()`・`write_name()`の**AWS書き込み禁止**を維持したまま読み取り・計画・テストだけ別途改訂可能。書き込み機能の検証・承認はG1〜G6の独立課題とする。

## 4. サービス別の安全な書き込み能力判定

| サービス・候補 | 候補に現れた用途 | 既知の上書き仕様 | 原子的 ABSENT-or-EMPTY-only の根拠 | R1.1書き込みGate |
|---|---|---|---|---|
| EC2 / EBS | EC2親NameからEBSへ継承 | `CreateTags` は同一キーを上書き | **NOT PROVEN** | **BLOCKED** |
| RDS DB Instance / Cluster | 親クラスターの所属関係 | 同一キーを上書き | **NOT PROVEN** | **BLOCKED** |
| CloudFront | オリジン・Comment・Alias | サービス固有仕様を個別確認要 | **NOT PROVEN** | **BLOCKED** |
| API Gateway Stage | REST API・ステージ | サービス固有仕様を個別確認要 | **NOT PROVEN** | **BLOCKED** |
| OpenSearch / ELB / WAF / Lambda / Logs / Athena | サービス固有リソース | サービスごとに未評価 | **NOT PROVEN** | **BLOCKED** |
| S3 | バケット | タグ集合置換の副作用がある | **NOT PROVEN** | **BLOCKED**（既存方針維持） |

**注意:** EC2のAPI `DryRun=True` は権限確認であって「既存Nameが上書きされない」の検証ではない。アプリの `--mode dryrun` とは別の概念。

### 採用しない「見かけ上の解決策」

- **read → read → write:** 2回目のreadの直後に競合可能。
- **DynamoDB等の外部ロック単体:** ロックに参加しないAWSタグ書き込み主体を防げない。DynamoDBで原子的なのはロック項目の更新であり、EC2/RDSのタグ更新ではない。
- **`aws:TagKeys=Name` 単体:** 書き込みキーの制限にはなるが既存Nameの上書き防止にはならない。
- **`aws:ResourceTag/Name` の不在・空文字条件を未検証のまま使用:** サービス・アクションにおける評価可否と並行競合の安全性が未証明。
- **CloudTrailの監視・復元:** 事後検出であり、上書きそのものを禁止する仕組みではない。

## 5. 将来の実行プロトコル（すべて未実装・未認可）

```text
PLAN（v3.5の既存読み取り専用処理）
  ↓ 候補・根拠・ハッシュを固定
HUMAN REVIEW
  ↓ 1件ごとにARN／Name／根拠を承認（現状全件未承認）
GATE CHECK
  ├─ ABSENT-or-EMPTY-only 書き込み能力未証明 → BLOCKED（現在）
  ├─ 対象IAM・Account・ARN・Name・根拠に差異 → BLOCKED
  ├─ 外部自動化・ABAC影響未評価 → BLOCKED
  └─ 全Gateが独立に通過 → WRITE ELIGIBLE（将来のみ）
  ↓
DURABLE PREPARE
  ↓ 永続記録を確認できなければ中止
FRESH READ / GUARDED WRITE
  ↓ AWS側で原子的にABSENTまたはEMPTYのときだけ更新できる保証がなければ呼ばない
POST-READ / RECONCILE
  ├─ Name一致＋AWS応答確証 → VERIFIED
  ├─ Nameが他値／旧値 → INCIDENT/CONFLICT、後続停止
  └─ タイムアウト・異常終了・不明 → OUTCOME_UNKNOWN、後続停止・自動再試行禁止
```

`Y` は現行どおり**レビュー記録のみ**であり、上記 `WRITE ELIGIBLE` を成立させない。上位プランの `approved=true` の入力だけでも実行許可しない。

## 6. 永続監査と復旧設計（実装前条件）

1 ARNごとに、少なくとも以下を **書き込み前に** 保存する：

- `operation_id`（重複なく固定）、`plan_sha256`、`proposal_id`、`resource_arn`、`kind`、`region`
- `account_id`、STS主体ARN/role/session、承認者と承認時刻、承認対象 `proposed_name`
- `name_before`（取得値そのもの）と **Nameキー存在有無**、`name_state=ABSENT|EMPTY|NONEMPTY|UNKNOWN`、命名根拠のfingerprint
- ターゲットのタグ読取時刻・API名、採用したサービス別のABSENT-or-EMPTY-only能力証明ID、およびABSENT/EMPTYに関する競合条件の検証結果
- `PREPARED` / `CALL_IN_FLIGHT` / `RESPONSE_RECEIVED` / `VERIFIED` / `CONFLICT` / `OUTCOME_UNKNOWN` の状態遷移
- AWSリクエストID、エラー分類、事後Name、再照合時刻

監査記録は、書き込みより先にdurableなPREPAREDを確定し、**AWS呼び出し直前にもCALL_IN_FLIGHTを確定**する。JSONL追記＋`fsync` はローカル障害の一部を緩和するが、ホスト故障・削除・ディスク故障でも失わない証跡の保証には、外部の不変・アクセス制御された保存先と独立検証が必要。CloudTrailは補助証拠であって単独の同期確定証拠としない。

異常終了時の復旧は既存記録の照会と**読み取り専用**のタグ再照合に限定し、変更系APIの再実行はしない。CloudTrail・AWS現況・操作時刻を突合しても確定できなければ `OUTCOME_UNKNOWN` のままOwner判断に戻す。

## 7. 反証可能なテスト計画

| ID | テスト | 合格条件 |
|---|---|---|
| T-001 | 既存Nameが非空 | 候補から除外。AWS書き込み0件 |
| T-002 | 既存Nameが空文字 `""` | **提案対象**になる。ただしSafety Hold中はAWS書き込み0件。将来の適用はEMPTY条件の原子的保証と全Gate通過が必須 |
| T-002A | Nameキーが未存在 | **提案対象**になる。ただしSafety Hold中はAWS書き込み0件 |
| T-002B | `Name=" "`、タブ等の空白のみ | EMPTY扱いせず既存値を保護。AWS書き込み0件 |
| T-002C | 取得したName値が不明・不正 | `manual_review` / `api_error` に保留、AWS書き込み0件 |
| T-003 | 読み取り時ABSENTまたはEMPTYの対象へ、別書き込み主体が更新前に非空Nameを設定 | 他者のNameが保持される **AWS側の原子的保証** がなければGate BLOCKED |
| T-004 | `write_name()`直接呼出し・`apply`直接呼出し | Safety Hold中は無条件拒否 |
| T-005 | 署名されない／ハッシュ不一致／プラン期限切れ | AWS書き込み0件 |
| T-006 | ARN・Account・Role・Region差異 | AWS書き込み0件 |
| T-007 | 親EC2、EBS attachment、RDS cluster membershipが変更 | 承認失効、AWS書き込み0件 |
| T-008 | PREPARED永続化失敗 | AWS書き込み0件 |
| T-009 | 1件目のAPI成功直後、プロセス停止 | 事前永続記録が残る。復旧は読み取りのみ。結果不明ならOUTCOME_UNKNOWN |
| T-010 | API timeout / 429 / 5xx | 変更APIの自動再試行0回、後続も停止 |
| T-011 | Name以外のタグを持つ対象 | 他キー／値が一切変わらない。S3など集合置換APIは拒否 |
| T-012 | `Y` / `dryrun` / `apply`（Gate未通過） | あらゆるAWS変更APIへの呼び出し0回 |
| T-013 | IAMによるTagKeys/ResourceTag制約 | action・リソース単位に条件の可否を独立検証。未証明ならBLOCKED |
| T-014 | Name追加・空文字から非空への変更によるABAC・EventBridge等の反応 | 本番影響が評価されていない場合はBLOCKED |
| T-015 | EMPTYのNameを別writerがNONEMPTYへ更新する競合 | 他者の非空Nameが必ず保持される証明がなければGate BLOCKED |
| T-016 | 非空Nameから空文字へ変わる競合 | 書き込み瞬間の状態に対する原子的条件評価ができない場合はGate BLOCKED |
| T-017 | レポート・監査でABSENTとEMPTYを混同 | 同一 `existing_name=""` に潰さず、`name_key_present` と `name_state` を検証 |

T-003は「モックで期待通り動いた」だけでは不十分。サービスの公的API契約とAWS側の競合動作が裏付けられない場合、書き込み機構は本番不可。

## 8. GateとOwner決裁

| Gate | 証明すること | 現状 |
|---|---|---|
| G0 | v3.5のsource/dryrun証跡とSHA-256固定 | **BASELINE CAPTURED**（承認とは別） |
| G1 | サービス別の原子的ABSENT-or-EMPTY-only書き込み保証（両状態を別々に証明） | **NOT PROVEN → BLOCKED** |
| G2 | IAM/他writer/外部自動化の影響と制御範囲 | **NOT VERIFIED** |
| G3 | 永続監査・クラッシュ復旧・outcome_unknown | **DESIGN ONLY / NOT TESTED** |
| G4 | 対象サービス別の競合再現・負例テスト | **NOT STARTED** |
| G5 | 58候補の正規承認（特にmedium 12件、RDS要注意6件） | **0 APPROVED / PENDING** |
| G6 | 人間Ownerの正式WRITE承認・対象/期間/IAM限定 | **NOT GRANTED** |

**統合判定：WRITE = BLOCKED。** Gate完了前のコード変更、書き込み機能復活、AWS/IAM変更、実AWSでの書き込み試験を本書は許可しない。

## 9. 次のタスク（推奨）

1. **G1調査のみ:** AWSサービス別の現行 `Name` 追加API、CAS/IfAbsent/IfEmpty相当の有無、IAM条件と競合時の保証を調査して、証拠URL・API版・対象リソース種別とともに表へ整理する。
2. **G2影響調査のみ:** 読み取り専用で、NameがABACや自動化の条件に使われていないか確認するための調査計画を作る。IAM/SCP/リソース構成は変更しない。
3. **G3設計審査:** 監査/障害復旧プロトコルを別担当がレビューする。実装しない。
4. **G5候補レビュー:** `medium` 12件と親RDS Name未設定6件の根拠を人が確認する。レポート中の `high` は許可ではない。
5. **再審査:** G1未実証であれば書き込みの設計は差し戻し、Safety Holdのまま Name補完候補レポートの運用を継続する。

## 10. 参考資料（設計判断の外部根拠）

- [AWS EC2 CreateTags API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateTags.html) — 同じキーは上書き、`DryRun` は権限検査。
- [AWS RDS Tagging](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html) — 同じキーは上書き。
- [AWS IAM tag-based access control](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_tags.html) — RequestTag / TagKeys / ResourceTag の意味とサービス差異。
- [AWS DynamoDB conditional writes](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html) — DynamoDBレコードへの条件付き書き込みであり、他サービスのタグ原子性とは無関係。
- [AWS CloudTrail consistency](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-data-consistency.html) — 伝播遅延と結果整合性。

---

**R1.1の境界:** 本書は書き込みを再開する実装指示・権限付与・正式承認ではない。レビュー対象としてのみ扱う。
