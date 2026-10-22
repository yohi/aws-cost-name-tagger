# G2 — Offline Evidence Bundle Acquisition Contract R1.1

**作成日:** 2026-10-22 JST  
**改訂:** R1.1 — PR #3 independent review FND-001〜004の限定是正（G1・Python実装は不変）  
**対象アカウント:** AWS `456720798575`  
**依存する設計:** `aws_cost_name_tagger_write_architecture_r1_1.md` および `docs/gates/G1_NATIVE_NAME_TAGGING_STATIC_RECHECK_R2_2026-10-22.md`  
**状態:** **PROPOSAL / NOT_EXECUTED / NO_ACCESS_GRANT**。AWSへの接続・IAM/SCP変更・Nameタグ操作をこの文書は一切許可しない。  
**目的:** AWS実環境アクセスを最小化し、固定した時点の読み取り証拠を安全に収集して、それ以降の調査・独立レビューをオフラインで進める。

## 1. 原則と調査範囲

1. AWS認証情報・アクセスキー・STSトークン・Secret値を証拠ZIPに含めない。read-only呼び出し限定。実行時にもアカウントIDをSTSで照合する。
2. **本契約は実行手順の設計であり、実行指示ではない。** コマンドやスクリプトの自動実行、クラウド接続、IAM変更、`TagResource`等の呼び出しは不可。
3. IAMポリシーのAllow・AWS管理ポリシーの名前だけで実効権限を証明しない。各Allow/Deny、グループ継承、AssumeRole信頼関係、Permission Boundary、SCP/RCP、セッションポリシー、リソースポリシーを区別する。
4. AWSの複数API取得は**原子的な単一時点スナップショットではない**。取得開始／終了の重要状態を照合し、収集中の変更や判定不能があれば `INCONSISTENT` / `UNKNOWN` として、単一時点の権限を断言しない（FND-004）。
5. CloudTrail Event History、TrailのS3配信原本、既存CloudTrail Lakeは**独立した証拠源**として範囲を記録する。リージョン・時間・イベント種別・ページ数・欠損と重複を記録し、一部しか調査できなければ **PARTIAL** にする（FND-002）。
6. IAM Identity CenterのPermission Set／アカウント割当／Identity Storeを、通常のIAMロール情報とは別の認可経路として追跡する。STSセッション条件・外部フェデレーション等、再現できない経路は `UNKNOWN`（FND-001）。
7. 原本は**制限付きRAW**で不変保存し、共有が必要な場合のみ**別ファイル**にマスキング済みデータを派生させ、双方のSHA-256と変換履歴で結ぶ。適切に保護できない秘匿値が現れたら収集・共有を停止する（FND-003）。
8. **G1がNOT PROVENである限り、G2がすべて揃ってもAWS WRITEはBLOCKED**。

## 2. 最小Evidence Bundleフォーマット（案）

```text
G2_EVIDENCE_BUNDLE_<UTC_TIMESTAMP>/
  00_READ_FIRST.md
  01_SCOPE.json
  02_ACQUISITION_MANIFEST.json
  03_SHA256SUMS.txt
  raw_secure/                      # アクセス制御された原本専用。共有・公開禁止
    sts_identity.json
    iam_authorization_details.json
    iam_managed_policy_versions.json
    iam_group_role_user_links.json
    identity_center_instances.json
    identity_center_permission_sets.json
    identity_center_account_assignments.json
    identity_store_principal_memberships.json
    federated_and_session_context_gaps.json
    org_scp_scope.json
    org_scp_policies.json
    org_other_policy_scope.json
    cloudtrail_event_history.jsonl
    cloudtrail_trail_configuration.json
    cloudtrail_trail_s3_logs_manifest.json
    cloudtrail_lake_data_stores.json
    cloudtrail_name_tag_events.jsonl  # 解析前の収集ソースは別途保持
    cloudtrail_event_coverage.json
    cloudformation_stack_inventory.json
    automation_writer_inventory.json
    name_sensitive_consumers.json
    candidate_resource_mapping.json
    snapshot_consistency_checks.json
  redacted_shared/                 # 共有時のみ作成。raw_secureと別バイト列・別ハッシュ
    derived_manifest.json
    <approved_sanitized_outputs>
  analysis/
    01_permissions_graph.json
    02_writer_candidates.csv
    03_name_event_coverage.csv
    04_evidence_gaps.csv
    05_g2_gate_preassessment.md
```

ディレクトリ構造とファイル名は論理例であり、収集を指示しない。証拠が取れない場合に空の「成功ファイル」を偽装せず、manifestに `ACCESS_DENIED` / `NOT_ATTEMPTED` / `FAILED` / `PARTIAL` / `INCONSISTENT` / `UNKNOWN` を記録する。

**FND-003：2層の証拠境界** — `raw_secure/`は限定権限・暗号化・非公開保管の**収集原本**、`redacted_shared/`は許可された範囲にマスキング・最小化した**別成果物**。収集原本のファイル自体を書き換えてマスキングしない。変換後の別SHA-256、原本ハッシュへの参照、変換手順／版／実施者／日時／対象フィールド／検証結果を派生manifestに記録し、公開リポジトリへ生の権限情報を置かない。原本の保管先に必要な保護がない場合や、禁止された資格情報・Secret本文を取得せざるを得ないと判明した場合は**取得前にSTOP**。偶発的に混入した場合は以後の共有・処理を停止し隔離、承認済みの安全対応でのみ扱う。SHA-256値は機密性の代わりにならない。

### Manifest必須フィールド

```json
{
  "schema_version": "g2-evidence-1.1",
  "account_id": "456720798575",
  "snapshot_started_at_utc": null,
  "snapshot_completed_at_utc": null,
  "snapshot_atomic": false,
  "snapshot_consistency_status": "NOT_ATTEMPTED",
  "snapshot_consistency_evidence": [],
  "collector_principal_arn": null,
  "read_only_assertion": "REQUIRES_INDEPENDENT_VERIFICATION",
  "source_baseline_sha": "2e8f048a81366849b7324a3fa25739a72332b347",
  "files": [
    {
      "evidence_id": "G2-A01",
      "source": "IAM",
      "raw_path": "raw_secure/example.json",
      "derived_path": null,
      "api": "iam:GetAccountAuthorizationDetails",
      "scope": "account",
      "started_at_utc": null,
      "completed_at_utc": null,
      "pages": 0,
      "pagination_complete": false,
      "status": "NOT_ATTEMPTED",
      "raw_sha256": null,
      "raw_bytes": null,
      "derived_sha256": null,
      "transform_log_ref": null,
      "limitations": []
    }
  ]
}
```

- 実収集では全件とページ終端、各API結果／エラー／リージョン／収集時刻を明記。例示の`null`を完了値として扱わない。
- `SHA256SUMS` は`raw_secure`の**取得直後の原本バイト列**と、`redacted_shared`の**派生バイト列**を別エントリとして計算。原本のZIP CRC・外側SHA-256も記録する。マスキング後の値を原本SHAとして再使用しない。
- `redacted_shared/derived_manifest.json`は各 `source_raw_sha256` → `derived_sha256` の対応と変換履歴を保持（原本ACLを迂回する漏洩を避けるため共有manifestの参照情報自体も精査）。原本の変更は禁止。
- 個人名、内部ユーザー、権限構成、ARN、タグ値、CloudTrailイベントは一般公開しない。原本と派生物で異なるアクセス権限を設定し、共有可能な結果だけを明示的に承認する。
- `snapshot_consistency_status`は`NOT_ATTEMPTED / CONSISTENT_WITHIN_CHECKED_FIELDS / INCONSISTENT / UNKNOWN`。`CONSISTENT_WITHIN_CHECKED_FIELDS`は**同一時点であることの証明ではない**。

## 3. G2-A取得マトリクス

| ID | 必須証拠 | 読み取りAPI候補・根拠 | 完了判定 |
|---|---|---|---|
| G2-A01 | 主体・グループ・Role・全IAM policy | `GetAccountAuthorizationDetails`、不足分は`GetPolicy`＋`GetPolicyVersion`／`GetRolePolicy`／`GetUserPolicy`／`GetGroupPolicy` | ロール、ユーザー、グループ、inlineとmanaged、default version、Resource、Condition、Allow/Denyを全件記録 |
| G2-A02 | グループ継承・role trust・AssumeRole可能経路 | `ListGroupsForUser`、`GetRole`、IAM principal policies | 条件付き経路と外部ID・Principalを明記。Principalの相互到達性は別途検証 |
| G2-A02a | IAM Identity CenterのPermission Set→Account→IAM Role→User/Group | `ListInstances`、`ListPermissionSets`、`DescribePermissionSet`、`GetInlinePolicyForPermissionSet`、`ListManagedPoliciesInPermissionSet`、`ListCustomerManagedPolicyReferencesInPermissionSet`、`ListAccountsForProvisionedPermissionSet`、`ListAccountAssignments`、Identity Store `DescribeUser` / `DescribeGroup` / `ListGroupMemberships` | 対象アカウントのAssignment、PrincipalId↔User/Group、Permission Set版／Provisioned Roleを連結。インスタンスや権限が取得できない、STS session policy／session tags／外部フェデレーションが解決できない場合は`UNKNOWN` |
| G2-A03 | Organizations管理構造・SCP/RCP | `DescribeOrganization`、`ListParents`、`ListPoliciesForTarget`、`DescribePolicy` 等 | 管理アカウント／委任管理権限が必要なら未取得として分離。ターゲットへの継承を証明 |
| G2-A04 | セッション・境界・リソースポリシー | IAM boundary情報、対象サービスの`Get*Policy`等 | 条件の欠落も記録。実効権限の単純な集合和を禁止 |
| G2-A05 | 実タグ変更履歴（3経路を独立取得） | **Event History:** `LookupEvents`。**Trail→S3:** `GetTrail` / `GetEventSelectors` / `GetTrailStatus` で設定照合し、アクセス許可がある場合のみ`ListObjectsV2` / `GetObject` で配信済みログ原本を取得。**既存CloudTrail Lake:** `ListEventDataStores` / `GetEventDataStore` で存在・設定を確認（Queryの開始は別途承認） | 経路ごとに取得可能性、リージョン・アカウント・期間・eventCategory・イベントソース・取得件数・ページ終端・権限拒否／欠損／遅延を固定し、Event IDと元sourceを保持して重複排除後、対象58候補に照合。未取得経路を網羅済みと主張しない |
| G2-A06 | 全writer候補の自動化構成 | CloudFormation stacks、EventBridge Rules/Scheduler、Lambda設定、Step Functions、CodeBuild等の**設定だけ** | リソースの列挙・詳細取得の両方。コード実行・secret取得なし |
| G2-A07 | Nameで駆動するABAC／副作用 | Policy本文、EventBridgeパターン、アプリ設定の非機密メタデータ。API Gateway REST APIとStage双方のタグ、および継承条件 | `Name`を条件・入力・連携キーに使う場所のリスト。REST API→Stageの継承タグがABACへ影響するか確認し、未取得はUNKNOWN |
| G2-A08 | Name候補の現在値・関連根拠 | 元のv3.6 dryrunプラン＋各サービスのタグ読み取りAPI。API GatewayはStageと親REST APIを区別 | `ABSENT/EMPTY/NONEMPTY/UNKNOWN` を区別。ARN/リージョン/親関係を固定。API Gateway `GetTags`は継承タグを返さないため、Stage直接タグとREST API由来のABAC上の継承タグを**別列**で保存。継承タグはCost Explorerのコスト配分タグに使えない |
| G2-A09 | 収集の完全性・時間整合性 | STS照合、リージョン一覧、ページネーション・APIログ、SHA256SUMS、およびIAM／SCP／Nameタグ等の開始・終了時の独立再読取 | アカウント一致と予定範囲の完走。policy default version／document hash、Assignment、SCP対象／版、対象Name／ARNを前後で比較し、不一致は`INCONSISTENT`。確認不能は`UNKNOWN`。AccessDeniedを成功として隠さない |

**FND-002：CloudTrailの独立3ソース・完全性契約**

1. **Event History / `LookupEvents`:** 原則直近90日の管理イベント、**アカウントとリージョン別**。Trail/Lakeの設定とは独立した取得元であり、これだけを全履歴としない。イベント名・時刻・ページ継続トークンの最終状態を保存する。
2. **TrailでS3に配信済みのログ:** Trailの配送先・prefix・selectors・全リージョン設定・配送/取得期間を確認し、対象範囲の`*.json.gz`**原本バイト列**を保全する。IAM権限・暗号鍵・他アカウントbucket等で取得できない場合は`ACCESS_DENIED` / `UNKNOWN`。配信遅延・保持期限・途中欠落、digest検証の可否も記録し、Trailが存在するだけでイベント原本を取得済みとはみなさない。
3. **既存のCloudTrail Lake:** Event Data Storeの有無と対象アカウント・リージョン・イベント種別・保存期間を調べる。既存のStoreにクエリが必要でも`StartQuery`は別途コスト・権限・実行承認が必要なため、本契約のみでは実行しない。未配置／権限不足／利用不可ならそれぞれ`NOT_CONFIGURED` / `ACCESS_DENIED` / `UNKNOWN`とし、不可用期間の完全性を主張しない。新規Lake作成はスコープ外。

全ソースからのイベントには`source`・`account`・`region`・`eventTime`・`eventID`・`eventSource`・`eventName`・`requestParameters.Name`該当箇所・対象ARNの出所を記録。原本を維持したままイベント識別子（同一イベントIDとアカウント・リージョン等）で重複を整理し、**ソース重複と異なるイベントの誤マージを区別**する。ソース別のcoverageは併合せず保持し、欠損区間・非記録カテゴリを別途示す。高頻度`CreateTags`の一部ページだけで「Name更新0件」と宣言してはならない。

**FND-001：Identity Centerの経路を展開する条件**

- インスタンスはRegionごとに`ListInstances`の結果と参照先を記録。東京でインスタンスが0件でも全リージョン・委任管理先で不在と断言しない。
- Permission Setが実際にどのアカウントへプロビジョニングされたか、当該アカウントにどのUser/Groupが割り当てられたかを参照し、`AWSReservedSSO_*`等のIAM Roleとの関係を根拠付きで追う。割当のないPermission Setから存在しない利用主体を推定しない。
- Identity StoreのGroup membershipも展開し、`principal_id`の名前解決に失敗したら`UNKNOWN`。外部IdP・SAML/OIDC・STS Session Policy/Tag・フェデレーション元は別根拠が取れない限り`UNKNOWN`であり、Role一覧のみでは完全性を宣言しない。

**API Gateway固有の注意（G2-A07/A08）:** REST APIの親タグは子Stage等へ**ABAC用途でのみ継承**される。子Stageの直接設定タグが同キーでは優先される。`GetTags`は継承タグを返さず、継承タグはCost Explorerのコスト配分タグには利用されない。よって「GetTagsにNameがない」と「認可コンテキストにNameがない」を同義に扱わない。

### FND-004：収集中の構成変更／時間整合性の判定

- **BEGINチェック:** STS、IAM Role・User・Groupと接続ポリシーの参照、managed policyの`DefaultVersionId`と本文SHA-256、inline policyハッシュ、Identity Center Assignment、SCP/RCP継承範囲、対象ARN・Name状態・親関連を時刻付きで採取する。
- **ENDチェック:** 同じ識別子・バージョン・ドキュメントハッシュ・状態を可能な限り再取得しBEGINと比較する。途中で取得した各オブジェクトにも収集時刻・版を付ける。CloudTrail等で期間中の関連変更が判明した場合は差分の根拠を保存する。
- **変更検出:** 前後で不一致／取得中に変更が観測された項目があれば`INCONSISTENT`としてGate判定を止める。未取得／AccessDenied／ページ未完／比較不可は`UNKNOWN`または`PARTIAL`にし、整合と推定しない。矛盾した結果を混在したまま`COMPLETE`にしない。
- **限界:** BEGIN/ENDの一致だけでは中間での変更・復元（ABA）を排除できず、複数サービス横断の単一時点・原子的snapshotにはならない。検査済みフィールドについて一貫した観測ができた場合だけ`CONSISTENT_WITHIN_CHECKED_FIELDS`を使用。
- **復旧:** `INCONSISTENT`であれば当該Bundleを未承認として封印し、後続の再取得は新しいsnapshot IDで別証拠として行う。旧Bundleを書き換えて整合したことにしない。

## 4. 前回までの部分的な観測値（新規証拠ではない）

以下は先行G2-A調査で観測した**過去スナップショットの背景情報**であり、このドキュメント作成にあたりAWSへ再接続・再取得はしていない。これらだけではbundleの完全性要件を満たさない。

- 対象アカウントとのSTS一致、IAM role 113、user 75、group 6、カスタマー管理policy 98を確認。
- `AdministratorAccess`等の広い権限の**直接アタッチ関係**について、role/user/groupの一次抽出28件。全員の実効Tag書込可能性を示す数字ではない。
- OrganizationsでSCPの有効化を確認したが、`ListRoots`はAccessDenied。
- CloudTrail `cloudtrail-log` のIsLogging、multi-region、ログ検証設定を確認。
- ECS `TagResource`で`Name`キーの操作1件を確認。AWSコンソールまたは別主体の操作を含む全経路の不存在を証明しない。
- 東京リージョンの`CreateTags`は少なくとも350イベントまで探索して続きがあった。そこまでのサンプルでNameキーの該当なしでも網羅性はUNKNOWN。

当該CloudTrailイベントと対象58候補の関連、直前直後のタグ値、他regionの履歴は**未確認**。

## 5. 解析者のオフライン成果物

### permission graph
`Principal → IAM Group / Identity Center Assignment + Permission Set + Identity Store Membership / Federation → Role assumption → Attached/Inline Policy Version → Allow/Deny → Resource/Condition → SCP/Boundary/Session → Candidate ARN`を根拠つきで構成。各辺にevidence IDと該当JSONパスを保持し、展開できないmanaged policy／外部IdP／セッションコンテキストはUNKNOWNとする.

### writer candidate table

`principal_id,principal_type,action,resource_scope,name_tag_condition,allow_evidence,deny_evidence,group_inheritance,identity_center_assignment,permission_set,identity_store_membership,assume_role_path,session_context,policy_boundary,scp_scope,confidence,unknowns`。潜在権限と実際のCloudTrail操作主体を別列で保持。

### Name event coverage
`account,region,acquisition_source,source_id,event_category,event_source,event_name,from_utc,to_utc,pages_read,pagination_complete,records_seen,name_tag_events,dedupe_key,duplicates,missing_intervals,source_status,redaction_status`。Event History／Trail S3／Lakeのソース別coverageを保存。ゼロ件は「完全にスキャンした当該範囲で0」とだけ表現し、リソースの過去全期間の変更ゼロと混同しない。

## 6. 成功／失敗基準と実行権限

- **Evidence capture READY** = 主体照合・スコープ・最小権限・非公開保管・ログ・エラー記録・停止条件が明確。
- **Evidence capture COMPLETE** = 必須項目で保護されたRAW原本と派生物双方のハッシュ・変換履歴が検証され、各source/region/期間/イベント種別/ページ網羅が満たされ、時間整合性が`CONSISTENT_WITHIN_CHECKED_FIELDS`（限定的意味）であること。必須範囲に`INCONSISTENT` / `UNKNOWN` / `PARTIAL` / `ACCESS_DENIED`があれば原則COMPLETEとしない。例外的な補完証拠の採用には独立レビューが必要。
- **G2 VERIFIED** = 独立レビュアーが全writerの権限・実行/変更経路・現在のName利用副作用を対象候補ごとに検証。収集完了だけでは達成しない。
- **G1依存** = `G1 NOT PROVEN`である限り、`G2 VERIFIED`でもタグの書き込みGateを通せない。
- `AccessDenied`、Identity Center割当未取得、pagination未完了、Trail原本やLakeの欠落、組織管理アカウントの証拠なし、外部自動化・CloudTrailの不足、RAW保護不能、スナップショット不整合は**OPEN**として扱う。
- 人間Ownerが取得・保存先・対象期間・接続方法を**別途**明示的に承認するまで、このドキュメントをもってAWSアクセスを開始しない。

### 出典（是正事項の一次資料）

- [IAM Identity Center ListAccountAssignments](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListAccountAssignments.html)／[ListPermissionSets](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListPermissionSets.html)／[ListAccountsForProvisionedPermissionSet](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListAccountsForProvisionedPermissionSet.html)
- [CloudTrail Event Historyの範囲と制約](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)／[Trail S3配信原本の取得](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html)／[既存Lake Event Data Stores](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListEventDataStores.html)
- [API Gatewayタグ継承／GetTags／Cost Explorerの制約](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-tagging-supported-resources.html)

## 7. 結論と次の実務

**現時点の推奨:** まずG1未証明の厳格要件を維持し、G2は「一括の読み取り証拠を収集してオフライン解析」する準備まで進める。公開リポジトリに生のIAM/CloudTrailインベントリをコミットしない。

既存コードの `write_name()`・`apply()` とSafety Hold、G1〜G6の判定、Owner承認状態は**不変**。
