# G2 — Offline Evidence Bundle Acquisition Contract R1

**作成日:** 2026-10-22 JST  
**対象アカウント:** AWS `456720798575`  
**依存する設計:** `aws_cost_name_tagger_write_architecture_r1_1.md` および `docs/gates/G1_NATIVE_NAME_TAGGING_STATIC_RECHECK_R2_2026-10-22.md`  
**状態:** **PROPOSAL / NOT_EXECUTED / NO_ACCESS_GRANT**。AWSへの接続・IAM/SCP変更・Nameタグ操作をこの文書は一切許可しない。  
**目的:** AWS実環境アクセスを最小化し、固定した時点の読み取り証拠を安全に収集して、それ以降の調査・独立レビューをオフラインで進める。

## 1. 原則と調査範囲

1. AWS認証情報・アクセスキー・STSトークン・Secret値を証拠ZIPに含めない。read-only呼び出し限定。実行時にもアカウントIDをSTSで照合する。
2. **本契約は実行手順の設計であり、実行指示ではない。** コマンドやスクリプトの自動実行、クラウド接続、IAM変更、`TagResource`等の呼び出しは不可。
3. IAMポリシーのAllow・AWS管理ポリシーの名前だけで実効権限を証明しない。各Allow/Deny、グループ継承、AssumeRole信頼関係、Permission Boundary、SCP/RCP、セッションポリシー、リソースポリシーを区別する。
4. 取得した構成は**スナップショット時点のみ**の証拠。以降の変更に対する「現在も安全」の証明ではない。
5. 頻繁なタグ操作があるCloudTrailやイベント駆動処理は、地域・時間・ページ数・保持期間をすべて記録し、検索結果が一部なら **PARTIAL** にする。
6. **G1がNOT PROVENである限り、G2がすべて揃ってもAWS WRITEはBLOCKED**。

## 2. 最小Evidence Bundleフォーマット（案）

```text
G2_EVIDENCE_BUNDLE_<UTC_TIMESTAMP>/
  00_READ_FIRST.md
  01_SCOPE.json
  02_ACQUISITION_MANIFEST.json
  03_SHA256SUMS.txt
  raw/
    sts_identity.json
    iam_authorization_details.json
    iam_managed_policy_versions.json
    iam_group_role_user_links.json
    org_scp_scope.json
    org_scp_policies.json
    org_other_policy_scope.json
    identity_center_instances.json
    cloudtrail_trail_configuration.json
    cloudtrail_name_tag_events.jsonl
    cloudtrail_event_coverage.json
    cloudformation_stack_inventory.json
    automation_writer_inventory.json
    name_sensitive_consumers.json
    candidate_resource_mapping.json
  analysis/
    01_permissions_graph.json
    02_writer_candidates.csv
    03_name_event_coverage.csv
    04_evidence_gaps.csv
    05_g2_gate_preassessment.md
```

`raw/`ファイル名は論理的な例。証拠が取れない場合、空の「成功ファイル」を偽装せず、manifestに `ACCESS_DENIED` / `NOT_ATTEMPTED` / `FAILED` / `PARTIAL` を記録する。秘密・個人情報を適切にマスキングした**非公開**のBundleを保管する。公開GitHubには匿名化した集計や設計のみ置く。

### Manifest必須フィールド

```json
{
  "schema_version": "g2-evidence-1",
  "account_id": "456720798575",
  "snapshot_started_at_utc": null,
  "snapshot_completed_at_utc": null,
  "collector_principal_arn": null,
  "read_only_assertion": "REQUIRES_INDEPENDENT_VERIFICATION",
  "source_baseline_sha": "2e8f048a81366849b7324a3fa25739a72332b347",
  "files": [
    {
      "evidence_id": "G2-A01",
      "path": "raw/example.json",
      "api": "iam:GetAccountAuthorizationDetails",
      "scope": "account",
      "started_at_utc": null,
      "completed_at_utc": null,
      "pages": 0,
      "pagination_complete": false,
      "status": "NOT_ATTEMPTED",
      "sha256": null,
      "bytes": null,
      "redactions": [],
      "limitations": []
    }
  ]
}
```

- 実収集ではリストの全件、ページの継続トークン終了、各呼出し結果／エラー／Regionを明記。テスト用の`null`を完了値として扱わない。
- `SHA256SUMS` は収集済みファイルの原本バイト列に対して算出し、アーカイブCRCと外側SHA-256も独立提示する。
- 正規化・匿名化・分析結果はrawと分離する。原本の変更は許可しない。
- 個人名、内部ユーザー、アクセス構成、ARN、タグ値、CloudTrailイベントは一般公開しない。共有にはアクセス制御された別保存先を使う。

## 3. G2-A取得マトリクス

| ID | 必須証拠 | 読み取りAPI候補・根拠 | 完了判定 |
|---|---|---|---|
| G2-A01 | 主体・グループ・Role・全IAM policy | `GetAccountAuthorizationDetails`、不足分は`GetPolicy`＋`GetPolicyVersion`／`GetRolePolicy`／`GetUserPolicy`／`GetGroupPolicy` | ロール、ユーザー、グループ、inlineとmanaged、default version、Resource、Condition、Allow/Denyを全件記録 |
| G2-A02 | グループ継承・role trust・AssumeRole可能経路 | `ListGroupsForUser`、`GetRole`、IAM principal policies | 条件付き経路と外部ID・Principalを明記。Principalの相互到達性は別途検証 |
| G2-A03 | Organizations管理構造・SCP/RCP | `DescribeOrganization`、`ListParents`、`ListPoliciesForTarget`、`DescribePolicy` 等 | 管理アカウント／委任管理権限が必要なら未取得として分離。ターゲットへの継承を証明 |
| G2-A04 | セッション・境界・リソースポリシー | IAM boundary情報、対象サービスの`Get*Policy`等 | 条件の欠落も記録。実効権限の単純な集合和を禁止 |
| G2-A05 | 実タグ変更履歴 | `LookupEvents`（CloudTrail管理イベント）、Trailのイベントセレクタと保存先 | サービス・region・期間・ページ終端・タグkeyを正規化し、対象58候補に照合 |
| G2-A06 | 全writer候補の自動化構成 | CloudFormation stacks、EventBridge Rules/Scheduler、Lambda設定、Step Functions、CodeBuild等の**設定だけ** | リソースの列挙・詳細取得の両方。コード実行・secret取得なし |
| G2-A07 | Nameで駆動するABAC／副作用 | Policy本文、EventBridgeパターン、アプリ設定の非機密メタデータ | `Name`を条件・入力・連携キーに使う場所のリスト。未取得はUNKNOWN |
| G2-A08 | Name候補の現在値・関連根拠 | 元のv3.6 dryrunプラン＋各サービスのタグ読み取りAPI | `ABSENT/EMPTY/NONEMPTY/UNKNOWN` を区別。ARN/リージョン/親関係を固定 |
| G2-A09 | 収集の完全性 | STS照合、リージョン一覧、ページネーション・APIログ、SHA256SUMS | アカウント一致と全予定範囲の完走。AccessDeniedを成功として隠さない |

**注意:** CloudTrailの`LookupEvents`は原則90日のEvent history／管理イベントの範囲に制約があり、全履歴の欠落がない証拠にはならない。S3・ECS等のタグイベントはAPI名だけでなく`eventSource`・request中の`Name`キー・対象ARNによる照合が必要。高頻度`CreateTags`は一部ページだけで「Name更新0件」と宣言してはならない。

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
`Principal → Group/Role assumption → Attached/Inline Policy Version → Allow/Deny → Resource/Condition → SCP/Boundary/Session → Candidate ARN`を根拠つきで構成。各辺にevidence IDと該当JSONパスを保持し、展開できないmanaged policyはUNKNOWNとする。

### writer candidate table

`principal_id,principal_type,action,resource_scope,name_tag_condition,allow_evidence,deny_evidence,group_inheritance,assume_role_path,policy_boundary,scp_scope,confidence,unknowns`。潜在権限と実際のCloudTrail操作主体を別列で保持。

### Name event coverage
`account,region,event_source,event_name,from_utc,to_utc,pages_read,pagination_complete,records_seen,name_tag_events,redaction_status`。ゼロ件は「完全にスキャンした当該範囲で0」とだけ表現し、リソースの過去全期間の変更ゼロと混同しない。

## 6. 成功／失敗基準と実行権限

- **Evidence capture READY** = 主体照合・スコープ・最小権限・非公開保管・ログ・エラー記録・停止条件が明確。
- **Evidence capture COMPLETE** = 必須項目で原本と整合性検証、region/ページ網羅が満たされている。権限拒否がある場合は補完証拠または制約を明記し、無理にCOMPLETEとしない。
- **G2 VERIFIED** = 独立レビュアーが全writerの権限・実行/変更経路・現在のName利用副作用を対象候補ごとに検証。収集完了だけでは達成しない。
- **G1依存** = `G1 NOT PROVEN`である限り、`G2 VERIFIED`でもタグの書き込みGateを通せない。
- `AccessDenied`、pagination未完了、組織管理アカウントの証拠なし、外部自動化・CloudTrailの不足は**OPEN**として扱う。
- 人間Ownerが取得・保存先・対象期間・接続方法を**別途**明示的に承認するまで、このドキュメントをもってAWSアクセスを開始しない。

## 7. 結論と次の実務

**現時点の推奨:** まずG1未証明の厳格要件を維持し、G2は「一括の読み取り証拠を収集してオフライン解析」する準備まで進める。公開リポジトリに生のIAM/CloudTrailインベントリをコミットしない。

既存コードの `write_name()`・`apply()` とSafety Hold、G1〜G6の判定、Owner承認状態は**不変**。
