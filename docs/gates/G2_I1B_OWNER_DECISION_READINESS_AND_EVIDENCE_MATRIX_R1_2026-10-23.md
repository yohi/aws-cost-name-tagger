# G2-I1-B — Evidence Acquisition / Owner Decision Readiness Matrix R2

**基準日:** 2026-10-23（JST）  
**役割:** 参照設計の独立審査入力と、将来の人間Ownerによる**別途の取得認可判断の準備**。  
**上位仕様:** [G2 R1.1契約](G2_OFFLINE_EVIDENCE_BUNDLE_CONTRACT_R1_2026-10-22.md) / [G2-I1-B R2参照設計](G2_I1B_READ_ONLY_COLLECTOR_REFERENCE_DESIGN_R1_2026-10-23.md)（従来ファイル名を維持）
**現在の決定:** **R1 REVISION_REQUIRED / R2 CORRECTED_IN_PROPOSAL / INDEPENDENT_REVIEW_PENDING / NO HUMAN EXECUTION GRANT / NO AWS CONNECTION / DESIGN REVIEW ONLY**。この文書にOwner署名・承認トークンは含まない。

## 1. 3つの独立Gateを混同しない

| Gate | 通過に必要な証拠 | 本PRでの結果 |
|---|---|---|
| **Design Review Gate** | API × Account × Context × Region/期間 × 最小権限の整合性、Manifest/RAW保護、Fail Closed、独立技術レビュー | **PROPOSAL / INDEPENDENT_REVIEW_PENDING** |
| **Execution Authorization Gate** | 人間Ownerが限定取得計画・対象principal・Role・保存先・期間・最大費用／回数／bytes・有効期限を**別の署名済み記録**として承認 | **NOT_GRANTED** |
| **Evidence / G2 Acceptance Gate** | 実AWS RAW原本、Source別coverage、IAM/SCP/SSOの権限推論、CloudTrailの3系統、BEGIN/END、独立再照合 | **NOT_EXECUTED / NOT_VERIFIED** |

`READY_FOR_IMPLEMENTATION`≠`READY_FOR_EXECUTION`≠`G2 VERIFIED`。全てのGateが通過してもG1がNOT PROVENであればAWS WRITEはBLOCKED。

## 2. 具体的なEvidence取得・証明義務マトリクス

| G2-ID | Source/主体 | 捕捉と照合の要求（**完了条件**） | 現在の未証明・制約 |
|---|---|---|---|
| **A01** | P1/IAM | `GetAccountAuthorizationDetails`のFilterを本計画では`[User, Role, Group, LocalManagedPolicy, AWSManagedPolicy]`に固定。全5種別のレスポンス検証、全`IsTruncated/Marker`ページ終端、managed PolicyARN→DefaultVersionId→本文SHA・添付関係を照合 | Filter/種別漏れ・policy版本文不足はPARTIAL/UNKNOWN。実効権限の完全性は別証拠 |
| **A02** | P1/IAM + external trust | `ListGroupsForUser`・Role trust・AssumeRole条件・ExternalId・Permissions Boundary等をアカウント／principal別に展開 | AssumeRoleの実行なし。セッションポリシー／外部IdPの不明領域はUNKNOWN |
| **A02a** | P3/Identity Center | InstanceArn → PermissionSetArn → account provisioning → AccountAssignment → PrincipalId → IdentityStore group membership → Roleと政策本文をevidence IDでjoin | 専用P3 grant・IdP連携証拠なし。単なるRole列挙ではActor到達性はUNKNOWN |
| **A03** | P2/Organizations | 対象AccountからOU/rootまでListParentsを辿り、各targetのSCP/RCP direct attachmentsと`DescribePolicy`本文・適用範囲を確定 | 管理／delegated principal未決。組織管理主体にアクセスできない場合、継承範囲はUNKNOWN |
| **A04** | P1/P2/P3＋A06 writer＋対象resource | `principal_type`・`account_role`・`service_linked_role`・`resource_account`・`scp_applicable`・`rcp_applicable`・`exception_reason`・`evidence_id`を必須記録。適用・除外・非対応・UNKNOWNを分離し、IAM/Boundary/Session/Resource Policyと別評価 | SCP/RCPの例外を全principalに誤適用してWriter不可能と結論しない。除外≠Allow成立 |
| **A05-EH** | P1 CloudTrail Event History | Account/Region/90日窓/management等カテゴリ/全pagination、EventID/EventSource/EventName/Nameのキー・対象ARN対応を記録 | Event History外の時代・カテゴリ・Regionの非存在は結論できない |
| **A05-Trail** | P1 metadata + P4 S3 raw | 現在設定と時系列設定を区別。`historical_selector_evidence`、`trail_config_change_events`、`logging_disabled_intervals`、`validation_disabled_intervals`、`digest_chain_segments/breaks`、`delivery_gap_intervals`と再配送証拠を記録。SDK `ListObjectsV2`→IAM `s3:ListBucket`を使用し、approved Bucket/Prefix/Token/object/期間/bytesに固定。`GetObject`は別IAM Action | 現時点のGetTrailStatus/selector、BEGIN/END一致だけで過去はCOMPLETE不可。履歴不明はUNKNOWN/PARTIAL、P4未GrantもUNKNOWN |
| **A05-Lake-Account** | P1：対象アカウント | Account-level EDSのRegion/selector/retention/ingestion statusを個別coverage行で記録 | P1の0件はOrganization EDS不存在の証明ではない |
| **A05-Lake-Organization** | P2-Lake：CloudTrail管理/委任管理（別Grant） | Organization EDSは管理アカウント所有。管理・正当な委任管理principalから、対象account、Region、selector、retention、ingestion statusを**独立した**coverage行で確認 | 管理コンテキスト未取得・権限不明ならUNKNOWN。NOT_CONFIGURED禁止。StartQueryは別承認 |
| **A06** | 対象構成 / IaC | CloudFormation・EventBridge・Lambda・StepFunctions・CodeBuild等のWriter候補を構成読み取りだけで台帳化。A04の適用判定を**Actor×Resource×Action**で結合し、管理Account principal/SLR/resource accountを確認 | 管理主体・service-linked roleにSCP Denyを誤適用しWriter不可能としない。UNKNOWN actorを削除しない |
| **A07** | Name consumer / ABAC | IAM/Resource policy/EventBridge/アプリ入力のName参照と親子継承を特定。API Gateway REST APIの親タグとStageの直接タグを区別 | API Gatewayの親からの継承タグは`GetTags`で見えず、Cost Explorer配分タグではない |
| **A08** | Name対象ARN / 各タグ読取API | 最新の対象集合を確定し、`ABSENT`／厳密`EMPTY=""`／`NONEMPTY`／`UNKNOWN`をRAW値から区別 | 過去58件は現在集合でない。空白1字や`"\\t"`はNONEMPTYで保護 |
| **A09** | 全Source + custody | Account/Principal/Region/期間/全request/token/RAW/SHA/Manifest/BEGIN-ENDを評価。**各SDKリクエスト直前にGrant取消/有効期限/code/plan fingerprint/principalを再照合**するledgerを記録 | Grant取消後の後続呼び出し0件。in-flightは取消保証せず返却RAW未承認seal。非原子的・ABA未解消、G2 VERIFIED不可 |

各行はさらに`expected_items`、`observed_items`、`api_call_count`、`pages`、`termination_reason`、`evidence_sha256`、`context_id`、`unknowns`を記録する。件数0を「不存在」と断定できるのは、有効なscopeで終端まで検索した範囲に限る。


## 2A. A04×A06 SCP/RCPの適用判定契約（R1-003）

適用性は`actor × action × resource`の粒度で判定する。各レコードに次の**必須フィールド**を持たせる。`service_linked_role`は真偽または未証明`null`。除外・サービス非対応と、証拠不足によるUNKNOWNは別の状態とする。

```json
{
  "principal_type": "ROLE|USER|ROOT|SERVICE_LINKED_ROLE|FEDERATED|AWS_SERVICE|UNKNOWN",
  "principal_account": null,
  "account_role": "MANAGEMENT|MEMBER|DELEGATED_ADMIN_MEMBER|EXTERNAL|UNKNOWN",
  "service_linked_role": null,
  "resource_account": null,
  "resource_service": null,
  "action": null,
  "authorized_resource_types": [],
  "rcp_resource_coverage": "COVERED|NOT_COVERED|UNKNOWN",
  "authorization_reference_evidence_id": null,
  "scp_applicable": "APPLICABLE|EXEMPT|UNKNOWN",
  "rcp_applicable": "APPLICABLE|EXEMPT|NOT_SUPPORTED|UNKNOWN",
  "exception_reason": null,
  "evidence_id": [],
  "effective_write_reachability": "UNKNOWN"
}
```

`authorized_resource_types`は対象`action`のService Authorization Reference（SAR）Action表にある認可Resource typeを、ARN/owner account/必須・任意/証拠IDと一対一で記録する。`rcp_resource_coverage`はCOVERED/NOT_COVERED/UNKNOWNの三値で、ActionとResource typeの一致を確認するまではUNKNOWNを維持する。`authorization_reference_evidence_id`でSAR Action行・取得日・原本ハッシュを結ぶ。対応サービスという情報だけではRCPの適用は確定しない。 

`exception_reason`はEXEMPT/NOT_SUPPORTEDなら必須。`evidence_id`にはIAM Role/SLR識別根拠、Organizations管理/委任管理account情報、対象Resource所有account、SCP/RCPの有効状態と階層attachment、対象サービスの公式サポート根拠を結ぶ。欠落時はUNKNOWNであり、推測で`scp_applicable=false`を埋めない。

| 合成Actor/Resource反例 | `scp_applicable` | `rcp_applicable` | 正しい解釈 |
|---|---|---|---|
| 管理アカウントのRole→管理アカウントResource | EXEMPT | EXEMPT | 両ガードレールを誤適用しない |
| 管理アカウントのRole→RCP対象の**メンバー**Resource | EXEMPT | APPLICABLE | RCPは要求者でなく資源アカウントを基準とする |
| メンバーRole→対応するメンバーResource | APPLICABLE | APPLICABLE | 権限/明示Deny等を別評価 |
| 委任管理**メンバー**Role→対応メンバーResource | APPLICABLE | APPLICABLE | 委任管理という名目だけで除外しない |
| **Service-linked role**→対応メンバーResource | EXEMPT | EXEMPT | SCP/RCPでは制限できない。role trust・service callerも調査 |
| メンバーRole→**RCP非対応サービス** | APPLICABLE | NOT_SUPPORTED | RCPでwriter不可能としない |
| RCP対応サービスだが当該Actionの認可Resource typeが未確定 | APPLICABLE | UNKNOWN | Action/Resource Type未確認はUNKNOWN。Writer候補を残す |
| 対応Actionとメンバー所有認可Resource typeが証拠で一致 | APPLICABLE | APPLICABLE | Resourceごとに`rcp_resource_coverage=COVERED`。RCP Statementの効果は別判定 |
| Principal/SLR/Resource所有者/サービス対応の根拠不明 | UNKNOWN | UNKNOWN | A06 writer候補を消さずOPEN |

RCPは管理アカウントResourceには適用されず、対象は対応サービスのメンバーResource（外部principalからの呼出しにも適用され得る）。SCPは管理アカウントprincipalとSLRを除外。**ガードレール除外は実効ALLOWと同義ではない**。他のIAM/boundary/session/resource policy・trust・denyなどを引き続き検証する。

**実装開始前の必須反例テスト:** 合成SCPがName書込をdenyしていても、管理AccountのRoleやSLRを`IMPOSSIBLE_WRITER`にしない。管理AccountのresourceやRCP非対応serviceへRCP denyを誤適用しない。一方、管理RoleからメンバーResourceへの書き込み経路ではRCP適用を省かない。UNKNOWNのactorはA06台帳に残す。本PRは設計のみでテスト実装なし。

## 2A-1. R2-NEW-002 — Actionの認可Resource TypeとRCP coverage（限定是正）

AWS OrganizationsのRCPは、単にServiceが対応しているかでなく、当該Actionで**認可されるResource type**に作用する。各ActionはAWS Service Authorization Reference（SAR）のAction行／Resource type列と突合する。管理アカウント資源・SLR例外はR1のA04契約を維持する。

- `authorized_resource_types`を各Actionの**配列**とし、要素には`resource_type`、`resource_arn`、`resource_owner_account`、`sar_action_reference`、`required_or_optional`、`evidence_id`を含める。同一APIで複数の認可Resource typeが現れる場合、それぞれを別行で判定し、単純な1つのBooleanにしない。
- `rcp_resource_coverage=COVERED`にできるのは、SAR Action行の認可Resource type、実際のリクエストで認可対象となったARN、対応するメンバーアカウントResource、RCP対応対象が**証拠で一致**したときだけ。RCPのPolicy本文・階層attachment・Conditionの検証は別であり、COVEREDだけではDeny確定でもAllow確定でもない。
- `NOT_COVERED`は対象Action/認可ResourceがRCPの非対応範囲であることを**公式仕様と観測範囲**から確認した場合だけ。サービス対応だけ判明してもAction/Resource typeが不明なら`UNKNOWN`。ARNの所有者、SAR Action行、対応するResource typeのいずれかが欠落したら`UNKNOWN`を維持する。
- SARでResource type欄が空／明示されない場合、その事实と対象SDK/Actionのモデルを記録し、RCP非適用を結論できるか独立照合する。未検証の場合は`UNKNOWN`であり、`rcp_applicable=NOT_SUPPORTED`に自動変換しない。
- A06のWriter閉包は、全ての認可Resource typeの適用性とRCP/その他IAM評価が確定するまでOPEN。`exception_reason`と`authorization_reference_evidence_id`が揃わない除外・非対応の断定は禁止。

**将来の合成反例テスト:** ① RCP対応サービスだが認可Resource typeが不明→UNKNOWN、② 同一サービスのAction A/Bで認可Resource typeが異なる→別結果、③ 複数Resource中1件が不明→全Writerを不可能としない、④ 管理アカウント資源→EXEMPT、⑤メンバー資源のSAR対象Resource type一致→COVERED、⑥SAR版／実SDK認可対象が矛盾→UNKNOWN。本PRではテスト設計のみ、コード実装なし。

## 2B. A05-Trailの時系列証拠／coverage契約（R1-004）

```json
{
  "account": null,
  "region": null,
  "trail_arn": null,
  "approved_window": {"start_utc": null, "end_utc": null},
  "current_selector_snapshot": null,
  "historical_selector_evidence": [],
  "trail_config_change_events": [],
  "logging_disabled_intervals": [],
  "validation_disabled_intervals": [],
  "digest_chain_segments": [],
  "digest_chain_breaks": [],
  "delivery_gap_intervals": [],
  "delivery_retry_evidence": [],
  "source_evidence_ids": [],
  "historical_coverage_status": "UNKNOWN",
  "limitations": ["Current selectors and BEGIN/END do not prove historical event capture"]
}
```

- 取得可能なCloudTrail管理イベントや既存変更記録から、`CreateTrail`/`UpdateTrail`/`PutEventSelectors`/`PutInsightSelectors`/`StartLogging`/`StopLogging`、log file validationの切替、Trail削除/再作成を収集し**時系列の設定変更を再構成**する。変更履歴の取得能力自体が部分的なら「変更がなかった」とは推定しない。
- digestの連鎖は`連続区間`を単位に証明する。CloudTrailのlog file validation無効化、StopLogging、Trail削除、配信先bucket障害等によるdigest断絶、遅延・再配送・順序入替を区別する。現在の`GetTrailStatus`にDeliveryErrorがなくても過去に欠損がないとは断言しない。
- 各区間で設定履歴・S3 original gzip/digest・署名チェーン・ログのeventTime/region/account・配送/retentionを対応付け、未確認区間を`PARTIAL`/`UNKNOWN`とする。矛盾があるとき`INCONSISTENT`。**現在のEventSelector/IsLoggingとBEGIN/END一致だけでは過去全期間`COMPLETE`禁止**。
- 反例：過去の3日間にStopLoggingまたはselector変更を否定できなければ、その区間の`Name更新0件`主張は禁止。

## 2C. Owner Grantの実行中失効契約（R1-006 RESOLVED_IN_REQUIREMENTS / R2-NEW-001 限定是正）

各**物理HTTP送信試行の直前**に署名/承認元のGrant状態・取消・満了時刻・固定コードHEAD・承認済plan SHA・principal/context・paramsを検証する（最初のSTS、ページ2以降、Collector-managed retry、Context切替、BEGIN/END含む）。参照元に到達不能、時計の信用不足、状態不明でも`STOP_GRANT`、**以後の物理HTTP送信ゼロ**。SDK設定は`Config(retries={"mode":"standard","total_max_attempts":1})`で内部再試行を禁止。`before-call`単独の確認は実送信単位の証明ではなく、`before-send`相当の送信直前guardとtransport送信数の監査が別途必要。

**実装方式は「SDK内部retry無効化／Collectorのみがretry所有」に固定する。** 各再試行で新`attempt_id`を付け、`CHECK_GRANT` → `CHECK_SCOPE` → `RESERVE_SEND_BUDGET` → `SEND_ONCE`という状態遷移を繰り返す。SDK標準の自動retryだけでなく、custom `needs-retry` handler、redirect、別Client、credential providerの暗黙送信経路が存在するなら、送信境界の観測と制御を証明するまで`RUNTIME_NOT_PROVEN`で停止する。

**失効競合:** 直前チェックと本当の送信の間にOwner取消が割り込むTOCTOUを、単なるローカル時刻比較だけで解決したと主張しない。Owner取消と物理送信認可の線形化を単一`Grant authority`の`revocation_epoch`/`attempt_id`で仲介し、取消完了後の新規送信を禁止できるruntime証拠が未成立なら`STRICT_REVOCATION_NOT_PROVEN`でAWS実行不可。すでに送信されたin-flight要求は撤回不能として未承認sealする。

**証跡:** page/attempt ledgerに`transport_attempt_id`、`grant_id`、`grant_revocation_epoch`、`pre_send_grant_decision`、`grant_checked_at_utc`、`effective_sdk_total_max_attempts`、`physical_send_count`、`retry_owner=COLLECTOR_ONLY`、`revocation_observed_at_utc`、`in_flight_at_revocation`を持たせ、Owner取消→次送信0回を独立監査できるようにする。新しいAWS接続権限は一切付与していない。

すでに送信済みのin-flightリクエストは後から巻き戻せる保証がないため、失効時の応答と既取得RAWは`UNAUTHORIZED_AFTER_REVOKE`という**内部保全ラベル**で未承認seal・隔離し、共有不可。再開には新しいOwner決裁・新規snapshot IDと独立確認が必須。これは設計上の要求であり、現PRには取消実装もOwner Grantも存在しない。

## 3. 権限取得前の決裁未確定項目（**未署名**）

次の項目が揃うまでは、**AWSに1回も接続しない**。

| 項目 | 必要な具体情報 | 状態 |
|---|---|---|
| Owner authorization identity | 取得実行を認可する人間Owner、決裁方法、署名・監査保存先 | PENDING |
| Collector code baseline | 独立レビューに通過した実Collector commit + artifact SHA256、依存lock、非書込検査 | NOT_IMPLEMENTED |
| Plan fingerprint | `plan_sha256`と正規スキーマ、何をどの順番でいつ取得するか | NOT_DEFINED |
| Target Account | `456720798575`（規範上の既存ターゲット）。実行直前のOwner再確認 | NOT_RECONFIRMED |
| Source contexts | P1/P2/P3/P4、**P2-Lake Organization EDS独立文脈**の期待STS Account/ARN、CloudTrail delegated権限、セッション方式、credential lifetime/role | ALL_PENDING |
| Action/resource policy | SDK OperationとIAM Actionを別欄にしてS3 `ListObjectsV2`→`s3:ListBucket`、承認済Bucket/Prefix/token/期間・件数・SCP/RCP適用性と除外例外を検証 | NOT_VERIFIED |
| Regions | 対象Regionの明示リストとGlobal IAM/STSの処理方法 | NOT_APPROVED |
| Period and as-of | CloudTrail Event Historyの直近90日に収まるstart/end/as_of、Trail/Lake各別期間 | NOT_APPROVED |
| Rate, cost and size | API calls/second、最大pages/requests/bytes、timeout、有限retry、停止予算 | NOT_APPROVED |
| Sensitive RAW custody | 暗号化・0700/0600相当・アクセス制御・監査記録・保管期限・隔離手順 | NOT_VERIFIED |
| S3/KMS log grants | 正確なbucket/prefix/object range、key ARN、Decrypt例外、別アカウント許可 | NOT_APPROVED |
| Existing Lake query permission | P1 Account EDSとP2-Lake Organization EDSの独立Grants、Region/selector/retention/ingestion、既存store、料金上限と`StartQuery`別承認 | NOT_APPROVED |
| Preflight source validity | I1モックと実AWS SDK modelの差、S3 gzip原本/digest検証、fixture不信頼入力境界 | NOT_PROVEN |
| Stop/incident authority | `STOP_GRANT`を含む全停止状態、Owner取消状態の権威・リクエスト直前の再検証、未承認RAW隔離と報告先 | NOT_APPROVED |
| Independent review | 非実行設計レビューと、後続コード/Grant/RAWのレビュー担当を独立に指定 | PENDING |

**決裁記録の必須文言候補（署名ではない）:** 「対象計画SHA、実装SHA、Principal、Region/Source、期間、暗号化保存先、予算を固定した**AWSの読み取りだけ**を期限付きで承認する。対象外のAWS操作／権限追加／別Principalへのfallback／タグ書き込みは認可しない」。Ownerがこの文言を承認したと**推定しない**。

## 4. Collectorと証拠の必須受入試験（将来のI1-B実装で必要）

1. **Policy lint/Non-write:** サービス・Operationの固定allowlist以外は実SDK client生成段階と`before-call`層の双方で拒否。タグ変更、IAM/Organizations変更、Lake新規作成を拒否する合成テスト。SDK `Get*`一般許可は禁止。
2. **Identity mismatch:** P1/P2/P3/P4でSTS Account/Arn mismatch → 以降の呼び出し0件。期限切れ時は別credentialへ自動fallbackしない。
3. **Pagination/model:** IAM `IsTruncated/Marker`、各NextToken、空ページ、重複token、トークン欠落、型不正、未認識SDKモデル、範囲/費用上限を全て独立テスト。terminal成功≠取得範囲全体COMPLETE。
4. **Cross-account:** Organizations member principalでは権限否認と記録、SSO管理主体が不在ならUNKNOWN、S3 bucket/KMS key未承認ならP4未実行。権限を迂回するrole chainなし。
5. **CloudTrail:** EH/Trail S3/Lakeを独立管理。P1 EDSゼロでもP2-Lake不在と推定しない。Trailの変更履歴・StopLogging・digest断絶・配信欠損／再配送・保存期間を区間ごとに照合し、現時点のselector一致だけで過去COMPLETE不可。EventID重複はsource別coverageを維持。
6. **State consistency:** 各principal/policy version/assignment/Name等のBEGIN/END照合で実際に変化させた模擬ケースはINCONSISTENT。未観測はUNKNOWN。ABA可能性を記録。
7. **Evidence custody:** SDK-decoded JSONとS3原本byteを別ハッシュ・媒体別に保全。書込中断・改変・symlink・公開ZIPへのRAW混入・認証情報混入はfail-closed。Secretsスキャナだけでクリーンと判定しない。
8. **No secrets/no real AWS on CI:** テストはシークレット不要、ネットワーク遮断、依存固定、カバレッジ計測とSonarCloud連携。実AWS統合検証のGrantとは完全分離する。
9. **Attack surface:** 外部JSONや非信頼fixtureを任意Pythonオブジェクトへ変換しない。I1の`deepcopy`は内部合成fixture限定。プロセス・環境変数・任意endpoint/SDK hookを未信頼に与えない。
10. **Formal review:** これらの全テストPASSでもG2 VERIFICATIONやG1条件付き書込安全性は成立しない。独立レビュー結果を具体的HEAD/plan fingerprintにのみ紐付ける。

11. **S3 API/IAM:** SDK `ListObjectsV2`↔IAM `s3:ListBucket`を正しく紐付け、SDK Operation `ListBucket`は拒否。Bucket/Prefix/ContinuationToken/MaxKeys/Window/ObjectKey/bytesがGrant外ならAPIを出さない。`GetObject`・SSE-KMSは別Grant。
12. **Organization EDS:** P1のLake=0件・P2-LakeのGrantなし→`UNKNOWN`。P2-Lake管理/正当な委任管理コンテキストの別行が揃うまで`NOT_CONFIGURED`禁止。
13. **A04×A06反例:** 管理Account principal、SLR、管理資源、RCP非対応サービス、管理principal→メンバー資源、管理と異なるメンバーdelegated roleを検証。Unknown writerを消さない。
14. **Trail過去区間:** Selector変更、StopLogging、digest断絶、配信欠損・再配送を合成し、現在設定とBEGIN/ENDが同じでもhistorical coverageをCOMPLETEにしない。
15. **IAM Filter:** 5種別以外、部分ページ、DefaultVersionIdとPolicy ARN不一致、Policy本文未取得を`PARTIAL/UNKNOWN`にする。
16. **Grant実行中失効:** 1ページ目完了後にOwner取消/満了/取消照会不能/planやHEAD不一致→2ページ目以降AWS API0、未承認RAW seal、別Grantなしの再開禁止。in-flightは取消可能と主張しない。

17. **R2-N01 物理送信境界とOwner取消:** 合成transportで初回`SEND_ONCE`→Throttling/5xx→SDK標準内部retryが無効のままCollector再試行を予約→OwnerがGrant取消・`revocation_epoch`更新→再試行の`CHECK_GRANT`が`STOP_GRANT`→**以後のHTTP transport send 0回**を確認。`before-call`検証後の取消、`before-send`前の取消、照会不能、期限切れ、SDK設定改変、custom retry handler、redirect、別Client、競合同時実行とin-flight隔離を含める。`before-send`のみの単体テストではtransport経路全体を証明しない。
18. **R2-N02 RCP Action/Resource Type:** RCP対応サービスでActionの認可Resource type不明→`UNKNOWN`。同一サービスの別Actionで異なるタイプ、複数Resourceの一部が不明、管理資源、サービスリンクロール、SAR版不一致を合成し、`rcp_resource_coverage`をresource別に確認。`UNKNOWN`を`NOT_SUPPORTED`や書込不可能に変換しない。

## 4A. R1 Finding Closure Tracker（R2独立クローズ済み）

| Finding | Major/Minor | R2の証拠箇所 | 現時点の判定 |
|---|---|---|---|
| R1-001 | Major | 参照設計`2 SDK↔IAM Action表、S3 request bound、受入試験11 | RESOLVED_IN_PROPOSAL |
| R1-002 | Major | 参照設計`2 P1/P2-Lake別行、A05-Lake-Organization、受入試験12 | RESOLVED_IN_PROPOSAL |
| R1-003 | Major | 本表`2AのActor×Resource適用判定表、A04×A06、受入試験13 | RESOLVED_IN_PROPOSAL |
| R1-004 | Major | 本表`2Bの時系列coverage、参照設計`8、受入試験14 | RESOLVED_IN_PROPOSAL |
| R1-005 | Minor | A01 Filter5種類とDefaultVersionId・本文ハッシュ照合、受入試験15 | RESOLVED_IN_PROPOSAL |
| R1-006 | Minor | 本表`2Cおよび参照設計page ledgerのGrant再検証、受入試験16 | RESOLVED_IN_PROPOSAL |

**正式クローズではない。** 著者側がR2の是正を記述したことと、過去の独立レビュアーまたは新規レビュアーによる`RESOLVED`判定は別である。現Gateは`R1 REVISION_REQUIRED / R2 INDEPENDENT_REVIEW_PENDING`。

## 5. Independent Design Review依頼内容

独立レビュアーには次を要求する。

- G2 R1.1原文と本R2の**正規スコープ差分**（勝手な認可拡張・候補API不足・Source漏れ）、P1〜P4とP2-LakeのIAM principalと実行権限分離を追跡する。
- 具体的に不足するAPI・condition・resource-level IAM対応、CloudTrail 3ソースでの非原子的なcoverage、Identity Center Permission Set/Group/Roleマッピング、OU/root SCP/RCP継承を反証可能なFindingとして示す。
- RAW保存と公開ZIPの安全性、認証情報漏洩、失敗・中断、将来のOwner署名と実行者の分離を評価する。
- **提出判定は`ACCEPTABLE_IN_DESIGN`または`REVISION_REQUIRED`等の設計に限る**。`AWS GRANT APPROVED`／`G2 VERIFIED`を自動付与しない。
- PRへの文書反映、静的テストの成功は**この独立レビューそのものではない**。レビュー完了後の署名済みOwner実行認可も別手続き。

## 6. 次の安全な作業分解

- **I1-B R2（本PR）:** 非実行設計2文書のR1独立レビュー指摘6件の是正。実行権限は未付与。
- **I1-B D2（別PR）:** 本R2の独立再レビューを経て、実SDKモデルに基づく純粋なschemaと合成fixtureのoffline契約テストを実装する。AWS接続なし。
- **I1-B Runtime（別PR + 別Grant）:** Authenticated read-only client、strict policy guard、RAW writer、audit/observabilityの実装とoffline test。接続前の別審査必須。
- **G2 Evidence Capture（別Owner決裁）:** 固定したAWS Account/role/期間/sourceにだけ短期アクセスして、完全性を過大評価しない収集。
- **G2 Independent Assessment:** 実収集証拠に対する第三者判断。G1 NOT PROVENなら書き込み再開なし。

## 7. 最終状態

`R1 REVISION_REQUIRED / R2 INDEPENDENT_REVIEW_PENDING` / `EXECUTION NOT AUTHORIZED` / `EVIDENCE NOT CAPTURED` / `G2 NOT VERIFIED` / `G1 NOT PROVEN` / **AWS WRITE BLOCKED**。

**この文書自体も他のどの設計・Pull Requestのマージも、AWS接続認可またはタグ書込解除を発生させない。**
