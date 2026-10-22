# G2-I1-B — Evidence Acquisition / Owner Decision Readiness Matrix R1

**基準日:** 2026-10-23（JST）  
**役割:** 参照設計の独立審査入力と、将来の人間Ownerによる**別途の取得認可判断の準備**。  
**上位仕様:** [G2 R1.1契約](G2_OFFLINE_EVIDENCE_BUNDLE_CONTRACT_R1_2026-10-22.md) / [G2-I1-B R1参照設計](G2_I1B_READ_ONLY_COLLECTOR_REFERENCE_DESIGN_R1_2026-10-23.md)  
**現在の決定:** **NO HUMAN EXECUTION GRANT / NO AWS CONNECTION / DESIGN REVIEW ONLY**。この文書にOwner署名・承認トークンは含まない。

## 1. 3つの独立Gateを混同しない

| Gate | 通過に必要な証拠 | 本PRでの結果 |
|---|---|---|
| **Design Review Gate** | API × Account × Context × Region/期間 × 最小権限の整合性、Manifest/RAW保護、Fail Closed、独立技術レビュー | **PROPOSAL / INDEPENDENT_REVIEW_PENDING** |
| **Execution Authorization Gate** | 人間Ownerが限定取得計画・対象principal・Role・保存先・期間・最大費用／回数／bytes・有効期限を**別の署名済み記録**として承認 | **NOT_GRANTED** |
| **Evidence / G2 Acceptance Gate** | 実AWS RAW原本、Source別coverage、IAM/SCP/SSOの権限推論、CloudTrailの3系統、BEGIN/END、独立再照合 | **NOT_EXECUTED / NOT_VERIFIED** |

\`READY_FOR_IMPLEMENTATION\`≠\`READY_FOR_EXECUTION\`≠\`G2 VERIFIED\`。全てのGateが通過してもG1がNOT PROVENであればAWS WRITEはBLOCKED。

## 2. 具体的なEvidence取得・証明義務マトリクス

| G2-ID | Source/主体 | 捕捉と照合の要求（**完了条件**） | 現在の未証明・制約 |
|---|---|---|---|
| **A01** | P1/IAM | IAMユーザー・グループ・ロール・managed/inline policyの取得、全ページ終端、policy default version/本文・attached relationship・hashの対応を確認 | 実収集なし。IAM \`GetAccountAuthorizationDetails\`だけでは外部権限や全policyの実効性は証明できない |
| **A02** | P1/IAM + external trust | \`ListGroupsForUser\`・Role trust・AssumeRole条件・ExternalId・Permissions Boundary等をアカウント／principal別に展開 | AssumeRoleの実行なし。セッションポリシー／外部IdPの不明領域はUNKNOWN |
| **A02a** | P3/Identity Center | InstanceArn → PermissionSetArn → account provisioning → AccountAssignment → PrincipalId → IdentityStore group membership → Roleと政策本文をevidence IDでjoin | 専用P3 grant・IdP連携証拠なし。単なるRole列挙ではActor到達性はUNKNOWN |
| **A03** | P2/Organizations | 対象AccountからOU/rootまでListParentsを辿り、各targetのSCP/RCP direct attachmentsと\`DescribePolicy\`本文・適用範囲を確定 | 管理／delegated principal未決。組織管理主体にアクセスできない場合、継承範囲はUNKNOWN |
| **A04** | P1/P2/P3と対象サービス | identity policy × SCP/RCP × boundary × session policy × resource policy × Conditionの明示的Deny/Allowと範囲を区別 | IAM Simulatorの単独結果やmanaged policy名は有効な「全write主体不存在」証明でない |
| **A05-EH** | P1 CloudTrail Event History | Account/Region/90日窓/management等カテゴリ/全pagination、EventID/EventSource/EventName/Nameのキー・対象ARN対応を記録 | Event History外の時代・カテゴリ・Regionの非存在は結論できない |
| **A05-Trail** | P1 metadata + P4 S3 raw | Trail selector/有効期間/bucket/prefix/暗号化/配送ステータスを照合し、承認済み\`*.json.gz\`とdigestの元バイト列を取得。可能なら署名チェーン検証 | S3/KMS grant未定。Trail設定の存在はS3 RAWの取得・真正性と別 |
| **A05-Lake** | P1 metadata + 別cost grant | 既存Event Data Storeとregion/account/event types/retentionを記録。Query実行する場合は別費用・許可承認と結果ハッシュが必要 | \`StartQuery\`未許可。Event HistoryとLakeを自動統合してCOMPLETEとしない |
| **A06** | 対象構成 / IaC | CloudFormation・EventBridge・Lambda・StepFunctions・CodeBuild等のWriter候補を構成読取だけで台帳化しIAM Role/実イベントへ結合 | IAMだけで自動化Actorを閉包しない。実行・Secret取得は範囲外 |
| **A07** | Name consumer / ABAC | IAM/Resource policy/EventBridge/アプリ入力のName参照と親子継承を特定。API Gateway REST APIの親タグとStageの直接タグを区別 | API Gatewayの親からの継承タグは\`GetTags\`で見えず、Cost Explorer配分タグではない |
| **A08** | Name対象ARN / 各タグ読取API | 最新の対象集合を確定し、\`ABSENT\`／厳密\`EMPTY=""\`／\`NONEMPTY\`／\`UNKNOWN\`をRAW値から区別 | 過去58件は現在集合でない。空白1字や\`"\\t"\`はNONEMPTYで保護 |
| **A09** | 全Source + custody | Account/Principal/Region/期間/全request + token/RAW + SHA/Manifest + BEGIN/END critical hashの揃ったscope行だけを評価 | 非原子的・ABA未解消。全Sourceに不足が残る限りG2 VERIFIEDでない |

各行はさらに\`expected_items\`、\`observed_items\`、\`api_call_count\`、\`pages\`、\`termination_reason\`、\`evidence_sha256\`、\`context_id\`、\`unknowns\`を記録する。件数0を「不存在」と断定できるのは、有効なscopeで終端まで検索した範囲に限る。

## 3. 権限取得前の決裁未確定項目（**未署名**）

次の項目が揃うまでは、**AWSに1回も接続しない**。

| 項目 | 必要な具体情報 | 状態 |
|---|---|---|
| Owner authorization identity | 取得実行を認可する人間Owner、決裁方法、署名・監査保存先 | PENDING |
| Collector code baseline | 独立レビューに通過した実Collector commit + artifact SHA256、依存lock、非書込検査 | NOT_IMPLEMENTED |
| Plan fingerprint | \`plan_sha256\`と正規スキーマ、何をどの順番でいつ取得するか | NOT_DEFINED |
| Target Account | \`456720798575\`（規範上の既存ターゲット）。実行直前のOwner再確認 | NOT_RECONFIRMED |
| Source contexts | P1/P2/P3/P4それぞれのAccount ID、期待STS ARN、セッション方式、credential lifetime/role | ALL_PENDING |
| Action/resource policy | AWS Service Authorization ReferenceによるIAM Action、リソース条件、SCP/Boundary/Session政策との交差、監査 | NOT_VERIFIED |
| Regions | 対象Regionの明示リストとGlobal IAM/STSの処理方法 | NOT_APPROVED |
| Period and as-of | CloudTrail Event Historyの直近90日に収まるstart/end/as_of、Trail/Lake各別期間 | NOT_APPROVED |
| Rate, cost and size | API calls/second、最大pages/requests/bytes、timeout、有限retry、停止予算 | NOT_APPROVED |
| Sensitive RAW custody | 暗号化・0700/0600相当・アクセス制御・監査記録・保管期限・隔離手順 | NOT_VERIFIED |
| S3/KMS log grants | 正確なbucket/prefix/object range、key ARN、Decrypt例外、別アカウント許可 | NOT_APPROVED |
| Existing Lake query permission | 既存store、料金上限、\`StartQuery\`/結果取得の要否と独立承認 | NOT_APPROVED |
| Preflight source validity | I1モックと実AWS SDK modelの差、S3 gzip原本/digest検証、fixture不信頼入力境界 | NOT_PROVEN |
| Stop/incident authority | \`ABORTED_IDENTITY\`、\`ACCESS_DENIED\`、\`STOP_SENSITIVE\`などの実行停止権限と異常時の報告先 | NOT_APPROVED |
| Independent review | 非実行設計レビューと、後続コード/Grant/RAWのレビュー担当を独立に指定 | PENDING |

**決裁記録の必須文言候補（署名ではない）:** 「対象計画SHA、実装SHA、Principal、Region/Source、期間、暗号化保存先、予算を固定した**AWSの読み取りだけ**を期限付きで承認する。対象外のAWS操作／権限追加／別Principalへのfallback／タグ書き込みは認可しない」。Ownerがこの文言を承認したと**推定しない**。

## 4. Collectorと証拠の必須受入試験（将来のI1-B実装で必要）

1. **Policy lint/Non-write:** サービス・Operationの固定allowlist以外は実SDK client生成段階と\`before-call\`層の双方で拒否。タグ変更、IAM/Organizations変更、Lake新規作成を拒否する合成テスト。SDK \`Get*\`一般許可は禁止。
2. **Identity mismatch:** P1/P2/P3/P4でSTS Account/Arn mismatch → 以降の呼び出し0件。期限切れ時は別credentialへ自動fallbackしない。
3. **Pagination/model:** IAM \`IsTruncated/Marker\`、各NextToken、空ページ、重複token、トークン欠落、型不正、未認識SDKモデル、範囲/費用上限を全て独立テスト。terminal成功≠取得範囲全体COMPLETE。
4. **Cross-account:** Organizations member principalでは権限否認と記録、SSO管理主体が不在ならUNKNOWN、S3 bucket/KMS key未承認ならP4未実行。権限を迂回するrole chainなし。
5. **CloudTrail:** EH/Trail S3/Lakeを別に記録。EventID重複統合しても各source coverageを保存。配信遅延、digest欠損、90日外、非対象Regionで「Name操作0件」を主張しない。
6. **State consistency:** 各principal/policy version/assignment/Name等のBEGIN/END照合で実際に変化させた模擬ケースはINCONSISTENT。未観測はUNKNOWN。ABA可能性を記録。
7. **Evidence custody:** SDK-decoded JSONとS3原本byteを別ハッシュ・媒体別に保全。書込中断・改変・symlink・公開ZIPへのRAW混入・認証情報混入はfail-closed。Secretsスキャナだけでクリーンと判定しない。
8. **No secrets/no real AWS on CI:** テストはシークレット不要、ネットワーク遮断、依存固定、カバレッジ計測とSonarCloud連携。実AWS統合検証のGrantとは完全分離する。
9. **Attack surface:** 外部JSONや非信頼fixtureを任意Pythonオブジェクトへ変換しない。I1の\`deepcopy\`は内部合成fixture限定。プロセス・環境変数・任意endpoint/SDK hookを未信頼に与えない。
10. **Formal review:** これらの全テストPASSでもG2 VERIFICATIONやG1条件付き書込安全性は成立しない。独立レビュー結果を具体的HEAD/plan fingerprintにのみ紐付ける。

## 5. Independent Design Review依頼内容

独立レビュアーには次を要求する。

- G2 R1.1原文と本R1の**正規スコープ差分**（勝手な認可拡張・候補API不足・Source漏れ）、P1〜P4のIAM principalと実行権限分離を追跡する。
- 具体的に不足するAPI・condition・resource-level IAM対応、CloudTrail 3ソースでの非原子的なcoverage、Identity Center Permission Set/Group/Roleマッピング、OU/root SCP/RCP継承を反証可能なFindingとして示す。
- RAW保存と公開ZIPの安全性、認証情報漏洩、失敗・中断、将来のOwner署名と実行者の分離を評価する。
- **提出判定は\`ACCEPTABLE_IN_DESIGN\`または\`REVISION_REQUIRED\`等の設計に限る**。\`AWS GRANT APPROVED\`／\`G2 VERIFIED\`を自動付与しない。
- PRへの文書反映、静的テストの成功は**この独立レビューそのものではない**。レビュー完了後の署名済みOwner実行認可も別手続き。

## 6. 次の安全な作業分解

- **I1-B R1（本PR）:** 非実行設計2文書のみ。**現在着手可能・実行権限不要**。
- **I1-B R2（別PR）:** 現仕様の是正、実SDKモデルに基づく純粋なschema定義、公開API docsと合成fixtureによる契約テスト。AWS接続なし。
- **I1-B Runtime（別PR + 別Grant）:** Authenticated read-only client、strict policy guard、RAW writer、audit/observabilityの実装とoffline test。接続前の別審査必須。
- **G2 Evidence Capture（別Owner決裁）:** 固定したAWS Account/role/期間/sourceにだけ短期アクセスして、完全性を過大評価しない収集。
- **G2 Independent Assessment:** 実収集証拠に対する第三者判断。G1 NOT PROVENなら書き込み再開なし。

## 7. 最終状態

\`DESIGN REVIEW PENDING\` / \`EXECUTION NOT AUTHORIZED\` / \`EVIDENCE NOT CAPTURED\` / \`G2 NOT VERIFIED\` / \`G1 NOT PROVEN\` / **AWS WRITE BLOCKED**。

**この文書自体も他のどの設計・Pull Requestのマージも、AWS接続認可またはタグ書込解除を発生させない。**
