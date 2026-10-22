# G2-I1-B — 実AWS Read-only Evidence Collector 参照設計 R1

**基準日:** 2026-10-23（JST）  
**Baseline:** \`yohi/aws-cost-name-tagger\` master \`423f123a2df64bd3c296376c1f3980b4e1aa0267\`  
**上位規範:** \`docs/gates/G2_OFFLINE_EVIDENCE_BUNDLE_CONTRACT_R1_2026-10-22.md\`（本文R1.1）  
**依存実装:** I0 \`g2_evidence.py\`、I1 \`g2_collector_contract.py\`  
**文書状態:** **DESIGN PROPOSAL / UNSIGNED / NO ACCESS GRANT / NOT_EXECUTED**  
**Gate:** G1 NOT PROVEN、G2 NOT VERIFIED、AWS WRITE BLOCKED、Safety Hold維持。

## 0. 本設計の境界

この文書は**実AWSアクセスの認可でも、実行指示でも、IAMポリシーとしてデプロイ可能な完成品でもない**。本PRは文書追加のみ。資格情報の取得、AWS CLI/SDK呼び出し、IAM/SCP/ログ設定変更、CloudTrail Lakeクエリ、Nameタグ更新、実AWS証拠のアップロードを行わない。

**成功しても解除できない事項:** G1の条件付きNameタグ原子更新はNOT PROVEN。G2-I0の「バイト整合性」／I1の「合成レスポンスの契約検証」は実AWSでの全件取得・実効ReadOnly権限・真正性・単一時点整合性・全writer不存在の証明ではない。過去のName候補58件という数字は再取得済みの現在値ではない。

## 1. Trust boundaries / アーキテクチャ

データ経路は概念上、次の分離を要求する。

\`\`\`text
Human Owner（別途署名する取得範囲・時刻・principal・上限）
       │ grant_id + approved plan_hash（承認前は必ず停止）
       ▼
Offline policy compiler / static contract verifier（AWSへ接続しない）
       ▼
Isolated Collector Host（独立プロセス、最小限ネットワーク、書込API無し）
       │ 事前検証：環境・STS Identity（各認証コンテキストで実施）
       │ EXACT service.operation.allowlist + args schema + quotas
       ├── P1 Target Account Reader   → IAM / CloudTrail Event History / Trail metadata
       ├── P2 Organization Reader     → Organizations 管理／delegated principal
       ├── P3 Identity Center Reader → SSO + Identity Store 許可管理主体
       └── P4 Log Archive Reader     → 事前認可済S3 prefix（別Grant・通常は保留）
       ▼
Protected RAW staging（AWS SDK decoded result 又は S3原本バイト列を区別）
       ▼
Per-call/page ledger + manifest + SHA-256 + immutable snapshot seal
       ▼
Offline verification / independent reviewer（raw_secureは共有しない）
       └── redacted_shared：人間レビュー済み派生物のみ
\`\`\`

- **Context separation:** P1〜P4のIAM主体を「同じ資格情報で呼べるはず」と推定しない。対象アカウントのIdentity＝管理アカウント／SSO管理者／ログ保管管理者とは限らない。別コンテキストが提供・承認されなければ対象区分は\`NOT_ATTEMPTED\`／\`ACCESS_DENIED\`／\`UNKNOWN\`で止め、別principalへの自動fallbackを禁止。
- **Credential separation:** Collectorが使うのは事前に用意され、有効期間・対象アカウント・権限が独立確認された短期的な認証コンテキストのみ。長期IAMキー、Secret本文、環境変数での認証情報コピー、ログへのトークン出力、AIエージェントへの資格情報返却、既存キーへのfallback、実行時の権限追加は不可。認証方式の最終選択もOwner判断とする。
- **STS caveat:** \`GetCallerIdentity\`のAccount/Arn/UserIdを前後で検証し、期待と違えば停止。**このAPIは権限を必要としないため、STSの成功を「ReadOnly保証」や「権限範囲が適切」の証拠にしてはならない**。実際のallow/denyはsession policy、permission boundary、SCP/RCP、resource policy等を含めて別途評価。
- **Offline boundary:** I0の\`OFFLINE_IMPORT_ONLY\`を実AWS収集の完成manifestへ勝手に変換しない。実収集データ用の新schema・検証器・attestation chainは後続実装／独立レビューで追加。I1\`FixturePort\`は実SDKへ差し替えない（Pythonの任意オブジェクトやdeepcopyは信頼境界外）。

## 2. 取得フェーズ・API allowlist（候補、未認可）

各操作には\`context\`、\`account_id\`、\`region\`、\`request_schema\`、\`resource_scope\`、\`purpose\`、\`expected_output\`、\`page_limit\`、\`request_limit\`、\`byte_limit\`、\`time_window\`を明示し、**service/operation名の\`Get*\`／\`List*\`パターンだけで許可しない**。API固有のパラメータとレスポンスの型をSDKモデル・AWS公式仕様に照合し、不要な項目や権限拡大を拒否する。

| Context/段階 | G2-ID | 事前審査する読取API候補 | アクセスの制限・不足 |
|---|---|---|---|
| **P1 対象アカウント** | A09 | \`sts:GetCallerIdentity\`（BEGIN/END） | identity照合のみ。実効ReadOnly証明ではない |
| P1 | A01/A02 | \`iam:GetAccountAuthorizationDetails\`、必要なら個別\`iam:GetRole\`、\`iam:GetPolicy\`、\`iam:GetPolicyVersion\`、\`iam:GetRolePolicy\`、\`iam:GetUserPolicy\`、\`iam:GetGroupPolicy\`、\`iam:ListGroupsForUser\` | 必須の\`Filter\`、\`IsTruncated/Marker\`の終端、policy version・trust・principal参照を固定。IAM policy文書はAPI出力でエンコードされ得るため処理表現も記録 |
| P1 | A05 | \`cloudtrail:LookupEvents\` | 明示したRegion/期間のみ。Event Historyは**直近90日、管理イベント等に制約**。account×Regionあたり最大2 calls/sのサービス制限を尊重。全履歴、全region、全イベント種別の証明にはならない |
| P1 | A05 | \`cloudtrail:ListTrails\`、\`cloudtrail:DescribeTrails\`、\`cloudtrail:GetTrail\`、\`cloudtrail:GetTrailStatus\`、\`cloudtrail:GetEventSelectors\` | Trail設定・status・selector取得のみ。S3に配信済みログ原本の取得とは区別する。trailの所有者、multi-region、organization trail、bucket/prefix、regionを照合 |
| P1 | A05 | \`cloudtrail:ListEventDataStores\`、\`cloudtrail:GetEventDataStore\` | **既存**CloudTrail Lakeの存在・範囲調査のみ。新規Lake作成と\`StartQuery\`は別承認（クエリ費用含む） |
| **P2 Organizations管理／委任管理** | A03/A04/A09 | \`organizations:DescribeOrganization\`、\`organizations:ListRoots\`、\`organizations:ListParents\`、\`organizations:ListPoliciesForTarget\`、\`organizations:DescribePolicy\`、必要なら\`organizations:DescribeOrganizationalUnit\` | Target Account → OU(s) → Rootを到達確認し、各階層でSCP/RCPとpolicy本文を収集。member accountの権限だけで取得できると仮定しない。管理／delegated主体のgrant必須 |
| **P3 Identity Center管理** | A02a/A09 | \`sso:ListInstances\`、\`sso:ListPermissionSetsProvisionedToAccount\`、\`sso:ListPermissionSets\`、\`sso:DescribePermissionSet\`、\`sso:GetInlinePolicyForPermissionSet\`、\`sso:ListManagedPoliciesInPermissionSet\`、\`sso:ListCustomerManagedPolicyReferencesInPermissionSet\`、\`sso:ListAccountsForProvisionedPermissionSet\`、\`sso:ListAccountAssignments\`、必要なら\`sso:GetPermissionsBoundaryForPermissionSet\` | InstanceArn/PermissionSetArn/AccountIdを対応付け。Permission Set provision状態とAssignmentを別エッジで保全。SSOリージョンと管理主体の根拠がなければUNKNOWN |
| P3 | A02a | \`identitystore:DescribeUser\`、\`identitystore:DescribeGroup\`、\`identitystore:ListGroupMemberships\`、必要なら\`identitystore:ListUsers\`、\`identitystore:ListGroups\` | IdentityStoreIdとPrincipalIdをキーに関連を証明。個人情報を含むため最小限のみ保護RAWに収集。外部IdPとフェデレーションの完全な権限推論は別証拠なしではUNKNOWN |
| **P4 別Grant: ログ保管先** | A05 | \`s3:ListBucket\`（承認済みbucket/prefix）、\`s3:GetObject\`（許可されたログ・digest objectのみ）、\`s3:GetBucketLocation\`、SSE-KMS時の限定\`kms:Decrypt\` | 配信ログ・digest原本の取得にはログ保管アカウント/bucket policy/KMS key policyの確認が必要。Decryptは高感度な**例外権限**で、通常のP1権限に混ぜない。未承認ならスキップしUNKNOWN |
| **後続の別設計** | A04/A06/A07/A08/A09 | サービス別Resource policy、IaC writer、58候補の現NameタグとAPI Gateway親子・ABAC、BEGIN/ENDの各resource再照合 | 具体的なリソース/ARN/API表が確定するまで実装・実行しない。候補58は過去情報であり現在の対象集合の証拠ではない |

\`sso:\`等のIAMアクション名と実SDKサービスIDは異なり得るため、**AWS Service Authorization Referenceに対してAction・Resource・Conditionを操作ごとに再照合**しなければ実IAM policyを作成しない。上表は**許可候補の整理**であり、完成した\`Action: "*"\`や広域\`Resource: "*"\`を許容するものではない。APIが資源レベル権限をサポートしない場合はその例外を個別記録し、全アカウント権限の無条件採用を禁止する。

**明示的に禁止:** 全\`Tag*\`/\`Untag*\`、IAMやOrganizationsの\`Create*\`/\`Put*\`/\`Update*\`/\`Delete*\`/\`Attach*\`/\`Detach*\`、\`sts:AssumeRole*\`の無許可実行、CloudTrail\`StartQuery\`、Trail/Lake新規作成・設定変更、Lambda/StepFunctions/CodeBuildの実行、EC2/ECS操作、\`secretsmanager:GetSecretValue\`、SSM\`GetParameter(...WithDecryption=true)\`、KMS鍵操作（P4例外で明示承認されたDecryptを除く）。非破壊に見えるAPIであっても費用や情報公開の副作用は別評価。

## 3. 認可・実行preflight（実装前の要求）

1. **Grant binding:** 人間Ownerの署名済み決裁原本と、固定した\`plan_sha256\`／コードcommit／収集対象Account／context principal・role ARN／regions／from-to-as_of／保存先／費用・回数・bytes上限／有効期限／中止条件を一対一で紐付ける。どれか欠けたら\`NOT_AUTHORIZED\`（現状は全て未承認）。
2. **Client creation:** 管理者指定profile/credential-providerを使い、接続前に環境値・出力先の安全性、対象アカウントの確認方法、SDKバージョン・TLS・リトライ・endpoint方針を検査。任意\`endpoint_url\`やローカルmetadata認証への予期せぬfallbackを許可しない。認証情報をログ／保存ファイルへ出さない。
3. **STS identity:** コンテキストごとにAccount・ARN・UserId（必要ならrole sessionの追加根拠）を確認し、期待Account/ARNと一致しなければ即停止。STS照合だけで「readonly=true」を立てない。
4. **Permission feasibility:** 発行可能な権限からIAM/SCP/permission boundary/resource policyを独立評価。CloudTrailやSource側の収集権限が欠ければそのsourceは\`ACCESS_DENIED\`で、別アカウント／roleへ自動切替しない。
5. **Request allowlist:** Context×operation×resource×params×region×timeを照合し、read-onlyの正規APIだけを実行。非許可・スキーマ不正・範囲外で\`STOP_POLICY\`。
6. **Budgets:** 全体とsource別でpages/API calls/bytes/期間/estimated costsをハード制限。RateLimitは明示制御（CloudTrail LookupEventsは2 calls/s/account/Region）。読取のみの有限回数retryは別途決定し、結果・retry回数・ページ重複をledgerに残す。上限超過は\`PARTIAL\`で停止し、全件成功に見せない。
7. **No execution by CI:** GitHub Actionsは合成fixtureとソース検査だけ。本番資格情報をCIに提供しない。実Collectorの接続試行は別の明示承認・独立レビューの後に限る。

## 4. 非原子的収集とSource別完全性

- **Coverage matrix:** \`evidence_id × account × source_context × region × time_window × event_category × target_ARN × API\`ごとに\`NOT_ATTEMPTED / CAPTURED_UNVERIFIED / PARTIAL / ACCESS_DENIED / UNKNOWN / INCONSISTENT\`を維持。\`UNKNOWN\`とゼロ件を混同しない。
- **Pagination:** IAMは\`IsTruncated/Marker\`、他APIは各々の\`NextToken\`。空配列でもNextTokenがあれば継続。トークン循環、リクエスト指紋違い、欠落配列、SDK/API差異、最大ページ制限、期限切れはFail Closed。完走を主張するには最終ページで正しい終端値とpage ledgerが必要。
- **CloudTrail 3 sources independently:** (E1) Event Historyの90日管理イベント等、(E2) S3に配信済みTrailログとdigest、(E3)既存CloudTrail Lake。ソース間はeventID等で重複を識別するが、source coverageを併合して「完全」にしない。Trailが設定済みでもS3原本未取得なら\`UNVERIFIED\`。CloudTrail Lakeの新規利用は2026-05-31以降の新規顧客への制約があるため既存Storeの調査に限る。
- **BEGIN/END:** STS、IAM managed/inline/default policy document hash、principal attachments、Organizations OU/root path・policy版、SSO Permission Set/Account Assignments、Name状態・親関連を取得開始と終了で再読取。差分があれば\`INCONSISTENT\`、取得不可なら\`UNKNOWN\`。一致しても\`CONSISTENT_WITHIN_CHECKED_FIELDS\`（ABAや途中の復元を否定しない）。P1だけではG2-A09全体の一致を主張不可。
- **No false downgrade:** API取得自体の成功と、schema validity、権限真正性、時点整合性、範囲完全性を独立フラグとする。前提1つでも欠けるなら\`G2 VERIFIED\`に自動昇格しない。

## 5. Evidence custody / 保存・真正性・機密性

**RAW表現の正確性:** SDK応答をJSONとして再符号化したバイト列は、AWS HTTPレスポンス原文バイト列ではない。\`payload_representation = SDK_DECODED_JSON\`と明記し、正規化ルール・SDK名/版・response \`RequestId\`・ローカル収集時刻を記録。S3 CloudTrail \`*.json.gz\`等は\`S3_OBJECT_BYTES\`として**GetObjectから得た元バイト列**を保存し、未圧縮JSONとハッシュを混同しない。S3原本の証明は、可能ならCloudTrail digest/signature chainを別途検証して記録する。SHA-256単独は取得元真正性の証明ではない。

Page ledger必須レコード候補:

\`\`\`json
{
  "schema": "g2-collector-page-ledger-proposal-1",
  "plan_sha256": null,
  "context_id": null,
  "expected_account": "456720798575",
  "observed_account": null,
  "observed_principal_arn": null,
  "region": null,
  "source": null,
  "evidence_id": null,
  "operation": null,
  "request_fingerprint_sha256": null,
  "request_id": null,
  "page_index": null,
  "pagination_token_digest": null,
  "received_at_utc": null,
  "payload_representation": null,
  "payload_sha256": null,
  "payload_bytes": null,
  "status": "NOT_ATTEMPTED",
  "pagination_complete": false,
  "failure_code": null,
  "scope_limitations": []
}
\`\`\`

- \`request_fingerprint_sha256\`はAWS service、operation、region、account、**全リクエスト引数（Filter/TargetId/AccountId/時間/next token）**を正規化して算出。トークンは生値を平文で広域ログに残さず、保護された再取得状態かハッシュで照合。上記JSONは例示であり、実APIコール結果・署名を伴わない。
- RAWはGitリポジトリ外の**アクセス制御・暗号化・監査可能な非公開領域**へ0700/0600相当で保存。書込者とレビュー閲覧者を分離し、機密ログ・ユーザー名・ARN・policy本文・タグ値を公開しない。機密値の混入が判明した場合、転送/共有を停止・隔離。SecretスキャナのPASSを「秘匿値がない」の証明にしない。
- RAWはappend-only相当でsealし、\`SHA256SUMS\`、manifestの各entry・署名または独立保全の外側SHA-256を照合。状態不整合やクラッシュ時はjournalと完全なエラー証跡を保全し、既存Bundleを上書きせず新しいsnapshot IDで再収集。
- 派生共有物は\`raw_secure/\`を含めない。マスキング後の各\`derived_sha256\`と\`source_raw_sha256\`、変換ツール版、日時、実施者、検証者、フィールド削除履歴を独立保存。I0のZIP検査は**構造検証**であり、秘匿値の除去と外部Owner承認の真正性までは保証しない。
- \`s3:GetObject\`によって得られるCloudTrailログには高感度データが含まれる可能性がある。P4の取得先、転送経路、廃棄期限、暗号鍵アクセス、監査ログ、外部共有禁止を承認しない限りP4は行わない。

## 6. 停止条件・事象と結果

| トリガー | 固定結果 | 処理 |
|---|---|---|
| Owner Grant未署名、scope/plan/HEAD不一致 | \`NOT_AUTHORIZED\` | AWSへ一切接続しない |
| STS Account/ARN不一致、意図しない主体切替 | \`ABORTED_IDENTITY\` | 以後のAPIを停止。取得済みデータを承認扱いにしない |
| 未許可operation／リソース／パラメータ／endpoint | \`STOP_POLICY\` | 呼び出さず停止し監査記録 |
| 資格情報・Secret・禁止データの取得要求／混入 | \`STOP_SENSITIVE\` | 収集と共有を停止、隔離。RAWの自動公開不可 |
| AccessDenied/未プロビジョンSSO/他アカウント不足 | \`ACCESS_DENIED\`または\`UNKNOWN\` | 不足範囲を開いたまま、別principalに自動fallbackしない |
| ソース未配置（既存Lakeなし等） | \`NOT_CONFIGURED\`（検証済み範囲のみ） | 他sourceの完全性へ振り替えない |
| トークン欠落／循環、タイムアウト／制限超過 | \`PARTIAL\`または\`UNKNOWN\` | 全件取得を主張せず、そのsourceを保留 |
| BEGIN/END間の権限／resource変化 | \`INCONSISTENT\` | snapshot seal後、別runに分離 |
| RAW保存失敗、manifest/hash不一致 | \`INTEGRITY_BLOCKED\` | 対象Bundleを未承認として隔離 |
| 不明なSDK差異、新規API field、対象追加 | \`REVISION_REQUIRED\` | Allowlist／文書／テストを改訂し独立レビューへ戻す |

\`ACCESS_DENIED\`や\`INCONSISTENT\`を無理に\`COMPLETE\`へ変換しない。\`NOT_CONFIGURED\`も有効に全Region/Accountを確認できていなければ\`UNKNOWN\`。

## 7. 実装・レビュー工程（未実施）

1. **D1: Design Independent Review.** 本仕様・G2-A01〜09マトリクス、4-contextの境界、実AWS権限候補、Secret/Log保管先、コスト制約、拒否条件を審査。判定は\`READY_FOR_IMPLEMENTATION\`等でありAWSアクセス承認とは別。
2. **D2: Offline Adapter Contract.** 専用アダプター（実SDK挿入不可のfixture契約から新規分離）と、IAM/Organizations/SSO/CloudTrailの実レスポンスschema fixtureを**合成データ**で検証。悪意のある任意Pythonオブジェクトに対する\`deepcopy()\`／特殊メソッド実行リスクを排除。ネットワーク遮断CIとcoverageレポートを追加。既存Safety Holdには触れない。
3. **D3: Credential / Policy Dry Evaluation.** 対象Account・各Contextの権限・endpoint・Resource ARN/Condition・SCP影響を**承認された別工程**で照合。ロールを勝手に作成・AssumeRoleしない。
4. **D4: Limited Read-only Execution Grant.** Ownerが対象API、プリンシパル、期間、Region、保存先、予算、最大APIコール数、監査方針を署名。Collector HEADとplan hashを封印後にのみ限定実行可能とする（現時点未付与）。
5. **D5: Evidence Capture & Independent Integrity Recheck.** 実APIの収集・SHA/manifest・3 CloudTrail源・BEGIN/ENDを第三者照合。実測不足はOPEN。データ保管/共有権限とG2独立受入を分離。
6. **D6: Formal G2 Assessment.** すべてのwriter候補・権限・Name副作用・対象ARNの全証拠がレビューされるまでは\`G2 NOT VERIFIED\`。G2が将来VERIFIEDでも、**G1 NOT PROVENならAWS WRITE BLOCKED**。

## 8. 根拠となるAWS公式仕様

- [STS GetCallerIdentity：権限を要しない](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [IAM GetAccountAuthorizationDetails：IsTruncated/Marker・URLエンコードpolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html)
- [Organizations ListPoliciesForTarget：直接attachmentとNextToken](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPoliciesForTarget.html) / [ListParents：管理/委任管理が必要](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListParents.html)
- [IAM Identity Center ListAccountAssignments](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListAccountAssignments.html) / [ListPermissionSetsProvisionedToAccount](https://docs.aws.amazon.com/singlesignon/latest/APIReference/API_ListPermissionSetsProvisionedToAccount.html) / [IdentityStore API](https://docs.aws.amazon.com/online-register/latest/data-formats/awsidentitystore.html)
- [CloudTrail LookupEvents：直近90日、2 calls/s/account/Region](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html)
- [CloudTrail GetEventSelectors：data/management/read-write selectors](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html)
- [CloudTrail digest/signature validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html) / [S3/KMS暗号化ログ読み取り](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html)
- [CloudTrail Lake：既存Storeと2026-05-31以降の新規顧客制約](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_ListEventDataStores.html)

**結論:** 本R1はG2-I1-Bの実装可否を判定するための**非実行参照設計**である。いかなるCI PASSや文書マージもAWS接続・IAM権限付与・G1/G2正式承認・Nameタグ書込の解禁を意味しない。
