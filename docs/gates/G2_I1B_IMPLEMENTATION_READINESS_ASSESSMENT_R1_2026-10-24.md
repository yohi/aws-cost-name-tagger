# G2-I1-B — Implementation Readiness Assessment R1

**基準日:** 2026-10-24 JST  
**Repository:** `yohi/aws-cost-name-tagger`  
**固定master/PR #8 merge HEAD:** `0ed903f0ab2936023823df3a2669536ec781d421`  
**PR #8 独立レビュー合格HEAD:** `0f7819ae15d8fb3753516442a082d0c3c6fde936`  
**対象:** I0/I1/D2から将来のRead-only Collector実装への移行準備。**今回の成果物は非実行の技術評価のみ。**  
**Author assessment status:** `R2_LIMITED_CORRECTIONS_IN_PROPOSAL / FRESH_INDEPENDENT_READINESS_RE_REVIEW_REQUIRED`（前回独立判定`REVISION_REQUIRED`、本改訂は著者側の限定是正で正式Gate通過ではない）  
**結論:** **`READY_FOR_NEXT_OFFLINE_DESIGN_AND_FEASIBILITY_WORK_ONLY` / `NOT_READY_FOR_REAL_AWS_RUNTIME_OR_EXECUTION`**  
**既存の安全状態:** `G1 NOT PROVEN / G2 NOT VERIFIED / AWS EVIDENCE NOT EXECUTED / OWNER EXECUTION GRANT NOT_GRANTED / AWS WRITE BLOCKED / SAFETY HOLD ACTIVE`。

## 1. 審査範囲・固定証拠

### 1.1 対象原本（すべて固定master）

| 対象 | 原本 | 実際に根拠として使える範囲 |
|---|---|---|
| 上位規範 | `docs/gates/G2_OFFLINE_EVIDENCE_BUNDLE_CONTRACT_R1_2026-10-22.md` | G2 R1.1／Source別収集・真正性・一貫性・Owner決裁を要求する非実行仕様 |
| Collector設計 | `docs/gates/G2_I1B_READ_ONLY_COLLECTOR_REFERENCE_DESIGN_R1_2026-10-23.md` | R3設計上のSAES・HTTP送信・Owner取消の契約と取得API候補 |
| Owner準備表 | `docs/gates/G2_I1B_OWNER_DECISION_READINESS_AND_EVIDENCE_MATRIX_R1_2026-10-23.md` | Owner未署名のGrant決裁項目、P1/P2/P2-Lake/P3/P4のSource/Context、受入試験1〜22 |
| I0 | `g2_evidence.py` | オフラインbundle形式・staging・checksum・検証・共有制限のみ |
| I1 | `g2_collector_contract.py` | 固定fixtureを用いたPlan/Request/Pagination/Response契約のみ |
| D2 | `g2_d2_saes.py`、`g2_d2_rcp.py` | 合成SAES順序・取消/送信競合・合成SAR Resource Evaluationのみ |
| D2証拠 | `docs/gates/G2_I1B_D2_OFFLINE_CONTRACT_IMPLEMENTATION_R1_2026-10-23.md` | D2の受入条件・未証明事項。文書中の古いreview-pending表示は作成時点の履歴 |
| 安全境界 | `g2_static_guard.py`、`.github/workflows/g2-offline.yml`、`.github/workflows/ci.yml` | 合成テスト・固定AST guard・Docker `--network none --read-only`・Write Safety Hold |
| 独立レビュー | PR #8 fixed HEAD `0f7819ae15d8fb3753516442a082d0c3c6fde936` | 2026-10-24 JST受領の独立R3判定`LIMITED_PASS_OFFLINE_CONTRACT`。オフライン**ソース/モデル限定**。レビュー原本のGitHub提出・ハッシュは未確認（下記1.1A参照） |

固定HEADおよびPR #8のmergeをGitHubから確認。PRレビューのテキストは別途受領済み審査証拠として扱う。設計文書先頭の「R3限定レビュー待ち」、D2実装文書先頭の「コードレビュー待ち」という旧記述は**過去時点の状態表示**であって、後の独立PASS/マージを否定するものではない。本R1は履歴を破壊せず現在の状態を追記するスナップショットである。

### 1.1A 独立レビューの監査参照（FND-PR9-004）

以下は**受領したレビューの書誌識別・参照情報**であり、GitHubに存在しないレビュー原本、電子署名、バイト単位のハッシュを捏造していない。

| 項目 | 記録 | 検証水準 |
|---|---|---|
| 本評価のローカル管理ID | `PR8-D2-R3-INDEPENDENT-REVIEW-20261024`（**本書で付した参照用ラベルであり、外部発行IDではない**） | 本書のトレーサビリティ用 |
| 独立判定・受領日 | `LIMITED_PASS_OFFLINE_CONTRACT`、2026-10-24 JST | 会話上で受領したレビュー内容 |
| 独立レビュー対象コードHEAD | [`0f7819ae15d8fb3753516442a082d0c3c6fde936`](https://github.com/yohi/aws-cost-name-tagger/tree/0f7819ae15d8fb3753516442a082d0c3c6fde936) | GitHub commit参照 |
| 対象PR／merge commit | [PR #8](https://github.com/yohi/aws-cost-name-tagger/pull/8) ／ `0ed903f0ab2936023823df3a2669536ec781d421` | GitHubに記録されたPR・merge |
| CI照合 | [G2 Offline Evidence Safety](https://github.com/yohi/aws-cost-name-tagger/actions/runs/39982878467)、[Safety Hold CI](https://github.com/yohi/aws-cost-name-tagger/actions/runs/39982878375) | 固定コードのテスト証跡。**レビュー原本の代替ではない** |
| 独立レビュー原本URL / ID | **`NOT_ARCHIVED / NOT_VERIFIED`**。GitHub PR review、署名済み審査報告書、固定ファイル原本の所在を未確認 | 未検証 |
| 独立レビュー原本SHA-256 | **`NOT_AVAILABLE`**。受領テキストとファイルの同一バイト列を検証していないため算出・推定しない | 未検証 |

**証拠の差:** レビュー判定を既知の受領履歴として継承することと、独立した第三者がその**原本の完全性・真正性**を追試できることは別。正式な監査証跡を要する段階に進む前に、別途Ownerまたはレビュアーが、レビュー本文の原本を不変保存し、SHA-256・ファイルサイズ・発行/受領時刻・レビュー対象固定HEAD・取得経路を記録する。原本未取得を**PASS**と表示しない。

### 1.2 今回の判定で「証明済み」と呼べる最も強い内容

- `OFFLINE_MODEL_REVIEWED`：D2の合成First-byte/取消競合、旧Attempt差替え拒否、合成Fencing witnessの扱い、RCP Resource別UNKNOWN伝播が固定コードと合成テストで独立レビュー済み。
- `CI_COMPLETED_SUCCESS`：固定HEADのG2 Offline Evidence Safety／Safety Hold CI／SonarCloud Check Runは成功。ただしランタイム・実効IAM・証拠真正性の証明ではない。
- `RUNTIME_NOT_PROVEN`：実`botocore`client、HTTP/TLS/OSの初回送信境界、複数HostでのSAES直列化、実Gatewayのfencing、永続ledger、署名付きOwner Grant、credential adapter、実AWSへのアクセスはD2に含まれない。
- `AWS_EVIDENCE_NOT_EXECUTED`：P1/P2/P2-Lake/P3/P4のどれについても、この工程で実AWS RAW原本を取得したと主張しない。`G2 NOT VERIFIED`を維持する。
- `AWS_WRITE_BLOCKED`：Nameタグ更新、安全な条件付き書込のG1 Gateは別の証明義務であり、本評価に含めない。

## 2. Readinessマトリクス — 三段階の依存関係と停止条件（FND-PR9-001/003）

**循環を禁止するフェーズ定義:**

- **`PRE_EXECUTION`**：初回の実AWS read-only送信**より前**に必要な実装・セキュリティ受入。選定構成における一意なSAES権威・完全仲介・耐久状態、実送信境界、RAW保管基盤、固定Runtime HEADの独立審査、Host境界受入、明示的な人間Ownerの限定Grantなど。未成立ならAWS Evidence Acquisitionを禁止。
- **`EVIDENCE_ACQUISITION`**：PRE_EXECUTIONの全前提が通過し、別途人間Ownerが発行した**対象限定・期限付きread-only Grant**の範囲で、実AWSのRAWをSource別に取得する段階。収集中の不整合、アクセス不能、欠落は`UNKNOWN/PARTIAL/NOT_ATTEMPTED`として記録。**G2 VERIFIEDは取得開始条件ではない。**
- **`POST_ACQUISITION`**：取得後のRAW完全性・署名/ハッシュ・source coverage・非原子的BEGIN/END・実効権限推論の独立検証とG2受入。**本段階の未完了はG2判定のBLOCKであって、すでに別承認された証拠取得を開始するためのBLOCKではない。**

| ID | 義務とフェーズ | D2/設計の既存証拠 | 現在の未証明部分 | 正確なGate効果 |
|---|---|---|---|---|
| IR-01 | **PRE_EXECUTION** Owner署名Grantの真正性、scope/TTL/plan/HEAD/principal binding、取消Auth | 合成SAES Grant状態と規範 | 実署名・本人性・取消権限・鍵管理・replay防止 NOT_PROVEN | **PRE_EXECUTION_BLOCK** |
| IR-02 | **PRE_EXECUTION** GatewayのみがAWS向けegressできる隔離と完全仲介 | SAES専有の参照設計 | OS/net/sidecar/provider/redirectの経路閉包 NOT_PROVEN | **PRE_EXECUTION_BLOCK** |
| IR-03 | **PRE_EXECUTION** 採用構成での**一意なAuthority・耐久状態・送信/取消の線形化・旧経路排除** | 単一プロセス`RLock`とsyntheticイベント | durable ledger/partition/crash/epoch・fencing NOT_IMPLEMENTED。**Replica/leader選挙はReplica採用時のみ必要** | **PRE_EXECUTION_BLOCK** |
| IR-04 | **PRE_EXECUTION** 取消成功ACK後の新規Gateway-local送信0・不明Gatewayなら成功拒否 | Synthetic fencing witnessとACK順序 | 実Gateway停止・旧経路の排除・取消信号真正性 NOT_PROVEN。**旧Leader fencingはLeader交代を採用した場合の追加義務** | **PRE_EXECUTION_BLOCK** |
| IR-05 | **PRE_EXECUTION** 物理HTTP First-byte/Retry完全仲介 | SDK内部retry禁止（`total_max_attempts=1`）の設計 | 実botocore/TLS/OS境界・暗黙通信・SDK retry閉包 NOT_IMPLEMENTED | **PRE_EXECUTION_BLOCK** |
| IR-06 | **PRE_EXECUTION** `SEND_INTENT/SEND_STARTED`の耐久ledger・crash unknownの非再送 | 合成`SEND_OUTCOME_UNKNOWN` | 実durable journal・write order・crash/replay耐性 NOT_PROVEN | **PRE_EXECUTION_BLOCK** |
| IR-07 | **PRE_EXECUTION** 事前固定API allowlist・SDK Operation×IAM Action/ARN/Condition/Region/Plan | I1 fixtureとAPI候補 | SDKモデルversion・フィルタ/予算・resource scope closure INCOMPLETE | **PRE_EXECUTION_BLOCK** |
| IR-08 | **PRE_EXECUTION → EVIDENCE_ACQUISITION** Source別に承認済みprincipal/role/Grantと、実行時のSTS identity・read-only制約確認 | P1/P2/P2-Lake/P3/P4分離設計 | 事前認可・context検証は未実装。実APIアクセス可否は取得中に判明（拒否はSource別記録） | 事前binding不足なら**PRE_EXECUTION_BLOCK**。実取得の拒否は**EVIDENCE_PARTIAL/UNKNOWN** |
| IR-09 | **PRE_EXECUTION → POST_ACQUISITION** SAR Action/Resource型モデルと安全なUNKNOWN伝播、取得後IAM/SCP/RCP/SSO graph/Writer候補評価 | 合成RCP ResourceEvaluation、I1 mock | 事前schema/禁止writer推論の検証未完。実policy/ownership/assignmentとwriter closureはRAW取得後のみ | 事前のモデル欠落は**PRE_EXECUTION_BLOCK**。実Writer推論は**POST_ACQUISITION_GATE** |
| IR-10 | **EVIDENCE_ACQUISITION → POST_ACQUISITION** CloudTrail EH/Trail-S3/Lakeの取得、期間coverage・履歴・digest/配送欠損評価 | R1.1 source別coverage契約 | Region/Source/timeの**事前取得plan**未承認。実RAW・過去区間coverageは未取得 | 取得scope/Grant欠落はIR-07/13の**PRE_EXECUTION_BLOCK**。Source取得は**EVIDENCE_ACQUISITION**、独立coverage判定は**POST_ACQUISITION_GATE**。**G2事前通過を要求しない** |
| IR-11 | **PRE_EXECUTION → POST_ACQUISITION** 暗号化secure RAW staging/manifest/不変seal・取得後のcustody照合 | I0のbundle完全性検査 | 取得前のsecure storage/ACL/漏洩隔離・ledger link未証明。実SDK decoded byte/S3原本の同一性は取得後照合 | 収集先の安全な保存基盤なしは**PRE_EXECUTION_BLOCK**。原本完全性は**POST_ACQUISITION_GATE** |
| IR-12 | **PRE_EXECUTION** CIの非実行境界とHostのread-only隔離検証 | AST guard・Docker network-none・Safety Hold | Host network acceptance、SDK/OS hostile test、Coverage ingestion未証明 | Host環境の受入不足は**PRE_EXECUTION_BLOCK**。既存D2のCI成功はoffline限定 |
| IR-13 | **PRE_EXECUTION** 人間Ownerの限定実行Grant（account/context/role/region/time/API/budget/bytes/credential/storage） | Owner Matrixの未署名項目 | **OWNER GRANT NOT_GRANTED** | **PRE_EXECUTION_BLOCK** |
| IR-14 | **POST_ACQUISITION + INDEPENDENT G1** 実RAWの独立受入→G2判定。G1条件付きName書込は別系統 | G2/G1の規範のみ | `G2 NOT_VERIFIED`は取得**後**の検証未完了、`G1 NOT_PROVEN`はWriter更新禁止 | **POST_ACQUISITION_G2_GATE**（取得前のBLOCKではない）／**G1_WRITE_BLOCK**（取得と独立） |

**Gateの型:** `PRE_EXECUTION_BLOCK`は実AWS read-only Evidence Acquisition開始を禁止する条件。`EVIDENCE_PARTIAL/UNKNOWN`は承認済取得中の部分・未収集の証拠状態。`POST_ACQUISITION_GATE`は取得後のG2証拠受入条件。`G1_WRITE_BLOCK`はNameタグ書込を別途禁止する条件。これらを同一の単一`BLOCK`へ潰さない。offline RA-A/B/Cの文書・モデル作業はいずれにも依存しない。

**非循環の必要条件:** `PRE_EXECUTION_ACCEPTED + OWNER_GRANT` → `EVIDENCE_ACQUISITION` → `POST_ACQUISITION_G2_ASSESSMENT`。逆向きの`G2 VERIFIED → EVIDENCE_ACQUISITION`辺は**禁止**。G1のWrite Gateは取得フローから独立。


## 3. 技術上の優先依存関係（非循環、FND-PR9-002）

`D2 fixed approved offline model`  
→ `RA-A: normative contract & threat model snapshot`  
→ `RA-B: SAES/Grant/credential/egress architecture selection`  
→ `RA-C: falsifiable offline contract test specification`  
→ `RA-D: separately scoped offline feasibility spike (NO REAL AWS CONNECTIVITY)`  
→ `RA-E: fresh independent offline architecture/feasibility review`  
→ **`RUNTIME_IMPLEMENTATION_ELIGIBILITY_DECISION`（現時点保留）**  
→ 将来の**別PR**で`runtime adapter implementation`（SDKやtransportを実装しても、実AWSへ送信しない）  
→ `ISOLATED_HOSTILE_RUNTIME_VERIFICATION`（モックendpoint / 隔離OS/netで敵対的試験、実AWS資格情報なし）  
→ **`RUNTIME_FIXED_HEAD_INDEPENDENT_REVIEW`**（固定コードHEADとテスト原本・SDK version・脅威モデルを独立審査）  
→ **`HOST_NETWORK_BOUNDARY_ACCEPTANCE`**（実Hostの完全仲介、Gateway外egress禁止、credential-provider/redirect/旧経路・fencingなどの遮断を別証拠で受入。**実AWS通信なし**のHost境界試験。証明不能なら停止）  
→ **`PRE_EXECUTION_ACCEPTANCE`**（IR-01〜09/11〜13のうち取得前に必要な証明と範囲固定。該当するレビューとHost受入の全件PASSが必須）  
→ **`OWNER_EXECUTION_AUTHORIZATION`**（人間Ownerの別個の署名済み・期限/範囲付きRead-only Grant。未承認なら禁止）  
→ **`EVIDENCE_ACQUISITION`**（初めての限定Read-only AWS RAW収集。失敗/拒否/欠損をSource別に記録）  
→ **`POST_ACQUISITION_RAW_AND_COVERAGE_INDEPENDENT_ASSESSMENT`**（IR-09〜11/14の取得後証拠照合）  
→ **`G2_INDEPENDENT_ACCEPTANCE_DECISION`**（RAWとcoverageを得た**後**にのみ判定）。

**別系統:** `G1 NOT PROVEN` ⇒ `AWS WRITE BLOCKED` を上記の**全段階で継続**。G1合否をRead-only AWS RAW取得の前提へ混入させない。G2受入もGrant発行・収集開始の前提へ逆流させない。

`RUNTIME_FIXED_HEAD_INDEPENDENT_REVIEW`と`HOST_NETWORK_BOUNDARY_ACCEPTANCE`は**RA-E（実装前レビュー）の代用品ではなく、Runtime実装後の独立した2つのGate**。いずれか未受入なら`PRE_EXECUTION_ACCEPTANCE`を出さず、Owner Grantの承認候補へ昇格しない。Host受入に実AWS通信が必要と判明した場合、別の限定事前認可と再設計がない限り「未証明」として停止する。循環を避けるため、**実AWSのRAW収集結果で事前のHost受入を事後正当化しない**。

このDAGは本評価用の**提案**であり、RA工程の名前・昇格条件は未承認。RA-A/B/Cは資料・反例仕様のみ。RA-D以降の実装・ホスト検証とRuntime PRは別判断・別審査。Owner Grant/実AWSアクセスは**未承認**。


## 4. 次の安全な工程 — RA-A/B/C（設計だけで進められる）

### RA-A：境界・脅威モデルの正式化

- Owner本人性とGrant発行・取消の信頼境界（誰が署名し、何を署名し、誰が署名鍵と取消Authorityを保護するか）。`CANCEL_PENDING`、`REVOKE_COMMITTED`、`REVOKE_ACK_SUCCESS`、無効Grant・期限切れ・不明状態の差を契約化する。
- Worker↔Gateway↔OS/net↔AWS endpoint、およびSDK認証provider・STS・DNS・TLS・redirect・HTTP再試行を含む**全egress経路**の閉包を証明対象として定義する。
- 成功ACK後の**新規Gateway-local SEND_STARTED=0**という保証と、既開始in-flight byte／AWS到達・処理の非保証を厳格に分離する。
- 失効中の読取RAW、欠落・不一致・送信結果不明を承認済証拠に変換しない。

### RA-B：技術方式の選定（選択は未決）

| 決定ID | 未決事項 | 採用条件（勝手な既定値なし） |
|---|---|---|
| ARC-01 | 単一GatewayとGrant Authorityの配置・**Replicaは未決の任意構成** | 構成に依らず一意なAuthority・耐久状態・取消/送信の線形化・Gateway外の送信禁止が必須。**Replica/Leader選挙・旧Leader fencingは複製・切替を採用するときだけ追加必須**。単一Gatewayでも障害時停止と復旧後の古い送信禁止は必要 |
| ARC-02 | Grant ledgerのdurable storageと線形化サービス | `SEND_INTENT`と`SEND_STARTED`のcrash gapをUNKNOWNにでき、実環境で旧状態のreplayを遮断 |
| ARC-03 | Owner認可・取消の本人確認、署名原本の保存・照合 | Code/Plan/Principal/Role/Account/Region/API/params/TTL/budget/contextすべて束縛 |
| ARC-04 | 短期Read-only credential adapterと資格情報の配置 | Worker/Agent/ログにSecretを返さない。想定外provider fallbackや暗黙ネットワークを列挙・遮断 |
| ARC-05 | SDK version/transport adaptation、送信計測位置 | retryの実効設定を検証、認可と初回HTTP送信の順序境界が実測・独立試験可能 |
| ARC-06 | Source別Owner Grant・IAM allowlist/Region/S3 prefix | P1/P2/P2-Lake/P3/P4が独立。アクセス不可はUNKNOWN・NOT_ATTEMPTEDで停止 |
| ARC-07 | RAW secure staging／証拠の署名・封印・共有 | 取得時刻／request/Grant/ledger/RAWの相互結合とNo Secretsの検証を可能にする |
| ARC-08 | 対象Host・network namespace・CI実行場所 | 実クラウド資格情報はCIに提供しない。Hostに実行権限を与える前に隔離機能を独立証明 |

選定の根拠が不足している場合は`CANDIDATE_NOT_SELECTED`とし、利便性だけで1つの方式に決めない。

### RA-C：反証可能なオフライン試験の追加仕様

| テストID | 故障注入・反例 | 必須観測／Fail Closed |
|---|---|---|
| RA-T01 | Grant検証済み→Owner取消→初回send境界 | 取消勝ちならHTTP send 0／`SEND_STARTED`なし。送信勝ちなら先行started seq、ACKは後 |
| RA-T02 | SDK内部retry/custom handler/redirect/metadata provider | 未認可・台帳外送信経路があれば起動不可（合成模擬でも未証明を成功扱いしない） |
| RA-T03 | Authority分断・旧Leader fencing不能 | 新Gateway切替禁止、Ownerへの取消成功ACK禁止、`CANCEL_PENDING/UNKNOWN`保持 |
| RA-T04 | `SEND_INTENT`後／`SEND_STARTED`前後でCrash | 未確定送信は`SEND_OUTCOME_UNKNOWN`、同じattemptの自動再送0 |
| RA-T05 | 一部Hostだけが隔離され、別Hostから直接AWSへ送れる | `COMPLETE_MEDIATION_NOT_PROVEN`、実行不可 |
| RA-T06 | 失効済みOwner Grant／code/plan/params変更／期限・予算超過 | 全物理送信0、拒否理由と試行IDをauditへ |
| RA-T07 | SAR REQUIRED Resource typeやRCP例外の証拠不一致 | 必ず`UNKNOWN`。Writerを`IMPOSSIBLE`にしない |
| RA-T08 | P1のLake空、P2-Lake未認可、Trail期間に欠損、Identity Center未取得 | Source別`PARTIAL/UNKNOWN`、全域COMPLETE禁止 |
| RA-T09 | JWT/STS/credential/RAW機密文字列がledger/共有ZIPへ混入 | Fail Closed・共有出力停止、Secret本文は再出力しない |
| RA-T10 | BEGIN/ENDでPolicy/Principal/Role/Assignmentが変化（ABA含む） | `INCONSISTENT/UNKNOWN`、単一時点のeffective permissionと断定しない |

これらは**受入試験案**であり、D2までのPASS件数に混ぜて「実装済み」としない。

## 5. Owner決裁との分離

**本評価は署名済みGrantではない。** 将来のread-only AWS収集を検討する場合でも、次を人間が別途個別判断するまで`OWNER_AUTHORIZATION_NOT_GRANTED`：

1. 対象Account・principal・Role・別context（P1/P2/P2-Lake/P3/P4）の明示許可。
2. SDK Service/Operation×IAM Action×Resource/Conditionの固定allowlistと禁止操作。
3. 対象Region、過去の期間、開始／終了の照合条件、CloudTrail各ソース、P4 Bucket/Prefix/bytesとKMS例外。
4. Code commit・Plan SHA・環境・credential provider・短期認証期間・grant取消権者・コスト/API回数／物理送信／bytes上限。
5. 保護RAW保存先、暗号化・アクセス制御・保持／破棄、公開するredacted派生物とレビュー責任。
6. リスク受容基準、取得中断時のUNKNOWN・取消成功通知の意味、実行前の独立安全審査結果。

「実装の準備ができた」と「OwnerがAWSアクセスを承認した」は**別の事実**。

## 6. 品質・ドキュメント残課題

- PR #8の独立コードレビューR3は`LIMITED_PASS_OFFLINE_CONTRACT`を付与した。Finding `FND-D2-001..005`および`R2-NEW-001`は合成ソースで解消したとの審査結果を継承する。ただし実HTTP/TLSやGatewayのruntime保証を昇格させない。
- マージ済みmasterで`G2 Offline Evidence Safety`、`Safety Hold CI`、`SonarCloud Code Analysis`はSUCCESS。SonarCloudのmasterチェックには新規Issueが50件と表示された。PR #8の3件は`g2_d2_rcp.py`のCognitive Complexity 2件およびnested `if` 1件として確認済み。新規コードCoverageはPR #8チェック上`0.0%`と表示され、CIでテストを実行した事実とは区別。**実装フェーズへの昇格前に**CIカバレッジ計測・取込、重大Code Smellの取扱いを技術的に判定する。
- R3設計原本とD2履歴文書の旧「review pending」表示を、現在の安全状態や承認の証拠として再利用しない。新文書には`fixed commit → independent review → merge commit`の履歴を明示する。上位仕様や既存Findingのステータスをこの評価だけで改変・再OPEN・解決しない。
- SDKの実transportやAWS Credentialの実装は、静的guardを単に弱めて既存D2モジュールに混入させない。専用の別設計・別ブランチ・別CI/Gateを必要条件とする。

## 6A. PR #9 Fresh Independent R1 — 限定是正Tracker

**独立レビュー入力HEAD:** `5681ce042bf605f1c6e2d4eb7c6fe3a4f04a20f7`。レビュー判定は`REVISION_REQUIRED`（Major 1 / Moderate 1 / Minor 2）。著者側の本改訂は下表の**`RESOLVED_IN_PROPOSAL`**に留め、固定HEADの新しい独立再審査が必要。

| Finding | 本改訂 | 著者状態 |
|---|---|---|
| FND-PR9-001 Major | §2で`PRE_EXECUTION` / `EVIDENCE_ACQUISITION` / `POST_ACQUISITION`を分離。IR-10とIR-14の実RAW・G2独立受入は**取得後のGate**と定義し、取得開始条件から除外。G1 Write閉鎖は独立 | RESOLVED_IN_PROPOSAL |
| FND-PR9-002 Moderate | §3にRuntime実装後の`RUNTIME_FIXED_HEAD_INDEPENDENT_REVIEW`と`HOST_NETWORK_BOUNDARY_ACCEPTANCE`を別々に明記。両方の受入後のみOwner Grant候補 | RESOLVED_IN_PROPOSAL |
| FND-PR9-003 Minor | IR-03/04およびARC-01で、一意権威・Durability・旧経路排除を普遍必須とし、Replica/Leader選出を方式依存の条件付き義務と規定 | RESOLVED_IN_PROPOSAL |
| FND-PR9-004 Minor | §1.1Aで独立判定のローカルID、受領日、対象HEAD、PR/merge/CIを記録。レビュー原本の永続URL・SHA-256がない点は**NOT_VERIFIED**として明示し、監査原本の後続固定化を要求 | PARTIALLY_RESOLVED（provenance未完了） |

**監査上の境界:** FND-PR9-004は出典メタデータを拡充したが、独立レビュー原本が手元にない以上`ORIGINAL_VERIFIED`とは主張しない。実際の独立PASS/署名、Runtime実装適格性・AWS実行認可を本PRの文書編集から生成しない。

## 7. 結論・次の許容作業

| 決定 | この時点 |
|---|---|
| `D2_OFFLINE_CONTRACT` | **LIMITED_PASS**（独立レビュー済み、PR #8 master反映済み） |
| `NEXT_OFFLINE_DESIGN / FEASIBILITY PREPARATION` | **READY_TO_PREPARE**（このR1報告は著者作成、独立評価前） |
| `RUNTIME_IMPLEMENTATION_READINESS` | **NOT_READY**（実行前の証明義務が未充足。POST_ACQUISITIONのG2受入をRuntime開始の前提にはしない） |
| `REAL_AWS_EXECUTION_AUTHORIZATION` | **NOT_GRANTED** |
| `G2_EVIDENCE_ACQUISITION` | **NOT_EXECUTED / NOT_VERIFIED** |
| `G1_NAME_WRITE_GATE` | **NOT_PROVEN / AWS_WRITE_BLOCKED** |

**次の安全なアクション:** R1固定HEAD `5681ce042bf605f1c6e2d4eb7c6fe3a4f04a20f7`に対する独立レビューで指摘されたFND-PR9-001〜004を本改訂として限定再審査する。独立PASSなら**RA-A/B/Cの非接続・非実行設計とオフライン反例の準備だけ**に進める。RA-D以降の実装、SDK/transport開発、Runtime Fixed-HEAD独立受入、Host Network Boundary受入、実AWSへの実行Grantはいずれも**別の証明とOwner判断**が必要。

**この文書の作成・PRマージ・レビューPASSが、Owner実行Grant・AWS接続・G1/G2形式的受入を発生させることはない。**
