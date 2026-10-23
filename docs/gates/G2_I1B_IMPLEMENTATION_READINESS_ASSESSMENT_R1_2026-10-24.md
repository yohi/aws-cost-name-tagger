# G2-I1-B — Implementation Readiness Assessment R1

**基準日:** 2026-10-24 JST  
**Repository:** `yohi/aws-cost-name-tagger`  
**固定master/PR #8 merge HEAD:** `0ed903f0ab2936023823df3a2669536ec781d421`  
**PR #8 独立レビュー合格HEAD:** `0f7819ae15d8fb3753516442a082d0c3c6fde936`  
**対象:** I0/I1/D2から将来のRead-only Collector実装への移行準備。**今回の成果物は非実行の技術評価のみ。**  
**Author assessment status:** `ASSESSMENT_PREPARED / FRESH_INDEPENDENT_READINESS_REVIEW_REQUIRED`（著者側の判定であり正式Gate通過ではない）  
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
| 独立レビュー | PR #8 fixed HEAD `0f7819ae…` | 受領済み独立R3レビューは`LIMITED_PASS_OFFLINE_CONTRACT`。オフライン**ソース/モデル**の判定であり実AWS安全性ではない |

固定HEADおよびPR #8のmergeをGitHubから確認。PRレビューのテキストは別途受領済み審査証拠として扱う。設計文書先頭の「R3限定レビュー待ち」、D2実装文書先頭の「コードレビュー待ち」という旧記述は**過去時点の状態表示**であって、後の独立PASS/マージを否定するものではない。本R1は履歴を破壊せず現在の状態を追記するスナップショットである。

### 1.2 今回の判定で「証明済み」と呼べる最も強い内容

- `OFFLINE_MODEL_REVIEWED`：D2の合成First-byte/取消競合、旧Attempt差替え拒否、合成Fencing witnessの扱い、RCP Resource別UNKNOWN伝播が固定コードと合成テストで独立レビュー済み。
- `CI_COMPLETED_SUCCESS`：固定HEADのG2 Offline Evidence Safety／Safety Hold CI／SonarCloud Check Runは成功。ただしランタイム・実効IAM・証拠真正性の証明ではない。
- `RUNTIME_NOT_PROVEN`：実`botocore`client、HTTP/TLS/OSの初回送信境界、複数HostでのSAES直列化、実Gatewayのfencing、永続ledger、署名付きOwner Grant、credential adapter、実AWSへのアクセスはD2に含まれない。
- `AWS_EVIDENCE_NOT_EXECUTED`：P1/P2/P2-Lake/P3/P4のどれについても、この工程で実AWS RAW原本を取得したと主張しない。`G2 NOT VERIFIED`を維持する。
- `AWS_WRITE_BLOCKED`：Nameタグ更新、安全な条件付き書込のG1 Gateは別の証明義務であり、本評価に含めない。

## 2. Readinessマトリクス — 設計の存在と実装実証を区別

| ID | 実装・証明義務 | 固定HEADにあるもの | 未充足（現状のステータス） | 実行への影響 |
|---|---|---|---|---|
| IR-01 | 人間Ownerの**別署名**Grant／失効認可、Grant scope・TTL・code/plan/identity binding | 設計要求と合成Grantのstate machine | 実署名検証・本人性・revoke authority・鍵管理・再利用防止 **NOT_PROVEN** | BLOCK |
| IR-02 | SAES Gateway以外からのAWS egress全遮断／権限分離 | SAESを唯一の送信権威とする参照設計 | OS/net/namespace/sidecar/credential-provider/redirectを含むcomplete mediation **NOT_PROVEN** | BLOCK |
| IR-03 | 複数Worker/Hostに対するGrant別の**耐久・線形化可能な**順序とepoch | 単一プロセス `RLock` と合成イベント順序 | 複製Authority、leader選出、fencing、partition/復旧、耐久性 **NOT_IMPLEMENTED** | BLOCK |
| IR-04 | 取消ACKの強い事後条件（ACK後の新規send 0、未知Gateway存在時はACK拒否） | 合成の取消勝敗・Fencing witness・ACK順序 | 実Gateway切替・旧Leaderの遮断確認、到達可能なOwner取消の真正性 **NOT_PROVEN** | BLOCK |
| IR-05 | 物理HTTP First-byte / Retryの完全な仲介 | SDK内部retry禁止の設計（`total_max_attempts=1`） | 実Botocore/urllib3/TLS transport／初回byteの実測・SDK event handlers／暗黙のnetwork hop **NOT_IMPLEMENTED** | BLOCK |
| IR-06 | crash前後の`SEND_INTENT`・`SEND_STARTED` ledger、Unknownな送信結果の非再送 | 合成`SEND_OUTCOME_UNKNOWN`・in-memory records | 原子的durable journal、fsync/commit順序、crash/partition/replay test **NOT_PROVEN** | BLOCK |
| IR-07 | Request allowlist・operation→IAM action／ARN／conditionの固定モデル | 設計上の各API候補、I1 fixture Plan/Operation | SDKバージョン固定のモデル照合、resource-level認可範囲・フィルタ/予算閉包 **INCOMPLETE** | BLOCK |
| IR-08 | Sourceごとの別principal／別Grant／read-only IAM条件の実効確認 | P1/P2/P2-Lake/P3/P4設計と合成STS identity | 本人性・権限の実証、管理主体の可用性、Session Policy/SCP/RCPの実効評価 **NOT_PROVEN** | BLOCK |
| IR-09 | IAM/SCP/RCP/SSO authorization graph・Writer候補の安全なUNKNOWN保持 | RCP合成ResourceEvaluationとI1 mock | 実SAR機械可読の固定・照合、policy chain／resource ownership、全Writer closure **NOT_PROVEN** | BLOCK |
| IR-10 | CloudTrail EH/Trail-S3/LakeのSource別coverage、過去履歴・digest/配送欠損 | G2 R1.1契約と受入試験 | 実Region/期間/selector履歴、独立3ソースのRAW・欠損解析 **NOT_EXECUTED** | BLOCK |
| IR-11 | 機密RAWの保護保存、BEGIN/END、manifest・immutable seal、共有派生物のみ | I0のオフラインbundle/整合性検査 | 実SDK decoded page・S3原本byteのcustody、Grant/attempt binding、暗号化／検閲・攻撃試験 **NOT_PROVEN** | BLOCK |
| IR-12 | CIの非実行境界と回帰テスト | 依存固定・静的guard・Docker network-none・Safety Hold | 実Hostのネットワーク隔離とSDK/OS送信妨害試験は別工程。Coverage ingestは未確認 | OFFLINE ONLY |
| IR-13 | Owner正式決裁（account, context, role, region, timeframe, budget, bytes, storage, credential） | Owner Matrixの未署名入力要件 | **ALL PENDING / NO GRANT** | BLOCK |
| IR-14 | G2 RAW独立受入、G1条件付き書込 | 必要な受入規範のみ | `G2 NOT VERIFIED / G1 NOT PROVEN` | BLOCK |

**判定規則:** `BLOCK`は「実AWS送信に進めない」の意味で、設計・ネットワーク遮断合成試験を禁止する意味ではない。`READY_FOR_OFFLINE_MODEL`を`READY_FOR_RUNTIME`へ昇格しない。

## 3. 技術上の優先依存関係（非循環）

`D2 fixed approved offline model`  
→ `RA-A: normative contract & threat model snapshot`  
→ `RA-B: SAES/Grant/credential/egress architecture choice`  
→ `RA-C: each boundary's offline falsification test specification`  
→ `RA-D: separated offline feasibility spike (no SDK network access)`  
→ `RA-E: fresh independent architecture/feasibility review`  
→ **`RUNTIME_IMPLEMENTATION_ELIGIBILITY_DECISION`（現時点保留）**  
→ 必要な場合のみ、将来の別PR・別評価で`runtime adapter implementation & hostile runtime verification`  
→ **別Ownerの`EXECUTION_AUTHORIZATION`**  
→ その後の限定Read-only AWS Evidence Acquisition／独立G2受入。  
**G1は常に別Gate、AWS WRITEは閉鎖継続**。

このDAGは本評価用の**提案**であり、RA工程の名前・昇格条件は未承認。RAの資料作成やオフライン合成試験ではAWSへのネットワーク接続や資格情報取得を行わない。

## 4. 次の安全な工程 — RA-A/B/C（設計だけで進められる）

### RA-A：境界・脅威モデルの正式化

- Owner本人性とGrant発行・取消の信頼境界（誰が署名し、何を署名し、誰が署名鍵と取消Authorityを保護するか）。`CANCEL_PENDING`、`REVOKE_COMMITTED`、`REVOKE_ACK_SUCCESS`、無効Grant・期限切れ・不明状態の差を契約化する。
- Worker↔Gateway↔OS/net↔AWS endpoint、およびSDK認証provider・STS・DNS・TLS・redirect・HTTP再試行を含む**全egress経路**の閉包を証明対象として定義する。
- 成功ACK後の**新規Gateway-local SEND_STARTED=0**という保証と、既開始in-flight byte／AWS到達・処理の非保証を厳格に分離する。
- 失効中の読取RAW、欠落・不一致・送信結果不明を承認済証拠に変換しない。

### RA-B：技術方式の選定（選択は未決）

| 決定ID | 未決事項 | 採用条件（勝手な既定値なし） |
|---|---|---|
| ARC-01 | 単一GatewayとGrant Authorityの配置・Replica要否 | Gateway以外のAWS送信禁止、全Hostの入口一致、他Host/旧Leader fencingが実証可能 |
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

## 7. 結論・次の許容作業

| 決定 | この時点 |
|---|---|
| `D2_OFFLINE_CONTRACT` | **LIMITED_PASS**（独立レビュー済み、PR #8 master反映済み） |
| `NEXT_OFFLINE_DESIGN / FEASIBILITY PREPARATION` | **READY_TO_PREPARE**（このR1報告は著者作成、独立評価前） |
| `RUNTIME_IMPLEMENTATION_READINESS` | **NOT_READY**（IR-01〜IR-11に未証明・未選定の必須項目） |
| `REAL_AWS_EXECUTION_AUTHORIZATION` | **NOT_GRANTED** |
| `G2_EVIDENCE_ACQUISITION` | **NOT_EXECUTED / NOT_VERIFIED** |
| `G1_NAME_WRITE_GATE` | **NOT_PROVEN / AWS_WRITE_BLOCKED** |

**次の安全なアクション:** 本R1を新しい独立レビュアーが、固定masterと実コード・未証明項目に照らしてレビューする。承認可能な場合は**RA-A/B/Cの非接続・非実行設計とオフライン反例の準備に限定**して着手できる。RA-D以降の実装、SDK/transport開発の権限拡張、実AWSへの実行Grantは**別のOwner判断と技術レビューが必要**。

**この文書の作成・PRマージ・レビューPASSが、Owner実行Grant・AWS接続・G1/G2形式的受入を発生させることはない。**
