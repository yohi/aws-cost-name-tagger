# AWS Cost Name Tagger v3.6 — Name補完専用 / Safety Hold

更新: 2026-10-21 (JST)。この版は **Nameタグの提案と関連根拠のレポート出力だけ**を行います。プロダクト分類（Productタグとの対応表、alias解決、原価配賦）は別の処理の責務です。

**AWS変更は禁止したままです。** `run --mode y` はレビューの記録のみ、`apply` は必ず拒否し、`Investigator.write_name()` も必ず例外を送出します。`dryrun` も AWS 読み取り・ローカルレポート生成のみです。

## v3.5 → v3.6 の変更点（OwnerのR1.1要件）

**Name補完対象:** `Name` キーがない（`ABSENT`）か、**キーは存在し値が厳密に空文字 `""`**（`EMPTY`）の場合だけName候補とする。いずれも、関連関係・名前の妥当性が不足すれば `manual_review` に留めます。

| Nameキー | Name値 | `name_state` | Name候補 | 保護 |
|---|---|---|---|---|
| なし | — | `ABSENT` | 根拠がある場合のみ | Safety HoldでAWS書込禁止 |
| あり | `""`（長さ0） | `EMPTY` | 根拠がある場合のみ | Safety HoldでAWS書込禁止 |
| あり | `" "`・`"\t"` 等、長さ1以上 | `NONEMPTY` | なし (`already_named`) | 既存値を保護 |
| あり | `"scs2-prd-web-ec2"` 等 | `NONEMPTY` | なし (`already_named`) | 既存値を保護 |
| 不正な型、APIエラー、取得不能、`name`/`NAME` のような紛らわしいキー | 不明 | `UNKNOWN` | なし (`manual_review` / `api_error`) | Fail Closed |

**取得値をtrimして空を判定しません。** 空白1文字でも`NONEMPTY`です。`Name`キーの重複や値欠落はUNKNOWNとして扱います。

**PR-BのAWSサービス別入力契約:** タグ取得元のAPIごとに、`list`形式（EC2系・RDS・OpenSearch・ELBv2・CloudFront・Athena・WAFv2・S3）または`dict`形式（API Gateway・CloudWatch Logs・Lambda）を明示し、不一致・不正なキー型・値型・同一キー重複は`UNKNOWN`としてName候補を生成しません。タグ値の`Value`がSDKレスポンスモデル上任意であるlist形式のEC2系・RDS・ELBv2・CloudFront・Athenaでは、**非Nameキーだけ**`Value`省略を空文字に正規化します。`Name`の`Value`欠落はサービスを問わず拒否します。OpenSearch・WAFv2・S3のlist形式は`Value`必須です。親リソースのタグも同じ形式契約で検証し、不正なら候補生成を止めます（子側の正常なABSENT状態自体は変更しません）。サービスがタグ項目そのものを省略したときは、既存の空集合既定値を維持します。正常な空文字・非NameのProductエイリアス不一致は拒否理由にしません。Pythonのdictは重複キーを表現できないため、重複検査はlist形式が対象です。ここでいう省略許容はbotocoreモデル上のスキーマ互換性であり、実AWSが必ずその形で返すことを証明するものではありません。

**PR-B FND-12-R2-003（ページネーション）:** Athenaの`ListTagsForResource`は`NextToken`、WAFv2の同APIは**トップレベル**の`NextMarker`で未取得ページを通知します。本版は追加ページを取得せず、継続トークンが返された時点で**Name状態を`UNKNOWN`・候補なし・`manual_review`**としてfail-closedにします。1ページ目のタグから`ABSENT`/`EMPTY`を確定しません。継続トークンがない（または`null`）単一ページは従来どおり評価します。**WAFv2のみ、`NextMarker=""`も正常な終端マーカーとして扱い、`ABSENT`/`EMPTY`/`NONEMPTY`を通常判定します。** AWS CLI公式例が空文字を返す一方、WAFv2 APIモデルでは`NextMarker`に最小長1の制約があります。この仕様表現の差異を記録し、非空トークンおよび不正な非文字列マーカーは引き続き拒否します。Athenaの`NextToken`に関するfail-closed契約は変更しません。この判断はAWS読み取り件数を増やさない限定防御で、複数ページのタグを網羅取得する機能や実AWSでのページ分割の確認ではありません。

**出力の互換性:** `plan.json` の `schema_version` を **2** に上げ、全候補に `name_state`・`name_key_present`・`name_raw_value`・`existing_name` を付与。CSV（review/report/result/監査/selected）でもNameの状態を独立した列で出力します。`name_key_present` は `true`/`false`、取得不能のときは `null` です。`name_raw_value` は、正常に取得できたName文字列（未設定は `null`、EMPTYは `""`）を保持します。異常な型ではRAWは利用せず `null` とし、UNKNOWNで拒否します。

**候補IDの互換性:** v3.6の `proposal_id` は旧v3.5と異なる専用名前空間にし、ABSENTとEMPTYを必ず区別します。旧レビューCSVや承認候補を流用せず、新しいdryrun結果をレビューしてください。`proposal_id` はレビュー識別子であり、書き込み認可ではありません。

**変更しない点:** `Product`名／別名の解釈は別工程。EBS→EC2のName継承、RDS所属、CloudFrontオリジン等の推定は維持。`Y` は人間のレビュー記録のみ、`apply`と`write_name`は常時拒否し、Name追加・Name空文字更新は**いずれも実施しません**。

## v3.4 → v3.5 から継承した機能

- `Product=storecms` / `Name=storecms2-...`、`Product=ogne` / `Name=coord-app-...`、`Product=ros` / `Name=ros-sftp-...` 等は、**Name候補を拒否する理由にしない**。alias辞書も導入しません。
- EBS・ENI・EIPは接続先EC2の**既存Nameのみ**を引き継ぎます。`Product`は参照根拠に観測値として残る場合がありますが、判定には使用しません。
- RDSは実際のクラスタ所属を照合し、既存NameまたはDB識別子から候補を生成します。`Product`タグとの文字列一致検証はしません。
- CloudFrontはオリジン・Alias・Commentから名前と用途を推定します。`Product`による補正・変換はしません。
- `shared-service-prd-*` のような共通基盤も**共有基盤としての記述的Name**を提案できます（`medium`）。特定のプロダクトへの割り当てはしません。
- CLIオプション `--products` を廃止。対象絞り込みは `--kinds`、`--min-cost` など、**リソース種類と費用**で行います。旧オプション使用はエラーで停止します。
- `Name` と `Product` の整合性を担保する責任は本ツールにはありません。下流の製品分類ロジックで別途検証してください。

### 維持する安全条件

- `Name` キーが存在して**非空文字**なら `already_named` として保護。`Name=""` は候補（根拠があるときのみ）。空白文字は非空として保護。
- 親子関係が複数候補・不明、または命名に必要な根拠が不足する場合は `manual_review`。
- EBS Snapshotは作成時点の所有者が証明できないため、自動推定しません。
- 命名プレフィックスの解析は「Nameの構造・環境名」の確認のみ。**AWS `Product` タグや製品カタログへのマッピングではありません。**
- S3タグ更新なし。すべてのAWS書き込み経路を無効化。ローカルレポートはPOSIX `0600`、新規ディレクトリ `0700`、symlink追跡禁止、上書き禁止。
- ステージング→複数ファイル公開は通常エラー時ロールバック可能ですが、**SIGKILL・電源断時の一括原子性は保証できません**。
- **PR-C候補の公開境界:** `plan`・`run`の既定`--output`は`./.aws-cost-name-tagger/name_tag_plan.json`です。専用ディレクトリがなければモード`0700`で作成します。明示指定の`--output`も、AWSログイン・CUR処理・AWS APIより前に公開先ディレクトリとplan/review/reportの既存ファイル衝突を検査します。`--mode dryrun`を指定した場合はresult、`--mode y`を指定した場合はselected/auditの衝突もログイン前に確認します。対話モードで選択が未確定の場合、追加ファイルはモード選択後・plan生成前に確認します。公開先とステージング元は実効UIDが所有し、group/otherの権限を許さないprivateディレクトリが必要です。既存ディレクトリは自動`chmod`せず、不一致は`PermissionError`で停止します。共有ディレクトリ直下へ直接出力する既存利用方法は変更が必要です。
- **検証済み実行環境はUbuntu Linuxに限定します。** 実行前にLinux/Ubuntuの判別、`O_DIRECTORY`・`O_NOFOLLOW`、`open/mkdir/stat/link/unlink` の`dir_fd`、`stat/link`の`follow_symlinks=False`能力を確認し、非対応ならAWSアクセス前に停止します。macOS/APFS（ACLや所有権無効ボリュームを含む）・他のLinuxディストリビューション等の安全性は未検証であり、本実装では拒否します。UbuntuでもACL・マウント設定・親ディレクトリの信頼性を含む実効隔離を普遍的に証明したものではありません。
- **同一UIDや特権プロセスを敵対的とする隔離保証はありません。** 通常のパス名チェック、所有者/mode検証、dirfdでは、同一UIDによるエントリ置換や変更可能な親パス全般を排除できません。これらを含める脅威モデルは別設計とGate判断が必要です。
- ステージング元のsymlink・FIFO・ディレクトリ等の非通常ファイルは公開しません。ロールバック自体が失敗した場合は、主障害とcleanup障害、残存した可能性のある出力先を例外情報として通知します（クラッシュ時の永続性保証ではありません）。

## 環境

- **PR-C候補: Ubuntu Linuxのみサポート。** macOSおよび他の未検証OSでは実行前に停止します。macOSの実機/APFS/ACL試験は実施しておらず、`0700`だけで実効隔離を保証しません。
- Python 3.10以降、`uv`、対話型 `aws login --remote` を利用する場合は対応AWS CLI。
- `pyproject.toml`: `boto3[crt]==1.43.116`。
- **このGitHubリポジトリには `uv.lock` をコミット済み**で、`boto3[crt]==1.43.116` がロックされています。元のv3.6配布ZIPには `uv.lock` が含まれていません。2026-10-22にGitHub Actionsで指定環境の **76/76 テストPASS（2通り）** を確認しました。

```bash
# 以下のコマンドはリポジトリのルートディレクトリで実行します。
uv sync --locked
uv run --locked python -m unittest -v test_aws_cost_name_tagger_v3
uv run --locked python test_aws_cost_name_tagger_v3.py
```

## 実行例（AWS読み取り専用）

`--output`を省略すると、カレントディレクトリ直下のprivateな`./.aws-cost-name-tagger/name_tag_plan.json`が既定になります。明示的な`--output`を使う場合、既存の出力先ディレクトリは`0700`相当のprivateな権限・実効UIDの所有が必要です。既存の`0755`ディレクトリ（リポジトリ直下等）に直接出力するとAWS認証前に拒否します。新規の中間ディレクトリは必要に応じて`0700`で作成します。

認証は別途ログインするか、`--login ask`で案内します。対象AWSアカウントと実際のIAM主体が表示されますが、ロール名・STSだけでは実効権限は証明されません。可能な限り読み取り専用ロールを使用してください。

```bash
aws login --remote --profile saas-prd-ro
aws sts get-caller-identity --profile saas-prd-ro

uv run --locked python aws_cost_name_tagger_v3.py run \
  --cur /path/to/aws-resource-cost-detail-00001_202610.csv.gz \
  --month 2026-10 --account 456720798575 \
  --profile saas-prd-ro --login skip --mode dryrun \
  --min-cost 10 --max-resources 100 \
  --output ./private-reports/high-cost/plan.json

uv run --locked python aws_cost_name_tagger_v3.py run \
  --cur /path/to/aws-resource-cost-detail-00001_202610.csv.gz \
  --month 2026-10 --account 456720798575 \
  --profile saas-prd-ro --login skip --mode dryrun \
  --min-cost 0.5 --kinds volume,snapshot \
  --output ./private-reports/ebs/plan.json
```

生成する出力ファイル（上記の `plan.json` を基準に命名）：

| 出力 | 内容 |
|---|---|
| `plan.json` | schema_version=2、候補、ARN、費用、根拠、name_state、Nameキーの有無・生値 |
| `plan.report.csv` | 調査結果一覧、Nameの状態・キー存在・生値を独立表示 |
| `plan.review.csv` | Name状態を含むレビュー入力用、承認列は初期状態で空 |
| `plan.result.csv` | Name状態を含むdryrun未変更結果 |
| `plan.selected.csv` / `plan.audit.jsonl` / `plan.audit.csv` | `Y`で選択した候補・レビュー監査のみ、**AWS書き込みなし** |

## 重要な制約

- Nameのプレフィックス自体が誤っている可能性や、共有リソースが複数プロダクトで使われる可能性は残ります。提案は製品帰属の証明ではありません。
- `write_name()` / `apply` は意図的に使用不可です。原子的な「Name未存在時のみタグ追加」が各サービスで保証できる書き込み設計は**未承認・未実装**です。
- 配布ZIP作成時点では指定依存環境による検証が未実施でした。GitHubでは `uv.lock` を追加し、固定依存環境での実行をCIで検証します。`test_results.txt` と `uv_lock_attempt.txt` は**配布ZIP作成時の履歴記録**であり、GitHub上での現状を示すものではありません。
- 2026-10-21の提出dryrunレポート（高額90件＋EBS28件）は `ABSENT` 58件・`NONEMPTY` 60件・`EMPTY` 0件でした。**提出データの整合性確認であり、AWSへの独立再接続・CloudTrail検証ではありません。**
- v3.4/v3.5の既存レポートはv3.6へ自動変換しません。特に従来の承認候補・候補IDは流用しないでください。

## GitHub Actions（Safety Hold CI）

`.github/workflows/ci.yml` は `master`、`feature/**` へのpush、Pull Request、手動実行で起動します。AWS認証情報や実AWSへの接続は不要で、**すべてモック／ローカルのテスト**です。

1. Python 3.12 と uv を準備し、`uv sync --locked` で依存関係を固定してインストール。
2. Boto3 `1.43.116` とAWS CRTをimportして依存バージョンを確認。
3. `SHA256_MANIFEST.json` に記載されたファイルのSHA-256とサイズを確認（`uv.lock` とCI workflowも含む）。
4. `uv run --locked python -m unittest -q test_aws_cost_name_tagger_v3` および直接実行でSafety Holdを含む現行76件のテストを検証（追加テスト数はリポジトリの更新により変わります）。

**CIの実行結果は[GitHub Actions Run #39702373325](https://github.com/yohi/aws-cost-name-tagger/actions/runs/39702373325)で確認済みです。** このRunでは依存関係固定、Boto3/CRT、マニフェスト11ファイル、両実行方法のテスト76/76がすべてPASSしました。依存関係の更新が必要な場合は、別変更で `uv lock` を実行して `uv.lock` とマニフェストを更新します。Safety Holdの解除やタグ書き込みは行いません。
