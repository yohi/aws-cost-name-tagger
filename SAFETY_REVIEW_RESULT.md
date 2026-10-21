# AWS Cost Name Tagger v3.6 — ABSENT / EMPTY 読み取り分類改訂

**範囲:** v3.5 Safety Hold（ZIP SHA-256 `1a88b2d9986bb767306ef107b323a4ee65f82eeaa5bba1915ac15afd37110172`）から、設計R1.1の**候補判定だけ**を変更。AWS実接続・タグ変更は一切未実施。

| 要件 | 判定 |
|---|---|
| `Name`タグがない（ABSENT） | 命名根拠があれば候補 |
| `Name=""`（EMPTY） | 命名根拠があれば候補 |
| 空白やタブだけでも1文字以上（NONEMPTY） | 既存Nameを保護 |
| 値がnull・不正型・不正形状／API取得不明（UNKNOWN） | 提案を中止、保留 |
| 出力 `name_state` / `name_key_present` / `name_raw_value` | JSON・CSVの全経路へ反映 |
| 旧版の候補ID混同防止 | `schema_version=2`、状態依存の別ID |
| `Product`マッピングとName補完 | 従来どおり分離 |
| `run --mode dryrun` / `Y` | AWS書き込みゼロ、Yはレビュー記録のみ |
| `apply` / 直接 `write_name()` | 常時拒否（Safety Hold） |
| POSIX O_NOFOLLOW／出力ファイル権限 | v3.5から維持 |
| 既知の複数ファイル公開の非原子性 | 残留。SIGKILL／電源断では部分公開の可能性 |
| 原子的 ABSENT-or-EMPTY-only AWS書き込み | **NOT PROVEN / BLOCKED** |
| AWS上のEmpty Name件数 | **NOT MEASURED**（新しいdryrunが必要） |
| 指定Boto3+CRT環境／uv.lock | **未検証**（オフラインでは生成できず） |

**テスト:** 既存60件のうち旧仕様の2件を更新し、状態分類・EBS/RDS/CloudFront・UNKNOWN・CSV・候補ID・Safety Holdの10件を追加。結果は `test_results.txt` に記録。テストはモックとローカルファイルのみで、実AWSのEmptyタグ件数は推計していない。

**重要:** Nameを付与するAPIは実装していないため、既存の非空Nameを実際に上書きしない条件付きタグ更新を証明したわけではありません。将来の書き込みGateは別途独立審査が必要です。
