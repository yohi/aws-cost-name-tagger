# エージェント向け作業ルール

## SHA-256 マニフェスト

`SHA256_MANIFEST.json` に登録されたファイルを変更した場合は、同じ変更で該当エントリーの SHA-256 と `bytes`（ファイルのバイト数）も更新すること。

CI と同じローカル検証コマンドは `uv run --locked --no-build python scripts/validate_sha256_manifest.py`。不一致がある場合は、最初に報告されたファイルだけでなく全件を修正し、検証成功後にコミットすること。

ローカルコミットでも自動検証するため、リポジトリごとに一度 `git config core.hooksPath .githooks` を設定すること。設定後は `.githooks/pre-commit` が上記検証を実行する。CI も同じスクリプトを呼び出す。
