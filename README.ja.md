# Agent Content Firewall

[English](README.md) | [简体中文](README.zh-CN.md) | [日本語](README.ja.md) | [한국어](README.ko.md)

Agent Content Firewall は、AI エージェント向けのローカルセキュリティファイアウォールです。悪意のあるコンテンツを遮断し、エージェントが操作されるのを防ぎます。

## 検査対象

- `pdf-injection-scanner` による PDF テキストの色とフォントサイズ
- Poppler と Tesseract による PDF レンダリングとローカル OCR
- PDF のメタデータ、JavaScript、埋め込み添付ファイル
- EPUB コンテナ、大量の画像、ローカル OCR 結果
- 分離された KindleUnpack 展開処理による暗号化されていない AZW3 と MOBI
- DOCX の非表示テキスト、マクロ、埋め込みオブジェクト、代替テキスト、外部リレーション
- HTML の非表示要素、コメント、属性、アクティブ要素、画面外スタイル
- ゼロ幅文字、双方向制御文字、Unicode タグ文字
- 英語と中国語のエージェント向け指示およびデータ送信指示
- MCP などのツール結果がエージェントへ返される前の検査
- 認証情報パスへのアクセス、環境情報の収集、パイプ経由のアップロード、ダウンロードしたコードの実行を行うシェルコマンド

結果は `clean`、`review`、`block`、`error` のいずれかです。既定では、`clean` 以外の結果が返ると Hook の処理を停止し、確認を求めます。ただし、Codex の `review` 結果は以下のとおり扱います。

### Codex の確認ダイアログ（macOS）

Codex のツール実行前チェックでは、次のように扱います。

- `block` と `error` は拒否します。
- 具体的な検出内容を伴わない `review` 結果は、確認なしで許可します。対象は、すべての画像に付く `IMAGE_HIDDEN_CHANNELS_NOT_PROVABLE` と `UNSUPPORTED_DOCUMENT_FORMAT` です。
- その他の `review` 結果では、ローカルの macOS ダイアログにファイル、各検出内容の説明、一致したテキストを表示します。「放行一次」（今回のみ許可）を選んだ場合だけ実行を続けます。「拒绝」（拒否）、120 秒のタイムアウト、ダイアログの失敗はすべて拒否として扱います。Codex の PreToolUse Hook は `permissionDecision: "ask"` を受け付けないため、Hook が直接ユーザーに確認します。
- ダイアログ表示時に通知音を鳴らし、`Tingting` の音声で「Codex 请求任务放行」と読み上げます。読み上げは 60 秒に 1 回までです。

一致したテキストはローカルのダイアログにのみ表示され、エージェントに返す拒否理由には検出コードだけが含まれます。

## ローカルセットアップ

必要な環境：

- Python 3.10 以降
- [`uv`](https://docs.astral.sh/uv/)
- Poppler コマンド：`pdfinfo`、`pdftotext`、`pdftoppm`、`pdfdetach`
- 必要な言語データを導入した Tesseract

分離された実行環境を作成します：

```bash
python3 scripts/bootstrap.py
```

ファイルを直接スキャンします：

```bash
agent-content-firewall file document.pdf
```

## Codex へのインストール

macOS では、リポジトリをダウンロードまたはクローンした後、`install-codex.command` をダブルクリックできます。インストーラーは対象パスを表示し、変更を適用する前に確認を求めます。

クローン後に非対話形式でインストールする場合は、次の 1 コマンドを実行します：

```bash
./install-codex.command --yes
```

ローカル変更をプレビューします：

```bash
python3 scripts/install_codex.py
```

Codex の Hooks とユーザースキルだけをインストールします：

```bash
python3 scripts/install_codex.py --apply
```

インストーラーは既存の Hook グループを保持し、Hook 設定のバックアップを一度作成して、ユーザーのローカルデータディレクトリへ配置します。Claude Code、Pi、OpenCode の設定は変更しません。インストール後は Codex を完全に終了して再起動し、新しいタスクで Hooks を確認してください。

`adapters/` には Claude Code、Pi、OpenCode、DeepSeek Harness、Tencent WorkBuddy 用の任意アダプターも含まれています。有効化方法と制約は `skills/agent-content-firewall/references/integration.md` を参照してください。

## セキュリティ上の境界

本プロジェクトは早期警告のための仕組みであり、コンテンツが完全に安全であることを証明するものではありません。チャットへ直接追加された添付ファイル、クライアント固有のファイル参照、ホスト型ツール、ステガノグラフィ、パーサーの不具合、未対応形式は Hook の範囲を超える場合があります。最小権限を維持し、アップロード、外部への書き込み、削除、認証情報へのアクセス、永続的な設定変更には確認手順を設けてください。

第三者のモデルまたは API リレーは、応答がエージェントへ届く前に返信やツール呼び出しを改変できます。信頼できないリレーをフルアクセスや無人実行と組み合わせないでください。シェルコマンド検査は多層防御の一部であり、信頼できるモデル接続先、サンドボックス、承認、制限されたネットワークアクセスの代替ではありません。

バックグラウンドサービスやリモートの意味分類器は使用しません。EPUB、暗号化されていない AZW3/MOBI、一般的なプロジェクト設定、PDF、DOCX、HTML、テキスト、画像を検査します。形式ごとの依存関係は `uv.lock` に固定されています。ライセンスは[サードパーティー通知](THIRD_PARTY_NOTICES.md)を参照してください。

## 開発と検証

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
uvx ruff check src adapters scripts tests
```

公開前にローカルのプライバシー検査を実行します：

```bash
python3 scripts/privacy_audit.py
git log --all --format='%h %an <%ae> %cn <%ce>'
```

個人名、別名、メールアドレスの一部を除外対象に追加できます：

```bash
python3 scripts/privacy_audit.py --deny-term "personal-name" --deny-term "email-fragment"
```

この検査は、追跡対象のファイル名と内容、到達可能な Git パッチ、作成者とコミッターの識別情報、ユーザーディレクトリのパス、一時添付ファイル名、秘密鍵のマーカー、一般的なトークン形式を確認します。コミットの作成者とコミッターは、プロジェクトで承認された `TeshengLee` の GitHub noreply 識別情報と完全に一致する必要があります。GitHub のシークレットスキャンも、プッシュ後の追加確認として有効にしてください。

本プロジェクトは MIT License で提供されます。
