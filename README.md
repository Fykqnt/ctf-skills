# CTF Skills

Jeopardy形式CTF特化のAIスキルセット。Claude Code / Cursorで使用可能。

## インストール

以下のディレクトリに配置:

```
~/.claude/skills/ctf-skills/
├── SKILL.md           # スキル定義（メインエントリポイント）
├── references/        # カテゴリ別リファレンス
│   ├── crypto/        # 暗号系
│   ├── forensics/     # フォレンジック
│   ├── misc/          # Misc問題
│   ├── pwn/           # バイナリexploit
│   ├── reverse/       # リバースエンジニアリング
│   └── web/           # Web脆弱性
├── scripts/           # 解析ツール群
└── README.md
```

または Cursor の場合:
```
~/.cursor/skills/ctf-skills/
```

## 概要

### SKILL.md
- CTFの基本戦略とマインドセット
- カテゴリ別の初動手順
- ツールの使い方クイックリファレンス

### references/
各カテゴリの詳細な技術リファレンス:

| ディレクトリ | 内容 |
|-------------|------|
| `crypto/` | 古典暗号、現代暗号、ハッシュ関数 |
| `forensics/` | ファイル解析、メモリ/ネットワークフォレンジック |
| `misc/` | PPC、Jail Escape、OSINT等 |
| `pwn/` | Buffer Overflow、Heap、ROP |
| `reverse/` | アセンブリ、デコンパイル |
| `web/` | SQLi、XSS、SSRF |

### scripts/
CTF解析用Pythonツール:

| スクリプト | 用途 |
|-----------|------|
| `crypto_tools.py` | XOR解析、RSA計算等 |
| `forensics_utils.py` | ファイル識別、エントロピー解析 |
| `misc_tools.py` | エンコード検出、QR処理 |
| `network_analyzer.py` | PCAP解析、HTTP/DNS抽出 |
| `pwn_helpers.py` | オフセット計算、ペイロード生成 |
| `web_scanner.py` | 初期スキャン、エンドポイント列挙 |

## 使用例

```bash
# Cryptoの初動
python3 scripts/crypto_tools.py sbxor --hex "..."

# Networkの解析
python3 scripts/network_analyzer.py stats capture.pcap

# Forensicsのファイル識別
python3 scripts/forensics_utils.py identify suspicious_file
```

## 対象カテゴリ

Crypto / Web / Pwn / Reverse / Forensics / Network / Misc
