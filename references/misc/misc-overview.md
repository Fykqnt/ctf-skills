# Misc (CTF Jeopardy)

## Overview
他カテゴリに収まらない問題群。発想力・検索力・雑学が問われる。
Jeopardyでは必ず出題され、Easy問題が多いため確実に取りたい。

## 典型サブカテゴリ

### Encoding / Decoding
- Base64, Base32, Base85, ASCII85
- Hex, Binary, Octal
- URL encoding, HTML entities
- ROT13, ROT47
- Morse, Braille, Semaphore
- **多重エンコード**: Base64(Hex(ROT13(...)))

### Esoteric Languages
- Brainfuck: `++++[>+++++<-]>.`
- Whitespace: 空白/タブ/改行のみ
- Piet: 画像がプログラム
- JSFuck: `[][(![]+[])[+[]]...]`
- Ook!: `Ook. Ook? Ook!`

### OSINT (Open Source Intelligence)
- 画像から位置特定（Google Maps, Yandex）
- ユーザー名追跡（Sherlock, Namechk）
- メタデータ（EXIF: GPS, 機材, 日時）
- Archive.org, Wayback Machine
- SNS調査

### Steganography (軽量)
- 画像LSB: zsteg, stegsolve
- 音声: スペクトログラム（Audacity）
- テキスト: 見えない文字（U+200B等）
- ファイル結合: zipをjpgの後ろに

### QR / Barcode
- QR読み取り: zbarimg, スマホ
- 破損QR修復: マスクパターン、エラー訂正
- Data Matrix, PDF417

### PPC (Professional Programming Competition)
- アルゴリズム問題: 大量計算、最適化
- nc接続で自動応答: pwntools使用
- 時間制限あり: 効率的な実装必須

### Jail Escape
- Python sandbox: `__builtins__`, `__import__`
- Bash restricted: PATH操作, 組み込みコマンド
- フィルタバイパス: 文字制限回避

## Quick Workflow

### 1. ファイル種別特定
```bash
file mysterious_file
xxd mysterious_file | head
python3 scripts/forensics_utils.py identify mysterious_file
```

### 2. エンコード検出
```bash
python3 scripts/misc_tools.py detect-encoding data.txt

# CyberChefの「Magic」機能も有効
# https://gchq.github.io/CyberChef/
```

### 3. 多重デコード
```bash
# Base64 → Hex → ROT13 のような連鎖
python3 scripts/misc_tools.py multi-decode "..."
```

### 4. QR/バーコード
```bash
zbarimg image.png
# 破損している場合は手動修復 or QRazyBox
```

### 5. OSINT
```bash
exiftool image.jpg  # GPS座標確認
# Google画像検索/Yandex画像検索
# sherlock username  # ユーザー名追跡
```

## Tools

### Encoding
- CyberChef (ブラウザ): https://gchq.github.io/CyberChef/
- dcode.fr: https://www.dcode.fr/
- `misc_tools.py` (本リポジトリ)

### Esoteric
- https://www.dcode.fr/brainfuck-language
- https://tio.run/ (Try It Online)

### OSINT
- exiftool / Sherlock / Maltego
- Google Maps / Yandex Images

### Stego
- zsteg / stegsolve / Stegseek
- Audacity / Sonic Visualiser

### QR
- zbarimg / QRazyBox (修復)

## Jeopardy Tips

1. **まずstrings**: 隠しflagがそのまま入っていることも
2. **CyberChefのMagic**: 自動でエンコード検出
3. **複数ツール試す**: 1つで見つからなくても別ツールで発見
4. **問題名・説明文ヒント**: タイトルがヒントのことが多い
5. **ファイル拡張子を疑う**: .txt が実は画像、など

## Flag Hiding Patterns (Misc)

- ファイル末尾に追記
- EXIFメタデータ
- 見えない文字（Zero-width space）
- 白文字 on 白背景
- コメント内（HTML, PDF, PNG chunks）
- 音声の高周波/スペクトログラム
