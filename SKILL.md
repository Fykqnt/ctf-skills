# SKILL.md

**Jeopardy形式CTF特化スキルセット**

目的は「最短で解く」「再現可能に解く」「次回もっと速く解く」。
ここに書くスキルは **実戦で手が勝手に動くレベル** を想定。

---

## Jeopardy CTF Overview

### 形式
- カテゴリ別に問題が出題（Crypto / Web / Pwn / Reverse / Forensics / Misc / Network）
- 各問題を解いてflagを提出 → ポイント獲得
- 制限時間内にチーム合計ポイントを最大化

### 勝利のための原則
1. **First Blood狙い**: 早解きボーナス/動的スコアで高得点
2. **得意分野で確実に取る**: 全カテゴリ満遍なくより、深い専門性
3. **詰まったら切り替え**: 1問に固執せず、他問題→戻る戦略
4. **flag format確認**: 提出前に形式確認（`flag{...}`, `CTF{...}`, etc.）
5. **Writeup即時記録**: 解法メモは解いた直後に（後で思い出せない）

### 時間配分目安
| 難易度 | 目安時間 | 判断 |
|--------|----------|------|
| Easy | 〜30min | 30分で糸口なし→スキップ |
| Medium | 〜2h | 1時間で進展なし→一旦離れる |
| Hard | 〜4h+ | チーム相談、並行作業 |

---

## Core Mindset

- 問題分類→最短ルート推定→検証→flag抽出
- **「何を聞かれているか」を最初に特定**（カテゴリ名だけで判断しない）
- 失敗の切り分け：入力・前提・環境・観測点・制約（時間/計算量/権限）

## Operating Loop (Jeopardy)

```
1. READ: 問題文/添付ファイル/接続先を全て確認
2. CLASSIFY: カテゴリ内の典型パターンに当てはめる
3. TRIAGE: 簡単そう？時間かかりそう？→優先度決定
4. SOLVE: 最小PoCで仮説検証→flag抽出
5. SUBMIT: flag format確認→提出→Writeupメモ
```

---

## Category Skills

### Crypto
**得点源になりやすい。数学的直感＋実装力。**

- 古典暗号: Caesar/Vigenere/Substitution → 頻度分析、既知平文
- XOR系: Single-byte/Repeating-key → スコアリング自動化
- RSA: small e, common factor, Coppersmith, padding oracle
- AES: ECB detection, CBC padding oracle, CTR nonce reuse
- 署名: nonce reuse (ECDSA), hash length extension

**初動**:
```bash
# 暗号文の特徴を見る（hex? base64? 長さ?）
# XORなら
python3 scripts/crypto_tools.py sbxor --hex "..."
# RSAならn, e, cの関係を確認
```

### Web
**入力点→脆弱性→flag読み出しの連鎖を構築。**

- SQLi: Error/Union/Blind → DB内のflagテーブル
- XSS: Reflected/Stored → admin cookie奪取 → flag表示
- SSRF: 内部サービス→metadata/admin endpoint
- SSTI: テンプレートエンジン特定→RCE→flag読み出し
- Path Traversal / LFI: `/etc/passwd`確認→flag.txt
- Deserialization: 言語特定→gadget chain→RCE

**初動**:
```bash
python3 scripts/web_scanner.py info https://target/
python3 scripts/web_scanner.py endpoints https://target/
# robots.txt, .git/, backup files確認
```

### Pwn
**保護機構を見て攻撃手法を決定。**

- Buffer Overflow: NX off → shellcode, NX on → ROP
- Format String: leak → GOT overwrite
- Heap: UAF, double free, tcache poisoning
- 保護機構確認: `checksec ./binary`

**初動**:
```bash
checksec ./binary
file ./binary
strings ./binary | grep -i flag
# gdbでクラッシュポイント特定
```

### Reverse
**静的解析で構造把握→動的で値確認。**

- 入力検証ロジック: 文字列比較、暗号化後比較
- VM/難読化: opcode解析、トレースで挙動把握
- Anti-debug: ptrace検出、時間チェック回避
- Keygenme: 検証ロジック逆算

**初動**:
```bash
file ./binary
strings ./binary | grep -E "flag|correct|wrong"
# Ghidra/IDAでmain関数から追跡
```

### Forensics
**ファイルの中に隠されたflagを発掘。**

- ファイルカービング: binwalk, foremost
- ステガノグラフィ: LSB, palette, EXIF
- メモリダンプ: Volatility3でプロセス/ファイル抽出
- ディスクイメージ: sleuthkit, autopsy
- PCAP: → Network参照

**初動**:
```bash
file suspicious_file
python3 scripts/forensics_utils.py identify suspicious_file
binwalk suspicious_file
strings suspicious_file | grep -i flag
exiftool suspicious_file  # 画像の場合
```

### Network
**通信の中からflagを抽出。**

- HTTP: リクエスト/レスポンスボディ、ヘッダ内
- DNS: exfiltration（長いサブドメイン、TXTレコード）
- TCP/UDP: ストリーム再構成、カスタムプロトコル
- TLS: SSLKEYLOG復号、証明書情報

**初動**:
```bash
python3 scripts/network_analyzer.py stats capture.pcap
python3 scripts/network_analyzer.py search capture.pcap --pattern "flag"
python3 scripts/network_analyzer.py http capture.pcap
python3 scripts/network_analyzer.py dns capture.pcap --detect-exfil
```

### Misc
**他カテゴリに収まらない問題。発想力勝負。**

- OSINT: 画像から位置特定、ユーザー名追跡
- PPC (Programming): アルゴリズム問題、大量計算
- Jail Escape: Python/Bash sandbox脱出
- Esoteric: Brainfuck, Piet, Whitespace
- QR/Barcode: 破損修復、多重エンコード
- Steganography (軽量): LSB, 音声スペクトログラム

**初動**:
```bash
# ファイル種別確認
file mysterious_file
# エンコーディング確認
python3 scripts/misc_tools.py detect-encoding data.txt
# QRコード
zbarimg qr.png
```

---

## Tooling Baseline

### Core (全カテゴリ共通)
```
Python3 / pwntools / requests / z3 / SageMath
CyberChef (ブラウザ) — エンコード変換の定番
```

### Crypto
```
SageMath / gmpy2 / pycryptodome / hashcat(補助)
crypto_tools.py (本リポジトリ)
```

### Web
```
Burp Suite / curl / requests / sqlmap(最終手段)
web_scanner.py (本リポジトリ)
```

### Pwn
```
pwntools / gdb + pwndbg/gef / checksec
ROPgadget / one_gadget / libc-database
```

### Reverse
```
Ghidra / IDA Free / radare2 / Binary Ninja
Frida / angr / z3
```

### Forensics
```
binwalk / foremost / exiftool / strings
Volatility3 / sleuthkit / Autopsy
forensics_utils.py (本リポジトリ)
```

### Network
```
Wireshark / tshark / pyshark / scapy
tcpdump / NetworkMiner
network_analyzer.py (本リポジトリ)
```

### Misc
```
zbarimg (QR) / Audacity (音声) / GIMP/Stegsolve (画像)
dcode.fr / CyberChef
misc_tools.py (本リポジトリ)
```

---

## Quick Reference (Jeopardy初動)

### 全問題共通
```bash
# 添付ファイルの確認
file *
strings * | grep -iE "flag|ctf"

# エントロピー確認（暗号化/圧縮判定）
python3 scripts/forensics_utils.py entropy file
```

### Crypto
```bash
# Base64/Hex判定して変換
echo "..." | base64 -d
echo "..." | xxd -r -p

# XOR解析
python3 scripts/crypto_tools.py sbxor --hex "..."
python3 scripts/crypto_tools.py rkxorkey --hex "..."
```

### Web
```bash
# 初期スキャン
curl -I https://target/
python3 scripts/web_scanner.py endpoints https://target/

# SQLi確認
curl "https://target/search?q='"
```

### Pwn
```bash
checksec ./binary
python3 -c "print('A'*100)" | ./binary
# オフセット特定
python3 -c "from pwn import *; print(cyclic(200))" | ./binary
```

### Reverse
```bash
strings ./binary | head -50
objdump -d ./binary | head -100
# Ghidra: File → Import → Analyze
```

### Forensics
```bash
python3 scripts/forensics_utils.py identify file
binwalk -e file
foremost -i file -o out/
```

### Network
```bash
python3 scripts/network_analyzer.py stats file.pcap
python3 scripts/network_analyzer.py search file.pcap --pattern "flag"
tshark -r file.pcap -z follow,tcp,ascii,0 -q
```

### Misc
```bash
# エンコード検出
python3 scripts/misc_tools.py detect-encoding file

# QR読み取り
zbarimg image.png

# 音声スペクトログラム
# → Audacity / Sonic Visualiser
```

---

## Flag Patterns

よくあるflag形式（提出前に確認）:
```
flag{...}
FLAG{...}
CTF{...}
CONTEST_NAME{...}
picoCTF{...}
HTB{...}
```

flag抽出の最終確認:
```bash
# 全ファイルからflag候補を検索
grep -rioE "[a-zA-Z0-9_]+\{[^}]+\}" .
```

---

## Quality Bar

- **速度**: 典型問題は30分以内、Easyは即解き
- **正確性**: flag format間違いで失点しない
- **記録**: 解法の要点を3行で残す（後でWriteup化）
- **切り替え**: 詰まったら離れる勇気
