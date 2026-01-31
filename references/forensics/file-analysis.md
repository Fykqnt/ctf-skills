# File Analysis (CTF)

## Skill
- ファイル種別特定：magic/header/footer/コンテナ（zip/png/pdf/elf/pcap/pcapng）
- メタデータ/隠し領域：exif, chunks, streams, slack space
- 破損修復：ヘッダ整形、chunk長修正、再構成
- ステガ：LSB/パレット/周波数/圧縮差、辞書・鍵探索の最短化

## Workflow
1. `forensics_utils.py identify <file>` でmagic/hash/entropy確認
2. extract: binwalk/foremost/手動カービング
3. normalize: 破損修復、デコード
4. diff/scan: 差分検出、パターン検索

## Quick Commands
```bash
# ファイル特定
python3 forensics_utils.py identify suspicious.bin

# エントロピー（暗号化/圧縮判定）
python3 forensics_utils.py entropy suspicious.bin

# 文字列抽出
python3 forensics_utils.py strings suspicious.bin --min 6

# PNGカービング
python3 forensics_utils.py carve-png disk.img --out ./out

# PCAPの場合 → network_analyzer.py へ
python3 network_analyzer.py stats capture.pcap
```

## Tools
- file / binwalk / xxd / strings / exiftool / foremost
- zsteg / pngcheck / pdfid
- `forensics_utils.py` (本リポジトリ)

## Related
- PCAP解析 → `network-forensics.md`
- メモリ解析 → `memory-forensics.md`
