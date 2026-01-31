# File Analysis (CTF)

## Skill
- ファイル種別特定：magic/header/footer/コンテナ（zip/png/pdf/elf/pcap）
- メタデータ/隠し領域：exif, chunks, streams, slack space
- 破損修復：ヘッダ整形、chunk長修正、再構成
- ステガ：LSB/パレット/周波数/圧縮差、辞書・鍵探索の最短化

## Workflow
- 1) identify 2) extract 3) normalize 4) diff/scan
- 「怪しいバイト列」を最小化して仮説検証

## Tools
- file/binwalk/xxd/strings/exiftool/foremost
- zsteg/pngcheck/pdfid
