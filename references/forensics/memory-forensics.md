# Memory Forensics (CTF)

## Skill
- OS判定→プロファイル→プロセス/モジュール/ネットワーク/ハンドルの相関
- credential/keys/tokens の痕跡抽出（平文・構造体・残骸）
- マルウェア痕跡：インジェクション、unlinked modules、RWX領域
- 時系列再構成：ログ/アーティファクトと突き合わせて矛盾を潰す

## Quick Checklist
1. OS/プロファイル特定: `vol -f mem.raw windows.info` or `linux.info`
2. プロセス一覧: `pslist`, `pstree` で異常プロセス発見
3. ネットワーク: `netscan` で通信先/ポート確認
4. DLL/モジュール: `dlllist`, `ldrmodules` でインジェクション検出
5. 文字列検索: `strings mem.raw | grep -i flag` で先行確認

## Volatility3 Commands
```bash
# OS情報
vol -f mem.raw windows.info

# プロセス一覧
vol -f mem.raw windows.pslist
vol -f mem.raw windows.pstree

# ネットワーク接続
vol -f mem.raw windows.netscan

# コマンドライン
vol -f mem.raw windows.cmdline

# ファイルスキャン
vol -f mem.raw windows.filescan

# プロセスダンプ
vol -f mem.raw -o ./out windows.dumpfiles --pid 1234
```

## Tools
- Volatility3 (推奨) / Volatility2 (レガシー)
- rekall (必要時)
- yara / strings / grep
- bulk_extractor

## Related
- ファイル解析 → `file-analysis.md`
- ネットワーク解析 → `network-forensics.md`
