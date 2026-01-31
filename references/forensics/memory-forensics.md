# Memory Forensics (CTF)

## Skill
- OS判定→プロファイル→プロセス/モジュール/ネットワーク/ハンドルの相関
- credential/keys/tokens の痕跡抽出（平文・構造体・残骸）
- マルウェア痕跡：インジェクション、unlinked modules、RWX領域
- 時系列再構成：ログ/アーティファクトと突き合わせて矛盾を潰す

## Quick Checklist
- pslist/pstree、dlllist/ldrmodules、netscan、handles
- stringsから先に当たり（flag形式/URL/キー）を引く

## Tools
- Volatility3、rekall(必要時)、yara、strings/grep
