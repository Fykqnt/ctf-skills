# SQLi (CTF)

## Skill
- Entry探索：params/body/json/header/cookie、型とエスケープ境界の把握
- Error/Union/Boolean/Time-based を状況で切替
- DB特有：MySQL/Postgres/SQLite/MSSQL の関数・メタデータ参照
- WAF回避：コメント/大小/演算子分割/エンコード/キーワード分割
- 目的：情報漏洩→認証回避→RCE（UDF, xp_cmdshell等）を連鎖

## Minimal Checklist
- `' " )` で構文崩れるか
- UNION列数/型合わせ
- blindなら比較軸（len/ascii/substr）を最短化

## Tools
- 手動payload + 自作スキャナ（速度優先）
- sqlmapは最後（環境依存を避ける）
