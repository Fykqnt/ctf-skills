# XSS (CTF)

## Skill
- 反射/格納/DOMを分類→実行コンテキスト（HTML/attr/JS/CSS/URL）確定
- フィルタ回避：エンコード差、イベント、template literal、svg/mathml
- CSP/TrustedTypes/サニタイザの穴を突く（nonce/strict-dynamic等）
- 目的：cookie/CSRF/権限昇格/内部API叩き（fetch）/SSRF誘発

## Quick Checks
- 出力点でのエスケープ種類（HTML entity / JS escape / URL encode）
- innerHTML系 or setAttribute系か
- CSPヘッダを必ず見る

## Tools
- 自作ペイロード辞書、CSP evaluator的思考
- headlessブラウザ（playwright）で自動検証
