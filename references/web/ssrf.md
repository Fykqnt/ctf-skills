# SSRF (CTF)

## Skill
- URLパーサ差異：scheme, userinfo, @, #, //, \, unicode, ipv6, oct/dec表記
- 到達性：メタデータ(169.254.169.254) / localhost / internal DNS
- ブロック回避：redirect chain, DNS rebinding(条件次第), gopher(稀), dict/file(稀)
- 目的：内部管理画面→認証バイパス→鍵/トークン取得→RCE

## Fast Workflow
- 反射内容で「実際にHTTPしてるか」確認（タイミング/ログ）
- allowlist/denylist判定→パース差分で突破
- 取れた情報（IAM, env, kube, redis等）から横展開

## Tools
- burp + collaborator相当の観測
- 自前のredirector / DNSログ
