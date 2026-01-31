# Hash Functions (CTF)

## Skill
- 長さ拡張（Merkle–Damgård）：MD5/SHA1/SHA256系のprefix MAC破壊
- 衝突：MD5 chosen-prefix/既知衝突の活用（条件付き）
- 部分一致：ハッシュのトランケーション、弱いsalt/pepper
- 構造：XOR/加算/ローテーション混在の自作hashを差分解析

## Fast Workflow
- hashの種類推定（長さ/charset/フォーマット/識別子）
- salt有無・位置（prefix/suffix）を推定
- 1) length extension 2) brute 3) 構造解析 の順で当てる

## Tools
- hashpump / length-extension実装
- hashcat/john（最小限に）
- Python差分テスト（bit-level）
