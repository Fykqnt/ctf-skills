# Modern Crypto (CTF Jeopardy)

## Jeopardy典型パターン

| 問題の特徴 | 攻撃 | 解法 |
|-----------|------|------|
| RSA, e=3, 小さいm | Low exponent | m = c^(1/3) |
| RSA, 2つの暗号文, 同じn | Common modulus | Bezout's identity |
| RSA, n が複数で共通素因数 | GCD | gcd(n1, n2) |
| RSA, e=65537, c≈n | Coppersmith | small roots |
| AES, 同じブロック繰り返し | ECB mode | ブロック入れ替え |
| AES, サーバーがエラー返す | Padding oracle | CBC復号 |
| ECDSA, 同じr値 | Nonce reuse | 秘密鍵復元 |

## Skill
- RSA：small e/d, Coppersmith系, CRT誤用, 共通mod/共通素因数, padding事故
- ECC：弱曲線/パラメータ不備、署名nonce再利用、invalid-curve
- AES：ECB痕跡、CBC padding oracle、CTR nonce再利用、GCM nonce再利用/タグ
- PRNG：seed推定、LCG/MT/XSの復元、状態漏洩
- Protocol：認証欠落、replay、KDF/nonce設計ミス、鍵合意の脆弱性

## RSA Quick Reference
```python
from gmpy2 import iroot, gcd
from Crypto.Util.number import long_to_bytes

# Low exponent (e=3)
m, _ = iroot(c, e)
print(long_to_bytes(m))

# Common modulus
# c1 = m^e1 mod n, c2 = m^e2 mod n, gcd(e1,e2)=1
# Bezout: a*e1 + b*e2 = 1
# m = c1^a * c2^b mod n

# Factorization
p = gcd(n1, n2)
q = n // p
```

## Attack Heuristics
- 「nonce/IV/seedの再利用」→最優先で疑う
- 「署名」→nonce, hash, encoding, malleability
- 「実装」→ endian/型/切り詰め/比較のタイミング/例外

## Tools
- SageMath（格子/数論）、pycryptodome、gmpy2
- z3（制約）、hashcat（補助）
- RsaCtfTool: https://github.com/RsaCtfTool/RsaCtfTool
- FactorDB: http://factordb.com/
