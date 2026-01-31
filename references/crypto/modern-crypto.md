# Modern Crypto (CTF)

## Skill
- RSA：small e/d, Coppersmith系, CRT誤用, 共通mod/共通素因数, padding事故
- ECC：弱曲線/パラメータ不備、署名nonce再利用、invalid-curve
- AES：ECB痕跡、CBC padding oracle、CTR nonce再利用、GCM nonce再利用/タグ
- PRNG：seed推定、LCG/MT/XSの復元、状態漏洩
- Protocol：認証欠落、replay、KDF/nonce設計ミス、鍵合意の脆弱性

## Attack Heuristics
- 「nonce/IV/seedの再利用」→最優先で疑う
- 「署名」→nonce, hash, encoding, malleability
- 「実装」→ endian/型/切り詰め/比較のタイミング/例外

## Tools
- SageMath（格子/数論）、pycryptodome、gmpy2
- z3（制約）、hashcat（補助）
