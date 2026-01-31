# Classical Ciphers (CTF Jeopardy)

## Jeopardy典型パターン

| 問題の特徴 | 暗号種類 | 解法 |
|-----------|---------|------|
| アルファベットのみ、短い | Caesar/ROT | ROT全探索 |
| 周期的なパターン | Vigenere | Kasiski→鍵長推定 |
| 記号/数字含む、意味不明 | Substitution | 頻度分析 |
| 2文字ペア | Playfair | キーワード推定 |
| ジグザグ配置 | Rail Fence | 段数ブルート |
| a,b係数ヒント | Affine | ax+b mod 26 |

## Skill
- 頻出：Caesar/ROT/Vigenere/Substitution/Playfair/rail fence/affine
- 文字頻度/NG-gramスコアで復号を自動評価
- 既知平文・鍵長推定（Kasiski, IOC）を即適用
- 多層（例：base系→古典暗号→zip）の剥がし順最適化

## Quick Checks
1. アルファベット限定か、記号/数字の扱いは？
2. 規則性（周期/置換）と統計（頻度/偏り）を見る
3. 「復号結果が読める」ことをスコア化して探索
4. **flag format既知なら、その部分から逆算**

## Quick Commands
```bash
# ROT全探索
python3 scripts/misc_tools.py rot-all "Guvf vf n frperg"

# Caesar with crypto_tools
python3 scripts/crypto_tools.py caesar --s "..." --bruteforce

# Vigenere鍵長推定（XORと同じ原理）
python3 scripts/crypto_tools.py rkxorkey --s "..."

# 頻度分析
python3 scripts/crypto_tools.py freq --s "..."
```

## Online Tools
- dcode.fr: https://www.dcode.fr/
- quipqiup (Substitution): https://quipqiup.com/
- CyberChef: https://gchq.github.io/CyberChef/

## Tools
- `crypto_tools.py` / `misc_tools.py` (本リポジトリ)
- Python（freq, hillclimb, simulated annealing）
- wordlist/辞書、quadgram統計
