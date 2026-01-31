# Classical Ciphers (CTF)

## Skill
- 頻出：Caesar/ROT/Vigenere/Substitution/Playfair/rail fence/affine
- 文字頻度/NG-gramスコアで復号を自動評価
- 既知平文・鍵長推定（Kasiski, IOC）を即適用
- 多層（例：base系→古典暗号→zip）の剥がし順最適化

## Quick Checks
- アルファベット限定か、記号/数字の扱いは？
- 規則性（周期/置換）と統計（頻度/偏り）を見る
- 「復号結果が読める」ことをスコア化して探索

## Tools
- Python（freq, hillclimb, simulated annealing）
- wordlist/辞書、quadgram統計
