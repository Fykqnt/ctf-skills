# Decompilation (CTF Jeopardy)

## Jeopardy典型パターン

| 問題の特徴 | 種類 | 解法 |
|-----------|------|------|
| strcmp(input, "flag") | 単純比較 | strings/Ghidraで直接読む |
| XOR/ADD変換後に比較 | 変換比較 | 逆変換スクリプト |
| 複雑な条件分岐 | 条件解析 | z3/angr |
| 独自VM実装 | VM reversing | opcode解析 |
| Anti-debug | 保護回避 | パッチ/Frida |

## Skill
- デコンパイル結果を鵜呑みにせず、型/境界/符号/桁あふれを再検証
- 重要関数同定：入力検証/暗号/比較/エンコード/VMループ
- 動的解析と往復：ブレークポイント、トレース、フックで真値を見る
- solver化：条件抽出→z3化、またはパッチ/キー抽出で短絡

## Jeopardy Workflow
```
1. strings ./binary | grep flag  # 直接埋め込みチェック
2. file ./binary  # アーキ確認
3. Ghidraでmain→入力検証関数を追跡
4. 検証ロジック理解→逆算 or solver
5. flag入力 or パッチ
```

## Quick z3 Template
```python
from z3 import *

# 例: flag[i] ^ key[i] == target[i]
flag = [BitVec(f'flag_{i}', 8) for i in range(32)]
s = Solver()

# 制約: printable ASCII
for f in flag:
    s.add(f >= 0x20, f <= 0x7e)

# 制約: 変換後の値
target = [0x12, 0x34, ...]  # Ghidraから抽出
key = [0xAB, 0xCD, ...]
for i in range(len(target)):
    s.add(flag[i] ^ key[i] == target[i])

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[f].as_long()) for f in flag)
    print(result)
```

## angr Template
```python
import angr

proj = angr.Project('./binary', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)

# success: "Correct" 出力アドレス
# fail: "Wrong" 出力アドレス
simgr.explore(find=0x401234, avoid=0x401200)

if simgr.found:
    found = simgr.found[0]
    print(found.posix.dumps(0))  # stdin
```

## Tools
- Ghidra + scripts（無料、強力）
- IDA Free（限定的だが高速）
- angr（シンボリック実行）
- z3（SMT solver）
- Frida（動的フック、アプリ/モバイル）

## Tips
1. **まずstrings**: flagが直接埋め込まれていることも
2. **main関数から追う**: エントリポイント→main→検証関数
3. **比較関数にブレーク**: strcmp, memcmpの引数を見る
4. **パッチも選択肢**: 検証をスキップしてflag表示させる
