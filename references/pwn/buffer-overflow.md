# Buffer Overflow (CTF)

## Skill
- アーキ/ABI：x86_64 SysV / x86 / ARM の呼出規約を即適用
- 保護機構：NX/PIE/Canary/RELRO/ASLR を見て方針決定
- Leak→ret2libc/ROP→安定化（remote差分に強い）
- 入力経路：argv/stdin/socket、改行/NULL/長さ制限の扱い最適化

## Quick Checklist
- crash制御（RIP/EIP）→offset確定
- leak可能性（puts/printf/format/partial read）
- GOT/PLT/one_gadget/stack pivot の候補列挙

## Tools
- pwntools, gdb(gef), checksec, ROPgadget, one_gadget
