# ROP Chains (CTF)

## Skill
- gadget探索→最短チェーン設計（set regs / syscall / call）
- SROP（rt_sigreturn）や ret2csu、stack pivot を状況で使い分け
- libc特定：leak→symbols→remoteの差分吸収（LibcDB相当）
- I/O安定化：read再呼び出し、ROPでステージング

## Heuristics
- 最初に「leak」「pivot」「write primitive」を確保
- constraints（badchars/align/stack size）を先に固定

## Tools
- pwntools ROP, ropper, libc-database
