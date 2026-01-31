# SKILL.md

このリポジトリはCTF特化。目的は「最短で解く」「再現可能に解く」「次回もっと速く解く」。
ここに書くスキルは **実戦で手が勝手に動くレベル** を想定。

## Core Mindset
- 問題分類→最短ルート推定→検証→自動化→確証（PoC/Exploit/Writeup）
- CTF問題の精度を最優先（特にforensics・pwn）
- 失敗の切り分け：入力・前提・環境・観測点・制約（時間/計算量/権限）

## Operating Loop
1. Recon: 何が出ているか（入出力/エラー/プロトコル/暗号要素/権限境界）
2. Hypothesis: 典型パターンを当てる（分類器のように）
3. Proof: 最小PoCで成立確認
4. Exploit: 安定化（環境依存排除・自動化）
5. Extract: flag取得→副作用確認→ログ/証跡整理

## Domain Skills (Summary)
- Crypto: 数学的性質/実装欠陥/プロトコル破綻の見抜き、Sage/pyで即検証
- Web: 入力点探索→エスケープ/境界/SSRF経路→権限昇格の連鎖
- Pwn: アーキ/ABI/保護機構を前提にROP/heapで安定化、遠隔運用を想定
- Reverse: 静的/動的を高速往復、難読化やVM系も「観測点」から崩す
- Forensics: 「痕跡の整合性」を崩さず復元・相関、時系列再構成が得意
- Network: PCAP/プロトコル/暗号化通信の異常点を抽出、再送/改竄も可能
- Programming: 速度重視のスクリプト、exploit/solverを即席で安全に書く

## Tooling Baseline
- Python / pwntools / requests / z3 / Sage / angr / Ghidra / IDA(代替可) / Frida
- Wireshark / tshark / tcpdump / scapy
- binutils / gdb-peda(or gef) / strace / ltrace
- volatility / sleuthkit / yara / exiftool / foremost / strings

## Quality Bar
- 速度：手動→半自動→全自動（最低でも再実行1コマンド）
- 安定：ランダム性・時刻・ASLR差分・ネットワーク遅延に強い
- 記録：解法の決定点（何を見て何を確信したか）を短く残す
