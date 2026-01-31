#!/usr/bin/env python3
"""
forensics_utils.py — minimal CTF forensics utilities

Focus:
- Quick file carving helpers
- Hashing / entropy / strings
- Magic header detection
- PCAP quick analysis (for deep analysis, use network_analyzer.py)

Stdlib only for core functions. Combine with external tools when needed.

For full PCAP/network analysis with pyshark/tshark/scapy:
  → Use network_analyzer.py instead

Examples:
  python3 forensics_utils.py identify suspicious.bin
  python3 forensics_utils.py strings suspicious.bin --min 6 | head
  python3 forensics_utils.py entropy suspicious.bin
  python3 forensics_utils.py carve-png disk.img --out ./out
  python3 forensics_utils.py pcap-quick capture.pcap --pattern "flag"
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import math
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Iterable


MAGIC = [
    (b"\x7fELF", "ELF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPG"),
    (b"%PDF-", "PDF"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"OggS", "OGG"),
    (b"RIFF", "RIFF/WAV/AVI"),
    # PCAP formats
    (b"\xd4\xc3\xb2\xa1", "PCAP (little-endian)"),
    (b"\xa1\xb2\xc3\xd4", "PCAP (big-endian)"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG"),
    # Archives
    (b"\x1f\x8b", "GZIP"),
    (b"BZ", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
    # Executables
    (b"MZ", "PE/DOS"),
    (b"\xca\xfe\xba\xbe", "Mach-O (fat)"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64 (le)"),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def printable_strings(data: bytes, min_len: int = 4) -> List[str]:
    pattern = rb"[ -~]{{{min_len},}}" % min_len
    return [m.group(0).decode("ascii", "ignore") for m in re.finditer(pattern, data)]

def identify(data: bytes) -> List[str]:
    hits = []
    for sig, name in MAGIC:
        if data.startswith(sig):
            hits.append(name)
    # also check common embedded markers
    if b"ftyp" in data[:64]:
        hits.append("MP4/ISO-BMFF(?)")
    return hits

def carve_png(blob: bytes) -> List[bytes]:
    """
    Very naive PNG carver: find PNG header and IEND chunk.
    Good enough for CTF disk dumps where PNGs are intact.
    """
    out = []
    sig = b"\x89PNG\r\n\x1a\n"
    i = 0
    while True:
        j = blob.find(sig, i)
        if j == -1:
            break
        # find IEND
        k = blob.find(b"IEND", j)
        if k == -1:
            break
        # IEND chunk is 12 bytes: length(4)+type(4)+crc(4)
        end = k + 8  # points after type + crc start, but we need include crc
        # Ensure we include the CRC bytes if present
        end = min(len(blob), k + 8 + 4)
        # attempt to extend to full 12 bytes before IEND? Actually: [len][IEND][crc]
        # Since we searched "IEND" inside chunk type, grab 8+4 bytes after that.
        out.append(blob[j:end])
        i = end
    return out

def cmd_identify(args: argparse.Namespace) -> None:
    p = Path(args.path)
    data = p.read_bytes()
    hits = identify(data[:4096])
    print(f"path: {p}")
    print(f"size: {p.stat().st_size}")
    print(f"sha256: {sha256_file(p)}")
    print(f"md5: {md5_file(p)}")
    print(f"entropy: {shannon_entropy(data):.4f}")
    print(f"magic: {', '.join(hits) if hits else 'unknown'}")

def cmd_strings(args: argparse.Namespace) -> None:
    data = Path(args.path).read_bytes()
    for s in printable_strings(data, min_len=args.min):
        print(s)

def cmd_entropy(args: argparse.Namespace) -> None:
    data = Path(args.path).read_bytes()
    print(f"{shannon_entropy(data):.6f}")

def cmd_grep(args: argparse.Namespace) -> None:
    """
    Raw grep in binary (good for quick PCAP token searches).
    """
    data = Path(args.path).read_bytes()
    needle = args.pattern.encode()
    idx = 0
    hits = 0
    while True:
        j = data.find(needle, idx)
        if j == -1:
            break
        start = max(0, j - args.context)
        end = min(len(data), j + len(needle) + args.context)
        snippet = data[start:end]
        print(f" @{j} {binascii.hexlify(snippet[:64]).decode()} ...")
        try:
            print(snippet.decode("utf-8", "ignore"))
        except Exception:
            pass
        print("-" * 60)
        hits += 1
        idx = j + 1
        if hits >= args.limit:
            break

def cmd_carve_png(args: argparse.Namespace) -> None:
    blob = Path(args.path).read_bytes()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    images = carve_png(blob)
    print(f"found={len(images)}")
    for i, b in enumerate(images):
        outpath = outdir / f"carved_{i:03d}.png"
        outpath.write_bytes(b)
        print(f"wrote {outpath} ({len(b)} bytes)")


def cmd_pcap_quick(args: argparse.Namespace) -> None:
    """
    Quick PCAP triage: identify, basic stats, pattern search.
    For deep analysis, use network_analyzer.py instead.
    """
    p = Path(args.path)
    data = p.read_bytes()

    # Identify PCAP type
    hits = identify(data[:64])
    pcap_type = None
    for h in hits:
        if "PCAP" in h:
            pcap_type = h
            break

    if not pcap_type:
        print(f"[!] File does not appear to be a PCAP: {hits}")
        print("[!] For full analysis, use: python3 network_analyzer.py stats <file>")
        return

    print(f"[+] File: {p.name}")
    print(f"[+] Type: {pcap_type}")
    print(f"[+] Size: {p.stat().st_size} bytes")
    print(f"[+] SHA256: {sha256_file(p)}")

    # Pattern search in raw bytes
    if args.pattern:
        needle = args.pattern.encode()
        idx = 0
        hits_count = 0
        print(f"\n[*] Searching for '{args.pattern}'...")
        while True:
            j = data.find(needle, idx)
            if j == -1:
                break
            context_start = max(0, j - 20)
            context_end = min(len(data), j + len(needle) + 40)
            snippet = data[context_start:context_end]
            try:
                snippet_str = snippet.decode("utf-8", "ignore")
            except:
                snippet_str = binascii.hexlify(snippet[:40]).decode()
            print(f"  @{j}: ...{snippet_str}...")
            hits_count += 1
            idx = j + 1
            if hits_count >= 10:
                print(f"  ... (showing first 10 hits)")
                break
        print(f"[+] Total hits: {hits_count}+")

    print("\n[*] For detailed protocol analysis, use:")
    print(f"    python3 network_analyzer.py stats {args.path}")
    print(f"    python3 network_analyzer.py http {args.path}")
    print(f"    python3 network_analyzer.py dns {args.path} --detect-exfil")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Minimal CTF forensics helper (stdlib)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("identify", help="hash/entropy/magic of a file")
    sp.add_argument("path")
    sp.set_defaults(fn=cmd_identify)

    sp = sub.add_parser("strings", help="extract printable strings")
    sp.add_argument("path")
    sp.add_argument("--min", type=int, default=4)
    sp.set_defaults(fn=cmd_strings)

    sp = sub.add_parser("entropy", help="compute Shannon entropy")
    sp.add_argument("path")
    sp.set_defaults(fn=cmd_entropy)

    sp = sub.add_parser("grep", help="binary grep with context")
    sp.add_argument("path")
    sp.add_argument("--pattern", required=True)
    sp.add_argument("--context", type=int, default=48)
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(fn=cmd_grep)

    sp = sub.add_parser("carve-png", help="naive PNG carver")
    sp.add_argument("path")
    sp.add_argument("--out", required=True)
    sp.set_defaults(fn=cmd_carve_png)

    sp = sub.add_parser("pcap-quick", help="quick PCAP triage (use network_analyzer.py for deep analysis)")
    sp.add_argument("path")
    sp.add_argument("--pattern", help="pattern to search in raw bytes")
    sp.set_defaults(fn=cmd_pcap_quick)

    return p

def main() -> None:
    args = build_parser().parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
