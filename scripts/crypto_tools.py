#!/usr/bin/env python3
"""
crypto_tools.py — minimal CTF crypto utilities (fast, composable)

Philosophy:
- Small functions you can import into a solver.
- Also usable as a quick CLI for one-off transforms.
- No heavy dependencies (pure stdlib). Bring Sage/z3 when needed in your solver.

Examples:
  python3 crypto_tools.py xor --hex "deadbeef" --key "1337"
  python3 crypto_tools.py b64d --s "SGVsbG8="
  python3 crypto_tools.py freq --s "LIPPSASVPH"
  python3 crypto_tools.py cribxor --hex "..." --crib "flag{"
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import itertools
import math
import re
from collections import Counter
from typing import Iterable, List, Tuple, Dict, Optional


# ---------------------------
# Byte / encoding helpers
# ---------------------------

def to_bytes(s: str, *, assume_hex: bool = False) -> bytes:
    """Best-effort string->bytes for CTF: supports 0x.. hex, \x.., base64:, or utf-8."""
    s = s.strip()
    if assume_hex:
        return unhex(s)
    if s.startswith("0x"):
        return unhex(s[2:])
    if s.startswith("base64:"):
        return base64.b64decode(s.split(":", 1)[1])
    # Accept "\x41\x42" style
    if r"\x" in s:
        try:
            return codecs_decode_hex_escapes(s)
        except Exception:
            pass
    # If it looks like hex
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try:
            return unhex(s)
        except Exception:
            pass
    return s.encode("utf-8", "ignore")


def codecs_decode_hex_escapes(s: str) -> bytes:
    # Interpret literal backslash-x sequences.
    out = bytearray()
    i = 0
    while i < len(s):
        if i + 3 < len(s) and s[i] == "\" and s[i+1] == "x":
            out.append(int(s[i+2:i+4], 16))
            i += 4
        else:
            out.extend(s[i].encode())
            i += 1
    return bytes(out)


def unhex(h: str) -> bytes:
    h = re.sub(r"\s+", "", h)
    return binascii.unhexlify(h)

def hexify(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def int_from(b: bytes, endian: str = "big") -> int:
    return int.from_bytes(b, endian, signed=False)

def int_to(n: int, length: Optional[int] = None, endian: str = "big") -> bytes:
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, endian, signed=False)

# ---------------------------
# XOR and scoring
# ---------------------------

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, itertools.cycle(key)))

ENGLISH_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
    'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
    'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
    'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
    'z': 0.00074, ' ': 0.13000,
}

def english_score(b: bytes) -> float:
    """Higher is better. Simple chi-square-ish heuristic with penalties."""
    if not b:
        return float("-inf")
    # Penalize non-printable heavily
    nonprint = sum(1 for x in b if x < 0x09 or (0x0E <= x < 0x20) or x == 0x7F)
    if nonprint > 0:
        return -50.0 * nonprint
    s = b.decode("latin-1", "ignore").lower()
    counts = Counter(s)
    score = 0.0
    for ch, exp in ENGLISH_FREQ.items():
        obs = counts.get(ch, 0) / max(1, len(s))
        score -= (obs - exp) ** 2 / (exp + 1e-9)
    # Reward common printable range
    score += sum(1 for x in b if 0x20 <= x <= 0x7E) / len(b)
    return score


def break_single_byte_xor(ct: bytes, topk: int = 5) -> List[Tuple[float, int, bytes]]:
    res = []
    for k in range(256):
        pt = xor_bytes(ct, bytes([k]))
        res.append((english_score(pt), k, pt))
    res.sort(reverse=True, key=lambda t: t[0])
    return res[:topk]

def guess_repeating_xor_keylen(ct: bytes, min_k: int = 2, max_k: int = 40, topk: int = 5) -> List[Tuple[float, int]]:
    """Estimate repeating-key XOR key length using normalized Hamming distance."""
    def hdist(a: bytes, b: bytes) -> int:
        return sum((x ^ y).bit_count() for x, y in zip(a, b))
    scores = []
    for k in range(min_k, max_k + 1):
        blocks = [ct[i:i+k] for i in range(0, min(len(ct), k*8), k)]
        if len(blocks) < 4 or min(map(len, blocks)) < k:
            continue
        d = 0.0
        pairs = 0
        for i in range(len(blocks)-1):
            d += hdist(blocks[i], blocks[i+1]) / k
            pairs += 1
        scores.append((-(d / max(1, pairs)), k))  # higher better
    scores.sort(reverse=True)
    return scores[:topk]

def break_repeating_xor(ct: bytes, keylen: int) -> bytes:
    """Recover repeating-key XOR key by single-byte XOR per column."""
    key = bytearray()
    for i in range(keylen):
        col = ct[i::keylen]
        best = break_single_byte_xor(col, topk=1)[0]
        key.append(best[1])
    return bytes(key)

# ---------------------------
# Classical helpers
# ---------------------------

def caesar(s: str, shift: int) -> str:
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c)-97 + shift) % 26 + 97))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c)-65 + shift) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)

def freq(s: str) -> List[Tuple[str, int]]:
    c = Counter([ch.lower() for ch in s if ch.isalpha()])
    return c.most_common()

# ---------------------------
# Hash / MAC helpers
# ---------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# ---------------------------
# Crib dragging (XOR)
# ---------------------------

def crib_drag_xor(ct: bytes, crib: bytes) -> List[Tuple[int, bytes]]:
    """
    Returns positions where crib XOR produces printable-ish plaintext.
    Useful for OTP reuse / two-time pad style attacks (use in solver).
    """
    hits = []
    for i in range(0, len(ct) - len(crib) + 1):
        slice_ = ct[i:i+len(crib)]
        x = xor_bytes(slice_, crib)
        if all(0x20 <= b <= 0x7E for b in x):
            hits.append((i, x))
    return hits


# ---------------------------
# CLI
# ---------------------------

def _cmd_xor(args: argparse.Namespace) -> None:
    data = unhex(args.hex) if args.hex else to_bytes(args.s)
    key = to_bytes(args.key, assume_hex=args.key_hex)
    out = xor_bytes(data, key)
    if args.out_hex:
        print(hexify(out))
    else:
        try:
            print(out.decode("utf-8"))
        except Exception:
            print(out)

def _cmd_b64d(args: argparse.Namespace) -> None:
    b = b64d(args.s)
    if args.out_hex:
        print(hexify(b))
    else:
        try:
            print(b.decode("utf-8"))
        except Exception:
            print(b)

def _cmd_b64e(args: argparse.Namespace) -> None:
    data = unhex(args.hex) if args.hex else to_bytes(args.s)
    print(b64e(data))

def _cmd_freq(args: argparse.Namespace) -> None:
    for ch, n in freq(args.s):
        print(f"{ch}\t{n}")

def _cmd_sbxor(args: argparse.Namespace) -> None:
    ct = unhex(args.hex) if args.hex else to_bytes(args.s)
    for score, k, pt in break_single_byte_xor(ct, topk=args.topk):
        preview = pt[:120]
        try:
            preview_s = preview.decode("utf-8", "ignore")
        except Exception:
            preview_s = str(preview)
        print(f"score={score:.3f}\tkey=0x{k:02x}\t{preview_s}")

def _cmd_rkxorkey(args: argparse.Namespace) -> None:
    ct = unhex(args.hex) if args.hex else to_bytes(args.s)
    for score, k in guess_repeating_xor_keylen(ct, args.min_k, args.max_k, args.topk):
        print(f"score={score:.3f}\tkeylen={k}")

def _cmd_rkxorbreak(args: argparse.Namespace) -> None:
    ct = unhex(args.hex) if args.hex else to_bytes(args.s)
    key = break_repeating_xor(ct, args.keylen)
    print(f"key_hex={hexify(key)}")
    pt = xor_bytes(ct, key)
    try:
        print(pt.decode("utf-8"))
    except Exception:
        print(pt)

def _cmd_caesar(args: argparse.Namespace) -> None:
    if args.bruteforce:
        for sh in range(26):
            print(f"{sh:02d}: {caesar(args.s, sh)}")
    else:
        print(caesar(args.s, args.shift))

def _cmd_cribxor(args: argparse.Namespace) -> None:
    ct = unhex(args.hex)
    crib = args.crib.encode()
    hits = crib_drag_xor(ct, crib)
    for pos, x in hits[: args.topk]:
        try:
            xs = x.decode("utf-8", "ignore")
        except Exception:
            xs = str(x)
        print(f"pos={pos}\t{x.hex()}\t{xs}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="CTF crypto helper utilities (stdlib only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("xor", help="XOR data with repeating key")
    sp.add_argument("--hex", help="hex input")
    sp.add_argument("--s", help="string input")
    sp.add_argument("--key", required=True, help="key (string or hex)")
    sp.add_argument("--key-hex", action="store_true", help="interpret key as hex")
    sp.add_argument("--out-hex", action="store_true", help="print hex output")
    sp.set_defaults(fn=_cmd_xor)

    sp = sub.add_parser("b64d", help="base64 decode")
    sp.add_argument("--s", required=True)
    sp.add_argument("--out-hex", action="store_true")
    sp.set_defaults(fn=_cmd_b64d)

    sp = sub.add_parser("b64e", help="base64 encode")
    sp.add_argument("--hex")
    sp.add_argument("--s")
    sp.set_defaults(fn=_cmd_b64e)

    sp = sub.add_parser("freq", help="simple letter frequency")
    sp.add_argument("--s", required=True)
    sp.set_defaults(fn=_cmd_freq)

    sp = sub.add_parser("sbxor", help="break single-byte XOR (english scoring)")
    sp.add_argument("--hex")
    sp.add_argument("--s")
    sp.add_argument("--topk", type=int, default=5)
    sp.set_defaults(fn=_cmd_sbxor)

    sp = sub.add_parser("rkxorkey", help="guess repeating-key XOR key length")
    sp.add_argument("--hex")
    sp.add_argument("--s")
    sp.add_argument("--min-k", type=int, default=2)
    sp.add_argument("--max-k", type=int, default=40)
    sp.add_argument("--topk", type=int, default=5)
    sp.set_defaults(fn=_cmd_rkxorkey)

    sp = sub.add_parser("rkxorbreak", help="break repeating-key XOR with keylen")
    sp.add_argument("--hex")
    sp.add_argument("--s")
    sp.add_argument("--keylen", type=int, required=True)
    sp.set_defaults(fn=_cmd_rkxorbreak)

    sp = sub.add_parser("caesar", help="caesar shift / bruteforce")
    sp.add_argument("--s", required=True)
    sp.add_argument("--shift", type=int, default=0)
    sp.add_argument("--bruteforce", action="store_true")
    sp.set_defaults(fn=_cmd_caesar)

    sp = sub.add_parser("cribxor", help="crib-drag on XOR ciphertext (hex) using ascii crib")
    sp.add_argument("--hex", required=True)
    sp.add_argument("--crib", required=True)
    sp.add_argument("--topk", type=int, default=20)
    sp.set_defaults(fn=_cmd_cribxor)

    return p

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
