#!/usr/bin/env python3
"""
misc_tools.py — CTF Jeopardy Misc utilities

Focus:
- Encoding detection and multi-layer decoding
- Esoteric language detection
- Hidden character detection
- Quick flag pattern search

Stdlib only for core functions.

Examples:
  python3 misc_tools.py detect-encoding data.txt
  python3 misc_tools.py multi-decode "SGVsbG8gV29ybGQ="
  python3 misc_tools.py hidden-chars text.txt
  python3 misc_tools.py find-flag file.bin
  python3 misc_tools.py rot-all "Uryyb Jbeyq"
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import string
from pathlib import Path
from typing import List, Optional, Tuple, Dict


# =============================================================================
# Encoding Detection & Decoding
# =============================================================================

def is_base64(s: str) -> bool:
    """Check if string looks like valid base64."""
    s = s.strip()
    if len(s) < 4:
        return False
    if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
        return False
    if len(s) % 4 != 0:
        return False
    try:
        base64.b64decode(s)
        return True
    except Exception:
        return False


def is_base32(s: str) -> bool:
    """Check if string looks like valid base32."""
    s = s.strip().upper()
    if len(s) < 8:
        return False
    if not re.match(r'^[A-Z2-7]*={0,6}$', s):
        return False
    try:
        base64.b32decode(s)
        return True
    except Exception:
        return False


def is_hex(s: str) -> bool:
    """Check if string is valid hex."""
    s = s.strip()
    if len(s) < 2 or len(s) % 2 != 0:
        return False
    return bool(re.match(r'^[0-9a-fA-F]+$', s))


def is_binary(s: str) -> bool:
    """Check if string is binary (0s and 1s)."""
    s = s.replace(' ', '').strip()
    if len(s) < 8 or len(s) % 8 != 0:
        return False
    return bool(re.match(r'^[01]+$', s))


def is_octal(s: str) -> bool:
    """Check if string looks like octal ASCII."""
    parts = s.strip().split()
    if len(parts) < 2:
        return False
    try:
        for p in parts:
            val = int(p, 8)
            if val < 0 or val > 127:
                return False
        return True
    except ValueError:
        return False


def is_decimal(s: str) -> bool:
    """Check if string looks like decimal ASCII."""
    parts = s.strip().split()
    if len(parts) < 2:
        return False
    try:
        for p in parts:
            val = int(p)
            if val < 0 or val > 127:
                return False
        return True
    except ValueError:
        return False


def decode_base64(s: str) -> bytes:
    return base64.b64decode(s.strip())


def decode_base32(s: str) -> bytes:
    return base64.b32decode(s.strip().upper())


def decode_hex(s: str) -> bytes:
    return binascii.unhexlify(s.strip())


def decode_binary(s: str) -> bytes:
    s = s.replace(' ', '').strip()
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))


def decode_octal(s: str) -> bytes:
    return bytes(int(p, 8) for p in s.strip().split())


def decode_decimal(s: str) -> bytes:
    return bytes(int(p) for p in s.strip().split())


def detect_encoding(s: str) -> List[Tuple[str, bytes]]:
    """
    Detect possible encodings and return decoded results.
    Returns list of (encoding_name, decoded_bytes).
    """
    results = []
    s = s.strip()

    if is_base64(s):
        try:
            decoded = decode_base64(s)
            results.append(("base64", decoded))
        except Exception:
            pass

    if is_base32(s):
        try:
            decoded = decode_base32(s)
            results.append(("base32", decoded))
        except Exception:
            pass

    if is_hex(s):
        try:
            decoded = decode_hex(s)
            results.append(("hex", decoded))
        except Exception:
            pass

    if is_binary(s):
        try:
            decoded = decode_binary(s)
            results.append(("binary", decoded))
        except Exception:
            pass

    if is_octal(s):
        try:
            decoded = decode_octal(s)
            results.append(("octal", decoded))
        except Exception:
            pass

    if is_decimal(s):
        try:
            decoded = decode_decimal(s)
            results.append(("decimal", decoded))
        except Exception:
            pass

    return results


def multi_decode(s: str, max_depth: int = 10) -> List[Tuple[List[str], str]]:
    """
    Recursively decode through multiple layers.
    Returns list of (encoding_chain, final_result).
    """
    results = []
    
    def recurse(current: str, chain: List[str], depth: int):
        if depth >= max_depth:
            return
        
        encodings = detect_encoding(current)
        if not encodings:
            # No more decodable layers
            if chain:
                results.append((chain.copy(), current))
            return
        
        for enc_name, decoded in encodings:
            try:
                decoded_str = decoded.decode('utf-8', 'ignore')
                if decoded_str and all(c in string.printable for c in decoded_str[:50]):
                    new_chain = chain + [enc_name]
                    results.append((new_chain, decoded_str))
                    recurse(decoded_str, new_chain, depth + 1)
            except Exception:
                pass
    
    recurse(s, [], 0)
    return results


# =============================================================================
# ROT/Caesar
# =============================================================================

def rot_n(s: str, n: int) -> str:
    """Apply ROT-N to string."""
    result = []
    for c in s:
        if 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + n) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + n) % 26 + ord('A')))
        else:
            result.append(c)
    return ''.join(result)


def rot_all(s: str) -> List[Tuple[int, str]]:
    """Apply all ROT values (0-25)."""
    return [(n, rot_n(s, n)) for n in range(26)]


def rot47(s: str) -> str:
    """Apply ROT47 (printable ASCII rotation)."""
    result = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            result.append(chr(33 + (o - 33 + 47) % 94))
        else:
            result.append(c)
    return ''.join(result)


# =============================================================================
# Hidden Characters
# =============================================================================

HIDDEN_CHARS = {
    '\u200b': 'ZWSP (Zero Width Space)',
    '\u200c': 'ZWNJ (Zero Width Non-Joiner)',
    '\u200d': 'ZWJ (Zero Width Joiner)',
    '\u200e': 'LRM (Left-to-Right Mark)',
    '\u200f': 'RLM (Right-to-Left Mark)',
    '\u2060': 'WJ (Word Joiner)',
    '\ufeff': 'BOM (Byte Order Mark)',
    '\u00a0': 'NBSP (Non-Breaking Space)',
    '\u2000': 'EN QUAD',
    '\u2001': 'EM QUAD',
    '\u2002': 'EN SPACE',
    '\u2003': 'EM SPACE',
    '\u2004': 'THREE-PER-EM SPACE',
    '\u2005': 'FOUR-PER-EM SPACE',
    '\u2006': 'SIX-PER-EM SPACE',
    '\u2007': 'FIGURE SPACE',
    '\u2008': 'PUNCTUATION SPACE',
    '\u2009': 'THIN SPACE',
    '\u200a': 'HAIR SPACE',
    '\u202f': 'NNBSP (Narrow No-Break Space)',
    '\u205f': 'MMSP (Medium Mathematical Space)',
    '\u3000': 'IDEOGRAPHIC SPACE',
}


def detect_hidden_chars(s: str) -> List[Tuple[int, str, str]]:
    """
    Find hidden/invisible characters in string.
    Returns list of (position, character, description).
    """
    results = []
    for i, c in enumerate(s):
        if c in HIDDEN_CHARS:
            results.append((i, repr(c), HIDDEN_CHARS[c]))
        elif not c.isprintable() and c not in '\n\r\t':
            results.append((i, repr(c), f'Non-printable: U+{ord(c):04X}'))
    return results


def extract_hidden_binary(s: str) -> Optional[str]:
    """
    Extract binary data encoded in hidden characters.
    ZWSP=0, other hidden char=1 pattern.
    """
    binary = ''
    for c in s:
        if c == '\u200b':  # ZWSP = 0
            binary += '0'
        elif c in HIDDEN_CHARS:  # Other hidden = 1
            binary += '1'
    
    if len(binary) >= 8 and len(binary) % 8 == 0:
        try:
            result = decode_binary(binary)
            return result.decode('utf-8', 'ignore')
        except Exception:
            pass
    return None


# =============================================================================
# Esoteric Language Detection
# =============================================================================

def detect_esoteric(s: str) -> List[str]:
    """Detect possible esoteric programming languages."""
    results = []
    s = s.strip()
    
    # Brainfuck: only contains ><+-.,[]
    bf_chars = set('><+-.,[]')
    if s and all(c in bf_chars or c.isspace() for c in s):
        if any(c in s for c in '><+-'):
            results.append('Brainfuck')
    
    # Whitespace: only space, tab, newline
    ws_chars = set(' \t\n')
    if s and all(c in ws_chars for c in s) and len(s) > 10:
        results.append('Whitespace')
    
    # Ook!
    if 'Ook' in s and re.search(r'Ook[.!?]', s):
        results.append('Ook!')
    
    # JSFuck: only []()!+
    jsfuck_chars = set('[]()!+')
    if s and all(c in jsfuck_chars for c in s) and len(s) > 20:
        results.append('JSFuck')
    
    # Malbolge: specific character set
    if s and all(32 <= ord(c) <= 126 for c in s):
        malbolge_chars = set("ji*p</teleport\'o;=@sym{}?>!~|xw")
        if len(set(s) & malbolge_chars) > 5:
            results.append('Malbolge (maybe)')
    
    return results


# =============================================================================
# Flag Pattern Search
# =============================================================================

FLAG_PATTERNS = [
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'[a-zA-Z0-9_]+CTF\{[^}]+\}',
    r'[a-zA-Z0-9_]+\{[^}]+\}',
]


def find_flags(data: bytes) -> List[str]:
    """Search for flag patterns in binary data."""
    flags = []
    
    # Try as UTF-8
    try:
        text = data.decode('utf-8', 'ignore')
        for pattern in FLAG_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                if m.group() not in flags:
                    flags.append(m.group())
    except Exception:
        pass
    
    # Try as Latin-1
    try:
        text = data.decode('latin-1', 'ignore')
        for pattern in FLAG_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                if m.group() not in flags:
                    flags.append(m.group())
    except Exception:
        pass
    
    return flags


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_detect_encoding(args: argparse.Namespace) -> None:
    """Detect encoding of input."""
    if args.file:
        data = Path(args.file).read_text(encoding='utf-8', errors='ignore')
    else:
        data = args.input
    
    results = detect_encoding(data)
    if not results:
        print("[!] No standard encoding detected")
        print("[*] Try: CyberChef Magic, dcode.fr")
        return
    
    print(f"[*] Detected {len(results)} possible encoding(s):")
    for enc_name, decoded in results:
        try:
            decoded_str = decoded.decode('utf-8', 'ignore')
            preview = decoded_str[:100] + '...' if len(decoded_str) > 100 else decoded_str
            print(f"\n  [{enc_name}]")
            print(f"  {preview}")
        except Exception:
            print(f"\n  [{enc_name}] (binary)")
            print(f"  {decoded[:50].hex()}")


def cmd_multi_decode(args: argparse.Namespace) -> None:
    """Recursively decode through multiple layers."""
    if args.file:
        data = Path(args.file).read_text(encoding='utf-8', errors='ignore')
    else:
        data = args.input
    
    results = multi_decode(data, max_depth=args.depth)
    if not results:
        print("[!] No decodable layers found")
        return
    
    print(f"[*] Found {len(results)} decoding chain(s):")
    for chain, final in results:
        chain_str = ' → '.join(chain)
        print(f"\n  Chain: {chain_str}")
        preview = final[:200] + '...' if len(final) > 200 else final
        print(f"  Result: {preview}")


def cmd_hidden_chars(args: argparse.Namespace) -> None:
    """Detect hidden characters in file."""
    data = Path(args.file).read_text(encoding='utf-8', errors='ignore')
    
    hidden = detect_hidden_chars(data)
    if not hidden:
        print("[*] No hidden characters found")
        return
    
    print(f"[*] Found {len(hidden)} hidden character(s):")
    for pos, char, desc in hidden[:20]:  # Limit output
        print(f"  @{pos}: {char} - {desc}")
    
    if len(hidden) > 20:
        print(f"  ... and {len(hidden) - 20} more")
    
    # Try to extract binary
    binary_data = extract_hidden_binary(data)
    if binary_data:
        print(f"\n[*] Possible hidden binary message:")
        print(f"  {binary_data}")


def cmd_rot_all(args: argparse.Namespace) -> None:
    """Apply all ROT values."""
    if args.file:
        data = Path(args.file).read_text(encoding='utf-8', errors='ignore')
    else:
        data = args.input
    
    print("[*] ROT-N results:")
    for n, result in rot_all(data):
        preview = result[:80]
        print(f"  ROT{n:02d}: {preview}")
    
    print(f"\n[*] ROT47: {rot47(data)[:80]}")


def cmd_find_flag(args: argparse.Namespace) -> None:
    """Search for flag patterns in file."""
    data = Path(args.file).read_bytes()
    
    flags = find_flags(data)
    if not flags:
        print("[!] No flag patterns found")
        print("[*] Try: strings file | grep -i flag")
        return
    
    print(f"[*] Found {len(flags)} flag candidate(s):")
    for flag in flags:
        print(f"  {flag}")


def cmd_esoteric(args: argparse.Namespace) -> None:
    """Detect esoteric programming language."""
    if args.file:
        data = Path(args.file).read_text(encoding='utf-8', errors='ignore')
    else:
        data = args.input
    
    results = detect_esoteric(data)
    if not results:
        print("[!] No esoteric language detected")
        return
    
    print(f"[*] Possible language(s): {', '.join(results)}")
    print("\n[*] Online interpreters:")
    print("  - https://tio.run/")
    print("  - https://www.dcode.fr/")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CTF Misc utilities for Jeopardy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s detect-encoding "SGVsbG8gV29ybGQ="
  %(prog)s multi-decode "U0dWc2JHOGdWMjl5YkdRPQ=="
  %(prog)s hidden-chars suspicious.txt
  %(prog)s rot-all "Uryyb Jbeyq"
  %(prog)s find-flag challenge.bin
  %(prog)s esoteric code.bf
        """
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    
    # detect-encoding
    sp = sub.add_parser("detect-encoding", help="Detect encoding type")
    sp.add_argument("input", nargs='?', help="Input string")
    sp.add_argument("--file", "-f", help="Input file")
    sp.set_defaults(fn=cmd_detect_encoding)
    
    # multi-decode
    sp = sub.add_parser("multi-decode", help="Recursively decode multiple layers")
    sp.add_argument("input", nargs='?', help="Input string")
    sp.add_argument("--file", "-f", help="Input file")
    sp.add_argument("--depth", type=int, default=10, help="Max decode depth")
    sp.set_defaults(fn=cmd_multi_decode)
    
    # hidden-chars
    sp = sub.add_parser("hidden-chars", help="Detect hidden/invisible characters")
    sp.add_argument("file", help="Input file")
    sp.set_defaults(fn=cmd_hidden_chars)
    
    # rot-all
    sp = sub.add_parser("rot-all", help="Apply all ROT values (0-25) + ROT47")
    sp.add_argument("input", nargs='?', help="Input string")
    sp.add_argument("--file", "-f", help="Input file")
    sp.set_defaults(fn=cmd_rot_all)
    
    # find-flag
    sp = sub.add_parser("find-flag", help="Search for flag patterns")
    sp.add_argument("file", help="Input file")
    sp.set_defaults(fn=cmd_find_flag)
    
    # esoteric
    sp = sub.add_parser("esoteric", help="Detect esoteric programming language")
    sp.add_argument("input", nargs='?', help="Input string")
    sp.add_argument("--file", "-f", help="Input file")
    sp.set_defaults(fn=cmd_esoteric)
    
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
