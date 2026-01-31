#!/usr/bin/env python3
"""
pwn_helpers.py — minimal CTF pwn helpers

Goal:
- Tiny primitives for exploitation scripts (pwntools-friendly but stdlib-compatible).
- Patterns you re-use: packing/unpacking, cyclic, simple TCP, parsing leaks, etc.

If pwntools is available, you can still import this and use its helpers alongside.

Examples:
  from pwn_helpers import p64, u64, cyclic, cyclic_find, hexdump
"""
from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Union


# ---------------------------
# Packing / unpacking
# ---------------------------

def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)

def u64(b: bytes) -> int:
    b = b.ljust(8, b"\x00")[:8]
    return struct.unpack("<Q", b)[0]

def p32(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)

def u32(b: bytes) -> int:
    b = b.ljust(4, b"\x00")[:4]
    return struct.unpack("<I", b)[0]

def p16(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)

def u16(b: bytes) -> int:
    b = b.ljust(2, b"\x00")[:2]
    return struct.unpack("<H", b)[0]


# ---------------------------
# Cyclic pattern (De Bruijn)
# ---------------------------

_ALPH = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def cyclic(n: int, alphabet: bytes = _ALPH) -> bytes:
    """
    Generate a cyclic pattern (De Bruijn sequence) for finding offsets.
    Compatible with typical CTF usage (not identical to pwntools but similar).
    """
    k = len(alphabet)
    a = [0] * (k * 2)
    seq = []

    def db(t: int, p: int):
        if t > 2:
            if 2 % p == 0:
                seq.extend(a[1:p+1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    out = bytes(alphabet[i] for i in seq)
    return (out * ((n // len(out)) + 1))[:n]


def cyclic_find(needle: Union[int, bytes], *, maxlen: int = 10000) -> int:
    """
    Find offset of needle in cyclic() output. needle can be bytes or int (packed little-endian).
    """
    pat = cyclic(maxlen)
    if isinstance(needle, int):
        # try 4 and 8 byte variants
        b4 = p32(needle)
        b8 = p64(needle)
        i = pat.find(b8)
        if i != -1:
            return i
        i = pat.find(b4)
        return i
    else:
        return pat.find(needle)


# ---------------------------
# Basic socket tube
# ---------------------------

 @dataclass
class Tube:
    host: str
    port: int
    timeout: float = 3.0
    sock: Optional[socket.socket] = None

    def connect(self) -> "Tube":
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        s.settimeout(self.timeout)
        self.sock = s
        return self

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            finally:
                self.sock = None

    def recv(self, n: int = 4096) -> bytes:
        assert self.sock
        return self.sock.recv(n)

    def recvuntil(self, delim: bytes, max_bytes: int = 1_000_000) -> bytes:
        assert self.sock
        buf = bytearray()
        while len(buf) < max_bytes:
            chunk = self.sock.recv(1)
            if not chunk:
                break
            buf += chunk
            if buf.endswith(delim):
                break
        return bytes(buf)

    def send(self, b: bytes) -> None:
        assert self.sock
        self.sock.sendall(b)

    def sendline(self, b: bytes) -> None:
        self.send(b + b"\n")

    def interact(self) -> None:
        """Very small interactive loop (good enough for CTF)."""
        assert self.sock
        import sys
        self.sock.settimeout(0.2)
        try:
            while True:
                try:
                    data = self.sock.recv(4096)
                    if data:
                        sys.stdout.buffer.write(data)
                        sys.stdout.buffer.flush()
                except socket.timeout:
                    pass
                if sys.stdin in select_ready():
                    line = sys.stdin.buffer.readline()
                    if not line:
                        break
                    self.send(line)
        finally:
            self.close()


def select_ready():
    import select, sys
    r, _, _ = select.select([sys.stdin], [], [], 0)
    return set(r)


# ---------------------------
# Leak parsing helpers
# ---------------------------

def parse_hex_leak(s: Union[str, bytes]) -> Optional[int]:
    """
    Extract first 0x... hex number from string/bytes.
    """
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", "ignore")
        except Exception:
            s = repr(s)
    import re
    m = re.search(r"0x[0-9a-fA-F]+", s)
    if not m:
        return None
    return int(m.group(0), 16)


def hexdump(b: bytes, width: int = 16) -> str:
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hexpart = " ".join(f"{x:02x}" for x in chunk)
        asc = "".join(chr(x) if 0x20 <= x <= 0x7E else "." for x in chunk)
        out.append(f"{i:08x}  {hexpart:<{width*3}}  {asc}")
    return "\n".join(out)
