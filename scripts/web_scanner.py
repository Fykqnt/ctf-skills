#!/usr/bin/env python3
"""
web_scanner.py — minimal CTF web recon/scanner helper

This is NOT a full vuln scanner. It's a fast assistant for:
- grabbing common endpoints
- extracting forms/params quickly
- basic reflected input tests
- basic header/CSP/tech fingerprint
- quick SSRF "does it fetch" probes (with your own callback URL)

Dependencies:
- requests (recommended). If missing, fallback to urllib (limited).
- bs4 optional (HTML parsing). If missing, uses regex heuristics.

Examples:
  python3 web_scanner.py info https://target/
  python3 web_scanner.py crawl https://target/ --depth 1
  python3 web_scanner.py reflect https://target/search?q=TEST --token "CTF123"
  python3 web_scanner.py endpoints https://target/ --wordlist ../assets/wordlists/common-web.txt
"""
from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.parse
from collections import deque
from typing import Dict, List, Set, Tuple, Optional

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from bs4 import BeautifulSoup
except Exception:  # pragma: no cover
    BeautifulSoup = None


DEFAULT_UA = "ctf-scanner/0.1"
COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/.env", "/.DS_Store",
    "/admin", "/login", "/register", "/api", "/api/v1", "/health", "/debug",
]


def http_get(url: str, *, timeout: float = 8.0, allow_redirects: bool = True, headers: Optional[Dict[str, str]] = None):
    headers = headers or {}
    headers.setdefault("User-Agent", DEFAULT_UA)
    if requests:
        r = requests.get(url, timeout=timeout, allow_redirects=allow_redirects, headers=headers)
        return r.status_code, dict(r.headers), r.text, r.url
    else:  # urllib fallback
        import urllib.request
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            return resp.status, dict(resp.headers), body, resp.geturl()


def normalize_base(url: str) -> str:
    if not re.match(r"^https?://", url):
        url = "http://" + url
    return url.rstrip("/")


def join_url(base: str, path: str) -> str:
    return urllib.parse.urljoin(base + "/", path.lstrip("/"))


def fingerprint_headers(h: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k in ["Server", "X-Powered-By", "Content-Security-Policy", "Set-Cookie", "Strict-Transport-Security"]:
        if k in h:
            out[k] = h[k]
    return out


def extract_links(html: str, base_url: str) -> List[str]:
    links: Set[str] = set()
    if BeautifulSoup:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.select("a[href]"):
            href = a.get("href", "")
            u = urllib.parse.urljoin(base_url, href)
            links.add(u)
        for f in soup.select("form[action]"):
            u = urllib.parse.urljoin(base_url, f.get("action", ""))
            links.add(u)
    else:
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html, re.I):
            links.add(urllib.parse.urljoin(base_url, m.group(1)))
        for m in re.finditer(r'action=["\']([^"\']+)["\']', html, re.I):
            links.add(urllib.parse.urljoin(base_url, m.group(1)))
    # keep only http(s)
    return [u for u in links if u.startswith("http://") or u.startswith("https://")]


def same_origin(a: str, b: str) -> bool:
    pa, pb = urllib.parse.urlparse(a), urllib.parse.urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)

def cmd_info(args: argparse.Namespace) -> None:
    base = normalize_base(args.url)
    code, headers, body, final_url = http_get(base, timeout=args.timeout)
    print(f"[+] GET {base} -> {code} ({final_url})")
    for k, v in fingerprint_headers(headers).items():
        print(f"{k}: {v}")
    print(f"len(body)={len(body)}")
    if "Content-Security-Policy" in headers:
        csp = headers["Content-Security-Policy"]
        if "unsafe-inline" in csp or "*" in csp:
            print("[!] CSP looks loose (contains unsafe-inline or wildcard)")
    if "Set-Cookie" in headers:
        sc = headers["Set-Cookie"]
        if "HttpOnly" not in sc:
            print("[!] Cookie missing HttpOnly (check all cookies manually)")
        if "Secure" not in sc and base.startswith("https://"):
            print("[!] Cookie missing Secure")
    if args.snip:
        print("\n--- snippet ---")
        print(body[:600])

def cmd_endpoints(args: argparse.Namespace) -> None:
    base = normalize_base(args.url)
    paths = list(COMMON_PATHS)
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith("/"):
                        line = "/" + line
                    paths.append(line)
    seen = set()
    for p in paths:
        if p in seen:
            continue
        seen.add(p)
        u = join_url(base, p)
        try:
            code, headers, body, final_url = http_get(u, timeout=args.timeout, allow_redirects=False)
            if code not in (404, 400):
                print(f"{code}\t{u}")
        except Exception:
            pass

def cmd_crawl(args: argparse.Namespace) -> None:
    base = normalize_base(args.url)
    q = deque([(base, 0)])
    visited: Set[str] = set()
    while q:
        u, d = q.popleft()
        if u in visited:
            continue
        visited.add(u)
        try:
            code, headers, body, final_url = http_get(u, timeout=args.timeout)
        except Exception:
            continue
        print(f"{code}\t{u}")
        if d >= args.depth:
            continue
        for v in extract_links(body, final_url):
            if same_origin(base, v) and v not in visited:
                q.append((v.split("#", 1)[0], d + 1))

def cmd_reflect(args: argparse.Namespace) -> None:
    """
    Naive reflection check: replace token in query params and see if it appears in response.
    Good first-pass to find reflected XSS candidates.
    """
    url = args.url
    token = args.token
    if token is None:
        token = "CTF_REFLECT_" + str(int(time.time()))
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        print("[!] No query parameters found. Provide a URL with ?a=1")
        return
    for k in list(qs.keys()):
        qs2 = dict(qs)
        qs2[k] = [token]
        new_q = urllib.parse.urlencode(qs2, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
        try:
            code, headers, body, final_url = http_get(new_url, timeout=args.timeout)
        except Exception as e:
            print(f"[!] request failed: {e}")
            continue
        hit = token in body
        print(f"{ 'HIT' if hit else '---' }\tparam={k}\t{code}\t{new_url}")

def cmd_ssrfprobe(args: argparse.Namespace) -> None:
    """
    Naive SSRF probe helper: set a parameter to callback URL and observe on your side.
    This tool only constructs requests; you must monitor the callback endpoint yourself.
    """
    url = args.url
    callback = args.callback
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if args.param and args.param in qs:
        targets = [args.param]
    else:
        targets = list(qs.keys())
    if not targets:
        print("[!] No query params to set. Provide ?url=...")
        return
    for k in targets:
        qs2 = dict(qs)
        qs2[k] = [callback]
        new_q = urllib.parse.urlencode(qs2, doseq=True)
        new_url = urllib.parse.urlunparse(parsed._replace(query=new_q))
        try:
            code, headers, body, final_url = http_get(new_url, timeout=args.timeout)
            print(f"{code}\tparam={k}\t{new_url}")
        except Exception as e:
            print(f"[!] {k} failed: {e}")

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Minimal CTF web helper")
    p.add_argument("--timeout", type=float, default=8.0, help="request timeout seconds")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("info", help="fetch base URL and print useful headers")
    sp.add_argument("url")
    sp.add_argument("--snip", action="store_true", help="print body snippet")
    sp.set_defaults(fn=cmd_info)

    sp = sub.add_parser("endpoints", help="check common endpoints (and optional wordlist)")
    sp.add_argument("url")
    sp.add_argument("--wordlist", help="newline-separated paths")
    sp.set_defaults(fn=cmd_endpoints)

    sp = sub.add_parser("crawl", help="simple same-origin crawl")
    sp.add_argument("url")
    sp.add_argument("--depth", type=int, default=1)
    sp.set_defaults(fn=cmd_crawl)

    sp = sub.add_parser("reflect", help="naive reflected-parameter check")
    sp.add_argument("url", help="URL with query params")
    sp.add_argument("--token", help="token to inject")
    sp.set_defaults(fn=cmd_reflect)

    sp = sub.add_parser("ssrfprobe", help="set param(s) to callback URL")
    sp.add_argument("url", help="URL with query params (e.g. ?url=...)")
    sp.add_argument("--callback", required=True, help="your callback URL")
    sp.add_argument("--param", help="specific param to set (default: all)")
    sp.set_defaults(fn=cmd_ssrfprobe)

    return p

def main() -> None:
    p = build_parser()
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
