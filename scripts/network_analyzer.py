#!/usr/bin/env python3
"""
network_analyzer.py — CTF network/PCAP analysis toolkit

Features:
- pyshark-based protocol analysis (HTTP, DNS, TCP streams, TLS)
- tshark CLI wrapper for fast extraction
- scapy integration for low-level packet manipulation
- CTF-specific: anomaly detection, flag pattern search, data exfil detection

Dependencies:
- pyshark (pip install pyshark) — requires tshark installed
- scapy (pip install scapy)
- tshark (apt install tshark / brew install wireshark)

Examples:
  python3 network_analyzer.py http capture.pcap
  python3 network_analyzer.py dns capture.pcap --detect-exfil
  python3 network_analyzer.py streams capture.pcap --stream 0
  python3 network_analyzer.py stats capture.pcap
  python3 network_analyzer.py search capture.pcap --pattern "flag{"
  python3 network_analyzer.py tls capture.pcap --keylog sslkey.log
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

# Optional imports with graceful degradation
try:
    import pyshark
    HAS_PYSHARK = True
except ImportError:
    HAS_PYSHARK = False
    pyshark = None

try:
    from scapy.all import rdpcap, TCP, UDP, IP, DNS, DNSQR, DNSRR, Raw, wrpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def check_tshark() -> bool:
    """Check if tshark is available."""
    return shutil.which("tshark") is not None


def require_pyshark():
    if not HAS_PYSHARK:
        print("[!] pyshark not installed. Run: pip install pyshark", file=sys.stderr)
        print("[!] Also requires tshark: apt install tshark / brew install wireshark", file=sys.stderr)
        sys.exit(1)


def require_scapy():
    if not HAS_SCAPY:
        print("[!] scapy not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(1)


# =============================================================================
# tshark CLI Wrapper (fast, powerful)
# =============================================================================

def tshark_extract_fields(pcap: str, display_filter: str, fields: List[str],
                          keylog: Optional[str] = None) -> List[Dict[str, str]]:
    """
    Extract fields using tshark -T fields.
    Returns list of dicts with field names as keys.
    """
    if not check_tshark():
        print("[!] tshark not found in PATH", file=sys.stderr)
        return []

    cmd = ["tshark", "-r", pcap, "-T", "fields"]
    for f in fields:
        cmd.extend(["-e", f])
    if display_filter:
        cmd.extend(["-Y", display_filter])
    if keylog:
        cmd.extend(["-o", f"tls.keylog_file:{keylog}"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        lines = result.stdout.strip().split("\n")
        out = []
        for line in lines:
            if not line.strip():
                continue
            parts = line.split("\t")
            row = {}
            for i, f in enumerate(fields):
                row[f] = parts[i] if i < len(parts) else ""
            out.append(row)
        return out
    except Exception as e:
        print(f"[!] tshark error: {e}", file=sys.stderr)
        return []


def tshark_follow_stream(pcap: str, proto: str = "tcp", stream_id: int = 0,
                         mode: str = "ascii") -> str:
    """
    Follow a TCP/UDP stream using tshark -z follow.
    mode: ascii, hex, raw
    """
    if not check_tshark():
        return ""

    cmd = ["tshark", "-r", pcap, "-z", f"follow,{proto},{mode},{stream_id}", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        print(f"[!] tshark follow error: {e}", file=sys.stderr)
        return ""


def tshark_conversations(pcap: str, proto: str = "tcp") -> str:
    """Get conversation statistics."""
    if not check_tshark():
        return ""

    cmd = ["tshark", "-r", pcap, "-z", f"conv,{proto}", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        print(f"[!] tshark conv error: {e}", file=sys.stderr)
        return ""


def tshark_protocol_hierarchy(pcap: str) -> str:
    """Get protocol hierarchy statistics."""
    if not check_tshark():
        return ""

    cmd = ["tshark", "-r", pcap, "-z", "io,phs", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout
    except Exception as e:
        print(f"[!] tshark phs error: {e}", file=sys.stderr)
        return ""


# =============================================================================
# pyshark-based Analysis (structured, convenient)
# =============================================================================

def pyshark_http_extract(pcap: str, keylog: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extract HTTP requests/responses with bodies.
    Returns list of HTTP transaction details.
    """
    require_pyshark()

    override_prefs = {}
    if keylog:
        override_prefs["tls.keylog_file"] = keylog

    results = []
    try:
        cap = pyshark.FileCapture(
            pcap,
            display_filter="http",
            override_prefs=override_prefs if override_prefs else None
        )
        for pkt in cap:
            entry = {"frame": int(pkt.frame_info.number)}
            if hasattr(pkt, "http"):
                http = pkt.http
                # Request
                if hasattr(http, "request_method"):
                    entry["type"] = "request"
                    entry["method"] = http.request_method
                    entry["uri"] = getattr(http, "request_uri", "")
                    entry["host"] = getattr(http, "host", "")
                    entry["user_agent"] = getattr(http, "user_agent", "")
                # Response
                elif hasattr(http, "response_code"):
                    entry["type"] = "response"
                    entry["code"] = http.response_code
                    entry["content_type"] = getattr(http, "content_type", "")

                # Body data (if present)
                if hasattr(http, "file_data"):
                    entry["body"] = http.file_data
                elif hasattr(http, "data"):
                    entry["body"] = http.data

                results.append(entry)
        cap.close()
    except Exception as e:
        print(f"[!] pyshark HTTP error: {e}", file=sys.stderr)

    return results


def pyshark_dns_extract(pcap: str) -> List[Dict[str, Any]]:
    """
    Extract DNS queries and responses.
    Useful for detecting DNS exfiltration.
    """
    require_pyshark()

    results = []
    try:
        cap = pyshark.FileCapture(pcap, display_filter="dns")
        for pkt in cap:
            if hasattr(pkt, "dns"):
                dns = pkt.dns
                entry = {
                    "frame": int(pkt.frame_info.number),
                    "src": pkt.ip.src if hasattr(pkt, "ip") else "",
                    "dst": pkt.ip.dst if hasattr(pkt, "ip") else "",
                }
                # Query
                if hasattr(dns, "qry_name"):
                    entry["qry_name"] = dns.qry_name
                    entry["qry_type"] = getattr(dns, "qry_type", "")
                # Response
                if hasattr(dns, "a"):
                    entry["a_record"] = dns.a
                if hasattr(dns, "aaaa"):
                    entry["aaaa_record"] = dns.aaaa
                if hasattr(dns, "txt"):
                    entry["txt_record"] = dns.txt
                if hasattr(dns, "cname"):
                    entry["cname"] = dns.cname

                results.append(entry)
        cap.close()
    except Exception as e:
        print(f"[!] pyshark DNS error: {e}", file=sys.stderr)

    return results


def detect_dns_exfiltration(dns_records: List[Dict[str, Any]],
                            subdomain_threshold: int = 30,
                            entropy_threshold: float = 3.5) -> List[Dict[str, Any]]:
    """
    Detect potential DNS exfiltration patterns.
    - Long subdomains
    - High entropy in subdomain
    - Base64/hex-like patterns
    """
    import math

    def shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = Counter(s.lower())
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def looks_encoded(s: str) -> bool:
        # Check for base64-ish or hex-ish patterns
        if re.match(r"^[A-Za-z0-9+/=]+$", s) and len(s) > 20:
            return True
        if re.match(r"^[0-9a-fA-F]+$", s) and len(s) > 20:
            return True
        return False

    suspicious = []
    for rec in dns_records:
        if "qry_name" not in rec:
            continue
        qname = rec["qry_name"]
        # Get leftmost label (subdomain)
        parts = qname.split(".")
        if len(parts) < 2:
            continue
        subdomain = parts[0]

        reasons = []
        if len(subdomain) > subdomain_threshold:
            reasons.append(f"long_subdomain({len(subdomain)})")
        ent = shannon_entropy(subdomain)
        if ent > entropy_threshold:
            reasons.append(f"high_entropy({ent:.2f})")
        if looks_encoded(subdomain):
            reasons.append("encoded_pattern")

        if reasons:
            rec["exfil_indicators"] = reasons
            suspicious.append(rec)

    return suspicious


def pyshark_tls_info(pcap: str, keylog: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Extract TLS handshake information.
    If keylog provided, can decrypt traffic.
    """
    require_pyshark()

    override_prefs = {}
    if keylog:
        override_prefs["tls.keylog_file"] = keylog

    results = []
    try:
        cap = pyshark.FileCapture(
            pcap,
            display_filter="tls.handshake",
            override_prefs=override_prefs if override_prefs else None
        )
        for pkt in cap:
            if hasattr(pkt, "tls"):
                tls = pkt.tls
                entry = {"frame": int(pkt.frame_info.number)}
                if hasattr(tls, "handshake_type"):
                    entry["handshake_type"] = tls.handshake_type
                if hasattr(tls, "handshake_extensions_server_name"):
                    entry["sni"] = tls.handshake_extensions_server_name
                if hasattr(tls, "handshake_ja3"):
                    entry["ja3"] = tls.handshake_ja3
                if hasattr(tls, "handshake_ja3s"):
                    entry["ja3s"] = tls.handshake_ja3s
                if hasattr(tls, "handshake_ciphersuite"):
                    entry["cipher"] = tls.handshake_ciphersuite
                results.append(entry)
        cap.close()
    except Exception as e:
        print(f"[!] pyshark TLS error: {e}", file=sys.stderr)

    return results


# =============================================================================
# scapy-based Analysis (low-level, flexible)
# =============================================================================

def scapy_tcp_streams(pcap: str) -> Dict[Tuple, List[bytes]]:
    """
    Reconstruct TCP streams using scapy.
    Returns dict: (src_ip, src_port, dst_ip, dst_port) -> [payloads]
    """
    require_scapy()

    streams: Dict[Tuple, List[bytes]] = defaultdict(list)
    try:
        packets = rdpcap(pcap)
        for pkt in packets:
            if TCP in pkt and Raw in pkt:
                ip = pkt[IP]
                tcp = pkt[TCP]
                key = (ip.src, tcp.sport, ip.dst, tcp.dport)
                streams[key].append(bytes(pkt[Raw].load))
    except Exception as e:
        print(f"[!] scapy TCP stream error: {e}", file=sys.stderr)

    return streams


def scapy_extract_payloads(pcap: str, port: Optional[int] = None) -> List[bytes]:
    """
    Extract raw payloads from packets (TCP/UDP).
    Optionally filter by port.
    """
    require_scapy()

    payloads = []
    try:
        packets = rdpcap(pcap)
        for pkt in packets:
            if Raw in pkt:
                if port is not None:
                    if TCP in pkt:
                        if pkt[TCP].sport != port and pkt[TCP].dport != port:
                            continue
                    elif UDP in pkt:
                        if pkt[UDP].sport != port and pkt[UDP].dport != port:
                            continue
                payloads.append(bytes(pkt[Raw].load))
    except Exception as e:
        print(f"[!] scapy payload error: {e}", file=sys.stderr)

    return payloads


# =============================================================================
# CTF-specific Utilities
# =============================================================================

def search_pattern_in_pcap(pcap: str, pattern: str, use_regex: bool = False) -> List[Dict[str, Any]]:
    """
    Search for pattern (string or regex) in packet payloads.
    Useful for finding flags.
    """
    require_scapy()

    results = []
    try:
        packets = rdpcap(pcap)
        for i, pkt in enumerate(packets):
            if Raw in pkt:
                data = bytes(pkt[Raw].load)
                try:
                    text = data.decode("utf-8", "ignore")
                except:
                    text = data.decode("latin-1", "ignore")

                match = None
                if use_regex:
                    m = re.search(pattern, text)
                    if m:
                        match = m.group(0)
                else:
                    if pattern in text:
                        match = pattern

                if match:
                    entry = {
                        "packet": i + 1,
                        "match": match,
                        "context": text[:200] if len(text) > 200 else text,
                    }
                    if IP in pkt:
                        entry["src"] = pkt[IP].src
                        entry["dst"] = pkt[IP].dst
                    results.append(entry)
    except Exception as e:
        print(f"[!] search error: {e}", file=sys.stderr)

    return results


def detect_encoded_data(pcap: str) -> List[Dict[str, Any]]:
    """
    Detect base64/hex encoded data in payloads.
    """
    require_scapy()

    results = []
    try:
        packets = rdpcap(pcap)
        for i, pkt in enumerate(packets):
            if Raw in pkt:
                data = bytes(pkt[Raw].load)
                try:
                    text = data.decode("utf-8", "ignore")
                except:
                    continue

                # Base64 pattern
                b64_matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
                for m in b64_matches:
                    try:
                        decoded = base64.b64decode(m)
                        if len(decoded) > 4 and all(0x20 <= b <= 0x7e or b in (0x0a, 0x0d, 0x09) for b in decoded[:20]):
                            results.append({
                                "packet": i + 1,
                                "type": "base64",
                                "encoded": m[:50] + "..." if len(m) > 50 else m,
                                "decoded_preview": decoded[:100].decode("utf-8", "ignore"),
                            })
                    except:
                        pass

                # Hex pattern
                hex_matches = re.findall(r"[0-9a-fA-F]{40,}", text)
                for m in hex_matches:
                    try:
                        decoded = binascii.unhexlify(m)
                        if len(decoded) > 4:
                            results.append({
                                "packet": i + 1,
                                "type": "hex",
                                "encoded": m[:50] + "..." if len(m) > 50 else m,
                                "decoded_preview": decoded[:50],
                            })
                    except:
                        pass
    except Exception as e:
        print(f"[!] encoded detection error: {e}", file=sys.stderr)

    return results


def pcap_summary(pcap: str) -> Dict[str, Any]:
    """
    Quick summary of PCAP for initial triage.
    """
    summary: Dict[str, Any] = {"file": pcap}

    # Protocol hierarchy
    phs = tshark_protocol_hierarchy(pcap)
    summary["protocol_hierarchy"] = phs

    # Conversations
    conv = tshark_conversations(pcap, "tcp")
    summary["tcp_conversations"] = conv

    # Quick stats
    if HAS_SCAPY:
        try:
            packets = rdpcap(pcap)
            summary["total_packets"] = len(packets)

            protocols = Counter()
            for pkt in packets:
                if TCP in pkt:
                    protocols["TCP"] += 1
                if UDP in pkt:
                    protocols["UDP"] += 1
                if DNS in pkt:
                    protocols["DNS"] += 1
            summary["protocol_counts"] = dict(protocols)
        except Exception as e:
            summary["scapy_error"] = str(e)

    return summary


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_http(args: argparse.Namespace) -> None:
    """Extract HTTP traffic."""
    results = pyshark_http_extract(args.pcap, args.keylog)
    for r in results:
        print(f"[{r.get('type', 'unknown')}] frame={r['frame']}")
        if r.get("type") == "request":
            print(f"  {r.get('method', '')} {r.get('uri', '')} Host: {r.get('host', '')}")
        elif r.get("type") == "response":
            print(f"  {r.get('code', '')} {r.get('content_type', '')}")
        if "body" in r:
            body = r["body"]
            print(f"  body({len(body)} chars): {body[:200]}{'...' if len(body) > 200 else ''}")
        print()


def cmd_dns(args: argparse.Namespace) -> None:
    """Extract DNS traffic and optionally detect exfiltration."""
    results = pyshark_dns_extract(args.pcap)

    if args.detect_exfil:
        suspicious = detect_dns_exfiltration(results)
        print(f"[*] Found {len(suspicious)} suspicious DNS queries:")
        for s in suspicious:
            print(f"  {s.get('qry_name', '')} -> {s.get('exfil_indicators', [])}")
        print()

    if not args.exfil_only:
        for r in results:
            qname = r.get("qry_name", "")
            if qname:
                print(f"[Q] {qname} (type={r.get('qry_type', '')})")
            if r.get("a_record"):
                print(f"  A: {r['a_record']}")
            if r.get("txt_record"):
                print(f"  TXT: {r['txt_record']}")


def cmd_streams(args: argparse.Namespace) -> None:
    """Follow TCP/UDP streams."""
    if args.stream is not None:
        output = tshark_follow_stream(args.pcap, args.proto, args.stream, args.mode)
        print(output)
    else:
        # List available streams
        print("[*] TCP Conversations:")
        print(tshark_conversations(args.pcap, "tcp"))


def cmd_stats(args: argparse.Namespace) -> None:
    """Show PCAP statistics."""
    summary = pcap_summary(args.pcap)
    print(f"File: {summary['file']}")
    if "total_packets" in summary:
        print(f"Total packets: {summary['total_packets']}")
    if "protocol_counts" in summary:
        print(f"Protocols: {summary['protocol_counts']}")
    print("\n--- Protocol Hierarchy ---")
    print(summary.get("protocol_hierarchy", ""))


def cmd_search(args: argparse.Namespace) -> None:
    """Search for pattern in PCAP."""
    results = search_pattern_in_pcap(args.pcap, args.pattern, args.regex)
    print(f"[*] Found {len(results)} matches for '{args.pattern}':")
    for r in results:
        print(f"  pkt={r['packet']} src={r.get('src', '?')} dst={r.get('dst', '?')}")
        print(f"  context: {r['context'][:100]}...")
        print()


def cmd_tls(args: argparse.Namespace) -> None:
    """Extract TLS handshake info."""
    results = pyshark_tls_info(args.pcap, args.keylog)
    for r in results:
        print(f"[TLS] frame={r['frame']}")
        if r.get("sni"):
            print(f"  SNI: {r['sni']}")
        if r.get("ja3"):
            print(f"  JA3: {r['ja3']}")
        if r.get("cipher"):
            print(f"  Cipher: {r['cipher']}")
        print()


def cmd_encoded(args: argparse.Namespace) -> None:
    """Detect encoded data (base64, hex) in PCAP."""
    results = detect_encoded_data(args.pcap)
    print(f"[*] Found {len(results)} encoded data patterns:")
    for r in results:
        print(f"  pkt={r['packet']} type={r['type']}")
        print(f"  encoded: {r['encoded']}")
        print(f"  decoded: {r['decoded_preview']}")
        print()


def cmd_extract_raw(args: argparse.Namespace) -> None:
    """Extract raw payloads to files."""
    payloads = scapy_extract_payloads(args.pcap, args.port)
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    for i, p in enumerate(payloads):
        outpath = outdir / f"payload_{i:04d}.bin"
        outpath.write_bytes(p)
        print(f"Wrote {outpath} ({len(p)} bytes)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CTF Network/PCAP Analysis Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s http capture.pcap                    # Extract HTTP traffic
  %(prog)s dns capture.pcap --detect-exfil      # DNS with exfil detection
  %(prog)s streams capture.pcap --stream 0      # Follow TCP stream #0
  %(prog)s stats capture.pcap                   # Quick statistics
  %(prog)s search capture.pcap --pattern "flag{"
  %(prog)s tls capture.pcap --keylog sslkey.log # TLS with decryption
        """
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # HTTP
    sp = sub.add_parser("http", help="Extract HTTP requests/responses")
    sp.add_argument("pcap", help="PCAP file path")
    sp.add_argument("--keylog", help="TLS keylog file for decryption")
    sp.set_defaults(fn=cmd_http)

    # DNS
    sp = sub.add_parser("dns", help="Extract DNS traffic")
    sp.add_argument("pcap")
    sp.add_argument("--detect-exfil", action="store_true", help="Detect DNS exfiltration patterns")
    sp.add_argument("--exfil-only", action="store_true", help="Only show suspicious DNS")
    sp.set_defaults(fn=cmd_dns)

    # Streams
    sp = sub.add_parser("streams", help="Follow TCP/UDP streams")
    sp.add_argument("pcap")
    sp.add_argument("--stream", type=int, help="Stream ID to follow")
    sp.add_argument("--proto", default="tcp", choices=["tcp", "udp"])
    sp.add_argument("--mode", default="ascii", choices=["ascii", "hex", "raw"])
    sp.set_defaults(fn=cmd_streams)

    # Stats
    sp = sub.add_parser("stats", help="PCAP statistics and summary")
    sp.add_argument("pcap")
    sp.set_defaults(fn=cmd_stats)

    # Search
    sp = sub.add_parser("search", help="Search for pattern in payloads")
    sp.add_argument("pcap")
    sp.add_argument("--pattern", required=True, help="Search pattern")
    sp.add_argument("--regex", action="store_true", help="Use regex matching")
    sp.set_defaults(fn=cmd_search)

    # TLS
    sp = sub.add_parser("tls", help="Extract TLS handshake info")
    sp.add_argument("pcap")
    sp.add_argument("--keylog", help="TLS keylog file for decryption")
    sp.set_defaults(fn=cmd_tls)

    # Encoded detection
    sp = sub.add_parser("encoded", help="Detect base64/hex encoded data")
    sp.add_argument("pcap")
    sp.set_defaults(fn=cmd_encoded)

    # Raw extraction
    sp = sub.add_parser("extract-raw", help="Extract raw payloads to files")
    sp.add_argument("pcap")
    sp.add_argument("--out", required=True, help="Output directory")
    sp.add_argument("--port", type=int, help="Filter by port")
    sp.set_defaults(fn=cmd_extract_raw)

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
