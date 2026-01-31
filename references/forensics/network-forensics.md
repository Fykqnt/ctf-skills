# Network Forensics (CTF)

## Skill
- PCAP構造理解：Ethernet/IP/TCP/UDP/アプリ層の階層と境界
- プロトコル解析：HTTP/DNS/TLS/FTP/SMTP/カスタムプロトコルの即時分類
- ストリーム再構成：TCPセッション/HTTPトランザクション/ファイル抽出
- 異常検出：exfiltration/C2/tunnel/covert channelの特徴認識
- 暗号化通信：TLS復号（SSLKEYLOG）、弱い暗号、証明書検証不備

## Attack Patterns (CTF頻出)
- DNS Exfiltration：長いサブドメイン/TXTレコード/高エントロピー
- HTTP隠蔽：ヘッダ内データ/chunked encoding/gzip内flag
- TCP Covert：SEQ/ACK番号/タイムスタンプにデータ埋め込み
- ICMP Tunnel：ペイロードにエンコードデータ
- ポートノッキング：特定シーケンス後に通信開始

## Quick Workflow
1. **Triage**: `tshark -r x.pcap -z io,phs -q` でプロトコル分布
2. **Conversations**: `tshark -r x.pcap -z conv,tcp -q` で通信ペア把握
3. **Filter**: Wireshark/tshark display filter で絞り込み
4. **Extract**: ストリーム再構成 or ファイルカービング
5. **Decode**: Base64/hex/暗号化の解除

## Essential Commands

### tshark (CLI解析の主力)
```bash
# プロトコル統計
tshark -r capture.pcap -z io,phs -q

# TCP会話一覧
tshark -r capture.pcap -z conv,tcp -q

# TCPストリーム#0をASCII出力
tshark -r capture.pcap -z follow,tcp,ascii,0 -q

# HTTPリクエストURIを抽出
tshark -r capture.pcap -Y http.request -T fields -e http.request.uri

# DNS クエリ名を抽出
tshark -r capture.pcap -Y dns.qry.name -T fields -e dns.qry.name

# TLS SNI（接続先ホスト名）を抽出
tshark -r capture.pcap -Y tls.handshake.extensions_server_name -T fields -e tls.handshake.extensions_server_name

# TLS復号（SSLKEYLOGファイル使用）
tshark -r capture.pcap -o tls.keylog_file:sslkey.log -Y http

# 特定文字列を含むパケット
tshark -r capture.pcap -Y 'frame contains "flag"'
```

### pyshark (Python統合)
```python
import pyshark

# HTTP解析
cap = pyshark.FileCapture('capture.pcap', display_filter='http')
for pkt in cap:
    if hasattr(pkt.http, 'request_uri'):
        print(f"{pkt.http.request_method} {pkt.http.request_uri}")
    if hasattr(pkt.http, 'file_data'):
        print(f"Body: {pkt.http.file_data[:100]}")

# DNS exfiltration検出
cap = pyshark.FileCapture('capture.pcap', display_filter='dns')
for pkt in cap:
    if hasattr(pkt.dns, 'qry_name'):
        name = pkt.dns.qry_name
        if len(name.split('.')[0]) > 30:  # 異常に長いサブドメイン
            print(f"Suspicious: {name}")

# TLS復号
cap = pyshark.FileCapture('capture.pcap',
    override_prefs={'tls.keylog_file': 'sslkey.log'})
```

### scapy (低レベル操作)
```python
from scapy.all import rdpcap, TCP, Raw, IP

# TCPストリーム再構成
packets = rdpcap('capture.pcap')
stream = b''
for pkt in packets:
    if TCP in pkt and Raw in pkt:
        if pkt[TCP].dport == 80:  # サーバー向け
            stream += bytes(pkt[Raw].load)

# パターン検索
for pkt in packets:
    if Raw in pkt and b'flag{' in bytes(pkt[Raw].load):
        print(f"Found in packet from {pkt[IP].src}")
```

## CTF典型問題と解法

### DNS Exfiltration
```bash
# 長いサブドメインを抽出
tshark -r capture.pcap -Y dns.qry.name -T fields -e dns.qry.name | \
  awk -F'.' '{print $1}' | sort -u

# Base64デコード
echo "encoded_subdomain" | base64 -d
```

### HTTP Hidden Data
```bash
# レスポンスボディを全て抽出
tshark -r capture.pcap -Y 'http.response' -T fields -e http.file_data

# 特定Content-Typeのみ
tshark -r capture.pcap -Y 'http.content_type contains "image"'
```

### TLS Decryption (SSLKEYLOG)
```bash
# 環境変数でキャプチャ時に鍵を保存
export SSLKEYLOGFILE=/tmp/sslkey.log
curl https://target.com

# Wiresharkで復号
Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
```

### ICMP Tunnel
```python
from scapy.all import rdpcap, ICMP, Raw

packets = rdpcap('capture.pcap')
data = b''
for pkt in packets:
    if ICMP in pkt and Raw in pkt:
        data += bytes(pkt[Raw].load)
print(data)  # 結合されたデータ
```

## Tools
- **解析**: Wireshark / tshark / tcpdump / pyshark / scapy
- **抽出**: foremost / binwalk / NetworkMiner
- **復号**: SSLKEYLOG / mitmproxy / ssldump
- **統計**: capinfos / ngrep / zeek(bro)
- **CTF特化**: `network_analyzer.py`（本リポジトリ）

## Cheat Sheet

| 目的 | tshark filter / command |
|------|-------------------------|
| HTTP GET | `http.request.method == "GET"` |
| HTTP POST body | `http.file_data` |
| DNS query | `dns.qry.name` |
| DNS TXT record | `dns.txt` |
| TLS SNI | `tls.handshake.extensions_server_name` |
| FTP data | `ftp-data` |
| TCP flags | `tcp.flags.syn == 1` |
| 文字列含む | `frame contains "string"` |
| IPアドレス | `ip.addr == 192.168.1.1` |
| ポート | `tcp.port == 443` |
