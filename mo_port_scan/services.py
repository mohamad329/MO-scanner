"""Service identification: names, probes, banner signatures and risk hints."""

from __future__ import annotations

import re
import socket
from typing import Dict, Tuple

HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000}
HTTP_PROBE = (b"GET / HTTP/1.0\r\nHost: {host}\r\n"
              b"User-Agent: Mo-port-scan\r\nAccept: */*\r\n\r\n")

# Protocol-specific UDP payloads; services rarely answer an empty datagram.
UDP_PROBES: Dict[int, bytes] = {
    53: (b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07example\x03com\x00\x00\x01\x00\x01"),                    # DNS A query
    123: b"\x1b" + 47 * b"\x00",                                         # NTP client
    161: (b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00"
          b"\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05"
          b"\x2b\x06\x01\x02\x01\x05\x00"),                              # SNMPv1 get
}

_SIGNATURE_SRC = [
    (r"^SSH-\d\.\d+-(?P<ver>\S+)", "ssh"),
    (r"^HTTP/\d(?:\.\d)? \d{3}", "http"),
    (r"^220[ -].*?(?P<ver>vsftpd [\d.]+|ProFTPD [\d.]+\w*|Pure-FTPd|FileZilla Server [\d.]+)", "ftp"),
    (r"^220[ -].*?FTP", "ftp"),
    (r"^220[ -].*?(?P<ver>Postfix|Exim [\d.]+|Sendmail[\w./]*)", "smtp"),
    (r"^220[ -].*?SMTP", "smtp"),
    (r"^\+OK.*?(?P<ver>Dovecot)", "pop3"),
    (r"^\+OK", "pop3"),
    (r"^\* OK.*?(?P<ver>Dovecot|Cyrus)", "imap"),
    (r"^\* OK", "imap"),
    (r"^RFB (?P<ver>\d{3}\.\d{3})", "vnc"),
    (r"^.\x00\x00\x00\x0a(?P<ver>[\w.+\-]+)\x00", "mysql"),
    (r"^-(?:ERR|NOAUTH|DENIED)|^\+PONG|redis_version", "redis"),
    (r"^AMQP", "amqp"),
    (r"^\xff[\xfb-\xfe]", "telnet"),
]
SIGNATURES = [(re.compile(p, re.S), name) for p, name in _SIGNATURE_SRC]

FALLBACK_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

# Short, non-judgmental hints for services that are commonly risky when exposed.
RISK_NOTES: Dict[Tuple[int, str], str] = {
    (21, "tcp"): "FTP sends credentials in cleartext; prefer SFTP/FTPS",
    (23, "tcp"): "Telnet is unencrypted; replace with SSH",
    (110, "tcp"): "POP3 without TLS exposes credentials",
    (135, "tcp"): "MS-RPC should not be exposed to untrusted networks",
    (139, "tcp"): "NetBIOS should not be exposed to untrusted networks",
    (445, "tcp"): "SMB exposed; restrict access and keep patched",
    (1433, "tcp"): "Database port exposed",
    (3306, "tcp"): "Database port exposed",
    (3389, "tcp"): "RDP exposed; require NLA/VPN and strong auth",
    (5432, "tcp"): "Database port exposed",
    (5900, "tcp"): "VNC exposed; ensure strong auth and tunneling",
    (6379, "tcp"): "Redis is often deployed without authentication",
    (9200, "tcp"): "Elasticsearch exposed; check authentication",
    (11211, "tcp"): "Memcached exposed; can be abused for amplification",
    (27017, "tcp"): "MongoDB exposed; check authentication",
    (69, "udp"): "TFTP has no authentication",
    (161, "udp"): "SNMP exposed; check for default community strings",
    (11211, "udp"): "Memcached over UDP can be abused for amplification",
}


def service_name(port: int, proto: str = "tcp") -> str:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return FALLBACK_SERVICES.get(port, "unknown") if proto == "tcp" else "unknown"


def risk_note(port: int, proto: str = "tcp") -> str:
    return RISK_NOTES.get((port, proto), "")


def identify(port: int, proto: str, raw: str) -> Tuple[str, str, Dict[str, str]]:
    """Return (service, version, extra) using the banner when available."""
    service, version, extra = service_name(port, proto), "", {}
    if raw:
        for rx, name in SIGNATURES:
            m = rx.search(raw)
            if m:
                service = name
                version = (m.groupdict().get("ver") or "").strip()
                break
        if service == "http":
            sm = re.search(r"^Server:\s*(.+)$", raw, re.I | re.M)
            if sm:
                version = sm.group(1).strip()
            tm = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
            if tm:
                extra["http_title"] = " ".join(tm.group(1).split())[:100]
    return service, version, extra


def clean_banner(raw: str, limit: int = 100) -> str:
    """First non-empty line of a banner, printable characters only."""
    for line in raw.splitlines():
        line = line.strip()
        if line:
            line = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in line)
            return line[:limit]
    return ""
