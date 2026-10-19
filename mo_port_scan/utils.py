"""Helpers: port/target parsing, rate limiting, colors and progress bar."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import sys
import threading
import time
from typing import Iterable, List, Sequence, Tuple

MAX_HOSTS = 65536

# ~100 commonly used TCP ports (ordered roughly by popularity).
TOP_TCP_PORTS: List[int] = list(dict.fromkeys([
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81,
    6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26, 1433,
    49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631, 631, 49153,
    8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357,
    427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646, 49157, 1028,
    873, 1755, 2717, 4899, 9100, 119, 37, 6379, 9200, 11211, 27017,
]))


# --------------------------------------------------------------------- ports
def parse_ports(spec: str) -> List[int]:
    """Parse '80', '1-1024', '22,80,443,8000-8100' or 'all' into a sorted list."""
    spec = spec.strip().lower()
    if spec in ("all", "-"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("No ports specified")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def top_ports(n: int) -> List[int]:
    if n < 1:
        raise ValueError("--top-ports must be >= 1")
    return TOP_TCP_PORTS[:n]


# ------------------------------------------------------------------- targets
_RANGE_LAST = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")
_RANGE_FULL = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$")


def _resolve(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve host: {host}") from None
    for family, *_rest, sockaddr in infos:
        if family == socket.AF_INET:
            return sockaddr[0]
    return infos[0][4][0]


def expand_target(spec: str) -> List[Tuple[str, str]]:
    """Expand one target spec into [(label, ip), ...].

    Supports: hostname, IPv4/IPv6, CIDR (10.0.0.0/24), last-octet range
    (10.0.0.1-50) and full range (10.0.0.1-10.0.0.20).
    """
    spec = spec.strip()
    if not spec:
        return []

    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        if net.num_addresses > MAX_HOSTS:
            raise ValueError(f"Network too large (max {MAX_HOSTS} addresses): {spec}")
        hosts = list(net.hosts()) or [net.network_address]
        return [(str(h), str(h)) for h in hosts]

    m = _RANGE_LAST.match(spec)
    if m:
        prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        if lo > hi or hi > 255:
            raise ValueError(f"Invalid range: {spec}")
        ipaddress.ip_address(f"{prefix}{lo}")  # validates the octets
        return [(f"{prefix}{i}", f"{prefix}{i}") for i in range(lo, hi + 1)]

    m = _RANGE_FULL.match(spec)
    if m:
        start, end = ipaddress.ip_address(m.group(1)), ipaddress.ip_address(m.group(2))
        if int(end) < int(start):
            raise ValueError(f"Invalid range: {spec}")
        if int(end) - int(start) + 1 > MAX_HOSTS:
            raise ValueError(f"Range too large (max {MAX_HOSTS} addresses): {spec}")
        ips = [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        return [(ip, ip) for ip in ips]

    bare = spec.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return [(bare, bare)]
    except ValueError:
        return [(spec, _resolve(spec))]


def parse_targets(specs: Iterable[str], exclude: Iterable[str] = ()) -> List[Tuple[str, str]]:
    excluded = set()
    for e in exclude:
        for _, ip in expand_target(e):
            excluded.add(ip)
    seen, out = set(), []
    for spec in specs:
        for label, ip in expand_target(spec):
            if ip in excluded or ip in seen:
                continue
            seen.add(ip)
            out.append((label, ip))
    return out


def read_target_file(path: str) -> List[str]:
    with open(path, encoding="utf-8") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.lstrip().startswith("#")]


# ------------------------------------------------------------- rate limiting
class RateLimiter:
    """Thread-safe limiter: at most `rate` operations per second (0 = unlimited)."""

    def __init__(self, rate: float = 0.0):
        self.interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - now
        if delay > 0:
            time.sleep(delay)


# ------------------------------------------------------------ colors/progress
GREEN, YELLOW, RED, CYAN, BOLD, DIM = "32", "33", "31", "36", "1", "2"


def supports_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def make_colorizer(enabled: bool):
    def colorize(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if enabled else text
    return colorize


class Progress:
    """Minimal thread-safe progress bar written to stderr."""

    WIDTH = 30

    def __init__(self, total: int, enabled: bool = True, stream=None):
        self.total = max(total, 1)
        self.done = 0
        self.enabled = enabled
        self.stream = stream or sys.stderr
        self._lock = threading.Lock()
        self._last = 0.0

    def update(self, n: int = 1) -> None:
        with self._lock:
            self.done += n
            if not self.enabled:
                return
            now = time.monotonic()
            if now - self._last < 0.1 and self.done < self.total:
                return
            self._last = now
            frac = min(self.done / self.total, 1.0)
            filled = int(frac * self.WIDTH)
            bar = "#" * filled + "-" * (self.WIDTH - filled)
            self.stream.write(f"\r[{bar}] {frac * 100:5.1f}% ({self.done}/{self.total})")
            self.stream.flush()

    def clear(self) -> None:
        if self.enabled:
            self.stream.write("\r" + " " * (self.WIDTH + 30) + "\r")
            self.stream.flush()
