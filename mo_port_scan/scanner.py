"""Core scanning engine: TCP connect, UDP, host discovery, banners and TLS."""

from __future__ import annotations

import logging
import random
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

from .services import (HTTP_PORTS, HTTP_PROBE, UDP_PROBES, clean_banner,
                       identify, risk_note, service_name)
from .utils import Progress, RateLimiter

log = logging.getLogger("mo_port_scan")

DISCOVERY_PORTS = (80, 443, 22, 445, 3389, 8080)


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"            # open | open|filtered
    service: str = "unknown"
    version: str = ""
    banner: str = ""
    hint: str = ""
    tls: Optional[Dict[str, str]] = None
    extra: Dict[str, str] = field(default_factory=dict)


@dataclass
class HostResult:
    target: str
    ip: str
    hostname: str = ""
    ports: List[PortResult] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------ probing
def host_alive(ip: str, timeout: float) -> bool:
    """TCP-based discovery: an accepted *or refused* connection proves the host is up."""
    for port in DISCOVERY_PORTS:
        try:
            socket.create_connection((ip, port), timeout=timeout).close()
            return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def grab_banner(sock: socket.socket, port: int, timeout: float, host: str) -> str:
    """Read a service banner; speak first only for HTTP or when the service stays silent."""
    data = b""
    try:
        if port in HTTP_PORTS:
            sock.settimeout(timeout)
            sock.sendall(HTTP_PROBE.replace(b"{host}", host.encode()))
            data = sock.recv(4096)
        else:
            sock.settimeout(min(timeout, 1.0))
            try:
                data = sock.recv(1024)
            except socket.timeout:
                data = b""
            if not data:
                sock.sendall(b"\r\n")
                data = sock.recv(1024)
    except OSError:
        pass
    return data.decode("latin-1")


def tls_info(ip: str, port: int, timeout: float, server_hostname: Optional[str] = None) -> Optional[Dict[str, str]]:
    """Handshake details. Tries a verified handshake first (to read the parsed
    certificate), then falls back to an unverified one (self-signed, etc.)."""
    for verify in (True, False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        if not verify:
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw, \
                    ctx.wrap_socket(raw, server_hostname=server_hostname) as s:
                info = {"version": s.version() or "", "cipher": (s.cipher() or ("",))[0],
                        "verified": str(verify).lower()}
                cert = s.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    info["subject"] = subject.get("commonName", "")
                    info["issuer"] = issuer.get("commonName", "") or issuer.get("organizationName", "")
                    info["not_after"] = cert.get("notAfter", "")
                return info
        except (ssl.SSLError, OSError):
            continue
    return None


def probe_tcp(ip: str, port: int, timeout: float, retries: int = 1,
              limiter: Optional[RateLimiter] = None, banner: bool = False,
              tls: bool = False, host_header: str = "") -> Optional[PortResult]:
    sock = None
    for _ in range(retries + 1):
        if limiter:
            limiter.wait()
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            break
        except ConnectionRefusedError:
            return None                       # closed: no retry needed
        except OSError:
            continue                          # timeout / unreachable: retry
    if sock is None:
        return None

    res = PortResult(port=port, protocol="tcp", state="open", service=service_name(port))
    raw = ""
    try:
        if banner:
            raw = grab_banner(sock, port, timeout, host_header or ip)
    finally:
        sock.close()

    if banner:
        res.service, res.version, res.extra = identify(port, "tcp", raw)
        res.banner = clean_banner(raw)
    if tls:
        res.tls = tls_info(ip, port, timeout, host_header if host_header != ip else None)
        if res.tls and res.service == "unknown":
            res.service = "ssl"
    res.hint = risk_note(port, "tcp")
    return res


def probe_udp(ip: str, port: int, timeout: float, retries: int = 1,
              limiter: Optional[RateLimiter] = None) -> Optional[PortResult]:
    """UDP is connectionless: a reply => open, ICMP unreachable => closed,
    silence => open|filtered."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    payload = UDP_PROBES.get(port, b"")
    for _ in range(retries + 1):
        if limiter:
            limiter.wait()
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((ip, port))
                s.send(payload)
                data = s.recv(1024)
            except (ConnectionRefusedError, ConnectionResetError):
                return None                   # ICMP port unreachable => closed
            except socket.timeout:
                continue
            except OSError:
                continue
            res = PortResult(port=port, protocol="udp", state="open",
                             service=service_name(port, "udp"),
                             banner=f"{len(data)} bytes response")
            res.hint = risk_note(port, "udp")
            return res
    res = PortResult(port=port, protocol="udp", state="open|filtered",
                     service=service_name(port, "udp"))
    res.hint = risk_note(port, "udp")
    return res


# ------------------------------------------------------------------- engine
class Scanner:
    def __init__(self, ports: Sequence[int], scan_types: Sequence[str] = ("tcp",),
                 threads: int = 100, timeout: float = 1.0, retries: int = 1,
                 rate: float = 0.0, randomize: bool = False, banner: bool = False,
                 tls: bool = False, skip_discovery: bool = False, resolve: bool = False,
                 include_filtered: bool = False, progress: Optional[Progress] = None):
        self.ports = list(ports)
        self.scan_types = tuple(scan_types)
        self.threads = max(1, threads)
        self.timeout = timeout
        self.retries = max(0, retries)
        self.randomize = randomize
        self.banner = banner
        self.tls = tls
        self.skip_discovery = skip_discovery
        self.resolve = resolve
        self.include_filtered = include_filtered
        self.progress = progress
        self.limiter = RateLimiter(rate)

    @property
    def probes_per_host(self) -> int:
        return len(self.ports) * len(self.scan_types)

    def discover(self, targets: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        if self.skip_discovery:
            return targets
        with ThreadPoolExecutor(max_workers=min(self.threads, 256)) as pool:
            alive = list(pool.map(lambda t: host_alive(t[1], self.timeout), targets))
        for (label, ip), up in zip(targets, alive):
            if not up:
                log.debug("host %s appears down", ip)
        return [t for t, up in zip(targets, alive) if up]

    def _probe(self, proto: str, ip: str, port: int, label: str) -> Optional[PortResult]:
        try:
            if proto == "tcp":
                return probe_tcp(ip, port, self.timeout, self.retries, self.limiter,
                                 self.banner, self.tls, label)
            return probe_udp(ip, port, self.timeout, self.retries, self.limiter)
        finally:
            if self.progress:
                self.progress.update()

    def scan_host(self, label: str, ip: str) -> HostResult:
        import time
        start = time.monotonic()
        host = HostResult(target=label, ip=ip)
        tasks = [(proto, port) for proto in self.scan_types for port in self.ports]
        if self.randomize:
            random.shuffle(tasks)

        pool = ThreadPoolExecutor(max_workers=self.threads)
        try:
            futures = [pool.submit(self._probe, proto, ip, port, label) for proto, port in tasks]
            for fut in as_completed(futures):
                res = fut.result()
                if res and (res.state == "open" or self.include_filtered):
                    host.ports.append(res)
            pool.shutdown(wait=True)
        except BaseException:
            pool.shutdown(wait=False, cancel_futures=True)
            raise

        host.ports.sort(key=lambda r: (r.protocol, r.port))
        if self.resolve:
            try:
                host.hostname = socket.gethostbyaddr(ip)[0]
            except OSError:
                pass
        host.duration = round(time.monotonic() - start, 2)
        return host

    def scan(self, targets: List[Tuple[str, str]]) -> Iterator[HostResult]:
        live = self.discover(targets)
        if self.progress:
            self.progress.update((len(targets) - len(live)) * self.probes_per_host)
        for label, ip in live:
            yield self.scan_host(label, ip)
