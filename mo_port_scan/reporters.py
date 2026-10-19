"""Output: console tables and JSON / CSV / HTML / TXT reports."""

from __future__ import annotations

import csv
import html
import io
import json
import os
from typing import Callable, Dict, List, Optional

from .scanner import HostResult
from .utils import BOLD, CYAN, DIM, GREEN, RED, YELLOW


# ------------------------------------------------------------------ console
def render_host(host: HostResult, c: Callable[[str, str], str]) -> str:
    title = host.ip if host.target == host.ip else f"{host.target} ({host.ip})"
    if host.hostname and host.hostname != host.target:
        title += f" [{host.hostname}]"
    lines = [c(f"Scan report for {title}", BOLD)]
    if not host.ports:
        lines.append("  No open ports found.")
        return "\n".join(lines)

    lines.append(c(f"  {'PORT':<11}{'STATE':<15}{'SERVICE':<16}VERSION / BANNER", DIM))
    for p in host.ports:
        color = GREEN if p.state == "open" else YELLOW
        info = p.version or p.banner
        port = f"{p.port}/{p.protocol}"
        lines.append(f"  {port:<11}{c(f'{p.state:<15}', color)}{p.service:<16}{info}")
        if p.extra.get("http_title"):
            lines.append(c(f"      title: {p.extra['http_title']}", DIM))
        if p.tls:
            t = p.tls
            detail = f"{t.get('version', '')} {t.get('cipher', '')}".strip()
            if t.get("subject"):
                detail += f" | CN={t['subject']} | issuer={t.get('issuer', '')} | expires {t.get('not_after', '')}"
            if t.get("verified") == "false":
                detail += " | untrusted certificate"
            lines.append(c(f"      tls: {detail}", CYAN))
        if p.hint:
            lines.append(c(f"      ! {p.hint}", RED))
    return "\n".join(lines)


# ------------------------------------------------------------------ formats
def _rows(hosts: List[HostResult]):
    for h in hosts:
        for p in h.ports:
            yield [h.target, h.ip, h.hostname, p.port, p.protocol, p.state,
                   p.service, p.version, p.banner, p.hint]


CSV_HEADER = ["target", "ip", "hostname", "port", "protocol", "state",
              "service", "version", "banner", "hint"]


def to_json(hosts: List[HostResult], meta: Dict) -> str:
    return json.dumps({"meta": meta, "hosts": [h.to_dict() for h in hosts]}, indent=2)


def to_csv(hosts: List[HostResult], meta: Dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_HEADER)
    w.writerows(_rows(hosts))
    return buf.getvalue()


def to_txt(hosts: List[HostResult], meta: Dict) -> str:
    plain = lambda text, code: text  # noqa: E731
    head = f"Mo-port-scan {meta.get('version', '')} report - {meta.get('started', '')}\n\n"
    return head + "\n\n".join(render_host(h, plain) for h in hosts) + "\n"


def to_html(hosts: List[HostResult], meta: Dict) -> str:
    e = html.escape
    parts = ["""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Mo-port-scan report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#1b1f24;background:#fff}
h1{margin-bottom:.2rem} .meta{color:#57606a;margin-bottom:1.5rem}
.host{border:1px solid #d0d7de;border-radius:8px;margin:1rem 0;padding:1rem}
table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #eaeef2;font-size:.92rem}
th{background:#f6f8fa} .open{color:#1a7f37;font-weight:600} .filtered{color:#9a6700;font-weight:600}
.hint{color:#cf222e;font-size:.85rem} code{background:#f6f8fa;padding:0 .25rem;border-radius:4px}
@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}.host{border-color:#30363d}
th{background:#161b22}th,td{border-color:#21262d}.meta{color:#8b949e}code{background:#161b22}
.open{color:#3fb950}.filtered{color:#d29922}.hint{color:#ff7b72}}
</style></head><body>"""]
    parts.append("<h1>Mo-port-scan report</h1>")
    parts.append(f'<div class="meta">Started {e(str(meta.get("started", "")))} &middot; '
                 f'duration {e(str(meta.get("duration_s", "")))}s &middot; '
                 f'{meta.get("hosts_up", 0)} host(s) up &middot; '
                 f'{meta.get("open_ports", 0)} open port(s)</div>')
    for h in hosts:
        title = h.ip if h.target == h.ip else f"{h.target} ({h.ip})"
        if h.hostname:
            title += f" [{h.hostname}]"
        parts.append(f'<div class="host"><h2>{e(title)}</h2>')
        if not h.ports:
            parts.append("<p>No open ports found.</p></div>")
            continue
        parts.append("<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version / banner</th><th>Details</th></tr>")
        for p in h.ports:
            cls = "open" if p.state == "open" else "filtered"
            details = []
            if p.extra.get("http_title"):
                details.append(f"title: {e(p.extra['http_title'])}")
            if p.tls:
                t = p.tls
                details.append("TLS: " + e(f"{t.get('version', '')} {t.get('cipher', '')} "
                                            f"CN={t.get('subject', '')} exp {t.get('not_after', '')}".strip()))
            if p.hint:
                details.append(f'<span class="hint">{e(p.hint)}</span>')
            parts.append(f"<tr><td><code>{p.port}/{p.protocol}</code></td>"
                         f'<td class="{cls}">{e(p.state)}</td><td>{e(p.service)}</td>'
                         f"<td>{e(p.version or p.banner)}</td><td>{'<br>'.join(details)}</td></tr>")
        parts.append("</table></div>")
    parts.append('<p class="meta">For authorized security testing only.</p></body></html>')
    return "".join(parts)


FORMATS = {"json": to_json, "csv": to_csv, "html": to_html, "txt": to_txt}
EXTENSIONS = {".json": "json", ".csv": "csv", ".html": "html", ".htm": "html", ".txt": "txt"}


def write_report(path: str, hosts: List[HostResult], meta: Dict, fmt: Optional[str] = None) -> str:
    fmt = fmt or EXTENSIONS.get(os.path.splitext(path)[1].lower(), "json")
    content = FORMATS[fmt](hosts, meta)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(content)
    return fmt
