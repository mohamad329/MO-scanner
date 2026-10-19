"""Command-line interface."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .reporters import FORMATS, render_host, write_report
from .scanner import HostResult, Scanner
from .utils import (Progress, make_colorizer, parse_ports, parse_targets,
                    read_target_file, supports_color, top_ports)

SCAN_TYPES = {"tcp": ("tcp",), "udp": ("udp",), "both": ("tcp", "udp")}
LEGAL = "[!] Use only on systems you own or have explicit written permission to test."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mo-port-scan",
        description="Fast multi-threaded TCP/UDP port scanner with service detection "
                    "and HTML/JSON/CSV reports. For authorized testing only.",
        epilog="examples:\n"
               "  mo-port-scan 192.168.1.10 -F -b\n"
               "  mo-port-scan 10.0.0.0/24 -p 22,80,443 -o report.html\n"
               "  mo-port-scan example.local -s both --top-ports 50 --tls -o scan.json\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    t = p.add_argument_group("targets")
    t.add_argument("targets", nargs="*", metavar="TARGET",
                   help="hostname, IP, CIDR (10.0.0.0/24), range (10.0.0.1-50 or 10.0.0.1-10.0.0.9)")
    t.add_argument("-L", "--input-list", metavar="FILE", help="read targets from file (one per line, # comments)")
    t.add_argument("--exclude", metavar="LIST", help="comma-separated targets to skip")

    s = p.add_argument_group("port selection")
    s.add_argument("-p", "--ports", default="1-1024", help="e.g. 80 | 1-1024 | 22,80,443 (default: 1-1024)")
    s.add_argument("-F", "--fast", action="store_true", help="scan the 100 most common ports")
    s.add_argument("--top-ports", type=int, metavar="N", help="scan the N most common ports")
    s.add_argument("--all-ports", action="store_true", help="scan all 65535 ports")

    m = p.add_argument_group("scan options")
    m.add_argument("-s", "--scan", choices=SCAN_TYPES, default="tcp", help="tcp (default), udp or both")
    m.add_argument("-b", "--banner", action="store_true", help="grab banners and identify services/versions")
    m.add_argument("--tls", action="store_true", help="collect TLS version and certificate info")
    m.add_argument("--no-ping", action="store_true", help="skip host discovery (treat all hosts as up)")
    m.add_argument("--resolve", action="store_true", help="reverse DNS lookup of scanned hosts")
    m.add_argument("--show-filtered", action="store_true", help="also report open|filtered UDP ports")

    perf = p.add_argument_group("performance")
    perf.add_argument("-t", "--threads", type=int, default=100, help="worker threads (default: 100)")
    perf.add_argument("--timeout", type=float, default=1.0, help="per-port timeout in seconds (default: 1.0)")
    perf.add_argument("-r", "--retries", type=int, default=1, help="retries for timed-out probes (default: 1)")
    perf.add_argument("--rate", type=float, default=0.0, help="max probes per second (default: unlimited)")
    perf.add_argument("--randomize", action="store_true", help="randomize port order")

    o = p.add_argument_group("output")
    o.add_argument("-o", "--output", metavar="FILE", help="save report (format from extension: .json .csv .html .txt)")
    o.add_argument("--format", choices=sorted(FORMATS), help="force report format")
    o.add_argument("-q", "--quiet", action="store_true", help="results only (no banner/progress)")
    o.add_argument("-v", "--verbose", action="store_true", help="debug output")
    o.add_argument("--no-color", action="store_true", help="disable colored output")
    o.add_argument("-y", "--yes", action="store_true", help="confirm scanning more than 256 hosts")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def select_ports(args) -> List[int]:
    if args.all_ports:
        return parse_ports("all")
    if args.top_ports:
        return top_ports(args.top_ports)
    if args.fast:
        return top_ports(100)
    return parse_ports(args.ports)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="[debug] %(message)s")
    c = make_colorizer(supports_color(sys.stdout) and not args.no_color)
    err = lambda msg: print(f"[!] {msg}", file=sys.stderr)  # noqa: E731

    try:
        specs = list(args.targets)
        if args.input_list:
            specs += read_target_file(args.input_list)
        if not specs:
            parser.error("no targets specified")
        exclude = [x for x in (args.exclude or "").split(",") if x.strip()]
        ports = select_ports(args)
        targets = parse_targets(specs, exclude)
        if args.threads < 1 or args.timeout <= 0 or args.retries < 0:
            raise ValueError("threads must be >= 1, timeout > 0 and retries >= 0")
    except (ValueError, OSError) as exc:
        err(str(exc))
        return 1

    if not targets:
        err("no valid targets after exclusions")
        return 1
    if len(targets) > 256 and not args.yes:
        err(f"Refusing to scan {len(targets)} hosts without --yes. Make sure you are authorized.")
        return 1

    types = SCAN_TYPES[args.scan]
    show_status = not args.quiet
    progress = Progress(len(targets) * len(ports) * len(types),
                        enabled=show_status and sys.stderr.isatty())
    scanner = Scanner(ports, types, threads=args.threads, timeout=args.timeout,
                      retries=args.retries, rate=args.rate, randomize=args.randomize,
                      banner=args.banner, tls=args.tls, skip_discovery=args.no_ping,
                      resolve=args.resolve, include_filtered=args.show_filtered,
                      progress=progress)

    if show_status:
        print(c(LEGAL, "33"), file=sys.stderr)
        print(f"[*] {len(targets)} target(s) | {len(ports)} port(s) | scan: {args.scan} | "
              f"threads: {args.threads} | timeout: {args.timeout}s", file=sys.stderr)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    results: List[HostResult] = []
    interrupted = False
    try:
        for host in scanner.scan(targets):
            results.append(host)
            progress.clear()
            print(render_host(host, c) + "\n")
    except KeyboardInterrupt:
        interrupted = True
        progress.clear()
        err("Scan interrupted by user")
    progress.clear()

    duration = round(time.monotonic() - t0, 2)
    open_ports = sum(len(h.ports) for h in results)
    if show_status:
        print(f"[+] Done: {len(results)}/{len(targets)} host(s) up, "
              f"{open_ports} open port(s) in {duration}s", file=sys.stderr)

    if args.output:
        meta = {"tool": "Mo-port-scan", "version": __version__,
                "started": started.isoformat(timespec="seconds"), "duration_s": duration,
                "arguments": " ".join(argv if argv is not None else sys.argv[1:]),
                "hosts_scanned": len(targets), "hosts_up": len(results),
                "open_ports": open_ports, "interrupted": interrupted}
        try:
            fmt = write_report(args.output, results, meta, args.format)
            if show_status:
                print(f"[+] {fmt.upper()} report saved to {args.output}", file=sys.stderr)
        except OSError as exc:
            err(f"Could not write report: {exc}")
            return 1
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
