# Mo-port-scan

A fast, dependency-free TCP/UDP port scanner written in Python, with service detection, TLS inspection and professional reports (HTML / JSON / CSV).

> **Legal notice:** For authorized security testing and education only. Scan only systems you own or have explicit written permission to test. Unauthorized scanning may be illegal. The author accepts no liability for misuse.

## Features

| Area | Details |
|---|---|
| Targets | Hostname, IPv4/IPv6, CIDR (`10.0.0.0/24`), ranges (`10.0.0.1-50`, `10.0.0.1-10.0.0.20`), `-L targets.txt`, `--exclude` |
| Scan types | TCP connect, UDP (with DNS/NTP/SNMP probes), or both |
| Ports | `-p 22,80,8000-8100`, `-F` (top 100), `--top-ports N`, `--all-ports` |
| Detection | Host discovery, service names, banner grabbing, version signatures (SSH, HTTP, FTP, SMTP, MySQL, Redis, VNC...), HTTP title, TLS version/cipher/certificate |
| Performance | Multi-threading, retries, `--rate` limiting, `--randomize` port order |
| Reports | Colored console, `.json`, `.csv`, `.html` (light/dark), `.txt` |
| Safety | Legal reminder, confirmation required for >256 hosts, Ctrl+C keeps partial results |
| Quality | Zero dependencies, Python 3.9+, unit tests, CI on Linux/Windows/macOS |

## Install

```bash
git clone https://github.com/USERNAME/MO-scanner.git
cd MO-scanner
pip install .            # adds the `mo-port-scan` command
# or run without installing:
python -m mo_port_scan --help
```

Docker: `docker build -t mo-port-scan . && docker run --rm mo-port-scan 127.0.0.1 -F`

## Usage

```bash
mo-port-scan 192.168.1.10 -F -b                      # top 100 ports + banners/service detection
mo-port-scan 10.0.0.0/24 -p 22,80,443 -o report.html # subnet scan with HTML report
mo-port-scan scanme.nmap.org --top-ports 50 --tls    # include TLS certificate info
mo-port-scan host.local -s both -p 53,123,161,80     # TCP + UDP
mo-port-scan -L targets.txt --exclude 10.0.0.1 --rate 200 -o scan.json
```

Run `mo-port-scan --help` for every option.

## Example output

```
Scan report for scanme.nmap.org (45.33.32.156)
  PORT       STATE          SERVICE         VERSION / BANNER
  22/tcp     open           ssh             OpenSSH_6.6.1p1
  80/tcp     open           http            Apache/2.4.7 (Ubuntu)
      title: Go ahead and ScanMe!
```

## Notes

- **UDP** scanning is inherently slow/ambiguous: silence is reported as `open|filtered` (shown with `--show-filtered`).
- Discovery uses TCP connects (no root needed). Use `--no-ping` for hosts that drop probes.
- This is a connect scanner; it does not forge packets or require elevated privileges.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## Roadmap

- [ ] SYN scan (raw sockets / scapy)
- [ ] Async engine (`asyncio`) for very large scans
- [ ] OS fingerprinting hints
- [ ] Vulnerability hints via CVE database lookup
- [ ] XML / Markdown reports

## License

MIT - see [LICENSE](LICENSE).
