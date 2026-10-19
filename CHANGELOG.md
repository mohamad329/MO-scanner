# Changelog

## 2.0.0
- Rewrite as an installable package (`pip install .`, `python -m mo_port_scan`)
- Targets: hostnames, IPv4/IPv6, CIDR, ranges, input files, exclusions
- TCP connect and UDP scanning (protocol-specific probes for DNS/NTP/SNMP)
- Host discovery, retries, rate limiting, port randomization
- Banner grabbing, service/version signatures, HTTP title, TLS certificate info
- Risk hints for commonly exposed services
- Reports: console, JSON, CSV, HTML (dark-mode aware), TXT
- Progress bar, colored output, Ctrl+C saves partial results
- Unit tests and GitHub Actions CI

## 1.0.0
- Initial single-file TCP scanner
