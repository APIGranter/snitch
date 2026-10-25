# Changelog

All notable changes to SNItch are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] — Unreleased

A full internal rewrite that keeps the 1.x command line and output layout.

### Added

- `snitchlib/` package (importable, testable) with a thin `snitch.py` wrapper
  and `python -m snitchlib` support.
- One streaming `tshark` pass (TLS SNI, DNS, HTTP hosts, flows, TCP flags,
  retransmissions) instead of several slower passes.
- Live capture: `--live [IFACE]`, `--duration`, `--packet-limit`,
  `--list-interfaces`.
- Time and filter controls: `--since`, `--until`, `--display-filter`.
- Client selection: `--auto-clients`, `--hotspot-net`, `--gateway`,
  `--exclude-ip`, `--min-packets`.
- Finding allowlist (`--allowlist PATH`): suppress findings for known-good
  IPs, CIDRs and domain suffixes (boundary-aware), with a suppression warning.
- Automatic fallback to `--auto-clients` when the default Windows-hotspot
  filter matches no clients (with a warning); explicit network options disable
  the fallback.
- Enrichment: concurrent geolocation/rDNS/RDAP, optional VirusTotal domain
  checks (`--vt-domains`), Tor exit-node checks, `--offline`, `--refresh`,
  `--no-cache`, configurable `--workers`.
- Versioned `enrichment_cache.json` with TTLs and automatic migration from the
  1.x `ip_cache.json`.
- Local heuristics: beaconing, exfiltration, DNS anomalies, port scans,
  Tor-like traffic, cleartext protocols and retransmissions, with severity,
  confidence, score and evidence.
- New dashboard: themes, map zoom/pan, timeline, charts, searchable/sortable/
  paginated tables, findings and details modals, About page, CSV/JSON exports
  and a strict CSP. All dynamic values are escaped.
- New outputs: `data/analysis.json`, `domains.csv`, `flows.csv`, `dns.csv`,
  `findings.csv`, `summary.txt` (1.x files are still written).
- `--fail-on` severity gate (exit code 3), `--open`, `--title`, `--no-html`,
  `--quiet`, `--verbose` and JSON config files (`--config`, `snitch.json`).
- Packaging: `pyproject.toml` with a `snitch` console script, package data,
  `MANIFEST.in`, PyInstaller `snitch.spec`, build scripts and GitHub Actions CI.
- 95 unit/integration tests (no tshark or network required).
- Documentation: rewritten `README.md`, `snitch.example.json`, `HANDOFF.md`.

### Changed

- Domain classification now matches on label boundaries, so `example.com`
  matches `cdn.example.com` but not `notexample.com`.
- Geolocation/rDNS/RDAP lookups run concurrently; VirusTotal stays sequential
  for free-tier rate limits.
- Generated JSON is embedded safely in the dashboard (`<`, `>`, `&` escaped).
- Cache, result and packaging artifacts are covered by `.gitignore`.

### Fixed

- Wrong dashboard metadata keys (`file`/`source`/`size_bytes`/`tshark_version`)
  and missing `dport` in flow search.
- Malformed newline when writing cached VirusTotal results.
- Summary TXT metadata keys and 1.x cache import edge cases.

### Compatibility

- Python 3.9+; standard library only.
- Existing commands, output folder names, `data/results.json`, `data/results.csv`
  and `domains/*.txt` remain valid. New files are additive.
- Default client mode is still `192.168.137.0/24` with gateway
  `192.168.137.1`; if that filter finds no clients, SNItch now retries once
  with `--auto-clients`. Use `--src-ip`/`--all` for explicit control.

## [1.0.0] — Previous release

- Original single-script analyzer: tshark extraction, ipwho.is geolocation,
  VirusTotal IP reputation, SNI/DNS classification, CSV/JSON/TXT output and a
  static HTML dashboard with a world map.
