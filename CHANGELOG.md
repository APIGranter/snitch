# Changelog

All notable changes to SNItch are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] — Unreleased

A full internal rewrite that keeps the 1.x command line and output layout.

### Added

- `snitchlib/` package (importable, testable) with a thin `snitch.py` wrapper
  and `python -m snitchlib` support.
- One streaming `tshark` pass (TLS/DTLS/QUIC/gQUIC SNI, DNS, HTTP/1.1 Host and
  HTTP/2 `:authority`, flows, TCP flags, retransmissions) instead of several
  slower passes.
- Live capture: `--live [IFACE]`, `--duration`, `--packet-limit`,
  `--list-interfaces`.
- Time and filter controls: `--since`, `--until`, `--display-filter`.
- Client selection: `--auto-clients`, `--detect-local`, `--hotspot-net`,
  `--gateway`, `--exclude-ip`, `--min-packets`.
- Capture provenance: when `capinfos` is installed, the About page shows the
  capture application, OS, hardware, encapsulation, interface names and strict
  time-order flag recorded in the file (`meta.capinfos`).
- HTTP methods and User-Agent strings from cleartext requests, shown in the
  destination details modal and `data/analysis.json`.
- Geolocation results carry a `status` (`ok`, `unknown`, `failed`,
  `failed_cached`, `offline`, `disabled`, `unavailable`, `local`) so "provider
  has no record" is distinct from "lookup failed"; shown in destination details
  and exported as `geo_status`/`geo_source` in the CSV and flat JSON.
- Optional offline ASN database (`--asn-db PATH`): reads a MaxMind GeoLite2
  ASN CSV or `CIDR ASN Organisation` lines and fills missing ASN/owner values
  without overriding online results. Works with `--offline`.
- Configurable RDAP endpoint (`--rdap-url TEMPLATE`, must contain `{ip}`);
  cached records from a different provider are ignored, and the About page
  names the provider used.
- Server hostnames announced in cleartext FTP/SMTP/IMAP/POP3 greeting banners
  are linked to the destination IP and domain table (tagged IMAP responses;
  current tshark does not dissect untagged IMAP greetings).
- Finding allowlist (`--allowlist PATH`): suppress findings for known-good
  IPs, CIDRs and domain suffixes (boundary-aware), with a suppression warning
  and a "Suppressed by allowlist" section in the dashboard. Entries can be
  scoped with `[only: ...]` or `[except: ...]` to suppress just some finding
  categories.
- Automatic client-subnet discovery: when the default Windows-hotspot filter
  matches no clients, SNItch parses `ip addr`/`ifconfig`/`ipconfig` (with a
  socket fallback) and retries with this machine's private IPv4 subnets before
  falling back to `--auto-clients` (with warnings). `--detect-local` opts in
  up front; explicit network options disable the fallback.
- Cached geolocation failures separately from genuine "unknown" answers, with
  `--geo-failure-ttl HOURS` (default 6) so provider outages are retried later
  instead of hammering the API on every run.
- CLI/config thresholds for every heuristic
  (`--beacon-min-events`, `--exfil-min-bytes`, `--dns-min-unique`,
  `--scan-min-ports`, `--tor-*`, …) with positive-value validation.
- Heuristic presets: `--profile {quiet,balanced,aggressive}`; explicit
  thresholds override the preset, and the effective profile is recorded in
  report metadata/About.
- Enrichment: concurrent geolocation/rDNS/RDAP, optional VirusTotal domain
  checks (`--vt-domains`), Tor exit-node checks, `--offline`, `--refresh`,
  `--no-cache`, configurable `--workers`.
- Versioned `enrichment_cache.json` with TTLs and automatic migration from the
  1.x `ip_cache.json`.
- Local heuristics: beaconing, exfiltration, DNS anomalies, port scans,
  Tor-like traffic, cleartext protocols and retransmissions, with severity,
  confidence, score, evidence, MITRE ATT&CK references and remediation
  guidance (`findings.csv`, `summary.txt`, dashboard modal); the finding
  modal pivots to related destinations, domains and flows, and can highlight
  the finding's time window on the timeline.
- New dashboard: themes, map zoom/pan, timeline, charts, searchable/sortable/
  paginated tables (including a per-client view), findings and details modals,
  About page, CSV/JSON exports and a strict CSP. All dynamic values are escaped.
- Best-effort client device names from DHCP hostname options (joined via MAC),
  NetBIOS, mDNS `.local` names and SMTP HELO/EHLO; shown in the Clients tab and
  `data/analysis.json`.
- New outputs: `data/analysis.json`, `domains.csv`, `flows.csv`, `dns.csv`,
  `findings.csv`, `summary.txt` (1.x files are still written).
- `--fail-on` severity gate (exit code 3), `--open`, `--title`, `--no-html`,
  `--quiet`, `--verbose` and JSON config files (`--config`, `snitch.json`).
- Packaging: `pyproject.toml` with a `snitch` console script, package data,
  `MANIFEST.in`, PyInstaller `snitch.spec`, build scripts and GitHub Actions CI.
- 166 unit/integration tests (no tshark or network required).
- Documentation: rewritten `README.md`, `snitch.example.json`, `HANDOFF.md`.

### Changed

- Domain classification now matches on label boundaries, so `example.com`
  matches `cdn.example.com` but not `notexample.com`.
- Geolocation/rDNS/RDAP lookups run concurrently; VirusTotal stays sequential
  for free-tier rate limits.
- Generated JSON is embedded safely in the dashboard (`<`, `>`, `&` escaped).
- Cache, result and packaging artifacts are covered by `.gitignore`.
- The dashboard embeds only the top 5,000 destinations, domains, DNS pairs and
  flows (rows referenced by findings are always kept) so large captures stay
  fast to open. `data/analysis.json` and the CSV exports keep the full data;
  the About page shows each limit and the total row counts.

### Fixed

- `.gitignore` no longer excludes the bundled dashboard template, which is
  required in clean clones and CI builds.
- Wrong dashboard metadata keys (`file`/`source`/`size_bytes`/`tshark_version`)
  and missing `dport` in flow search.
- Malformed newline when writing cached VirusTotal results.
- Summary TXT metadata keys and 1.x cache import edge cases.
- Fields unknown to the installed tshark are now discovered once via
  `tshark -G fields` and skipped with a warning instead of making the whole
  capture fail on older Wireshark versions.

### Compatibility

- Python 3.9+; standard library only.
- Existing commands, output folder names, `data/results.json`, `data/results.csv`
  and `domains/*.txt` remain valid. New files are additive.
- Default client mode is still `192.168.137.0/24` with gateway
  `192.168.137.1`; if that filter finds no clients, SNItch now retries with
  this machine's detected private subnets and then `--auto-clients`.
  Use `--src-ip`/`--all` for explicit control.

## [1.0.0] — Previous release

- Original single-script analyzer: tshark extraction, ipwho.is geolocation,
  VirusTotal IP reputation, SNI/DNS classification, CSV/JSON/TXT output and a
  static HTML dashboard with a world map.
