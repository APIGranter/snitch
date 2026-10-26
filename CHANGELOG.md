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
- Finding details explain why the finding fired: observed values (contact
  events, interval CV, upload volume, DNS entropy, ports, …) are compared with
  the active thresholds in a compact bar view, with raw evidence behind a
  collapsible block.
- Findings tab filters by severity, confidence and finding category (plus free
  text search) and shows how many rows match. An **Include allowlisted** toggle
  mixes suppressed findings back in with an `allowlisted` badge; their detail
  modal explains that they are excluded from totals.
- About tab threshold tuner: edit the profile or individual heuristic values,
  preview the equivalent CLI command, copy it and download a matching
  `snitch.json`.
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
- 224 unit/integration tests (no network required), including end-to-end
  tests that run the real tshark on generated captures (skipped when tshark
  is missing).
- Each client records why it was selected (`selected_by`: hotspot network,
  `src-ip`, detected subnet, auto, or IPv6 via MAC), shown as a tag in the
  Clients tab; the About page and `summary.txt` show the client selection and
  whether a fallback was used.
- IPv6 traffic of selected clients is attributed to them by MAC address.
- Documentation: rewritten `README.md`, `snitch.example.json`.

### Changed

- Domain classification now matches on label boundaries, so `example.com`
  matches `cdn.example.com` but not `notexample.com`.
- Geolocation/rDNS/RDAP lookups run concurrently; VirusTotal stays sequential
  for free-tier rate limits.
- Generated JSON is embedded safely in the dashboard (`<`, `>`, `&` escaped).
- Cache, result and packaging artifacts are covered by `.gitignore`.
- The dashboard embeds only the top 5,000 destinations, domains, DNS pairs and
  flows and 500 findings (rows referenced by findings are always kept) so
  large captures stay fast to open. `data/analysis.json` and the CSV exports
  keep the full data; the About page shows each limit and the total row counts.
- Client fallback: when the default hotspot network matches nothing, capture
  **files** go straight to `--auto-clients`; this computer's network
  interfaces are only searched for live captures or with `--detect-local`.
  All fallback candidates are evaluated in the same tshark pass.
- Beaconing to telemetry/update/analytics destinations is low severity.
- VirusTotal key lookup order documented as CLI > `VT_API_KEY` > `vt_key.txt`
  (matching the code).
- Warnings go to stderr; ANSI colours are enabled on the Windows console.
- Enrichment uses one shared cache, saved once; Ctrl-C during enrichment
  writes the report with partial data.

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
- VirusTotal/Tor-exit findings were computed and discarded; they now reach the
  dashboard, CSV/TXT outputs and `--fail-on`, and honour `--allowlist`.
- `flows.csv`, `dns.csv`, `findings.csv` and `analysis.json` were silently
  truncated at 5,000/500 rows; the summary under-counted findings.
- DNS: queries from unselected hosts (including the hotspot PC's own upstream
  lookups) were counted for the selected clients; each lookup was counted
  twice (query + response); `NULL`/`HINFO`/`OPT` types were unnamed, so NULL
  tunnelling was missed; response time kept only the last value (now
  average + max).
- Carrier-grade NAT/Tailscale addresses (100.64.0.0/10) were treated as
  internet destinations (geolocated and sent to VirusTotal).
- Packets with two IP headers (ICMP errors, tunnels) were dropped, and ICMP
  errors were counted as TCP/UDP on the quoted port.
- In `--all` mode a client's own global IPv6 address could become a
  "destination" (and be sent to enrichment services).
- Local subnet discovery crashed on non-English Windows (`ipconfig` output in
  the OEM code page) and only understood English labels.
- VirusTotal: a rate-limited IP was never retried; an exhausted daily quota
  stalled the run for hours; three "not found" answers disabled VT.
- Reverse DNS had no overall timeout; RDAP failures were never cached; the
  dashboard's RDAP link ignored `--rdap-url`.
- A capture string equal to a dashboard placeholder (e.g. a User-Agent of
  `/*__GEO__*/`) broke the dashboard.
- Config values skipped validation (an invalid `fail_on` crashed after the
  full analysis); `_comment` keys produced a warning on every run.
- `--min-packets` did not filter beaconing events; banner versions such as
  `1.3.5e` were taken as hostnames; the retransmission rate used all packets
  instead of TCP packets; cleartext evidence listed every port.
- `--detect-local` could trigger an identical second tshark pass.
- The output folder is created before enrichment, so an unwritable
  `--out-dir` fails immediately; `--open` builds a proper `file://` URI.
- Classification: `ads.*`/`pagead*`/`ogads*`/`adtrafficquality` hosts are
  Ads/tracking even under vendor suffixes; added `google.com`,
  `withgoogle.com`, `mozilla.com`, `msftconnecttest.com`, `msedge.net`,
  `arpa`; `clients6.google.com` is no longer "Software updates".

### Compatibility

- Python 3.9+; standard library only.
- Existing commands, output folder names, `data/results.json`, `data/results.csv`
  and `domains/*.txt` remain valid. New files are additive.
- Default client mode is still `192.168.137.0/24` with gateway
  `192.168.137.1`; if that filter finds no clients, SNItch falls back to
  `--auto-clients` (live captures try this machine's detected private subnets
  first). Use `--src-ip`/`--all` for explicit control.
- `--duration`, `--packet-limit`, `--min-packets` and `--workers` now reject
  zero/negative values (exit code 2).

## [1.0.0] — Previous release

- Original single-script analyzer: tshark extraction, ipwho.is geolocation,
  VirusTotal IP reputation, SNI/DNS classification, CSV/JSON/TXT output and a
  static HTML dashboard with a world map.
