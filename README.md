# SNItch

**SNItch** turns a packet capture (`.pcap` / `.pcapng`) into a clear picture of
where a device *really* talks to. It extracts destinations with `tshark`,
geolocates them, checks their reputation on VirusTotal, classifies the domains
seen in TLS SNI and DNS, runs local traffic heuristics, and builds a
**self-contained offline HTML dashboard** — map, timeline, charts, searchable
tables and findings.

The name plays on **SNI** (the hostname sent in the TLS handshake): SNItch
*snitches* on the servers each app contacts.

> Author: **@APIGranter** · MIT licensed · Educational / defensive use only.
> Runs on Linux (incl. Kali), Windows and macOS. No Python dependencies.

---

## What it does

1. **Reads** a capture once with a streaming `tshark` pass (or captures live).
2. **Extracts** destinations, clients, ports, protocols, DNS queries, TLS SNI
   and HTTP hosts, and aggregates them into flows.
3. **Enriches** IPs with geolocation, reverse DNS, optional RDAP ownership and
   VirusTotal reputation; optionally checks the Tor exit-node list.
4. **Classifies** domains (target, chatbot, tracking, analytics, device
   telemetry, updates, apps, email, security/VPN, CDN, cloud, unclassified).
5. **Runs local heuristics** for beaconing, possible exfiltration, DNS
   anomalies, port scans, Tor-like traffic, cleartext protocols and high
   retransmission rates.
6. **Writes** JSON/CSV/TXT reports and a single-file HTML dashboard that works
   offline (no CDN, no external assets).

---

## Requirements

- **Python 3.9+** — standard library only.
- **Wireshark / `tshark`** installed and on `PATH` (or pass `--tshark PATH`).
- Optional: a free **VirusTotal API key** for reputation checks.
- Optional: **Tkinter** for the graphical file picker when no capture is given
  (`sudo apt install python3-tk` on Kali/Debian).

---

## Install

```bash
git clone https://github.com/APIGranter/snitch.git
cd snitch
python3 snitch.py --help
```

Or install it as a command:

```bash
python3 -m pip install .
snitch --help
# development install:
python3 -m pip install -e .
```

`python3 -m snitchlib` is equivalent to `python3 snitch.py`.

---

## Quick start

```bash
# Analyze a capture, only the traffic of one client
python3 snitch.py capture.pcapng --src-ip 192.168.1.42 --open

# Follow one domain and mark it as the target
python3 snitch.py capture.pcapng --target example.com --open

# Analyze everything, without VirusTotal (fast, offline-friendly)
python3 snitch.py capture.pcapng --all --no-vt

# Live capture for 60 seconds on eth0
python3 snitch.py --live eth0 --duration 60 --open

# List capture interfaces
python3 snitch.py --list-interfaces
```

With no capture argument, a file picker opens if Tkinter is available.

### VirusTotal key

Provide it in one of these ways (first match wins):

1. `--vt-key KEY`
2. `vt_key.txt` next to where you run the command (see `vt_key.example.txt`)
3. the `VT_API_KEY` environment variable

Free-tier keys are limited to **4 requests/minute**, so the default delay is
16 seconds between requests. Use `--no-vt` to skip checks entirely, or
`--vt-domains N` to also check up to `N` domains (IP checks are always done
when a key is present).

---

## Choosing what to analyze

By default SNItch assumes the Windows-hotspot layout used by the original
project: clients in `192.168.137.0/24` and gateway `192.168.137.1`. On other
networks pick one of:

| Option | Meaning |
|---|---|
| `--src-ip IP[,IP]` | Only count traffic from these client IPs. |
| `--auto-clients` | Treat every private/local address as a client (except gateways). |
| `--all` | Count every public destination, no client filtering. |
| `--hotspot-net CIDR[,CIDR]` | Change the client network(s) for the default mode. |
| `--gateway IP[,IP]` | Addresses never counted as clients. |
| `--exclude-ip IP[,CIDR]` | Exclude addresses/networks (repeatable). |
| `--min-packets N` | Ignore destinations seen in fewer than `N` packets. |
| `--allowlist PATH` | Suppress findings for known-good IPs/CIDRs/domains. |
| `--display-filter FILTER` | Extra tshark display filter, e.g. `tcp.port == 443`. |
| `--since` / `--until` | Time range (ISO-8601 or epoch seconds). |

### Suppress known-good traffic

Chatty updaters, analytics endpoints or your own infrastructure can drown the
findings. Pass a text file with one entry per line (see
`allowlist.example.txt`):

```bash
python3 snitch.py capture.pcapng --allowlist allowlist.txt
```

```
# IPs, CIDRs, IPv6 and domain suffixes all work
203.0.113.10
198.51.100.0/24
example.com          # also matches cdn.example.com, not notexample.com
*.telemetry.example.org
```

A finding is suppressed when one of its domains matches, or when **every** IP
it references matches. Matching is boundary-aware. Suppressed findings are
counted in a warning shown on the dashboard and in `summary.txt`; raw
destinations/domains are still reported normally. Invalid entries fail fast
with exit code 2.

---

## Output

Each run creates a timestamped folder:

```
<capture>_YYYY-MM-DD_HHMMSS/
├─ dashboard.html          # open this — works offline
├─ <capture>.pcapng        # copy of the analyzed capture
├─ data/
│  ├─ analysis.json        # full machine-readable report (v2)
│  ├─ results.json         # 1.x-compatible flat results
│  ├─ results.csv          # one row per destination
│  ├─ domains.csv          # one row per domain
│  ├─ flows.csv            # one row per aggregated flow
│  ├─ dns.csv              # one row per query name/type
│  ├─ findings.csv         # one row per finding
│  └─ summary.txt          # human-readable summary
└─ domains/
   ├─ sni_hosts.txt        # TLS SNI / HTTP hosts
   ├─ dns_queries.txt      # DNS names
   └─ classification.txt   # domains grouped by category
```

Use `--out-dir DIR` to choose the parent folder, `--no-html` to skip the
dashboard, and `--title` / `--handle` to brand the report.

### Dashboard

- World map with destination markers (zoom/pan, click for details)
- Summary cards, traffic timeline and protocol/country/category charts
- Searchable, sortable, paginated tables: destinations, domains, flows, DNS,
  findings
- Findings panel with severity, confidence and evidence
- About page with capture metadata and the exact filter used
- Strict Content-Security-Policy; **no network requests** at runtime

---

## Enrichment

| Option | Effect |
|---|---|
| `--no-geo` | Skip geolocation lookups. |
| `--no-rdns` | Skip reverse-DNS lookups. |
| `--rdap` | Look up network ownership via RDAP. |
| `--no-vt` | Skip VirusTotal (cached results are still used). |
| `--check-tor-exits` | Download the Tor exit list and flag matching IPs. |
| `--offline` | No network requests at all; use cache only. |
| `--refresh` | Ignore cached values and query again. |
| `--no-cache` | Do not read or write the enrichment cache. |
| `--workers N` | Concurrent workers for geo/rDNS/RDAP (default 8). |

Results are cached in `enrichment_cache.json` in the output base folder, with a
versioned schema and TTLs. A 1.x `ip_cache.json` is imported automatically on
first run. VirusTotal requests stay sequential to respect free-tier limits.

---

## Configuration file

Any long option can be set in `snitch.json` (or `--config PATH`) using
underscores instead of dashes. CLI flags override the file. Start from
`snitch.example.json`:

```json
{
  "target": "example.com",
  "auto_clients": true,
  "allowlist": "allowlist.txt",
  "vt_domains": 25,
  "workers": 8,
  "fail_on": "high"
}
```

CLI options that are flags (e.g. `--all`) accept `true`/`false` in JSON.
`snitch.json` is git-ignored because it may contain a key.

---

## Findings and exit codes

Heuristics look for periodic beaconing, possible data exfiltration, DNS
anomalies (long/high-entropy names, TXT abuse), horizontal port scans,
Tor/anonymising-proxy traffic, cleartext application protocols and elevated
TCP retransmissions. VirusTotal and the Tor exit list add reputation findings.

`--fail-on {none,info,low,medium,high,critical}` makes SNItch exit with
**3** when a finding reaches that severity — useful in CI or scripts.

| Exit code | Meaning |
|---|---|
| `0` | Success. |
| `1` | No usable capture/destinations, or an unexpected runtime error. |
| `2` | Bad arguments, missing `tshark`, or unsupported input. |
| `3` | `--fail-on` threshold reached. |
| `130` | Interrupted (Ctrl-C). |

---

## Build a standalone executable

```bash
# Linux/macOS
./scripts/build.sh

# Windows
scripts\build.bat
```

This uses `snitch.spec` and PyInstaller to produce `dist/snitch` (or
`dist\snitch.exe`). The dashboard template and `world.geo.json` are embedded.
Put `vt_key.txt` next to the executable if you want reputation checks. Builds
are not committed: attach them to a GitHub *Release*.

---

## Development

```bash
python3 -m unittest discover -s tests -v   # 92 tests, no network/tshark needed
python3 -m build                           # wheel + sdist
```

Layout:

```
snitch.py                 thin CLI wrapper (backwards compatible)
snitchlib/
  cli.py                  argument parsing, config, pipeline, exit codes
  capture.py              tshark discovery, live capture, filters
  extract.py              single streaming pass, synthetic rows, aggregation
  allowlist.py            parser/matcher for finding suppression
  classify.py             domain categories and base-domain logic
  analyze.py              beaconing/exfil/DNS/port-scan/Tor/cleartext heuristics
  enrich.py               geo, rDNS, RDAP, VirusTotal, Tor exits, cache
  report.py               JSON/CSV/TXT + dashboard assembly
  models.py, util.py      dataclasses, logging, JSON/cache/path helpers
  templates/dashboard.html
  world.geo.json
tests/                    unit and integration tests (unittest)
scripts/                  PyInstaller build helpers
```

CI runs the test suite on Python 3.9/3.11/3.13 (Linux) plus Windows and macOS,
then builds and installs the wheel. See `HANDOFF.md` for the current status and
the backlog.

---

## Security and privacy

- The capture copy stays in the results folder; delete it if it is sensitive.
- `vt_key.txt`, `snitch.json` and generated result folders are git-ignored.
- The dashboard embeds all data and assets locally — it loads nothing from the
  internet and ships with a restrictive CSP.
- Enrichment sends destination IPs/domains to third parties (ipwho.is, DNS,
  RDAP, VirusTotal) unless you pass `--offline`/`--no-geo`/`--no-vt`.
- Educational project: only capture and analyze networks/devices you own or
  are authorized to test.
