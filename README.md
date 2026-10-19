# SNItch

A Python tool that, from a network capture (`.pcap`/`.pcapng`), reveals where a
device really talks to: it extracts the destination IPs, **geolocates** them,
checks their **reputation** on VirusTotal, **classifies the domains** by category
(target, chatbot, tracking, device telemetry, other apps…) and builds a
**self-contained HTML dashboard** (world map + tables + charts) that opens in any
browser offline.

The name plays on **SNI** (the hostname that travels in the TLS handshake):
SNItch *snitches* on which servers each app contacts.

Built as part of a network-traffic analysis exercise (Ethical Hacking).

> Author: **@APIGranter** · Runs on Windows, Linux (incl. Kali) and macOS.

## What it does

1. **Picks** the capture file (CLI argument or a graphical file picker).
2. **Extracts** the destination IPs with `tshark`, dedupes them and counts packets.
   By default it isolates only the hotspot clients' traffic (dropping the laptop's own).
3. **Enriches** each IP: geolocation (ipwho.is) and reputation (VirusTotal).
4. **Extracts and classifies the domains** (SNI and DNS) by category.
5. **Saves** the results as CSV, JSON and TXT.
6. **Builds** an HTML dashboard with a host map, summary, per-country and
   per-provider breakdown, domain classification and each IP's reputation (clickable).

## Requirements

- [Python 3](https://www.python.org/downloads/) (no external dependencies: standard library only).
- [Wireshark](https://www.wireshark.org/) / `tshark` installed and on PATH (already present on Kali).
- (Optional) A free VirusTotal API key for the reputation column.
- (Optional, for the graphical file picker) Tkinter: on Kali/Debian, `sudo apt install python3-tk`.

## Usage

Copy `vt_key.example.txt` to `vt_key.txt` and paste your VirusTotal API key inside.

```bash
# Windows
python snitch.py capture.pcapng --target example.com

# Linux (Kali) / macOS
python3 snitch.py capture.pcapng --target example.com
```

With no capture given, a file picker opens (if Tkinter is available).
Shortcuts: **double-click `run.bat`** (Windows) or **`./run.sh`** (Linux/macOS).

> On Linux the default Windows-hotspot filter (`192.168.137.0/24`) does not apply:
> use `--all`, `--src-ip <IP>` or `--hotspot-net`/`--gateway` for your network.

### Useful options

| Option | What for |
|---|---|
| `--target example.com` | Marks that domain as "Target" in the classification. |
| `--all` | Analyze every destination IP, including the laptop's traffic. |
| `--src-ip 192.168.137.80` | Count only that IP's traffic (a specific phone). |
| `--vt-key KEY` | Pass the API key via the command line (instead of the file). |
| `--vt-delay 20` | Seconds to wait between VirusTotal queries (free tier = 16). |
| `--handle @you` | Change the brand shown on the dashboard. |

Each analysis creates a `name_date` subfolder, organized like this:

```
name_date/
├─ dashboard.html        # the file you open
├─ <capture>.pcapng      # copy of the capture
├─ data/                 # results.csv, results.json
└─ domains/              # sni_hosts.txt, dns_queries.txt, classification.txt
```

## Build an executable (.exe)

On Windows: `pyinstaller --onefile --name snitch --add-data "world.geo.json;." snitch.py`
→ the executable lands in `dist\snitch.exe`. Copy your `vt_key.txt` next to it.

On Linux/macOS the `--add-data` separator is `:` instead of `;`:

```bash
pyinstaller --onefile --name snitch --add-data "world.geo.json:." snitch.py
```

> The `.exe` is not committed to the repo: to distribute it, attach it to a GitHub *Release*.

## Security

`vt_key.txt` holds your API key and is in `.gitignore`: **never commit it**.

## Note

Educational project. Use it only on networks and devices you own.
