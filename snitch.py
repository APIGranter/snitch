#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
snitch.py
=====================================================================
SNItch - Network traffic analyzer.

From a capture file (.pcap / .pcapng) it reveals where a device really
talks to: it extracts destination IPs, geolocates them, checks their
reputation on VirusTotal, classifies the domains (SNI/DNS) by category
and builds a self-contained HTML dashboard (world map + tables + charts)
that opens in any browser offline.

The name plays on SNI (the hostname that travels in the TLS handshake):
SNItch snitches on which servers each app contacts.

Pipeline:
  1. Pick a capture file (CLI argument or a graphical file picker).
  2. Extract destination IPs with tshark, dedupe them and count packets.
     By default it keeps only the traffic of the hotspot clients (the
     phone), dropping the laptop's own traffic.
  3. Enrich each unique IP:
       - Geolocation (country, city, lat/lon, ISP, ASN) -> ipwho.is
       - Reputation (engines flagging it as malicious) -> VirusTotal
  4. Extract and classify domains (SNI + DNS) by category.
  5. Save results as CSV, JSON and TXT.
  6. Build a self-contained HTML dashboard.

Only the Python standard library is used (no 'pip install' needed).

Typical use:
    python snitch.py capture.pcapng --target example.com --vt-key YOUR_KEY

Runs on Windows, Linux (incl. Kali) and macOS.

Author: @APIGranter  -  Designed with Claude Code.
=====================================================================
"""

import argparse
import csv
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime

# --------------------------------------------------------------------------
# 1. HELPERS
# --------------------------------------------------------------------------

def log(msg):
    """Print a timestamped message."""
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def base_output_dir():
    """Folder where results and cache are created: next to the .exe when the
    program is frozen with PyInstaller, or next to the script otherwise."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name):
    """Path to a bundled resource (e.g. world.geo.json). Compatible with
    PyInstaller's onefile mode (which unpacks data into sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def pick_file():
    """Open a graphical dialog to choose the .pcap if none was given via CLI."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(
            title="Select the capture file",
            filetypes=[("Network captures", "*.pcap *.pcapng"), ("All files", "*.*")],
        )
        root.destroy()
        return path or None
    except Exception:
        return None


def find_tshark(manual_path=None):
    """Return the path to tshark, trying the usual locations."""
    if manual_path and os.path.isfile(manual_path):
        return manual_path
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "tshark",  # on PATH (Linux/macOS, or Windows with PATH set)
    ]
    for c in candidates:
        try:
            subprocess.run([c, "--version"], capture_output=True, check=True)
            return c
        except Exception:
            continue
    return None


def read_api_key(cli_key, key_file):
    """Resolve the VirusTotal API key: CLI argument > environment > file.

    The file (vt_key.txt by default, next to the script) must hold the key
    on one line; lines starting with # are ignored.
    """
    if cli_key:
        return cli_key.strip()
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"].strip()
    paths = [key_file,
             os.path.join(base_output_dir(), key_file),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), key_file)]
    for p in paths:
        if os.path.isfile(p):
            for line in open(p, encoding="utf-8"):
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    return ""


def is_public_ip(ip):
    """True only for internet-routable IPs (drops private/local ones)."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_multicast
                or obj.is_reserved or obj.is_link_local or obj.is_unspecified)


def make_is_client(hotspot_net, gateway):
    """Return a function is_client(ip): True if the IP belongs to the hotspot
    network and is not the gateway (i.e. a connected device)."""
    try:
        net = ipaddress.ip_network(hotspot_net, strict=False)
    except ValueError:
        log(f"Invalid hotspot network: {hotspot_net}")
        sys.exit(1)

    def is_client(ip):
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return obj in net and str(obj) != gateway
    return is_client


def _should_count(src, mode, src_ip, is_client):
    """Decide whether a packet from source 'src' should be counted."""
    if mode == "all":
        return True
    if mode == "ip":
        return src == src_ip
    return is_client(src)


# --------------------------------------------------------------------------
# 2. DESTINATION IP EXTRACTION (tshark)
# --------------------------------------------------------------------------

def extract_ips(pcap, tshark, mode, src_ip, hotspot_net, gateway):
    """
    Run tshark and return (dst_counter, detected_clients).

    Reads the source and destination of each IP packet and decides which
    destinations to count according to 'mode':
      - "client" (default): only packets whose SOURCE is a device connected
        to the hotspot (IP inside hotspot_net and not the gateway). This drops
        the laptop's own traffic.
      - "ip": only packets whose source is exactly src_ip (the phone).
      - "all": every public destination, without filtering by source.

    'detected_clients' is a Counter {client_ip: packets} so we can show which
    hotspot devices were seen (e.g. the phone).
    """
    is_client = make_is_client(hotspot_net, gateway)
    cmd = [tshark, "-r", pcap, "-Y", "ip", "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
    log(f"Extracting traffic with tshark (mode: {mode}) ...")
    try:
        output = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        log(f"ERROR running tshark: {e.stderr.strip()[:200]}")
        sys.exit(1)

    counter, clients = Counter(), Counter()
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        src, dst = parts[0].strip(), parts[1].strip()
        if is_client(src):
            clients[src] += 1
        if not dst or not is_public_ip(dst):
            continue
        if _should_count(src, mode, src_ip, is_client):
            counter[dst] += 1

    if clients:
        detail = ", ".join(f"{ip} ({n} pkt)" for ip, n in clients.most_common())
        log(f"  Hotspot clients detected: {detail}")
    log(f"  {sum(counter.values())} packets counted -> {len(counter)} unique destination IPs")
    return counter, clients


def extract_domains(pcap, tshark, display_filter, field, mode, src_ip,
                    hotspot_net, gateway):
    """Extract a text field (SNI or DNS name) filtering by the client.
    Return a Counter {value: occurrences}."""
    is_client = make_is_client(hotspot_net, gateway)
    cmd = [tshark, "-r", pcap, "-Y", display_filter, "-T", "fields",
           "-e", "ip.src", "-e", field]
    try:
        output = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError:
        return Counter()
    cont = Counter()
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        src, val = parts[0].strip(), parts[1].strip()
        if val and _should_count(src, mode, src_ip, is_client):
            # a single packet may carry several comma-separated names
            for v in val.split(","):
                v = v.strip()
                if v:
                    cont[v] += 1
    return cont


def save_list(counter, path):
    """Save a Counter as text: one value per line, most frequent first."""
    with open(path, "w", encoding="utf-8") as f:
        for val, n in counter.most_common():
            f.write(f"{val}\n")


# HEURISTIC domain classification by keywords. Order matters: the first
# matching category wins.
_KW_CHATBOT = ("zendesk", "zdassets", "intercom", "tidio", "tawk", "drift",
               "livechat", "crisp", "freshchat", "freshdesk", "landbot",
               "manychat", "openai", "anthropic", "dialogflow", "watson")
_KW_TRACKING = ("doubleclick", "googleads", "pubads", "adservice", "adsystem",
                "scorecardresearch", "adtidy", "criteo", "taboola", "outbrain",
                "google-analytics", "googletagmanager", "analytics", "hotjar",
                "mixpanel", "segment", "appsflyer", "adjust", "branch.io",
                "marketingplatform", "cookiebot", "census-app")
_KW_DEVICE = ("xiaomi", "miui", "mioffice", "firebase", "crashlytics",
              "safebrowsing", "android.apis", "play-fe", "gvt1", "gvt2",
              "mozilla", "firefox", "icloud", "apple.com", "umeng",
              "windowsupdate", "telemetry")
_KW_APPS = ("spotify", "scdn.co", "whatsapp", "instagram", "facebook", "fbcdn",
            "tiktok", "bytedance", "byteplus", "tobsnssdk", "snssdk", "linkedin",
            "snapchat", "telegram", "youtube", "ytimg", "netflix", "twitch",
            "discord", "gonewsvod")
_KW_CDN = ("cloudflare", "akamai", "fastly", "cloudfront", "edgekey", "edgesuite",
           "gstatic", "googleusercontent", "azureedge", "trustpilot")

CAT_TARGET = "Target"
CAT_CHATBOT = "Chatbot / support"
CAT_TRACKING = "Ads / tracking"
CAT_DEVICE = "Device / OS telemetry"
CAT_APPS = "Other apps"
CAT_CDN = "CDN / infrastructure"
CAT_OTHER = "Unclassified"

CATEGORY_ORDER = [CAT_TARGET, CAT_CHATBOT, CAT_TRACKING, CAT_DEVICE,
                  CAT_APPS, CAT_CDN, CAT_OTHER]


def classify_domain(dom, target_base):
    """Return the heuristic category of a domain."""
    d = dom.lower()
    hit = lambda kws: any(k in d for k in kws)
    if hit(_KW_CHATBOT):
        return CAT_CHATBOT
    if target_base and target_base in d:
        return CAT_TARGET
    if hit(_KW_TRACKING):
        return CAT_TRACKING
    if hit(_KW_DEVICE):
        return CAT_DEVICE
    if hit(_KW_APPS):
        return CAT_APPS
    if hit(_KW_CDN):
        return CAT_CDN
    return CAT_OTHER


def classify_domains(sni, target_base):
    """Group SNI domains by category. Return an ordered dict."""
    groups = {}
    for dom, n in sni.most_common():
        cat = classify_domain(dom, target_base)
        groups.setdefault(cat, []).append([dom, n])
    return {c: groups[c] for c in CATEGORY_ORDER if c in groups}


# --------------------------------------------------------------------------
# 3. ENRICHMENT (geolocation + reputation)
# --------------------------------------------------------------------------

def _get_json(url, headers=None, timeout=15):
    """Simple GET returning a JSON dict (or an {_error} dict on failure)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        return {"_error": str(e)}


def geolocate(ip):
    """Geolocate an IP with ipwho.is. Return a normalized dict."""
    d = _get_json(f"https://ipwho.is/{ip}")
    if not d or not d.get("success", False):
        return {"country": "", "cc": "", "region": "", "city": "",
                "lat": None, "lon": None, "isp": "", "asn": ""}
    con = d.get("connection", {}) or {}
    return {
        "country": d.get("country", ""),
        "cc": d.get("country_code", ""),
        "region": d.get("region", ""),
        "city": d.get("city", ""),
        "lat": d.get("latitude"),
        "lon": d.get("longitude"),
        "isp": con.get("isp", "") or con.get("org", ""),
        "asn": f"AS{con.get('asn', '')}" if con.get("asn") else "",
    }


def vt_reputation(ip, api_key):
    """Query VirusTotal. Return (malicious, suspicious, error).

    error is None on success, or a string describing the failure
    (e.g. 'HTTP Error 401' for a bad key, '429' for rate limiting).
    """
    if not api_key:
        return None, None, None
    d = _get_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
    )
    if isinstance(d, dict) and "_error" in d:
        return None, None, d["_error"]
    try:
        stats = d["data"]["attributes"]["last_analysis_stats"]
        return int(stats.get("malicious", 0)), int(stats.get("suspicious", 0)), None
    except (KeyError, TypeError):
        return None, None, "unexpected VirusTotal response"


def enrich(counter, api_key, vt_delay, cache_path):
    """Walk the unique IPs and enrich them, using an on-disk cache."""
    cache = {}
    if os.path.isfile(cache_path):
        try:
            cache = json.load(open(cache_path, encoding="utf-8"))
        except Exception:
            cache = {}

    records = []
    total = len(counter)
    vt_on = bool(api_key)  # turned off if the key turns out to be invalid
    for i, (ip, packets) in enumerate(counter.most_common(), 1):
        reg = dict(cache[ip]) if ip in cache else None
        origin = "cache" if reg else "new"
        if reg is None:
            geo = geolocate(ip)
            reg = {**geo, "vt_malicious": None, "vt_suspicious": None}

        # (Re)query VirusTotal when there is no reputation yet and we have a
        # valid key. Covers IPs cached without VT from a previous run.
        if vt_on and reg.get("vt_malicious") is None:
            mal, sus, err = vt_reputation(ip, api_key)
            if err:
                if "401" in err or "403" in err:
                    log(f"  VirusTotal: invalid key or no permission ({err}). "
                        "Disabling VT for the rest.")
                    vt_on = False
                elif "429" in err:
                    log(f"  VirusTotal: rate limit reached (429). "
                        "Raise --vt-delay or wait.")
                else:
                    log(f"  VirusTotal: error on {ip}: {err}")
            else:
                reg["vt_malicious"], reg["vt_suspicious"] = mal, sus
                time.sleep(vt_delay)  # respect the free API limit (4/min)

        cache[ip] = reg
        json.dump(cache, open(cache_path, "w", encoding="utf-8"))
        vt_val = reg.get("vt_malicious")
        vt_txt = "VT n/a" if vt_val is None else f"VT mal={vt_val}"
        log(f"  ({i}/{total}) {ip} -> {reg['country'] or '?'} / {reg['isp']} | {vt_txt} [{origin}]")

        reg["ip"] = ip
        reg["packets"] = packets
        records.append(reg)
    return records


# --------------------------------------------------------------------------
# 4. OUTPUTS (CSV / JSON)
# --------------------------------------------------------------------------

FIELDS = ["ip", "country", "cc", "region", "city", "lat", "lon",
          "isp", "asn", "packets", "vt_malicious", "vt_suspicious"]


def save_csv(records, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)
    log(f"CSV saved: {path}")


def save_json(records, path):
    json.dump(records, open(path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    log(f"JSON saved: {path}")


# --------------------------------------------------------------------------
# 5. SELF-CONTAINED HTML DASHBOARD
# --------------------------------------------------------------------------

def build_dashboard(records, geojson, out_html, capture_name,
                    handle="@APIGranter", sni=None, groups=None):
    """Build a self-contained HTML dashboard (map, summary, charts, table)."""
    n_ips = len(records)
    countries = sorted({r["country"] for r in records if r["country"]})
    providers = sorted({r["isp"] for r in records if r["isp"]})
    n_mal = sum(1 for r in records if r.get("vt_malicious") not in (None, 0))
    summary = {
        "ips": n_ips,
        "countries": len(countries),
        "providers": len(providers),
        "malicious": n_mal,
        "capture": capture_name,
        "date": f"{datetime.now():%Y-%m-%d %H:%M}",
    }
    data = json.dumps(records, ensure_ascii=False)
    summary_js = json.dumps(summary, ensure_ascii=False)
    sni_js = json.dumps(dict(sni.most_common(20)) if sni else {}, ensure_ascii=False)
    groups_js = json.dumps(groups or {}, ensure_ascii=False)

    html = _HTML_TEMPLATE
    html = html.replace("/*__GEO__*/", geojson)
    html = html.replace("/*__DATA__*/", data)
    html = html.replace("/*__SUMMARY__*/", summary_js)
    html = html.replace("/*__SNI__*/", sni_js)
    html = html.replace("/*__GROUPS__*/", groups_js)
    html = html.replace("__HANDLE__", handle)
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    log(f"Dashboard saved: {out_html}")


# HTML+CSS+JS template. The tokens /*__GEO__*/, /*__DATA__*/, /*__SUMMARY__*/,
# /*__SNI__*/, /*__GROUPS__*/ and __HANDLE__ are replaced with real data.
_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SNItch — Network traffic analysis</title>
<style>
  :root{
    --bg:#0f141b; --panel:#182230; --panel2:#1e2a3a; --line:#2b3a4e;
    --txt:#e6edf5; --muted:#8aa0b6; --accent:#38bdf8; --accent2:#22d3a6;
    --danger:#f87171; --land:#243447; --land-stroke:#34506e;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--txt);
       font-family:"Segoe UI",system-ui,-apple-system,Arial,sans-serif;font-size:15px}
  header{padding:22px 28px;border-bottom:1px solid var(--line);
         background:linear-gradient(90deg,#111a26,#0f141b);position:relative}
  header h1{margin:0;font-size:22px;letter-spacing:.2px}
  header p{margin:4px 0 0;color:var(--muted);font-size:13px}
  .handle{position:absolute;top:22px;right:28px;font-size:13px;font-weight:600;
          color:var(--accent);background:rgba(56,189,248,.12);
          border:1px solid rgba(56,189,248,.35);border-radius:20px;padding:5px 14px}
  .wrap{padding:22px 28px;max-width:1200px;margin:0 auto}
  .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
        padding:16px 18px}
  .card .n{font-size:30px;font-weight:700}
  .card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
  .card.danger .n{color:var(--danger)}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;
         padding:18px;margin-bottom:22px}
  .panel h2{margin:0 0 14px;font-size:15px;font-weight:600;color:var(--txt)}
  svg#map{width:100%;height:auto;display:block;background:#0b1118;border-radius:8px}
  .country{fill:var(--land);stroke:var(--land-stroke);stroke-width:.4}
  .dot{stroke:#0b1118;stroke-width:1;cursor:pointer}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:22px}
  @media(max-width:820px){.grid2{grid-template-columns:1fr}.cards{grid-template-columns:repeat(2,1fr)}}
  .bar-row{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:13px}
  .bar-row .name{width:150px;color:var(--muted);white-space:nowrap;overflow:hidden;
                 text-overflow:ellipsis}
  .bar-row .track{flex:1;background:var(--panel2);border-radius:6px;overflow:hidden;height:16px}
  .bar-row .fill{height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}
  .bar-row .val{width:34px;text-align:right;color:var(--txt)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left}
  th{color:var(--muted);font-weight:600;cursor:pointer;user-select:none}
  tbody tr:hover{background:var(--panel2)}
  .pill{display:inline-block;padding:2px 8px;border-radius:20px;font-size:11px}
  .pill.ok{background:rgba(34,211,166,.15);color:var(--accent2)}
  .pill.bad{background:rgba(248,113,113,.15);color:var(--danger)}
  .pill.na{background:rgba(138,160,182,.15);color:var(--muted)}
  #tip{position:fixed;pointer-events:none;background:#0b1118;border:1px solid var(--line);
       border-radius:8px;padding:8px 10px;font-size:12px;opacity:0;transition:opacity .1s;
       max-width:260px;z-index:9}
  #tip b{color:var(--accent)}
  .row-click{cursor:pointer}
  .clase{margin-bottom:14px}
  .clase-h{font-weight:600;font-size:13px;margin-bottom:7px}
  .clase-h .n{color:var(--muted);font-weight:400;font-size:12px}
  .clase-h .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:middle}
  .chips{display:flex;flex-wrap:wrap;gap:6px}
  .chip{background:var(--panel2);border:1px solid var(--line);border-radius:14px;
        padding:3px 10px;font-size:12px;color:var(--muted)}
  .chip b{color:var(--accent);font-weight:600}
  #modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:none;
         align-items:center;justify-content:center;z-index:20;padding:20px}
  #modal.open{display:flex}
  #modal .box{background:var(--panel);border:1px solid var(--line);border-radius:14px;
              max-width:460px;width:100%;padding:22px 24px;position:relative}
  #modal h3{margin:0 0 2px;font-size:20px;font-family:monospace}
  #modal .cc{color:var(--muted);font-size:13px;margin-bottom:14px}
  #modal .vtbanner{margin:0 0 14px;padding:10px 12px;border-radius:8px;font-size:14px;font-weight:600}
  #modal .vtbanner.ok{background:rgba(34,211,166,.12);color:var(--accent2)}
  #modal .vtbanner.bad{background:rgba(248,113,113,.12);color:var(--danger)}
  #modal .vtbanner.na{background:rgba(138,160,182,.12);color:var(--muted)}
  #modal .kv{display:flex;justify-content:space-between;padding:7px 0;
             border-bottom:1px solid var(--line);font-size:14px}
  #modal .kv span:first-child{color:var(--muted)}
  #modal .acts{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
  #modal a.btn{flex:1;text-align:center;text-decoration:none;padding:10px;border-radius:8px;
               font-size:13px;font-weight:600;background:var(--accent);color:#06121c}
  #modal a.btn.sec{background:var(--panel2);color:var(--txt);border:1px solid var(--line)}
  #modal .x{position:absolute;top:12px;right:16px;cursor:pointer;color:var(--muted);
            font-size:22px;line-height:1;border:none;background:none}
  footer{color:var(--muted);font-size:12px;text-align:center;padding:16px}
</style>
</head>
<body>
<header>
  <h1>SNItch · Network traffic analysis</h1>
  <p id="sub"></p>
  <span class="handle">__HANDLE__</span>
</header>
<div class="wrap">
  <div class="cards" id="cards"></div>

  <div class="panel">
    <h2>Contacted hosts map</h2>
    <svg id="map" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet"></svg>
    <p style="color:var(--muted);font-size:12px;margin:10px 0 0">
      Each dot is a destination IP. Size = packet count.
      <span style="color:var(--danger)">Red</span> = flagged as malicious on VirusTotal.
    </p>
  </div>

  <div class="grid2">
    <div class="panel"><h2>IPs by country</h2><div id="chart-country"></div></div>
    <div class="panel"><h2>IPs by provider</h2><div id="chart-isp"></div></div>
  </div>

  <div class="panel">
    <h2>Contacted domains (SNI)</h2>
    <div id="chart-sni"></div>
    <p style="color:var(--muted);font-size:12px;margin:10px 0 0">
      Domains seen in the TLS handshake. If few show up, the app uses encrypted SNI (ECH).
    </p>
  </div>

  <div class="panel">
    <h2>Domain classification</h2>
    <div id="chart-groups"></div>
    <p style="color:var(--muted);font-size:12px;margin:12px 0 0">
      Heuristic keyword classification: separates the target from trackers,
      the device's own telemetry and other apps. Indicative, not exact.
    </p>
  </div>

  <div class="panel">
    <h2>Host details</h2>
    <table id="tabla">
      <thead><tr>
        <th data-k="ip">IP</th><th data-k="country">Country</th><th data-k="city">City</th>
        <th data-k="isp">Provider</th><th data-k="asn">ASN</th>
        <th data-k="packets">Packets</th><th data-k="vt">VirusTotal</th>
      </tr></thead>
      <tbody></tbody>
    </table>
  </div>
</div>
<footer>Generated by SNItch &middot; data: ipwho.is + VirusTotal &middot; <b style="color:var(--accent)">__HANDLE__</b></footer>
<div id="tip"></div>
<div id="modal"><div class="box">
  <button class="x" id="modalX">&times;</button>
  <h3 id="m-ip"></h3>
  <div class="cc" id="m-loc"></div>
  <div id="m-vt" class="vtbanner"></div>
  <div id="m-kv"></div>
  <div class="acts" id="m-acts"></div>
</div></div>

<script>
const GEO = /*__GEO__*/;
const DATA = /*__DATA__*/;
const SUMMARY = /*__SUMMARY__*/;
const SNI = /*__SNI__*/;
const GROUPS = /*__GROUPS__*/;

// ---- equirectangular projection: [lon,lat] -> [x,y] in a 1000x500 viewBox
const W=1000, H=500;
const proj = (lon,lat)=>[(lon+180)/360*W, (90-lat)/180*H];

// ---- header and summary cards
document.getElementById('sub').textContent =
  `Capture: ${SUMMARY.capture}  ·  ${SUMMARY.date}`;
const cards=[
  ['Unique IPs',SUMMARY.ips,''],
  ['Countries',SUMMARY.countries,''],
  ['Providers',SUMMARY.providers,''],
  ['Malicious IPs',SUMMARY.malicious,SUMMARY.malicious?'danger':''],
];
document.getElementById('cards').innerHTML = cards.map(
  c=>`<div class="card ${c[2]}"><div class="n">${c[1]}</div><div class="l">${c[0]}</div></div>`
).join('');

// ---- draw countries
const map=document.getElementById('map');
const SVGNS='http://www.w3.org/2000/svg';
function pathFrom(coords){ // coords = array of rings [[ [lon,lat],... ]]
  let d='';
  for(const ring of coords){
    ring.forEach((pt,i)=>{const [x,y]=proj(pt[0],pt[1]);
      d+=(i?'L':'M')+x.toFixed(1)+' '+y.toFixed(1);});
    d+='Z';
  }
  return d;
}
for(const f of GEO.features){
  const g=f.geometry; if(!g) continue;
  const polys = g.type==='Polygon' ? [g.coordinates] : g.coordinates;
  let d='';
  for(const poly of polys) d+=pathFrom(poly);
  const p=document.createElementNS(SVGNS,'path');
  p.setAttribute('d',d); p.setAttribute('class','country');
  map.appendChild(p);
}

// ---- IP markers
const tip=document.getElementById('tip');
const maxPkt=Math.max(1,...DATA.map(d=>d.packets));
for(const r of DATA){
  if(r.lat==null||r.lon==null) continue;
  const [x,y]=proj(r.lon,r.lat);
  const mal=r.vt_malicious!=null && r.vt_malicious>0;
  const radius=4+6*Math.sqrt(r.packets/maxPkt);
  const c=document.createElementNS(SVGNS,'circle');
  c.setAttribute('cx',x); c.setAttribute('cy',y); c.setAttribute('r',radius);
  c.setAttribute('class','dot');
  c.setAttribute('fill', mal?'#f87171':'#38bdf8');
  c.setAttribute('fill-opacity','.85');
  c.addEventListener('mousemove',e=>{
    tip.style.opacity=1; tip.style.left=(e.clientX+14)+'px'; tip.style.top=(e.clientY+14)+'px';
    const vt = r.vt_malicious==null?'no data':(r.vt_malicious+' engines');
    tip.innerHTML=`<b>${r.ip}</b><br>${r.city?r.city+', ':''}${r.country||'?'}<br>`+
      `${r.isp||''} ${r.asn?'('+r.asn+')':''}<br>Packets: ${r.packets} · VT: ${vt}`;
  });
  c.addEventListener('mouseleave',()=>tip.style.opacity=0);
  c.addEventListener('click',()=>openDetail(r));
  map.appendChild(c);
}

// ---- bar charts (grouped)
function bars(id,counter){
  const ent=Object.entries(counter).sort((a,b)=>b[1]-a[1]).slice(0,10);
  const max=Math.max(1,...ent.map(e=>e[1]));
  document.getElementById(id).innerHTML = ent.map(([k,v])=>
    `<div class="bar-row"><div class="name" title="${k}">${k||'(unknown)'}</div>`+
    `<div class="track"><div class="fill" style="width:${v/max*100}%"></div></div>`+
    `<div class="val">${v}</div></div>`).join('') || '<p style="color:var(--muted)">No data</p>';
}
const byCountry={}, byIsp={};
for(const r of DATA){
  byCountry[r.country]=(byCountry[r.country]||0)+1;
  byIsp[r.isp]=(byIsp[r.isp]||0)+1;
}
bars('chart-country',byCountry);
bars('chart-isp',byIsp);
bars('chart-sni',SNI);

// ---- domain classification by category
const COLORS={
  "Target":"#38bdf8","Chatbot / support":"#22d3a6","Ads / tracking":"#f87171",
  "Device / OS telemetry":"#fbbf24","Other apps":"#a78bfa",
  "CDN / infrastructure":"#60a5fa","Unclassified":"#8aa0b6"};
(function(){
  const cont=document.getElementById('chart-groups');
  let out='';
  for(const cat in GROUPS){
    const arr=GROUPS[cat]; if(!arr||!arr.length) continue;
    const col=COLORS[cat]||'#8aa0b6';
    out+=`<div class="clase"><div class="clase-h">`+
         `<span class="dot" style="background:${col}"></span>${cat} `+
         `<span class="n">(${arr.length})</span></div><div class="chips">`+
         arr.map(x=>`<span class="chip">${x[0]} <b>${x[1]}</b></span>`).join('')+
         `</div></div>`;
  }
  cont.innerHTML=out||'<p style="color:var(--muted)">No SNI domains (encrypted SNI or no TLS traffic).</p>';
})();

// ---- table (click a header to sort)
const tbody=document.querySelector('#tabla tbody');
function vtPill(r){
  if(r.vt_malicious==null) return '<span class="pill na">no data</span>';
  if(r.vt_malicious>0) return `<span class="pill bad">${r.vt_malicious} malicious</span>`;
  return '<span class="pill ok">clean</span>';
}
function paint(rows){
  tbody.innerHTML=rows.map(r=>`<tr class="row-click" data-ip="${r.ip}" title="View detail">
    <td>${r.ip}</td><td>${r.country||''}</td><td>${r.city||''}</td>
    <td>${r.isp||''}</td><td>${r.asn||''}</td><td>${r.packets}</td><td>${vtPill(r)}</td>
  </tr>`).join('');
}
let sort={k:'packets',asc:false};
function doSort(){
  const k=sort.k;
  const rows=[...DATA].sort((a,b)=>{
    let va=k==='vt'?(a.vt_malicious??-1):a[k], vb=k==='vt'?(b.vt_malicious??-1):b[k];
    if(typeof va==='string') return sort.asc?va.localeCompare(vb):vb.localeCompare(va);
    return sort.asc?(va-vb):(vb-va);
  });
  paint(rows);
}
document.querySelectorAll('#tabla th').forEach(th=>{
  th.addEventListener('click',()=>{
    const k=th.dataset.k; sort.asc = sort.k===k ? !sort.asc : false; sort.k=k; doSort();
  });
});
doSort();

// ---- detail panel when clicking a row or a map dot
function openDetail(r){
  document.getElementById('m-ip').textContent = r.ip;
  document.getElementById('m-loc').textContent =
    [r.city, r.region, r.country].filter(Boolean).join(', ') || 'Unknown location';
  const vt=document.getElementById('m-vt');
  if(r.vt_malicious==null){ vt.className='vtbanner na'; vt.textContent='VirusTotal: no data'; }
  else if(r.vt_malicious>0){ vt.className='vtbanner bad';
    vt.textContent=`\u26A0 VirusTotal: ${r.vt_malicious} engine(s) flag it as malicious`+
      (r.vt_suspicious?`, ${r.vt_suspicious} suspicious`:''); }
  else { vt.className='vtbanner ok'; vt.textContent='VirusTotal: clean (0 detections)'; }
  const kv=[['Provider',r.isp||'-'],['ASN',r.asn||'-'],['Country',r.country||'-'],
            ['City',r.city||'-'],['Packets',r.packets],
            ['Coordinates', r.lat!=null?`${r.lat}, ${r.lon}`:'-']];
  document.getElementById('m-kv').innerHTML=kv.map(
    x=>`<div class="kv"><span>${x[0]}</span><span>${x[1]}</span></div>`).join('');
  const acts=[`<a class="btn" target="_blank" rel="noopener" `+
              `href="https://www.virustotal.com/gui/ip-address/${r.ip}">View VirusTotal report</a>`];
  if(r.lat!=null) acts.push(`<a class="btn sec" target="_blank" rel="noopener" `+
      `href="https://www.openstreetmap.org/?mlat=${r.lat}&mlon=${r.lon}#map=6/${r.lat}/${r.lon}">View location</a>`);
  document.getElementById('m-acts').innerHTML=acts.join('');
  document.getElementById('modal').classList.add('open');
}
const modal=document.getElementById('modal');
document.getElementById('modalX').onclick=()=>modal.classList.remove('open');
modal.addEventListener('click',e=>{ if(e.target.id==='modal') modal.classList.remove('open'); });
document.addEventListener('keydown',e=>{ if(e.key==='Escape') modal.classList.remove('open'); });
tbody.addEventListener('click',e=>{
  const tr=e.target.closest('tr'); if(!tr||!tr.dataset.ip) return;
  const r=DATA.find(d=>d.ip===tr.dataset.ip); if(r) openDetail(r);
});
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# 6. MAIN
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Analyze a network capture: geolocate the destination IPs, "
                    "check their reputation, classify domains and build an HTML dashboard.")
    ap.add_argument("capture", nargs="?", help="Capture file .pcap/.pcapng (if omitted, a file picker opens)")
    ap.add_argument("--vt-key", default="",
                    help="VirusTotal API key (takes precedence over the file)")
    ap.add_argument("--vt-key-file", default="vt_key.txt",
                    help="File holding the API key (default: vt_key.txt next to the script)")
    ap.add_argument("--tshark", help="Path to tshark if it is not auto-detected")
    ap.add_argument("--target", default="",
                    help="Target domain (e.g. example.com) to mark as 'Target' in the classification")
    ap.add_argument("--src-ip", help="Exact phone IP to count only its traffic (ip.src)")
    ap.add_argument("--all", action="store_true",
                    help="Count ALL destination IPs, without filtering by source (includes the laptop)")
    ap.add_argument("--hotspot-net", default="192.168.137.0/24",
                    help="Hotspot network (default is the Windows one: 192.168.137.0/24)")
    ap.add_argument("--gateway", default="192.168.137.1",
                    help="Laptop/gateway IP to exclude (default 192.168.137.1)")
    ap.add_argument("--vt-delay", type=float, default=16.0,
                    help="Seconds to wait between VirusTotal queries (free tier = 16)")
    ap.add_argument("--out-dir", default="",
                    help="Base folder where the analysis subfolder is created "
                         "(default: the script/exe folder)")
    ap.add_argument("--handle", default="@APIGranter",
                    help="Your handle/brand to show on the dashboard")
    args = ap.parse_args()

    # 1. Capture file
    pcap = args.capture or pick_file()
    if not pcap or not os.path.isfile(pcap):
        log("No valid capture file provided.")
        sys.exit(1)
    name = os.path.basename(pcap)
    log(f"Capture: {pcap}")

    # 2. tshark
    tshark = find_tshark(args.tshark)
    if not tshark:
        log("tshark not found. Install Wireshark or pass --tshark PATH.")
        sys.exit(1)

    # 3. Extraction
    if args.all:
        mode = "all"
    elif args.src_ip:
        mode = "ip"
    else:
        mode = "client"
    counter, clients = extract_ips(pcap, tshark, mode, args.src_ip,
                                   args.hotspot_net, args.gateway)
    if not counter:
        if mode == "client" and not clients:
            log("No hotspot clients detected on the network "
                f"({args.hotspot_net}). Check it with --hotspot-net, "
                "pin the phone with --src-ip, or use --all.")
        else:
            log("No public destination IPs found with this filter.")
        sys.exit(1)

    # 4. Analysis folder: <name>_<date> inside the base folder
    base = os.path.splitext(name)[0]
    base_dir = args.out_dir or base_output_dir()
    date = f"{datetime.now():%Y-%m-%d_%H%M%S}"
    run_dir = os.path.join(base_dir, f"{base}_{date}")
    data_dir = os.path.join(run_dir, "data")
    domains_dir = os.path.join(run_dir, "domains")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(domains_dir, exist_ok=True)
    log(f"Results folder: {run_dir}")

    # Copy the capture into the analysis folder
    try:
        shutil.copy2(pcap, os.path.join(run_dir, name))
        log("Capture copy saved into the folder.")
    except (OSError, shutil.SameFileError) as e:
        log(f"WARNING: could not copy the capture ({e}).")

    # Domains: SNI (HTTPS) and DNS queries, filtered by the same client
    sni = extract_domains(pcap, tshark, "tls.handshake.extensions_server_name",
                          "tls.handshake.extensions_server_name", mode, args.src_ip,
                          args.hotspot_net, args.gateway)
    dns = extract_domains(pcap, tshark, "dns.flags.response==0 && dns.qry.name",
                          "dns.qry.name", mode, args.src_ip,
                          args.hotspot_net, args.gateway)
    save_list(sni, os.path.join(domains_dir, "sni_hosts.txt"))
    save_list(dns, os.path.join(domains_dir, "dns_queries.txt"))
    log(f"  SNI: {len(sni)} unique domains | DNS: {len(dns)} unique queries")

    # Heuristic classification of the SNI domains by category
    target_base = args.target.lower().split(".")[0] if args.target else ""
    groups = classify_domains(sni, target_base)
    with open(os.path.join(domains_dir, "classification.txt"), "w", encoding="utf-8") as f:
        for cat, items in groups.items():
            f.write(f"== {cat} ({len(items)}) ==\n")
            for dom, n in items:
                f.write(f"  {dom}  ({n})\n")
            f.write("\n")
    if groups:
        log("  Classification: " + ", ".join(f"{c}={len(v)}" for c, v in groups.items()))

    # 5. Enrichment (the cache stays in the base folder, shared across analyses,
    #    so IPs are not re-queried and the VirusTotal quota is preserved)
    api_key = read_api_key(args.vt_key, args.vt_key_file)
    if not api_key:
        log("WARNING: no API key (no --vt-key, no VT_API_KEY, no vt_key.txt). "
            "VirusTotal will not be queried.")
    else:
        log("VirusTotal API key loaded.")
    cache = os.path.join(base_dir, "ip_cache.json")
    records = enrich(counter, api_key, args.vt_delay, cache)

    # 6. Outputs (inside data/)
    save_csv(records, os.path.join(data_dir, "results.csv"))
    save_json(records, os.path.join(data_dir, "results.json"))

    # 7. Dashboard
    geojson_path = resource_path("world.geo.json")
    try:
        geojson = open(geojson_path, encoding="utf-8").read()
    except FileNotFoundError:
        log(f"Missing world.geo.json ({geojson_path}).")
        sys.exit(1)
    build_dashboard(records, geojson, os.path.join(run_dir, "dashboard.html"),
                    name, args.handle, sni, groups)

    log(f"Done. Results in: {run_dir}")
    log("Open dashboard.html in your browser.")


if __name__ == "__main__":
    main()
