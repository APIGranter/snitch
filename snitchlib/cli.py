# -*- coding: utf-8 -*-
"""Command-line interface and pipeline orchestration for SNItch.

The original release was a single 900-line script that invoked tshark several
times and wrote its own HTML.  This module keeps the same command line (and
output folder layout) while running a single streaming extraction pass and
delegating the work to :mod:`snitchlib`.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import urllib.parse
from dataclasses import replace
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence

from . import APP_NAME, __version__
from .analyze import (
    HEURISTIC_PROFILES, AnalysisOptions, apply_categories, profile_thresholds,
    run_heuristics, run_threat_intel, sort_findings,
)
from .allowlist import Allowlist, AllowlistError
from .asndb import AsnDatabase, apply_asn_db
from .capture import (
    TsharkError, build_display_filter, capture_info, default_live_path,
    find_tshark, iter_packets, list_interfaces, live_capture, platform_note,
    resolve_interface, tshark_version, validate_capture,
)
from .classify import normalize_target
from .enrich import EnrichOptions, enrich
from .extract import ExtractionOptions, extract, parse_networks
from .models import SEVERITY_ORDER
from .netinfo import format_networks, local_ipv4_networks
from .report import build_dashboard, build_report, save_all
from .util import (
    Logger, base_output_dir, human_bytes, human_duration, iso_utc,
    load_json, open_in_browser, parse_time_arg, safe_filename, set_default_logger,
    sha256_file, split_csv_arg,
)

#: Defaults are intentionally the same as SNItch 1.x so existing scripts keep
#: working.  They can be overridden with a JSON config file or on the CLI.
DEFAULTS: Dict[str, Any] = {
    "handle": "@APIGranter",
    "title": "",
    "target": "",
    "hotspot_net": "192.168.137.0/24",
    "gateway": "192.168.137.1",
    "src_ip": "",
    "all": False,
    "auto_clients": False,
    "detect_local": False,
    "exclude_ip": None,
    "min_packets": 1,
    "allowlist": "",
    "tshark": None,
    "vt_key": "",
    "vt_key_file": "vt_key.txt",
    "vt_delay": 16.0,
    "vt_domains": 0,
    "workers": 8,
    "geo_failure_ttl": 6.0,
    "no_geo": False,
    "no_vt": False,
    "no_rdns": False,
    "offline": False,
    "refresh": False,
    "no_cache": False,
    "rdap": False,
    "rdap_url": None,
    "asn_db": "",
    "check_tor_exits": False,
    "no_html": False,
    "open": False,
    "fail_on": "none",
    "quiet": False,
    "verbose": False,
    "out_dir": "",
    "duration": None,
    "packet_limit": None,
    "since": None,
    "until": None,
    "display_filter": "",
    "config": None,
    "profile": "balanced",
    "beacon_min_events": None,
    "beacon_max_cv": None,
    "beacon_min_interval": None,
    "beacon_max_interval": None,
    "exfil_min_bytes": None,
    "exfil_ratio": None,
    "dns_min_unique": None,
    "scan_min_ports": None,
    "tor_max_destinations": None,
    "tor_min_bytes": None,
}


#: Thresholds exposed on the CLI/config and mapped onto AnalysisOptions.
HEURISTIC_FIELDS = (
    "beacon_min_events", "beacon_max_cv", "beacon_min_interval",
    "beacon_max_interval", "exfil_min_bytes", "exfil_ratio", "dns_min_unique",
    "scan_min_ports", "tor_max_destinations", "tor_min_bytes",
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _csv_values(value: Any) -> List[str]:
    """Flatten a comma-separated string or a list of strings."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        parts: List[str] = []
        for item in value:
            parts.extend(split_csv_arg(str(item)))
        return parts
    return split_csv_arg(str(value))


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("1", "true", "yes", "on", "y")


def _positive_int(value: Any) -> int:
    number = int(value)
    if number < 1:
        raise ValueError("must be at least 1")
    return number


def _positive_float(value: Any) -> float:
    number = float(value)
    if number <= 0:
        raise ValueError("must be greater than 0")
    return number


def _rdap_url(value: Any) -> str:
    """Validate an RDAP URL template containing ``{ip}``."""
    url = str(value or "").strip()
    if "{ip}" not in url:
        raise ValueError("RDAP URL template must contain {ip}")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("RDAP URL must be an http(s) URL")
    return url


def _unique_dir(path: str) -> str:
    """Return ``path`` or ``path_2``/``path_3``... if it already exists."""
    if not os.path.exists(path):
        return path
    for index in range(2, 1000):
        candidate = f"{path}_{index}"
        if not os.path.exists(candidate):
            return candidate
    raise RuntimeError(f"could not find a free output folder for {path}")


def _expand(value: Optional[str]) -> Optional[str]:
    return os.path.expanduser(value) if value else value


def pick_file() -> Optional[str]:
    """Open a graphical file dialog when no capture was given on the CLI."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception:
        return None
    try:
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askopenfilename(
            title="Select the capture file",
            filetypes=[("Network captures", "*.pcap *.pcapng"),
                       ("All files", "*.*")],
        )
        root.destroy()
        return path or None
    except Exception:
        return None


def read_api_key(cli_key: str = "", key_file: str = "vt_key.txt") -> str:
    """Resolve the VirusTotal key: CLI > ``VT_API_KEY`` > key file."""
    if cli_key:
        return cli_key.strip()
    env_key = os.environ.get("VT_API_KEY", "").strip()
    if env_key:
        return env_key

    key_file = _expand(key_file) or "vt_key.txt"
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        key_file,
        os.path.join(base_output_dir(), key_file),
        os.path.join(repo_root, key_file),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), key_file),
    ]
    seen = set()
    for path in candidates:
        path = os.path.abspath(path)
        if path in seen:
            continue
        seen.add(path)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        return line
        except OSError:
            continue
    return ""


# --------------------------------------------------------------------------
# Configuration file
# --------------------------------------------------------------------------

def _config_candidates() -> List[str]:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [
        os.path.join(os.getcwd(), "snitch.json"),
        os.path.join(repo_root, "snitch.json"),
    ]


def _find_config_path(explicit: Optional[str]) -> Optional[str]:
    """Locate the config file, distinguishing an explicit path from a probe."""
    if explicit:
        path = _expand(explicit)
        if not path or not os.path.isfile(path):
            raise FileNotFoundError(f"config file not found: {explicit}")
        return path
    for candidate in _config_candidates():
        if os.path.isfile(candidate):
            return candidate
    return None


def _extract_config_arg(argv: Sequence[str]) -> Optional[str]:
    """Find ``--config`` before the full parser runs (it affects defaults)."""
    for index, token in enumerate(argv):
        if token == "--config" and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith("--config="):
            return token.split("=", 1)[1]
    return None


def _apply_config(parser: argparse.ArgumentParser, raw: Dict[str, Any],
                  logger: Logger) -> None:
    actions = {action.dest: action for action in parser._actions}
    defaults: Dict[str, Any] = {}
    for key, value in raw.items():
        dest = str(key).strip().replace("-", "_")
        action = actions.get(dest)
        if action is None:
            logger.warn(f"config: ignoring unknown option {key!r}")
            continue
        try:
            if isinstance(action, (argparse._StoreTrueAction,
                                   argparse._StoreFalseAction)):
                defaults[dest] = _as_bool(value)
            elif action.type is not None and not isinstance(value, list):
                defaults[dest] = action.type(value)
            else:
                defaults[dest] = value
        except (TypeError, ValueError) as exc:
            logger.warn(f"config: invalid value for {key!r}: {exc}")
    parser.set_defaults(**defaults)


def _load_config(raw_path: Optional[str], logger: Logger) -> Dict[str, Any]:
    if not raw_path:
        return {}
    data = load_json(raw_path, default=None)
    if not isinstance(data, dict):
        raise ValueError(f"config file is not a JSON object: {raw_path}")
    return data


# --------------------------------------------------------------------------
# Argument parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snitch.py",
        description=(
            "Analyze a network capture: geolocate destination IPs, enrich them "
            "with reputation data, classify SNI/DNS domains and build an "
            "offline HTML dashboard."
        ),
        epilog=(
            "Examples:\n"
            "  python snitch.py capture.pcapng --target example.com\n"
            "  python snitch.py capture.pcapng --src-ip 192.168.137.42 --no-vt\n"
            "  python snitch.py --live eth0 --duration 60 --open\n"
            "  python snitch.py --list-interfaces\n"
            "\nA JSON config file (snitch.json or --config PATH) can set any "
            "long option using underscores instead of dashes."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.set_defaults(**DEFAULTS)

    parser.add_argument("capture", nargs="?",
                        help="Capture file (.pcap/.pcapng). Omit to open a file picker.")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {__version__}")

    # --- capture source ---------------------------------------------------
    source = parser.add_argument_group("capture source")
    source.add_argument("--live", nargs="?", const="auto", metavar="IFACE",
                        help="Capture live traffic (optionally on IFACE; default: auto).")
    source.add_argument("--duration", type=int, metavar="SECONDS",
                        help="Stop a live capture after SECONDS.")
    source.add_argument("--packet-limit", type=int, metavar="N",
                        help="Stop a live capture after N packets (files: read at most N).")
    source.add_argument("--list-interfaces", action="store_true",
                        help="List tshark capture interfaces and exit.")
    source.add_argument("--tshark", metavar="PATH",
                        help="Path to tshark when it is not auto-detected.")
    source.add_argument("--since", metavar="TIME",
                        help="Only analyze packets at/after this time (ISO-8601 or epoch).")
    source.add_argument("--until", metavar="TIME",
                        help="Only analyze packets at/before this time (ISO-8601 or epoch).")
    source.add_argument("--display-filter", default="", metavar="FILTER",
                        help="Extra tshark display filter, e.g. 'tcp.port == 443'.")

    # --- what to analyze --------------------------------------------------
    selection = parser.add_argument_group("what to analyze")
    selection.add_argument("--target", default="", metavar="DOMAIN",
                           help="Target domain (or URL) marked as 'Target' in reports.")
    selection.add_argument("--src-ip", default="", metavar="IP[,IP]",
                           help="Only count traffic from these client IP(s).")
    selection.add_argument("--all", action="store_true",
                           help="Count every public destination, without client filtering.")
    selection.add_argument("--auto-clients", action="store_true",
                           help="Treat every private/local address as a client (except gateways).")
    selection.add_argument("--detect-local", action="store_true",
                           help="Add this machine's local IPv4 subnets to --hotspot-net.")
    selection.add_argument("--hotspot-net", default="192.168.137.0/24",
                           metavar="CIDR[,CIDR]",
                           help="Client network(s) in the default client mode.")
    selection.add_argument("--gateway", default="192.168.137.1", metavar="IP[,IP]",
                           help="Gateway address(es) never counted as clients.")
    selection.add_argument("--exclude-ip", action="append", metavar="IP[,CIDR]",
                           help="Exclude destination/client addresses (repeatable).")
    selection.add_argument("--min-packets", type=int, default=1, metavar="N",
                           help="Ignore destinations with fewer than N packets.")
    selection.add_argument("--allowlist", default="", metavar="PATH",
                           help="Text file of IPs/CIDRs/domains whose findings are suppressed.")

    # --- enrichment -------------------------------------------------------
    enrich_group = parser.add_argument_group("enrichment")
    enrich_group.add_argument("--vt-key", default="",
                              help="VirusTotal API key (overrides env/file).")
    enrich_group.add_argument("--vt-key-file", default="vt_key.txt", metavar="PATH",
                              help="File containing the VirusTotal key (default: vt_key.txt).")
    enrich_group.add_argument("--vt-delay", type=float, default=16.0, metavar="SECONDS",
                              help="Delay between VirusTotal requests (free tier: 16).")
    enrich_group.add_argument("--vt-domains", nargs="?", const=50, type=int,
                              default=0, metavar="N",
                              help="Also check up to N domains on VirusTotal (default: off).")
    enrich_group.add_argument("--no-vt", action="store_true",
                              help="Do not query VirusTotal (cached results are still used).")
    enrich_group.add_argument("--no-geo", action="store_true",
                              help="Skip geolocation lookups.")
    enrich_group.add_argument("--no-rdns", action="store_true",
                              help="Skip reverse-DNS lookups.")
    enrich_group.add_argument("--rdap", action="store_true",
                              help="Look up network ownership via RDAP.")
    enrich_group.add_argument("--rdap-url", type=_rdap_url, default=None, metavar="TEMPLATE",
                              help="RDAP URL template containing {ip} "
                                   "(default: https://rdap.org/ip/{ip}); implies --rdap.")
    enrich_group.add_argument("--asn-db", default="", metavar="PATH",
                              help="Offline ASN database (GeoLite2 ASN CSV or "
                                   "'CIDR ASN Organisation' text) that fills "
                                   "missing ASN/owner values.")
    enrich_group.add_argument("--check-tor-exits", action="store_true",
                              help="Download the Tor exit-node list and flag matches.")
    enrich_group.add_argument("--offline", action="store_true",
                              help="No network requests; use only cached enrichment.")
    enrich_group.add_argument("--refresh", action="store_true",
                              help="Ignore cached enrichment and query again.")
    enrich_group.add_argument("--no-cache", action="store_true",
                              help="Do not read or write the enrichment cache.")
    enrich_group.add_argument("--workers", type=int, default=8, metavar="N",
                              help="Concurrent workers for geo/rDNS/RDAP (default: 8).")
    enrich_group.add_argument("--geo-failure-ttl", type=_positive_float,
                              default=6.0, metavar="HOURS",
                              help="Reuse recent geolocation failures for this long (default: 6).")

    # --- heuristic thresholds ---------------------------------------------
    heuristics = parser.add_argument_group("heuristic thresholds (advanced)")
    heuristics.add_argument("--profile", choices=("quiet", "balanced", "aggressive"),
                            default="balanced",
                            help="Threshold preset; explicit --beacon-*/--dns-*/… flags win (default: balanced).")
    heuristics.add_argument("--beacon-min-events", type=_positive_int, default=None,
                            metavar="N", help="Minimum connections before flagging beaconing (default: 5).")
    heuristics.add_argument("--beacon-max-cv", type=_positive_float, default=None,
                            metavar="RATIO", help="Maximum gap variation for beaconing (default: 0.50).")
    heuristics.add_argument("--beacon-min-interval", type=_positive_float, default=None,
                            metavar="SECONDS", help="Minimum median beacon interval (default: 5).")
    heuristics.add_argument("--beacon-max-interval", type=_positive_float, default=None,
                            metavar="SECONDS", help="Maximum median beacon interval (default: 3600).")
    heuristics.add_argument("--exfil-min-bytes", type=_positive_int, default=None,
                            metavar="BYTES", help="Minimum upload volume for exfil findings (default: 5 MiB).")
    heuristics.add_argument("--exfil-ratio", type=_positive_float, default=None,
                            metavar="RATIO", help="Upload/download ratio for exfil findings (default: 5).")
    heuristics.add_argument("--dns-min-unique", type=_positive_int, default=None,
                            metavar="N", help="Unique subdomains before a DNS anomaly (default: 20).")
    heuristics.add_argument("--scan-min-ports", type=_positive_int, default=None,
                            metavar="N", help="Ports before a port-scan finding (default: 25).")
    heuristics.add_argument("--tor-max-destinations", type=_positive_int, default=None,
                            metavar="N", help="Destination limit for the Tor-like check (default: 4).")
    heuristics.add_argument("--tor-min-bytes", type=_positive_int, default=None,
                            metavar="BYTES", help="Traffic needed for a Tor-like finding (default: 200 KiB).")

    # --- output -----------------------------------------------------------
    output = parser.add_argument_group("output")
    output.add_argument("--out-dir", default="", metavar="DIR",
                        help="Base folder for the analysis folder (default: current directory).")
    output.add_argument("--handle", default="@APIGranter",
                        help="Handle/brand shown on the dashboard.")
    output.add_argument("--title", default="", metavar="TEXT",
                        help="Report title shown on the dashboard.")
    output.add_argument("--no-html", action="store_true",
                        help="Skip the HTML dashboard (JSON/CSV/TXT are still written).")
    output.add_argument("--open", action="store_true",
                        help="Open the dashboard in the default browser when finished.")
    output.add_argument("--fail-on", choices=["none", "info", "low", "medium",
                                              "high", "critical"],
                        default="none",
                        help="Exit with status 3 when a finding reaches this severity.")
    output.add_argument("--quiet", action="store_true",
                        help="Only print warnings and errors.")
    output.add_argument("--verbose", action="store_true",
                        help="Print debug details (tshark command, paths, cache hits).")
    output.add_argument("--config", metavar="PATH",
                        help="JSON config file with default values.")
    return parser


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def _prepare_cache(base_dir: str, args: argparse.Namespace, logger: Logger) -> str:
    """Return the cache path, importing the 1.x ``ip_cache.json`` if needed."""
    new_path = os.path.join(base_dir, "enrichment_cache.json")
    old_path = os.path.join(base_dir, "ip_cache.json")
    if not os.path.exists(new_path) and os.path.isfile(old_path):
        try:
            shutil.copy2(old_path, new_path)
            logger.info("Imported legacy cache: ip_cache.json -> enrichment_cache.json")
        except OSError as exc:
            logger.warn(f"could not import legacy cache: {exc}")
            return old_path
    return new_path


def _client_options(args: argparse.Namespace) -> ExtractionOptions:
    if args.all:
        mode = "all"
    elif args.src_ip:
        mode = "ip"
    else:
        mode = "client"

    try:
        client_networks = parse_networks(_csv_values(args.hotspot_net))
        exclude_networks = parse_networks(_csv_values(args.exclude_ip))
    except ValueError as exc:
        raise ValueError(str(exc))

    return ExtractionOptions(
        mode=mode,
        src_ips=set(_csv_values(args.src_ip)),
        client_networks=client_networks,
        gateways=set(_csv_values(args.gateway)),
        auto_clients=bool(args.auto_clients),
        exclude_networks=exclude_networks,
        min_packets=max(1, int(args.min_packets or 1)),
    )


def _detected_client_networks():
    """Local IPv4 subnets as a best-effort hint; never raises."""
    try:
        return list(local_ipv4_networks())
    except Exception:  # pragma: no cover - defensive, discovery is best-effort
        return []


def _add_detected_networks(options: ExtractionOptions,
                           networks) -> ExtractionOptions:
    """Merge detected subnets into the client networks (deduplicated)."""
    if not networks:
        return options
    seen = {str(network) for network in options.client_networks}
    merged = list(options.client_networks)
    for network in networks:
        if str(network) not in seen:
            merged.append(network)
            seen.add(str(network))
    return replace(options, client_networks=merged)


def _analysis_options(args: argparse.Namespace,
                      allowlist: Allowlist) -> AnalysisOptions:
    """Build AnalysisOptions from the profile plus CLI/config overrides."""
    profile = getattr(args, "profile", None) or "balanced"
    values = profile_thresholds(profile)
    overrides = {
        name: getattr(args, name)
        for name in HEURISTIC_FIELDS
        if getattr(args, name, None) is not None
    }
    values.update(overrides)
    options = AnalysisOptions(target=normalize_target(args.target),
                              allowlist=allowlist)
    return replace(options, **values) if values else options


def _heuristic_meta(args: argparse.Namespace) -> Dict[str, Any]:
    """Effective heuristic thresholds for the report metadata."""
    profile = getattr(args, "profile", None) or "balanced"
    meta = profile_thresholds(profile)
    for name in HEURISTIC_FIELDS:
        value = getattr(args, name, None)
        if value is not None:
            meta[name] = value
        elif name not in meta:
            meta[name] = getattr(AnalysisOptions(), name)
    meta["profile"] = profile
    return meta


def _capture_meta(args: argparse.Namespace, tshark: str, source: str,
                  display_name: str, display_filter: str, live: bool,
                  interface: str = "",
                  client_networks: Optional[Sequence[Any]] = None,
                  auto_clients: bool = False,
                  detected_networks: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
    effective_networks = (
        [str(network) for network in client_networks]
        if client_networks is not None else _csv_values(args.hotspot_net)
    )
    meta: Dict[str, Any] = {
        "file": display_name,
        "source": source,
        "live": live,
        "tool": APP_NAME,
        "tshark_version": tshark_version(tshark),
        "filter": display_filter,
        "target": normalize_target(args.target),
        "mode": "all" if args.all else ("ip" if args.src_ip else "client"),
        "src_ips": _csv_values(args.src_ip),
        "client_networks": effective_networks,
        "gateways": _csv_values(args.gateway),
        "excluded": _csv_values(args.exclude_ip),
        "auto_clients": bool(auto_clients),
        "detected_networks": [str(network) for network in (detected_networks or [])],
        "min_packets": int(args.min_packets or 1),
        "since": iso_utc(args.since),
        "until": iso_utc(args.until),
        "live_interface": interface,
        "packet_limit": args.packet_limit,
        "heuristics": _heuristic_meta(args),
        "heuristic_profiles": {
            name: dict(values) for name, values in HEURISTIC_PROFILES.items()
        },
    }
    if not live:
        try:
            meta["sha256"] = sha256_file(source)
            meta["size_bytes"] = os.path.getsize(source)
        except OSError as exc:
            meta["hash_error"] = str(exc)
        # capinfos adds what the capture's authoring stack recorded (application,
        # OS, hardware, encapsulation, interface names).  It is optional: if the
        # tool is missing or fails, the dashboard simply omits those rows.
        info = capture_info(source, tshark)
        if info:
            meta["capinfos"] = info
    return meta


def _limited(rows: Iterable[Dict[str, str]], limit: Optional[int]):
    if not limit or limit <= 0:
        yield from rows
        return
    for index, row in enumerate(rows, 1):
        if index > limit:
            break
        yield row


def _should_auto_retry(args: argparse.Namespace, analysis: Any,
                       options: ExtractionOptions) -> bool:
    """True when the default hotspot filter matched nothing at all.

    On non-Windows-hotspot networks the 1.x default (192.168.137.0/24) often
    finds no clients.  Rather than fail, retry once with ``--auto-clients``.
    Explicit network/gateway values disable the fallback so typos stay visible.
    """
    if options.mode != "client" or options.auto_clients:
        return False
    if analysis.destinations or analysis.clients:
        return False
    hotspot = str(getattr(args, "hotspot_net", "") or "").strip()
    gateway = str(getattr(args, "gateway", "") or "").strip()
    return (hotspot == DEFAULTS["hotspot_net"]
            and gateway == DEFAULTS["gateway"])


def _print_interfaces(tshark: str) -> int:
    try:
        interfaces = list_interfaces(tshark)
    except TsharkError as exc:
        print(f"Could not list interfaces: {exc}", file=sys.stderr)
        return 2
    if not interfaces:
        print("No capture interfaces reported by tshark.")
        return 0
    width = max(len(item["name"]) for item in interfaces)
    print(f"{'IDX':<4} {'INTERFACE':<{width}}  DESCRIPTION")
    for item in interfaces:
        print(f"{item['index']:<4} {item['name']:<{width}}  {item['description']}")
    return 0


def _resolve_live_interface(tshark: str, requested: Any) -> str:
    value = requested
    if value is True or value in (None, "", "auto"):
        interfaces = [item for item in list_interfaces(tshark)
                      if item["name"] not in ("any", "lo", "lo0")]
        if not interfaces:
            interfaces = list_interfaces(tshark)
        if not interfaces:
            raise TsharkError("tshark did not report any capture interface")
        chosen = interfaces[0]["name"]
        print(f"Auto-selected interface: {chosen}")
        return chosen
    return resolve_interface(tshark, str(value))


def _print_summary(report: Dict[str, Any], logger: Logger) -> None:
    summary = report.get("summary") or {}
    meta = report.get("meta") or {}
    logger.ok(
        "Done: {ips} destination(s), {domains} domain(s), {flows} flow(s), "
        "{findings} finding(s)".format(
            ips=summary.get("ips", 0),
            domains=summary.get("domains", 0),
            flows=summary.get("flows", 0),
            findings=summary.get("findings", 0),
        )
    )
    logger.info(
        f"Traffic: {human_bytes(meta.get('analyzed_bytes') or 0)} analyzed "
        f"of {human_bytes(meta.get('bytes') or 0)} "
        f"over {human_duration(meta.get('duration'))}"
    )
    by_severity = summary.get("findings_by_severity") or {}
    if by_severity:
        order = [name for name in ("critical", "high", "medium", "low", "info")
                 if by_severity.get(name)]
        if order:
            logger.info("Findings: " + ", ".join(
                f"{name}={by_severity[name]}" for name in order))


def run(args: argparse.Namespace, logger: Logger) -> int:
    tshark = find_tshark(_expand(args.tshark))
    if args.list_interfaces:
        if not tshark:
            logger.error("tshark not found. Install Wireshark or pass --tshark PATH.")
            return 2
        return _print_interfaces(tshark)

    if not tshark:
        logger.error("tshark not found. Install Wireshark or pass --tshark PATH.")
        logger.info(platform_note())
        return 2
    logger.debug(f"tshark: {tshark} ({tshark_version(tshark)})")

    # --- parse time range early so a typo fails before a live capture -----
    try:
        args.since = parse_time_arg(args.since)
        args.until = parse_time_arg(args.until)
    except ValueError as exc:
        logger.error(str(exc))
        return 2
    if args.since and args.until and args.since > args.until:
        logger.error("--since is after --until")
        return 2

    # --- capture source ---------------------------------------------------
    live = False
    interface = ""
    temp_capture = ""
    if args.live is not None and args.live is not False:
        live = True
        interface = _resolve_live_interface(tshark, args.live)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        display_name = f"live_{safe_filename(interface, 'iface')}_{stamp}.pcapng"
        temp_capture = default_live_path("snitch-live")
        try:
            live_capture(tshark, interface, args.duration, args.packet_limit,
                         temp_capture, logger)
        except TsharkError as exc:
            logger.error(str(exc))
            logger.info(platform_note())
            return 2
        source = temp_capture
        limit = None  # already enforced by tshark
    else:
        source = _expand(args.capture) or pick_file()
        if not source:
            logger.error("No capture file provided.")
            logger.info("Pass a .pcap/.pcapng file, use --live, or run with a desktop session for the file picker.")
            return 1
        source = os.path.abspath(source)
        try:
            validate_capture(source)
        except TsharkError as exc:
            logger.error(str(exc))
            return 1
        display_name = os.path.basename(source)
        limit = args.packet_limit

    try:
        return _analyze(args, logger, tshark, source, display_name,
                        display_filter_extra=args.display_filter,
                        live=live, interface=interface, limit=limit)
    finally:
        if temp_capture and os.path.exists(temp_capture):
            try:
                os.unlink(temp_capture)
            except OSError:
                pass


def _analyze(args: argparse.Namespace, logger: Logger, tshark: str,
             source: str, display_name: str, display_filter_extra: str,
             live: bool, interface: str, limit: Optional[int]) -> int:
    display_filter = build_display_filter(args.since, args.until,
                                          display_filter_extra)
    try:
        options = _client_options(args)
    except ValueError as exc:
        logger.error(str(exc))
        return 2

    try:
        allowlist = Allowlist.load(args.allowlist) if args.allowlist else Allowlist.empty()
    except AllowlistError as exc:
        logger.error(str(exc))
        return 2
    if allowlist.entries:
        logger.info(f"Allowlist: {allowlist.entries} entries ({allowlist.describe()})")

    asn_db = None
    if args.asn_db:
        try:
            asn_db = AsnDatabase.load(_expand(args.asn_db) or args.asn_db)
        except (OSError, ValueError) as exc:
            logger.error(f"cannot read ASN database: {exc}")
            return 2
        logger.info(
            f"ASN database: {len(asn_db)} networks ({asn_db.source}"
            + (f", {asn_db.skipped} invalid line(s) skipped" if asn_db.skipped else "")
            + ")"
        )

    logger.info(f"Capture: {source if not live else interface}")

    detected_networks = []
    if options.mode == "client" and not options.auto_clients \
            and getattr(args, "detect_local", False):
        detected_networks = _detected_client_networks()
        if detected_networks:
            options = _add_detected_networks(options, detected_networks)
            logger.info(
                "Detected local subnet(s): "
                + format_networks(detected_networks)
            )
        else:
            logger.warn(
                "--detect-local found no private IPv4 subnets; "
                "keeping --hotspot-net."
            )

    def run_extraction(current: ExtractionOptions):
        rows = _limited(
            iter_packets(source, tshark, display_filter, logger),
            limit,
        )
        return extract(rows, current, logger)

    logger.info(f"Analyzing {display_name} with a single tshark pass ...")
    try:
        analysis = run_extraction(options)
    except TsharkError as exc:
        logger.error(str(exc))
        return 2

    if _should_auto_retry(args, analysis, options):
        if not detected_networks:
            detected_networks = _detected_client_networks()
        if detected_networks:
            logger.warn(
                "No clients matched the default hotspot network "
                f"({DEFAULTS['hotspot_net']}); retrying with detected local "
                f"subnet(s): {format_networks(detected_networks)}."
            )
            options = _add_detected_networks(options, detected_networks)
            try:
                analysis = run_extraction(options)
            except TsharkError as exc:
                logger.error(str(exc))
                return 2
            if analysis.destinations or analysis.clients:
                analysis.warnings.append(
                    "The default hotspot client filter matched no clients; "
                    "detected local subnet(s) were used instead: "
                    + format_networks(detected_networks)
                )
        if not analysis.destinations and not analysis.clients:
            logger.warn(
                "No clients matched the default hotspot network or the "
                "detected subnets; retrying with --auto-clients."
            )
            options = replace(options, auto_clients=True)
            try:
                analysis = run_extraction(options)
            except TsharkError as exc:
                logger.error(str(exc))
                return 2
            analysis.warnings.append(
                "The default hotspot client filter matched no clients; "
                "auto-clients fallback was used."
            )

    analysis.capture.update(_capture_meta(
        args, tshark,
        source if not live else f"live:{interface}",
        display_name, display_filter, live, interface,
        client_networks=options.client_networks,
        auto_clients=options.auto_clients,
        detected_networks=detected_networks,
    ))

    if not analysis.destinations:
        if options.mode == "client" and not analysis.capture.get("clients_detected"):
            logger.error("No clients detected in the capture.")
            logger.info(
                "Check --hotspot-net, pin a device with --src-ip, or use "
                "--auto-clients/--all."
            )
        elif args.min_packets and int(args.min_packets) > 1:
            logger.error(f"No destinations with at least {args.min_packets} packets.")
        else:
            logger.error("No public destination IPs matched this filter.")
            if args.exclude_ip:
                logger.info("Review --exclude-ip values.")
        return 1

    # --- classification and local heuristics ------------------------------
    if allowlist.entries:
        analysis.capture["allowlist_entries"] = allowlist.entries
        analysis.capture["allowlist_source"] = allowlist.source

    apply_categories(analysis, args.target)
    run_heuristics(analysis, _analysis_options(args, allowlist))

    # --- enrichment -------------------------------------------------------
    base_dir = os.path.abspath(_expand(args.out_dir) or base_output_dir())
    vt_key = read_api_key(args.vt_key, args.vt_key_file)
    if args.no_vt:
        vt_key = ""
    if not vt_key and not args.no_vt and not args.offline:
        analysis.warnings.append(
            "VirusTotal API key not configured; reputation checks were skipped."
        )
    if args.offline:
        analysis.warnings.append(
            "Offline mode: geolocation, rDNS, RDAP and VirusTotal requests were skipped."
        )

    enrich_options = EnrichOptions(
        offline=bool(args.offline),
        geo=not args.no_geo,
        vt=not args.no_vt,
        rdns=not args.no_rdns,
        rdap=bool(args.rdap) or bool(args.rdap_url),
        rdap_url=str(args.rdap_url or ""),
        vt_key=vt_key,
        vt_delay=max(0.0, float(args.vt_delay or 0)),
        vt_domains=max(0, int(args.vt_domains or 0)),
        workers=max(1, int(args.workers or 8)),
        geo_failure_ttl_hours=max(0.1, float(getattr(args, "geo_failure_ttl", 6.0) or 6.0)),
        refresh=bool(args.refresh),
        cache_enabled=not args.no_cache,
        cache_path=_prepare_cache(base_dir, args, logger),
        tor_exits=bool(args.check_tor_exits),
        logger=logger,
    )
    enrich(analysis, enrich_options)
    if asn_db is not None:
        analysis.enrichment["asn_db"] = apply_asn_db(analysis, asn_db, logger)
    run_threat_intel(analysis)
    sort_findings(analysis)

    # --- output folder + capture copy -------------------------------------
    stem = safe_filename(display_name)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_dir = _unique_dir(os.path.join(base_dir, f"{stem}_{stamp}"))
    data_dir = os.path.join(run_dir, "data")
    domains_dir = os.path.join(run_dir, "domains")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(domains_dir, exist_ok=True)
    logger.info(f"Results folder: {run_dir}")

    copied_capture = os.path.join(run_dir, display_name)
    if live:
        try:
            shutil.copy2(source, copied_capture)
            analysis.capture["source"] = display_name
            analysis.capture["live"] = True
        except (OSError, shutil.SameFileError) as exc:
            logger.warn(f"could not copy the live capture: {exc}")
    elif os.path.abspath(source) != os.path.abspath(copied_capture):
        try:
            shutil.copy2(source, copied_capture)
        except (OSError, shutil.SameFileError) as exc:
            logger.warn(f"could not copy the capture into the results folder: {exc}")

    # --- report + files ---------------------------------------------------
    report = build_report(analysis, handle=args.handle, title=args.title)
    paths = save_all(analysis, report, run_dir, data_dir, domains_dir, logger)

    html_path = ""
    if args.no_html:
        logger.info("HTML dashboard disabled (--no-html).")
        if args.open:
            logger.warn("--open ignored because the dashboard was disabled.")
    else:
        html_path = os.path.join(run_dir, "dashboard.html")
        try:
            build_dashboard(report, html_path, logger)
        except (OSError, RuntimeError) as exc:
            logger.error(f"could not build the dashboard: {exc}")

    _print_summary(report, logger)
    logger.info(f"Data: {paths['analysis_json']}")
    if html_path:
        logger.info(f"Dashboard: {html_path}")
        if args.open:
            if open_in_browser(html_path):
                logger.info("Opened the dashboard in the default browser.")
            else:
                logger.warn("Could not open the browser automatically.")

    # --- exit status ------------------------------------------------------
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(finding.severity, 0) >= threshold
               for finding in analysis.findings):
            logger.warn(f"Failing because a finding is at/above {args.fail_on} severity.")
            return 3
    return 0


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    logger = Logger(quiet=bool(DEFAULTS["quiet"]), verbose=bool(DEFAULTS["verbose"]))
    try:
        config_arg = _extract_config_arg(argv)
        config_path = _find_config_path(config_arg)
        if config_path:
            raw = _load_config(config_path, logger)
            _apply_config(parser, raw, logger)
        args = parser.parse_args(argv)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    logger = Logger(quiet=bool(args.quiet), verbose=bool(args.verbose))
    set_default_logger(logger)

    try:
        return run(args, logger)
    except KeyboardInterrupt:
        logger.warn("Interrupted; partial outputs were not written.")
        return 130
    except (TsharkError, ValueError, RuntimeError, OSError) as exc:
        logger.error(str(exc))
        if args.verbose:
            raise
        return 2
    except Exception as exc:  # pragma: no cover - defensive last resort
        logger.error(f"unexpected error: {exc}")
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
