# -*- coding: utf-8 -*-
"""Report assembly and file outputs (JSON, CSV, TXT and HTML dashboard)."""

from __future__ import annotations

import csv
import os
import tempfile
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import APP_NAME, __version__, __author__
from .classify import (
    CATEGORY_DESCRIPTIONS, CATEGORY_ORDER, CAT_OTHER, CAT_TARGET,
    base_domain, classify_domain, port_service,
)
from .models import Analysis, Destination, DomainStat, SEVERITY_ORDER
from .util import (
    Logger, atomic_write_json, human_bytes, human_duration,
    iso_utc, resource_path, safe_json_dumps,
)


# Dashboard payload limits (full data remains in analysis.json / CSVs).
MAX_DNS_ROWS = 5000
MAX_FLOW_ROWS = 5000
MAX_DASHBOARD_FINDINGS = 500


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _risk(dest: Destination) -> str:
    malicious = dest.vt.get("malicious")
    suspicious = dest.vt.get("suspicious")
    if isinstance(malicious, int) and malicious > 0:
        return "malicious"
    if isinstance(suspicious, int) and suspicious > 0:
        return "suspicious"
    if dest.tor_exit:
        return "tor"
    if isinstance(malicious, int):
        return "clean"
    return "unknown"


def _destination_category(dest: Destination, analysis: Analysis, target: str) -> str:
    cats = Counter()
    for name in dest.domains:
        stat = analysis.domains.get(name)
        category = stat.category if stat else classify_domain(name, target)
        if category == CAT_TARGET:
            return CAT_TARGET
        cats[category] += max(1, sum(stat.sources.values()) if stat else 1)
    if cats:
        return cats.most_common(1)[0][0]
    return CAT_OTHER


def _domain_hits(stat: DomainStat) -> int:
    return sum(stat.sources.values()) or stat.count or 1


def _top(counter: Counter, n: int = 10) -> List[Dict[str, Any]]:
    total = sum(counter.values())
    return [
        {"name": str(name), "count": int(count),
         "percent": round(100.0 * count / total, 2) if total else 0.0}
        for name, count in counter.most_common(n)
    ]


def _timeline(analysis: Analysis, target_points: int = 160) -> Dict[str, Any]:
    """Compress the per-second timeline into at most ~target_points buckets."""
    if not analysis.timeline:
        return {"bucket_seconds": 1, "points": []}
    duration = max(1.0, analysis.duration)
    raw_bucket = duration / target_points
    nice = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600,
            7200, 21600, 43200, 86400, 604800]
    bucket = next((value for value in nice if value >= raw_bucket), nice[-1])
    bucket = int(bucket)
    start = int(analysis.first_seen // bucket) * bucket
    end = int(analysis.last_seen // bucket) * bucket
    aggregated: Dict[int, List[int]] = {}
    for second, entry in analysis.timeline.items():
        key = int(second // bucket) * bucket
        target = aggregated.setdefault(key, [0, 0, 0, 0])
        target[0] += entry[0]
        target[1] += entry[1]
        target[2] += entry[2]
        target[3] += entry[3]
    points: List[List[float]] = []
    current = start
    while current <= end and len(points) <= 5000:
        out_p, in_p, out_b, in_b = aggregated.get(current, (0, 0, 0, 0))
        points.append([current, out_p, in_p, out_b, in_b])
        current += bucket
    return {"bucket_seconds": bucket, "points": points}


# --------------------------------------------------------------------------
# Report construction
# --------------------------------------------------------------------------

def build_report(analysis: Analysis, handle: str = "", title: str = "",
                 generated: Optional[float] = None) -> Dict[str, Any]:
    """Create the JSON-serializable report used by every output format."""
    target = analysis.capture.get("target", "") or ""
    generated = generated or datetime.now(tz=timezone.utc).timestamp()

    destinations = []
    risk_counter: Counter = Counter()
    country_counter: Counter = Counter()
    provider_counter: Counter = Counter()
    asn_counter: Counter = Counter()

    for dest in sorted(analysis.destinations.values(),
                       key=lambda d: (d.bytes, d.packets), reverse=True):
        risk = _risk(dest)
        risk_counter[risk] += 1
        country = dest.geo.get("country") or "Unknown"
        country_counter[country] += 1
        provider = dest.geo.get("isp") or "Unknown"
        provider_counter[provider] += 1
        asn = dest.geo.get("asn") or "Unknown"
        asn_counter[asn] += 1

        domain_entries = []
        for name, count in dest.domains.most_common():
            stat = analysis.domains.get(name)
            domain_entries.append({
                "name": name,
                "count": int(count),
                "category": stat.category if stat else classify_domain(name, target),
                "hits": _domain_hits(stat) if stat else int(count),
            })
        destinations.append({
            "ip": dest.ip,
            "packets": dest.packets,
            "packets_out": dest.packets_out,
            "packets_in": dest.packets_in,
            "bytes": dest.bytes,
            "bytes_out": dest.bytes_out,
            "bytes_in": dest.bytes_in,
            "retransmissions": dest.retransmissions,
            "syn_count": dest.syn_count,
            "first_seen": dest.first_seen,
            "last_seen": dest.last_seen,
            "risk": risk,
            "category": _destination_category(dest, analysis, target),
            "cleartext": dest.has_cleartext,
            "tor_exit": dest.tor_exit,
            "geo": dict(dest.geo),
            "vt": dict(dest.vt),
            "rdns": dest.rdns,
            "rdap": dict(dest.rdap),
            "ports": [
                {"port": int(port), "count": int(count),
                 "service": port_service(int(port))}
                for port, count in dest.ports.most_common()
            ],
            "protocols": dict(dest.protocols),
            "clients": dict(dest.clients),
            "domains": domain_entries,
            "tls_versions": dict(dest.tls_versions),
            "alpn": dict(dest.alpn),
            "ja4": dict(dest.ja4),
        })

    domain_rows = []
    category_count: Counter = Counter()
    category_hits: Counter = Counter()
    for stat in analysis.domains.values():
        hits = _domain_hits(stat)
        category_count[stat.category] += 1
        category_hits[stat.category] += hits
        domain_rows.append({
            "domain": stat.domain,
            "base": base_domain(stat.domain),
            "category": stat.category,
            "hits": hits,
            "sources": dict(stat.sources),
            "clients": dict(stat.clients),
            "ips": dict(stat.ips),
            "first_seen": stat.first_seen,
            "last_seen": stat.last_seen,
            "vt": dict(stat.vt),
        })
    domain_rows.sort(key=lambda d: (d["hits"], len(d["ips"])), reverse=True)

    client_rows = []
    for client in sorted(analysis.clients.values(), key=lambda c: c.bytes, reverse=True):
        client_rows.append({
            "ip": client.ip,
            "packets": client.packets,
            "packets_out": client.packets_out,
            "packets_in": client.packets_in,
            "bytes": client.bytes,
            "bytes_out": client.bytes_out,
            "bytes_in": client.bytes_in,
            "destinations": len(client.destinations),
            "domains": len(client.domains),
            "first_seen": client.first_seen,
            "last_seen": client.last_seen,
            "top_destinations": [
                {"ip": ip, "packets": n} for ip, n in client.destinations.most_common(10)
            ],
            "top_domains": [
                {"domain": name, "hits": n} for name, n in client.domains.most_common(10)
            ],
        })

    flow_rows = []
    for flow in sorted(analysis.flows.values(), key=lambda f: f.bytes, reverse=True):
        flow_rows.append({
            "client": flow.client,
            "dst": flow.dst,
            "proto": flow.proto,
            "dport": flow.dport,
            "service": port_service(flow.dport, flow.proto),
            "packets": flow.packets,
            "packets_out": flow.packets_out,
            "packets_in": flow.packets_in,
            "bytes": flow.bytes,
            "bytes_out": flow.bytes_out,
            "bytes_in": flow.bytes_in,
            "first_seen": flow.first_seen,
            "last_seen": flow.last_seen,
            "domains": list(flow.domains)[:5],
            "ja4": flow.ja4,
        })

    dns_rows = []
    for stat in sorted(analysis.dns_queries.values(),
                       key=lambda s: (s.count, s.last_seen), reverse=True):
        if not stat.qname:
            continue
        dns_rows.append({
            "qname": stat.qname,
            "base": base_domain(stat.qname),
            "qtype": stat.qtype_name,
            "count": stat.count,
            "answers": list(stat.answers)[:20],
            "clients": list(stat.clients)[:20],
            "first_seen": stat.first_seen,
            "last_seen": stat.last_seen,
            "response_ms": round(stat.response_time_ms, 2),
        })

    findings = [asdict(finding) for finding in analysis.findings]
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), -f.get("score", 0)))
    findings = findings[:MAX_DASHBOARD_FINDINGS]
    findings_by_severity = Counter(f["severity"] for f in findings)
    anomaly_bases = sorted({
        domain for f in findings
        if f.get("id") == "dns_anomaly" for domain in f.get("domains", [])
    })

    classification: Dict[str, List[List[Any]]] = {}
    for stat in sorted(analysis.domains.values(),
                       key=lambda s: (_domain_hits(s), s.domain), reverse=True):
        classification.setdefault(stat.category, []).append([stat.domain, _domain_hits(stat)])
    classification = {
        cat: classification[cat] for cat in CATEGORY_ORDER if cat in classification
    }

    total_queries = sum(stat.count for stat in analysis.dns_queries.values())
    capture = dict(analysis.capture)
    capture.update({
        "app": APP_NAME,
        "version": __version__,
        "author": __author__,
        "generated": generated,
        "generated_iso": iso_utc(generated),
        "handle": handle,
        "title": title or "Network traffic analysis",
        "duration": analysis.duration,
        "first_seen": analysis.first_seen,
        "last_seen": analysis.last_seen,
        "packets": analysis.total_packets,
        "bytes": analysis.total_bytes,
        "analyzed_packets": analysis.selected_packets,
        "analyzed_bytes": analysis.selected_bytes,
        "warnings": list(analysis.warnings),
        "enrichment": dict(analysis.enrichment),
        "limits": {"dns_rows": MAX_DNS_ROWS, "flow_rows": MAX_FLOW_ROWS},
    })

    summary = {
        "ips": len(destinations),
        "countries": len([c for c in country_counter if c != "Unknown"]),
        "providers": len([p for p in provider_counter if p != "Unknown"]),
        "asns": len([a for a in asn_counter if a != "Unknown"]),
        "clients": len(client_rows),
        "domains": len(domain_rows),
        "dns_queries": len(dns_rows),
        "dns_query_count": total_queries,
        "flows": len(flow_rows),
        "packets": analysis.total_packets,
        "bytes": analysis.total_bytes,
        "analyzed_packets": analysis.selected_packets,
        "analyzed_bytes": analysis.selected_bytes,
        "malicious": risk_counter.get("malicious", 0),
        "suspicious": risk_counter.get("suspicious", 0),
        "tor_exits": risk_counter.get("tor", 0),
        "clean": risk_counter.get("clean", 0),
        "unknown": risk_counter.get("unknown", 0),
        "findings": len(findings),
        "findings_by_severity": dict(findings_by_severity),
        "duration": analysis.duration,
    }

    return {
        "meta": capture,
        "summary": summary,
        "destinations": destinations,
        "domains": domain_rows,
        "clients": client_rows,
        "flows": flow_rows[:MAX_FLOW_ROWS],
        "flows_total": len(flow_rows),
        "dns": dns_rows[:MAX_DNS_ROWS],
        "dns_total": len(dns_rows),
        "findings": findings,
        "dns_anomaly_bases": anomaly_bases,
        "timeline": _timeline(analysis),
        "classification": classification,
        "category_descriptions": CATEGORY_DESCRIPTIONS,
        "charts": {
            "countries": _top(country_counter),
            "providers": _top(provider_counter),
            "asns": _top(asn_counter),
            "ports": _top(analysis.ports),
            "protocols": _top(analysis.protocols),
            "categories": _top(category_count),
            "risk": _top(risk_counter),
        },
        "category_hits": dict(category_hits),
        "warnings": list(analysis.warnings),
    }


# --------------------------------------------------------------------------
# Legacy/flat record + CSV outputs
# --------------------------------------------------------------------------

LEGACY_FIELDS = [
    "ip", "country", "cc", "region", "city", "lat", "lon", "isp", "asn",
    "packets", "packets_out", "packets_in", "bytes", "bytes_out", "bytes_in",
    "domains", "ports", "risk", "category", "rdns", "rdap_name",
    "vt_malicious", "vt_suspicious", "tor_exit", "first_seen", "last_seen",
]


def _flat_record(destination: Dict[str, Any]) -> Dict[str, Any]:
    geo = destination.get("geo") or {}
    vt = destination.get("vt") or {}
    rdap = destination.get("rdap") or {}
    return {
        "ip": destination["ip"],
        "country": geo.get("country", ""),
        "cc": geo.get("cc", ""),
        "region": geo.get("region", ""),
        "city": geo.get("city", ""),
        "lat": geo.get("lat"),
        "lon": geo.get("lon"),
        "isp": geo.get("isp", ""),
        "asn": geo.get("asn", ""),
        "packets": destination["packets"],
        "packets_out": destination["packets_out"],
        "packets_in": destination["packets_in"],
        "bytes": destination["bytes"],
        "bytes_out": destination["bytes_out"],
        "bytes_in": destination["bytes_in"],
        "domains": "; ".join(d["name"] for d in destination.get("domains", [])),
        "ports": "; ".join(
            f"{p['port']} ({p['service']})" for p in destination.get("ports", [])
        ),
        "risk": destination["risk"],
        "category": destination["category"],
        "rdns": destination.get("rdns", ""),
        "rdap_name": rdap.get("name", ""),
        "vt_malicious": vt.get("malicious"),
        "vt_suspicious": vt.get("suspicious"),
        "tor_exit": destination.get("tor_exit", False),
        "first_seen": iso_utc(destination["first_seen"]),
        "last_seen": iso_utc(destination["last_seen"]),
    }


def legacy_records(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [_flat_record(dest) for dest in report["destinations"]]


def save_results_json(report: Dict[str, Any], path: str) -> None:
    """Write the backwards-compatible flat destination list."""
    atomic_write_json(path, legacy_records(report))
    Logger(quiet=True).debug(f"results JSON written: {path}")


def save_analysis_json(report: Dict[str, Any], path: str) -> None:
    atomic_write_json(path, report)


def save_destinations_csv(report: Dict[str, Any], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEGACY_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(legacy_records(report))


def save_domains_csv(report: Dict[str, Any], path: str) -> None:
    fields = ["domain", "base", "category", "hits", "sni", "dns", "http",
              "clients", "ips", "vt_malicious", "first_seen", "last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["domains"]:
            writer.writerow({
                "domain": row["domain"],
                "base": row["base"],
                "category": row["category"],
                "hits": row["hits"],
                "sni": row["sources"].get("sni", 0),
                "dns": row["sources"].get("dns", 0),
                "http": row["sources"].get("http", 0),
                "clients": ";".join(row["clients"]),
                "ips": ";".join(row["ips"]),
                "vt_malicious": (row.get("vt") or {}).get("malicious"),
                "first_seen": iso_utc(row["first_seen"]),
                "last_seen": iso_utc(row["last_seen"]),
            })


def save_flows_csv(report: Dict[str, Any], path: str) -> None:
    fields = ["client", "dst", "proto", "dport", "service", "packets",
              "packets_out", "packets_in", "bytes", "bytes_out", "bytes_in",
              "domains", "ja4", "first_seen", "last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in report["flows"]:
            flat = dict(row)
            flat["domains"] = "; ".join(row.get("domains", []))
            flat["first_seen"] = iso_utc(row["first_seen"])
            flat["last_seen"] = iso_utc(row["last_seen"])
            writer.writerow(flat)


def save_dns_csv(report: Dict[str, Any], path: str) -> None:
    fields = ["qname", "base", "qtype", "count", "answers", "clients",
              "response_ms", "first_seen", "last_seen"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in report["dns"]:
            writer.writerow({
                "qname": row["qname"],
                "base": row["base"],
                "qtype": row["qtype"],
                "count": row["count"],
                "answers": ";".join(row["answers"]),
                "clients": ";".join(row["clients"]),
                "response_ms": row["response_ms"],
                "first_seen": iso_utc(row["first_seen"]),
                "last_seen": iso_utc(row["last_seen"]),
            })


def save_findings_csv(report: Dict[str, Any], path: str) -> None:
    fields = ["severity", "confidence", "id", "title", "detail", "score",
              "ips", "domains", "mitre", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for finding in report["findings"]:
            row = dict(finding)
            row["ips"] = ";".join(finding.get("ips", []))
            row["domains"] = ";".join(finding.get("domains", []))
            row["mitre"] = ";".join(finding.get("mitre", []))
            writer.writerow(row)


def save_summary_txt(report: Dict[str, Any], analysis: Analysis, path: str) -> None:
    meta, summary = report["meta"], report["summary"]
    lines = [
        f"{APP_NAME} {__version__} - network traffic analysis",
        "=" * 72,
        f"Capture     : {meta.get('file') or meta.get('name', '')}",
        f"Path        : {meta.get('source') or meta.get('path', '')}",
        f"SHA-256     : {meta.get('sha256', '')}",
        f"Generated   : {meta.get('generated_iso', '')} UTC",
        f"Window      : {iso_utc(meta.get('first_seen'))} .. {iso_utc(meta.get('last_seen'))}"
        f"  ({human_duration(meta.get('duration'))})",
        f"Packets     : {summary.get('packets', 0):,} total, "
        f"{summary.get('analyzed_packets', 0):,} analyzed",
        f"Traffic     : {human_bytes(summary.get('bytes'))} total, "
        f"{human_bytes(summary.get('analyzed_bytes'))} analyzed",
        f"Selection   : mode={meta.get('mode', '?')}  target={meta.get('target') or '-'}",
        f"Clients     : {', '.join(analysis.capture.get('clients_detected', {})) or '-'}",
        "",
        "Summary",
        "-" * 72,
        f"Destinations: {summary['ips']}   Countries: {summary['countries']}   "
        f"Providers: {summary['providers']}   ASNs: {summary['asns']}",
        f"Domains     : {summary['domains']}   DNS queries: {summary['dns_query_count']} "
        f"({summary['dns_queries']} unique name/type pairs)",
        f"Risk        : {summary['malicious']} malicious, {summary['suspicious']} suspicious, "
        f"{summary['tor_exits']} Tor exit, {summary['clean']} clean, "
        f"{summary['unknown']} not checked",
        "Findings    : " + ", ".join(
            f"{k}={v}" for k, v in sorted(
                summary["findings_by_severity"].items(),
                key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        ),
        "",
        "Findings",
        "-" * 72,
    ]
    if not report["findings"]:
        lines.append("No findings above the configured thresholds.")
    for finding in report["findings"]:
        lines.append(
            f"[{finding['severity'].upper():8}] {finding['title']} "
            f"(confidence: {finding['confidence']}, score {finding['score']:.2f})"
        )
        lines.append(f"           {finding['detail']}")
        if finding.get("ips"):
            lines.append(f"           IPs: {', '.join(finding['ips'][:12])}")
        if finding.get("domains"):
            lines.append(f"           Domains: {', '.join(finding['domains'][:12])}")
        if finding.get("mitre"):
            lines.append(f"           ATT&CK: {', '.join(finding['mitre'])}")
        if finding.get("remediation"):
            lines.append(f"           Next: {finding['remediation']}")
    lines.extend(["", "Top destinations by bytes", "-" * 72])
    for dest in report["destinations"][:20]:
        geo = dest.get("geo") or {}
        lines.append(
            f"{dest['ip']:39} {dest['bytes']:>12,} B  {dest['packets']:>8,} pkt  "
            f"{geo.get('country', '?')[:18]:18} {geom_isp(geo)[:28]:28} {dest['risk']}"
        )
    lines.extend(["", "Top domains by hits", "-" * 72])
    for domain in report["domains"][:30]:
        lines.append(
            f"{domain['hits']:>6}  {domain['category'][:28]:28}  {domain['domain']}"
        )
    lines.extend([
        "",
        "Definitions",
        "-" * 72,
        "Packets/bytes are both directions for the selected clients unless noted.",
        "Risk 'unknown' means VirusTotal was not queried or had no record.",
        "Findings are heuristics for triage, not proof of malicious activity.",
        "",
        "Full data: data/analysis.json, data/results.csv, data/flows.csv, data/dns.csv",
        "Dashboard: dashboard.html",
    ])
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def geom_isp(geo: Dict[str, Any]) -> str:
    return geo.get("isp") or geo.get("org") or ""


# --------------------------------------------------------------------------
# HTML dashboard
# --------------------------------------------------------------------------

def _write_text_atomic(path: str, text: str) -> None:
    folder = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".html", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def build_dashboard(report: Dict[str, Any], out_html: str,
                    logger: Optional[Logger] = None) -> str:
    """Render the self-contained dashboard from the report and template."""
    logger = logger or Logger(quiet=True)
    template_path = resource_path(os.path.join("templates", "dashboard.html"))
    try:
        with open(template_path, encoding="utf-8") as handle:
            template = handle.read()
    except OSError as exc:
        raise RuntimeError(
            f"dashboard template not found ({template_path}): {exc}"
        ) from exc

    geo_path = resource_path("world.geo.json")
    try:
        with open(geo_path, encoding="utf-8") as handle:
            geojson = handle.read()
    except OSError:
        logger.warn(f"world.geo.json not found ({geo_path}); the map will be empty.")
        geojson = '{"type":"FeatureCollection","features":[]}'

    html = template
    html = html.replace("/*__REPORT__*/", safe_json_dumps(report))
    html = html.replace("/*__GEO__*/", geojson)
    _write_text_atomic(out_html, html)
    logger.info(f"Dashboard saved: {out_html}")
    return out_html


def save_all(analysis: Analysis, report: Dict[str, Any], run_dir: str,
             data_dir: str, domains_dir: str, logger: Logger) -> Dict[str, str]:
    """Write every output file and return their paths."""
    paths: Dict[str, str] = {}
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(domains_dir, exist_ok=True)

    paths["analysis_json"] = os.path.join(data_dir, "analysis.json")
    save_analysis_json(report, paths["analysis_json"])
    paths["results_json"] = os.path.join(data_dir, "results.json")
    save_results_json(report, paths["results_json"])
    paths["results_csv"] = os.path.join(data_dir, "results.csv")
    save_destinations_csv(report, paths["results_csv"])
    paths["domains_csv"] = os.path.join(data_dir, "domains.csv")
    save_domains_csv(report, paths["domains_csv"])
    paths["flows_csv"] = os.path.join(data_dir, "flows.csv")
    save_flows_csv(report, paths["flows_csv"])
    paths["dns_csv"] = os.path.join(data_dir, "dns.csv")
    save_dns_csv(report, paths["dns_csv"])
    paths["findings_csv"] = os.path.join(data_dir, "findings.csv")
    save_findings_csv(report, paths["findings_csv"])
    paths["summary_txt"] = os.path.join(data_dir, "summary.txt")
    save_summary_txt(report, analysis, paths["summary_txt"])

    # Keep the original text file names/locations for backwards compatibility.
    with open(os.path.join(domains_dir, "sni_hosts.txt"), "w", encoding="utf-8") as handle:
        for stat in sorted(analysis.domains.values(),
                           key=lambda s: sum(s.sources.values()), reverse=True):
            if stat.sources.get("sni") or stat.sources.get("http"):
                handle.write(stat.domain + "\n")
    with open(os.path.join(domains_dir, "dns_queries.txt"), "w", encoding="utf-8") as handle:
        for stat in sorted(analysis.dns_queries.values(), key=lambda s: s.count, reverse=True):
            if stat.count:
                handle.write(stat.qname + "\n")
    with open(os.path.join(domains_dir, "classification.txt"), "w", encoding="utf-8") as handle:
        for category in CATEGORY_ORDER:
            rows = report["classification"].get(category, [])
            if not rows:
                continue
            handle.write(f"== {category} ({len(rows)}) ==\n")
            for domain, hits in rows:
                handle.write(f"  {domain}  ({hits})\n")
            handle.write("\n")

    for key, path in paths.items():
        logger.debug(f"{key}: {path}")
    return paths
