# -*- coding: utf-8 -*-
"""Heuristic traffic analysis and threat-intelligence findings.

The goal is to help a human triage a capture, not to prove malice. Every
finding is therefore labelled with a severity, a confidence and the evidence
that produced it, and thresholds are intentionally conservative.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .classify import (
    CAT_CDN, CAT_CLOUD, TOR_PORTS, base_domain, classify_domain,
    port_service, subdomain_prefix,
)
from .allowlist import Allowlist
from .models import Analysis, Finding
from .util import coefficient_of_variation, entropy, median, percentage


@dataclass
class AnalysisOptions:
    """Thresholds for the heuristic detectors."""

    target: str = ""
    beacon_min_events: int = 5
    beacon_max_cv: float = 0.50
    beacon_min_interval: float = 5.0
    beacon_max_interval: float = 3600.0
    beacon_max_findings: int = 15
    exfil_min_bytes: int = 5 * 1024 * 1024
    exfil_ratio: float = 5.0
    dns_min_unique: int = 20
    dns_max_findings: int = 10
    scan_min_ports: int = 25
    tor_max_destinations: int = 4
    tor_min_bytes: int = 200 * 1024
    allowlist: Optional[Allowlist] = None


# Ports where "regular" traffic is expected and not interesting for beaconing.
_BEACON_IGNORE_PORTS = {53, 123, 5353, 1900, 67, 68}

#: Threshold presets. Explicit CLI/config values always win over the profile.
HEURISTIC_PROFILES: Dict[str, Dict[str, Any]] = {
    "quiet": {
        "beacon_min_events": 8,
        "beacon_max_cv": 0.35,
        "exfil_min_bytes": 25 * 1024 * 1024,
        "exfil_ratio": 8.0,
        "dns_min_unique": 40,
        "scan_min_ports": 50,
        "tor_max_destinations": 2,
        "tor_min_bytes": 1024 * 1024,
    },
    "balanced": {},
    "aggressive": {
        "beacon_min_events": 4,
        "beacon_max_cv": 0.65,
        "exfil_min_bytes": 2 * 1024 * 1024,
        "exfil_ratio": 3.0,
        "dns_min_unique": 12,
        "scan_min_ports": 15,
        "tor_max_destinations": 8,
        "tor_min_bytes": 100 * 1024,
    },
}


def profile_thresholds(name: str) -> Dict[str, Any]:
    """Return a copy of the threshold overrides for a named profile."""
    try:
        return dict(HEURISTIC_PROFILES[name])
    except KeyError:
        choices = ", ".join(HEURISTIC_PROFILES)
        raise ValueError(f"unknown heuristic profile {name!r} (choose {choices})") from None

#: Analyst playbooks keyed by finding id: (remediation, MITRE ATT&CK refs).
PLAYBOOKS: Dict[str, Tuple[str, List[str]]] = {
    "beaconing": (
        "Identify the process on the client and compare the schedule with known "
        "update/telemetry traffic. If it is unexpected, block the destination, "
        "isolate the host and review persistence.",
        ["T1071.001 Application Layer Protocol: Web Protocols",
         "T1571 Non-Standard Port"],
    ),
    "outbound_volume": (
        "Confirm the destination is an approved backup/cloud service. If not, "
        "inspect the uploading process, preserve logs, suspend it and apply "
        "egress filtering/DLP.",
        ["T1048 Exfiltration Over Alternative Protocol",
         "T1567 Exfiltration Over Web Service"],
    ),
    "dns_anomaly": (
        "Inspect the DNS payloads, validate the base domain, and consider "
        "blocking it at the resolver. Correlate the queries with the client "
        "process and check for tunnelling tools.",
        ["T1071.004 Application Layer Protocol: DNS",
         "T1568.002 Domain Generation Algorithms"],
    ),
    "port_scan": (
        "Identify the scanning host/process, isolate it, and check whether the "
        "scan came from malware or from an authorised scanner.",
        ["T1046 Network Service Discovery"],
    ),
    "tor_like": (
        "Decide whether anonymity software is allowed by policy, then review "
        "the endpoint and correlate with the user/process. Tor-like traffic "
        "alone is not proof of malicious activity.",
        ["T1090.003 Multi-hop Proxy"],
    ),
    "cleartext": (
        "Prefer encrypted alternatives (HTTPS, SSH, IMAPS, SMTPS), block legacy "
        "plaintext protocols at the firewall, and rotate any credentials that "
        "may have been sent in the clear.",
        ["T1040 Network Sniffing"],
    ),
    "retransmissions": (
        "Check the local link, Wi-Fi signal, duplex/speed settings and upstream "
        "congestion. Retransmissions usually indicate packet loss, not an attack.",
        [],
    ),
    "vt_malicious": (
        "Block the indicator, isolate the contacting host, collect EDR/process "
        "evidence and submit related files for analysis. Reputation hits are "
        "leads, not proof.",
        ["T1071.001 Application Layer Protocol: Web Protocols"],
    ),
    "vt_suspicious": (
        "Review the detection details and the host's history before blocking. "
        "Confirm whether the destination is expected for this environment.",
        ["T1071.001 Application Layer Protocol: Web Protocols"],
    ),
    "vt_domain": (
        "Block the domain, review which clients resolved or contacted it, and "
        "collect endpoint evidence. Reputation hits are leads, not proof.",
        ["T1071.001 Application Layer Protocol: Web Protocols"],
    ),
    "tor_exit": (
        "Confirm whether Tor use is allowed by policy and review the endpoint "
        "and user/process behind it. Exit-node membership alone is not evidence "
        "of malice.",
        ["T1090.003 Multi-hop Proxy"],
    ),
}


def apply_playbooks(findings: List[Finding]) -> List[Finding]:
    """Attach remediation guidance and ATT&CK references to findings."""
    for finding in findings:
        remediation, mitre = PLAYBOOKS.get(finding.id, ("", []))
        if not finding.remediation:
            finding.remediation = remediation
        if not finding.mitre:
            finding.mitre = list(mitre)
    return findings


def apply_categories(analysis: Analysis, target: str = "") -> None:
    """Assign the heuristic category to every observed domain."""
    for domain, stat in analysis.domains.items():
        stat.category = classify_domain(domain, target)


def run_heuristics(analysis: Analysis, options: Optional[AnalysisOptions] = None) -> List[Finding]:
    """Run all local (network-free) detectors and append findings."""
    options = options or AnalysisOptions()
    findings: List[Finding] = []
    findings.extend(_detect_beaconing(analysis, options))
    findings.extend(_detect_exfiltration(analysis, options))
    findings.extend(_detect_dns_anomalies(analysis, options))
    findings.extend(_detect_port_scan(analysis, options))
    findings.extend(_detect_tor_like(analysis, options))
    findings.extend(_detect_cleartext(analysis))
    findings.extend(_detect_retransmissions(analysis))
    findings = apply_playbooks(findings)
    if options.allowlist and options.allowlist.entries:
        findings, suppressed = options.allowlist.filter(findings)
        if suppressed:
            analysis.warnings.append(
                f"Allowlist suppressed {suppressed} finding(s) "
                f"({options.allowlist.describe()})."
            )
    analysis.findings.extend(findings)
    return findings


# --------------------------------------------------------------------------
# Beaconing
# --------------------------------------------------------------------------

def _detect_beaconing(analysis: Analysis, options: AnalysisOptions) -> List[Finding]:
    groups: Dict[Tuple[str, str, str, int], List[float]] = defaultdict(list)
    for timestamp, client, dest, proto, dport in analysis.stream_events:
        if not client or not dest:
            continue
        if int(dport or 0) in _BEACON_IGNORE_PORTS:
            continue
        groups[(client, dest, proto, int(dport or 0))].append(timestamp)

    findings: List[Finding] = []
    for (client, dest, proto, dport), times in groups.items():
        times.sort()
        # Collapse bursts (parallel connections opened at the same moment).
        deduped: List[float] = []
        for ts in times:
            if not deduped or ts - deduped[-1] >= 1.0:
                deduped.append(ts)
        if len(deduped) < options.beacon_min_events:
            continue
        gaps = [b - a for a, b in zip(deduped, deduped[1:]) if b - a > 0.25]
        if len(gaps) < options.beacon_min_events - 1:
            continue
        med = median(gaps)
        if not (options.beacon_min_interval <= med <= options.beacon_max_interval):
            continue
        cv = coefficient_of_variation(gaps)
        tolerance = max(2.0, med * 0.20)
        regular = sum(1 for gap in gaps if abs(gap - med) <= tolerance) / len(gaps)
        if regular < 0.70 or cv > options.beacon_max_cv:
            continue
        score = regular * max(0.0, 1.0 - cv) * min(1.0, len(deduped) / 12.0)
        confidence = "high" if regular >= 0.85 and cv <= 0.25 else "medium"
        dest_obj = analysis.destinations.get(dest)
        domain = ""
        if dest_obj and dest_obj.domains:
            domain = dest_obj.domains.most_common(1)[0][0]
        findings.append(Finding(
            id="beaconing",
            severity="medium",
            title="Possible periodic beaconing",
            detail=(
                f"{client} contacted {dest}:{dport} ({port_service(dport, proto)}) "
                f"{len(deduped)} times with a median interval of {med:.1f}s "
                f"(regularity {regular:.0%}, CV {cv:.2f})."
                + (f" Hostname: {domain}." if domain else "")
            ),
            score=score,
            confidence=confidence,
            ips=[dest],
            domains=[domain] if domain else [],
            evidence={
                "client": client, "proto": proto, "port": dport,
                "events": len(deduped), "median_interval_s": round(med, 2),
                "cv": round(cv, 3), "regularity": round(regular, 3),
                "first_seen": deduped[0], "last_seen": deduped[-1],
            },
        ))
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:options.beacon_max_findings]


# --------------------------------------------------------------------------
# Outbound volume / exfiltration
# --------------------------------------------------------------------------

def _detect_exfiltration(analysis: Analysis, options: AnalysisOptions) -> List[Finding]:
    findings: List[Finding] = []
    for dest in analysis.destinations.values():
        if dest.bytes_out < options.exfil_min_bytes:
            continue
        ratio = dest.bytes_out / max(1, dest.bytes_in)
        if ratio < options.exfil_ratio:
            continue
        domain = dest.domains.most_common(1)[0][0] if dest.domains else ""
        category = classify_domain(domain, "") if domain else ""
        # Backups and cloud uploads are expected to be asymmetric; only raise
        # the confidence when the destination is otherwise unexplained.
        unexplained = not domain or category in ("Unclassified", "")
        severity = "medium" if unexplained and ratio >= 10 and dest.bytes_out >= 10 * 1024 * 1024 else "low"
        confidence = "medium" if unexplained else "low"
        findings.append(Finding(
            id="outbound_volume",
            severity=severity,
            title="Asymmetric outbound transfer",
            detail=(
                f"{dest.ip} received {dest.bytes_out / (1024 * 1024):.1f} MiB from the client "
                f"and sent back {dest.bytes_in / (1024 * 1024):.1f} MiB "
                f"(ratio {ratio:.1f}:1)."
                + (f" Hostname: {domain}." if domain else " No hostname was observed for this IP.")
            ),
            score=min(1.0, dest.bytes_out / (50 * 1024 * 1024)),
            confidence=confidence,
            ips=[dest.ip],
            domains=[domain] if domain else [],
            evidence={
                "bytes_out": dest.bytes_out, "bytes_in": dest.bytes_in,
                "ratio": round(ratio, 2), "category": category,
            },
        ))
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:5]


# --------------------------------------------------------------------------
# DNS anomalies (possible tunnelling / DGA)
# --------------------------------------------------------------------------

def _detect_dns_anomalies(analysis: Analysis, options: AnalysisOptions) -> List[Finding]:
    by_base: Dict[str, List] = defaultdict(list)
    for (qname, qtype), stat in analysis.dns_queries.items():
        if stat.count <= 0:
            continue
        by_base[base_domain(qname)].append(stat)

    findings: List[Finding] = []
    for base, stats in by_base.items():
        unique_names = {stat.qname for stat in stats}
        if len(unique_names) < options.dns_min_unique:
            continue
        prefixes = [subdomain_prefix(name) for name in unique_names]
        prefixes = [p for p in prefixes if p]
        if not prefixes:
            continue
        labels = [label for prefix in prefixes for label in prefix.split(".")]
        max_label = max((len(label) for label in labels), default=0)
        avg_entropy = sum(entropy(label) for label in labels) / max(1, len(labels))
        query_counts = Counter()
        for stat in stats:
            query_counts[stat.qtype_name] += stat.count
        txt_like = query_counts.get("TXT", 0) + query_counts.get("NULL", 0) + query_counts.get("ANY", 0)
        long_labels = sum(1 for label in labels if len(label) >= 30)

        suspicious = (
            (len(prefixes) >= options.dns_min_unique and max_label >= 50)
            or (txt_like >= 10 and len(prefixes) >= 10)
            or (len(prefixes) >= options.dns_min_unique
                and avg_entropy >= 3.5
                and sum(len(label) for label in labels) / len(labels) >= 15
                and long_labels >= max(3, len(labels) // 4))
        )
        if not suspicious:
            continue
        if txt_like:
            confidence, severity = "medium", "medium"
        else:
            confidence, severity = "low", "low"
        category = classify_domain(base, options.target)
        if category in (CAT_CDN, CAT_CLOUD) and not txt_like:
            # CDNs legitimately use huge numbers of random subdomains.
            confidence, severity = "low", "info"
        score = min(1.0, len(prefixes) / 100.0) * (0.5 + min(0.5, avg_entropy / 8.0))
        findings.append(Finding(
            id="dns_anomaly",
            severity=severity,
            title="Unusual DNS pattern (possible tunnelling / DGA)",
            detail=(
                f"{len(prefixes)} unique subdomains under {base}, "
                f"average label entropy {avg_entropy:.2f} bits, "
                f"longest label {max_label} chars, "
                f"TXT/NULL/ANY queries: {txt_like}."
            ),
            score=score,
            confidence=confidence,
            domains=[base],
            evidence={
                "unique_subdomains": len(prefixes),
                "avg_entropy": round(avg_entropy, 3),
                "max_label_len": max_label,
                "qtypes": dict(query_counts),
                "samples": sorted(unique_names)[:8],
            },
        ))
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:options.dns_max_findings]


# --------------------------------------------------------------------------
# Port scanning
# --------------------------------------------------------------------------

def _detect_port_scan(analysis: Analysis, options: AnalysisOptions) -> List[Finding]:
    by_pair: Dict[Tuple[str, str], List] = defaultdict(list)
    for flow in analysis.flows.values():
        if flow.client and flow.client != "-":
            by_pair[(flow.client, flow.dst)].append(flow)

    findings: List[Finding] = []
    for (client, dest), flows in by_pair.items():
        ports = {flow.dport for flow in flows if flow.dport}
        if len(ports) < options.scan_min_ports:
            continue
        small = [f for f in flows if f.packets_out <= 3]
        if len(small) < max(10, int(len(flows) * 0.7)):
            continue
        syns = sum(f.syn_count for f in flows)
        if syns < 10:
            continue
        findings.append(Finding(
            id="port_scan",
            severity="medium",
            title="Possible port scan",
            detail=(
                f"{client} contacted {len(ports)} distinct ports on {dest} "
                f"with mostly single-packet connections ({syns} SYNs)."
            ),
            score=min(1.0, len(ports) / 200.0),
            confidence="medium" if len(ports) >= 50 else "low",
            ips=[dest],
            evidence={"client": client, "ports": sorted(ports)[:60],
                      "unique_ports": len(ports), "syns": syns},
        ))
    findings.sort(key=lambda f: f.score, reverse=True)
    return findings[:5]


# --------------------------------------------------------------------------
# Tor-like / anonymising proxy
# --------------------------------------------------------------------------

def _detect_tor_like(analysis: Analysis, options: AnalysisOptions) -> List[Finding]:
    destinations = list(analysis.destinations.values())
    if not destinations or len(destinations) > options.tor_max_destinations:
        return []
    total_bytes = sum(d.bytes for d in destinations)
    if total_bytes < options.tor_min_bytes:
        return []
    client_dns = sum(stat.count for stat in analysis.dns_queries.values())
    tor_ports = sorted({port for d in destinations for port in d.ports if port in TOR_PORTS})
    tls_bytes = sum(d.bytes for d in destinations
                    if any(label in d.protocols for label in ("TLS", "QUIC")))
    tls_share = tls_bytes / max(1, total_bytes)
    if not tor_ports:
        # Only claim "Tor-like" without a known port when there is almost no
        # DNS, very few destinations and nearly all traffic is TLS.
        if client_dns > 2 or tls_share < 0.90 or total_bytes < 1024 * 1024:
            return []
    return [Finding(
        id="tor_like",
        severity="info",
        title="Possible Tor / anonymising proxy traffic",
        detail=(
            f"Only {len(destinations)} destination(s), {client_dns} DNS queries and "
            f"{percentage(tls_bytes, total_bytes):.0f}% TLS/QUIC traffic. "
            + (f"Tor-related ports observed: {', '.join(map(str, tor_ports))}."
               if tor_ports else "No hostname resolution was visible for most traffic.")
        ),
        score=0.9 if tor_ports else 0.5,
        confidence="high" if tor_ports else "low",
        ips=[d.ip for d in destinations],
        evidence={
            "destinations": len(destinations),
            "dns_queries": client_dns,
            "tls_share": round(tls_share, 3),
            "tor_ports": tor_ports,
            "bytes": total_bytes,
        },
    )]


# --------------------------------------------------------------------------
# Cleartext / network quality
# --------------------------------------------------------------------------

def _detect_cleartext(analysis: Analysis) -> List[Finding]:
    affected = [d for d in analysis.destinations.values() if d.has_cleartext]
    if not affected:
        return []
    affected.sort(key=lambda d: d.bytes, reverse=True)
    ports = Counter()
    for dest in affected:
        for port, count in dest.ports.items():
            ports[port] += count
    return [Finding(
        id="cleartext",
        severity="low",
        title="Cleartext application traffic",
        detail=(
            f"{len(affected)} destination(s) exchanged unencrypted application "
            f"protocols (HTTP/FTP/Telnet/SMTP/etc.). Credentials and content may "
            f"be readable on the wire."
        ),
        score=min(1.0, len(affected) / 20.0),
        confidence="medium",
        ips=[d.ip for d in affected[:20]],
        evidence={"destinations": len(affected), "ports": dict(ports.most_common(10))},
    )]


def _detect_retransmissions(analysis: Analysis) -> List[Finding]:
    total_packets = sum(d.packets for d in analysis.destinations.values())
    total_retrans = sum(d.retransmissions for d in analysis.destinations.values())
    if total_packets < 500 or total_retrans < 20:
        return []
    rate = percentage(total_retrans, total_packets)
    if rate < 2.0:
        return []
    worst = sorted(analysis.destinations.values(),
                   key=lambda d: d.retransmissions, reverse=True)[:10]
    return [Finding(
        id="retransmissions",
        severity="info",
        title="High TCP retransmission rate",
        detail=(
            f"{total_retrans} retransmissions out of {total_packets} packets "
            f"({rate:.1f}%). This points to packet loss or a congested link, "
            f"not necessarily malicious activity."
        ),
        score=min(1.0, rate / 10.0),
        confidence="high",
        ips=[d.ip for d in worst if d.retransmissions],
        evidence={"retransmissions": total_retrans, "packets": total_packets,
                  "rate_percent": round(rate, 2)},
    )]


# --------------------------------------------------------------------------
# Threat intelligence (after enrichment)
# --------------------------------------------------------------------------

def run_threat_intel(analysis: Analysis) -> List[Finding]:
    """Create findings from VirusTotal, rDNS and Tor exit-list results."""
    findings: List[Finding] = []
    for dest in analysis.destinations.values():
        malicious = dest.vt.get("malicious")
        suspicious = dest.vt.get("suspicious")
        if isinstance(malicious, int) and malicious > 0:
            severity = "critical" if malicious >= 5 else ("high" if malicious >= 2 else "medium")
            findings.append(Finding(
                id="vt_malicious",
                severity=severity,
                title="Destination flagged by VirusTotal",
                detail=(
                    f"{dest.ip} is flagged as malicious by {malicious} engine(s)"
                    + (f" and suspicious by {suspicious}." if suspicious else ".")
                ),
                score=min(1.0, malicious / 20.0),
                confidence="high",
                ips=[dest.ip],
                domains=list(dest.domains)[:5],
                evidence={"malicious": malicious, "suspicious": suspicious,
                          "link": f"https://www.virustotal.com/gui/ip-address/{dest.ip}"},
            ))
        elif isinstance(suspicious, int) and suspicious > 0:
            findings.append(Finding(
                id="vt_suspicious",
                severity="low",
                title="Destination flagged as suspicious",
                detail=f"{dest.ip} has {suspicious} suspicious detection(s) on VirusTotal.",
                score=min(1.0, suspicious / 10.0),
                confidence="medium",
                ips=[dest.ip],
                evidence={"suspicious": suspicious},
            ))
        if dest.tor_exit:
            findings.append(Finding(
                id="tor_exit",
                severity="info",
                title="Known Tor exit node",
                detail=f"{dest.ip} appears in the Tor exit-node list.",
                score=0.8,
                confidence="high",
                ips=[dest.ip],
                evidence={},
            ))

    for domain, stat in analysis.domains.items():
        malicious = stat.vt.get("malicious")
        if isinstance(malicious, int) and malicious > 0:
            findings.append(Finding(
                id="vt_domain",
                severity="medium" if malicious < 3 else "high",
                title="Domain flagged by VirusTotal",
                detail=f"{domain} is flagged by {malicious} engine(s).",
                score=min(1.0, malicious / 20.0),
                confidence="high",
                domains=[domain],
                ips=list(stat.ips)[:5],
                evidence={"malicious": malicious,
                          "link": f"https://www.virustotal.com/gui/domain/{domain}"},
            ))
    return apply_playbooks(findings)


def sort_findings(analysis: Analysis) -> None:
    analysis.findings.sort(key=lambda finding: finding.sort_key())
