# -*- coding: utf-8 -*-
"""Data structures shared by extraction, analysis and reporting."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


#: Severity order used for sorting and ``--fail-on``.
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Destination:
    """Aggregated statistics for one contacted (public) IP address."""

    ip: str
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    ports: Counter = field(default_factory=Counter)       # server-side ports
    protocols: Counter = field(default_factory=Counter)   # tcp/udp/quic/tls...
    clients: Counter = field(default_factory=Counter)
    domains: Counter = field(default_factory=Counter)
    tls_versions: Counter = field(default_factory=Counter)
    alpn: Counter = field(default_factory=Counter)
    ja4: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    http_methods: Counter = field(default_factory=Counter)
    retransmissions: int = 0
    tcp_packets: int = 0
    syn_count: int = 0
    cleartext_ports: Counter = field(default_factory=Counter)
    geo: Dict[str, Any] = field(default_factory=dict)
    vt: Dict[str, Any] = field(default_factory=dict)
    rdns: str = ""
    rdap: Dict[str, Any] = field(default_factory=dict)
    tor_exit: bool = False
    has_cleartext: bool = False

    @property
    def packets(self) -> int:
        return self.packets_out + self.packets_in

    @property
    def bytes(self) -> int:
        return self.bytes_out + self.bytes_in

    @property
    def vt_malicious(self) -> Optional[int]:
        value = self.vt.get("malicious")
        return value if isinstance(value, int) else None

    @property
    def vt_suspicious(self) -> Optional[int]:
        value = self.vt.get("suspicious")
        return value if isinstance(value, int) else None


@dataclass
class DomainStat:
    """A hostname observed via SNI, HTTP Host or DNS."""

    domain: str
    category: str = "Unclassified"
    sources: Counter = field(default_factory=Counter)  # sni/http/dns
    clients: Counter = field(default_factory=Counter)
    ips: Counter = field(default_factory=Counter)
    first_seen: float = 0.0
    last_seen: float = 0.0
    vt: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClientStat:
    """A local device seen in the capture."""

    ip: str
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    destinations: Counter = field(default_factory=Counter)
    domains: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    hostnames: Counter = field(default_factory=Counter)
    #: Why this address counts as a client (hotspot, src-ip, auto, mac, ...).
    selected_by: str = ""
    macs: Set[str] = field(default_factory=set)

    @property
    def packets(self) -> int:
        return self.packets_out + self.packets_in

    @property
    def bytes(self) -> int:
        return self.bytes_out + self.bytes_in


@dataclass
class Flow:
    """A unidirectional-ish conversation grouped by client, server and port.

    ``packets_out``/``bytes_out`` are client -> server; ``_in`` is the reverse.
    """

    client: str
    dst: str
    proto: str
    dport: int
    packets_out: int = 0
    packets_in: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    domains: Counter = field(default_factory=Counter)
    syn_count: int = 0
    ja4: str = ""

    @property
    def packets(self) -> int:
        return self.packets_out + self.packets_in

    @property
    def bytes(self) -> int:
        return self.bytes_out + self.bytes_in


@dataclass
class DNSQueryStat:
    """Aggregated DNS query information for one name/type pair."""

    qname: str
    qtype: int
    qtype_name: str = "A"
    count: int = 0
    clients: Counter = field(default_factory=Counter)
    answers: Counter = field(default_factory=Counter)
    first_seen: float = 0.0
    last_seen: float = 0.0
    response_time_ms: float = 0.0       # average over ``responses``
    max_response_time_ms: float = 0.0
    responses: int = 0

    def add_response_time(self, milliseconds: float) -> None:
        self.responses += 1
        self.response_time_ms += (milliseconds - self.response_time_ms) / self.responses
        self.max_response_time_ms = max(self.max_response_time_ms, milliseconds)


@dataclass
class Finding:
    """A heuristic or threat-intelligence observation."""

    id: str
    severity: str
    title: str
    detail: str
    score: float = 0.0
    confidence: str = "medium"
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    mitre: List[str] = field(default_factory=list)

    def sort_key(self) -> Tuple[int, float]:
        return (-SEVERITY_ORDER.get(self.severity, 0), -self.score)


@dataclass
class Analysis:
    """Everything extracted from one or more capture files (pre-enrichment)."""

    capture: Dict[str, Any] = field(default_factory=dict)
    destinations: Dict[str, Destination] = field(default_factory=dict)
    clients: Dict[str, ClientStat] = field(default_factory=dict)
    domains: Dict[str, DomainStat] = field(default_factory=dict)
    flows: Dict[Tuple[str, str, str, int], Flow] = field(default_factory=dict)
    dns_queries: Dict[Tuple[str, int], DNSQueryStat] = field(default_factory=dict)
    dns_answers: Dict[str, Set[str]] = field(default_factory=dict)   # ip -> names
    dns_names: Dict[str, Set[str]] = field(default_factory=dict)     # name -> ips
    dns_servers: Counter = field(default_factory=Counter)
    protocols: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    timeline: Dict[int, List[int]] = field(default_factory=dict)  # second -> [o_p, i_p, o_b, i_b]
    stream_events: List[Tuple[float, str, str, str, int]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    suppressed_findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    enrichment: Dict[str, Any] = field(default_factory=dict)
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0
    selected_packets: int = 0
    selected_bytes: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)


#: Human-readable DNS query types.
DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR", 13: "HINFO",
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC",
    33: "SRV", 35: "NAPTR", 36: "KX", 37: "CERT", 39: "DNAME", 41: "OPT", 43: "DS",
    44: "SSHFP", 45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
    49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA",
    55: "HIP", 59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC",
    63: "ZONEMD", 64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48",
    109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR", 252: "AXFR",
    255: "ANY", 256: "URI", 257: "CAA",
}


def dns_type_name(value: str) -> Tuple[int, str]:
    """Convert tshark's numeric DNS type (may be hex) to (int, label)."""
    try:
        number = int(str(value), 0)
    except (TypeError, ValueError):
        return 0, str(value or "?")
    return number, DNS_TYPES.get(number, str(number))
