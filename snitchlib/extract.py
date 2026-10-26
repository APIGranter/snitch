# -*- coding: utf-8 -*-
"""Turn the raw tshark field rows into an :class:`~snitchlib.models.Analysis`.

The extractor is deliberately streaming: it never stores one object per
packet. It keeps aggregates plus the timestamps needed for beaconing and the
DNS/SNI map used to tie hostnames to IPs.
"""

from __future__ import annotations

import functools
import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import (
    Analysis, ClientStat, DNSQueryStat, Destination, DomainStat, Flow,
    dns_type_name,
)
from .util import Logger


# --------------------------------------------------------------------------
# IP helpers
# --------------------------------------------------------------------------

#: RFC 6598 shared address space (carrier-grade NAT, Tailscale, mobile hotspots).
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


@functools.lru_cache(maxsize=65536)
def _parse_ip_cached(value: str):
    try:
        return ipaddress.ip_address(value.strip().strip("[]").split("%")[0])
    except ValueError:
        return None


def parse_ip(value: str):
    # Every packet parses the same few addresses many times; the cache makes
    # that a dictionary lookup instead of an ``ipaddress`` parse.
    return _parse_ip_cached(str(value or ""))


def is_public_ip(value: str) -> bool:
    """True only for internet-routable IPs (IPv4 and IPv6).

    ``is_global`` also excludes carrier-grade NAT (100.64.0.0/10) and other
    special-purpose ranges that ``is_private`` misses.
    """
    obj = parse_ip(value)
    if obj is None:
        return False
    return obj.is_global and not (
        obj.is_loopback or obj.is_multicast or obj.is_reserved
        or obj.is_link_local or obj.is_unspecified
    )


def is_local_ip(value: str) -> bool:
    """True for addresses plausibly belonging to the monitored device(s)."""
    obj = parse_ip(value)
    if obj is None:
        return False
    return bool(
        obj.is_private or obj.is_loopback or obj.is_link_local
        or obj.is_unspecified or obj in SHARED_ADDRESS_SPACE
    )


def normalize_ip(value: str) -> str:
    obj = parse_ip(value)
    return str(obj) if obj is not None else value.strip()


def first_value(value: Optional[str]) -> str:
    """First of tshark's comma-separated occurrences (the outer header).

    ICMP errors, GRE/IP-in-IP, 6in4 and Teredo carry two IP headers, and tshark
    then prints ``ip.src`` as ``"outer,inner"``.
    """
    return (value or "").split(",", 1)[0].strip()


_NBNS_SUFFIX_RE = re.compile(r"<[0-9a-f]{2}>\s*$", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
#: EHLO/HELO values that identify no useful device.
SMTP_PLACEHOLDER_NAMES = frozenset({
    "localhost", "localhost.localdomain", "unknown",
})
#: Leading reply codes / status words in cleartext service banners.
_BANNER_PREFIX_RE = re.compile(
    r"^\s*(?:\d{3}[- ]+|\+\s*OK\s+|\*\s+(?:OK|PREAUTH|BYE)\s+)", re.IGNORECASE
)
_BANNER_TOKEN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,252}[A-Za-z0-9])?")


def normalize_hostname(value: str) -> str:
    """Clean a DHCP/NetBIOS hostname for display, or return ``""``."""
    name = str(value or "").replace("\x00", "").strip().strip(".")
    name = _NBNS_SUFFIX_RE.sub("", name).strip().lower()
    if not name or len(name) > 253 or ".." in name:
        return ""
    if parse_ip(name) is not None:
        return ""
    if not _HOSTNAME_RE.match(name):
        return ""
    return name


def normalize_mac(value: str) -> str:
    """Normalize a DHCP client MAC address, or return ``""``."""
    raw = re.sub(r"[^0-9a-f]", "", str(value or "").lower())
    if len(raw) != 12 or raw == "0" * 12:
        return ""
    return ":".join(raw[index:index + 2] for index in range(0, 12, 2))


def parse_networks(values: Iterable[str]) -> List[ipaddress._BaseNetwork]:
    networks = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid network {value!r}: {exc}") from exc
    return networks


@dataclass
class ExtractionOptions:
    """Source-selection and filtering options for the extractor."""

    mode: str = "client"                    # client | ip | all
    src_ips: Set[str] = field(default_factory=set)
    client_networks: List[ipaddress._BaseNetwork] = field(default_factory=list)
    gateways: Set[str] = field(default_factory=set)
    auto_clients: bool = False
    exclude_networks: List[ipaddress._BaseNetwork] = field(default_factory=list)
    min_packets: int = 1
    #: Subset of ``client_networks`` that came from local-interface discovery
    #: (only used to label why a client was selected).
    detected_networks: List[ipaddress._BaseNetwork] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in ("client", "ip", "all"):
            raise ValueError(f"invalid mode {self.mode!r}")
        self.src_ips = {normalize_ip(ip) for ip in self.src_ips}
        self.gateways = {normalize_ip(ip) for ip in self.gateways}


#: The Windows Mobile Hotspot subnet SNItch was built around.
WINDOWS_HOTSPOT_NET = "192.168.137.0/24"


class ClientMatcher:
    """Decide whether an address is a monitored client.

    ``client`` mode restricts to the configured hotspot network(s) unless
    ``auto_clients`` is enabled, in which case every private/local address
    except the gateways counts as a client.
    """

    def __init__(self, options: ExtractionOptions) -> None:
        self.options = options
        self._cache: Dict[str, bool] = {}

    def __call__(self, ip: str) -> bool:
        cached = self._cache.get(ip)
        if cached is None:
            cached = self._cache[ip] = self._match(ip)
        return cached

    def _match(self, ip: str) -> bool:
        if self.options.mode == "ip":
            return normalize_ip(ip) in self.options.src_ips
        if self.options.mode == "all":
            return is_local_ip(ip)
        if normalize_ip(ip) in self.options.gateways:
            return False
        if self.options.auto_clients:
            return is_local_ip(ip)
        obj = parse_ip(ip)
        if obj is None:
            return False
        return any(obj in net for net in self.options.client_networks)

    def reason(self, ip: str) -> str:
        """Short label explaining why ``ip`` counts as a client ("" if not)."""
        if not self(ip):
            return ""
        if self.options.mode == "ip":
            return "src-ip"
        if self.options.mode == "all":
            return "all (local address)"
        obj = parse_ip(ip)
        for net in self.options.client_networks:
            if obj is not None and obj in net:
                if net in self.options.detected_networks:
                    return f"detected subnet {net}"
                if str(net) == WINDOWS_HOTSPOT_NET:
                    return f"hotspot {net}"
                return f"client network {net}"
        return "auto (local address)"

    def is_gateway(self, ip: str) -> bool:
        return normalize_ip(ip) in self.options.gateways


# --------------------------------------------------------------------------
# Domain helpers
# --------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*"
    r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$"
)


def normalize_domain(value: str) -> str:
    """Validate and normalise a hostname. Returns ``""`` when invalid."""
    name = value.strip().strip('"').strip("'").strip().lower()
    if not name or name in (".", "-"):
        return ""
    if name.endswith("."):
        name = name[:-1]
    if len(name) > 253 or " " in name or "/" in name:
        return ""
    if name.startswith("*."):
        name = name[2:]
    if not name or not _DOMAIN_RE.match(name):
        return ""
    # A bare TLD or an IP is not a useful hostname.
    if "." not in name and not name.startswith("localhost"):
        return ""
    if parse_ip(name) is not None:
        return ""
    return name


def banner_domain(value: str) -> str:
    """Pick a server hostname out of a cleartext service greeting banner.

    FTP/SMTP/POP3 servers often announce ``hostname.example.com`` in their
    welcome line, which gives an otherwise unknown destination IP a name.
    """
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    text = _BANNER_PREFIX_RE.sub("", text, count=1)
    for token in _BANNER_TOKEN_RE.findall(text):
        name = normalize_domain(token)
        if not name:
            continue
        # Skip version strings ("1.3.5", "1.3.5e", "v2.0"): a hostname ends
        # in an alphabetic top-level label of at least two characters.
        tld = name.rsplit(".", 1)[-1]
        if len(tld) < 2 or not tld.isalpha():
            continue
        return name
    return ""


def strip_host_port(host: str) -> str:
    """Remove a trailing ``:port`` from an HTTP Host value."""
    host = host.strip()
    if host.startswith("["):  # [IPv6]:port
        end = host.find("]")
        return host[1:end] if end != -1 else host
    if host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


TLS_VERSIONS = {
    "0x0300": "SSL 3.0",
    "0x0301": "TLS 1.0",
    "0x0302": "TLS 1.1",
    "0x0303": "TLS 1.2",
    "0x0304": "TLS 1.3",
    "0x0305": "TLS 1.4 (draft)",
}


def _split_multi(value: str) -> List[str]:
    return [part.strip() for part in (value or "").split(",") if part.strip()]


def _protocol_label(stack: str, proto: str) -> str:
    layers = set(stack.split(":")) if stack else set()
    if "quic" in layers:
        return "QUIC"
    if "tls" in layers:
        return "TLS"
    if "http" in layers:
        return "HTTP"
    if "dns" in layers:
        return "DNS"
    if "icmp" in layers or "icmpv6" in layers:
        return "ICMP"
    if proto == "tcp":
        return "TCP (other)"
    if proto == "udp":
        return "UDP (other)"
    return "Other"


CLEAR_PROTOCOLS = {"http", "ftp", "telnet", "smtp", "pop", "imap", "sip"}


# --------------------------------------------------------------------------
# Extractor
# --------------------------------------------------------------------------

class Extractor:
    """Stateful aggregator fed row-by-row by :func:`extract`."""

    def __init__(self, options: ExtractionOptions, logger: Optional[Logger] = None) -> None:
        self.options = options
        self.logger = logger or Logger(quiet=True)
        self.is_client = ClientMatcher(options)
        self.analysis = Analysis()
        self.detected_clients = {}  # type: Dict[str, int]
        self._seen_tcp_streams: Set[str] = set()
        self._seen_udp_streams: Set[Tuple[str, str, str, int, int]] = set()
        self._hostnames: Dict[str, Counter] = {}
        self._dhcp_names: Dict[str, Counter] = {}
        self._dhcp_ips: Dict[str, Set[str]] = {}
        # IPv6 clients usually use global addresses that no IPv4 network or
        # --src-ip matches.  Learn each IPv4 client's MAC address and treat
        # IPv6 addresses seen with that MAC as the same device.
        self._client_macs: Dict[str, str] = {}    # mac -> IPv4 client
        self._router_macs: Set[str] = set()       # MACs forwarding public IPv4
        self._ipv6_aliases: Dict[str, str] = {}   # IPv6 address -> mac

    # -- small helpers ---------------------------------------------------
    def _dest(self, ip: str) -> Destination:
        dest = self.analysis.destinations.get(ip)
        if dest is None:
            dest = Destination(ip=ip)
            self.analysis.destinations[ip] = dest
        return dest

    def _client(self, ip: str) -> ClientStat:
        client = self.analysis.clients.get(ip)
        if client is None:
            client = ClientStat(ip=ip)
            self.analysis.clients[ip] = client
        return client

    def _domain(self, name: str) -> DomainStat:
        stat = self.analysis.domains.get(name)
        if stat is None:
            stat = DomainStat(domain=name)
            self.analysis.domains[name] = stat
        return stat

    def _touch_domain(self, name: str, source: str, timestamp: float,
                      client: str = "", ip: str = "") -> None:
        name = normalize_domain(name)
        if not name:
            return
        stat = self._domain(name)
        stat.sources[source] += 1
        stat.first_seen = timestamp if not stat.first_seen else min(stat.first_seen, timestamp)
        stat.last_seen = max(stat.last_seen, timestamp)
        if client:
            stat.clients[client] += 1
        if ip:
            stat.ips[ip] += 1

    def _flow(self, client: str, dest: str, proto: str, dport: int) -> Flow:
        key = (client or "-", dest, proto, int(dport or 0))
        flow = self.analysis.flows.get(key)
        if flow is None:
            flow = Flow(client=client or "-", dst=dest, proto=proto,
                        dport=int(dport or 0))
            self.analysis.flows[key] = flow
        return flow

    def _excluded(self, ip: str) -> bool:
        obj = parse_ip(ip)
        if obj is None:
            return False
        return any(obj in net for net in self.options.exclude_networks)

    # -- public API ------------------------------------------------------
    def feed(self, row: Dict[str, str]) -> None:
        analysis = self.analysis

        try:
            timestamp = float(row.get("frame_time_epoch") or 0)
        except ValueError:
            return
        try:
            length = int(float(row.get("frame_len") or 0))
        except ValueError:
            length = 0

        ipv4_src = first_value(row.get("ip_src"))
        ipv4_dst = first_value(row.get("ip_dst"))
        is_ipv6 = not (ipv4_src or ipv4_dst)
        src = normalize_ip(ipv4_src or first_value(row.get("ipv6_src")))
        dst = normalize_ip(ipv4_dst or first_value(row.get("ipv6_dst")))
        if not src or not dst:
            return

        analysis.total_packets += 1
        analysis.total_bytes += length
        if not analysis.first_seen:
            analysis.first_seen = timestamp
        analysis.first_seen = min(analysis.first_seen, timestamp)
        analysis.last_seen = max(analysis.last_seen, timestamp)

        stack = row.get("frame_protocols") or ""
        layers = set(stack.split(":")) if stack else set()
        # ICMP errors quote the offending TCP/UDP header, so check ICMP first
        # and ignore the quoted ports.
        if "icmp" in layers or "icmpv6" in layers:
            proto = "icmp"
        elif "tcp" in layers:
            proto = "tcp"
        elif "udp" in layers:
            proto = "udp"
        else:
            proto = "ip"

        if proto == "icmp":
            sport = dport = 0
        else:
            sport = _to_int(first_value(row.get("tcp_srcport") or row.get("udp_srcport")))
            dport = _to_int(first_value(row.get("tcp_dstport") or row.get("udp_dstport")))

        # --- decide the public endpoint and direction ------------------
        direction = ""
        dest_ip = client_ip = ""
        server_port = 0
        src_client = self.is_client(src)
        dst_client = self.is_client(dst)
        eth_src = first_value(row.get("eth_src")).lower()
        eth_dst = first_value(row.get("eth_dst")).lower()
        src_public = is_public_ip(src)
        dst_public = is_public_ip(dst)
        if is_ipv6:
            if not src_client and self._client_mac(eth_src):
                src_client = self._alias_ipv6(src, eth_src)
            if not dst_client and self._client_mac(eth_dst):
                dst_client = self._alias_ipv6(dst, eth_dst)
        else:
            # A MAC that carries public IPv4 traffic belongs to a router or
            # the hotspot host (it forwards for everyone), never to one client.
            if src_public and eth_src:
                self._router_macs.add(eth_src)
            if dst_public and eth_dst:
                self._router_macs.add(eth_dst)
            if src_client and _is_unicast_mac(eth_src):
                self._client_macs.setdefault(eth_src, src)
            if dst_client and _is_unicast_mac(eth_dst):
                self._client_macs.setdefault(eth_dst, dst)

        if src_client:
            self.detected_clients[src] = self.detected_clients.get(src, 0) + 1

        self._feed_hostnames(row, src, src_client)

        if self.options.mode == "all":
            if src_client and dst_public and not dst_client:
                # IPv6 client recognised by MAC: its own address is public too.
                direction, dest_ip, client_ip, server_port = "out", dst, src, dport
            elif dst_client and src_public and not src_client:
                direction, dest_ip, client_ip, server_port = "in", src, dst, sport
            elif dst_public and not src_public:
                direction, dest_ip, client_ip, server_port = "out", dst, src, dport
            elif src_public and not dst_public:
                direction, dest_ip, client_ip, server_port = "in", src, dst, sport
            elif dst_public:
                # Both endpoints public (or an unusual capture): preserve the
                # old behaviour of attributing the packet to ip.dst.
                direction, dest_ip, client_ip, server_port = "out", dst, "", dport
        else:
            if src_client and dst_public:
                direction, dest_ip, client_ip, server_port = "out", dst, src, dport
            elif dst_client and src_public:
                direction, dest_ip, client_ip, server_port = "in", src, dst, sport

        selected = bool(dest_ip)
        if selected and (self._excluded(dest_ip) or self._excluded(client_ip)):
            selected = False

        if selected:
            analysis.selected_packets += 1
            analysis.selected_bytes += length
            dest = self._dest(dest_ip)
            dest.first_seen = timestamp if not dest.first_seen else min(dest.first_seen, timestamp)
            dest.last_seen = max(dest.last_seen, timestamp)
            if client_ip:
                dest.clients[client_ip] += 1
            if server_port:
                dest.ports[server_port] += 1
                analysis.ports[server_port] += 1
            label = _protocol_label(stack, proto)
            dest.protocols[label] += 1
            analysis.protocols[label] += 1

            if direction == "out":
                dest.packets_out += 1
                dest.bytes_out += length
            else:
                dest.packets_in += 1
                dest.bytes_in += length

            if proto == "tcp":
                dest.tcp_packets += 1
            if _truthy(row.get("tcp_analysis_retransmission") or ""):
                dest.retransmissions += 1
            if _truthy(row.get("tcp_flags_syn") or "") and not _truthy(row.get("tcp_flags_ack") or ""):
                dest.syn_count += 1

            if layers & CLEAR_PROTOCOLS:
                dest.has_cleartext = True
                if server_port:
                    dest.cleartext_ports[server_port] += 1

            # TLS metadata
            for version in _split_multi(row.get("tls_handshake_version") or ""):
                dest.tls_versions[TLS_VERSIONS.get(version.lower(), version)] += 1
            for alpn in _split_multi(row.get("tls_handshake_extensions_alpn_str") or ""):
                dest.alpn[alpn] += 1
            ja4 = (row.get("tls_handshake_ja4") or "").strip()
            if ja4:
                dest.ja4[ja4] += 1

            flow = self._flow(client_ip, dest_ip, proto, server_port) if client_ip else None
            if flow is not None:
                flow.first_seen = timestamp if not flow.first_seen else min(flow.first_seen, timestamp)
                flow.last_seen = max(flow.last_seen, timestamp)
                if direction == "out":
                    flow.packets_out += 1
                    flow.bytes_out += length
                    if _truthy(row.get("tcp_flags_syn") or "") and not _truthy(row.get("tcp_flags_ack") or ""):
                        flow.syn_count += 1
                    if ja4 and not flow.ja4:
                        flow.ja4 = ja4
                else:
                    flow.packets_in += 1
                    flow.bytes_in += length

            if client_ip:
                client = self._client(client_ip)
                client.first_seen = timestamp if not client.first_seen else min(client.first_seen, timestamp)
                client.last_seen = max(client.last_seen, timestamp)
                client.destinations[dest_ip] += 1
                if server_port:
                    client.ports[server_port] += 1
                if direction == "out":
                    client.packets_out += 1
                    client.bytes_out += length
                else:
                    client.packets_in += 1
                    client.bytes_in += length

            # Timeline (per-second, compressed later)
            bucket = int(timestamp)
            entry = analysis.timeline.get(bucket)
            if entry is None:
                entry = [0, 0, 0, 0]
                analysis.timeline[bucket] = entry
            if direction == "out":
                entry[0] += 1
                entry[2] += length
            else:
                entry[1] += 1
                entry[3] += length

        # --- domains (SNI / HTTP / DNS), independent of destination ----
        sni = (row.get("tls_handshake_extensions_server_name")
               or row.get("dtls_handshake_extensions_server_name")
               or row.get("gquic_tag_sni") or "")
        http_host = (row.get("http_host")
                     or row.get("http2_headers_authority") or "")
        # Plain HTTP requests expose the client software; keep a bounded copy.
        if selected and direction == "out":
            agent = (row.get("http_user_agent") or "").strip()
            if agent:
                self._dest(dest_ip).user_agents[agent[:300]] += 1
            method = (row.get("http_request_method") or "").strip().upper()
            if method:
                self._dest(dest_ip).http_methods[method[:20]] += 1
        # SNI and HTTP Host are only trustworthy on client -> server packets.
        domain_client = client_ip if selected and direction == "out" else ""
        if sni and selected and direction == "out":
            for value in _split_multi(sni):
                name = normalize_domain(value)
                if name:
                    self._touch_domain(name, "sni", timestamp, domain_client, dest_ip)
                    self._dest(dest_ip).domains[name] += 1
                    if client_ip:
                        flow = self._flow(client_ip, dest_ip, proto, server_port)
                        flow.domains[name] += 1
                    self._client_domain(client_ip, name)
        if http_host and selected and direction == "out":
            name = normalize_domain(strip_host_port(_split_multi(http_host)[0]))
            if name:
                self._touch_domain(name, "http", timestamp, domain_client, dest_ip)
                self._dest(dest_ip).domains[name] += 1
                if client_ip:
                    self._flow(client_ip, dest_ip, proto, server_port).domains[name] += 1
                self._client_domain(client_ip, name)

        # Cleartext service greetings (server -> client) name the server.
        if selected and direction == "in":
            name = ""
            source = ""
            if _to_int(row.get("ftp_response_code")) == 220:
                name, source = banner_domain(row.get("ftp_response_arg") or ""), "ftp"
            if not name and _to_int(row.get("smtp_response_code")) == 220:
                name, source = banner_domain(row.get("smtp_response") or ""), "smtp"
            if not name and (row.get("imap_response_status") or "").strip().upper() in ("OK", "PREAUTH"):
                name, source = banner_domain(row.get("imap_response") or ""), "imap"
            if not name and (row.get("pop_response_indicator") or "").strip().upper() == "+OK":
                name, source = banner_domain(row.get("pop_response_description") or ""), "pop3"
            if name:
                self._touch_domain(name, source, timestamp, client_ip, dest_ip)
                self._dest(dest_ip).domains[name] += 1
                if client_ip:
                    self._flow(client_ip, dest_ip, proto, server_port).domains[name] += 1
                self._client_domain(client_ip, name)

        self._feed_dns(row, timestamp, src, dst, sport, dport, src_client, dst_client)

        # --- connection starts for beaconing ---------------------------
        if selected and direction == "out" and client_ip:
            self._record_stream_start(proto, row, timestamp, client_ip, dest_ip, server_port)

    def _client_mac(self, mac: str) -> bool:
        return mac in self._client_macs and mac not in self._router_macs

    def _alias_ipv6(self, ip: str, mac: str) -> bool:
        """Treat an IPv6 address sent/received by a client's MAC as a client."""
        obj = parse_ip(ip)
        if obj is None or obj.version != 6 or obj.is_multicast \
                or obj.is_unspecified or obj.is_link_local or obj.is_loopback:
            return False
        self._ipv6_aliases.setdefault(ip, mac)
        return True

    def _client_domain(self, client_ip: str, name: str) -> None:
        if client_ip:
            self._client(client_ip).domains[name] += 1

    def _record_stream_start(self, proto: str, row: Dict[str, str], timestamp: float,
                             client: str, dest: str, dport: int) -> None:
        if proto == "tcp":
            stream = row.get("tcp_stream") or ""
            if not stream:
                return
            key = f"tcp:{stream}"
            if key in self._seen_tcp_streams:
                return
            self._seen_tcp_streams.add(key)
        elif proto == "udp":
            stream = row.get("udp_stream") or ""
            sport = _to_int(row.get("udp_srcport"))
            key = (stream, client, dest, dport, sport)
            if key in self._seen_udp_streams:
                return
            self._seen_udp_streams.add(key)
        else:
            return
        self.analysis.stream_events.append((timestamp, client, dest, proto, dport))

    def _remember_hostname(self, ip: str, name: str) -> None:
        ip = normalize_ip(ip)
        name = normalize_hostname(name)
        if not ip or not name or ip in ("0.0.0.0", "::"):
            return
        self._hostnames.setdefault(ip, Counter())[name] += 1

    def _feed_hostnames(self, row: Dict[str, str], src: str, src_client: bool) -> None:
        """Collect best-effort device names from DHCP and NetBIOS packets."""
        hostname = normalize_hostname(row.get("dhcp_option_hostname") or "")
        mac = normalize_mac(row.get("dhcp_hw_mac_addr") or "")
        if mac:
            if hostname:
                self._dhcp_names.setdefault(mac, Counter())[hostname] += 1
            for key in ("dhcp_ip_your", "dhcp_ip_client"):
                ip = normalize_ip(row.get(key) or "")
                if ip and ip not in ("0.0.0.0", "::"):
                    self._dhcp_ips.setdefault(mac, set()).add(ip)
                    if hostname:
                        self._remember_hostname(ip, hostname)
                    # A DHCP lease is the earliest place to learn a client's
                    # MAC for IPv6 attribution.
                    if self.is_client(ip) and _is_unicast_mac(mac):
                        self._client_macs.setdefault(mac, ip)

        nbns = normalize_hostname(row.get("nbns_name") or "")
        if nbns and src_client:
            self._remember_hostname(src, nbns)

        # SMTP clients announce themselves in HELO/EHLO; MAIL/RCPT parameters
        # contain addresses, not device names, so only those two commands count.
        smtp_command = (row.get("smtp_req_command") or "").strip().upper()
        if src_client and smtp_command in ("HELO", "EHLO"):
            name = normalize_hostname(row.get("smtp_req_parameter") or "")
            if name and name not in SMTP_PLACEHOLDER_NAMES:
                self._remember_hostname(src, name)

        # mDNS/LLMNR names ending in .local are usually the device's own name.
        if src_client and (row.get("dns_qry_name") or ""):
            for raw_name in _split_multi(row.get("dns_qry_name") or ""):
                name = normalize_hostname(raw_name)
                if name.endswith(".local"):
                    self._remember_hostname(src, name)

    def _feed_dns(self, row: Dict[str, str], timestamp: float, src: str, dst: str,
                  sport: int, dport: int, src_client: bool, dst_client: bool) -> None:
        qname_raw = row.get("dns_qry_name") or ""
        if not qname_raw:
            return
        is_response = _truthy(row.get("dns_flags_response") or "")
        qtype, qtype_name = dns_type_name(first_value(row.get("dns_qry_type")))
        answers = [normalize_ip(a) for a in
                   _split_multi(row.get("dns_a") or "") + _split_multi(row.get("dns_aaaa") or "")
                   if parse_ip(a) is not None]
        names = [name for name in map(normalize_domain, _split_multi(qname_raw)) if name]

        if is_response:
            # The IP -> name map only labels destinations, so it is learned
            # from every response, including lookups by unselected hosts.
            for name in names:
                for answer in answers:
                    self.analysis.dns_answers.setdefault(answer, set()).add(name)
                    self.analysis.dns_names.setdefault(name, set()).add(answer)
            if not dst_client:
                return
            self.analysis.dns_servers[src] += 1
        elif not src_client:
            # Queries from other devices (or the hotspot host forwarding them
            # upstream) do not belong to the selected clients.
            return

        try:
            response_ms = float(row.get("dns_time") or "") * 1000.0
        except ValueError:
            response_ms = None

        for name in names:
            key = (name, qtype)
            stat = self.analysis.dns_queries.get(key)
            if stat is None:
                stat = DNSQueryStat(qname=name, qtype=qtype, qtype_name=qtype_name)
                self.analysis.dns_queries[key] = stat
            stat.first_seen = timestamp if not stat.first_seen else min(stat.first_seen, timestamp)
            stat.last_seen = max(stat.last_seen, timestamp)

            if is_response:
                stat.answers.update(answers)
                if response_ms is not None:
                    stat.add_response_time(response_ms)
                # The lookup itself is counted on the query; only count the
                # response when the query was not captured.
                domain = self.analysis.domains.get(name)
                if domain is None:
                    self._touch_domain(name, "dns", timestamp, dst)
                    domain = self.analysis.domains.get(name)
                else:
                    domain.last_seen = max(domain.last_seen, timestamp)
                if domain is not None:
                    for answer in answers:
                        domain.ips[answer] += 1
            else:
                stat.count += 1
                stat.clients[src] += 1
                self._touch_domain(name, "dns", timestamp, src)

    # -- finish ----------------------------------------------------------
    def finish(self) -> Analysis:
        analysis = self.analysis

        # Attach DNS-derived names to every destination, even when the SNI
        # never appeared in the capture (e.g. cached TLS session reuse).
        # The domain table only lists names the selected clients used; a name
        # learned from another host's lookup still labels the destination.
        for ip, names in analysis.dns_answers.items():
            if ip not in analysis.destinations:
                continue
            dest = analysis.destinations[ip]
            for name in names:
                if name not in dest.domains:
                    dest.domains[name] = 0
                domain = analysis.domains.get(name)
                if domain is not None and ip not in domain.ips:
                    domain.ips[ip] += 1

        # Apply the minimum-packets filter after all aggregation, including
        # the connection events used for beaconing.
        min_packets = max(1, int(self.options.min_packets or 1))
        if min_packets > 1:
            keep = {ip for ip, d in analysis.destinations.items() if d.packets >= min_packets}
            analysis.destinations = {
                ip: d for ip, d in analysis.destinations.items() if ip in keep
            }
            analysis.flows = {
                key: f for key, f in analysis.flows.items() if f.dst in keep
            }
            analysis.stream_events = [
                event for event in analysis.stream_events if event[2] in keep
            ]
            for client in analysis.clients.values():
                client.destinations = type(client.destinations)(
                    (ip, n) for ip, n in client.destinations.items() if ip in keep
                )

        # Join DHCP hostnames (learned by MAC) to the lease addresses, then
        # attach every collected name to its client.
        for mac, names in self._dhcp_names.items():
            best = names.most_common(1)[0][0]
            for ip in self._dhcp_ips.get(mac, ()):
                self._remember_hostname(ip, best)
        for ip, names in self._hostnames.items():
            client = analysis.clients.get(ip)
            if client is not None:
                client.hostnames.update(names)

        # Record why each client was selected so reports can show it.
        for mac, owner in self._client_macs.items():
            if owner in analysis.clients and mac not in self._router_macs:
                analysis.clients[owner].macs.add(mac)
        ipv6_by_mac = {}
        for ip, client in analysis.clients.items():
            mac = self._ipv6_aliases.get(ip)
            if mac and not self.is_client(ip):
                owner = self._client_macs.get(mac, "")
                client.macs.add(mac)
                client.selected_by = f"IPv6 of {owner} (same MAC)" if owner else "IPv6 (same MAC)"
                if not client.hostnames and owner in analysis.clients:
                    client.hostnames.update(analysis.clients[owner].hostnames)
                ipv6_by_mac[ip] = owner
            else:
                client.selected_by = self.is_client.reason(ip)
        if ipv6_by_mac:
            analysis.capture["ipv6_clients_by_mac"] = ipv6_by_mac
            analysis.warnings.append(
                f"{len(ipv6_by_mac)} IPv6 address(es) were attributed to selected "
                "clients because they share the client's MAC address."
            )

        analysis.capture["clients_detected"] = dict(
            sorted(self.detected_clients.items(), key=lambda kv: kv[1], reverse=True)
        )
        analysis.capture["selected_packets"] = analysis.selected_packets
        analysis.capture["selected_bytes"] = analysis.selected_bytes
        return analysis


def _is_unicast_mac(mac: str) -> bool:
    """True for ``aa:bb:cc:dd:ee:ff`` addresses without the group bit set."""
    if len(mac) != 17:
        return False
    try:
        return not int(mac[:2], 16) & 1
    except ValueError:
        return False


def _to_int(value: Optional[str]) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def extract(rows: Iterable[Dict[str, str]], options: ExtractionOptions,
            logger: Optional[Logger] = None) -> Analysis:
    """Aggregate tshark rows into an Analysis object."""
    extractor = Extractor(options, logger)
    for row in rows:
        extractor.feed(row)
    return extractor.finish()


def extract_first_match(rows: Iterable[Dict[str, str]],
                        candidates: Sequence[ExtractionOptions],
                        logger: Optional[Logger] = None) -> Tuple[Analysis, int]:
    """Try several client selections in one pass; keep the first that matches.

    ``candidates`` are in priority order (e.g. hotspot network, then
    ``--auto-clients``).  Every row is fed to each candidate until a
    higher-priority one selects traffic, at which point the lower-priority
    fallbacks are dropped.  This replaces re-running tshark for each fallback
    and returns ``(analysis, index of the candidate used)``.  When nothing
    matches, the last (broadest) candidate's analysis is returned.
    """
    if not candidates:
        raise ValueError("at least one extraction candidate is required")
    extractors = [Extractor(options, logger) for options in candidates]
    for row in rows:
        for index, extractor in enumerate(extractors):
            extractor.feed(row)
            if extractor.analysis.selected_packets and index + 1 < len(extractors):
                del extractors[index + 1:]
                break
    for index, extractor in enumerate(extractors):
        if extractor.analysis.selected_packets:
            return extractor.finish(), index
    return extractors[-1].finish(), len(extractors) - 1
