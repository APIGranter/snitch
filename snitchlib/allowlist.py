# -*- coding: utf-8 -*-
"""Allowlist support for suppressing findings about known-good hosts.

The allowlist is a plain text file with one entry per line (``#`` starts a
comment).  Entries are auto-detected:

    # exact address or network
    203.0.113.10
    198.51.100.0/24

    # domain suffix (label boundary, subdomains included)
    example.com
    *.example.com

    # explicit prefixes also work
    ip 192.0.2.5
    cidr 10.0.0.0/8
    domain telemetry.example.org

A finding is suppressed when one of its domains matches, or when **every** IP
it references matches.  Findings without any IP/domain reference are kept.
This lets a user silence a known chatty service without hiding a port scan that
happens to include one allowlisted address.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence, Set, Tuple, Union

from .models import Finding

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class AllowlistError(ValueError):
    """Raised when an allowlist file cannot be read or parsed."""


def _normalize_domain(value: str) -> str:
    domain = str(value).strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if domain.startswith("."):
        domain = domain[1:]
    return domain


def _domain_is_valid(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    for label in value.split("."):
        if not label or len(label) > 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not all(ch.isalnum() or ch in "-_" for ch in label):
            return False
    return True


@dataclass
class Allowlist:
    """Parsed allowlist of IP networks and domain suffixes."""

    networks: List[IPNetwork] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    source: str = ""

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls()

    @classmethod
    def from_lines(cls, lines: Iterable[str], source: str = "<allowlist>") -> "Allowlist":
        networks: List[IPNetwork] = []
        domains: Set[str] = set()
        for number, raw in enumerate(lines, 1):
            line = str(raw).strip().lstrip("\ufeff")
            if not line or line.startswith("#"):
                continue
            # Strip trailing comments, but keep IPv6 addresses intact.
            if " #" in line:
                line = line.split(" #", 1)[0].strip()
            if not line:
                continue

            prefix = ""
            value = line
            lowered = line.lower()
            for candidate in ("ip", "cidr", "network", "domain", "host"):
                if lowered.startswith(candidate + " ") or lowered.startswith(candidate + ":"):
                    prefix = candidate
                    value = line[len(candidate) + 1:].strip()
                    break
            if not value:
                raise AllowlistError(f"{source}:{number}: empty entry")

            if prefix in ("domain", "host"):
                domain = _normalize_domain(value)
                if not _domain_is_valid(domain):
                    raise AllowlistError(f"{source}:{number}: invalid domain {value!r}")
                domains.add(domain)
                continue
            if prefix == "ip":
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    raise AllowlistError(
                        f"{source}:{number}: invalid IP address {value!r}")
                networks.append(ipaddress.ip_network(address))
                continue
            if prefix in ("cidr", "network"):
                try:
                    networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    raise AllowlistError(
                        f"{source}:{number}: invalid network {value!r}")
                continue

            # Auto-detect: network/IP first, domain otherwise.
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
                continue
            except ValueError:
                pass
            if "/" in value:  # looked like a CIDR but was invalid
                raise AllowlistError(f"{source}:{number}: invalid network {value!r}")
            domain = _normalize_domain(value)
            if not _domain_is_valid(domain):
                raise AllowlistError(f"{source}:{number}: invalid entry {value!r}")
            domains.add(domain)
        return cls(networks=networks, domains=domains, source=source)

    @classmethod
    def load(cls, path: str) -> "Allowlist":
        if not path:
            return cls.empty()
        expanded = os.path.expanduser(path)
        try:
            with open(expanded, "r", encoding="utf-8-sig") as handle:
                return cls.from_lines(handle, source=expanded)
        except OSError as exc:
            raise AllowlistError(f"could not read allowlist {expanded}: {exc}")

    @property
    def entries(self) -> int:
        return len(self.networks) + len(self.domains)

    def describe(self) -> str:
        parts = []
        if self.networks:
            parts.append(f"{len(self.networks)} network/IP")
        if self.domains:
            parts.append(f"{len(self.domains)} domain")
        return ", ".join(parts) if parts else "empty"

    def matches_ip(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        return any(address in network for network in self.networks)

    def matches_domain(self, value: str) -> bool:
        domain = _normalize_domain(value)
        if not domain:
            return False
        for suffix in self.domains:
            if domain == suffix or domain.endswith("." + suffix):
                return True
        return False

    def matches(self, finding: Finding) -> bool:
        """Return True when a finding should be suppressed."""
        domains = [d for d in (finding.domains or []) if d]
        if domains and any(self.matches_domain(d) for d in domains):
            return True
        ips = [ip for ip in (finding.ips or []) if ip]
        if ips and all(self.matches_ip(ip) for ip in ips):
            return True
        return False

    def filter(self, findings: Sequence[Finding]) -> Tuple[List[Finding], int]:
        """Return ``(kept, suppressed_count)``."""
        if not self.entries:
            return list(findings), 0
        kept = [finding for finding in findings if not self.matches(finding)]
        return kept, len(findings) - len(kept)
