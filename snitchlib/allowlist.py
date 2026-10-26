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

An entry can be scoped to specific finding categories with a trailing
bracketed modifier, so a known-good backup host may be allowed to beacon
without also hiding that it sends large amounts of data:

    backup.example.com [only: beaconing]
    203.0.113.10 [except: dns_anomaly, port_scan]

``only`` suppresses just the listed categories; ``except`` suppresses all
categories except the listed ones.  ``not`` and ``all:`` are accepted aliases.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, Union

from .models import Finding

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

#: Finding ids emitted by :mod:`snitchlib.analyze`.  Validated so a typo in a
#: category modifier cannot silently disable (``except``) or weaken (``only``)
#: an allowlist entry.  Keep in sync with the ``id=`` values there.
FINDING_CATEGORIES: FrozenSet[str] = frozenset({
    "beaconing", "cleartext", "dns_anomaly", "outbound_volume", "port_scan",
    "retransmissions", "tor_exit", "tor_like", "vt_domain", "vt_malicious",
    "vt_suspicious",
})


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


def _category(value: str) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")


def _parse_modifier(text: str, source: str, number: int) -> Tuple[str, FrozenSet[str], FrozenSet[str]]:
    """Split a trailing ``[...]`` category modifier off one entry."""
    line = text.strip()
    if "[" not in line:
        return line, frozenset(), frozenset()
    start = line.rfind("[")
    end = line.rfind("]")
    if end < start or line[end + 1:].strip():
        raise AllowlistError(f"{source}:{number}: unterminated category modifier")
    head = line[:start].strip()
    spec = line[start + 1:end].strip()
    if not head:
        raise AllowlistError(f"{source}:{number}: missing entry before category modifier")
    mode, _, names = spec.partition(":")
    if not _:
        parts = spec.replace(",", " ").split()
        if not parts:
            raise AllowlistError(f"{source}:{number}: empty category modifier")
        mode, names = parts[0], " ".join(parts[1:])
    mode = _category(mode)
    if mode == "not":
        mode = "except"
    if mode not in ("only", "except"):
        raise AllowlistError(
            f"{source}:{number}: unknown category modifier {mode!r} "
            "(use only: or except:)")
    categories = frozenset(
        _category(name) for name in names.replace(",", " ").split() if name.strip()
    )
    if not categories:
        raise AllowlistError(f"{source}:{number}: category modifier lists no categories")
    unknown = sorted(categories - FINDING_CATEGORIES)
    if unknown:
        raise AllowlistError(
            f"{source}:{number}: unknown finding category {unknown[0]!r} "
            f"(known: {', '.join(sorted(FINDING_CATEGORIES))})")
    if mode == "only":
        return head, categories, frozenset()
    return head, frozenset(), categories


@dataclass(frozen=True)
class AllowEntry:
    """One allowlisted IP, network or domain suffix with an optional scope."""

    network: Optional[IPNetwork] = None
    domain: str = ""
    only: FrozenSet[str] = frozenset()
    except_: FrozenSet[str] = frozenset()

    def applies_to(self, category: str) -> bool:
        name = _category(category)
        if self.only:
            return name in self.only
        if self.except_:
            return name not in self.except_
        return True

    def matches_ip(self, value: str) -> bool:
        if self.network is None:
            return False
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        return address in self.network

    def matches_domain(self, value: str) -> bool:
        if not self.domain:
            return False
        domain = _normalize_domain(value)
        return bool(domain) and (
            domain == self.domain or domain.endswith("." + self.domain)
        )

    def describe(self) -> str:
        target = str(self.network) if self.network is not None else self.domain
        if self.only:
            return f"{target} [only: {', '.join(sorted(self.only))}]"
        if self.except_:
            return f"{target} [except: {', '.join(sorted(self.except_))}]"
        return target


@dataclass
class Allowlist:
    """Parsed allowlist of IP networks and domain suffixes."""

    entries_list: List[AllowEntry] = field(default_factory=list)
    source: str = ""

    @classmethod
    def empty(cls) -> "Allowlist":
        return cls()

    @classmethod
    def from_lines(cls, lines: Iterable[str], source: str = "<allowlist>") -> "Allowlist":
        entries: List[AllowEntry] = []
        for number, raw in enumerate(lines, 1):
            line = str(raw).strip().lstrip("\ufeff")
            if not line or line.startswith("#"):
                continue
            # Strip trailing comments, but keep IPv6 addresses intact.
            if " #" in line:
                line = line.split(" #", 1)[0].strip()
            if not line:
                continue

            line, only, except_ = _parse_modifier(line, source, number)
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
                entries.append(AllowEntry(domain=domain, only=only, except_=except_))
                continue
            if prefix == "ip":
                try:
                    address = ipaddress.ip_address(value)
                except ValueError:
                    raise AllowlistError(
                        f"{source}:{number}: invalid IP address {value!r}")
                entries.append(AllowEntry(
                    network=ipaddress.ip_network(address), only=only, except_=except_))
                continue
            if prefix in ("cidr", "network"):
                try:
                    network = ipaddress.ip_network(value, strict=False)
                except ValueError:
                    raise AllowlistError(
                        f"{source}:{number}: invalid network {value!r}")
                entries.append(AllowEntry(network=network, only=only, except_=except_))
                continue

            # Auto-detect: network/IP first, domain otherwise.
            try:
                entries.append(AllowEntry(
                    network=ipaddress.ip_network(value, strict=False),
                    only=only, except_=except_))
                continue
            except ValueError:
                pass
            if "/" in value:  # looked like a CIDR but was invalid
                raise AllowlistError(f"{source}:{number}: invalid network {value!r}")
            domain = _normalize_domain(value)
            if not _domain_is_valid(domain):
                raise AllowlistError(f"{source}:{number}: invalid entry {value!r}")
            entries.append(AllowEntry(domain=domain, only=only, except_=except_))
        return cls(entries_list=entries, source=source)

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
    def networks(self) -> List[IPNetwork]:
        return [entry.network for entry in self.entries_list if entry.network is not None]

    @property
    def domains(self) -> Set[str]:
        return {entry.domain for entry in self.entries_list if entry.domain}

    @property
    def entries(self) -> int:
        return len(self.entries_list)

    @property
    def scoped_entries(self) -> int:
        return sum(1 for entry in self.entries_list if entry.only or entry.except_)

    def describe(self) -> str:
        parts = []
        if self.networks:
            parts.append(f"{len(self.networks)} network/IP")
        if self.domains:
            parts.append(f"{len(self.domains)} domain")
        if not parts:
            return "empty"
        if self.scoped_entries:
            parts.append(f"{self.scoped_entries} category-scoped")
        return ", ".join(parts)

    def matches_ip(self, value: str) -> bool:
        return any(entry.matches_ip(value) for entry in self.entries_list)

    def matches_domain(self, value: str) -> bool:
        return any(entry.matches_domain(value) for entry in self.entries_list)

    def matches(self, finding: Finding) -> bool:
        """Return True when a finding should be suppressed."""
        category = getattr(finding, "id", "") or ""
        domains = [d for d in (finding.domains or []) if d]
        if domains and any(
            entry.matches_domain(domain) and entry.applies_to(category)
            for domain in domains for entry in self.entries_list
        ):
            return True
        ips = [ip for ip in (finding.ips or []) if ip]
        if ips and all(
            any(entry.matches_ip(ip) and entry.applies_to(category)
                for entry in self.entries_list)
            for ip in ips
        ):
            return True
        return False

    def filter(self, findings: Sequence[Finding]) -> Tuple[List[Finding], int]:
        """Return ``(kept, suppressed_count)``."""
        if not self.entries:
            return list(findings), 0
        kept = [finding for finding in findings if not self.matches(finding)]
        return kept, len(findings) - len(kept)

    def partition(self, findings: Sequence[Finding]) -> Tuple[List[Finding], List[Finding]]:
        """Return ``(kept, suppressed)`` so callers can report suppressions."""
        if not self.entries:
            return list(findings), []
        kept = [finding for finding in findings if not self.matches(finding)]
        suppressed = [finding for finding in findings if self.matches(finding)]
        return kept, suppressed
