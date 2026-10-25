# -*- coding: utf-8 -*-
"""Optional offline ASN lookups from a local database.

SNItch normally learns the network owner from geolocation providers and RDAP.
When those are unavailable (offline analysis, rate limits, blocked APIs) an
optional local database fills in the ASN and organisation.  Two formats are
supported:

* MaxMind GeoLite2 ``GeoLite2-ASN-Blocks-IPv4.csv``/``-IPv6.csv`` files
  (``network,autonomous_system_number,autonomous_system_organization``),
* a plain text or CSV file with one ``CIDR ASN Organisation`` record per line
  (whitespace or comma separated, ``#`` comments allowed).

The database never overrides values already provided by an online lookup.
"""

from __future__ import annotations

import bisect
import csv
import ipaddress
import itertools
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import Analysis
from .util import Logger

#: Column aliases understood in a CSV header row.
_COLUMN_ALIASES = {
    "network": "network",
    "cidr": "network",
    "prefix": "network",
    "subnet": "network",
    "autonomous_system_number": "asn",
    "as_number": "asn",
    "asn": "asn",
    "as": "asn",
    "autonomous_system_organization": "org",
    "as_organization": "org",
    "organization": "org",
    "organisation": "org",
    "org": "org",
    "name": "org",
}

Record = Tuple[int, int, int, str, str]  # start, end, version, asn, org


def _clean_asn(value: Any) -> str:
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:].strip()
    if not text.isdigit():
        return ""
    return "AS" + text


def _clean_org(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def _record(network: str, asn: Any, org: Any) -> Optional[Record]:
    try:
        net = ipaddress.ip_network(str(network).strip(), strict=False)
    except ValueError:
        return None
    number = _clean_asn(asn)
    if not number:
        return None
    return (
        int(net.network_address),
        int(net.broadcast_address),
        net.version,
        number,
        _clean_org(org),
    )


def _header_map(cells: Iterable[str]) -> Optional[Dict[str, int]]:
    mapping: Dict[str, int] = {}
    for index, cell in enumerate(cells):
        key = str(cell).strip().lower().lstrip("\ufeff").replace("-", "_").replace(" ", "_")
        field = _COLUMN_ALIASES.get(key)
        if field and field not in mapping:
            mapping[field] = index
    if "network" not in mapping:
        return None
    mapping.setdefault("asn", 1)
    mapping.setdefault("org", 2)
    return mapping


def _parse_csv(handle: Any) -> Tuple[List[Record], int]:
    reader = csv.reader(handle)
    try:
        first = next(reader)
    except StopIteration:
        return [], 0
    if not first:
        return [], 0
    mapping = _header_map(first)
    body = reader if mapping else itertools.chain([first], reader)
    if not mapping:
        mapping = {"network": 0, "asn": 1, "org": 2}
    records: List[Record] = []
    skipped = 0
    for row in body:
        if not row or not any(str(cell).strip() for cell in row):
            continue
        if str(row[0]).lstrip().startswith("#"):
            continue
        def cell(field: str) -> str:
            index = mapping.get(field, -1)
            return row[index] if 0 <= index < len(row) else ""
        record = _record(cell("network"), cell("asn"), cell("org"))
        if record is None:
            skipped += 1
        else:
            records.append(record)
    return records, skipped


def _parse_text(handle: Any) -> Tuple[List[Record], int]:
    records: List[Record] = []
    skipped = 0
    for line in handle:
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.replace(",", " ").split()
        if len(parts) < 2:
            skipped += 1
            continue
        network, rest = parts[0], parts[1:]
        asn = ""
        org_parts: List[str] = []
        for token in rest:
            if not asn and _clean_asn(token):
                asn = token
            else:
                org_parts.append(token)
        record = _record(network, asn, " ".join(org_parts))
        if record is None:
            skipped += 1
        else:
            records.append(record)
    return records, skipped


class AsnDatabase:
    """Sorted set of CIDR -> ASN records with binary-search lookups."""

    def __init__(self, records: Iterable[Record], source: str = "",
                 skipped: int = 0) -> None:
        self.source = source or "local"
        self.skipped = skipped
        grouped = {4: [], 6: []}
        for record in records:
            grouped[record[2]].append(record)
        self._tables: Dict[int, List[Record]] = {}
        self._starts: Dict[int, List[int]] = {}
        for version, rows in grouped.items():
            rows.sort(key=lambda row: row[0])
            self._tables[version] = rows
            self._starts[version] = [row[0] for row in rows]

    def __len__(self) -> int:
        return len(self._tables.get(4, [])) + len(self._tables.get(6, []))

    @classmethod
    def load(cls, path: str) -> "AsnDatabase":
        """Read a database file, raising ``ValueError`` if none is usable."""
        expanded = os.path.expanduser(str(path))
        with open(expanded, "r", encoding="utf-8-sig", newline="") as handle:
            sample = handle.readline()
            handle.seek(0)
            if "," in sample:
                records, skipped = _parse_csv(handle)
            else:
                records, skipped = _parse_text(handle)
        if not records:
            raise ValueError(
                f"{path}: no usable CIDR/ASN records (expected GeoLite2 ASN CSV "
                "or 'CIDR ASN Organisation' lines)"
            )
        return cls(records, source=os.path.basename(expanded), skipped=skipped)

    def lookup(self, ip: str) -> Optional[Tuple[str, str]]:
        """Return ``(asn, organisation)`` for an IP, or ``None``."""
        try:
            obj = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        table = self._tables.get(obj.version) or []
        starts = self._starts.get(obj.version) or []
        number = int(obj)
        index = bisect.bisect_right(starts, number) - 1
        if index < 0:
            return None
        start, end, _version, asn, org = table[index]
        if start <= number <= end:
            return asn, org
        return None


def apply_asn_db(analysis: Analysis, database: AsnDatabase,
                 logger: Optional[Logger] = None) -> Dict[str, Any]:
    """Fill missing ASN/organisation values on destinations from a local DB."""
    logger = logger or Logger(quiet=True)
    stats: Dict[str, Any] = {
        "entries": len(database),
        "source": database.source,
        "matched": 0,
        "filled": 0,
    }
    for dest in analysis.destinations.values():
        hit = database.lookup(dest.ip)
        if hit is None:
            continue
        stats["matched"] += 1
        asn, org = hit
        geo = dest.geo if isinstance(dest.geo, dict) else {}
        dest.geo = geo
        changed = False
        if asn and not geo.get("asn"):
            geo["asn"] = asn
            changed = True
        if org:
            if not geo.get("org"):
                geo["org"] = org
                changed = True
            if not geo.get("isp"):
                geo["isp"] = org
                changed = True
        if changed:
            stats["filled"] += 1
            # Make it visible when no online provider supplied anything and the
            # local database was the only source of network ownership.
            if geo.get("status") != "ok":
                geo["status"] = "local"
            geo["asn_source"] = database.source
    if stats["filled"]:
        logger.info(
            f"ASN database: filled {stats['filled']} of {stats['matched']} "
            f"matching destination(s) from {database.source}"
        )
    else:
        logger.info(
            f"ASN database: {database.source} ({stats['entries']} networks, "
            f"{stats['matched']} matched, nothing missing)"
        )
    return stats
