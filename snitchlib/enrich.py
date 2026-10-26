# -*- coding: utf-8 -*-
"""Enrichment: geolocation, reverse DNS, RDAP, VirusTotal, Tor exit list.

Design points:

* Geo/rDNS/RDAP run concurrently (they are independent and latency-bound).
* VirusTotal runs sequentially because the free API allows only ~4 req/min.
* Every result is cached with a timestamp in a versioned JSON file.
* Network failures degrade gracefully: a run never dies because an API is
  down. Cached/stale values are preferred over aborting.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeout
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set

from . import __version__
from .models import Analysis
from .util import Logger, atomic_write_json, load_json

USER_AGENT = f"SNItch/{__version__} (+https://github.com/APIGranter/snitch)"
CACHE_VERSION = 2

GEO_PROVIDERS = ("ipwho.is", "ipapi.co")


def empty_geo(status: str = "unknown") -> Dict[str, Any]:
    return {
        "country": "", "cc": "", "region": "", "city": "",
        "lat": None, "lon": None, "isp": "", "org": "", "asn": "",
        "source": "", "status": status,
    }


# --------------------------------------------------------------------------
# HTTP helper
# --------------------------------------------------------------------------

def _get_json(url: str, headers: Optional[Dict[str, str]] = None,
              timeout: float = 10.0, retries: int = 2) -> Dict[str, Any]:
    """GET a JSON document, returning ``{"_error", "_status"}`` on failure."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    last_error = ""
    last_status = 0
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            last_status = exc.code
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
            if exc.code in (400, 401, 403, 404, 422):
                return {"_error": f"HTTP {exc.code}", "_status": exc.code,
                        "_body": body, "_retry_after": exc.headers.get("Retry-After", "")}
            last_error = f"HTTP {exc.code}"
            if exc.code == 429:
                # Honour Retry-After for VirusTotal's rate limiter.  The body
                # tells a per-minute limit apart from an exhausted daily quota.
                retry_after = exc.headers.get("Retry-After", "")
                return {"_error": "HTTP 429 (rate limited)", "_status": 429,
                        "_body": body, "_retry_after": retry_after}
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_error = str(getattr(exc, "reason", exc))
        except ValueError as exc:
            last_error = f"invalid JSON: {exc}"
        if attempt < retries:
            time.sleep(0.6 * (2 ** attempt))
    return {"_error": last_error or "network error", "_status": last_status}


def _get_text(url: str, timeout: float = 20.0, retries: int = 2) -> str:
    headers = {"User-Agent": USER_AGENT}
    last_error = ""
    for attempt in range(retries + 1):
        try:
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            last_error = str(getattr(exc, "reason", exc))
        if attempt < retries:
            time.sleep(0.6 * (2 ** attempt))
    raise OSError(last_error or "network error")


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

class EnrichmentCache:
    """Versioned, timestamped on-disk cache.

    Version 1 of SNItch stored a flat ``{ip: {country: ...}}`` dict. On load
    that shape is migrated into ``{"geo": {ip: {...}}}`` automatically.
    """

    def __init__(self, path: Optional[str], logger: Logger, enabled: bool = True) -> None:
        self.path = path
        self.logger = logger
        self.enabled = enabled and bool(path)
        self.data: Dict[str, Any] = {
            "version": CACHE_VERSION, "geo": {}, "vt": {}, "rdns": {},
            "rdap": {}, "domains": {}, "tor": {}, "geo_failed": {},
            "rdap_failed": {},
        }
        self._dirty = 0
        if self.enabled and path:
            self._load(path)

    def _load(self, path: str) -> None:
        try:
            raw = load_json(path, default=None)
        except Exception:
            raw = None
        if not isinstance(raw, dict):
            return
        if raw.get("version") == CACHE_VERSION or "geo" in raw:
            for key in self.data:
                value = raw.get(key)
                if isinstance(value, dict):
                    self.data[key] = value
            self.logger.debug(f"cache loaded: {path}")
            return
        # Version 1 migration: {ip: geo-record}
        migrated = {}
        for ip, value in raw.items():
            if not isinstance(value, dict):
                continue
            value = dict(value)
            value.setdefault("_ts", time.time())
            migrated[ip] = value
        self.data["geo"] = migrated
        self._dirty = 1
        self.logger.debug(f"migrated v1 cache with {len(migrated)} entries")

    def get(self, section: str, key: str, ttl_days: float = 0,
            refresh: bool = False) -> Optional[Dict[str, Any]]:
        """Return a cached entry if present (and fresh when ``ttl_days > 0``)."""
        if not self.enabled or refresh:
            return None
        entry = self.data.get(section, {}).get(key)
        if not isinstance(entry, dict):
            return None
        if ttl_days > 0:
            age = time.time() - float(entry.get("_ts", 0) or 0)
            if age > ttl_days * 86400:
                return None
        return entry

    def set(self, section: str, key: str, value: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        value = dict(value)
        value["_ts"] = time.time()
        self.data.setdefault(section, {})[key] = value
        self._dirty += 1
        if self._dirty >= 25:
            self.save()

    def discard(self, section: str, key: str) -> None:
        """Remove an entry (e.g. a failure that has since succeeded)."""
        if not self.enabled:
            return
        if self.data.get(section, {}).pop(key, None) is not None:
            self._dirty += 1

    def save(self) -> None:
        if not self.enabled or not self.path:
            return
        try:
            atomic_write_json(self.path, self.data, indent=None)
            self._dirty = 0
        except OSError as exc:
            self.logger.warn(f"could not save cache: {exc}")

    def count(self, section: str) -> int:
        return len(self.data.get(section, {}))


# --------------------------------------------------------------------------
# Options / result container
# --------------------------------------------------------------------------

@dataclass
class EnrichOptions:
    offline: bool = False
    geo: bool = True
    vt: bool = True
    rdns: bool = True
    rdap: bool = False
    vt_key: str = ""
    vt_delay: float = 16.0
    vt_domains: int = 0
    workers: int = 8
    refresh: bool = False
    cache_enabled: bool = True
    cache_path: Optional[str] = None
    geo_ttl_days: float = 30.0
    geo_failure_ttl_hours: float = 6.0
    vt_ttl_days: float = 7.0
    rdns_ttl_days: float = 7.0
    rdns_timeout: float = 30.0
    rdap_failure_ttl_hours: float = 6.0
    tor_exits: bool = False
    tor_exit_url: str = "https://check.torproject.org/torbulkexitlist"
    rdap_url: str = "https://rdap.org/ip/{ip}"
    logger: Logger = field(default_factory=lambda: Logger(quiet=True))


# --------------------------------------------------------------------------
# Geolocation
# --------------------------------------------------------------------------

def _geo_ipwho(ip: str) -> Dict[str, Any]:
    data = _get_json(f"https://ipwho.is/{ip}")
    if not data or data.get("_error") or not data.get("success", False):
        return {"_error": (data or {}).get("_error", "ipwho.is lookup failed")}
    connection = data.get("connection") or {}
    return {
        "country": data.get("country", "") or "",
        "cc": data.get("country_code", "") or "",
        "region": data.get("region", "") or "",
        "city": data.get("city", "") or "",
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "isp": connection.get("isp", "") or connection.get("org", "") or "",
        "org": connection.get("org", "") or "",
        "asn": f"AS{connection.get('asn')}" if connection.get("asn") else "",
        "source": "ipwho.is",
    }


def _geo_ipapi(ip: str) -> Dict[str, Any]:
    data = _get_json(f"https://ipapi.co/{ip}/json/")
    if not data or data.get("_error") or data.get("error"):
        return {"_error": (data or {}).get("_error", "ipapi.co lookup failed")}
    asn = data.get("asn", "") or ""
    if asn and not str(asn).upper().startswith("AS"):
        asn = "AS" + str(asn)
    return {
        "country": data.get("country_name", "") or "",
        "cc": data.get("country_code", "") or "",
        "region": data.get("region", "") or "",
        "city": data.get("city", "") or "",
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "isp": data.get("org", "") or "",
        "org": data.get("org", "") or "",
        "asn": asn,
        "source": "ipapi.co",
    }


def geolocate(ip: str) -> Dict[str, Any]:
    """Look up an IP with a primary provider and one fallback.

    The returned ``status`` distinguishes a provider that answered but had no
    location record (``unknown``) from a failed lookup (``failed``).
    """
    errors = []
    answered = False
    for provider in (_geo_ipwho, _geo_ipapi):
        result = provider(ip)
        if result and not result.get("_error"):
            answered = True
            if any(result.get(key) for key in (
                    "country", "cc", "region", "city", "isp", "org", "asn")):
                result["status"] = "ok"
                return result
            errors.append(f"{result.get('source') or 'provider'} returned no data")
            continue
        errors.append(str((result or {}).get("_error", "unknown")))
    result = empty_geo("unknown" if answered else "failed")
    result["_error"] = "; ".join(errors)
    return result


def _cache_for(options: EnrichOptions, cache: Optional[EnrichmentCache]) -> EnrichmentCache:
    """Use the shared cache from :func:`enrich`, or open one for direct calls."""
    if cache is not None:
        return cache
    return EnrichmentCache(options.cache_path, options.logger, options.cache_enabled)


def enrich_geo(analysis: Analysis, options: EnrichOptions,
               cache: Optional[EnrichmentCache] = None) -> Dict[str, Any]:
    cache = _cache_for(options, cache)
    todo = []
    stats = {"total": len(analysis.destinations), "cached": 0,
             "looked_up": 0, "unknown": 0, "failed": 0, "failed_cached": 0}
    failure_ttl_days = max(0.0, float(options.geo_failure_ttl_hours)) / 24.0
    for dest in analysis.destinations.values():
        cached = cache.get("geo", dest.ip, options.geo_ttl_days, options.refresh)
        if cached:
            dest.geo = {key: value for key, value in cached.items() if not key.startswith("_")}
            dest.geo.setdefault("status", "ok" if dest.geo.get("country") else "unknown")
            stats["cached"] += 1
            continue
        # Recent failures are remembered briefly so consecutive runs do not
        # hammer an unreachable provider. ``--refresh`` bypasses this.
        failure = (cache.get("geo_failed", dest.ip, failure_ttl_days, options.refresh)
                   if failure_ttl_days else None)
        if failure:
            dest.geo = empty_geo("failed_cached")
            stats["failed_cached"] += 1
        else:
            todo.append(dest.ip)

    if options.offline or not options.geo:
        placeholder = "offline" if options.offline else "disabled"
        for dest in analysis.destinations.values():
            if not dest.geo:
                dest.geo = empty_geo(placeholder)
        cache.save()
        stats["skipped"] = len(todo)
        return stats

    if todo:
        options.logger.info(f"Geolocating {len(todo)} IP(s) with {options.workers} workers ...")
    results: Dict[str, Dict[str, Any]] = {}
    failures = 0
    successes = 0
    unknown = 0
    total = len(todo)
    done = 0
    workers = max(1, min(32, int(options.workers or 8)))
    # Bounded batches keep memory/flight-time predictable if the network dies.
    batch_size = max(1, workers * 2)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="geo") as pool:
        for start in range(0, total, batch_size):
            batch = todo[start:start + batch_size]
            futures = {pool.submit(geolocate, ip): ip for ip in batch}
            for future in as_completed(futures):
                ip = futures[future]
                done += 1
                try:
                    data = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    data = {"_error": str(exc)}
                if data.get("status") == "unknown":
                    unknown += 1
                    results[ip] = data
                    cache.set("geo", ip, data)
                    cache.discard("geo_failed", ip)
                    options.logger.debug(f"  ({done}/{total}) {ip} -> no location record")
                elif data.get("_error"):
                    failures += 1
                    results[ip] = empty_geo("failed")
                    cache.set("geo_failed", ip, {"error": str(data["_error"])[:300]})
                    options.logger.debug(f"  geo failed for {ip}: {data['_error']}")
                else:
                    successes += 1
                    results[ip] = data
                    cache.set("geo", ip, data)
                    cache.discard("geo_failed", ip)
                    options.logger.info(
                        f"  ({done}/{total}) {ip} -> {data.get('country') or '?'}"
                        f" / {data.get('isp') or '?'} [{data.get('source')}]"
                    )
                if failures >= 5 and successes == 0 and unknown == 0 and done >= 5:
                    options.logger.warn(
                        "Geolocation providers are unreachable; skipping the rest. "
                        "Use --offline to silence this."
                    )
                    break
            if failures >= 5 and successes == 0 and unknown == 0 and done >= 5:
                for ip in todo[start + len(batch):]:
                    results[ip] = empty_geo("failed")
                    cache.set("geo_failed", ip,
                              {"error": "providers unreachable; skipped"})
                stats["failed"] = len(todo) - successes - unknown
                break

    for ip, data in results.items():
        if ip in analysis.destinations:
            analysis.destinations[ip].geo = data
    for dest in analysis.destinations.values():
        if not dest.geo:
            dest.geo = empty_geo("unavailable")
    cache.save()
    stats.update({"looked_up": successes, "unknown": unknown,
                  "failed": max(0, len(todo) - successes - unknown)})
    options.logger.info(
        f"Geolocation: {stats['cached']} cached, {successes} looked up, "
        f"{stats['unknown']} unknown, {stats['failed']} failed"
        + (f" ({stats['failed_cached']} recent failures reused)" if stats["failed_cached"] else "")
    )
    return stats


# --------------------------------------------------------------------------
# Reverse DNS / RDAP
# --------------------------------------------------------------------------

def reverse_dns(ip: str) -> Dict[str, Any]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return {"name": name.rstrip(".")}
    except (socket.herror, socket.gaierror, OSError):
        return {"name": ""}


def enrich_rdns(analysis: Analysis, options: EnrichOptions,
                cache: Optional[EnrichmentCache] = None) -> Dict[str, Any]:
    cache = _cache_for(options, cache)
    todo = []
    stats = {"cached": 0, "looked_up": 0, "timed_out": 0}
    for dest in analysis.destinations.values():
        cached = cache.get("rdns", dest.ip, options.rdns_ttl_days, options.refresh)
        if cached is not None:
            dest.rdns = cached.get("name", "")
            stats["cached"] += 1
        else:
            todo.append(dest.ip)
    if options.offline or not options.rdns or not todo:
        cache.save()
        return stats
    workers = max(1, min(32, int(options.workers or 8)))
    options.logger.info(f"Reverse DNS for {len(todo)} IP(s) ...")
    # gethostbyaddr has no timeout of its own and can hang for many seconds
    # per address (NetBIOS/LLMNR on Windows), so cap the total wait.
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdns")
    futures = {pool.submit(reverse_dns, ip): ip for ip in todo}
    try:
        for future in as_completed(futures, timeout=max(1.0, options.rdns_timeout)):
            ip = futures[future]
            try:
                data = future.result()
            except Exception:
                data = {"name": ""}
            cache.set("rdns", ip, data)
            if ip in analysis.destinations:
                analysis.destinations[ip].rdns = data.get("name", "")
            if data.get("name"):
                stats["looked_up"] += 1
    except FuturesTimeout:
        stats["timed_out"] = sum(1 for future in futures if not future.done())
        options.logger.warn(
            f"Reverse DNS: {stats['timed_out']} lookup(s) did not answer within "
            f"{options.rdns_timeout:g}s; continuing without them."
        )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    cache.save()
    options.logger.info(f"Reverse DNS: {stats['cached']} cached, {stats['looked_up']} names found")
    return stats


DEFAULT_RDAP_URL = "https://rdap.org/ip/{ip}"


def _rdap_source(rdap_url: str) -> str:
    """Human-readable provider label (hostname) for an RDAP URL template."""
    try:
        host = urllib.parse.urlsplit(rdap_url or DEFAULT_RDAP_URL).hostname or ""
    except ValueError:
        host = ""
    return host or "rdap"


def _rdap_lookup(ip: str, rdap_url: str = DEFAULT_RDAP_URL) -> Dict[str, Any]:
    template = rdap_url or DEFAULT_RDAP_URL
    parsed = urllib.parse.urlsplit(template)
    if "{ip}" not in template or parsed.scheme not in ("http", "https") or not parsed.netloc:
        return {"_error": "invalid RDAP URL template: expected an http(s) URL with {ip}"}
    try:
        url = template.format(ip=urllib.parse.quote(ip, safe=":"))
    except (KeyError, IndexError, ValueError) as exc:
        return {"_error": f"invalid RDAP URL template: {exc}"}
    data = _get_json(url, timeout=12.0, retries=1)
    if not data or data.get("_error"):
        return {"_error": (data or {}).get("_error", "RDAP lookup failed")}
    country = data.get("country", "") or ""
    name = data.get("name", "") or data.get("handle", "") or ""
    if not name:
        for entity in data.get("entities", []) or []:
            vcard = entity.get("vcardArray") or []
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        name = str(item[3])
                        break
            if name:
                break
    return {
        "name": name,
        "handle": data.get("handle", "") or "",
        "range": f"{data.get('startAddress', '')} - {data.get('endAddress', '')}".strip(" -"),
        "country": country,
        "type": data.get("type", "") or "",
        "source": _rdap_source(rdap_url),
    }


def enrich_rdap(analysis: Analysis, options: EnrichOptions,
                cache: Optional[EnrichmentCache] = None) -> Dict[str, Any]:
    cache = _cache_for(options, cache)
    source = _rdap_source(options.rdap_url)
    todo = []
    stats = {"cached": 0, "looked_up": 0, "failed": 0, "failed_cached": 0,
             "source": source, "template": options.rdap_url or DEFAULT_RDAP_URL}
    failure_ttl_days = max(0.0, float(options.rdap_failure_ttl_hours)) / 24.0
    for dest in analysis.destinations.values():
        cached = cache.get("rdap", dest.ip, 30, options.refresh)
        # Different providers may report different owners, so only reuse an
        # entry produced by the provider that is configured now.
        if cached and (cached.get("source") or _rdap_source(DEFAULT_RDAP_URL)) == source:
            dest.rdap = {k: v for k, v in cached.items() if not k.startswith("_")}
            stats["cached"] += 1
            continue
        # Like geolocation, remember recent failures briefly so every run
        # does not retry an endpoint that just failed.
        failure = (cache.get("rdap_failed", dest.ip, failure_ttl_days, options.refresh)
                   if failure_ttl_days else None)
        if failure and failure.get("source") == source:
            stats["failed_cached"] += 1
        else:
            todo.append(dest.ip)
    if options.offline or not options.rdap or not todo:
        cache.save()
        return stats
    options.logger.info(
        f"RDAP ({source}) network ownership for {len(todo)} IP(s) ...")
    workers = max(1, min(16, int(options.workers or 8)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdap") as pool:
        futures = {
            pool.submit(_rdap_lookup, ip, options.rdap_url or DEFAULT_RDAP_URL): ip
            for ip in todo
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                data = future.result()
            except Exception as exc:
                data = {"_error": str(exc)}
            if data.get("_error"):
                stats["failed"] += 1
                cache.set("rdap_failed", ip, {"error": str(data["_error"])[:300],
                                              "source": source})
                continue
            cache.set("rdap", ip, data)
            cache.discard("rdap_failed", ip)
            if ip in analysis.destinations:
                analysis.destinations[ip].rdap = data
            stats["looked_up"] += 1
    cache.save()
    options.logger.info(
        f"RDAP: {stats['cached']} cached, {stats['looked_up']} looked up, "
        f"{stats['failed']} failed"
    )
    return stats


# --------------------------------------------------------------------------
# VirusTotal
# --------------------------------------------------------------------------

class RateLimiter:
    def __init__(self, delay: float) -> None:
        self.delay = max(0.0, float(delay))
        self.last = 0.0
        self.requests = 0

    def wait(self) -> None:
        if self.requests and self.delay:
            elapsed = time.time() - self.last
            remaining = self.delay - elapsed
            if remaining > 0:
                time.sleep(remaining)
        self.last = time.time()
        self.requests += 1


def vt_lookup(ip: str, api_key: str) -> Dict[str, Any]:
    data = _get_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ip)}",
        headers={"x-apikey": api_key}, timeout=20.0, retries=0,
    )
    if not data:
        return {"_error": "empty response"}
    if data.get("_error"):
        return data
    try:
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {}) or {}
        return {
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "reputation": attributes.get("reputation"),
            "as_owner": attributes.get("as_owner", "") or "",
            "country": attributes.get("country", "") or "",
            "network": attributes.get("network", "") or "",
            "tags": attributes.get("tags", []) or [],
            "last_analysis_date": attributes.get("last_analysis_date"),
            "link": f"https://www.virustotal.com/gui/ip-address/{ip}",
        }
    except (KeyError, TypeError, ValueError):
        return {"_error": "unexpected VirusTotal response"}


def vt_domain_lookup(domain: str, api_key: str) -> Dict[str, Any]:
    data = _get_json(
        f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}",
        headers={"x-apikey": api_key}, timeout=20.0, retries=0,
    )
    if not data:
        return {"_error": "empty response"}
    if data.get("_error"):
        return data
    try:
        attributes = data["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {}) or {}
        return {
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories", {}) or {},
            "registrar": attributes.get("registrar", "") or "",
            "creation_date": attributes.get("creation_date"),
            "link": f"https://www.virustotal.com/gui/domain/{domain}",
        }
    except (KeyError, TypeError, ValueError):
        return {"_error": "unexpected VirusTotal response"}


def _cache_vt_result(cache: EnrichmentCache, section: str, key: str,
                     data: Dict[str, Any], ttl_days: float, options: EnrichOptions) -> None:
    if not data.get("_error"):
        cache.set(section, key, {k: v for k, v in data.items() if not k.startswith("_")})
    elif data.get("_status") == 404:
        # Cache "no record" (with the normal VT TTL) so repeated runs stay
        # cheap, but do not pretend the target is clean.
        cache.set(section, key, {"not_found": True})


def _vt_quota_exhausted(result: Dict[str, Any]) -> bool:
    """True when a 429 means the daily/monthly quota, not the per-minute limit."""
    return "QuotaExceeded" in str(result.get("_body") or "")


def _vt_retry_wait(result: Dict[str, Any]) -> float:
    try:
        return max(5.0, min(120.0, float(result.get("_retry_after") or "60")))
    except ValueError:
        return 60.0


def enrich_vt(analysis: Analysis, options: EnrichOptions,
              cache: Optional[EnrichmentCache] = None) -> Dict[str, Any]:
    cache = _cache_for(options, cache)
    stats = {"available": bool(options.vt_key), "queried": 0, "cached": 0,
             "failed": 0, "disabled": False, "quota_exhausted": False,
             "domains_queried": 0}
    if not options.vt_key or not options.vt:
        for dest in analysis.destinations.values():
            cached = cache.get("vt", dest.ip, 0)
            if cached:
                dest.vt = {k: v for k, v in cached.items() if not k.startswith("_")}
        cache.save()
        return stats

    if options.offline:
        for dest in analysis.destinations.values():
            cached = cache.get("vt", dest.ip, 0)
            if cached:
                dest.vt = {k: v for k, v in cached.items() if not k.startswith("_")}
                stats["cached"] += 1
            else:
                dest.vt = {"error": "offline"}
        cache.save()
        return stats

    limiter = RateLimiter(options.vt_delay)
    disabled = False
    disabled_reason = "disabled"
    consecutive_network_errors = 0
    todo = []
    for dest in analysis.destinations.values():
        cached = cache.get("vt", dest.ip, options.vt_ttl_days, options.refresh)
        if cached is not None:
            dest.vt = {k: v for k, v in cached.items() if not k.startswith("_")}
            stats["cached"] += 1
        else:
            todo.append(dest.ip)

    total = len(todo)
    if total:
        eta_min = (total - 1) * options.vt_delay / 60.0
        options.logger.info(
            f"VirusTotal: {total} IP(s) to query"
            + (f", ~{eta_min:.1f} min at {options.vt_delay:g}s/request" if options.vt_delay else "")
        )
    for index, ip in enumerate(todo, 1):
        if disabled:
            analysis.destinations[ip].vt = {"error": disabled_reason}
            continue
        # A 429 is retried once for the same IP after the requested pause; a
        # second 429 (or an explicit quota error) means the quota is gone.
        result: Dict[str, Any] = {}
        for attempt in range(2):
            limiter.wait()
            result = vt_lookup(ip, options.vt_key)
            if result.get("_status") != 429 or attempt or _vt_quota_exhausted(result):
                break
            wait = _vt_retry_wait(result)
            options.logger.warn(
                f"VirusTotal rate limit reached; sleeping {wait:.0f}s before retrying {ip} ...")
            time.sleep(wait)
            limiter.last = time.time()
        error = result.get("_error", "")
        if error:
            if result.get("_status") in (401, 403):
                options.logger.warn(
                    f"VirusTotal rejected the API key ({error}); disabling VT for this run."
                )
                disabled = True
                stats["disabled"] = True
                analysis.destinations[ip].vt = {"error": "auth"}
                continue
            if result.get("_status") == 429:
                remaining = total - index + 1
                reason = ("quota exhausted" if _vt_quota_exhausted(result)
                          else "still rate limited after a retry")
                options.logger.warn(
                    f"VirusTotal {reason}; skipping the remaining {remaining} IP(s).")
                analysis.warnings.append(
                    f"VirusTotal {reason}: {remaining} destination(s) were not checked."
                )
                disabled = True
                disabled_reason = "quota"
                stats["disabled"] = True
                stats["quota_exhausted"] = True
                analysis.destinations[ip].vt = {"error": "quota"}
                continue
            if result.get("_status") == 404:
                # "No record" is an answer, not a connectivity problem.
                consecutive_network_errors = 0
                analysis.destinations[ip].vt = {"not_found": True}
                _cache_vt_result(cache, "vt", ip, result, options.vt_ttl_days, options)
                continue
            consecutive_network_errors += 1
            stats["failed"] += 1
            options.logger.warn(f"  VirusTotal error for {ip}: {error}")
            analysis.destinations[ip].vt = {"error": error}
            _cache_vt_result(cache, "vt", ip, result, options.vt_ttl_days, options)
            if consecutive_network_errors >= 3:
                options.logger.warn("VirusTotal unreachable; disabling VT for this run.")
                disabled = True
                stats["disabled"] = True
            continue
        consecutive_network_errors = 0
        stats["queried"] += 1
        analysis.destinations[ip].vt = result
        _cache_vt_result(cache, "vt", ip, result, options.vt_ttl_days, options)
        options.logger.info(
            f"  ({index}/{total}) {ip} -> {result.get('malicious', 0)} malicious"
            f" / {result.get('suspicious', 0)} suspicious"
        )

    # Optional domain reputation (same rate limiter, sequential).
    if options.vt_domains > 0 and not disabled:
        ordered = sorted(
            analysis.domains.values(),
            key=lambda d: (sum(d.sources.values()), len(d.ips)),
            reverse=True,
        )[:options.vt_domains]
        for domain_stat in ordered:
            cached = cache.get("domains", domain_stat.domain, options.vt_ttl_days, options.refresh)
            if cached is not None:
                domain_stat.vt = {k: v for k, v in cached.items() if not k.startswith("_")}
                continue
            if disabled:
                break
            limiter.wait()
            result = vt_domain_lookup(domain_stat.domain, options.vt_key)
            if result.get("_error"):
                if result.get("_status") in (401, 403):
                    disabled = True
                    stats["disabled"] = True
                    break
                if result.get("_status") == 429:
                    options.logger.warn("VirusTotal rate limit hit during domain lookups; stopping.")
                    break
                stats["failed"] += 1
                continue
            domain_stat.vt = result
            _cache_vt_result(cache, "domains", domain_stat.domain, result,
                             options.vt_ttl_days, options)
            stats["domains_queried"] += 1
            options.logger.info(
                f"  domain {domain_stat.domain} -> {result.get('malicious', 0)} malicious"
            )

    cache.save()
    options.logger.info(
        f"VirusTotal: {stats['cached']} cached, {stats['queried']} queried, "
        f"{stats['failed']} failed"
    )
    return stats


# --------------------------------------------------------------------------
# Tor exit list
# --------------------------------------------------------------------------

def fetch_tor_exits(cache: EnrichmentCache, options: EnrichOptions) -> Set[str]:
    cached = cache.get("tor", "list", 1.0, options.refresh)
    if cached and isinstance(cached.get("ips"), list):
        return set(cached["ips"])
    if options.offline:
        return set()
    options.logger.info("Downloading the Tor exit-node list ...")
    try:
        text = _get_text(options.tor_exit_url)
    except OSError as exc:
        options.logger.warn(f"could not download Tor exit list: {exc}")
        return set()
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ips.add(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    cache.set("tor", "list", {"ips": sorted(ips)})
    options.logger.info(f"Tor exit list: {len(ips)} addresses")
    return ips


def apply_tor_exits(analysis: Analysis, exits: Set[str]) -> int:
    if not exits:
        return 0
    count = 0
    for dest in analysis.destinations.values():
        if dest.ip in exits:
            dest.tor_exit = True
            count += 1
    return count


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def enrich(analysis: Analysis, options: EnrichOptions) -> Dict[str, Any]:
    """Run all configured enrichment steps and attach results to the analysis.

    One cache object is shared by every step and saved once at the end, so
    steps do not reload/rewrite the file repeatedly.  Ctrl-C stops the
    enrichment early but keeps what was collected (and saves the cache), so
    the report can still be written with partial data.
    """
    started = time.time()
    enabled = ", ".join(filter(None, [
        "geo" if options.geo and not options.offline else "",
        "rDNS" if options.rdns and not options.offline else "",
        "RDAP" if options.rdap and not options.offline else "",
        "VT" if options.vt_key and options.vt and not options.offline else "",
        "Tor exits" if options.tor_exits and not options.offline else "",
    ]))
    options.logger.info("Enrichment: " + (enabled or "disabled (cache only)"))
    stats: Dict[str, Any] = {"offline": options.offline}
    cache = EnrichmentCache(options.cache_path, options.logger, options.cache_enabled)
    try:
        stats["geo"] = enrich_geo(analysis, options, cache)
        stats["rdns"] = enrich_rdns(analysis, options, cache)
        if options.rdap:
            stats["rdap"] = enrich_rdap(analysis, options, cache)
        if options.tor_exits:
            exits = fetch_tor_exits(cache, options)
            stats["tor_exits"] = {"listed": len(exits),
                                  "matched": apply_tor_exits(analysis, exits)}
        if options.vt:
            stats["vt"] = enrich_vt(analysis, options, cache)
        else:
            # Still expose cached VT data without making requests.
            for dest in analysis.destinations.values():
                cached = cache.get("vt", dest.ip, 0)
                if cached:
                    dest.vt = {k: v for k, v in cached.items() if not k.startswith("_")}
    except KeyboardInterrupt:
        stats["interrupted"] = True
        options.logger.warn("Enrichment interrupted; writing the report with partial data.")
        analysis.warnings.append(
            "Enrichment was interrupted (Ctrl-C); some destinations were not enriched."
        )
    finally:
        cache.save()
    stats["elapsed_seconds"] = round(time.time() - started, 2)
    analysis.enrichment = stats
    return stats
