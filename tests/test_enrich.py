# -*- coding: utf-8 -*-
"""Tests for the enrichment cache and offline behaviour (no network access)."""

import os
import tempfile
import time
import unittest
from unittest import mock

from snitchlib.enrich import (
    CACHE_VERSION, EnrichmentCache, EnrichOptions, _rdap_lookup, _rdap_source,
    apply_tor_exits, empty_geo, enrich, enrich_geo, enrich_rdap, enrich_rdns,
)
from snitchlib.models import Analysis, Destination
from snitchlib.util import Logger, atomic_write_json


QUIET = Logger(quiet=True)


class CacheTests(unittest.TestCase):
    def test_set_get_and_reload(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "cache.json")
            cache = EnrichmentCache(path, QUIET)
            cache.set("geo", "1.2.3.4", {"country": "Testland"})
            cache.save()
            self.assertTrue(os.path.isfile(path))

            loaded = EnrichmentCache(path, QUIET)
            entry = loaded.get("geo", "1.2.3.4")
            self.assertEqual(entry["country"], "Testland")
            self.assertIn("_ts", entry)
            self.assertGreaterEqual(loaded.count("geo"), 1)

    def test_ttl_expiry(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "cache.json")
            cache = EnrichmentCache(path, QUIET)
            cache.set("geo", "1.2.3.4", {"country": "Old"})
            cache.data["geo"]["1.2.3.4"]["_ts"] = time.time() - 10 * 86400
            self.assertIsNone(cache.get("geo", "1.2.3.4", ttl_days=5))
            self.assertIsNotNone(cache.get("geo", "1.2.3.4", ttl_days=30))

    def test_refresh_bypasses_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = EnrichmentCache(os.path.join(folder, "cache.json"), QUIET)
            cache.set("geo", "1.2.3.4", {"country": "X"})
            self.assertIsNone(cache.get("geo", "1.2.3.4", refresh=True))

    def test_v1_cache_migration(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "ip_cache.json")
            atomic_write_json(path, {"1.2.3.4": {"country": "Legacy", "cc": "LG"}})
            cache = EnrichmentCache(path, QUIET)
            entry = cache.get("geo", "1.2.3.4")
            self.assertEqual(entry["country"], "Legacy")
            self.assertIn("_ts", entry)
            self.assertEqual(cache.data["version"], CACHE_VERSION)

    def test_disabled_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "cache.json")
            cache = EnrichmentCache(path, QUIET, enabled=False)
            cache.set("geo", "1.2.3.4", {"country": "X"})
            cache.save()
            self.assertFalse(os.path.exists(path))
            self.assertIsNone(cache.get("geo", "1.2.3.4"))

    def test_discard_removes_entry(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = EnrichmentCache(os.path.join(folder, "cache.json"), QUIET)
            cache.set("geo_failed", "1.2.3.4", {"error": "timeout"})
            self.assertIsNotNone(cache.get("geo_failed", "1.2.3.4"))
            cache.discard("geo_failed", "1.2.3.4")
            self.assertIsNone(cache.get("geo_failed", "1.2.3.4"))
            cache.discard("geo_failed", "not-there")  # harmless


class GeoFailureCacheTests(unittest.TestCase):
    def test_recent_failures_are_reused_then_refreshed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "cache.json")
            analysis = Analysis()
            for ip in ("203.0.113.1", "203.0.113.2"):
                analysis.destinations[ip] = Destination(ip=ip)
            options = EnrichOptions(
                geo_ttl_days=30, geo_failure_ttl_hours=6, workers=2,
                cache_path=path, logger=QUIET,
            )
            with mock.patch("snitchlib.enrich.geolocate",
                            return_value={"_error": "provider down"}):
                first = enrich_geo(analysis, options)
            self.assertEqual(first["failed"], 2)
            self.assertEqual(first["failed_cached"], 0)

            # A second run must not touch the network while failures are fresh.
            calls = []

            def fake(ip):
                calls.append(ip)
                return {"country": "Testland", "cc": "TL", "source": "fake"}

            second_analysis = Analysis()
            for ip in ("203.0.113.1", "203.0.113.2"):
                second_analysis.destinations[ip] = Destination(ip=ip)
            with mock.patch("snitchlib.enrich.geolocate", side_effect=fake):
                second = enrich_geo(second_analysis, options)
            self.assertEqual(calls, [])
            self.assertEqual(second["failed_cached"], 2)
            self.assertEqual(second["failed"], 0)

            # --refresh bypasses the negative cache and clears it on success.
            third_analysis = Analysis()
            for ip in ("203.0.113.1", "203.0.113.2"):
                third_analysis.destinations[ip] = Destination(ip=ip)
            refreshed = EnrichOptions(**{**options.__dict__, "refresh": True})
            with mock.patch("snitchlib.enrich.geolocate", side_effect=fake):
                third = enrich_geo(third_analysis, refreshed)
            self.assertEqual(sorted(calls), ["203.0.113.1", "203.0.113.2"])
            self.assertEqual(third["failed_cached"], 0)
            self.assertEqual(third["looked_up"], 2)
            cache = EnrichmentCache(path, QUIET)
            self.assertIsNone(cache.get("geo_failed", "203.0.113.1"))


class RdapTests(unittest.TestCase):
    def test_source_label_and_default(self):
        self.assertEqual(_rdap_source(""), "rdap.org")
        self.assertEqual(
            _rdap_source("https://rdap.arin.net/registry/ip/{ip}"), "rdap.arin.net")
        self.assertEqual(_rdap_source("not a url"), "rdap")

    def test_template_is_used_and_ip_is_quoted(self):
        response = {"name": "TEST-NET", "handle": "NET-1",
                    "startAddress": "203.0.113.0", "endAddress": "203.0.113.255",
                    "country": "US", "type": "DIRECT ALLOCATION"}
        with mock.patch("snitchlib.enrich._get_json", return_value=response) as get:
            data = _rdap_lookup("2001:db8::1", "https://rdap.example.net/ip/{ip}")
        self.assertEqual(
            get.call_args.args[0],
            "https://rdap.example.net/ip/2001:db8::1",
        )
        self.assertEqual(data["source"], "rdap.example.net")
        self.assertEqual(data["name"], "TEST-NET")

    def test_invalid_template_reports_error_without_network(self):
        with mock.patch("snitchlib.enrich._get_json") as get:
            data = _rdap_lookup("1.2.3.4", "https://rdap.example.net/ip")
        self.assertIn("invalid RDAP URL template", data["_error"])
        get.assert_not_called()

    def test_cache_is_ignored_when_provider_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "cache.json")
            cache = EnrichmentCache(path, QUIET)
            cache.set("rdap", "1.2.3.4", {"name": "Old owner", "source": "rdap.org"})
            cache.save()

            analysis = Analysis()
            analysis.destinations["1.2.3.4"] = Destination(ip="1.2.3.4")
            options = EnrichOptions(
                offline=True, rdap=True, cache_path=path,
                rdap_url="https://rdap.arin.net/registry/ip/{ip}",
                logger=QUIET,
            )
            stats = enrich_rdap(analysis, options)
            self.assertEqual(stats["cached"], 0)
            self.assertEqual(stats["source"], "rdap.arin.net")
            self.assertEqual(analysis.destinations["1.2.3.4"].rdap, {})

            analysis.destinations["1.2.3.4"] = Destination(ip="1.2.3.4")
            options = EnrichOptions(offline=True, rdap=True, cache_path=path,
                                    logger=QUIET)
            stats = enrich_rdap(analysis, options)
            self.assertEqual(stats["cached"], 1)
            self.assertEqual(analysis.destinations["1.2.3.4"].rdap["name"], "Old owner")


class OfflineEnrichmentTests(unittest.TestCase):
    def analysis(self, ip="203.0.113.10"):
        value = Analysis()
        value.destinations[ip] = Destination(ip=ip)
        return value

    def options(self, **kwargs):
        base = dict(offline=True, logger=QUIET, cache_enabled=False)
        base.update(kwargs)
        return EnrichOptions(**base)

    def test_offline_geo_fills_placeholder(self):
        analysis = self.analysis()
        stats = enrich_geo(analysis, self.options())
        self.assertEqual(stats["skipped"], 1)
        self.assertEqual(analysis.destinations["203.0.113.10"].geo, empty_geo())

    def test_offline_rdns_is_skipped(self):
        analysis = self.analysis()
        stats = enrich_rdns(analysis, self.options())
        self.assertEqual(stats["looked_up"], 0)
        self.assertEqual(analysis.destinations["203.0.113.10"].rdns, "")

    def test_offline_pipeline(self):
        analysis = self.analysis()
        stats = enrich(analysis, self.options(geo=True, rdns=True, vt=True))
        self.assertTrue(stats["offline"])
        self.assertEqual(analysis.destinations["203.0.113.10"].geo, empty_geo())
        self.assertIn("geo", stats)

    def test_apply_tor_exits(self):
        analysis = self.analysis()
        count = apply_tor_exits(analysis, {"203.0.113.10", "198.51.100.1"})
        self.assertEqual(count, 1)
        self.assertTrue(analysis.destinations["203.0.113.10"].tor_exit)

    def test_empty_geo_shape(self):
        geo = empty_geo()
        for key in ("country", "cc", "city", "lat", "lon", "isp", "asn"):
            self.assertIn(key, geo)


if __name__ == "__main__":
    unittest.main()
