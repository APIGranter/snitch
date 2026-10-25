# -*- coding: utf-8 -*-
"""Tests for the enrichment cache and offline behaviour (no network access)."""

import os
import tempfile
import time
import unittest

from snitchlib.enrich import (
    CACHE_VERSION, EnrichmentCache, EnrichOptions, apply_tor_exits, empty_geo,
    enrich, enrich_geo, enrich_rdns,
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
