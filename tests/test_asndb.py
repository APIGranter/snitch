# -*- coding: utf-8 -*-
"""Tests for the optional offline ASN database (no network required)."""

import os
import tempfile
import unittest

from snitchlib.asndb import AsnDatabase, apply_asn_db
from snitchlib.models import Analysis, Destination
from snitchlib.util import Logger

QUIET = Logger(quiet=True)


def write(folder: str, name: str, text: str) -> str:
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


GEOLITE = """network,autonomous_system_number,autonomous_system_organization
1.0.0.0/24,13335,"Cloudflare, Inc."
203.0.113.0/24,64500,"TEST-NET"
2001:db8::/32,64501,"TEST-NET v6"
"""


class AsnDatabaseTests(unittest.TestCase):
    def test_geolite_csv_lookup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = write(folder, "GeoLite2-ASN-Blocks-IPv4.csv", GEOLITE)
            db = AsnDatabase.load(path)
        self.assertEqual(len(db), 3)
        self.assertEqual(db.source, "GeoLite2-ASN-Blocks-IPv4.csv")
        self.assertEqual(db.lookup("1.0.0.5"), ("AS13335", "Cloudflare, Inc."))
        self.assertEqual(db.lookup("203.0.113.200"), ("AS64500", "TEST-NET"))
        self.assertEqual(db.lookup("2001:db8::1"), ("AS64501", "TEST-NET v6"))
        self.assertIsNone(db.lookup("8.8.8.8"))
        self.assertIsNone(db.lookup("not-an-ip"))

    def test_text_format_comments_and_invalid_lines(self):
        text = """# custom ASN data
10.0.0.0/8 AS64510 Private Net
198.51.100.0/24 64511 TEST-NET-2
not-a-network AS1 Skip me
"""
        with tempfile.TemporaryDirectory() as folder:
            db = AsnDatabase.load(write(folder, "asn.txt", text))
        self.assertEqual(db.skipped, 1)
        self.assertEqual(db.lookup("10.1.2.3"), ("AS64510", "Private Net"))
        self.assertEqual(db.lookup("198.51.100.7"), ("AS64511", "TEST-NET-2"))

    def test_headerless_csv(self):
        text = "192.0.2.0/24,64496,Documentation\n"
        with tempfile.TemporaryDirectory() as folder:
            db = AsnDatabase.load(write(folder, "asn.csv", text))
        self.assertEqual(db.lookup("192.0.2.10"), ("AS64496", "Documentation"))

    def test_empty_database_is_an_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = write(folder, "empty.txt", "# nothing here\n")
            with self.assertRaises(ValueError):
                AsnDatabase.load(path)

    def test_apply_fills_only_missing_values(self):
        with tempfile.TemporaryDirectory() as folder:
            db = AsnDatabase.load(write(folder, "asn.txt", GEOLITE))

        analysis = Analysis()
        analysis.destinations["1.0.0.5"] = Destination(
            ip="1.0.0.5", geo={"asn": "AS999", "isp": "Known ISP", "org": "Known"})
        analysis.destinations["203.0.113.9"] = Destination(ip="203.0.113.9", geo={})
        analysis.destinations["8.8.8.8"] = Destination(ip="8.8.8.8", geo={})

        stats = apply_asn_db(analysis, db, QUIET)
        self.assertEqual(stats["matched"], 2)
        self.assertEqual(stats["filled"], 1)
        self.assertEqual(analysis.destinations["1.0.0.5"].geo["asn"], "AS999")
        filled = analysis.destinations["203.0.113.9"].geo
        self.assertEqual(filled["asn"], "AS64500")
        self.assertEqual(filled["org"], "TEST-NET")
        self.assertEqual(filled["isp"], "TEST-NET")
        self.assertEqual(filled["status"], "local")
        self.assertEqual(filled["asn_source"], "asn.txt")
        self.assertEqual(analysis.destinations["8.8.8.8"].geo, {})


if __name__ == "__main__":
    unittest.main()
