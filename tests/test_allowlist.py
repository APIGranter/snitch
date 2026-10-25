# -*- coding: utf-8 -*-
"""Tests for the finding allowlist parser and matcher."""

import os
import tempfile
import unittest

from snitchlib.allowlist import Allowlist, AllowlistError
from snitchlib.analyze import AnalysisOptions, run_heuristics
from snitchlib.models import Analysis, Finding


def finding(ips=None, domains=None, **kwargs):
    return Finding(
        id=kwargs.pop("id", "test_finding"),
        severity=kwargs.pop("severity", "medium"),
        title=kwargs.pop("title", "Test"),
        detail=kwargs.pop("detail", "Test detail"),
        ips=ips or [],
        domains=domains or [],
        **kwargs
    )


class ParsingTests(unittest.TestCase):
    def test_parses_all_entry_types(self):
        allow = Allowlist.from_lines([
            "# comment",
            "",
            "203.0.113.10",
            "198.51.100.0/24",
            "2001:db8::/32",
            "example.com",
            "*.Example.ORG.",
            "ip 192.0.2.5",
            "cidr 10.0.0.0/8",
            "domain telemetry.example.net",
            "analytics.example.com  # inline comment",
        ])
        self.assertEqual(allow.entries, 9)
        self.assertTrue(allow.matches_ip("203.0.113.10"))
        self.assertTrue(allow.matches_ip("198.51.100.42"))
        self.assertTrue(allow.matches_ip("2001:db8::1"))
        self.assertTrue(allow.matches_ip("192.0.2.5"))
        self.assertTrue(allow.matches_ip("10.9.8.7"))
        self.assertTrue(allow.matches_domain("example.com"))
        self.assertTrue(allow.matches_domain("cdn.example.com"))
        self.assertTrue(allow.matches_domain("example.org"))
        self.assertTrue(allow.matches_domain("telemetry.example.net"))
        self.assertTrue(allow.matches_domain("analytics.example.com"))

    def test_domain_matching_is_boundary_aware(self):
        allow = Allowlist.from_lines(["example.com"])
        self.assertFalse(allow.matches_domain("notexample.com"))
        self.assertFalse(allow.matches_domain("example.com.evil.net"))
        self.assertTrue(allow.matches_domain("a.b.example.com"))
        self.assertTrue(allow.matches_domain("EXAMPLE.COM."))

    def test_invalid_entries_raise(self):
        for lines in (["10.0.0.0/99"], ["domain bad_domain..com"], ["cidr nope"],
                      ["/24"], ["ip not-an-ip"]):
            with self.assertRaises(AllowlistError, msg=lines):
                Allowlist.from_lines(lines)

    def test_load_file_and_missing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "allow.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("\ufeff# header\nexample.com\n192.0.2.1\n")
            allow = Allowlist.load(path)
            self.assertEqual(allow.entries, 2)
            self.assertEqual(allow.source, path)
            self.assertTrue(allow.matches_domain("www.example.com"))
            with self.assertRaises(AllowlistError):
                Allowlist.load(os.path.join(folder, "missing.txt"))

    def test_empty_allowlist_is_a_noop(self):
        allow = Allowlist.empty()
        self.assertEqual(allow.entries, 0)
        items = [finding(domains=["example.com"])]
        kept, suppressed = allow.filter(items)
        self.assertEqual(kept, items)
        self.assertEqual(suppressed, 0)


class MatchingTests(unittest.TestCase):
    def test_domain_match_suppresses(self):
        allow = Allowlist.from_lines(["example.com"])
        self.assertTrue(allow.matches(finding(domains=["www.example.com"])))
        self.assertFalse(allow.matches(finding(domains=["other.example.net"])))

    def test_all_ips_must_match(self):
        allow = Allowlist.from_lines(["198.51.100.0/24"])
        self.assertTrue(allow.matches(finding(ips=["198.51.100.1", "198.51.100.2"])))
        self.assertFalse(allow.matches(finding(ips=["198.51.100.1", "203.0.113.9"])))
        self.assertFalse(allow.matches(finding(ips=["203.0.113.9"])))

    def test_finding_without_references_is_kept(self):
        allow = Allowlist.from_lines(["example.com"])
        self.assertFalse(allow.matches(finding()))
        self.assertFalse(allow.matches(finding(domains=[], ips=[])))

    def test_filter_counts(self):
        allow = Allowlist.from_lines(["example.com", "203.0.113.10"])
        items = [
            finding(domains=["www.example.com"]),
            finding(ips=["203.0.113.10"]),
            finding(ips=["203.0.113.11"]),
        ]
        kept, suppressed = allow.filter(items)
        self.assertEqual(suppressed, 2)
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].ips, ["203.0.113.11"])


class HeuristicsIntegrationTests(unittest.TestCase):
    def test_allowlist_suppresses_and_warns(self):
        analysis = Analysis()
        # Beacon to an allowlisted destination with an allowlisted domain.
        from snitchlib.models import Destination
        dest = Destination(ip="203.0.113.50")
        dest.domains["telemetry.example.com"] = 10
        analysis.destinations[dest.ip] = dest
        analysis.stream_events = [
            (1000.0 + 60 * index, "10.0.0.2", dest.ip, "tcp", 443)
            for index in range(10)
        ]
        allow = Allowlist.from_lines(["example.com"])
        findings = run_heuristics(
            analysis, AnalysisOptions(allowlist=allow))
        self.assertFalse([f for f in findings if f.id == "beaconing"])
        self.assertTrue(any("Allowlist suppressed" in w for w in analysis.warnings))
        self.assertEqual(analysis.findings, [])


if __name__ == "__main__":
    unittest.main()
