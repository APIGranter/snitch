# -*- coding: utf-8 -*-
"""Tests for domain classification and service names."""

import unittest

from snitchlib.classify import (
    CAT_ANALYTICS, CAT_APPS, CAT_CDN, CAT_CHATBOT, CAT_DEVICE, CAT_OTHER,
    CAT_TARGET, CAT_TRACKING, base_domain, classify_domain, classify_domains,
    is_cleartext_port, matches_target, normalize_target, port_service,
    subdomain_prefix,
)


class BaseDomainTests(unittest.TestCase):
    def test_simple_and_subdomains(self):
        self.assertEqual(base_domain("example.com"), "example.com")
        self.assertEqual(base_domain("cdn.a.example.com"), "example.com")
        self.assertEqual(base_domain("example.com."), "example.com")

    def test_multi_part_suffixes(self):
        self.assertEqual(base_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(base_domain("shop.example.com.au"), "example.com.au")

    def test_subdomain_prefix(self):
        self.assertEqual(subdomain_prefix("a.b.example.com"), "a.b")
        self.assertEqual(subdomain_prefix("example.com"), "")


class TargetTests(unittest.TestCase):
    def test_normalize_target_from_url(self):
        self.assertEqual(normalize_target("https://user@Example.COM:443/path?q=1"), "example.com")

    def test_matches_target_on_label_boundary(self):
        self.assertTrue(matches_target("api.example.com", "example.com"))
        self.assertTrue(matches_target("example.com", "example.com"))
        self.assertFalse(matches_target("notexample.com", "example.com"))

    def test_target_category(self):
        self.assertEqual(classify_domain("api.example.com", "example.com"), CAT_TARGET)


class ClassificationTests(unittest.TestCase):
    def test_known_suffixes(self):
        self.assertEqual(classify_domain("ads.doubleclick.net"), CAT_TRACKING)
        self.assertEqual(classify_domain("api.openai.com"), CAT_CHATBOT)
        self.assertEqual(classify_domain("www.google-analytics.com"), CAT_ANALYTICS)
        self.assertEqual(classify_domain("connectivitycheck.gstatic.com"), CAT_DEVICE)
        self.assertEqual(classify_domain("cdn.jsdelivr.net"), CAT_CDN)
        self.assertEqual(classify_domain("open.spotify.com"), CAT_APPS)

    def test_unknown_domain(self):
        self.assertEqual(classify_domain("totally-unknown.invalid"), CAT_OTHER)

    def test_suffix_does_not_match_partial_label(self):
        self.assertNotEqual(classify_domain("notgoogle-analytics.com"), CAT_ANALYTICS)
        self.assertNotEqual(classify_domain("notdoubleclick.com"), CAT_TRACKING)

    def test_bulk_classification_groups(self):
        groups = classify_domains(
            ["ads.doubleclick.net", "a.doubleclick.net", "example.org"], "example.org"
        )
        self.assertEqual(groups[CAT_TARGET], ["example.org"])
        self.assertEqual(groups[CAT_TRACKING], ["ads.doubleclick.net", "a.doubleclick.net"])


class ServiceTests(unittest.TestCase):
    def test_port_service(self):
        self.assertEqual(port_service(443), "HTTPS")
        self.assertEqual(port_service(443, "udp"), "QUIC / HTTPS")
        self.assertEqual(port_service(9001), "Tor ORPort")
        self.assertEqual(port_service(65000), "port 65000")
        self.assertEqual(port_service(0), "unknown")

    def test_cleartext_ports(self):
        self.assertTrue(is_cleartext_port(80))
        self.assertFalse(is_cleartext_port(443))


if __name__ == "__main__":
    unittest.main()
