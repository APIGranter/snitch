# -*- coding: utf-8 -*-
"""Tests for report assembly, file outputs and dashboard rendering."""

import json
import os
import tempfile
import unittest
from collections import Counter
from unittest import mock

import snitchlib.report as report_module
from snitchlib.models import Analysis, ClientStat, Destination, DNSQueryStat, DomainStat, Finding, Flow
from snitchlib.report import (
    build_dashboard, build_report, legacy_records, save_all, save_destinations_csv,
    save_findings_csv,
)
from snitchlib.util import Logger

QUIET = Logger(quiet=True)


def sample_analysis():
    analysis = Analysis()
    analysis.capture = {"file": "test.pcapng", "mode": "ip", "target": "example.com"}
    analysis.first_seen = 1700000000.0
    analysis.last_seen = 1700000060.0
    analysis.total_packets = 100
    analysis.total_bytes = 20000
    analysis.selected_packets = 90
    analysis.selected_bytes = 18000

    dest = Destination(
        ip="93.184.216.34", packets_out=60, packets_in=40,
        bytes_out=12000, bytes_in=8000, first_seen=1700000000.0,
        last_seen=1700000060.0, rdns="example.net",
        geo={"country": "United States", "cc": "US", "city": "Boston",
             "lat": 42.3, "lon": -71.0, "isp": "Example ISP", "asn": "AS15133"},
        vt={"malicious": 0, "suspicious": 0}, tor_exit=False,
    )
    dest.ports[443] = 80
    dest.protocols["TLS"] = 80
    dest.domains["www.example.com"] = 5
    analysis.destinations[dest.ip] = dest

    analysis.domains["www.example.com"] = DomainStat(
        domain="www.example.com", category="Target",
        sources=Counter({"sni": 5}), clients=Counter({"10.0.0.2": 5}),
        ips=Counter({dest.ip: 5}),
        first_seen=1700000000.0, last_seen=1700000060.0,
    )
    analysis.clients["10.0.0.2"] = ClientStat(
        ip="10.0.0.2", packets_out=60, packets_in=40,
        bytes_out=12000, bytes_in=8000,
        first_seen=1700000000.0, last_seen=1700000060.0,
        destinations=Counter({dest.ip: 100}),
        domains=Counter({"www.example.com": 5}), ports=Counter({443: 80}),
        hostnames=Counter({"test-laptop": 3}),
    )
    analysis.flows[("10.0.0.2", dest.ip, "tcp", 443)] = Flow(
        client="10.0.0.2", dst=dest.ip, proto="tcp", dport=443,
        packets_out=60, packets_in=40, bytes_out=12000, bytes_in=8000,
        first_seen=1700000000.0, last_seen=1700000060.0,
        domains=Counter({"www.example.com": 5}),
    )
    analysis.dns_queries[("www.example.com", 1)] = DNSQueryStat(
        qname="www.example.com", qtype=1, qtype_name="A", count=2,
        answers=Counter({dest.ip: 2}), clients=Counter({"10.0.0.2": 2}),
        first_seen=1700000000.0, last_seen=1700000060.0, response_time_ms=12.5,
    )
    analysis.dns_answers[dest.ip] = {"www.example.com"}
    analysis.dns_names["www.example.com"] = {dest.ip}
    analysis.ports[443] = 80
    analysis.protocols["TLS"] = 80
    analysis.timeline[1700000000] = [10, 5, 1000, 500]
    analysis.findings.append(Finding(
        id="test_finding", severity="medium", title="Test finding",
        detail="Something to see", score=0.5, confidence="high",
        ips=[dest.ip], domains=["www.example.com"],
        remediation="Investigate the endpoint.", mitre=["T1046 Network Service Discovery"],
    ))
    return analysis


class ReportTests(unittest.TestCase):
    def test_shape_and_summary(self):
        report = build_report(sample_analysis(), handle="@test", title="Test")
        self.assertEqual(report["meta"]["handle"], "@test")
        self.assertEqual(report["meta"]["file"], "test.pcapng")
        self.assertEqual(report["summary"]["ips"], 1)
        self.assertEqual(report["summary"]["domains"], 1)
        self.assertEqual(report["summary"]["clients"], 1)
        self.assertEqual(report["summary"]["flows"], 1)
        self.assertEqual(report["summary"]["malicious"], 0)
        self.assertEqual(report["summary"]["clean"], 1)
        self.assertEqual(report["summary"]["findings"], 1)
        self.assertEqual(report["findings"][0]["id"], "test_finding")
        self.assertEqual(
            report["findings"][0]["window"],
            {"first_seen": 1700000000.0, "last_seen": 1700000060.0},
        )
        self.assertEqual(report["destinations"][0]["ip"], "93.184.216.34")
        self.assertEqual(report["destinations"][0]["geo"]["country"], "United States")
        self.assertEqual(report["flows"][0]["service"], "HTTPS")
        self.assertEqual(report["clients"][0]["hostnames"], {"test-laptop": 3})

    def test_http_metadata_is_reported_and_rendered(self):
        analysis = sample_analysis()
        dest = analysis.destinations["93.184.216.34"]
        dest.user_agents["TestBrowser/1.0 (Linux)"] = 3
        dest.http_methods["GET"] = 2
        report = build_report(analysis)
        row = report["destinations"][0]
        self.assertEqual(row["user_agents"], {"TestBrowser/1.0 (Linux)": 3})
        self.assertEqual(row["http_methods"], {"GET": 2})
        with tempfile.TemporaryDirectory() as folder:
            out = os.path.join(folder, "dashboard.html")
            build_dashboard(report, out, QUIET)
            with open(out, encoding="utf-8") as handle:
                html = handle.read()
        self.assertIn("User agents", html)
        self.assertIn("TestBrowser/1.0 (Linux)", html)
        self.assertIn("HTTP methods", html)
        # The About tab ships a client-side threshold tuner.
        self.assertIn("heuristic-tuner", html)
        self.assertIn("Copy CLI command", html)
        # Findings can be filtered by severity, confidence and category.
        self.assertIn("finding-confidence", html)
        self.assertIn("finding-category", html)

    def test_dashboard_payload_caps_but_keeps_finding_rows(self):
        analysis = sample_analysis()
        popular = Destination(
            ip="198.51.100.10", packets_out=500, packets_in=500,
            bytes_out=500000, bytes_in=500000,
            first_seen=1700000000.0, last_seen=1700000060.0,
        )
        analysis.destinations[popular.ip] = popular
        analysis.domains["popular.example.net"] = DomainStat(
            domain="popular.example.net", category="Unclassified",
            sources=Counter({"sni": 900}), clients=Counter({"10.0.0.2": 900}),
            first_seen=1700000000.0, last_seen=1700000060.0,
        )
        report = build_report(analysis)
        self.assertEqual(report["destinations_total"], 2)
        self.assertEqual(report["domains_total"], 2)

        with mock.patch.object(report_module, "MAX_DESTINATION_ROWS", 1), \
                mock.patch.object(report_module, "MAX_DOMAIN_ROWS", 1):
            payload = report_module.dashboard_payload(report)
            # The top row is kept first; the finding's lower-volume row is
            # appended so pivoting from a finding still works.
            self.assertEqual(
                [row["ip"] for row in payload["destinations"]],
                ["198.51.100.10", "93.184.216.34"],
            )
            self.assertEqual(
                [row["domain"] for row in payload["domains"]],
                ["popular.example.net", "www.example.com"],
            )
            # The full report is untouched for JSON/CSV exports.
            self.assertEqual(len(report["destinations"]), 2)
            self.assertEqual(len(report["domains"]), 2)
            # Dashboard-only keys that duplicate other data are dropped.
            self.assertNotIn("classification", payload)
            self.assertNotIn("category_hits", payload)
            self.assertIn("classification", report)
            self.assertIn("category_hits", report)

            with tempfile.TemporaryDirectory() as folder:
                out = os.path.join(folder, "dashboard.html")
                build_dashboard(report, out, QUIET)
                with open(out, encoding="utf-8") as handle:
                    html = handle.read()
        self.assertIn("198.51.100.10", html)
        self.assertIn("93.184.216.34", html)
        self.assertIn('"destinations_total": 2', html)
        self.assertIn("Dashboard row limits", html)

    def test_legacy_records(self):
        report = build_report(sample_analysis())
        records = legacy_records(report)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["ip"], "93.184.216.34")
        self.assertIn("www.example.com", record["domains"])
        self.assertEqual(record["vt_malicious"], 0)

    def test_destination_csv(self):
        report = build_report(sample_analysis())
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "results.csv")
            save_destinations_csv(report, path)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        self.assertIn("ip,country", text)
        self.assertIn("93.184.216.34", text)

    def test_save_all_outputs(self):
        analysis = sample_analysis()
        report = build_report(analysis)
        with tempfile.TemporaryDirectory() as folder:
            paths = save_all(
                analysis, report, folder,
                os.path.join(folder, "data"),
                os.path.join(folder, "domains"), QUIET,
            )
            for path in paths.values():
                self.assertTrue(os.path.isfile(path), path)
            self.assertTrue(os.path.isfile(os.path.join(folder, "domains", "sni_hosts.txt")))
            with open(paths["analysis_json"], encoding="utf-8") as handle:
                loaded = json.load(handle)
            self.assertEqual(loaded["summary"]["ips"], 1)

    def test_findings_csv_includes_playbook(self):
        report = build_report(sample_analysis())
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "findings.csv")
            save_findings_csv(report, path)
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        self.assertIn("mitre,remediation", text)
        self.assertIn("T1046 Network Service Discovery", text)
        self.assertIn("Investigate the endpoint.", text)

    def test_suppressed_findings_are_serialized_and_rendered(self):
        analysis = sample_analysis()
        analysis.suppressed_findings.append(Finding(
            id="beaconing", severity="low", title="Suppressed beacon",
            detail="Allowlisted telemetry.", ips=["93.184.216.34"],
        ))
        report = build_report(analysis)
        self.assertEqual(report["summary"]["suppressed_findings"], 1)
        self.assertEqual(report["suppressed"][0]["id"], "beaconing")
        with tempfile.TemporaryDirectory() as folder:
            out = os.path.join(folder, "dashboard.html")
            build_dashboard(report, out, QUIET)
            with open(out, encoding="utf-8") as handle:
                html = handle.read()
        self.assertIn("Suppressed beacon", html)
        self.assertIn("Suppressed by allowlist", html)

    def test_dashboard_escapes_dynamic_values(self):
        analysis = sample_analysis()
        analysis.domains["<script>alert(1)</script>.example.com"] = DomainStat(
            domain="<script>alert(1)</script>.example.com", category="Unclassified",
            sources=Counter({"sni": 1}),
        )
        report = build_report(analysis)
        with tempfile.TemporaryDirectory() as folder:
            out = os.path.join(folder, "dashboard.html")
            build_dashboard(report, out, QUIET)
            with open(out, encoding="utf-8") as handle:
                html = handle.read()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", html)
        self.assertIn('id="map"', html)
        self.assertIn('id="client-table"', html)
        self.assertIn("test-laptop", html)
        self.assertIn("93.184.216.34", html)
        self.assertIn("MITRE ATT", html)
        self.assertIn("T1046 Network Service Discovery", html)
        self.assertIn("Investigate the endpoint.", html)
        self.assertIn("data-open-ip", html)
        self.assertIn("Related flows", html)
        self.assertIn("Show on timeline", html)
        self.assertIn("data-highlight-start", html)
        # The bundled GeoJSON must be embedded, not fetched.
        self.assertIn('"type":"FeatureCollection"', html)

    def test_dashboard_is_fully_offline(self):
        report = build_report(sample_analysis())
        with tempfile.TemporaryDirectory() as folder:
            out = os.path.join(folder, "dashboard.html")
            build_dashboard(report, out, QUIET)
            with open(out, encoding="utf-8") as handle:
                html = handle.read()
        # No external assets or network calls: everything is inline.
        for marker in ("<script src=", "<link", "@import", "url(",
                       "fetch(", "XMLHttpRequest", "<img", "<iframe"):
            self.assertNotIn(marker, html)

    def test_flat_records_expose_geo_status(self):
        report = build_report(sample_analysis())
        report["destinations"][0]["geo"]["status"] = "unknown"
        report["destinations"][0]["geo"]["source"] = "ipwho.is"
        row = legacy_records(report)[0]
        self.assertEqual(row["geo_status"], "unknown")
        self.assertEqual(row["geo_source"], "ipwho.is")
        self.assertIn("geo_status", report_module.LEGACY_FIELDS)

    def test_dashboard_without_geojson(self):
        report = build_report(sample_analysis())
        warnings = []

        class CaptureLogger(Logger):
            def warn(self, message):
                warnings.append(message)

        real_resource_path = report_module.resource_path

        def fake_resource_path(*parts):
            if parts and "world.geo.json" in parts[-1]:
                return os.path.join(tempfile.gettempdir(), "missing-world.geo.json")
            return real_resource_path(*parts)

        with tempfile.TemporaryDirectory() as folder:
            out = os.path.join(folder, "dashboard.html")
            with mock.patch.object(report_module, "resource_path", fake_resource_path):
                build_dashboard(report, out, CaptureLogger(quiet=True))
            with open(out, encoding="utf-8") as handle:
                html = handle.read()
        self.assertTrue(any("world.geo.json" in message for message in warnings))
        self.assertIn('{"type":"FeatureCollection","features":[]}', html)
        self.assertIn("93.184.216.34", html)


if __name__ == "__main__":
    unittest.main()
