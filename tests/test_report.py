# -*- coding: utf-8 -*-
"""Tests for report assembly, file outputs and dashboard rendering."""

import json
import os
import tempfile
import unittest
from collections import Counter

from snitchlib.models import Analysis, ClientStat, Destination, DNSQueryStat, DomainStat, Finding, Flow
from snitchlib.report import (
    build_dashboard, build_report, legacy_records, save_all, save_destinations_csv,
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
        self.assertEqual(report["destinations"][0]["ip"], "93.184.216.34")
        self.assertEqual(report["destinations"][0]["geo"]["country"], "United States")
        self.assertEqual(report["flows"][0]["service"], "HTTPS")

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
        self.assertIn("93.184.216.34", html)
        # The bundled GeoJSON must be embedded, not fetched.
        self.assertIn('"type":"FeatureCollection"', html)


if __name__ == "__main__":
    unittest.main()
