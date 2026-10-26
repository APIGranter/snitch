# -*- coding: utf-8 -*-
"""Tests for the local heuristic detectors."""

import unittest

from snitchlib.analyze import run_heuristics, run_threat_intel, sort_findings
from snitchlib.models import Analysis, Destination, DNSQueryStat, DomainStat, Flow


def destination(ip="203.0.113.10", **kwargs):
    return Destination(ip=ip, **kwargs)


def query(name, qtype=1, qtype_name="A", count=1, **kwargs):
    return DNSQueryStat(qname=name, qtype=qtype, qtype_name=qtype_name,
                        count=count, **kwargs)


class BeaconingTests(unittest.TestCase):
    def test_regular_beacon_is_detected(self):
        analysis = Analysis()
        dest = destination()
        dest.domains["telemetry.example.org"] = 10
        analysis.destinations[dest.ip] = dest
        analysis.stream_events = [
            (1000.0 + 60 * i, "10.0.0.2", dest.ip, "tcp", 443) for i in range(10)
        ]
        findings = run_heuristics(analysis)
        beacon = [f for f in findings if f.id == "beaconing"]
        self.assertEqual(len(beacon), 1)
        self.assertEqual(beacon[0].evidence["events"], 10)
        self.assertAlmostEqual(beacon[0].evidence["median_interval_s"], 60.0)

    def test_irregular_traffic_is_not_a_beacon(self):
        analysis = Analysis()
        analysis.destinations["203.0.113.10"] = destination()
        analysis.stream_events = [
            (1000.0, "10.0.0.2", "203.0.113.10", "tcp", 443),
            (1005.0, "10.0.0.2", "203.0.113.10", "tcp", 443),
            (1200.0, "10.0.0.2", "203.0.113.10", "tcp", 443),
            (1201.0, "10.0.0.2", "203.0.113.10", "tcp", 443),
            (1700.0, "10.0.0.2", "203.0.113.10", "tcp", 443),
            (2400.0, "10.0.0.2", "203.0.113.10", "tcp", 443),
        ]
        findings = run_heuristics(analysis)
        self.assertFalse([f for f in findings if f.id == "beaconing"])


class ExfiltrationTests(unittest.TestCase):
    def test_large_asymmetric_upload(self):
        analysis = Analysis()
        dest = destination(bytes_out=20 * 1024 * 1024, bytes_in=1024 * 1024)
        analysis.destinations[dest.ip] = dest
        findings = run_heuristics(analysis)
        exfil = [f for f in findings if f.id == "outbound_volume"]
        self.assertEqual(len(exfil), 1)
        self.assertEqual(exfil[0].severity, "medium")

    def test_small_upload_is_ignored(self):
        analysis = Analysis()
        analysis.destinations["203.0.113.10"] = destination(
            bytes_out=1024 * 1024, bytes_in=10
        )
        self.assertFalse([f for f in run_heuristics(analysis) if f.id == "outbound_volume"])


class DnsTests(unittest.TestCase):
    def test_high_entropy_subdomains(self):
        analysis = Analysis()
        for i in range(30):
            label = f"{i:02d}" + "".join(chr(97 + ((i * 7 + j * 3) % 26)) for j in range(38))
            name = f"{label}.example.com"
            analysis.dns_queries[(name, 1)] = query(name, count=1)
        findings = run_heuristics(analysis)
        dns = [f for f in findings if f.id == "dns_anomaly"]
        self.assertEqual(len(dns), 1)
        self.assertGreaterEqual(dns[0].evidence["unique_subdomains"], 30)

    def test_normal_dns_is_quiet(self):
        analysis = Analysis()
        for name in ("www.example.com", "mail.example.com", "api.example.com"):
            analysis.dns_queries[(name, 1)] = query(name)
        self.assertFalse([f for f in run_heuristics(analysis) if f.id == "dns_anomaly"])


class PortScanTests(unittest.TestCase):
    def test_many_single_packet_ports(self):
        analysis = Analysis()
        for port in range(1, 41):
            flow = Flow(client="10.0.0.2", dst="203.0.113.10", proto="tcp",
                        dport=port, packets_out=1, syn_count=1)
            analysis.flows[(flow.client, flow.dst, flow.proto, port)] = flow
        findings = run_heuristics(analysis)
        scan = [f for f in findings if f.id == "port_scan"]
        self.assertEqual(len(scan), 1)
        self.assertEqual(scan[0].evidence["unique_ports"], 40)


class PlaybookTests(unittest.TestCase):
    def test_local_findings_get_remediation_and_attack_refs(self):
        analysis = Analysis()
        dest = destination(bytes_out=20 * 1024 * 1024, bytes_in=1024 * 1024)
        analysis.destinations[dest.ip] = dest
        findings = run_heuristics(analysis)
        self.assertTrue(findings)
        for finding in findings:
            self.assertTrue(finding.remediation, finding.id)
            self.assertTrue(finding.mitre, finding.id)
            self.assertRegex(finding.mitre[0], r"^T\d{4}(\.\d{3})? ")

    def test_threat_intel_findings_get_remediation(self):
        analysis = Analysis()
        dest = destination(vt={"malicious": 7, "suspicious": 1})
        analysis.destinations[dest.ip] = dest
        findings = run_threat_intel(analysis)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].id, "vt_malicious")
        self.assertIn("T1071.001", findings[0].mitre[0])
        self.assertTrue(findings[0].remediation)


class TorLikeTests(unittest.TestCase):
    def test_two_tor_ports_with_tls(self):
        analysis = Analysis()
        for ip, port in (("141.227.158.81", 9000), ("185.148.1.50", 9001)):
            dest = destination(ip=ip, bytes_out=1_000_000, bytes_in=1_000_000)
            dest.ports[port] = 100
            dest.protocols["TLS"] = 100
            analysis.destinations[ip] = dest
        findings = run_heuristics(analysis)
        tor = [f for f in findings if f.id == "tor_like"]
        self.assertEqual(len(tor), 1)
        self.assertEqual(tor[0].evidence["tor_ports"], [9000, 9001])
        self.assertEqual(tor[0].confidence, "high")

    def test_too_many_destinations_is_quiet(self):
        analysis = Analysis()
        for index in range(10):
            dest = destination(ip=f"203.0.113.{index + 1}", bytes_out=500_000, bytes_in=500_000)
            dest.ports[443] = 10
            dest.protocols["TLS"] = 10
            analysis.destinations[dest.ip] = dest
        self.assertFalse([f for f in run_heuristics(analysis) if f.id == "tor_like"])


class OtherHeuristicTests(unittest.TestCase):
    def test_cleartext(self):
        analysis = Analysis()
        dest = destination(has_cleartext=True)
        dest.ports[80] = 4
        analysis.destinations[dest.ip] = dest
        findings = run_heuristics(analysis)
        self.assertTrue([f for f in findings if f.id == "cleartext"])

    def test_threat_intel_findings(self):
        analysis = Analysis()
        dest = destination(vt={"malicious": 7, "suspicious": 1})
        analysis.destinations[dest.ip] = dest
        bad = DomainStat(domain="bad.example", vt={"malicious": 2})
        analysis.domains[bad.domain] = bad
        findings = run_threat_intel(analysis)
        ids = {f.id for f in findings}
        self.assertIn("vt_malicious", ids)
        self.assertIn("vt_domain", ids)

    def test_sort_findings(self):
        analysis = Analysis()
        dest = destination(vt={"malicious": 7})
        analysis.destinations[dest.ip] = dest
        analysis.findings.extend(run_threat_intel(analysis))
        analysis.findings.append(
            type(analysis.findings[0])(id="x", severity="critical", title="x", detail="x")
        )
        sort_findings(analysis)
        self.assertEqual(analysis.findings[0].severity, "critical")


if __name__ == "__main__":
    unittest.main()
