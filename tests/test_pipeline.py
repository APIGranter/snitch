# -*- coding: utf-8 -*-
"""End-to-end (offline) pipeline test: synthetic packets -> files -> dashboard."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

from snitchlib.analyze import (
    AnalysisOptions, apply_categories, run_heuristics, run_threat_intel, sort_findings,
)
from snitchlib.enrich import EnrichOptions, enrich
from snitchlib.extract import ExtractionOptions, extract
from snitchlib.report import build_dashboard, build_report, save_all
from snitchlib.util import Logger

QUIET = Logger(quiet=True)
CLIENT = "10.0.0.2"


def row(number, timestamp, dst, sni, stream):
    return {
        "frame_number": str(number),
        "frame_time_epoch": f"{timestamp:.3f}",
        "frame_len": "200",
        "frame_protocols": "eth:ethertype:ip:tcp:tls",
        "ip_src": CLIENT,
        "ip_dst": dst,
        "ipv6_src": "",
        "ipv6_dst": "",
        "tcp_srcport": str(40000 + number),
        "tcp_dstport": "443",
        "tcp_flags_syn": "True",
        "tcp_flags_ack": "False",
        "tcp_stream": str(stream),
        "tcp_analysis_retransmission": "",
        "udp_srcport": "",
        "udp_dstport": "",
        "udp_stream": "",
        "icmp_type": "",
        "tls_handshake_extensions_server_name": sni,
        "tls_handshake_extensions_alpn_str": "h2",
        "tls_handshake_version": "0x0304",
        "tls_handshake_ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        "dns_flags_response": "",
        "dns_qry_name": "",
        "dns_qry_type": "",
        "dns_a": "",
        "dns_aaaa": "",
        "dns_time": "",
        "http_host": "",
        "http_user_agent": "",
        "http_request_method": "",
        "quic_version": "",
    }


def synthetic_rows():
    rows = []
    number = 1
    for index in range(10):
        rows.append(row(number, 1700000000 + index * 5, "93.184.216.34",
                        "www.example.com", number))
        number += 1
    for index in range(5):
        rows.append(row(number, 1700000000 + index * 5, "142.250.72.14",
                        "www.google-analytics.com", number))
        number += 1

    dns_query = row(number, 1700000000, "8.8.8.8", "", number)
    dns_query.update({
        "frame_protocols": "eth:ethertype:ip:udp:dns",
        "ip_dst": "8.8.8.8",
        "tcp_srcport": "", "tcp_dstport": "", "tcp_stream": "",
        "udp_srcport": "53000", "udp_dstport": "53", "udp_stream": "1",
        "dns_flags_response": "0", "dns_qry_name": "www.example.com",
        "dns_qry_type": "1", "tls_handshake_extensions_server_name": "",
    })
    rows.append(dns_query)
    number += 1

    dns_answer = dict(dns_query)
    dns_answer.update({
        "frame_number": str(number),
        "frame_time_epoch": "1700000000.050",
        "ip_src": "8.8.8.8", "ip_dst": CLIENT,
        "udp_srcport": "53", "udp_dstport": "53000",
        "dns_flags_response": "1", "dns_a": "93.184.216.34",
        "dns_time": "0.020",
    })
    rows.append(dns_answer)
    return rows


class PipelineTests(unittest.TestCase):
    def test_offline_pipeline_and_outputs(self):
        options = ExtractionOptions(mode="ip", src_ips={CLIENT})
        analysis = extract(synthetic_rows(), options, QUIET)
        self.assertEqual(len(analysis.destinations), 3)  # both servers + DNS resolver

        analysis.capture.update({"file": "synthetic.pcapng", "target": "example.com"})
        apply_categories(analysis, "example.com")
        self.assertEqual(analysis.domains["www.example.com"].category, "Target")
        self.assertEqual(analysis.domains["www.google-analytics.com"].category, "Analytics")

        run_heuristics(analysis, AnalysisOptions(target="example.com"))
        enrich(analysis, EnrichOptions(offline=True, logger=QUIET, cache_enabled=False))
        run_threat_intel(analysis)
        sort_findings(analysis)

        report = build_report(analysis, handle="@test")
        self.assertEqual(report["summary"]["ips"], 3)
        self.assertEqual(report["summary"]["domains"], 2)
        self.assertEqual(report["meta"]["target"], "example.com")
        self.assertIn("enrichment", report["meta"])

        with tempfile.TemporaryDirectory() as folder:
            data_dir = os.path.join(folder, "data")
            domains_dir = os.path.join(folder, "domains")
            paths = save_all(analysis, report, folder, data_dir, domains_dir, QUIET)
            for path in paths.values():
                self.assertTrue(os.path.isfile(path), path)
            html_path = os.path.join(folder, "dashboard.html")
            build_dashboard(report, html_path, QUIET)
            self.assertTrue(os.path.isfile(html_path))
            with open(paths["results_json"], encoding="utf-8") as handle:
                legacy = json.load(handle)
            self.assertEqual(len(legacy), 3)
            with open(paths["summary_txt"], encoding="utf-8") as handle:
                summary = handle.read()
            self.assertIn("synthetic.pcapng", summary)

    def test_cli_version_subprocess(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, os.path.join(root, "snitch.py"), "--version"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SNItch 2.", proc.stdout)

    def test_module_entry_point(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        proc = subprocess.run(
            [sys.executable, "-m", "snitchlib", "--version"],
            cwd=root, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SNItch 2.", proc.stdout)


if __name__ == "__main__":
    unittest.main()
