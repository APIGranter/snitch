# -*- coding: utf-8 -*-
"""Regression tests for fixed parsing, analysis, enrichment and reporting bugs."""

import contextlib
import csv
import io
import json
import os
import tempfile
import time
import unittest
from collections import Counter
from unittest import mock

from test_extract import CLIENT, SERVER, dns_query_row, dns_response_row, tcp_row

from snitchlib import cli
from snitchlib.allowlist import Allowlist
from snitchlib.analyze import (
    AnalysisOptions, apply_threat_intel, run_heuristics, run_threat_intel,
)
from snitchlib.classify import CAT_APPS, CAT_CDN, CAT_DEVICE, CAT_TRACKING, classify_domain
from snitchlib.enrich import EnrichmentCache, EnrichOptions, enrich, enrich_rdap, enrich_rdns, enrich_vt
from snitchlib.extract import (
    ExtractionOptions, banner_domain, extract, extract_first_match, is_local_ip,
    is_public_ip, parse_networks,
)
from snitchlib.models import (
    Analysis, DNSQueryStat, Destination, DomainStat, Finding, Flow, dns_type_name,
)
from snitchlib.netinfo import decode_output, parse_ipconfig
from snitchlib.report import (
    MAX_DASHBOARD_FINDINGS, MAX_DNS_ROWS, MAX_FLOW_ROWS, _domain_hits, build_dashboard,
    build_report, dashboard_payload, save_all,
)
from snitchlib.util import Logger, open_in_browser

QUIET = Logger(quiet=True)
OTHER = "10.0.0.9"


def ip_options(**kwargs):
    base = dict(mode="ip", src_ips={CLIENT})
    base.update(kwargs)
    return ExtractionOptions(**base)


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------

class DnsTests(unittest.TestCase):
    def test_null_hinfo_opt_types_are_named(self):
        self.assertEqual(dns_type_name("10"), (10, "NULL"))
        self.assertEqual(dns_type_name("13"), (13, "HINFO"))
        self.assertEqual(dns_type_name("41"), (41, "OPT"))

    def test_null_queries_count_towards_tunnelling(self):
        rows = [dns_query_row(frame_number=str(i), dns_qry_type="10",
                              dns_qry_name=f"{'a' * 40}{i}.tunnel.example.com")
                for i in range(25)]
        analysis = extract(rows, ip_options(), QUIET)
        findings = run_heuristics(analysis, AnalysisOptions())
        dns = [f for f in findings if f.id == "dns_anomaly"]
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0].evidence["qtypes"], {"NULL": 25})
        self.assertEqual(dns[0].severity, "medium")

    def test_unselected_hosts_lookups_are_not_counted(self):
        rows = [
            dns_query_row(ip_src=OTHER, dns_qry_name="other.example.net"),
            dns_response_row(ip_dst=OTHER, dns_qry_name="other.example.net"),
            tcp_row(tls_handshake_extensions_server_name=""),
        ]
        analysis = extract(rows, ip_options(), QUIET)
        self.assertEqual(analysis.dns_queries, {})
        self.assertNotIn("other.example.net", analysis.domains)
        self.assertEqual(sum(analysis.dns_servers.values()), 0)
        # The IP -> name mapping still names the client's destination.
        self.assertIn("other.example.net", analysis.destinations[SERVER].domains)

    def test_query_and_response_count_as_one_lookup(self):
        rows = [dns_query_row(), dns_response_row(),
                tcp_row(tls_handshake_extensions_server_name="")]
        analysis = extract(rows, ip_options(), QUIET)
        domain = analysis.domains["www.example.com"]
        self.assertEqual(domain.sources["dns"], 1)
        self.assertEqual(domain.ips[SERVER], 1)
        self.assertEqual(domain.clients[CLIENT], 1)

    def test_response_without_captured_query_still_counts(self):
        analysis = extract([dns_response_row()], ip_options(), QUIET)
        self.assertEqual(analysis.domains["www.example.com"].sources["dns"], 1)

    def test_response_time_is_average_and_max(self):
        rows = [dns_query_row(), dns_response_row(dns_time="0.010"),
                dns_query_row(frame_number="4"), dns_response_row(frame_number="5", dns_time="0.030"),
                dns_response_row(frame_number="6", dns_time="")]
        stat = extract(rows, ip_options(), QUIET).dns_queries[("www.example.com", 1)]
        self.assertEqual(stat.responses, 2)
        self.assertAlmostEqual(stat.response_time_ms, 20.0)
        self.assertAlmostEqual(stat.max_response_time_ms, 30.0)


class AddressTests(unittest.TestCase):
    def test_cgnat_is_local_not_public(self):
        self.assertFalse(is_public_ip("100.64.0.5"))
        self.assertTrue(is_local_ip("100.100.100.100"))
        self.assertFalse(is_public_ip("239.255.255.250"))
        self.assertTrue(is_public_ip("93.184.216.34"))
        self.assertTrue(is_public_ip("2a00:1450::1"))
        analysis = extract([tcp_row(ip_dst="100.64.0.5")], ip_options(), QUIET)
        self.assertEqual(analysis.destinations, {})

    def test_two_ip_headers_use_the_outer_one(self):
        row = tcp_row(ip_src=f"{CLIENT},10.9.9.9", ip_dst=f"{SERVER},8.8.8.8")
        analysis = extract([row], ip_options(), QUIET)
        self.assertEqual(list(analysis.destinations), [SERVER])

    def test_icmp_error_is_not_counted_as_tcp(self):
        row = tcp_row(ip_src=f"{SERVER},{CLIENT}", ip_dst=f"{CLIENT},{SERVER}",
                      frame_protocols="eth:ethertype:ip:icmp:ip:tcp",
                      tcp_srcport="50000", tcp_dstport="443", tcp_flags_syn="",
                      tls_handshake_extensions_server_name="")
        dest = extract([row], ip_options(), QUIET).destinations[SERVER]
        self.assertEqual(dict(dest.ports), {})
        self.assertEqual(dest.protocols["ICMP"], 1)
        self.assertEqual(dest.tcp_packets, 0)


class ExtractorMiscTests(unittest.TestCase):
    def test_banner_version_strings_are_not_hostnames(self):
        self.assertEqual(banner_domain("220 ProFTPD 1.3.5e Server ready"), "")
        self.assertEqual(banner_domain("220 vsFTPd v2.0 ready"), "")
        self.assertEqual(banner_domain("220 ProFTPD 1.3.5e Server (ftp.example.net)"),
                         "ftp.example.net")

    def test_min_packets_also_filters_beacon_events(self):
        rows = [tcp_row(frame_number=str(i), tcp_stream=str(i),
                        frame_time_epoch=str(1700000000 + i * 60), ip_dst="198.51.200.1")
                for i in range(8)]
        rows = [dict(r, ip_dst="81.2.69.160") for r in rows]
        rows += [tcp_row(frame_number=f"9{i}", tcp_stream=f"9{i}") for i in range(20)]
        analysis = extract(rows, ip_options(min_packets=10), QUIET)
        self.assertNotIn("81.2.69.160", analysis.destinations)
        self.assertTrue(all(event[2] != "81.2.69.160" for event in analysis.stream_events))
        self.assertEqual(run_heuristics(analysis, AnalysisOptions()), [])

    def test_tcp_packets_and_cleartext_ports(self):
        rows = [tcp_row(), tcp_row(frame_number="2", frame_protocols="eth:ethertype:ip:tcp:http",
                                   tcp_dstport="80", tcp_stream="2")]
        dest = extract(rows, ip_options(), QUIET).destinations[SERVER]
        self.assertEqual(dest.tcp_packets, 2)
        self.assertEqual(dict(dest.cleartext_ports), {80: 1})

    def test_router_mac_is_never_used_for_ipv6_attribution(self):
        gw_mac, phone_mac = "02:00:00:00:00:01", "02:00:00:00:00:42"
        rows = [
            # Gateway itself is "local" in --all mode, and forwards public traffic.
            tcp_row(ip_src="192.168.1.1", ip_dst="192.168.1.20", eth_src=gw_mac, eth_dst=phone_mac),
            tcp_row(ip_src=SERVER, ip_dst="192.168.1.20", eth_src=gw_mac, eth_dst=phone_mac),
            tcp_row(ip_src="", ip_dst="", ipv6_src="2606:4700::1", ipv6_dst="2a02::20",
                    eth_src=gw_mac, eth_dst=phone_mac),
        ]
        analysis = extract(rows, ExtractionOptions(mode="all"), QUIET)
        self.assertIn("2606:4700::1", analysis.destinations)
        self.assertNotIn("2a02::20", analysis.destinations)
        self.assertEqual(analysis.clients["2a02::20"].selected_by,
                         "IPv6 of 192.168.1.20 (same MAC)")

    def test_broadcast_mac_is_never_learned(self):
        rows = [
            tcp_row(ip_src=CLIENT, ip_dst="10.0.0.255", eth_src="02:00:00:00:00:02",
                    eth_dst="ff:ff:ff:ff:ff:ff"),
            tcp_row(ip_src="", ip_dst="", ipv6_src="2a02::9", ipv6_dst="2606:4700::1",
                    eth_src="ff:ff:ff:ff:ff:ff", eth_dst="02:00:00:00:00:fe"),
        ]
        analysis = extract(rows, ExtractionOptions(mode="client", auto_clients=True), QUIET)
        self.assertNotIn("2a02::9", analysis.clients)


class FirstMatchTests(unittest.TestCase):
    hotspot = ExtractionOptions(mode="client", client_networks=parse_networks(["192.168.137.0/24"]),
                                gateways={"192.168.137.1"})

    def candidates(self):
        from dataclasses import replace
        return [self.hotspot, replace(self.hotspot, auto_clients=True)]

    def test_falls_back_when_primary_never_matches(self):
        analysis, used = extract_first_match([tcp_row()], self.candidates(), QUIET)
        self.assertEqual(used, 1)
        self.assertIn(CLIENT, analysis.clients)
        self.assertEqual(analysis.clients[CLIENT].selected_by, "auto (local address)")

    def test_primary_wins_even_when_it_matches_late(self):
        rows = [tcp_row(frame_number=str(i)) for i in range(5)]
        rows.append(tcp_row(frame_number="99", ip_src="192.168.137.42"))
        analysis, used = extract_first_match(rows, self.candidates(), QUIET)
        self.assertEqual(used, 0)
        self.assertEqual(list(analysis.clients), ["192.168.137.42"])
        self.assertEqual(analysis.clients["192.168.137.42"].selected_by,
                         "hotspot 192.168.137.0/24")

    def test_nothing_matches_returns_broadest(self):
        analysis, used = extract_first_match(
            [tcp_row(ip_src=SERVER, ip_dst="8.8.8.8")], self.candidates(), QUIET)
        self.assertEqual(used, 1)
        self.assertEqual(analysis.destinations, {})

    def test_requires_a_candidate(self):
        with self.assertRaises(ValueError):
            extract_first_match([], [], QUIET)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def _dest(ip, **kwargs):
    dest = Destination(ip=ip)
    for key, value in kwargs.items():
        setattr(dest, key, value)
    return dest


class AnalysisTests(unittest.TestCase):
    def test_threat_intel_findings_reach_the_analysis(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = _dest(SERVER, vt={"malicious": 3, "suspicious": 1})
        added = apply_threat_intel(analysis)
        self.assertEqual([f.id for f in added], ["vt_malicious"])
        self.assertEqual([f.id for f in analysis.findings], ["vt_malicious"])
        self.assertEqual(analysis.findings[0].severity, "high")
        # run_threat_intel itself stays side-effect free.
        self.assertEqual(len(run_threat_intel(analysis)), 1)
        self.assertEqual(len(analysis.findings), 1)

    def test_threat_intel_honours_the_allowlist(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = _dest(SERVER, vt={"malicious": 3}, tor_exit=True)
        allowlist = Allowlist.from_lines([f"{SERVER} [only: vt_malicious]"])
        apply_threat_intel(analysis, allowlist)
        self.assertEqual([f.id for f in analysis.findings], ["tor_exit"])
        self.assertEqual([f.id for f in analysis.suppressed_findings], ["vt_malicious"])
        self.assertTrue(any("reputation" in w for w in analysis.warnings))

    def _beacon_analysis(self, domain):
        analysis = Analysis()
        dest = _dest("81.2.69.160", domains=Counter({domain: 3}))
        analysis.destinations[dest.ip] = dest
        analysis.stream_events = [(1700000000 + i * 60.0, CLIENT, dest.ip, "tcp", 443)
                                  for i in range(10)]
        return analysis

    def test_beaconing_to_telemetry_is_low(self):
        finding = run_heuristics(self._beacon_analysis("incoming.telemetry.mozilla.org"))[0]
        self.assertEqual((finding.id, finding.severity, finding.confidence),
                         ("beaconing", "low", "low"))
        unknown = run_heuristics(self._beacon_analysis("weird-host.example"))[0]
        self.assertEqual(unknown.severity, "medium")

    def test_retransmission_rate_uses_tcp_packets(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = _dest(SERVER, packets_out=5000, tcp_packets=600,
                                              retransmissions=30)
        findings = [f for f in run_heuristics(analysis) if f.id == "retransmissions"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence["packets"], 600)
        self.assertAlmostEqual(findings[0].evidence["rate_percent"], 5.0)

    def test_cleartext_evidence_only_lists_cleartext_ports(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = _dest(
            SERVER, has_cleartext=True, ports=Counter({443: 50, 80: 2}),
            cleartext_ports=Counter({80: 2}))
        finding = [f for f in run_heuristics(analysis) if f.id == "cleartext"][0]
        self.assertEqual(finding.evidence["ports"], {80: 2})

    def test_exfil_and_scan_caps_are_options(self):
        analysis = Analysis()
        for index in range(4):
            ip = f"81.2.69.{index + 1}"
            analysis.destinations[ip] = _dest(ip, bytes_out=20 * 1024 * 1024, bytes_in=1000)
        findings = run_heuristics(analysis, AnalysisOptions(exfil_max_findings=2))
        self.assertEqual(len([f for f in findings if f.id == "outbound_volume"]), 2)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------

class ReportTests(unittest.TestCase):
    def big_analysis(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = _dest(SERVER, packets_out=1)
        for index in range(MAX_FLOW_ROWS + 3):
            analysis.flows[(CLIENT, SERVER, "tcp", index + 1)] = Flow(
                client=CLIENT, dst=SERVER, proto="tcp", dport=index + 1, packets_out=1)
        for index in range(MAX_DNS_ROWS + 2):
            name = f"h{index}.example.com"
            analysis.dns_queries[(name, 1)] = DNSQueryStat(qname=name, qtype=1, count=1)
        for index in range(MAX_DASHBOARD_FINDINGS + 2):
            analysis.findings.append(Finding(id="beaconing", severity="low",
                                             title="t", detail="d", ips=[SERVER]))
        return analysis

    def test_files_keep_every_row_and_dashboard_is_capped(self):
        analysis = self.big_analysis()
        report = build_report(analysis)
        self.assertEqual(len(report["flows"]), MAX_FLOW_ROWS + 3)
        self.assertEqual(len(report["dns"]), MAX_DNS_ROWS + 2)
        self.assertEqual(len(report["findings"]), MAX_DASHBOARD_FINDINGS + 2)
        self.assertEqual(report["summary"]["findings"], MAX_DASHBOARD_FINDINGS + 2)
        self.assertEqual(report["summary"]["findings_by_severity"], {"low": MAX_DASHBOARD_FINDINGS + 2})
        payload = dashboard_payload(report)
        self.assertEqual(len(payload["flows"]), MAX_FLOW_ROWS)
        self.assertEqual(len(payload["dns"]), MAX_DNS_ROWS)
        self.assertEqual(len(payload["findings"]), MAX_DASHBOARD_FINDINGS)
        self.assertEqual(payload["flows_total"], MAX_FLOW_ROWS + 3)
        with tempfile.TemporaryDirectory() as folder:
            paths = save_all(analysis, report, folder, os.path.join(folder, "data"),
                             os.path.join(folder, "domains"), QUIET)
            for key, expected in (("flows_csv", MAX_FLOW_ROWS + 3),
                                  ("dns_csv", MAX_DNS_ROWS + 2),
                                  ("findings_csv", MAX_DASHBOARD_FINDINGS + 2)):
                with open(paths[key], newline="", encoding="utf-8") as handle:
                    self.assertEqual(sum(1 for _ in csv.DictReader(handle)), expected, key)

    def test_placeholder_in_capture_data_is_not_substituted(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = _dest(
            SERVER, packets_out=1, user_agents=Counter({"/*__GEO__*/ and /*__REPORT__*/": 1}))
        report = build_report(analysis)
        with tempfile.TemporaryDirectory() as folder:
            path = build_dashboard(report, os.path.join(folder, "d.html"), QUIET)
            with open(path, encoding="utf-8") as handle:
                html = handle.read()
        self.assertEqual(html.count('"FeatureCollection"'), 1)
        start = html.index("const REPORT = ") + len("const REPORT = ")
        end = html.index(";\nconst GEO = ")
        payload = json.loads(html[start:end])
        self.assertEqual(payload["destinations"][0]["user_agents"],
                         {"/*__GEO__*/ and /*__REPORT__*/": 1})

    def test_domain_hits_with_no_sources(self):
        self.assertEqual(_domain_hits(DomainStat(domain="x.example")), 1)


# --------------------------------------------------------------------------
# Enrichment
# --------------------------------------------------------------------------

def _vt_ok(malicious=0):
    return {"malicious": malicious, "suspicious": 0, "harmless": 1, "undetected": 1}


class VirusTotalTests(unittest.TestCase):
    def analysis(self, count=3):
        analysis = Analysis()
        for index in range(count):
            ip = f"81.2.69.{index + 1}"
            analysis.destinations[ip] = Destination(ip=ip)
        return analysis

    def options(self):
        return EnrichOptions(vt_key="k", vt_delay=0, cache_enabled=False, logger=QUIET)

    def test_rate_limited_ip_is_retried(self):
        analysis = self.analysis(1)
        responses = [{"_error": "HTTP 429", "_status": 429, "_retry_after": "5"}, _vt_ok(4)]
        with mock.patch("snitchlib.enrich.vt_lookup", side_effect=responses) as lookup, \
                mock.patch("snitchlib.enrich.time.sleep") as sleep:
            stats = enrich_vt(analysis, self.options())
        self.assertEqual(lookup.call_count, 2)
        sleep.assert_called_once_with(5.0)
        self.assertEqual(stats["queried"], 1)
        self.assertEqual(analysis.destinations["81.2.69.1"].vt["malicious"], 4)

    def test_exhausted_quota_stops_immediately(self):
        analysis = self.analysis(3)
        quota = {"_error": "HTTP 429", "_status": 429,
                 "_body": '{"error": {"code": "QuotaExceededError"}}'}
        with mock.patch("snitchlib.enrich.vt_lookup", return_value=quota) as lookup, \
                mock.patch("snitchlib.enrich.time.sleep") as sleep:
            stats = enrich_vt(analysis, self.options())
        self.assertEqual(lookup.call_count, 1)
        sleep.assert_not_called()
        self.assertTrue(stats["quota_exhausted"])
        self.assertEqual({d.vt.get("error") for d in analysis.destinations.values()}, {"quota"})
        self.assertTrue(any("3 destination(s)" in w for w in analysis.warnings))

    def test_two_rate_limits_in_a_row_stop(self):
        analysis = self.analysis(2)
        limited = {"_error": "HTTP 429", "_status": 429}
        with mock.patch("snitchlib.enrich.vt_lookup", return_value=limited) as lookup, \
                mock.patch("snitchlib.enrich.time.sleep"):
            stats = enrich_vt(analysis, self.options())
        self.assertEqual(lookup.call_count, 2)
        self.assertTrue(stats["disabled"])

    def test_not_found_answers_do_not_disable_vt(self):
        analysis = self.analysis(4)
        missing = {"_error": "HTTP 404", "_status": 404}
        responses = [missing, missing, missing, _vt_ok(0)]
        with mock.patch("snitchlib.enrich.vt_lookup", side_effect=responses):
            stats = enrich_vt(analysis, self.options())
        self.assertFalse(stats["disabled"])
        self.assertEqual(stats["queried"], 1)
        self.assertEqual(analysis.destinations["81.2.69.1"].vt, {"not_found": True})


class EnrichOrchestrationTests(unittest.TestCase):
    def test_one_shared_cache(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = Destination(ip=SERVER)
        with tempfile.TemporaryDirectory() as folder:
            options = EnrichOptions(offline=True, logger=QUIET,
                                    cache_path=os.path.join(folder, "c.json"))
            with mock.patch("snitchlib.enrich.EnrichmentCache", wraps=EnrichmentCache) as cache:
                enrich(analysis, options)
            self.assertEqual(cache.call_count, 1)

    def test_ctrl_c_keeps_partial_results_and_saves_cache(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = Destination(ip=SERVER)
        geo = {"country": "Testland", "cc": "TL", "status": "ok", "source": "test"}
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "c.json")
            options = EnrichOptions(logger=QUIET, cache_path=path, vt=False)
            with mock.patch("snitchlib.enrich.geolocate", return_value=dict(geo)), \
                    mock.patch("snitchlib.enrich.enrich_rdns", side_effect=KeyboardInterrupt):
                stats = enrich(analysis, options)
            self.assertTrue(stats["interrupted"])
            self.assertEqual(analysis.destinations[SERVER].geo["country"], "Testland")
            with open(path, encoding="utf-8") as handle:
                self.assertIn(SERVER, json.load(handle)["geo"])
        self.assertTrue(any("interrupted" in w for w in analysis.warnings))

    def test_reverse_dns_total_wait_is_capped(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = Destination(ip=SERVER)

        def slow(ip):
            time.sleep(3)
            return {"name": "late.example"}

        options = EnrichOptions(logger=QUIET, cache_enabled=False, rdns_timeout=1.0)
        started = time.time()
        with mock.patch("snitchlib.enrich.reverse_dns", side_effect=slow):
            stats = enrich_rdns(analysis, options)
        self.assertLess(time.time() - started, 2.5)
        self.assertEqual(stats["timed_out"], 1)
        self.assertEqual(analysis.destinations[SERVER].rdns, "")

    def test_rdap_failures_are_cached_briefly(self):
        analysis = Analysis()
        analysis.destinations[SERVER] = Destination(ip=SERVER)
        with tempfile.TemporaryDirectory() as folder:
            options = EnrichOptions(logger=QUIET, rdap=True,
                                    cache_path=os.path.join(folder, "c.json"))
            with mock.patch("snitchlib.enrich._rdap_lookup",
                            return_value={"_error": "HTTP 500"}) as lookup:
                first = enrich_rdap(analysis, options)
                second = enrich_rdap(analysis, options)
            self.assertEqual(lookup.call_count, 1)
            self.assertEqual(first["failed"], 1)
            self.assertEqual(second["failed_cached"], 1)
            # A different provider is not blocked by the other one's failure.
            options.rdap_url = "https://rdap.arin.net/registry/ip/{ip}"
            with mock.patch("snitchlib.enrich._rdap_lookup",
                            return_value={"name": "NET", "source": "rdap.arin.net"}) as lookup:
                third = enrich_rdap(analysis, options)
            self.assertEqual(lookup.call_count, 1)
            self.assertEqual(third["template"], options.rdap_url)

    def test_log_line_when_everything_is_off(self):
        logger = mock.Mock(spec=Logger)
        enrich(Analysis(), EnrichOptions(offline=True, logger=logger, cache_enabled=False))
        first = logger.info.call_args_list[0][0][0]
        self.assertEqual(first, "Enrichment: disabled (cache only)")


# --------------------------------------------------------------------------
# Local subnet discovery
# --------------------------------------------------------------------------

SPANISH_IPCONFIG = (
    "Configuración IP de Windows\r\n\r\n"
    "Adaptador de LAN inalámbrica Wi-Fi:\r\n\r\n"
    "   Sufijo DNS específico para la conexión. . : home\r\n"
    "   Vínculo: dirección IPv6 local. . . : fe80::1%12\r\n"
    "   Dirección IPv4. . . . . . . . . . . . . . : 10.237.75.12(Preferido)\r\n"
    "   Máscara de subred . . . . . . . . . . . . : 255.255.252.0\r\n"
    "   Puerta de enlace predeterminada . . . . . : 10.237.75.1\r\n"
)


class NetinfoTests(unittest.TestCase):
    def test_cp850_spanish_ipconfig(self):
        raw = SPANISH_IPCONFIG.encode("cp850")
        self.assertIn(b"\xa2", raw)  # the byte that crashed the UTF-8 reader
        text = decode_output(raw, "cp850")
        self.assertEqual([str(n) for n in parse_ipconfig(text)], ["10.237.72.0/22"])
        # Decoding with the wrong codec degrades but never raises.
        self.assertEqual([str(n) for n in parse_ipconfig(decode_output(raw, "utf-8"))],
                         ["10.237.72.0/22"])
        self.assertTrue(decode_output(raw, "no-such-codec"))

    def test_german_labels_and_missing_mask(self):
        text = ("IPv4-Adresse  . . . . . . . . . . : 192.168.1.20\n"
                "Subnetzmaske  . . . . . . . . . . : 255.255.255.128\n"
                "Standardgateway . . . . . . . . . : 192.168.1.1\n"
                "IPv4-Adresse  . . . . . . . . . . : 172.20.0.5\n")
        self.assertEqual([str(n) for n in parse_ipconfig(text)],
                         ["172.20.0.0/24", "192.168.1.0/25"])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _apply(raw):
    parser = cli.build_parser()
    logger = mock.Mock(spec=Logger)
    cli._apply_config(parser, raw, logger)
    return parser, logger


class ConfigValidationTests(unittest.TestCase):
    def test_invalid_choices_and_values_raise(self):
        for raw in ({"fail_on": "severe"}, {"profile": "loud"},
                    {"beacon_min_events": 0}, {"workers": "many"}, {"duration": -5},
                    {"rdap_url": "ftp://x/{ip}"}):
            with self.assertRaises(ValueError, msg=raw):
                _apply(raw)

    def test_comment_keys_are_skipped_silently(self):
        parser, logger = _apply({"_comment": "hello", "fail_on": "high"})
        logger.warn.assert_not_called()
        self.assertEqual(parser.parse_args(["x.pcap"]).fail_on, "high")

    def test_example_config_loads_cleanly(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "snitch.example.json"), encoding="utf-8") as handle:
            _, logger = _apply(json.load(handle))
        logger.warn.assert_not_called()

    def test_main_exits_2_on_bad_config(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "c.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"fail_on": "severe"}, handle)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(["x.pcap", "--config", path]), 2)

    def test_non_positive_limits_are_rejected(self):
        parser = cli.build_parser()
        for flag in ("--duration", "--packet-limit", "--min-packets", "--workers"):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                parser.parse_args(["x.pcap", flag, "0"])


class CandidateTests(unittest.TestCase):
    def args(self, *extra):
        return cli.build_parser().parse_args(["x.pcap", *extra])

    def test_capture_file_skips_local_interface_search(self):
        args = self.args()
        with mock.patch("snitchlib.cli._detected_client_networks") as detect:
            candidates = cli._client_candidates(args, cli._client_options(args), False, QUIET)
        detect.assert_not_called()
        self.assertEqual([c.auto_clients for c in candidates], [False, True])

    def test_live_capture_tries_detected_subnets_in_between(self):
        args = self.args()
        detected = parse_networks(["10.1.2.0/24"])
        with mock.patch("snitchlib.cli._detected_client_networks", return_value=detected):
            candidates = cli._client_candidates(args, cli._client_options(args), True, QUIET)
        self.assertEqual(len(candidates), 3)
        self.assertEqual([str(n) for n in candidates[1].detected_networks], ["10.1.2.0/24"])
        self.assertEqual(cli._selection_label(candidates[1]),
                         "hotspot 192.168.137.0/24, detected 10.1.2.0/24")

    def test_explicit_selection_has_no_fallback(self):
        for extra in (["--hotspot-net", "10.0.0.0/8"], ["--src-ip", CLIENT],
                      ["--all"], ["--auto-clients"]):
            args = self.args(*extra)
            candidates = cli._client_candidates(args, cli._client_options(args), True, QUIET)
            self.assertEqual(len(candidates), 1, extra)


class PipelineExitCodeTests(unittest.TestCase):
    """Run cli.main with the tshark pass replaced by synthetic rows."""

    def run_main(self, *extra, vt=None):
        rows = [tcp_row(frame_number=str(i), tcp_stream=str(i)) for i in range(3)]

        def fake_enrich(analysis, options):
            for dest in analysis.destinations.values():
                dest.vt = dict(vt or {})
            analysis.enrichment = {}
            return {}

        with tempfile.TemporaryDirectory() as folder:
            capture = os.path.join(folder, "c.pcapng")
            with open(capture, "wb") as handle:
                handle.write(b"\x00" * 64)
            out = os.path.join(folder, "out")
            argv = [capture, "--src-ip", CLIENT, "--offline", "--no-html", "--quiet",
                    "--out-dir", out, *extra]
            with mock.patch("snitchlib.cli.find_tshark", return_value="tshark"), \
                    mock.patch("snitchlib.cli.tshark_version", return_value="TShark (test)"), \
                    mock.patch("snitchlib.cli.capture_info", return_value={}), \
                    mock.patch("snitchlib.cli.iter_packets", return_value=iter(rows)), \
                    mock.patch("snitchlib.cli.enrich", side_effect=fake_enrich), \
                    contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(argv)
            run_dir = os.path.join(out, os.listdir(out)[0])
            with open(os.path.join(run_dir, "data", "findings.csv"), encoding="utf-8") as handle:
                ids = [row["id"] for row in csv.DictReader(handle)]
            return code, ids

    def test_vt_finding_triggers_fail_on(self):
        code, ids = self.run_main("--fail-on", "high", vt={"malicious": 3})
        self.assertEqual(code, 3)
        self.assertIn("vt_malicious", ids)

    def test_allowlisted_vt_finding_does_not_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            allow = os.path.join(folder, "allow.txt")
            with open(allow, "w", encoding="utf-8") as handle:
                handle.write(f"{SERVER} [only: vt_malicious]\n")
            code, ids = self.run_main("--fail-on", "high", "--allowlist", allow,
                                      vt={"malicious": 3})
        self.assertEqual(code, 0)
        self.assertNotIn("vt_malicious", ids)

    def test_unwritable_out_dir_fails_before_enrichment(self):
        with tempfile.TemporaryDirectory() as folder:
            blocker = os.path.join(folder, "file")
            with open(blocker, "w", encoding="utf-8") as handle:
                handle.write("x")
            capture = os.path.join(folder, "c.pcapng")
            with open(capture, "wb") as handle:
                handle.write(b"\x00" * 64)
            with mock.patch("snitchlib.cli.find_tshark", return_value="tshark"), \
                    mock.patch("snitchlib.cli.tshark_version", return_value="x"), \
                    mock.patch("snitchlib.cli.capture_info", return_value={}), \
                    mock.patch("snitchlib.cli.iter_packets", return_value=iter([tcp_row()])), \
                    mock.patch("snitchlib.cli.enrich") as enrich_mock, \
                    contextlib.redirect_stderr(io.StringIO()):
                code = cli.main([capture, "--src-ip", CLIENT, "--quiet",
                                 "--out-dir", os.path.join(blocker, "sub")])
            self.assertEqual(code, 2)
            enrich_mock.assert_not_called()


# --------------------------------------------------------------------------
# Classification / misc
# --------------------------------------------------------------------------

class ClassificationTests(unittest.TestCase):
    def test_known_domain_categories(self):
        expected = {
            "ogads-pa.clients6.google.com": CAT_TRACKING,
            "ads.mozilla.org": CAT_TRACKING,
            "ads-img.mozilla.org": CAT_TRACKING,
            "pagead2.googlesyndication.com": CAT_TRACKING,
            "ep1.adtrafficquality.google": CAT_TRACKING,
            "www.google.com": CAT_APPS,
            "consent.google.com": CAT_APPS,
            "csp.withgoogle.com": CAT_APPS,
            "firefox.settings.services.mozilla.com": CAT_DEVICE,
            "push.services.mozilla.com": CAT_DEVICE,
            "www.msftconnecttest.com": CAT_DEVICE,
            "ipv4only.arpa": CAT_CDN,
        }
        for domain, category in expected.items():
            self.assertEqual(classify_domain(domain), category, domain)

    def test_ad_tokens_do_not_overmatch(self):
        for domain in ("uploads.example.com", "my-ad-blocker.example.com", "adobe.com",
                       "loads.example.ad", "gemini.google.com"):
            self.assertNotEqual(classify_domain(domain), CAT_TRACKING, domain)


class UtilTests(unittest.TestCase):
    def test_open_in_browser_builds_a_valid_file_uri(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "run #1 100%", "dashboard.html")
            with mock.patch("snitchlib.util.webbrowser.open", return_value=True) as browser:
                self.assertTrue(open_in_browser(path))
        uri = browser.call_args[0][0]
        self.assertTrue(uri.startswith("file:///"))
        self.assertIn("%23", uri)
        self.assertIn("%25", uri)


if __name__ == "__main__":
    unittest.main()
