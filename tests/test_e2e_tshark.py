# -*- coding: utf-8 -*-
"""End-to-end tests that run the real tshark on generated captures.

They are skipped when tshark is not installed.  Each capture is built by
``pcapgen`` so the expected results are known exactly, and each scenario
covers bugs that synthetic tshark rows cannot catch (field names, multi-value
fields, IPv6, client fallback, dashboard rendering).
"""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from unittest import mock

import pcapgen as pg
from snitchlib import cli
from snitchlib.capture import find_tshark

TSHARK = find_tshark()

PHONE, PHONE_MAC = "192.168.137.42", "02:00:00:00:00:42"
PHONE6 = "2a02:1234::42"
PC, PC_MAC = "192.168.137.1", "02:00:00:00:00:01"
ROUTER_MAC = "02:00:00:00:00:fe"
WEB, WEB6 = "93.184.216.34", "2606:4700::1111"
T0 = 1700000000.0


def eth4(src_mac, dst_mac, src, dst, proto, payload):
    return pg.ethernet(src_mac, dst_mac, 0x0800, pg.ipv4(src, dst, proto, payload))


def eth6(src_mac, dst_mac, src, dst, payload):
    return pg.ethernet(src_mac, dst_mac, 0x86DD, pg.ipv6(src, dst, 6, payload))


def hotspot_frames():
    """A phone behind a Windows Mobile Hotspot, captured on the PC."""
    quoted = pg.ipv4(PHONE, "8.8.4.4", 17, pg.udp(53005, 53, pg.dns_query("x.example")))
    return [
        (T0 + 0.0, eth4(PHONE_MAC, PC_MAC, PHONE, PC, 17,
                        pg.udp(53001, 53, pg.dns_query("www.example.com")))),
        (T0 + 0.1, eth4(PC_MAC, PHONE_MAC, PC, PHONE, 17,
                        pg.udp(53, 53001, pg.dns_answer("www.example.com", WEB)))),
        # The hotspot PC's own upstream lookup: not the phone's traffic.
        (T0 + 0.2, eth4(PC_MAC, ROUTER_MAC, "10.0.0.5", "8.8.8.8", 17,
                        pg.udp(53002, 53, pg.dns_query("upstream-only.example.net")))),
        (T0 + 0.3, eth4(ROUTER_MAC, PC_MAC, "8.8.8.8", "10.0.0.5", 17,
                        pg.udp(53, 53002, pg.dns_answer("upstream-only.example.net", "151.101.1.1")))),
        (T0 + 1.0, eth4(PHONE_MAC, PC_MAC, PHONE, WEB, 6, pg.tcp(50000, 443, "S"))),
        (T0 + 1.1, eth4(PC_MAC, PHONE_MAC, WEB, PHONE, 6, pg.tcp(443, 50000, "SA", ack=1001))),
        (T0 + 1.2, eth4(PHONE_MAC, PC_MAC, PHONE, WEB, 6,
                        pg.tcp(50000, 443, "PA", pg.tls_client_hello("www.example.com"),
                               seq=1001, ack=1))),
        # Cleartext HTTP whose User-Agent looks like a dashboard placeholder.
        (T0 + 2.0, eth4(PHONE_MAC, PC_MAC, PHONE, "151.101.1.1", 6,
                        pg.tcp(50001, 80, "PA",
                               b"GET / HTTP/1.1\r\nHost: plain.example.org\r\n"
                               b"User-Agent: /*__GEO__*/\r\n\r\n"))),
        # Carrier-grade NAT peer: not an internet destination.
        (T0 + 3.0, eth4(PHONE_MAC, PC_MAC, PHONE, "100.64.0.5", 6, pg.tcp(50002, 443, "S"))),
        # ICMP error with two IP headers (outer router, inner quoted packet).
        (T0 + 4.0, eth4(PC_MAC, PHONE_MAC, "81.2.69.160", PHONE, 1, pg.icmp_unreachable(quoted))),
        # The phone's global IPv6 address, recognisable only by its MAC.
        (T0 + 5.0, eth6(PHONE_MAC, PC_MAC, PHONE6, WEB6, pg.tcp(50003, 443, "S"))),
        (T0 + 5.1, eth6(PC_MAC, PHONE_MAC, WEB6, PHONE6, pg.tcp(443, 50003, "SA", ack=1001))),
        # A NULL-type query (classic iodine tunnelling record type).
        (T0 + 6.0, eth4(PHONE_MAC, PC_MAC, PHONE, PC, 17,
                        pg.udp(53003, 53, pg.dns_query("abc.tunnel.example.com", qtype=10)))),
    ]


def vm_frames():
    """A capture taken inside a VirtualBox NAT guest (10.0.2.15), no hotspot."""
    guest, guest_mac, nat_mac = "10.0.2.15", "08:00:27:00:00:15", "52:54:00:12:35:02"
    return [
        (T0, eth4(guest_mac, nat_mac, guest, "10.0.2.3", 17,
                  pg.udp(53001, 53, pg.dns_query("www.example.com")))),
        (T0 + 0.1, eth4(nat_mac, guest_mac, "10.0.2.3", guest, 17,
                        pg.udp(53, 53001, pg.dns_answer("www.example.com", WEB)))),
        (T0 + 1, eth4(guest_mac, nat_mac, guest, WEB, 6, pg.tcp(40000, 443, "S"))),
        (T0 + 1.2, eth4(nat_mac, guest_mac, WEB, guest, 6, pg.tcp(443, 40000, "SA", ack=1001))),
    ]


@unittest.skipUnless(TSHARK, "tshark is not installed")
class TsharkEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_cli(self, frames, *extra, name="capture.pcap"):
        path = os.path.join(self.tmp.name, name)
        pg.write_pcap(path, frames)
        out_dir = os.path.join(self.tmp.name, "out")
        argv = [path, "--offline", "--no-cache", "--out-dir", out_dir,
                "--quiet", "--tshark", TSHARK, *extra]
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(argv)
        runs = [os.path.join(out_dir, entry) for entry in os.listdir(out_dir)] \
            if os.path.isdir(out_dir) else []
        report = None
        if runs:
            with open(os.path.join(runs[0], "data", "analysis.json"), encoding="utf-8") as handle:
                report = json.load(handle)
        return code, report, (runs[0] if runs else ""), err.getvalue()

    def test_hotspot_capture(self):
        code, report, run_dir, _ = self.run_cli(hotspot_frames())
        self.assertEqual(code, 0)
        meta = report["meta"]
        self.assertEqual(meta["client_selection"], "hotspot 192.168.137.0/24")
        self.assertFalse(meta["client_fallback"])

        clients = {row["ip"]: row for row in report["clients"]}
        self.assertEqual(clients[PHONE]["selected_by"], "hotspot 192.168.137.0/24")
        self.assertIn(PHONE_MAC, clients[PHONE]["macs"])
        # IPv6 traffic of the same phone is attributed to it via its MAC.
        self.assertIn(PHONE6, clients)
        self.assertIn(PHONE, clients[PHONE6]["selected_by"])

        dests = {row["ip"]: row for row in report["destinations"]}
        self.assertIn(WEB, dests)
        self.assertIn(WEB6, dests)
        self.assertIn("151.101.1.1", dests)
        self.assertNotIn("100.64.0.5", dests)        # CGNAT is not the internet
        self.assertNotIn("8.8.8.8", dests)           # the PC's own lookup
        self.assertNotIn(PHONE6, dests)              # never the client itself
        # The ICMP error is attributed to its outer source and is not "port 53".
        self.assertIn("81.2.69.160", dests)
        self.assertEqual(dests["81.2.69.160"]["ports"], [])
        self.assertIn("ICMP", dests["81.2.69.160"]["protocols"])

        dns = {(row["qname"], row["qtype"]): row for row in report["dns"]}
        self.assertEqual(dns[("www.example.com", "A")]["count"], 1)
        self.assertIn(("abc.tunnel.example.com", "NULL"), dns)
        self.assertNotIn("upstream-only.example.net", {row["qname"] for row in report["dns"]})

        domains = {row["domain"]: row for row in report["domains"]}
        self.assertEqual(domains["www.example.com"]["sources"], {"dns": 1, "sni": 1})
        self.assertEqual(domains["www.example.com"]["ips"], {WEB: 2})
        self.assertIn("plain.example.org", domains)
        self.assertEqual(dests["151.101.1.1"]["user_agents"], {"/*__GEO__*/": 1})

        # The User-Agent must not be replaced with the map geometry.
        with open(os.path.join(run_dir, "dashboard.html"), encoding="utf-8") as handle:
            html = handle.read()
        self.assertEqual(html.count('"FeatureCollection"'), 1)
        self.assertNotIn("/*__REPORT__*/", html)
        match = re.search(r"const REPORT = (\{.*?\});\nconst GEO = ", html, re.S)
        self.assertIsNotNone(match)
        payload = json.loads(match.group(1))
        self.assertEqual(payload["meta"]["client_selection"], "hotspot 192.168.137.0/24")
        self.assertEqual({row["ip"] for row in payload["destinations"]}, set(dests))

    def test_capture_file_falls_back_without_searching_local_interfaces(self):
        with mock.patch("snitchlib.cli.local_ipv4_networks") as local, \
                mock.patch("snitchlib.cli.iter_packets", wraps=cli.iter_packets) as packets:
            code, report, _, err = self.run_cli(vm_frames(), "--no-html")
        self.assertEqual(code, 0)
        local.assert_not_called()           # this PC's interfaces are irrelevant
        self.assertEqual(packets.call_count, 1)  # one tshark pass, no re-reads
        self.assertTrue(report["meta"]["client_fallback"])
        self.assertTrue(report["meta"]["auto_clients"])
        self.assertTrue(report["meta"]["client_selection"].startswith("auto-clients"))
        self.assertEqual([row["ip"] for row in report["clients"]], ["10.0.2.15"])
        self.assertEqual(report["clients"][0]["selected_by"], "auto (local address)")
        self.assertIn(WEB, {row["ip"] for row in report["destinations"]})
        self.assertTrue(any("auto-clients fallback" in w for w in report["warnings"]))
        self.assertIn("auto-clients fallback", err)

    def test_detect_local_is_still_available_on_request(self):
        import ipaddress
        detected = [ipaddress.ip_network("10.0.2.0/24")]
        with mock.patch("snitchlib.cli.local_ipv4_networks", return_value=detected):
            code, report, _, _ = self.run_cli(vm_frames(), "--no-html", "--detect-local")
        self.assertEqual(code, 0)
        self.assertFalse(report["meta"]["client_fallback"])
        self.assertEqual(report["meta"]["client_selection"],
                         "hotspot 192.168.137.0/24, detected 10.0.2.0/24")
        self.assertEqual(report["clients"][0]["selected_by"], "detected subnet 10.0.2.0/24")

    def test_src_ip_mode_isolates_dns_and_keeps_ipv6_by_mac(self):
        code, report, _, _ = self.run_cli(hotspot_frames(), "--no-html", "--src-ip", PHONE)
        self.assertEqual(code, 0)
        self.assertEqual({row["ip"] for row in report["clients"]}, {PHONE, PHONE6})
        self.assertNotIn("upstream-only.example.net", {row["qname"] for row in report["dns"]})
        self.assertTrue(any("IPv6" in w for w in report["warnings"]))

    def test_all_mode_never_reports_the_client_ipv6_as_destination(self):
        code, report, _, _ = self.run_cli(hotspot_frames(), "--no-html", "--all")
        self.assertEqual(code, 0)
        dests = {row["ip"] for row in report["destinations"]}
        self.assertIn(WEB6, dests)
        self.assertNotIn(PHONE6, dests)


if __name__ == "__main__":
    unittest.main()
