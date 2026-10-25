# -*- coding: utf-8 -*-
"""Tests for the streaming extractor using synthetic tshark rows."""

import unittest

from snitchlib.extract import (
    ClientMatcher, ExtractionOptions, extract, is_local_ip, is_public_ip,
    normalize_domain, normalize_hostname, normalize_ip, normalize_mac,
    parse_ip, parse_networks, strip_host_port,
)

CLIENT = "10.0.0.2"
SERVER = "93.184.216.34"


def tcp_row(**overrides):
    row = {
        "frame_number": "1",
        "frame_time_epoch": "1700000000.000",
        "frame_len": "120",
        "frame_protocols": "eth:ethertype:ip:tcp:tls",
        "ip_src": CLIENT,
        "ip_dst": SERVER,
        "ipv6_src": "",
        "ipv6_dst": "",
        "tcp_srcport": "50000",
        "tcp_dstport": "443",
        "tcp_flags_syn": "True",
        "tcp_flags_ack": "False",
        "tcp_stream": "1",
        "tcp_analysis_retransmission": "",
        "udp_srcport": "",
        "udp_dstport": "",
        "udp_stream": "",
        "icmp_type": "",
        "tls_handshake_extensions_server_name": "www.example.com",
        "tls_handshake_extensions_alpn_str": "h2",
        "tls_handshake_version": "0x0304",
        "tls_handshake_ja4": "t13d1516h2_8daaf6152771_02713d6af862",
        "dtls_handshake_extensions_server_name": "",
        "dhcp_hw_mac_addr": "",
        "dhcp_option_hostname": "",
        "dhcp_ip_your": "",
        "dhcp_ip_client": "",
        "nbns_name": "",
        "dns_flags_response": "",
        "dns_qry_name": "",
        "dns_qry_type": "",
        "dns_a": "",
        "dns_aaaa": "",
        "dns_time": "",
        "http_host": "",
        "http_user_agent": "",
        "http_request_method": "",
        "http2_headers_authority": "",
        "quic_version": "",
    }
    row.update(overrides)
    return row


def dns_query_row(**overrides):
    row = {
        "frame_number": "2",
        "frame_time_epoch": "1700000001.000",
        "frame_len": "80",
        "frame_protocols": "eth:ethertype:ip:udp:dns",
        "ip_src": CLIENT,
        "ip_dst": "8.8.8.8",
        "tcp_srcport": "",
        "tcp_dstport": "",
        "udp_srcport": "53000",
        "udp_dstport": "53",
        "udp_stream": "1",
        "dns_flags_response": "0",
        "dns_qry_name": "www.example.com",
        "dns_qry_type": "1",
        "tls_handshake_extensions_server_name": "",
        "http_host": "",
    }
    row.update(overrides)
    return row


def dns_response_row(**overrides):
    row = {
        "frame_number": "3",
        "frame_time_epoch": "1700000001.050",
        "frame_len": "140",
        "frame_protocols": "eth:ethertype:ip:udp:dns",
        "ip_src": "8.8.8.8",
        "ip_dst": CLIENT,
        "udp_srcport": "53",
        "udp_dstport": "53000",
        "udp_stream": "1",
        "dns_flags_response": "1",
        "dns_qry_name": "www.example.com",
        "dns_qry_type": "1",
        "dns_a": SERVER,
        "dns_time": "0.012",
        "tls_handshake_extensions_server_name": "",
        "http_host": "",
    }
    row.update(overrides)
    return row


class AddressTests(unittest.TestCase):
    def test_ip_helpers(self):
        self.assertEqual(normalize_ip("2001:0db8::1"), "2001:db8::1")
        self.assertIsNotNone(parse_ip("2001:db8::1"))
        self.assertIsNone(parse_ip("nope"))
        self.assertTrue(is_public_ip("93.184.216.34"))
        self.assertFalse(is_public_ip("192.168.1.10"))
        self.assertTrue(is_local_ip("fd00::1"))

    def test_parse_networks(self):
        nets = parse_networks(["10.0.0.0/8", "192.168.1.5"])
        self.assertEqual(len(nets), 2)
        with self.assertRaises(ValueError):
            parse_networks(["bad network"])

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain("WWW.Example.COM."), "www.example.com")
        self.assertEqual(normalize_domain("*.example.com"), "example.com")
        self.assertEqual(normalize_domain("bad host"), "")
        self.assertEqual(normalize_domain("http://example.com"), "")

    def test_strip_host_port(self):
        self.assertEqual(strip_host_port("example.com:8080"), "example.com")
        self.assertEqual(strip_host_port("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(strip_host_port("example.com"), "example.com")

    def test_normalize_hostname_and_mac(self):
        self.assertEqual(normalize_hostname(" DESKTOP-ABC. "), "desktop-abc")
        self.assertEqual(normalize_hostname("LAPTOP<00>"), "laptop")
        self.assertEqual(normalize_hostname("bad host"), "")
        self.assertEqual(normalize_hostname("192.168.1.10"), "")
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("00:00:00:00:00:00"), "")


class ClientMatcherTests(unittest.TestCase):
    def test_client_mode(self):
        options = ExtractionOptions(
            mode="client", client_networks=parse_networks(["10.0.0.0/24"]),
            gateways={"10.0.0.1"},
        )
        matcher = ClientMatcher(options)
        self.assertTrue(matcher("10.0.0.2"))
        self.assertFalse(matcher("10.0.0.1"))  # gateway
        self.assertFalse(matcher("192.168.1.10"))

    def test_auto_clients(self):
        options = ExtractionOptions(mode="client", auto_clients=True)
        matcher = ClientMatcher(options)
        self.assertTrue(matcher("192.168.1.10"))
        self.assertFalse(matcher("93.184.216.34"))

    def test_ip_mode(self):
        options = ExtractionOptions(mode="ip", src_ips={CLIENT})
        matcher = ClientMatcher(options)
        self.assertTrue(matcher(CLIENT))
        self.assertFalse(matcher("10.0.0.3"))


class ExtractorTests(unittest.TestCase):
    def options(self, **kwargs):
        base = dict(mode="ip", src_ips={CLIENT})
        base.update(kwargs)
        return ExtractionOptions(**base)

    def test_tcp_sni_flow_and_metadata(self):
        analysis = extract([tcp_row()], self.options())
        self.assertEqual(analysis.total_packets, 1)
        self.assertEqual(analysis.total_bytes, 120)
        self.assertEqual(analysis.selected_packets, 1)
        self.assertIn(SERVER, analysis.destinations)
        dest = analysis.destinations[SERVER]
        self.assertEqual(dest.packets_out, 1)
        self.assertEqual(dest.ports[443], 1)
        self.assertIn("TLS", dest.protocols)
        self.assertEqual(dest.tls_versions["TLS 1.3"], 1)
        self.assertEqual(dest.alpn["h2"], 1)
        self.assertTrue(dest.ja4)
        self.assertIn("www.example.com", dest.domains)
        self.assertEqual(analysis.domains["www.example.com"].sources["sni"], 1)
        key = (CLIENT, SERVER, "tcp", 443)
        self.assertIn(key, analysis.flows)
        self.assertEqual(analysis.flows[key].domains["www.example.com"], 1)
        self.assertEqual(analysis.stream_events[0][:4], (1700000000.0, CLIENT, SERVER, "tcp"))

    def test_dtls_sni_is_extracted(self):
        row = tcp_row(
            frame_protocols="eth:ethertype:ip:udp:dtls",
            tcp_srcport="",
            tcp_dstport="",
            udp_srcport="50000",
            udp_dstport="443",
            udp_stream="1",
            tls_handshake_extensions_server_name="",
            dtls_handshake_extensions_server_name="dtls.example.com",
        )
        analysis = extract([row], self.options())
        self.assertIn("dtls.example.com", analysis.domains)
        self.assertEqual(analysis.domains["dtls.example.com"].sources["sni"], 1)
        self.assertIn("dtls.example.com", analysis.destinations[SERVER].domains)

    def test_http2_authority_fallback(self):
        row = tcp_row(
            tls_handshake_extensions_server_name="",
            http_host="",
            http2_headers_authority="h2.example.com:8443",
        )
        analysis = extract([row], self.options())
        self.assertIn("h2.example.com", analysis.domains)
        self.assertEqual(analysis.domains["h2.example.com"].sources["http"], 1)

    def test_http_host_preferred_over_http2_authority(self):
        row = tcp_row(
            tls_handshake_extensions_server_name="",
            http_host="plain.example.com",
            http2_headers_authority="h2.example.com",
        )
        analysis = extract([row], self.options())
        self.assertIn("plain.example.com", analysis.domains)
        self.assertNotIn("h2.example.com", analysis.domains)

    def test_dhcp_hostname_is_attached_to_client(self):
        dhcp = tcp_row(
            frame_number="2",
            frame_protocols="eth:ethertype:ip:udp:dhcp",
            ip_src="192.168.1.1",
            ip_dst="255.255.255.255",
            tcp_srcport="", tcp_dstport="",
            udp_srcport="67", udp_dstport="68",
            tls_handshake_extensions_server_name="",
            dhcp_hw_mac_addr="aa:bb:cc:dd:ee:ff",
            dhcp_option_hostname="DESKTOP-ABC",
            dhcp_ip_your=CLIENT,
        )
        analysis = extract([tcp_row(), dhcp], self.options())
        self.assertIn("desktop-abc", analysis.clients[CLIENT].hostnames)

    def test_nbns_name_is_attached_to_source_client(self):
        nbns = tcp_row(
            frame_number="2",
            frame_protocols="eth:ethertype:ip:udp:nbns",
            ip_src=CLIENT,
            ip_dst="192.168.1.255",
            tcp_srcport="", tcp_dstport="",
            udp_srcport="137", udp_dstport="137",
            tls_handshake_extensions_server_name="",
            nbns_name="LAPTOP<00>",
        )
        analysis = extract([tcp_row(), nbns], self.options())
        self.assertIn("laptop", analysis.clients[CLIENT].hostnames)

    def test_dns_attaches_name_to_destination(self):
        rows = [
            tcp_row(tls_handshake_extensions_server_name="", frame_number="1"),
            dns_query_row(frame_number="2"),
            dns_response_row(frame_number="3"),
        ]
        analysis = extract(rows, self.options())
        self.assertIn("www.example.com", analysis.dns_answers[SERVER])
        self.assertEqual(analysis.dns_queries[("www.example.com", 1)].count, 1)
        self.assertAlmostEqual(analysis.dns_queries[("www.example.com", 1)].response_time_ms, 12.0)
        self.assertEqual(analysis.dns_servers["8.8.8.8"], 1)
        # DNS names are attached to destinations even without a visible SNI.
        self.assertIn("www.example.com", analysis.destinations[SERVER].domains)
        self.assertEqual(analysis.destinations[SERVER].domains["www.example.com"], 0)

    def test_min_packets_filter(self):
        rows = [tcp_row(frame_number=str(i)) for i in range(3)]
        analysis = extract(rows, self.options(min_packets=4))
        self.assertEqual(analysis.destinations, {})

    def test_exclude_networks(self):
        analysis = extract(
            [tcp_row()],
            self.options(exclude_networks=parse_networks(["93.184.216.0/24"])),
        )
        self.assertEqual(analysis.destinations, {})
        self.assertEqual(analysis.selected_packets, 0)

    def test_http_host_and_cleartext(self):
        row = tcp_row(
            frame_protocols="eth:ethertype:ip:tcp:http",
            tcp_dstport="80",
            tls_handshake_extensions_server_name="",
            http_host="example.com:8080",
            http_request_method="GET",
        )
        analysis = extract([row], self.options())
        self.assertTrue(analysis.destinations[SERVER].has_cleartext)
        self.assertEqual(analysis.domains["example.com"].sources["http"], 1)

    def test_ignore_inbound_when_not_client(self):
        row = tcp_row(ip_src=SERVER, ip_dst=CLIENT, tcp_srcport="443",
                      tcp_dstport="50000", tcp_flags_syn="", tcp_flags_ack="True")
        analysis = extract([row], self.options())
        dest = analysis.destinations[SERVER]
        self.assertEqual(dest.packets_in, 1)
        self.assertEqual(dest.packets_out, 0)

    def test_duplicate_tcp_stream_is_one_event(self):
        rows = [tcp_row(frame_number="1", tcp_stream="7"),
                tcp_row(frame_number="2", tcp_stream="7")]
        analysis = extract(rows, self.options())
        self.assertEqual(len(analysis.stream_events), 1)


if __name__ == "__main__":
    unittest.main()
