# -*- coding: utf-8 -*-
"""Tests for local subnet discovery (pure parsers, no real interfaces)."""

import unittest
from unittest import mock

import snitchlib.netinfo as netinfo
from snitchlib.cli import _add_detected_networks, build_parser, _client_options
from snitchlib.extract import ExtractionOptions


class ParserTests(unittest.TestCase):
    def test_parse_ip_addr(self):
        text = (
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
            "2: eth0    inet 192.168.1.42/24 brd 192.168.1.255 scope global eth0\n"
            "3: wlan0    inet 10.0.0.5/16 brd 10.0.255.255 scope global wlan0\n"
        )
        networks = netinfo.parse_ip_addr(text)
        self.assertEqual(
            [str(n) for n in networks],
            ["10.0.0.0/16", "127.0.0.0/8", "192.168.1.0/24"],
        )

    def test_parse_ifconfig_hex_and_dotted_masks(self):
        text = (
            "lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384\n"
            "        inet 127.0.0.1 netmask 0xff000000\n"
            "en0: flags=8863<UP,BROADCAST> mtu 1500\n"
            "        inet 192.168.0.23 netmask 0xffffff00 broadcast 192.168.0.255\n"
            "eth1: flags=4163<UP,BROADCAST> mtu 1500\n"
            "        inet 172.16.4.9 netmask 255.255.255.0 broadcast 172.16.4.255\n"
            "eth2: flags=4163<UP,BROADCAST> mtu 1500\n"
            "        inet addr:10.10.0.7  Bcast:10.10.0.255  Mask:255.255.0.0\n"
        )
        networks = [str(n) for n in netinfo.parse_ifconfig(text)]
        self.assertIn("192.168.0.0/24", networks)
        self.assertIn("172.16.4.0/24", networks)
        self.assertIn("10.10.0.0/16", networks)
        self.assertIn("127.0.0.0/8", networks)

    def test_parse_ipconfig(self):
        text = (
            "Windows IP Configuration\n\n"
            "Ethernet adapter Ethernet:\n"
            "   Connection-specific DNS Suffix  . : lan\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.20\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1\n\n"
            "Wireless LAN adapter Wi-Fi:\n"
            "   IPv4 Address. . . . . . . . . . . : 10.20.30.40\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.0.0\n"
        )
        networks = [str(n) for n in netinfo.parse_ipconfig(text)]
        self.assertEqual(networks, ["10.20.0.0/16", "192.168.1.0/24"])

    def test_parse_output_dispatches_by_platform(self):
        self.assertEqual(
            str(netinfo.parse_output("win32", "IPv4 Address. . . : 10.0.0.2\n"
                                     "Subnet Mask . . . . : 255.255.255.0\n")[0]),
            "10.0.0.0/24",
        )
        self.assertEqual(
            str(netinfo.parse_output("darwin", "en0: inet 192.168.2.5 netmask "
                                     "0xffffff00\n")[0]),
            "192.168.2.0/24",
        )

    def test_usable_filters(self):
        self.assertFalse(netinfo._is_usable(netinfo.IPv4Network("127.0.0.0/8")))
        self.assertFalse(netinfo._is_usable(netinfo.IPv4Network("169.254.0.0/16")))
        self.assertFalse(netinfo._is_usable(netinfo.IPv4Network("8.8.8.0/24")))
        self.assertTrue(netinfo._is_usable(netinfo.IPv4Network("192.168.1.0/24")))

    def test_local_networks_uses_runner_and_filters(self):
        text = (
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0    inet 192.168.5.10/24 brd 192.168.5.255\n"
            "3: eth1    inet 8.8.8.10/24 brd 8.8.8.255\n"
        )
        with mock.patch.object(netinfo.shutil, "which", return_value="/usr/bin/ip"):
            networks = netinfo.local_ipv4_networks(
                platform="linux", runner=lambda command: text)
        self.assertEqual([str(n) for n in networks], ["192.168.5.0/24"])


class CliIntegrationTests(unittest.TestCase):
    def test_add_detected_networks_deduplicates(self):
        options = ExtractionOptions(
            client_networks=netinfo.parse_ip_addr("inet 192.168.1.5/24"))
        merged = _add_detected_networks(
            options, netinfo.parse_ip_addr("inet 192.168.1.9/24 inet 10.0.0.4/8"))
        self.assertEqual(
            [str(n) for n in merged.client_networks],
            ["192.168.1.0/24", "10.0.0.0/8"],
        )

    def test_detect_local_flag_parses(self):
        parser = build_parser()
        args = parser.parse_args(["capture.pcapng", "--detect-local"])
        self.assertTrue(args.detect_local)
        self.assertFalse(parser.parse_args(["capture.pcapng"]).detect_local)
        self.assertEqual(_client_options(args).mode, "client")


if __name__ == "__main__":
    unittest.main()
