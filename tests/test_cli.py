# -*- coding: utf-8 -*-
"""Tests for CLI parsing, config merging and key resolution."""

import json
import os
import tempfile
import unittest
from unittest import mock

from snitchlib.cli import (
    _analysis_options, _apply_config, _client_options, _csv_values,
    _extract_config_arg, _find_config_path, _load_config, _should_auto_retry,
    build_parser, read_api_key,
)
from snitchlib.allowlist import Allowlist
from snitchlib.extract import ExtractionOptions
from snitchlib.models import Analysis, Destination
from snitchlib.util import Logger


class ParserTests(unittest.TestCase):
    def test_defaults_preserve_v1_behaviour(self):
        parser = build_parser()
        args = parser.parse_args(["capture.pcapng"])
        self.assertEqual(args.hotspot_net, "192.168.137.0/24")
        self.assertEqual(args.gateway, "192.168.137.1")
        self.assertEqual(args.vt_delay, 16.0)
        self.assertEqual(args.fail_on, "none")
        self.assertFalse(args.no_html)
        self.assertFalse(args.all)

    def test_new_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "capture.pcapng", "--src-ip", "10.0.0.2,10.0.0.3",
            "--exclude-ip", "1.2.3.4", "--exclude-ip", "10.9.0.0/16",
            "--no-vt", "--no-geo", "--rdap", "--offline", "--workers", "3",
            "--fail-on", "high", "--min-packets", "5",
        ])
        self.assertEqual(args.exclude_ip, ["1.2.3.4", "10.9.0.0/16"])
        self.assertTrue(args.no_vt)
        self.assertTrue(args.rdap)
        self.assertEqual(args.workers, 3)
        self.assertEqual(args.fail_on, "high")
        self.assertEqual(args.min_packets, 5)

    def test_vt_domains_optional_value(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["x.pcap"]).vt_domains, 0)
        self.assertEqual(parser.parse_args(["x.pcap", "--vt-domains"]).vt_domains, 50)
        self.assertEqual(parser.parse_args(["x.pcap", "--vt-domains", "7"]).vt_domains, 7)

    def test_heuristic_threshold_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "x.pcap", "--beacon-min-events", "8", "--beacon-max-cv", "0.3",
            "--beacon-min-interval", "10", "--beacon-max-interval", "600",
            "--exfil-min-bytes", "1048576", "--exfil-ratio", "2.5",
            "--dns-min-unique", "50", "--scan-min-ports", "100",
            "--tor-max-destinations", "2", "--tor-min-bytes", "4096",
        ])
        options = _analysis_options(args, Allowlist.empty())
        self.assertEqual(options.beacon_min_events, 8)
        self.assertAlmostEqual(options.beacon_max_cv, 0.3)
        self.assertAlmostEqual(options.beacon_min_interval, 10.0)
        self.assertAlmostEqual(options.beacon_max_interval, 600.0)
        self.assertEqual(options.exfil_min_bytes, 1048576)
        self.assertAlmostEqual(options.exfil_ratio, 2.5)
        self.assertEqual(options.dns_min_unique, 50)
        self.assertEqual(options.scan_min_ports, 100)
        self.assertEqual(options.tor_max_destinations, 2)
        self.assertEqual(options.tor_min_bytes, 4096)

    def test_heuristic_defaults_and_invalid_values(self):
        parser = build_parser()
        options = _analysis_options(parser.parse_args(["x.pcap"]), Allowlist.empty())
        self.assertEqual(options.beacon_min_events, 5)
        self.assertEqual(options.dns_min_unique, 20)
        with self.assertRaises(SystemExit):
            parser.parse_args(["x.pcap", "--beacon-min-events", "0"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["x.pcap", "--exfil-ratio", "-1"])


class ConfigTests(unittest.TestCase):
    def test_extract_config_arg(self):
        self.assertEqual(_extract_config_arg(["--config", "a.json"]), "a.json")
        self.assertEqual(_extract_config_arg(["--config=b.json"]), "b.json")
        self.assertIsNone(_extract_config_arg(["--no-vt"]))

    def test_apply_config_types_and_unknown_keys(self):
        parser = build_parser()
        logger = Logger(quiet=True)
        in_temp = tempfile.TemporaryDirectory()
        self.addCleanup(in_temp.cleanup)
        path = os.path.join(in_temp.name, "snitch.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({
                "workers": "3",
                "no_html": "true",
                "hotspot-net": ["10.0.0.0/8", "192.168.0.0/16"],
                "vt_delay": "2.5",
                "not_an_option": 1,
            }, handle)
        raw = _load_config(path, logger)
        _apply_config(parser, raw, logger)
        args = parser.parse_args(["capture.pcapng"])
        self.assertEqual(args.workers, 3)
        self.assertTrue(args.no_html)
        self.assertEqual(args.vt_delay, 2.5)
        self.assertEqual(args.hotspot_net, ["10.0.0.0/8", "192.168.0.0/16"])

    def test_find_config_path_explicit_missing(self):
        with self.assertRaises(FileNotFoundError):
            _find_config_path("/definitely/not/here.json")

    def test_client_options(self):
        parser = build_parser()
        args = parser.parse_args([
            "capture.pcapng", "--src-ip", "10.0.0.2,10.0.0.3",
            "--exclude-ip", "1.2.3.4", "--min-packets", "2",
        ])
        options = _client_options(args)
        self.assertEqual(options.mode, "ip")
        self.assertEqual(options.src_ips, {"10.0.0.2", "10.0.0.3"})
        self.assertEqual(options.min_packets, 2)
        self.assertEqual(len(options.exclude_networks), 1)

    def test_client_options_all_mode(self):
        parser = build_parser()
        options = _client_options(parser.parse_args(["capture.pcapng", "--all"]))
        self.assertEqual(options.mode, "all")

    def test_csv_values_accepts_lists(self):
        self.assertEqual(_csv_values(["a,b", "c"]), ["a", "b", "c"])
        self.assertEqual(_csv_values(None), [])


class ClientFallbackTests(unittest.TestCase):
    def args(self, *extra):
        return build_parser().parse_args(["capture.pcapng", *extra])

    def test_fallback_when_default_filter_matched_nothing(self):
        self.assertTrue(_should_auto_retry(
            self.args(), Analysis(), ExtractionOptions(mode="client")))

    def test_no_fallback_when_results_exist(self):
        analysis = Analysis()
        analysis.clients["10.0.0.2"] = object()
        self.assertFalse(_should_auto_retry(
            self.args(), analysis, ExtractionOptions(mode="client")))
        analysis = Analysis()
        analysis.destinations["203.0.113.1"] = Destination(ip="203.0.113.1")
        self.assertFalse(_should_auto_retry(
            self.args(), analysis, ExtractionOptions(mode="client")))

    def test_no_fallback_with_explicit_network_or_mode(self):
        self.assertFalse(_should_auto_retry(
            self.args("--hotspot-net", "10.0.0.0/8"), Analysis(),
            ExtractionOptions(mode="client")))
        self.assertFalse(_should_auto_retry(
            self.args("--gateway", "10.0.0.1"), Analysis(),
            ExtractionOptions(mode="client")))
        self.assertFalse(_should_auto_retry(
            self.args(), Analysis(),
            ExtractionOptions(mode="client", auto_clients=True)))
        self.assertFalse(_should_auto_retry(
            self.args(), Analysis(),
            ExtractionOptions(mode="ip", src_ips={"10.0.0.2"})))
        self.assertFalse(_should_auto_retry(
            self.args(), Analysis(), ExtractionOptions(mode="all")))


class ApiKeyTests(unittest.TestCase):
    def test_cli_key_wins(self):
        self.assertEqual(read_api_key("  cli-key  "), "cli-key")

    def test_environment_key(self):
        with mock.patch.dict(os.environ, {"VT_API_KEY": " env-key "}, clear=False):
            self.assertEqual(read_api_key(""), "env-key")

    def test_key_file_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "vt_key.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# comment\n\n  file-key  \nsecond-key\n")
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(read_api_key("", path), "file-key")

    def test_missing_key(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertEqual(read_api_key("", os.path.join(folder, "nope")), "")


if __name__ == "__main__":
    unittest.main()
