# -*- coding: utf-8 -*-
"""Tests for tshark field discovery (no tshark required)."""

import os
import subprocess
import unittest
from unittest import mock

import snitchlib.capture as capture
from snitchlib.util import Logger


class FakeLogger(Logger):
    def __init__(self):
        super().__init__(quiet=True)
        self.warnings = []

    def warn(self, message):
        self.warnings.append(message)


class FieldDiscoveryTests(unittest.TestCase):
    def test_unknown_support_keeps_all_fields(self):
        logger = FakeLogger()
        self.assertEqual(capture.filter_fields(None, logger), capture.FIELDS)
        self.assertEqual(logger.warnings, [])

    def test_missing_fields_are_dropped_and_reported(self):
        logger = FakeLogger()
        supported = set(capture.FIELDS) - {"http2.headers.authority", "quic.version"}
        fields = capture.filter_fields(supported, logger)
        self.assertNotIn("http2.headers.authority", fields)
        self.assertNotIn("quic.version", fields)
        self.assertIn("frame.number", fields)
        self.assertEqual(len(logger.warnings), 1)
        self.assertIn("http2.headers.authority", logger.warnings[0])

    def test_available_fields_parses_tshark_output(self):
        output = (
            "P\tShort Frame\t_ws.short\n"
            "F\tFrame Number\tframe.number\n"
            "F\tServer Name\ttls.handshake.extensions_server_name\n"
        )
        proc = subprocess.CompletedProcess(
            args=["tshark", "-G", "fields"], returncode=0, stdout=output, stderr="")
        capture._AVAILABLE_FIELDS.clear()
        with mock.patch.object(capture, "_run", return_value=proc):
            fields = capture.available_fields("/tmp/fake-tshark")
        self.assertIn("frame.number", fields)
        self.assertIn("tls.handshake.extensions_server_name", fields)
        self.assertNotIn("_ws.short", fields)
        # The second call uses the cache and cannot fail even if tshark breaks.
        with mock.patch.object(capture, "_run", side_effect=AssertionError("ran again")):
            self.assertIs(capture.available_fields("/tmp/fake-tshark"), fields)

    def test_available_fields_returns_none_on_garbage(self):
        proc = subprocess.CompletedProcess(
            args=["tshark", "-G", "fields"], returncode=0,
            stdout="not a field table", stderr="")
        capture._AVAILABLE_FIELDS.clear()
        with mock.patch.object(capture, "_run", return_value=proc):
            self.assertIsNone(capture.available_fields("/tmp/fake-tshark"))


class CapinfosTests(unittest.TestCase):
    OUTPUT = (
        "File name:           /tmp/capture.pcapng\n"
        "File type:           pcapng\n"
        "File encapsulation:  ether\n"
        "Number of packets:   3484\n"
        "File size:           3290416 bytes\n"
        "Capture duration:    17.675776002 seconds\n"
        "Earliest packet time: 2026-10-25 15:28:11.380213293\n"
        "Latest packet time:   2026-10-25 15:28:29.055989295\n"
        "Strict time order:   False\n"
        "Capture hardware:    11th Gen Intel(R) Core(TM) i5-1135G7\n"
        "Capture oper-sys:    Linux 6.19.14+kali-amd64\n"
        "Capture application: Dumpcap (Wireshark) 4.6.6\n"
        "Number of interfaces in file: 1\n"
        "Interface #0 info:\n"
        "                     Name = eth0\n"
        "                     Encapsulation = Ethernet (1 - ether)\n"
        "                     Capture length = 262144\n"
    )

    def test_parse_capinfos_keeps_typed_fields(self):
        info = capture.parse_capinfos(self.OUTPUT)
        self.assertEqual(info["file_type"], "pcapng")
        self.assertEqual(info["encapsulation"], "ether")
        self.assertEqual(info["packets"], 3484)
        self.assertEqual(info["file_size"], 3290416)
        self.assertAlmostEqual(info["duration"], 17.675776002)
        self.assertEqual(info["time_order"], "False")
        self.assertEqual(info["application"], "Dumpcap (Wireshark) 4.6.6")
        self.assertEqual(info["os"], "Linux 6.19.14+kali-amd64")
        self.assertEqual(info["hardware"], "11th Gen Intel(R) Core(TM) i5-1135G7")
        self.assertEqual(info["interfaces"], ["eth0"])
        self.assertEqual(info["interface_count"], 1)

    def test_parse_capinfos_ignores_unknown_and_empty_output(self):
        self.assertEqual(capture.parse_capinfos("SHA256: deadbeef\n"), {})
        self.assertEqual(capture.parse_capinfos(""), {})

    def test_capinfos_binary_prefers_sibling_of_tshark(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            tshark = os.path.join(folder, "tshark")
            capinfos = os.path.join(folder, "capinfos")
            for path in (tshark, capinfos):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("")
                os.chmod(path, 0o755)
            self.assertEqual(capture.capinfos_binary(tshark), capinfos)

    def test_capture_info_runs_capinfos(self):
        proc = subprocess.CompletedProcess(
            args=["capinfos", "-M", "/tmp/capture.pcapng"],
            returncode=0, stdout=self.OUTPUT, stderr="")
        with mock.patch.object(capture, "capinfos_binary", return_value="/usr/bin/capinfos"), \
                mock.patch.object(capture, "_run", return_value=proc) as run:
            info = capture.capture_info("/tmp/capture.pcapng", "/usr/bin/tshark")
        self.assertEqual(info["packets"], 3484)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/capinfos", "-M", "/tmp/capture.pcapng"])

    def test_capture_info_is_best_effort(self):
        with mock.patch.object(capture, "capinfos_binary", return_value=None):
            self.assertEqual(capture.capture_info("/tmp/x.pcapng"), {})
        failed = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
        with mock.patch.object(capture, "capinfos_binary", return_value="/usr/bin/capinfos"), \
                mock.patch.object(capture, "_run", return_value=failed):
            self.assertEqual(capture.capture_info("/tmp/x.pcapng"), {})
        with mock.patch.object(capture, "capinfos_binary", return_value="/usr/bin/capinfos"), \
                mock.patch.object(capture, "_run", side_effect=capture.TsharkError("missing")):
            self.assertEqual(capture.capture_info("/tmp/x.pcapng"), {})


if __name__ == "__main__":
    unittest.main()
