# -*- coding: utf-8 -*-
"""Tests for tshark field discovery (no tshark required)."""

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


if __name__ == "__main__":
    unittest.main()
