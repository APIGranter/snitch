# -*- coding: utf-8 -*-
"""Tests for :mod:`snitchlib.util`."""

import json
import os
import tempfile
import unittest

from snitchlib.util import (
    atomic_write_json, coefficient_of_variation, entropy, human_bytes,
    human_duration, iso_utc, load_json, parse_time_arg, safe_filename,
    safe_json_dumps, split_csv_arg,
)


class FormattingTests(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(human_bytes(0), "0 B")
        self.assertEqual(human_bytes(1024), "1.0 KiB")
        self.assertEqual(human_bytes(1536), "1.5 KiB")
        self.assertEqual(human_bytes(None), "-")

    def test_human_duration(self):
        self.assertEqual(human_duration(9), "9s")
        self.assertEqual(human_duration(65), "1m 05s")
        self.assertEqual(human_duration(3661), "1h 01m 01s")

    def test_safe_filename(self):
        self.assertEqual(safe_filename("/tmp/cap ture.pcapng"), "cap ture")
        self.assertEqual(safe_filename(""), "capture")
        self.assertNotIn("/", safe_filename("../../etc/passwd"))


class JsonTests(unittest.TestCase):
    def test_safe_json_escapes_script_breakout(self):
        payload = {"name": "<script>alert('x')</script>", "amp": "a&b"}
        text = safe_json_dumps(payload)
        self.assertNotIn("<script>", text)
        self.assertNotIn("&", text)
        self.assertIn("\\u003cscript\\u003e", text)
        # It must still be valid JSON.
        self.assertEqual(json.loads(text)["amp"], "a&b")

    def test_atomic_write_and_load(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "nested", "data.json")
            value = {"a": [1, 2, 3], "b": "ñ"}
            atomic_write_json(path, value)
            self.assertEqual(load_json(path), value)

    def test_load_json_defaults_on_bad_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            self.assertEqual(load_json(path, default={"ok": True}), {"ok": True})


class TimeTests(unittest.TestCase):
    def test_epoch_passthrough(self):
        self.assertEqual(parse_time_arg("1700000000"), 1700000000.0)

    def test_iso_and_naive_utc(self):
        self.assertEqual(parse_time_arg("2026-01-31T12:00:00Z"), 1769860800.0)
        self.assertEqual(parse_time_arg("2026-01-31 12:00:00"), 1769860800.0)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            parse_time_arg("not-a-date")

    def test_iso_utc_roundtrip(self):
        self.assertEqual(iso_utc(0), "1970-01-01T00:00:00+00:00")


class MathTextTests(unittest.TestCase):
    def test_entropy(self):
        self.assertAlmostEqual(entropy("aaaa"), 0.0)
        self.assertAlmostEqual(entropy("ab"), 1.0)

    def test_coefficient_of_variation(self):
        self.assertEqual(coefficient_of_variation([5, 5, 5]), 0.0)
        self.assertEqual(coefficient_of_variation([]), float("inf"))

    def test_split_csv_arg(self):
        self.assertEqual(split_csv_arg("a, b ,,c"), ["a", "b", "c"])
        self.assertEqual(split_csv_arg(None), [])


if __name__ == "__main__":
    unittest.main()
