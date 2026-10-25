# -*- coding: utf-8 -*-
"""Small, dependency-free helpers used across SNItch."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sys
import tempfile
import webbrowser
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

class Logger:
    """Tiny logger: timestamps, levels and optional colours.

    ``quiet`` only prints warnings/errors; ``verbose`` adds debug messages.
    Colours are disabled when stdout is not a TTY or NO_COLOR is set.
    """

    COLOURS = {
        "debug": "\033[90m",
        "info": "",
        "warn": "\033[33m",
        "error": "\033[31m",
        "ok": "\033[32m",
    }
    RESET = "\033[0m"

    def __init__(self, quiet: bool = False, verbose: bool = False) -> None:
        self.quiet = quiet
        self.verbose = verbose
        self.color = (
            sys.stdout.isatty()
            and os.environ.get("NO_COLOR") is None
            and os.environ.get("TERM") != "dumb"
        )

    def _emit(self, level: str, msg: str) -> None:
        colour = self.COLOURS.get(level, "") if self.color else ""
        reset = self.RESET if colour else ""
        stamp = f"{datetime.now():%H:%M:%S}"
        stream = sys.stderr if level == "error" else sys.stdout
        print(f"{colour}[{stamp}] {msg}{reset}", file=stream, flush=True)

    def debug(self, msg: str) -> None:
        if self.verbose and not self.quiet:
            self._emit("debug", msg)

    def info(self, msg: str) -> None:
        if not self.quiet:
            self._emit("info", msg)

    def ok(self, msg: str) -> None:
        if not self.quiet:
            self._emit("ok", msg)

    def warn(self, msg: str) -> None:
        self._emit("warn", msg)

    def error(self, msg: str) -> None:
        self._emit("error", msg)


# A default logger so library functions can be called without wiring one up.
_LOG = Logger()


def set_default_logger(logger: Logger) -> None:
    global _LOG
    _LOG = logger


def log(msg: str) -> None:
    _LOG.info(msg)


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------

def human_bytes(n: Optional[float]) -> str:
    """Return a compact binary-size string (e.g. ``1.4 MiB``)."""
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TiB"


def human_duration(seconds: Optional[float]) -> str:
    """Return ``1h 02m 03s``-style duration text."""
    if seconds is None:
        return "-"
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {sec:02d}s"
    return f"{minutes}m {sec:02d}s"


def fmt_time(epoch: Optional[float], with_date: bool = False) -> str:
    """Format an epoch timestamp in UTC (stable across machines/timezones)."""
    if epoch is None:
        return "-"
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


def iso_utc(epoch: Optional[float]) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# JSON / files
# --------------------------------------------------------------------------

def safe_json_dumps(obj: Any, indent: Optional[int] = None) -> str:
    """Serialize JSON so it can be embedded inside an HTML ``<script>`` tag.

    ``<``, ``>`` and ``&`` are escaped as unicode sequences, which prevents a
    malicious SNI/domain/capture name from terminating the script block.
    """
    text = json.dumps(obj, ensure_ascii=False, indent=indent, default=_json_default)
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _json_default(value: Any) -> Any:
    """Fallback for sets/counters and other non-JSON types."""
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    try:
        return dict(value)
    except (TypeError, ValueError):
        return str(value)


def atomic_write_json(path: str, obj: Any, indent: int = 2) -> None:
    """Write JSON atomically (temp file in the same folder + ``os.replace``)."""
    folder = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=indent, default=_json_default)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def load_json(path: str, default: Any = None) -> Any:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def safe_filename(name: str, fallback: str = "capture") -> str:
    """Make a capture basename safe for folders (keeps unicode letters)."""
    stem = os.path.splitext(os.path.basename(name))[0]
    stem = re.sub(r"[^\w.\- ]+", "_", stem, flags=re.UNICODE).strip(" ._")
    return stem[:80] or fallback


# --------------------------------------------------------------------------
# Paths (PyInstaller friendly)
# --------------------------------------------------------------------------

def base_output_dir() -> str:
    """Folder where results/caches are created.

    Next to the executable when frozen with PyInstaller, otherwise the current
    working directory. (The old version used the script folder, which made
    ``--out-dir`` behaviour surprising when running from another directory.)
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.getcwd()


def resource_path(name: str) -> str:
    """Path to a bundled resource, compatible with PyInstaller onefile mode."""
    candidates = []
    if getattr(sys, "_MEIPASS", None):
        candidates.append(os.path.join(sys._MEIPASS, name))
    here = os.path.dirname(os.path.abspath(__file__))
    candidates.extend([
        os.path.join(here, name),
        os.path.join(os.path.dirname(here), name),
        os.path.join(os.getcwd(), name),
    ])
    for path in candidates:
        if os.path.isfile(path):
            return path
    return candidates[0]


def open_in_browser(path: str) -> bool:
    try:
        return bool(webbrowser.open("file://" + os.path.abspath(path)))
    except Exception:
        return False


# --------------------------------------------------------------------------
# Math / text
# --------------------------------------------------------------------------

def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)
    return result


def median(values: Iterable[float]) -> float:
    vals = sorted(values)
    if not vals:
        return 0.0
    mid = len(vals) // 2
    if len(vals) % 2:
        return float(vals[mid])
    return (vals[mid - 1] + vals[mid]) / 2.0


def coefficient_of_variation(values: Iterable[float]) -> float:
    """Standard deviation / mean. Returns ``inf`` for an empty/zero-mean set."""
    vals = list(values)
    if not vals:
        return float("inf")
    mean = sum(vals) / len(vals)
    if mean == 0:
        return float("inf")
    variance = sum((v - mean) ** 2 for v in vals) / len(vals)
    return math.sqrt(variance) / mean


def percentage(part: float, whole: float) -> float:
    return (100.0 * part / whole) if whole else 0.0


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


# --------------------------------------------------------------------------
# Time parsing
# --------------------------------------------------------------------------

def parse_time_arg(value: Optional[str]) -> Optional[float]:
    """Parse an ISO-8601 timestamp, ``YYYY-mm-dd HH:MM[:SS]`` or epoch input.

    Naive datetimes are interpreted as UTC so results are reproducible.
    """
    if not value:
        return None
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        pass
    text = value.replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        raise ValueError(
            f"invalid date/time {value!r}: use ISO-8601 (2026-01-31T12:00:00) "
            "or a Unix epoch"
        )


def split_csv_arg(value: Optional[str]) -> list:
    """Split a comma-separated CLI value, trimming blanks."""
    if not value:
        return []
    return [part.strip() for part in str(value).split(",") if part.strip()]
