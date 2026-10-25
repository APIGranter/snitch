# -*- coding: utf-8 -*-
"""Thin, robust wrapper around tshark.

All packet information is collected in a **single** tshark invocation. The
previous version ran tshark once for IPs, once for SNI and once for DNS (plus
one pass per extra field); on large captures that is the dominant cost.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, Iterator, List, Optional

from .util import Logger


class TsharkError(RuntimeError):
    """Raised when tshark is missing, fails to read a capture or is interrupted."""


#: Fields requested from tshark. Keep the order in sync with ``_FIELD_NAMES``.
FIELDS: List[str] = [
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.stream",
    "tcp.analysis.retransmission",
    "udp.srcport",
    "udp.dstport",
    "udp.stream",
    "icmp.type",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.version",
    "tls.handshake.ja4",
    "dtls.handshake.extensions_server_name",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.aaaa",
    "dns.time",
    "http.host",
    "http.user_agent",
    "http.request.method",
    "http2.headers.authority",
    "quic.version",
]

_FIELD_NAMES = [f.replace(".", "_") for f in FIELDS]


def find_tshark(manual_path: Optional[str] = None) -> Optional[str]:
    """Locate tshark, trying common install locations and ``PATH``."""
    if manual_path:
        if os.path.isfile(manual_path) or shutil.which(manual_path):
            return manual_path
        return None
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "tshark",
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _run(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TsharkError(f"could not run {cmd[0]!r}: {exc}") from exc


def tshark_version(tshark: str) -> str:
    """Return the first line of ``tshark --version`` (or ``unknown``)."""
    try:
        proc = _run([tshark, "--version"], timeout=15)
    except TsharkError:
        return "unknown"
    lines = (proc.stdout or proc.stderr or "").strip().splitlines()
    return lines[0].strip() if lines else "unknown"


def list_interfaces(tshark: str) -> List[Dict[str, str]]:
    """Return tshark's interfaces as ``[{index, name, description}]``."""
    proc = _run([tshark, "-D"], timeout=20)
    if proc.returncode != 0:
        raise TsharkError((proc.stderr or "tshark -D failed").strip())
    interfaces = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        number, _, rest = line.partition(".")
        rest = rest.strip()
        # "1. eth0 (description)" or "1. eth0"
        name, _, desc = rest.partition(" (")
        interfaces.append({
            "index": number.strip(),
            "name": name.strip(),
            "description": desc.rstrip(")").strip(),
        })
    return interfaces


def validate_capture(path: str) -> None:
    if not path or not os.path.isfile(path):
        raise TsharkError(f"capture file not found: {path}")
    if not os.access(path, os.R_OK):
        raise TsharkError(f"capture file is not readable: {path}")
    if os.path.getsize(path) == 0:
        raise TsharkError(f"capture file is empty: {path}")


def build_display_filter(since: Optional[float] = None,
                         until: Optional[float] = None,
                         extra: Optional[str] = None) -> str:
    """Compose the tshark display filter (IPv4 + IPv6, optional time range)."""
    parts = ["(ip or ipv6)"]
    if since is not None:
        parts.append(f"(frame.time_epoch >= {since:.6f})")
    if until is not None:
        parts.append(f"(frame.time_epoch <= {until:.6f})")
    if extra:
        parts.append(f"({extra})")
    return " && ".join(parts)


def iter_packets(pcap: str, tshark: str, display_filter: str,
                 logger: Logger, progress_every: int = 10000) -> Iterator[Dict[str, str]]:
    """Yield one dict per packet with the fields from :data:`FIELDS`.

    stdout is streamed line by line, so memory use stays constant. tshark's
    stderr goes to a temporary file to avoid pipe-buffer deadlocks.
    """
    cmd = [tshark, "-n", "-r", pcap, "-Y", display_filter, "-T", "fields"]
    for field in FIELDS:
        cmd.extend(["-e", field])
    logger.debug("tshark: " + " ".join(cmd))

    err_file = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    try:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=err_file, text=True,
                encoding="utf-8", errors="replace", bufsize=1 << 20,
            )
        except OSError as exc:
            raise TsharkError(f"could not start tshark: {exc}") from exc

        assert proc.stdout is not None
        count = 0
        try:
            for line in proc.stdout:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                values = line.split("\t")
                if len(values) < len(FIELDS):
                    values.extend([""] * (len(FIELDS) - len(values)))
                count += 1
                if progress_every and count % progress_every == 0:
                    logger.info(f"  ... {count:,} packets read")
                yield dict(zip(_FIELD_NAMES, values[:len(FIELDS)]))
        except KeyboardInterrupt:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            raise
        finally:
            proc.stdout.close()
            returncode = proc.wait()

        if returncode != 0:
            err_file.seek(0)
            error = err_file.read().strip()
            raise TsharkError(
                f"tshark exited with code {returncode}"
                + (f": {error[-1500:]}" if error else "")
            )
        err_file.seek(0)
        warnings = err_file.read().strip()
        if warnings:
            logger.debug("tshark stderr: " + warnings[-1500:])
        logger.debug(f"tshark read {count:,} packets")
    finally:
        err_file.close()


def live_capture(tshark: str, interface: str, duration: Optional[int],
                 packet_limit: Optional[int], out_path: str,
                 logger: Logger) -> str:
    """Capture live traffic with tshark into ``out_path`` and return the path.

    The capture is stopped by ``duration`` seconds, ``packet_limit`` packets,
    or Ctrl+C. A partial capture is kept if it contains packets.
    """
    cmd = [tshark, "-n", "-q", "-i", interface, "-w", out_path]
    if duration:
        cmd.extend(["-a", f"duration:{int(duration)}"])
    if packet_limit:
        cmd.extend(["-c", str(int(packet_limit))])
    logger.info(f"Live capture on {interface!r} (Ctrl+C to stop) ...")
    logger.debug("tshark: " + " ".join(cmd))
    proc = subprocess.Popen(cmd)
    try:
        proc.wait()
    except KeyboardInterrupt:
        logger.info("Stopping capture ...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
        raise TsharkError(
            "live capture produced no data (check the interface name and "
            "capture permissions; see --list-interfaces)"
        )
    return out_path


def default_live_path(prefix: str = "snitch-live") -> str:
    """Create a private temporary file path for a live capture."""
    fd, path = tempfile.mkstemp(prefix=prefix + "-", suffix=".pcapng")
    os.close(fd)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def resolve_interface(tshark: str, requested: str) -> str:
    """Accept an interface name or the index shown by ``tshark -D``."""
    interfaces = list_interfaces(tshark)
    for item in interfaces:
        if requested == item["index"] or requested == item["name"]:
            return item["name"]
    names = ", ".join(f"{i['index']}:{i['name']}" for i in interfaces)
    raise TsharkError(
        f"unknown interface {requested!r}. Available: {names or 'none'}"
    )


def platform_note() -> str:
    if sys.platform.startswith("win"):
        return "On Windows, install Wireshark with Npcap and run the terminal as Administrator for live capture."
    if sys.platform == "darwin":
        return "On macOS, live capture may require sudo or BPF permissions."
    return "On Linux, live capture requires root or membership in the wireshark group."
