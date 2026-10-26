# -*- coding: utf-8 -*-
"""Best-effort discovery of the local IPv4 subnets (no dependencies).

Client selection defaults to the Windows-hotspot subnet for compatibility
with SNItch 1.x.  On other networks that filter matches nothing, so SNItch can
fall back to the subnets this machine is attached to before resorting to the
very broad ``--auto-clients`` mode.

Command output is parsed leniently for the three common platforms:

* Linux: ``ip -o -4 addr show`` (preferred) or ``ifconfig``
* macOS/BSD: ``ifconfig``
* Windows: ``ipconfig`` (any display language / OEM code page)

Anything unexpected is ignored; the result is only a hint, never a hard
failure.  Loopback, link-local and public addresses are discarded.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import subprocess
import sys
from typing import Iterable, List

IPv4Network = ipaddress.IPv4Network

_INET_RE = re.compile(r"\binet(?:6)?\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)(?:/(\d+))?")
_MASK_RE = re.compile(r"\b(?:netmask|Mask)\s*:?\s*(\d+\.\d+\.\d+\.\d+|0x[0-9a-fA-F]+)")
#: ``<label> . . . : a.b.c.d`` lines; the value may carry "(Preferred)" etc.
_IPCONFIG_VALUE_RE = re.compile(r"^(?P<label>[^:]*):\s*(?P<ip>\d+\.\d+\.\d+\.\d+)")


def _is_usable(network: IPv4Network) -> bool:
    """True for private unicast subnets that can identify local clients."""
    if network.prefixlen >= 31 or network.is_loopback or network.is_link_local:
        return False
    if network.is_multicast or network.is_unspecified:
        return False
    return network.is_private


def _mask_to_prefix(mask: str) -> int:
    try:
        if mask.lower().startswith("0x"):
            value = int(mask, 16)
            return bin(value).count("1")
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 0


def parse_ip_addr(text: str) -> List[IPv4Network]:
    """Parse Linux ``ip -o -4 addr show`` output."""
    networks = set()
    for match in _INET_RE.finditer(text or ""):
        address, prefix = match.group(1), match.group(2)
        try:
            if prefix is not None:
                network = ipaddress.IPv4Network(f"{address}/{prefix}", strict=False)
            else:
                network = ipaddress.IPv4Network(f"{address}/24", strict=False)
        except ValueError:
            continue
        networks.add(network)
    return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))


def parse_ifconfig(text: str) -> List[IPv4Network]:
    """Parse macOS/BSD/Linux ``ifconfig`` output."""
    networks = set()
    for line in (text or "").splitlines():
        match = _INET_RE.search(line)
        if not match:
            continue
        address = match.group(1)
        prefix = int(match.group(2)) if match.group(2) else 0
        if not prefix:
            mask = _MASK_RE.search(line)
            prefix = _mask_to_prefix(mask.group(1)) if mask else 24
        try:
            networks.add(ipaddress.IPv4Network(f"{address}/{prefix}", strict=False))
        except ValueError:
            continue
    return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))


def _is_netmask(value: str) -> bool:
    """True for contiguous dotted masks such as 255.255.255.0."""
    if not value.startswith("255."):
        return False
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{value}")
    except ValueError:
        return False
    return True


def parse_ipconfig(text: str) -> List[IPv4Network]:
    """Parse Windows ``ipconfig`` output in any display language.

    Labels are localized ("Subnet Mask", "Máscara de subred", "Subnetzmaske"),
    so only "IPv4" (which every translation keeps) is matched; the mask is
    the next value that is a valid contiguous netmask.
    """
    networks = set()
    pending = ""
    for line in (text or "").splitlines():
        match = _IPCONFIG_VALUE_RE.match(line.strip())
        if not match:
            continue
        value = match.group("ip")
        if "ipv4" in match.group("label").lower():
            if pending:
                networks.add(ipaddress.IPv4Network(f"{pending}/24", strict=False))
            pending = value
        elif pending and _is_netmask(value):
            networks.add(ipaddress.IPv4Network(f"{pending}/{value}", strict=False))
            pending = ""
    if pending:
        networks.add(ipaddress.IPv4Network(f"{pending}/24", strict=False))
    return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))


def parse_output(platform: str, text: str) -> List[IPv4Network]:
    """Pick the right parser for a platform name (``sys.platform``)."""
    if platform.startswith("win"):
        return parse_ipconfig(text)
    if platform in ("darwin", "freebsd", "openbsd", "netbsd"):
        return parse_ifconfig(text)
    return parse_ip_addr(text) or parse_ifconfig(text)


def _console_encoding() -> str:
    """Encoding used by console tools such as ``ipconfig``.

    Windows tools write in the OEM code page (cp850 on Spanish systems), not
    UTF-8, even when Python itself runs in UTF-8 mode.
    """
    if sys.platform.startswith("win"):
        try:
            import ctypes
            return f"cp{ctypes.windll.kernel32.GetConsoleOutputCP() or ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:  # pragma: no cover - exotic Windows setups
            return "oem"
    return "utf-8"


def _run(command: List[str]) -> str:
    try:
        proc = subprocess.run(command, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode != 0:
        return ""
    return decode_output(proc.stdout, _console_encoding())


def decode_output(raw: bytes, encoding: str) -> str:
    """Decode command output without ever raising (labels may be lost)."""
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _socket_networks() -> List[IPv4Network]:
    addresses = set()
    try:
        _, _, resolved = socket.gethostbyname_ex(socket.gethostname())
        addresses.update(resolved)
    except OSError:
        pass
    # A UDP connect reveals the address of the default route without sending.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 9))  # TEST-NET-1, non-routable
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    networks = set()
    for address in addresses:
        try:
            networks.add(ipaddress.IPv4Network(f"{address}/24", strict=False))
        except ValueError:
            continue
    return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))


def local_ipv4_networks(platform: str = "", runner=None) -> List[IPv4Network]:
    """Return the machine's private IPv4 subnets, loopback excluded.

    The result may be empty when nothing can be discovered; callers must treat
    it as a hint and keep an explicit fallback.
    """
    import sys

    platform = platform or sys.platform
    command = ""
    if platform.startswith("win"):
        command = "ipconfig"
    elif shutil.which("ip") and platform.startswith("linux"):
        command = "ip -o -4 addr show"
    elif shutil.which("ifconfig"):
        command = "ifconfig -a"
    if command:
        text = (runner or _run)(command.split())
        networks = parse_output(platform, text)
    else:
        networks = []
    if not networks:
        networks = _socket_networks()
    return [network for network in _unique_networks(networks) if _is_usable(network)]


def _unique_networks(networks: Iterable[IPv4Network]) -> List[IPv4Network]:
    unique = set(networks)
    return sorted(unique, key=lambda n: (int(n.network_address), n.prefixlen))


def format_networks(networks: Iterable[IPv4Network]) -> str:
    return ", ".join(str(network) for network in networks)
