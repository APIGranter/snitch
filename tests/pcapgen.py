# -*- coding: utf-8 -*-
"""Build tiny Ethernet pcap files for end-to-end tests with a real tshark.

Only what the tests need: IPv4/IPv6, TCP (SYN, TLS ClientHello with SNI, plain
HTTP), UDP DNS queries/answers and ICMP errors.  Checksums are left at zero
where tshark does not validate them by default.
"""

import ipaddress
import struct
from typing import List, Tuple


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ethernet(src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> bytes:
    return _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
        ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed,
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    return struct.pack("!IHBB", 6 << 28, len(payload), next_header, 64) \
        + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload


def tcp(sport: int, dport: int, flags: str = "S", payload: bytes = b"",
        seq: int = 1000, ack: int = 0) -> bytes:
    bits = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}
    value = sum(bits[flag] for flag in flags)
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, value,
                       65535, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_unreachable(quoted_ip_packet: bytes) -> bytes:
    body = struct.pack("!BBHI", 3, 3, 0, 0) + quoted_ip_packet[:28]
    return body[:2] + struct.pack("!H", _checksum(body)) + body[4:]


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns_query(name: str, qtype: int = 1, ident: int = 1) -> bytes:
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _qname(name) \
        + struct.pack("!HH", qtype, 1)


def dns_answer(name: str, address: str, ident: int = 1) -> bytes:
    addr = ipaddress.ip_address(address)
    rtype = 1 if addr.version == 4 else 28
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + _qname(name) \
        + struct.pack("!HH", rtype, 1) \
        + struct.pack("!HHHIH", 0xC00C, rtype, 1, 60, len(addr.packed)) + addr.packed


def tls_client_hello(server_name: str) -> bytes:
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack("!HH", 0, len(sni)) + sni
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack("!HH", 2, 0x1301) + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def write_pcap(path: str, frames: List[Tuple[float, bytes]]) -> None:
    with open(path, "wb") as handle:
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in frames:
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("!IIII", seconds, micros, len(frame), len(frame)))
            handle.write(frame)
