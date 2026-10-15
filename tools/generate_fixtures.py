#!/usr/bin/env python3
"""Generate synthetic Ethernet PCAPs. Never captures or sends network traffic.

dpkt constructs bytes and checksums independently of the C++ decoder. Classic
PCAP framing is explicit so endian/resolution and corruption are reproducible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from ipaddress import ip_address
import dpkt

EPOCH = 1_767_225_600  # 2026-01-01T00:00:00Z


def frame(source, destination, protocol, transport) -> bytes:
    """Explicit addresses avoid routing, interface lookup, and all socket access."""
    ipv6 = ":" in source
    src, dst = ip_address(source).packed, ip_address(destination).packed
    if ipv6:
        network = dpkt.ip6.IP6(src=src, dst=dst, nxt=protocol, hlim=64,
                              plen=len(transport), data=transport)
    else:
        network = dpkt.ip.IP(src=src, dst=dst, p=protocol, ttl=64, id=1,
                             len=20 + len(transport), data=transport)
    return bytes(dpkt.ethernet.Ethernet(
        src=bytes.fromhex("020000000001"), dst=bytes.fromhex("020000000002"),
        type=0x86dd if ipv6 else 0x0800, data=network))


def udp(sport, dport, payload=b""):
    payload = bytes(payload)
    return dpkt.udp.UDP(sport=sport, dport=dport, ulen=8 + len(payload), data=payload)


def tcp(sport, dport, flags, seq=100, ack=0, data=b""):
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack,
                        off=5, win=8192, data=data)


def dns(name="demo.test", identifier=1, response=False):
    message = dpkt.dns.DNS(id=identifier, qd=[dpkt.dns.DNS.Q(name=name, type=1)])
    if response:
        message.qr = 1
        message.ra = 1
        message.an = [dpkt.dns.DNS.RR(name=name, type=1, ttl=60,
                                     rdata=ip_address("198.51.100.7").packed)]
    return bytes(message)


def baseline() -> list[tuple[int, bytes]]:
    client, server, resolver = "192.0.2.10", "198.51.100.7", "192.0.2.53"
    request = b"GET /demo HTTP/1.0\r\nHost: demo.test\r\n\r\n"
    response = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    rows = [
        (0, frame(client, resolver, 17, udp(53000, 53, dns()))),
        (30_000, frame(resolver, client, 17, udp(53, 53000, dns(response=True)))),
        (100_000, frame(client, server, 6, tcp(50000, 80, 2))),
        (110_000, frame(server, client, 6, tcp(80, 50000, 18, 900, 101))),
        (120_000, frame(client, server, 6, tcp(50000, 80, 16, 101, 901))),
        (200_000, frame(client, server, 6, tcp(50000, 80, 24, 101, 901, request))),
        (230_000, frame(server, client, 6, tcp(80, 50000, 24, 901, 101 + len(request), response))),
        (300_000, frame(client, server, 6, tcp(50000, 80, 17, 101 + len(request), 901 + len(response)))),
        (400_000, frame("2001:db8::10", "2001:db8::20", 17, udp(60000, 9000, b"hello"))),
        (500_000, frame("2001:db8::20", "2001:db8::10", 17, udp(9000, 60000, b"reply"))),
        (600_000, frame(client, server, 1, dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"synthetic")))),
        (700_000, frame(server, client, 1, dpkt.icmp.ICMP(type=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"synthetic")))),
    ]
    return rows


def investigation() -> list[tuple[int, bytes]]:
    rows = baseline()
    for i in range(16):
        rows.append((2_000_000 + i * 60_000, frame("198.51.100.10", "192.0.2.20", 6, tcp(40000, 20 + i, 2, 1000 + i))))
    for i in range(7):
        rows.append((4_000_000 + i * 200_000, frame("198.51.100.11", "198.51.100.7", 6, tcp(41000, 443, 2, 555))))
    for i in range(140):
        rows.append((7_000_000 + i * 3_000, frame("203.0.113.99", "192.0.2.53", 17, udp(45000, 9999, bytes([i % 256]) * 128))))
    for i in range(30):
        rows.append((10_000_000 + i * 120_000, frame("192.0.2.10", "192.0.2.53", 17, udp(54000 + i, 53, dns(f"q{i}.demo.test", 100 + i)))))
    return rows


def encode(rows: list[tuple[int, bytes]], endian: str = "<", nano: bool = False) -> bytes:
    header = struct.pack(endian + "IHHIIII", 0xA1B23C4D if nano else 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    output = bytearray(header)
    for relative_us, packet in rows:
        sec, fraction = divmod(relative_us, 1_000_000)
        if nano:
            fraction = fraction * 1000 + 123  # exercise sub-microsecond preservation
        output += struct.pack(endian + "IIII", EPOCH + sec, fraction, len(packet), len(packet)) + packet
    return bytes(output)


def generate(output: Path) -> None:
    output.mkdir(parents=False, exist_ok=False)
    regular = baseline()
    cases = {
        "baseline.pcap": encode(regular),
        "investigation.pcap": encode(investigation()),
        "big-endian-nanoseconds.pcap": encode(regular, ">", True),
        "empty.pcap": encode([]),
        "damaged-tail.pcap": encode(regular) + b"short",
        "unsupported.pcapng": bytes.fromhex("0a0d0d0a") + bytes(24),
    }
    manifest = {"generator": "tools/generate_fixtures.py", "epoch_utc": "2026-01-01T00:00:00Z", "files": {}}
    for name, content in cases.items():
        (output / name).write_bytes(content)
        manifest["files"][name] = {"sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Generated {len(cases)} synthetic captures in {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory; parent must exist")
    generate(parser.parse_args().output)
