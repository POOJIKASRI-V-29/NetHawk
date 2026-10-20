"""Builder for NetHawk's bundled sample capture file.

The packets are CRAFTED IN MEMORY and written straight to a .pcap file.
Nothing is ever transmitted: this module opens no socket and needs no
privileges.  The frames are synthetic but well-formed Ethernet/IP/TCP/UDP
packets, so replaying the file exercises Scapy's genuine dissection path.

Contents of the sample capture:
  * two benign HTTPS conversations (handshake, data both ways, teardown)
  * benign DNS query/response pairs
  * a SYN scan across 18 ports
  * a 900-packet SYN flood against one port
"""
from __future__ import annotations

import random
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, TCP, UDP, Raw, wrpcap

from .. import config

CLIENT_MAC = "aa:bb:cc:00:11:22"
ROUTER_MAC = "aa:bb:cc:99:88:77"
GATEWAY = "192.168.1.1"


def benign_web_flow(client: str, server: str, sport: int, start: float,
                    packets: int = 24) -> list:
    """A normal-looking HTTPS conversation: handshake, data both ways, teardown."""
    out = []
    t = start
    base = Ether(src=CLIENT_MAC, dst=ROUTER_MAC)
    out.append(_stamp(base / IP(src=client, dst=server) /
                      TCP(sport=sport, dport=443, flags="S", window=64240), t))
    t += 0.012
    out.append(_stamp(Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / IP(src=server, dst=client) /
                      TCP(sport=443, dport=sport, flags="SA", window=65535), t))
    t += 0.001
    out.append(_stamp(base / IP(src=client, dst=server) /
                      TCP(sport=sport, dport=443, flags="A", window=64240), t))
    for i in range(packets):
        t += random.uniform(0.004, 0.05)
        if i % 3 == 0:
            out.append(_stamp(base / IP(src=client, dst=server) /
                              TCP(sport=sport, dport=443, flags="PA", window=64240) /
                              Raw(b"\x17\x03\x03" + bytes(random.randint(0, 255)
                                                          for _ in range(220))), t))
        else:
            out.append(_stamp(Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                              IP(src=server, dst=client) /
                              TCP(sport=443, dport=sport, flags="PA", window=65535) /
                              Raw(b"\x17\x03\x03" + bytes(random.randint(0, 255)
                                                          for _ in range(900))), t))
    t += 0.02
    out.append(_stamp(base / IP(src=client, dst=server) /
                      TCP(sport=sport, dport=443, flags="FA", window=64240), t))
    return out


def benign_dns(client: str, start: float, queries: int = 4) -> list:
    out, t = [], start
    for i in range(queries):
        out.append(_stamp(Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                          IP(src=client, dst=GATEWAY) /
                          UDP(sport=40000 + i, dport=53) /
                          DNS(rd=1, qd=DNSQR(qname=f"host{i}.example.com")), t))
        t += 0.03
        out.append(_stamp(Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                          IP(src=GATEWAY, dst=client) /
                          UDP(sport=53, dport=40000 + i) /
                          DNS(qr=1, qd=DNSQR(qname=f"host{i}.example.com")), t))
        t += 0.4
    return out


def port_scan(attacker: str, target: str, start: float, ports: list[int]) -> list:
    """SYN probes to many ports: one or two packets per flow, microsecond gaps."""
    out, t = [], start
    for i, port in enumerate(ports):
        out.append(_stamp(Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                          IP(src=attacker, dst=target) /
                          TCP(sport=50000 + i, dport=port, flags="S", window=1024), t))
        t += 0.0004
        if port in (80, 443, 22):
            out.append(_stamp(Ether(src=ROUTER_MAC, dst=CLIENT_MAC) /
                              IP(src=target, dst=attacker) /
                              TCP(sport=port, dport=50000 + i, flags="RA", window=0), t))
            t += 0.0003
    return out


def syn_flood(attacker: str, target: str, start: float, count: int = 900) -> list:
    """A high-rate one-to-one flood against a single port."""
    out, t = [], start
    for i in range(count):
        out.append(_stamp(Ether(src=CLIENT_MAC, dst=ROUTER_MAC) /
                          IP(src=attacker, dst=target) /
                          TCP(sport=1024 + (i % 60000), dport=80, flags="S", window=229) /
                          Raw(bytes(random.randint(0, 255) for _ in range(60))), t))
        t += 0.00035
    return out


def _stamp(packet, when: float):
    packet.time = when
    return packet


def build(seed: int = 7) -> list:
    random.seed(seed)
    t0 = 1_700_000_000.0
    packets = []
    packets += benign_web_flow("192.168.1.42", "93.184.216.34", 51514, t0, 26)
    packets += benign_dns("192.168.1.42", t0 + 2.0)
    packets += benign_web_flow("192.168.1.57", "140.82.112.3", 52880, t0 + 4.0, 18)
    packets += port_scan("192.168.1.188", "192.168.1.10", t0 + 8.0,
                         [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                          1433, 3306, 3389, 5900, 8080, 8443])
    packets += syn_flood("192.168.1.188", "192.168.1.10", t0 + 12.0, 900)
    packets.sort(key=lambda p: p.time)
    return packets




def write_sample_pcap(path: Path | str | None = None, seed: int = 7) -> tuple[Path, int]:
    """Build the sample capture and write it to disk. Returns (path, packets)."""
    path = Path(path) if path else config.SAMPLE_PCAP_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    packets = build(seed)
    wrpcap(str(path), packets)
    return path, len(packets)
