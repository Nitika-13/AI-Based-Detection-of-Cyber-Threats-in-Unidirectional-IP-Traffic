"""Scapy-based PCAP writer. Never transmits packets to a real interface."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from .models import PacketSpec

# Fixed synthetic MAC addresses (lab-only, never transmitted).
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def build_scapy_packet(spec: PacketSpec) -> Packet:
    """Build a single Scapy packet from a PacketSpec (Ethernet + IPv4)."""
    eth = Ether(src=SRC_MAC, dst=DST_MAC)
    ip = IP(src=spec.src_ip, dst=spec.dst_ip)

    if spec.protocol == "tcp":
        transport = TCP(
            sport=spec.src_port,
            dport=spec.dst_port,
            flags=spec.tcp_flags or "A",
            seq=spec.tcp_seq,
            ack=spec.tcp_ack,
        )
    elif spec.protocol == "udp":
        transport = UDP(sport=spec.src_port, dport=spec.dst_port)
    elif spec.protocol == "icmp":
        transport = ICMP(type=spec.icmp_type, code=spec.icmp_code)
    else:
        raise ValueError(f"Unsupported protocol: {spec.protocol}")

    pkt = eth / ip / transport / spec.payload
    pkt[IP].len = spec.ip_total_length
    # Set the packet timestamp for deterministic PCAP output.
    pkt.time = spec.timestamp
    return pkt


def write_pcap(path: str, packets: List[PacketSpec]) -> None:
    """Write a list of PacketSpecs to a PCAP file using Scapy."""
    from scapy.utils import wrpcap

    Path(path).parent.mkdir(parents=True, exist_ok=True)
    sorted_packets = sorted(packets, key=lambda p: p.timestamp)
    scapy_packets = [build_scapy_packet(p) for p in sorted_packets]
    wrpcap(path, scapy_packets)