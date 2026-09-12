"""Scapy-based PCAP reader. Read-only; never touches a live interface."""

from __future__ import annotations

from pathlib import Path
from typing import List

from .models import PacketRecord

# Scapy 2.7.0 on Python 3.14 does not auto-register linktype 1 (Ethernet)
# and requires the inet layer to be imported for IP/TCP/UDP dissection.
# Block 1's validate script uses the same workaround.
from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP  # noqa: F401  (import enables dissection)
from scapy.layers.l2 import Ether

conf.l2types.register(1, Ether)


def _flag_str(flags) -> str:
    """Convert a Scapy TCP flags value to its string form (e.g. 'PA')."""
    if flags is None:
        return ""
    try:
        return str(flags)
    except Exception:
        return ""


def read_pcap(path: Path) -> List[PacketRecord]:
    """Read a PCAP file and return PacketRecords sorted by timestamp.

    Read-only: uses rdpcap (no packet transmission, no live capture).
    """
    from scapy.utils import rdpcap

    packets = rdpcap(str(path))
    records: List[PacketRecord] = []

    for pkt in packets:
        if "IP" not in pkt:
            continue
        ip = pkt["IP"]

        if "TCP" in pkt:
            protocol = "tcp"
            sport, dport = int(pkt["TCP"].sport), int(pkt["TCP"].dport)
            tcp_flags = _flag_str(pkt["TCP"].flags)
            payload = bytes(pkt["TCP"].payload)
        elif "UDP" in pkt:
            protocol = "udp"
            sport, dport = int(pkt["UDP"].sport), int(pkt["UDP"].dport)
            tcp_flags = None
            payload = bytes(pkt["UDP"].payload)
        else:
            # ICMP (Block 1 convention: ports 0).
            protocol = "icmp"
            sport, dport = 0, 0
            tcp_flags = None
            payload = bytes(pkt["ICMP"].payload) if "ICMP" in pkt else b""

        records.append(
            PacketRecord(
                src_ip=str(ip.src),
                src_port=sport,
                dst_ip=str(ip.dst),
                dst_port=dport,
                protocol=protocol,
                timestamp=float(pkt.time),
                ip_len=int(ip.len),
                tcp_flags=tcp_flags,
                payload=payload,
            )
        )

    records.sort(key=lambda r: r.timestamp)
    return records