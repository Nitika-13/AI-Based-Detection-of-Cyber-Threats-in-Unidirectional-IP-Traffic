"""Scapy-based PCAP reader. Read-only; never touches a live interface."""

from __future__ import annotations

from typing import Iterator, List

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


def _parse_packets(packets) -> List[PacketRecord]:
    """Convert Scapy packets into PacketRecords (read-only dissection)."""
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
    return records


def iter_pcap_records(path, sort_by_timestamp: bool = True) -> "Iterator[PacketRecord]":
    """Yield PacketRecords from a PCAP (read-only; no live capture).

    ``sort_by_timestamp`` keeps the invariant the flow manager relies on
    (packets arrive in non-decreasing timestamp order). It defaults to True
    because idle/active-timeout segmentation is only well defined for ordered
    input.
    """
    from scapy.utils import rdpcap

    records = _parse_packets(rdpcap(str(path)))
    if sort_by_timestamp:
        records.sort(key=lambda r: r.timestamp)
    yield from records


def read_pcap(path) -> List[PacketRecord]:
    """Read a PCAP and return PacketRecords sorted by timestamp.

    Kept for backward compatibility; the streaming sensor uses
    :func:`iter_pcap_records` instead.
    """
    return list(iter_pcap_records(path))