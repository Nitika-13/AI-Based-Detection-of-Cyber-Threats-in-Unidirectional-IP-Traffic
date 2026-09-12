"""Feature computation from reconstructed flows (PCAP-only values)."""

from __future__ import annotations

import math
from typing import List

from .config import MIN_DURATION_FOR_RATES
from .models import ExtractedFlow, PacketRecord

# TCP flag letters counted per flow.
_FLAG_NAMES = ("S", "F", "R", "P", "A", "U")


def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _pstdev(values: List[float]) -> float:
    """Population standard deviation (ddof=0)."""
    if not values:
        return 0.0
    mu = _mean(values)
    return math.sqrt(sum((v - mu) ** 2 for v in values) / len(values))


def compute_flow_features(
    flow_id: str,
    run_id: str,
    scenario: str,
    packets: List[PacketRecord],
) -> ExtractedFlow:
    """Compute all features for one flow from its packets only.

    Every value is derived from the PCAP packet records; ground-truth CSV
    values are never used here.
    """
    first = packets[0]
    start_ts = packets[0].timestamp
    end_ts = packets[-1].timestamp
    duration = end_ts - start_ts

    packet_count = len(packets)
    byte_count = sum(p.ip_len for p in packets)

    denom = max(duration, MIN_DURATION_FOR_RATES)
    packets_per_second = packet_count / denom
    bytes_per_second = byte_count / denom

    sizes = [p.ip_len for p in packets]
    min_size = min(sizes)
    max_size = max(sizes)
    mean_size = _mean([float(s) for s in sizes])
    std_size = _pstdev([float(s) for s in sizes])

    iats = [
        b.timestamp - a.timestamp for a, b in zip(packets, packets[1:])
    ]
    iat_mean = _mean(iats)
    iat_std = _pstdev(iats)
    iat_min = min(iats) if iats else 0.0
    iat_max = max(iats) if iats else 0.0
    iat_count = len(iats)

    # TCP flag summary (empty string + zero counts for non-TCP).
    tcp_flags = ""
    flag_counts = {f: 0 for f in _FLAG_NAMES}
    if first.protocol == "tcp":
        seen = set()
        for p in packets:
            if p.tcp_flags:
                seen.update(p.tcp_flags)
                for f in p.tcp_flags:
                    if f in flag_counts:
                        flag_counts[f] += 1
        tcp_flags = ",".join(sorted(seen))

    return ExtractedFlow(
        flow_id=flow_id,
        run_id=run_id,
        scenario=scenario,
        flow_key=first.flow_key,
        src_ip=first.src_ip,
        src_port=first.src_port,
        dst_ip=first.dst_ip,
        dst_port=first.dst_port,
        protocol=first.protocol,
        start_ts=round(start_ts, 6),
        end_ts=round(end_ts, 6),
        duration=round(duration, 6),
        packet_count=packet_count,
        byte_count=byte_count,
        packets_per_second=round(packets_per_second, 6),
        bytes_per_second=round(bytes_per_second, 6),
        min_packet_size=min_size,
        max_packet_size=max_size,
        mean_packet_size=round(mean_size, 6),
        std_packet_size=round(std_size, 6),
        iat_mean=round(iat_mean, 6),
        iat_std=round(iat_std, 6),
        iat_min=round(iat_min, 6),
        iat_max=round(iat_max, 6),
        iat_count=iat_count,
        tcp_flags=tcp_flags,
        tcp_syn_count=flag_counts["S"],
        tcp_fin_count=flag_counts["F"],
        tcp_rst_count=flag_counts["R"],
        tcp_psh_count=flag_counts["P"],
        tcp_ack_count=flag_counts["A"],
        tcp_urg_count=flag_counts["U"],
    )


def assign_flow_ids(
    flows: List[ExtractedFlow], run_id: str
) -> List[ExtractedFlow]:
    """Assign deterministic flow_ids: sorted by (start_ts, flow_key)."""
    ordered = sorted(flows, key=lambda f: (f.start_ts, f.flow_key))
    for seq, flow in enumerate(ordered):
        flow.flow_id = f"{run_id}__{seq:04d}"
    return ordered