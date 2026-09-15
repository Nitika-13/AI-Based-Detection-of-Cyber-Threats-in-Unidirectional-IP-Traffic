"""Feature computation from reconstructed flows (PCAP-only values)."""

from __future__ import annotations

import math
from typing import List

from .config import MIN_DURATION_FOR_RATES
from .models import ExtractedFlow, PacketRecord
from .payload_features import (
    mode_smallest,
    parse_dns_payload,
    parse_tls_record,
    shannon_entropy,
)

# TCP flag letters counted per flow.
_FLAG_NAMES = ("S", "F", "R", "P", "A", "U")

# Destination ports identifying DNS and TLS-like traffic (Block 1).
DNS_DST_PORT = 53
TLS_DST_PORT = 443


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
    direction: str = "unknown",
) -> ExtractedFlow:
    """Compute all features for one flow from its packets only.

    Every value is derived from the PCAP packet records; ground-truth CSV
    values are never used here. ``direction`` is the only exception and it is
    traceability metadata, not a model input.
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
    flag_diversity = 0
    syn_ratio = 0.0
    if first.protocol == "tcp":
        seen = set()
        for p in packets:
            if p.tcp_flags:
                seen.update(p.tcp_flags)
                for f in p.tcp_flags:
                    if f in flag_counts:
                        flag_counts[f] += 1
        tcp_flags = ",".join(sorted(seen))
        flag_diversity = len(seen)
        syn_ratio = flag_counts["S"] / packet_count if packet_count else 0.0

    # Inter-arrival regularity: the C2 beaconing signature. A coefficient of
    # variation near 0 means machine-like periodicity.
    iat_cv = (iat_std / iat_mean) if iat_mean > 0 else 0.0

    # Payload content metadata (raw bytes only; nothing is ever decrypted).
    payload_bytes_total = sum(len(p.payload) for p in packets)
    payload_ratio = payload_bytes_total / byte_count if byte_count else 0.0
    payload_entropies = [
        shannon_entropy(p.payload) for p in packets if p.payload
    ]
    payload_entropy_mean = _mean(payload_entropies)
    payload_entropy_max = max(payload_entropies) if payload_entropies else 0.0

    # DNS metadata: parsed from UDP dst-port-53 payloads only.
    dns_lens: List[int] = []
    dns_entropies: List[float] = []
    dns_qtypes: List[int] = []
    if first.protocol == "udp" and first.dst_port == DNS_DST_PORT:
        for p in packets:
            parsed = parse_dns_payload(p.payload)
            if parsed is not None:
                dns_lens.append(parsed.qname_len)
                dns_entropies.append(parsed.qname_entropy)
                dns_qtypes.append(parsed.qtype)
    dns_packet_count = len(dns_lens)

    # TLS record metadata: parsed from TCP dst-port-443 payloads only.
    # NOTE: synthetic record headers only — no ClientHello, SNI, JA3/JA4.
    tls_versions: List[int] = []
    tls_ctypes: List[int] = []
    tls_lens: List[int] = []
    tls_entropies: List[float] = []
    if first.protocol == "tcp" and first.dst_port == TLS_DST_PORT:
        for p in packets:
            if not p.payload:
                continue
            parsed_tls = parse_tls_record(p.payload)
            if parsed_tls is not None:
                tls_versions.append(parsed_tls.version)
                tls_ctypes.append(parsed_tls.content_type)
                tls_lens.append(parsed_tls.declared_len)
                tls_entropies.append(parsed_tls.inner_entropy)
    tls_record_count = len(tls_versions)

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
        dns_packet_count=dns_packet_count,
        dns_qname_len_mean=round(_mean([float(v) for v in dns_lens]), 6),
        dns_qname_len_max=max(dns_lens) if dns_lens else 0,
        dns_qname_entropy_mean=round(_mean(dns_entropies), 6),
        dns_qname_entropy_max=round(max(dns_entropies), 6) if dns_entropies else 0.0,
        dns_qtype_mode=mode_smallest(dns_qtypes),
        tls_record_count=tls_record_count,
        tls_version_mode=mode_smallest(tls_versions),
        tls_content_type_mode=mode_smallest(tls_ctypes),
        tls_record_len_mean=round(_mean([float(v) for v in tls_lens]), 6),
        tls_record_len_max=max(tls_lens) if tls_lens else 0,
        tls_payload_entropy_mean=round(_mean(tls_entropies), 6),
        iat_cv=round(iat_cv, 6),
        tcp_syn_ratio=round(syn_ratio, 6),
        tcp_flag_diversity=flag_diversity,
        payload_bytes_total=payload_bytes_total,
        payload_ratio=round(payload_ratio, 6),
        payload_entropy_mean=round(payload_entropy_mean, 6),
        payload_entropy_max=round(payload_entropy_max, 6),
        direction=direction,
    )


def assign_flow_ids(
    flows: List[ExtractedFlow], run_id: str, scenario: str
) -> List[ExtractedFlow]:
    """Assign deterministic, globally-unique flow_ids.

    Format: ``{scenario}__{run_id}__{seq:04d}`` sorted by (start_ts, flow_key).
    Scoping by scenario makes flow_ids globally unique even when multiple
    manifest entries reuse the same run_id (e.g. all Block 1 runs use
    run_id="run_001").
    """
    ordered = sorted(flows, key=lambda f: (f.start_ts, f.flow_key))
    for seq, flow in enumerate(ordered):
        flow.flow_id = f"{scenario}__{run_id}__{seq:04d}"
    return ordered
