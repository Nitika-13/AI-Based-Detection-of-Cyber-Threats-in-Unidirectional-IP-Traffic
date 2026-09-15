"""Windowed per-host aggregates: the cross-flow canonical table.

Several threat characteristics cannot be a property of a single unidirectional
flow, because a flow by definition has exactly one destination port and one
peer address:

* **destination-port fan-out** (port scanning) - one flow per probed port, so
  the fan-out lives across flows;
* **destination-host fan-out** (host sweeping) - same;
* **source diversity** (DDoS) - the victim is one host contacted by many
  sources;
* **destination repetition** (C2 beaconing) - many flows to the same server.

These are properties of a HOST observed over a TIME WINDOW, so Block 2 emits
them as a separate canonical table (``host_windows.csv``) rather than forcing
them into the per-flow feature matrix. The columns are documented in
``feature_schema.py`` under ``host_window``.

Everything here is computed from flows that were themselves derived from
packets. No ground-truth value is used.

Streaming note: a *tumbling* window is used (fixed-size, non-overlapping,
aligned to the capture start) because it only needs the flows that have already
been emitted by the flow manager. A sliding window would need to buffer flows,
which does not fit a streaming sensor.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List

from .feature_schema import HOST_WINDOW_TABLE, table_columns
from .models import ExtractedFlow
from .payload_features import shannon_entropy

# Columns of host_windows.csv, in written order.
HOST_WINDOW_COLUMNS: List[str] = (
    table_columns(HOST_WINDOW_TABLE, "metadata")
    + table_columns(HOST_WINDOW_TABLE, "ml_feature")
)

_ROLE_SRC = "src"
_ROLE_DST = "dst"


def _entropy(values: List[str]) -> float:
    """Shannon entropy (bits) of a distribution of hashable labels."""
    if not values:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for value in values:
        counts[value] += 1
    total = float(len(values))
    return -sum(
        (c / total) * math.log2(c / total) for c in counts.values() if c
    )


def _is_probe_like(flow: ExtractedFlow) -> bool:
    """True when a TCP flow looks like a bare probe (SYN only, no teardown)."""
    if flow.protocol != "tcp":
        return False
    return flow.packet_count > 0 and flow.tcp_syn_count == flow.packet_count


def compute_host_windows(
    flows: List[ExtractedFlow],
    run_id: str,
    scenario: str,
    window_seconds: float,
) -> List[Dict]:
    """Aggregate flows into per-(window, host, role) rows.

    ``window_seconds`` is the tumbling window length. Rows are returned sorted
    by ``(window_index, role, ip)`` for deterministic output.
    """
    if window_seconds <= 0:
        raise ValueError(
            f"window_seconds must be positive, got {window_seconds}"
        )
    if not flows:
        return []

    capture_start = min(flow.start_ts for flow in flows)
    buckets: Dict[tuple, List[ExtractedFlow]] = defaultdict(list)

    for flow in flows:
        index = int((flow.start_ts - capture_start) // window_seconds)
        buckets[(index, _ROLE_SRC, flow.src_ip)].append(flow)
        buckets[(index, _ROLE_DST, flow.dst_ip)].append(flow)

    rows: List[Dict] = []
    for (index, role, ip) in sorted(buckets):
        group = buckets[(index, role, ip)]
        if role == _ROLE_SRC:
            peers_ip = [f.dst_ip for f in group]
            peers_port = [str(f.dst_port) for f in group]
        else:
            peers_ip = [f.src_ip for f in group]
            peers_port = [str(f.src_port) for f in group]

        packet_total = sum(f.packet_count for f in group)
        byte_total = sum(f.byte_count for f in group)
        syn_flows = sum(1 for f in group if _is_probe_like(f))

        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "window_index": index,
                "window_start_ts": round(capture_start + index * window_seconds, 6),
                "window_end_ts": round(capture_start + (index + 1) * window_seconds, 6),
                "ip": ip,
                "role": role,
                "flow_count": len(group),
                "packet_count": packet_total,
                "byte_count": byte_total,
                "unique_peer_ip_count": len(set(peers_ip)),
                "unique_peer_port_count": len(set(peers_port)),
                "peer_ip_entropy": round(_entropy(peers_ip), 6),
                "peer_port_entropy": round(_entropy(peers_port), 6),
                "syn_flow_count": syn_flows,
                "syn_flow_ratio": round(syn_flows / len(group), 6) if group else 0.0,
                "mean_flow_duration": round(
                    sum(f.duration for f in group) / len(group), 6
                ),
                "mean_packets_per_flow": round(packet_total / len(group), 6),
                "packet_rate_pps": round(packet_total / window_seconds, 6),
                "byte_rate_bps": round(byte_total / window_seconds, 6),
            }
        )
    return rows
