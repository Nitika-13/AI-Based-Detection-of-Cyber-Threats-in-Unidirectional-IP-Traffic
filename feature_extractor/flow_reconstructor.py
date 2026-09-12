"""Flow reconstruction: 5-tuple grouping + approved boundary rules.

Boundary rules (approved, with one documented deviation):

1. Group by direction-sensitive 5-tuple (src_ip, src_port, dst_ip,
   dst_port, protocol).
2. Idle timeout: inter-packet gap > 15s starts a new flow.
3. Active timeout: flow duration > 30s closes the flow; the next packet
   starts a new flow.
4. TCP FIN/RST (deviation per user decision "Option 2"): FIN/RST marks the
   end of a TCP connection attempt, but a subsequent packet with the SAME
   5-tuple re-joins the same unidirectional flow rather than starting a new
   one. Rationale: Block 1 (frozen) guarantees exactly one ground-truth
   flow per 5-tuple per run, and its c2_beacon scenario emits repeated
   beacon connections (each ending in FIN+ACK) within a single GT flow.
   Re-joining keeps extraction 1:1 with Block 1 ground truth. FIN/RST is
   still fully captured as a feature (tcp_fin_count / tcp_rst_count).
"""

from __future__ import annotations

from typing import Dict, List

from .models import PacketRecord

# TCP flags that mark a connection end (feature-only; do not split flows).
FLOW_CLOSING_FLAGS = ("F", "R")  # FIN, RST


def group_by_flow_key(packets: List[PacketRecord]) -> Dict[str, List[PacketRecord]]:
    """Group packets by direction-sensitive unidirectional 5-tuple."""
    groups: Dict[str, List[PacketRecord]] = {}
    for pkt in packets:
        groups.setdefault(pkt.flow_key, []).append(pkt)
    return groups


def segment_flow(
    packets: List[PacketRecord],
    idle_timeout: float,
    active_timeout: float,
) -> List[List[PacketRecord]]:
    """Segment one 5-tuple group into flows using approved boundary rules.

    Rules applied per packet:
    1. Idle timeout: gap from previous packet > idle_timeout -> new flow.
    2. Active timeout: current flow duration would exceed active_timeout
       -> close current flow, start new one at this packet.
    3. FIN/RST: NOT a split trigger (documented deviation, see module
       docstring); connection-end flags are preserved as features.

    ``packets`` must already be sorted by timestamp.
    """
    if not packets:
        return []

    flows: List[List[PacketRecord]] = []
    current: List[PacketRecord] = [packets[0]]

    for prev, pkt in zip(packets, packets[1:]):
        gap = pkt.timestamp - prev.timestamp
        flow_duration = pkt.timestamp - current[0].timestamp

        if gap > idle_timeout or flow_duration > active_timeout:
            flows.append(current)
            current = [pkt]
        else:
            current.append(pkt)

    flows.append(current)
    return flows


def reconstruct_flows(
    packets: List[PacketRecord],
    idle_timeout: float,
    active_timeout: float,
) -> List[List[PacketRecord]]:
    """Reconstruct all unidirectional flows from a packet list.

    Returns a list of flows; each flow is a timestamp-sorted list of
    PacketRecords sharing one 5-tuple.
    """
    groups = group_by_flow_key(packets)
    flows: List[List[PacketRecord]] = []
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda p: p.timestamp)
        flows.extend(segment_flow(group, idle_timeout, active_timeout))
    return flows