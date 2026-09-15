"""Flow reconstruction: 5-tuple grouping + boundary rules.

Thin orchestration over :class:`feature_extractor.flow_manager.FlowManager`,
which owns the actual rules. Keeping the rules in one place guarantees that
PCAP sequential processing, PCAP replay and any future live source produce
flows with identical semantics.

Rules (see ``flow_manager.py`` for the full rationale):

1. group by direction-sensitive 5-tuple ``(src_ip, src_port, dst_ip,
   dst_port, protocol)``;
2. idle timeout: an inter-packet gap over ``idle_timeout`` closes the flow;
3. active timeout: a flow longer than ``active_timeout`` is closed;
4. TCP FIN/RST closes the flow (a later packet with the same 5-tuple starts a
   new one).

Note on rule 4: an earlier version of this module deliberately did NOT split
on FIN/RST. That was a workaround for a Block 1 generator bug (``c2_beacon``
emitting repeated FIN-terminated connections inside one ground-truth flow).
The generator has been fixed, so the natural rule is restored and the
workaround is gone.
"""

from __future__ import annotations

from typing import List

from .flow_manager import FlowManager
from .models import PacketRecord


def reconstruct_flows(
    packets: List[PacketRecord],
    idle_timeout: float,
    active_timeout: float,
) -> List[List[PacketRecord]]:
    """Reconstruct all unidirectional flows from a packet list.

    Returns flows ordered deterministically by ``(first packet timestamp,
    flow key)``. Each flow is a timestamp-ordered list of PacketRecords
    sharing one 5-tuple.
    """
    manager = FlowManager(
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        close_on_fin_rst=True,
    )
    closed: List[List[PacketRecord]] = []
    for pkt in packets:
        closed.extend(manager.add(pkt))
    closed.extend(manager.flush())
    closed.sort(key=lambda flow: (flow[0].timestamp, flow[0].flow_key))
    return closed


def segment_flow(
    packets: List[PacketRecord],
    idle_timeout: float,
    active_timeout: float,
) -> List[List[PacketRecord]]:
    """Segment one already-grouped 5-tuple series into flows.

    Kept for backward compatibility with earlier tests/callers. ``packets``
    must share a single flow key and be sorted by timestamp.
    """
    if not packets:
        return []
    return reconstruct_flows(packets, idle_timeout, active_timeout)
