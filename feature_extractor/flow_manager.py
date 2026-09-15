"""Streaming flow manager: the single flow-reconstruction engine for Block 2.

This module owns the boundary rules. Every input mode (PCAP sequential, PCAP
replay, and any future live source) feeds packets into one instance of
:class:`FlowManager`, so flow reconstruction cannot diverge between training
and inference.

Boundary rules
--------------

1. **Direction-sensitive 5-tuple.** ``(src_ip, src_port, dst_ip, dst_port,
   protocol)``. Packets travelling the other way are a different flow. This is
   the correct notion of a flow for passively observed one-directional traffic
   and requires no active communication with either endpoint.

2. **Idle timeout.** If the gap from the previous packet exceeds
   ``idle_timeout`` seconds, the flow is closed and the packet starts a new one.

3. **Active timeout.** If the flow would grow longer than ``active_timeout``
   seconds, it is closed and the packet starts a new one.

4. **TCP FIN/RST closes the flow.** A FIN or RST is a genuine connection
   teardown, so the flow ends there. A later packet with the same 5-tuple is a
   NEW connection and starts a NEW flow.

   This rule was previously documented as a *deviation* ("FIN/RST does not
   split a flow"). That deviation existed only to compensate for a Block 1
   generator bug: the ``c2_beacon`` scenario emitted many independent
   SYN/PA/FIN connections that reused one 5-tuple inside a single ground-truth
   flow. The generator has been fixed to emit one long-lived connection per
   channel, so the workaround is gone and the natural rule is restored. See
   ``traffic_generator/scenarios/c2_beacon.py``.

No active communication
-----------------------
Flow reconstruction is purely bookkeeping over observed packets. It never
sends anything, never probes a source, and never tries to complete a handshake
to confirm a flow's direction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .models import PacketRecord

# TCP flags that mark a connection teardown.
FIN_FLAG = "F"
RST_FLAG = "R"


@dataclass
class _OpenFlow:
    """A flow that is still accepting packets."""

    packets: List[PacketRecord] = field(default_factory=list)

    @property
    def first_ts(self) -> float:
        return self.packets[0].timestamp

    @property
    def last_ts(self) -> float:
        return self.packets[-1].timestamp


class FlowManager:
    """Incremental flow table shared by every Block 2 input mode.

    Usage::

        manager = FlowManager(idle_timeout=15.0, active_timeout=30.0)
        for packet in source.packets():
            for closed in manager.add(packet):
                ...  # a finished flow, available immediately
        for closed in manager.flush():
            ...  # flows still open at end of stream
    """

    def __init__(
        self,
        idle_timeout: float,
        active_timeout: float,
        close_on_fin_rst: bool = True,
    ) -> None:
        self.idle_timeout = float(idle_timeout)
        self.active_timeout = float(active_timeout)
        self.close_on_fin_rst = bool(close_on_fin_rst)
        self._table: Dict[str, _OpenFlow] = {}

    # ------------------------------------------------------------------
    # Introspection (useful for streaming dashboards and tests)
    # ------------------------------------------------------------------

    @property
    def open_flow_count(self) -> int:
        """Number of flows currently held open."""
        return len(self._table)

    @property
    def tracked_flow_keys(self) -> List[str]:
        """Sorted 5-tuple keys currently held open."""
        return sorted(self._table)

    # ------------------------------------------------------------------
    # Packet ingestion
    # ------------------------------------------------------------------

    def add(self, pkt: PacketRecord) -> List[List[PacketRecord]]:
        """Feed one packet; return any flows this packet closed.

        The returned flows are complete and may be handed to feature extraction
        immediately, which is what makes this manager usable in a streaming
        setting rather than only after the whole capture has been read.
        """
        key = pkt.flow_key
        state = self._table.get(key)

        if state is None:
            self._table[key] = _OpenFlow(packets=[pkt])
            return []

        gap = pkt.timestamp - state.last_ts
        if gap > self.idle_timeout:
            closed = state.packets
            self._table[key] = _OpenFlow(packets=[pkt])
            return [closed]

        if pkt.timestamp - state.first_ts > self.active_timeout:
            closed = state.packets
            self._table[key] = _OpenFlow(packets=[pkt])
            return [closed]

        state.packets.append(pkt)
        if self.close_on_fin_rst and self._is_teardown(pkt):
            del self._table[key]
            return [state.packets]
        return []

    def flush(self) -> List[List[PacketRecord]]:
        """Close every flow still open (end of stream)."""
        remaining = [state.packets for _, state in sorted(self._table.items())]
        self._table.clear()
        return remaining

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _is_teardown(pkt: PacketRecord) -> bool:
        """True when the packet carries FIN or RST."""
        if not pkt.tcp_flags:
            return False
        return FIN_FLAG in pkt.tcp_flags or RST_FLAG in pkt.tcp_flags
