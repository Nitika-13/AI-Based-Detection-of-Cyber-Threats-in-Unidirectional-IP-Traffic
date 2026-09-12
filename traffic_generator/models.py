"""Data models for the traffic generator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


def make_flow_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
) -> str:
    """Build the canonical unidirectional 5-tuple flow key.

    Format: ``src_ip:src_port->dst_ip:dst_port/protocol``
    """
    return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"


@dataclass
class PacketSpec:
    """Specification for a single synthetic packet."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp" | "udp" | "icmp"
    timestamp: float  # epoch seconds (float, microsecond precision)
    ip_total_length: int  # IP header + payload (byte-count convention)
    payload: bytes = b""
    # TCP-specific
    tcp_flags: Optional[str] = None  # e.g. "S", "A", "PA", "FA", "R"
    tcp_seq: int = 0
    tcp_ack: int = 0
    # ICMP-specific
    icmp_type: int = 8  # echo request by default
    icmp_code: int = 0

    @property
    def flow_key(self) -> str:
        return make_flow_key(
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )


@dataclass
class Flow:
    """A unidirectional flow: a sequence of packets sharing a 5-tuple."""

    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    label: str
    scenario: str
    run_id: str
    packets: List[PacketSpec] = field(default_factory=list)

    @property
    def flow_key(self) -> str:
        return make_flow_key(
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )

    @property
    def start_ts(self) -> float:
        return self.packets[0].timestamp if self.packets else 0.0

    @property
    def end_ts(self) -> float:
        return self.packets[-1].timestamp if self.packets else 0.0

    @property
    def duration(self) -> float:
        return self.end_ts - self.start_ts if self.packets else 0.0

    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def byte_count(self) -> int:
        """Sum of IP total_length (approved byte-count convention)."""
        return sum(p.ip_total_length for p in self.packets)

    @property
    def tcp_flags(self) -> str:
        """Comma-joined sorted unique TCP flags; empty for non-TCP."""
        if self.protocol != "tcp":
            return ""
        flags = set()
        for p in self.packets:
            if p.tcp_flags:
                flags.update(p.tcp_flags)
        return ",".join(sorted(flags))

    @property
    def packet_sizes(self) -> List[int]:
        return [p.ip_total_length for p in self.packets]

    @property
    def inter_arrival_times(self) -> List[float]:
        """Inter-arrival times between consecutive packets (seconds)."""
        if len(self.packets) < 2:
            return []
        return [
            round(b.timestamp - a.timestamp, 6)
            for a, b in zip(self.packets, self.packets[1:])
        ]


@dataclass
class GroundTruthRecord:
    """One row of the ground-truth CSV."""

    flow_id: str
    run_id: str
    scenario: str
    label: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    flow_key: str
    start_ts: float
    end_ts: float
    duration: float
    packet_count: int
    byte_count: int
    tcp_flags: str

    @classmethod
    def from_flow(cls, flow: Flow) -> "GroundTruthRecord":
        return cls(
            flow_id=flow.flow_id,
            run_id=flow.run_id,
            scenario=flow.scenario,
            label=flow.label,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            flow_key=flow.flow_key,
            start_ts=round(flow.start_ts, 6),
            end_ts=round(flow.end_ts, 6),
            duration=round(flow.duration, 6),
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            tcp_flags=flow.tcp_flags,
        )

    def to_csv_row(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "run_id": self.run_id,
            "scenario": self.scenario,
            "label": self.label,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "flow_key": self.flow_key,
            "start_ts": f"{self.start_ts:.6f}",
            "end_ts": f"{self.end_ts:.6f}",
            "duration": f"{self.duration:.6f}",
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "tcp_flags": self.tcp_flags,
        }