"""Base scenario class for the traffic generator."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from typing import List, Set

from ..config import ScenarioConfig
from ..models import Flow, PacketSpec
from ..utils import make_rng, random_ip, unique_flow_key


class BaseScenario(ABC):
    """Abstract base class for all traffic scenarios.

    Each scenario generates a list of unidirectional Flows. Attack scenarios
    mix benign background flows with their anomalous/malicious flows.
    """

    def __init__(
        self,
        config: ScenarioConfig,
        *,
        run_id: str,
        seed: int,
        src_ranges: List[str],
        dst_ranges: List[str],
        base_epoch: float,
    ) -> None:
        self.config = config
        self.run_id = run_id
        self.seed = seed
        self.src_ranges = src_ranges
        self.dst_ranges = dst_ranges
        self.base_epoch = base_epoch
        self.rng = make_rng(seed)
        self.used_keys: Set[str] = set()

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def label(self) -> str:
        return self.config.label

    def _pick_src_ip(self) -> str:
        return random_ip(self.rng, self.rng.choice(self.src_ranges))

    def _pick_dst_ip(self) -> str:
        return random_ip(self.rng, self.rng.choice(self.dst_ranges))

    def _new_flow(
        self,
        flow_id: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
        label: str,
    ) -> Flow:
        return Flow(
            flow_id=flow_id,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            label=label,
            scenario=self.name,
            run_id=self.run_id,
        )

    def _allocate_key(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        dst_port: int | None = None,
    ) -> tuple[int, int, str]:
        """Allocate a unique (src_port, dst_port, flow_key) for this run."""
        return unique_flow_key(
            self.used_keys,
            self.rng,
            src_ip,
            dst_ip,
            protocol,
            dst_port=dst_port,
        )

    def _add_packet(
        self,
        flow: Flow,
        *,
        timestamp: float,
        ip_total_length: int,
        payload: bytes = b"",
        tcp_flags: str | None = None,
        tcp_seq: int = 0,
        tcp_ack: int = 0,
        icmp_type: int = 8,
        icmp_code: int = 0,
    ) -> None:
        flow.packets.append(
            PacketSpec(
                src_ip=flow.src_ip,
                src_port=flow.src_port,
                dst_ip=flow.dst_ip,
                dst_port=flow.dst_port,
                protocol=flow.protocol,
                timestamp=round(timestamp, 6),
                ip_total_length=ip_total_length,
                payload=payload,
                tcp_flags=tcp_flags,
                tcp_seq=tcp_seq,
                tcp_ack=tcp_ack,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
            )
        )

    @abstractmethod
    def generate(self) -> List[Flow]:
        """Generate the flows for this scenario run."""
        raise NotImplementedError