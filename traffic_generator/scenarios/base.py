"""Base scenario class for the traffic generator."""

from __future__ import annotations

import random
from abc import ABC, abstractmethod
from typing import List, Set

from ..config import ScenarioConfig
from ..models import Flow, PacketSpec, make_flow_key
from ..utils import (
    make_rng,
    next_timestamp,
    random_ip,
    random_payload_ascii,
    random_payload_dns,
    random_payload_dns_benign,
    unique_flow_key,
)


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

    @property
    def difficulty(self) -> str:
        """Controlled difficulty level for this scenario run."""
        return self.config.difficulty

    def difficulty_params(self, table: dict) -> dict:
        """Resolve the effective parameters for this run's difficulty.

        Lookup order (later wins):

        1. ``table["medium"]`` (baseline defaults),
        2. ``table[self.difficulty]`` (the requested difficulty),
        3. ``self.config.params`` (explicit CLI/programmatic overrides).

        Every scenario module declares a module-level ``DIFFICULTY`` dict with
        one entry per level, so the behavioural difference between LOW and HIGH
        is explicit and reviewable in one place.
        """
        if self.difficulty not in table:
            raise ValueError(
                f"Scenario '{self.name}' has no difficulty level "
                f"'{self.difficulty}'. Available: {sorted(table)}"
            )
        merged = dict(table.get("medium", {}))
        merged.update(table.get(self.difficulty, {}))
        merged.update(self.config.params)
        return merged

    def _pick_src_ip(self) -> str:
        return random_ip(self.rng, self.rng.choice(self.src_ranges))

    def _pick_dst_ip(self) -> str:
        return random_ip(self.rng, self.rng.choice(self.dst_ranges))

    def _src_ip_pool(self, size: int) -> tuple:
        """Return a deterministic pool of ``size`` distinct source IPs.

        Used by scenarios where *source/host diversity* is itself an observable
        characteristic (DDoS source spread, scan host fan-out). A limited pool
        makes LOW difficulty visibly less diverse than HIGH.
        """
        from ..utils import distinct_ip_pool

        return distinct_ip_pool(self.rng, self.rng.choice(self.src_ranges), size)

    def _dst_ip_pool(self, size: int) -> tuple:
        """Return a deterministic pool of ``size`` distinct destination IPs."""
        from ..utils import distinct_ip_pool

        return distinct_ip_pool(self.rng, self.rng.choice(self.dst_ranges), size)

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

    # ------------------------------------------------------------------
    # Shared building blocks (used by several scenarios)
    # ------------------------------------------------------------------

    # Actual IP total lengths as serialized by Scapy (IP header included):
    #   TCP  = 20 (IP) + 20 (TCP) + payload
    #   UDP  = 20 (IP) +  8 (UDP) + payload
    #   ICMP = 20 (IP) +  8 (ICMP) + payload
    TCP_NO_PAYLOAD_LEN = 40
    UDP_NO_PAYLOAD_LEN = 28
    ICMP_NO_PAYLOAD_LEN = 28

    def _add_tcp_open(self, flow: Flow, timestamp: float, seq: int) -> float:
        """Append a SYN packet (start of a TCP connection). Returns timestamp."""
        self._add_packet(
            flow,
            timestamp=timestamp,
            ip_total_length=self.TCP_NO_PAYLOAD_LEN,
            tcp_flags="S",
            tcp_seq=seq,
        )
        return timestamp

    def _add_tcp_close(self, flow: Flow, timestamp: float, seq: int) -> float:
        """Append a FIN+ACK packet (end of a TCP connection). Returns timestamp."""
        self._add_packet(
            flow,
            timestamp=timestamp,
            ip_total_length=self.TCP_NO_PAYLOAD_LEN,
            tcp_flags="FA",
            tcp_seq=seq,
            tcp_ack=1,
        )
        return timestamp

    def _benign_background(
        self,
        count: int,
        *,
        duration: float,
        packets_range=(2, 5),
        gap_range=(0.01, 0.5),
        tcp_payload_range=(0, 0),
        use_wordlike_dns: bool = True,
    ) -> List[Flow]:
        """Build ``count`` benign background flows (label ``benign``).

        Every attack scenario mixes these with its anomalous flows so that the
        classifier has to separate anomalies from plausible normal traffic
        rather than from silence. Traffic shape: TCP/80, TCP/443, UDP/53 and
        occasionally ICMP echo.
        """
        flows: List[Flow] = []
        t0 = self.base_epoch
        for i in range(count):
            choice = self.rng.random()
            flow_id = f"b{i:04d}"

            if choice < 0.4:
                # TCP web flow to 80/443.
                src_ip = self._pick_src_ip()
                dst_ip = self._pick_dst_ip()
                dst_port = self.rng.choice([80, 443])
                sp, dp, _ = self._allocate_key(src_ip, dst_ip, "tcp", dst_port=dst_port)
                flow = self._new_flow(flow_id, src_ip, sp, dst_ip, dp, "tcp", "benign")
                t = t0 + self.rng.uniform(0, duration * 0.8)
                seq = self.rng.randint(0, 2**31)
                self._add_tcp_open(flow, t, seq)
                n_pkts = self.rng.randint(*packets_range)
                for j in range(n_pkts):
                    t = next_timestamp(self.rng, t, *gap_range)
                    lo, hi = tcp_payload_range
                    payload = (
                        random_payload_ascii(self.rng, self.rng.randint(lo, hi))
                        if hi > 0
                        else b""
                    )
                    self._add_packet(
                        flow,
                        timestamp=t,
                        ip_total_length=self.TCP_NO_PAYLOAD_LEN + len(payload),
                        tcp_flags="PA",
                        tcp_seq=seq + (j + 1) * 100,
                        tcp_ack=1,
                        payload=payload,
                    )
                t = next_timestamp(self.rng, t, *gap_range)
                self._add_tcp_close(flow, t, seq + (n_pkts + 1) * 100)
            elif choice < 0.8:
                # DNS lookup over UDP/53.
                src_ip = self._pick_src_ip()
                dst_ip = self._pick_dst_ip()
                sp, dp, _ = self._allocate_key(src_ip, dst_ip, "udp", dst_port=53)
                flow = self._new_flow(flow_id, src_ip, sp, dst_ip, dp, "udp", "benign")
                t = t0 + self.rng.uniform(0, duration * 0.8)
                n_pkts = self.rng.randint(*packets_range)
                for _ in range(n_pkts):
                    t = next_timestamp(self.rng, t, 0.001, 0.1)
                    if use_wordlike_dns:
                        payload = random_payload_dns_benign(self.rng)
                    else:
                        payload = random_payload_dns(self.rng, self.rng.randint(10, 40))
                    self._add_packet(
                        flow,
                        timestamp=t,
                        ip_total_length=self.UDP_NO_PAYLOAD_LEN + len(payload),
                        payload=payload,
                    )
            else:
                # ICMP echo request (ports 0 per the approved design).
                src_ip = self._pick_src_ip()
                dst_ip = self._pick_dst_ip()
                key = make_flow_key(src_ip, 0, dst_ip, 0, "icmp")
                if key in self.used_keys:
                    dst_ip = self._pick_dst_ip()
                    key = make_flow_key(src_ip, 0, dst_ip, 0, "icmp")
                self.used_keys.add(key)
                flow = self._new_flow(flow_id, src_ip, 0, dst_ip, 0, "icmp", "benign")
                t = t0 + self.rng.uniform(0, duration * 0.8)
                n_pkts = self.rng.randint(*packets_range)
                for _ in range(n_pkts):
                    t = next_timestamp(self.rng, t, 0.01, 0.5)
                    self._add_packet(
                        flow,
                        timestamp=t,
                        ip_total_length=self.ICMP_NO_PAYLOAD_LEN,
                        icmp_type=8,
                        icmp_code=0,
                    )
            flows.append(flow)
        return flows