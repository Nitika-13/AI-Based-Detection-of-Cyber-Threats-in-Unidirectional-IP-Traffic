"""DDoS scenario: SYN flood + UDP flood with benign background.

Observable characteristics (all measurable by Block 2 from packets alone):

* high packet rate and high byte rate within each attack flow
  -> ``packets_per_second`` / ``bytes_per_second`` (relative to duration)
* many distinct sources hitting one victim
  -> ``unique_peer_ip_count`` / ``peer_ip_entropy`` in the host-window
     aggregates, with the victim in the ``dst`` role
* SYN behaviour where applicable
  -> ``tcp_syn_count`` / ``tcp_syn_ratio`` = 1.0 for flood flows
* protocol behaviour
  -> a mix of TCP SYN floods and UDP floods to one victim
* short, tightly-packed flows
  -> low ``iat_mean`` / ``iat_max`` / high ``packets_per_second``

Difficulty (observable, never a model feature):

=================  ================  ================  ================
Difficulty         packets / flow    inter-packet gap  distinct sources
=================  ================  ================  ================
LOW                5-10              20-200 ms         5
MEDIUM             10-20             1-50 ms           25
HIGH               20-40             0.5-10 ms         100
=================  ================  ================  ================
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp
from .base import BaseScenario

DIFFICULTY = {
    "medium": {
        "packets_range": (10, 20),
        "gap_range": (0.001, 0.05),
        "src_pool_size": 25,
    },
    "low": {
        "packets_range": (5, 10),
        "gap_range": (0.02, 0.2),
        "src_pool_size": 5,
    },
    "high": {
        "packets_range": (20, 40),
        "gap_range": (0.0005, 0.01),
        "src_pool_size": 100,
    },
}


class DDoSScenario(BaseScenario):
    """Generates SYN-flood and UDP-flood attack flows plus benign background."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        params = self.difficulty_params(DIFFICULTY)
        pkt_lo, pkt_hi = params["packets_range"]
        gap_lo, gap_hi = params["gap_range"]
        src_pool_size = int(params["src_pool_size"])

        n_syn = n_attack // 2
        n_udp = n_attack - n_syn

        # Benign background flows (label=benign).
        flows.extend(self._benign_background(n_benign, duration=duration))

        # One victim; source diversity comes from a difficulty-sized pool.
        # Note: the pool is intentionally NOT widened to the attack-flow count,
        # so LOW difficulty genuinely shows fewer distinct sources.
        victim = self._pick_dst_ip()
        attackers = self._src_ip_pool(src_pool_size)

        # Attack flows: TCP SYN flood (label=ddos).
        for i in range(n_syn):
            src_ip = attackers[i % len(attackers)]
            sp, dp, _ = self._allocate_key(src_ip, victim, "tcp", dst_port=80)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, victim, dp, "tcp", "ddos")
            t = t0 + self.rng.uniform(0, duration * 0.3)
            seq = self.rng.randint(0, 2**31)
            for _ in range(self.rng.randint(pkt_lo, pkt_hi)):
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                # SYN only, no payload: IP.len = 40.
                self._add_packet(
                    flow,
                    timestamp=t,
                    ip_total_length=self.TCP_NO_PAYLOAD_LEN,
                    tcp_flags="S",
                    tcp_seq=seq,
                )
            flows.append(flow)

        # Attack flows: UDP flood (label=ddos).
        for i in range(n_udp):
            src_ip = attackers[i % len(attackers)]
            sp, dp, _ = self._allocate_key(src_ip, victim, "udp", dst_port=53)
            flow = self._new_flow(
                f"a{n_syn + i:04d}", src_ip, sp, victim, dp, "udp", "ddos"
            )
            t = t0 + self.rng.uniform(0, duration * 0.3)
            for _ in range(self.rng.randint(pkt_lo, pkt_hi)):
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                # No payload: IP.len = 28. (No DNS payload is attached, so the
                # DNS feature columns stay at 0 for these flood flows.)
                self._add_packet(
                    flow, timestamp=t, ip_total_length=self.UDP_NO_PAYLOAD_LEN
                )
            flows.append(flow)

        return flows