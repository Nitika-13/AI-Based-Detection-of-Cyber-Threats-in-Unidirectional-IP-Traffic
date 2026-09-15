"""Exfiltration scenario: large sustained outbound transfers.

Observable characteristics (measured by Block 2):

* unusual outbound volume      -> ``byte_count``, ``bytes_per_second``
* inbound/outbound asymmetry   -> direction metadata (``direction``) plus the
                                  per-flow volume columns; the flow is
                                  unidirectional by construction, and the
                                  host-window aggregates give the outbound vs
                                  inbound totals for the same host
* sustained transfer           -> long ``duration`` with a high
                                  ``bytes_per_second`` and low ``iat_cv``
* unusual destination behaviour -> few destinations receiving large volumes
                                  (see ``unique_peer_ip_count`` for the source)
* bulk packet sizes            -> ``mean_packet_size`` close to MTU and a high
                                  ``payload_ratio``

Flows now follow a real TCP lifecycle (SYN ... data ... FIN+ACK) so that the
FIN/RST flow-closing path is exercised by genuine traffic rather than by
synthetic beacons.

Difficulty (observable, never a model feature):

===========  ===============  ==============  =============
Difficulty   payload / packet packets / flow  inter-packet
===========  ===============  ==============  =============
LOW          300-700 B        15-30           50-400 ms
MEDIUM       700-1200 B       25-45           20-250 ms
HIGH         1200-1500 B      40-80           5-150 ms
===========  ===============  ==============  =============
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_payload_ascii
from .base import BaseScenario

# Upper bound on one TCP payload so the serialized packet stays within the
# classic 1500-byte Ethernet MTU (20 IP + 20 TCP + 1460 payload).
MAX_TCP_PAYLOAD = 1460

DIFFICULTY = {
    "medium": {
        "payload_range": (700, 1200),
        "packets_range": (25, 45),
        "gap_range": (0.02, 0.25),
    },
    "low": {
        "payload_range": (300, 700),
        "packets_range": (15, 30),
        "gap_range": (0.05, 0.4),
    },
    "high": {
        "payload_range": (1200, MAX_TCP_PAYLOAD),
        "packets_range": (40, 80),
        "gap_range": (0.005, 0.15),
    },
}


class ExfiltrationScenario(BaseScenario):
    """Generates large sustained outbound TCP/UDP transfers plus benign background."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        params = self.difficulty_params(DIFFICULTY)
        payload_lo, payload_hi = params["payload_range"]
        pkt_lo, pkt_hi = params["packets_range"]
        gap_lo, gap_hi = params["gap_range"]

        if payload_hi > MAX_TCP_PAYLOAD:
            raise ValueError(
                f"exfiltration: payload {payload_hi} exceeds MAX_TCP_PAYLOAD "
                f"({MAX_TCP_PAYLOAD}) and would fragment."
            )

        # Benign background flows (label=benign).
        flows.extend(self._benign_background(n_benign, duration=duration))

        # A small set of external destinations so the destination behaviour
        # ("few destinations, large volumes") is observable.
        externals = self._dst_ip_pool(3)

        for i in range(n_attack):
            external = externals[i % len(externals)]
            src_ip = self._pick_src_ip()
            proto = self.rng.choice(["tcp", "udp"])
            dst_port = 443 if proto == "tcp" else self.rng.choice([53, 123, 443])
            sp, dp, _ = self._allocate_key(src_ip, external, proto, dst_port=dst_port)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, external, dp, proto, "exfiltration")

            t = round(t0 + self.rng.uniform(0, duration * 0.2), 6)
            seq = self.rng.randint(0, 2**31)
            n_pkts = self.rng.randint(pkt_lo, pkt_hi)

            if proto == "tcp":
                # Real connection lifecycle for TCP transfers.
                self._add_tcp_open(flow, t, seq)

            for j in range(n_pkts):
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                size = self.rng.randint(payload_lo, payload_hi)
                payload = random_payload_ascii(self.rng, size)
                if proto == "tcp":
                    self._add_packet(
                        flow,
                        timestamp=t,
                        ip_total_length=self.TCP_NO_PAYLOAD_LEN + len(payload),
                        tcp_flags="PA",
                        tcp_seq=seq + (j + 1) * MAX_TCP_PAYLOAD,
                        tcp_ack=1,
                        payload=payload,
                    )
                else:
                    self._add_packet(
                        flow,
                        timestamp=t,
                        ip_total_length=self.UDP_NO_PAYLOAD_LEN + len(payload),
                        payload=payload,
                    )

            if proto == "tcp":
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                self._add_tcp_close(flow, t, seq + (n_pkts + 1) * MAX_TCP_PAYLOAD)

            flows.append(flow)

        return flows