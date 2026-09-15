"""Port scan scenario: TCP SYN probing with benign background.

Three scan patterns are supported so that the fan-out characteristics a
detector has to measure are actually present in the data:

``ports``
    Many destination ports against one host (vertical scan).
``hosts``
    A few common ports across many hosts (horizontal / host sweep).
``broad``
    Many ports against many hosts (broad scan).

Observable characteristics (measured by Block 2):

* destination-port fan-out   -> ``unique_peer_port_count`` / ``peer_port_entropy``
                                in the host-window aggregates (scanner in the
                                ``src`` role)
* destination-host fan-out   -> ``unique_peer_ip_count`` for the scanner
* scan rate                  -> ``packet_rate_pps`` for the scanner, and per
                                flow ``iat_mean`` / ``iat_max``
* probe behaviour            -> SYN-only flows: ``tcp_syn_count == packet_count``,
                                ``tcp_syn_ratio == 1.0``, no payload, tiny
                                ``byte_count``

Difficulty (observable, never a model feature):

===========  ==================  ==============  ===========  ============
Difficulty   pattern             port range      host count   gap
===========  ==================  ==============  ===========  ============
LOW          ports               1-20             1           50-500 ms
MEDIUM       ports               1-1024           1           10-200 ms
HIGH         broad               1-65535          8           1-20 ms
===========  ==================  ==============  ===========  ============
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp
from .base import BaseScenario

# Ports used by the horizontal ("hosts") sweep pattern.
COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080)

DIFFICULTY = {
    "medium": {
        "scan_mode": "ports",
        "port_start": 1,
        "port_count": 1024,
        "host_count": 1,
        "gap_range": (0.01, 0.2),
        "packets_range": (1, 3),
    },
    "low": {
        "scan_mode": "ports",
        "port_start": 1,
        "port_count": 20,
        "host_count": 1,
        "gap_range": (0.05, 0.5),
        "packets_range": (1, 3),
    },
    "high": {
        "scan_mode": "broad",
        "port_start": 1,
        "port_count": 65535,
        "host_count": 8,
        "gap_range": (0.001, 0.02),
        "packets_range": (1, 3),
    },
}


class PortScanScenario(BaseScenario):
    """Generates TCP SYN scan flows plus benign background."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        params = self.difficulty_params(DIFFICULTY)
        scan_mode = str(params["scan_mode"])
        port_start = int(params["port_start"])
        port_count = int(params["port_count"])
        host_count = int(params["host_count"])
        gap_lo, gap_hi = params["gap_range"]
        pkt_lo, pkt_hi = params["packets_range"]

        if scan_mode not in ("ports", "hosts", "broad"):
            raise ValueError(
                f"port_scan: unknown scan_mode '{scan_mode}'; "
                "expected one of ports, hosts, broad."
            )

        # Benign background flows (label=benign).
        flows.extend(self._benign_background(n_benign, duration=duration))

        targets = self._dst_ip_pool(max(1, host_count))

        for i in range(n_attack):
            if scan_mode == "ports":
                target = targets[0]
                dst_port = min(65535, port_start + i)
            elif scan_mode == "hosts":
                target = targets[i % len(targets)]
                dst_port = COMMON_PORTS[i % len(COMMON_PORTS)]
            else:  # broad
                target = targets[i % len(targets)]
                dst_port = self.rng.randint(1, min(65535, port_count))

            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, target, "tcp", dst_port=dst_port)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, target, dp, "tcp", "port_scan")

            t = t0 + self.rng.uniform(0, duration * 0.6)
            seq = self.rng.randint(0, 2**31)
            for _ in range(self.rng.randint(pkt_lo, pkt_hi)):
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                # SYN probe, no payload: IP.len = 40.
                self._add_packet(
                    flow,
                    timestamp=t,
                    ip_total_length=self.TCP_NO_PAYLOAD_LEN,
                    tcp_flags="S",
                    tcp_seq=seq,
                )
            flows.append(flow)

        return flows