"""Port scan scenario: sequential/random TCP SYN scans with benign background."""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp
from .base import BaseScenario


class PortScanScenario(BaseScenario):
    """Generates TCP SYN scan flows to many ports on a target plus benign background."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        # Benign background flows (label=benign)
        for i in range(n_benign):
            src_ip = self._pick_src_ip()
            dst_ip = self._pick_dst_ip()
            dst_port = self.rng.choice([80, 443, 53])
            proto = "tcp" if dst_port in (80, 443) else "udp"
            sp, dp, _ = self._allocate_key(src_ip, dst_ip, proto, dst_port=dst_port)
            flow = self._new_flow(f"b{i:04d}", src_ip, sp, dst_ip, dp, proto, "benign")
            t = t0 + self.rng.uniform(0, duration * 0.5)
            n_pkts = self.rng.randint(2, 5)
            for j in range(n_pkts):
                t = next_timestamp(self.rng, t, 0.01, 0.5)
                size = self.rng.randint(64, 600)
                if proto == "tcp":
                    self._add_packet(flow, timestamp=t, ip_total_length=size, tcp_flags="PA", tcp_seq=j * 100, tcp_ack=1)
                else:
                    self._add_packet(flow, timestamp=t, ip_total_length=size)
            flows.append(flow)

        # Port scan flows (label=port_scan)
        target = self._pick_dst_ip()
        scan_mode = self.config.params.get("scan_mode", "sequential")
        for i in range(n_attack):
            src_ip = self._pick_src_ip()
            if scan_mode == "sequential":
                dst_port = 1 + i  # sequential ports
            else:
                dst_port = self.rng.randint(1, 1024)  # random ports
            sp, dp, _ = self._allocate_key(src_ip, target, "tcp", dst_port=dst_port)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, target, dp, "tcp", "port_scan")
            t = t0 + self.rng.uniform(0, duration * 0.3)
            n_pkts = self.rng.randint(1, 3)
            seq = self.rng.randint(0, 2**31)
            for j in range(n_pkts):
                t = next_timestamp(self.rng, t, 0.001, 0.1)
                self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="S", tcp_seq=seq + j)
            flows.append(flow)

        return flows