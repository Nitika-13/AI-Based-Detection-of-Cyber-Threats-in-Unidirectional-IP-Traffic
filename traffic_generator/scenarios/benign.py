"""Benign scenario: normal web, DNS, and ICMP traffic."""

from __future__ import annotations

from typing import List

from ..models import Flow, make_flow_key
from ..utils import (
    next_timestamp,
    random_payload_ascii,
    random_payload_dns,
)
from .base import BaseScenario


class BenignScenario(BaseScenario):
    """Generates low-rate, varied benign traffic (web/DNS/ICMP)."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        n = self.config.flow_count
        duration = self.config.duration_seconds
        t0 = self.base_epoch

        for i in range(n):
            src_ip = self._pick_src_ip()
            dst_ip = self._pick_dst_ip()
            proto_choice = self.rng.random()
            flow_id = f"f{i:04d}"

            if proto_choice < 0.5:
                # TCP web flow (80/443)
                dst_port = self.rng.choice([80, 443])
                sp, dp, _ = self._allocate_key(src_ip, dst_ip, "tcp", dst_port=dst_port)
                flow = self._new_flow(flow_id, src_ip, sp, dst_ip, dp, "tcp", "benign")
                t = t0 + self.rng.uniform(0, duration * 0.8)
                seq = self.rng.randint(0, 2**31)
                # SYN
                self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="S", tcp_seq=seq)
                # Data packets (ACK+PSH)
                n_pkts = self.rng.randint(2, 8)
                for j in range(n_pkts):
                    t = next_timestamp(self.rng, t, 0.01, 0.5)
                    size = self.rng.randint(64, 1200)
                    payload = random_payload_ascii(self.rng, max(0, size - 40))
                    self._add_packet(
                        flow, timestamp=t, ip_total_length=size,
                        tcp_flags="PA", tcp_seq=seq + j * 100, tcp_ack=1,
                        payload=payload,
                    )
                # FIN+ACK
                t = next_timestamp(self.rng, t, 0.01, 0.5)
                self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="FA", tcp_seq=seq + n_pkts * 100, tcp_ack=1)
            elif proto_choice < 0.8:
                # DNS query (UDP/53)
                sp, dp, _ = self._allocate_key(src_ip, dst_ip, "udp", dst_port=53)
                flow = self._new_flow(flow_id, src_ip, sp, dst_ip, dp, "udp", "benign")
                t = t0 + self.rng.uniform(0, duration * 0.8)
                n_pkts = self.rng.randint(1, 3)
                for _ in range(n_pkts):
                    t = next_timestamp(self.rng, t, 0.001, 0.1)
                    payload = random_payload_dns(self.rng, self.rng.randint(10, 40))
                    size = 28 + len(payload)  # IP(20) + UDP(8) + payload
                    self._add_packet(flow, timestamp=t, ip_total_length=size, payload=payload)
            else:
                # ICMP echo request (ports 0 per approved design)
                sp, dp = 0, 0
                key = make_flow_key(src_ip, sp, dst_ip, dp, "icmp")
                if key in self.used_keys:
                    dst_ip = self._pick_dst_ip()
                    key = make_flow_key(src_ip, sp, dst_ip, dp, "icmp")
                self.used_keys.add(key)
                flow = self._new_flow(flow_id, src_ip, sp, dst_ip, dp, "icmp", "benign")
                t = t0 + self.rng.uniform(0, duration * 0.8)
                n_pkts = self.rng.randint(1, 4)
                for _ in range(n_pkts):
                    t = next_timestamp(self.rng, t, 0.01, 0.5)
                    size = self.rng.randint(64, 128)
                    self._add_packet(flow, timestamp=t, ip_total_length=size, icmp_type=8, icmp_code=0)

            flows.append(flow)

        return flows