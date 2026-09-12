"""DNS anomaly scenario: high-volume DNS queries with long QNAMEs."""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_payload_dns
from .base import BaseScenario


class DNSAnomalyScenario(BaseScenario):
    """Generates high-volume DNS query flows plus benign background."""

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

        # DNS anomaly flows (label=dns_anomaly)
        dns_server = self._pick_dst_ip()
        for i in range(n_attack):
            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, dns_server, "udp", dst_port=53)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, dns_server, dp, "udp", "dns_anomaly")
            t = t0 + self.rng.uniform(0, duration * 0.3)
            n_pkts = self.rng.randint(10, 30)
            for _ in range(n_pkts):
                t = next_timestamp(self.rng, t, 0.001, 0.05)
                # Long QNAMEs (anomalous)
                qname_len = self.rng.randint(40, 100)
                payload = random_payload_dns(self.rng, qname_len)
                size = 28 + len(payload)
                self._add_packet(flow, timestamp=t, ip_total_length=size, payload=payload)
            flows.append(flow)

        return flows