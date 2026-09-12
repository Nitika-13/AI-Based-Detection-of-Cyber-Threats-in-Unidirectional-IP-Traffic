"""Exfiltration scenario: large sustained outbound transfers with benign background."""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_payload_ascii
from .base import BaseScenario

# Actual IP total lengths (Scapy computes IP.len from serialized bytes):
TCP_NO_PAYLOAD_LEN = 40
UDP_NO_PAYLOAD_LEN = 28


class ExfiltrationScenario(BaseScenario):
    """Generates large sustained outbound TCP/UDP transfers plus benign background."""

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
                if proto == "tcp":
                    # No payload: IP.len = 40
                    self._add_packet(flow, timestamp=t, ip_total_length=TCP_NO_PAYLOAD_LEN, tcp_flags="PA", tcp_seq=j * 100, tcp_ack=1)
                else:
                    # No payload: IP.len = 28
                    self._add_packet(flow, timestamp=t, ip_total_length=UDP_NO_PAYLOAD_LEN)
            flows.append(flow)

        # Exfiltration flows (label=exfiltration)
        external = self._pick_dst_ip()
        for i in range(n_attack):
            src_ip = self._pick_src_ip()
            proto = self.rng.choice(["tcp", "udp"])
            dst_port = 443 if proto == "tcp" else self.rng.choice([53, 123, 443])
            sp, dp, _ = self._allocate_key(src_ip, external, proto, dst_port=dst_port)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, external, dp, proto, "exfiltration")
            t = t0 + self.rng.uniform(0, duration * 0.2)
            n_pkts = self.rng.randint(20, 60)
            seq = self.rng.randint(0, 2**31)
            for j in range(n_pkts):
                t = next_timestamp(self.rng, t, 0.001, 0.1)
                # Large packets: IP.len = header + payload
                if proto == "tcp":
                    size = self.rng.randint(1000, 1500)
                    payload = random_payload_ascii(self.rng, max(0, size - 40))
                    self._add_packet(flow, timestamp=t, ip_total_length=40 + len(payload), tcp_flags="PA", tcp_seq=seq + j * 1400, tcp_ack=1, payload=payload)
                else:
                    size = self.rng.randint(1000, 1500)
                    payload = random_payload_ascii(self.rng, max(0, size - 28))
                    self._add_packet(flow, timestamp=t, ip_total_length=28 + len(payload), payload=payload)
            flows.append(flow)

        return flows