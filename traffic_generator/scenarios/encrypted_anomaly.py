"""Encrypted anomaly scenario: synthetic TLS-like flows with anomalous patterns.

Entirely synthetic and pattern/metadata based. No real malware modeling,
no decryption, no real-world attack artifacts. The "anomaly" is expressed
only in observable flow patterns (record sizes, timing, entropy).
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_tls_like_payload
from .base import BaseScenario


class EncryptedAnomalyScenario(BaseScenario):
    """Generates synthetic TLS-like flows with anomalous patterns plus benign background."""

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

        # Encrypted anomaly flows (label=encrypted_anomaly)
        server = self._pick_dst_ip()
        anomaly_mode = self.config.params.get("anomaly_mode", "handshake_size")
        for i in range(n_attack):
            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, server, "tcp", dst_port=443)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, server, dp, "tcp", "encrypted_anomaly")
            t = t0 + self.rng.uniform(0, duration * 0.3)
            seq = self.rng.randint(0, 2**31)

            # SYN
            self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="S", tcp_seq=seq)
            # TLS-like records
            n_pkts = self.rng.randint(5, 15)
            for j in range(n_pkts):
                t = next_timestamp(self.rng, t, 0.001, 0.1)
                if anomaly_mode == "handshake_size":
                    # Anomalous: abnormally large handshake records
                    size = self.rng.randint(500, 1500)
                elif anomaly_mode == "beacon_timing":
                    # Anomalous: regular beacon-like timing
                    size = self.rng.randint(100, 400)
                else:
                    # Anomalous: high-entropy payloads with odd sizes
                    size = self.rng.choice([64, 128, 256, 512, 1024])
                payload = random_tls_like_payload(self.rng, max(0, size - 40))
                self._add_packet(
                    flow, timestamp=t, ip_total_length=size,
                    tcp_flags="PA", tcp_seq=seq + j * 1500, tcp_ack=1,
                    payload=payload,
                )
            # FIN+ACK
            t = next_timestamp(self.rng, t, 0.001, 0.1)
            self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="FA", tcp_seq=seq + n_pkts * 1500, tcp_ack=1)
            flows.append(flow)

        return flows