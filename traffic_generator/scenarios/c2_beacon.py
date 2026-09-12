"""C2 beacon scenario: periodic low-rate TCP beacons with benign background."""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_payload_ascii
from .base import BaseScenario


class C2BeaconScenario(BaseScenario):
    """Generates periodic beaconing flows to a C2 IP plus benign background."""

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

        # C2 beacon flows (label=c2_beacon)
        # NOTE: beacon_interval must stay <= MAX_INTER_PACKET_GAP_SECONDS (5.0s)
        # so Block 2's 15s idle timeout never splits a beacon flow.
        c2_ip = self._pick_dst_ip()
        beacon_interval = float(self.config.params.get("beacon_interval", 3.0))
        if beacon_interval > 5.0:
            raise ValueError(
                "c2_beacon beacon_interval must be <= 5.0s to preserve "
                "the flow segmentation guarantee (idle timeout = 15s)."
            )
        for i in range(n_attack):
            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, c2_ip, "tcp", dst_port=443)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, c2_ip, dp, "tcp", "c2_beacon")
            t = t0 + self.rng.uniform(0, beacon_interval)
            n_beacons = max(2, int(duration / beacon_interval))
            seq = self.rng.randint(0, 2**31)
            for j in range(n_beacons):
                # SYN
                self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="S", tcp_seq=seq + j * 1000)
                # Small data (ACK+PSH)
                t = next_timestamp(self.rng, t, 0.001, 0.01)
                size = self.rng.randint(64, 200)
                payload = random_payload_ascii(self.rng, max(0, size - 40))
                self._add_packet(flow, timestamp=t, ip_total_length=size, tcp_flags="PA", tcp_seq=seq + j * 1000 + 1, tcp_ack=1, payload=payload)
                # FIN+ACK
                t = next_timestamp(self.rng, t, 0.001, 0.01)
                self._add_packet(flow, timestamp=t, ip_total_length=60, tcp_flags="FA", tcp_seq=seq + j * 1000 + 2, tcp_ack=1)
                # Next beacon at fixed interval
                t = t + beacon_interval
            flows.append(flow)

        return flows