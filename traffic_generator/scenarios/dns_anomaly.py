"""DNS anomaly scenario: high-volume DNS with long, high-entropy QNAMEs.

Observable characteristics (measured by Block 2):

* unusually long QNAMEs            -> ``dns_qname_len_mean`` / ``dns_qname_len_max``
* higher QNAME entropy             -> ``dns_qname_entropy_mean`` / ``_max``
* unusual character distribution   -> random ``[a-z0-9-]`` labels instead of
                                      the word-like labels benign traffic uses
* repeated query rate behaviour    -> ``packets_per_second``, short ``iat_mean``
* query-type behaviour             -> ``dns_qtype_mode``

This is metadata/pattern analysis only. No DNS response inspection, no
decryption, and no queries are ever sent to a real resolver.

Difficulty (observable, never a model feature):

===========  =============  ==============  ===========  ===============
Difficulty   QNAME length   packets / flow  gap          query types
===========  =============  ==============  ===========  ===============
LOW          20-50          5-15            10-200 ms    A, AAAA
MEDIUM       40-100         10-30           1-50 ms      A, AAAA, MX, TXT, NS
HIGH         80-180         20-50           0.5-20 ms    TXT, MX
===========  =============  ==============  ===========  ===============
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_payload_dns
from .base import BaseScenario

# Wire-format QNAME limit (RFC 1035): 255 bytes including the root label.
MAX_QNAME_WIRE_LEN = 255

DIFFICULTY = {
    "medium": {
        "qname_len_range": (40, 100),
        "packets_range": (10, 30),
        "gap_range": (0.001, 0.05),
        "qtypes": (1, 28, 15, 16, 2),
    },
    "low": {
        "qname_len_range": (20, 50),
        "packets_range": (5, 15),
        "gap_range": (0.01, 0.2),
        "qtypes": (1, 28),
    },
    "high": {
        "qname_len_range": (80, 180),
        "packets_range": (20, 50),
        "gap_range": (0.0005, 0.02),
        "qtypes": (16, 15),
    },
}


class DNSAnomalyScenario(BaseScenario):
    """Generates high-volume, long-QNAME DNS query flows plus benign background."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        params = self.difficulty_params(DIFFICULTY)
        qname_lo, qname_hi = params["qname_len_range"]
        pkt_lo, pkt_hi = params["packets_range"]
        gap_lo, gap_hi = params["gap_range"]
        qtypes = tuple(params["qtypes"])

        if qname_hi + 4 > MAX_QNAME_WIRE_LEN:
            raise ValueError(
                f"dns_anomaly: qname length {qname_hi} exceeds the RFC 1035 "
                f"wire limit ({MAX_QNAME_WIRE_LEN} bytes)."
            )

        # Benign background flows (label=benign): word-like, low-entropy DNS.
        flows.extend(self._benign_background(n_benign, duration=duration))

        # DNS anomaly flows (label=dns_anomaly).
        dns_server = self._pick_dst_ip()
        for i in range(n_attack):
            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, dns_server, "udp", dst_port=53)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, dns_server, dp, "udp", "dns_anomaly")

            t = t0 + self.rng.uniform(0, duration * 0.4)
            for _ in range(self.rng.randint(pkt_lo, pkt_hi)):
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                # Long, high-entropy QNAME (random [a-z0-9-] labels).
                qname_len = self.rng.randint(qname_lo, qname_hi)
                payload = random_payload_dns(self.rng, qname_len, qtypes=qtypes)
                self._add_packet(
                    flow,
                    timestamp=t,
                    ip_total_length=self.UDP_NO_PAYLOAD_LEN + len(payload),
                    payload=payload,
                )
            flows.append(flow)

        return flows