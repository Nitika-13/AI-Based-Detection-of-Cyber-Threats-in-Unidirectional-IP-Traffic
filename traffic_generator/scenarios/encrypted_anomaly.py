"""Encrypted anomaly scenario: synthetic TLS-like flows with anomalous patterns.

Entirely synthetic and pattern/metadata based. No malware modelling, no
decryption, no real-world attack artifacts. The "anomaly" is expressed only in
observable flow patterns (record sizes, timing, payload entropy).

Observable characteristics (metadata only, measured by Block 2):

* packet-size patterns      -> min/max/mean/std_packet_size
* timing                    -> iat_mean / iat_cv
* TLS-like record lengths   -> tls_record_count, tls_record_len_mean/max
* TLS record version/type   -> tls_version_mode, tls_content_type_mode
* payload entropy           -> tls_payload_entropy_mean and the general
                               payload_entropy_mean/max columns
* persistence               -> many records over a long-ish duration

Record shape follows a realistic TLS session: one handshake record (content
type 22) followed by application-data records (content type 23). This makes
tls_content_type_mode a meaningful value instead of noise.

EXPLICIT LIMITATION: this generator emits TLS-like *record headers only*. There
is no ClientHello body, no SNI, and no cipher-suite/extension list, so JA3/JA4
fingerprints and SNI features are genuinely impossible and are not attempted.
No payload is ever decrypted.

Migration note: the old ad-hoc ``anomaly_mode`` parameter
(``handshake_size`` / ``beacon_timing`` / ``payload_size``) has been replaced by
the controlled difficulty levels below. It was never part of the output
contract and was not reachable from the CLI.

Difficulty (observable, never a model feature):

===========  ==================  ==============  =============
Difficulty   record size         records / flow  inter-record
===========  ==================  ==============  =============
LOW          60-300 B            4-10            50-500 ms
MEDIUM       100-600 B           5-15            1-100 ms
HIGH         900-1500 B          10-25           1-50 ms
===========  ==================  ==============  =============
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from ..utils import next_timestamp, random_tls_like_payload
from .base import BaseScenario

# TLS record content types used here.
CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_APPDATA = 23
# TLS 1.2 record version (0x0303), the most common on the wire.
TLS_VERSION_1_2 = 0x0303

# Maximum TLS record payload we emit (well below the RFC 5246 2^14 limit).
MAX_TLS_RECORD_SIZE = 1500

DIFFICULTY = {
    "medium": {
        "record_size_range": (100, 600),
        "records_range": (5, 15),
        "gap_range": (0.001, 0.1),
    },
    "low": {
        "record_size_range": (60, 300),
        "records_range": (4, 10),
        "gap_range": (0.05, 0.5),
    },
    "high": {
        "record_size_range": (900, MAX_TLS_RECORD_SIZE),
        "records_range": (10, 25),
        "gap_range": (0.001, 0.05),
    },
}


class EncryptedAnomalyScenario(BaseScenario):
    """Generates synthetic TLS-like flows with anomalous record patterns."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        params = self.difficulty_params(DIFFICULTY)
        size_lo, size_hi = params["record_size_range"]
        rec_lo, rec_hi = params["records_range"]
        gap_lo, gap_hi = params["gap_range"]

        if size_hi > MAX_TLS_RECORD_SIZE:
            raise ValueError(
                f"encrypted_anomaly: record size {size_hi} exceeds "
                f"MAX_TLS_RECORD_SIZE ({MAX_TLS_RECORD_SIZE})."
            )

        # Benign background flows (label=benign).
        flows.extend(self._benign_background(n_benign, duration=duration))

        # A small set of TLS-like servers so repeated destinations are visible.
        servers = self._dst_ip_pool(2)

        for i in range(n_attack):
            server = servers[i % len(servers)]
            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, server, "tcp", dst_port=443)
            flow = self._new_flow(
                f"a{i:04d}", src_ip, sp, server, dp, "tcp", "encrypted_anomaly"
            )

            t = round(t0 + self.rng.uniform(0, duration * 0.4), 6)
            seq = self.rng.randint(0, 2**31)
            n_records = self.rng.randint(rec_lo, rec_hi)

            # ONE connection open.
            self._add_tcp_open(flow, t, seq)

            for j in range(n_records):
                t = next_timestamp(self.rng, t, gap_lo, gap_hi)
                size = self.rng.randint(size_lo, size_hi)
                # First record looks like a handshake, the rest like app data.
                content_type = (
                    CONTENT_TYPE_HANDSHAKE if j == 0 else CONTENT_TYPE_APPDATA
                )
                payload = random_tls_like_payload(
                    self.rng,
                    size,
                    content_type=content_type,
                    version=TLS_VERSION_1_2,
                )
                self._add_packet(
                    flow,
                    timestamp=t,
                    ip_total_length=self.TCP_NO_PAYLOAD_LEN + len(payload),
                    tcp_flags="PA",
                    tcp_seq=seq + (j + 1) * MAX_TLS_RECORD_SIZE,
                    tcp_ack=1,
                    payload=payload,
                )

            # ONE connection close.
            t = next_timestamp(self.rng, t, gap_lo, gap_hi)
            self._add_tcp_close(flow, t, seq + (n_records + 1) * MAX_TLS_RECORD_SIZE)

            flows.append(flow)

        return flows