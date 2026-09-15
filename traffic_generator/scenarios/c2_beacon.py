"""C2 beacon scenario: periodic low-rate TCP beacons with benign background.

Architecture of one C2 channel (one ground-truth flow)
======================================================

    TCP connection open (SYN)
        |
    Beacon 1   (small application-data packet)
        |  wait ``beacon_interval``
    Beacon 2
        |  wait ``beacon_interval``
        ...
        |  wait ``beacon_interval``
    Beacon N
        |  wait ``beacon_interval``
    TCP connection close (FIN+ACK)

The repeated beacons belong to the SAME logical flow because they are carried
by a single, long-lived TCP connection. This is what makes the generator's
ground truth agree with normal flow reconstruction:

* there is exactly ONE SYN and exactly ONE FIN/RST in the flow, so a flow
  reconstructor that closes flows on FIN/RST still produces exactly one flow;
* every inter-packet gap equals ``beacon_interval`` (plus small jitter), so the
  idle timeout never fires and the inter-arrival statistics show the periodicity
  a C2 detector has to measure;
* the whole channel spans less than ``MAX_CHANNEL_SPAN_SECONDS``, which is well
  under Block 2's active timeout, so the active timeout never splits it either.

Historically this scenario emitted N independent SYN/PA/FIN connections reusing
one 5-tuple inside a single ground-truth flow, which forced Block 2 to ignore
FIN/RST boundaries. That workaround is no longer needed and has been removed.

Observable characteristics produced here:

* strong inter-arrival periodicity  -> ``iat_mean`` / ``iat_cv``
* repeated destination              -> destination-set size in host windows
* small communication volumes       -> low ``byte_count`` / ``mean_packet_size``
* persistence                       -> many packets spread over a long duration

Difficulty (observable behaviour, never a model feature):

* LOW    : 4.0 s interval, loose timing (20% jitter), 1 C2 destination
* MEDIUM : 3.0 s interval, moderate timing (8% jitter), 1 C2 destination
* HIGH   : 2.0 s interval, tight timing (2% jitter), 3 C2 destinations
"""

from __future__ import annotations

from typing import List

from ..config import MAX_INTER_PACKET_GAP_SECONDS
from ..models import Flow
from ..utils import jittered, random_payload_ascii
from .base import BaseScenario

# Highest interval jitter allowed. Keeps the worst-case gap under the
# documented idle-timeout guarantee.
MAX_JITTER_FRACTION = 0.20

# Hard cap on how long one channel may span. Deliberately well under
# MAX_FLOW_DURATION_SECONDS so jitter can never push the flow past Block 2's
# active timeout.
MAX_CHANNEL_SPAN_SECONDS = 22.0

DIFFICULTY = {
    "medium": {
        "beacon_interval": 3.0,
        "timing_jitter": 0.08,
        "beacon_payload_min": 64,
        "beacon_payload_max": 200,
        "c2_destination_count": 1,
    },
    "low": {
        "beacon_interval": 4.0,
        "timing_jitter": 0.20,
        "beacon_payload_min": 32,
        "beacon_payload_max": 96,
        "c2_destination_count": 1,
    },
    "high": {
        "beacon_interval": 2.0,
        "timing_jitter": 0.02,
        "beacon_payload_min": 80,
        "beacon_payload_max": 220,
        "c2_destination_count": 3,
    },
}


class C2BeaconScenario(BaseScenario):
    """Generates periodic beaconing channels to C2 server(s) plus benign traffic."""

    def generate(self) -> List[Flow]:
        flows: List[Flow] = []
        duration = self.config.duration_seconds
        t0 = self.base_epoch
        n_attack = self.config.flow_count
        n_benign = self.config.benign_background_flows

        params = self.difficulty_params(DIFFICULTY)
        beacon_interval = float(params["beacon_interval"])
        timing_jitter = float(params["timing_jitter"])
        payload_min = int(params["beacon_payload_min"])
        payload_max = int(params["beacon_payload_max"])
        n_destinations = int(params["c2_destination_count"])

        # Guard the two segmentation guarantees this scenario depends on.
        worst_case_gap = beacon_interval * (1.0 + timing_jitter)
        if worst_case_gap > MAX_INTER_PACKET_GAP_SECONDS:
            raise ValueError(
                f"c2_beacon: worst-case beacon gap {worst_case_gap:.3f}s exceeds "
                f"MAX_INTER_PACKET_GAP_SECONDS={MAX_INTER_PACKET_GAP_SECONDS}s; "
                "lower beacon_interval or timing_jitter."
            )
        if timing_jitter > MAX_JITTER_FRACTION:
            raise ValueError(
                f"c2_beacon: timing_jitter {timing_jitter} exceeds "
                f"MAX_JITTER_FRACTION={MAX_JITTER_FRACTION}."
            )

        # Number of beacons so that (n_beacons + 1) intervals stay inside the
        # channel-span cap (the extra interval is the gap before FIN+ACK).
        if "n_beacons" in params:
            n_beacons = int(params["n_beacons"])
        else:
            n_beacons = max(2, int(MAX_CHANNEL_SPAN_SECONDS / beacon_interval) - 1)

        span = (n_beacons + 1) * worst_case_gap
        if span > MAX_CHANNEL_SPAN_SECONDS * (1.0 + timing_jitter):
            raise ValueError(
                f"c2_beacon: channel span {span:.3f}s exceeds the "
                f"{MAX_CHANNEL_SPAN_SECONDS}s cap."
            )

        # Benign background flows (label=benign).
        flows.extend(self._benign_background(n_benign, duration=duration))

        # A small pool of C2 servers. HIGH difficulty spreads beacons over
        # several servers, which shows up as a larger destination set.
        c2_servers = self._dst_ip_pool(max(1, n_destinations))

        for i in range(n_attack):
            c2_ip = c2_servers[i % len(c2_servers)]
            src_ip = self._pick_src_ip()
            sp, dp, _ = self._allocate_key(src_ip, c2_ip, "tcp", dst_port=443)
            flow = self._new_flow(f"a{i:04d}", src_ip, sp, c2_ip, dp, "tcp", "c2_beacon")

            # Spread channel starts over the first half of the scenario so the
            # capture is not one synchronised burst.
            t = round(t0 + self.rng.uniform(0, duration * 0.5), 6)
            seq = self.rng.randint(0, 2**31)

            # ONE connection open for the whole channel.
            self._add_tcp_open(flow, t, seq)

            for j in range(n_beacons):
                # Regular spacing is the defining C2 characteristic.
                t = round(t + jittered(self.rng, beacon_interval, timing_jitter), 6)
                size = self.rng.randint(payload_min, payload_max)
                payload = random_payload_ascii(self.rng, size)
                self._add_packet(
                    flow,
                    timestamp=t,
                    ip_total_length=self.TCP_NO_PAYLOAD_LEN + len(payload),
                    tcp_flags="PA",
                    tcp_seq=seq + (j + 1) * 1000,
                    tcp_ack=1,
                    payload=payload,
                )

            # ONE connection close, one more interval later, so the final
            # inter-arrival time is regular too.
            t = round(t + jittered(self.rng, beacon_interval, timing_jitter), 6)
            self._add_tcp_close(flow, t, seq + (n_beacons + 1) * 1000)

            flows.append(flow)

        return flows