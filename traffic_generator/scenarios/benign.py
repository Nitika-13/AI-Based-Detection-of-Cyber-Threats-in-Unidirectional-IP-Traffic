"""Benign scenario: normal web, DNS, and ICMP traffic.

This scenario is the *baseline*: it produces only ``benign`` flows. Attack
scenarios reuse the same benign-background builder (``BaseScenario.
_benign_background``) so that normal traffic is statistically consistent across
every capture — an anomaly detector must not be able to separate attack runs
from benign runs just because the background looks different.

Observable characteristics:

* varied protocols (TCP/80, TCP/443, UDP/53, ICMP echo)
* low packet counts and modest volumes
* irregular inter-arrival times (no periodicity)
* word-like, low-entropy DNS QNAMEs of modest length

Difficulty scales the volume of normal traffic (observable, never a feature):

* LOW    : 2-4 packets per flow, up to 400 B of payload
* MEDIUM : 2-8 packets per flow, up to 1200 B of payload
* HIGH   : 4-16 packets per flow, up to 1500 B of payload
"""

from __future__ import annotations

from typing import List

from ..models import Flow
from .base import BaseScenario

DIFFICULTY = {
    "medium": {"packets_range": (2, 8), "tcp_payload_max": 1200},
    "low": {"packets_range": (2, 4), "tcp_payload_max": 400},
    "high": {"packets_range": (4, 16), "tcp_payload_max": 1500},
}


class BenignScenario(BaseScenario):
    """Generates low-rate, varied benign traffic (web/DNS/ICMP)."""

    def generate(self) -> List[Flow]:
        params = self.difficulty_params(DIFFICULTY)
        return self._benign_background(
            self.config.flow_count,
            duration=self.config.duration_seconds,
            packets_range=tuple(params["packets_range"]),
            tcp_payload_range=(0, int(params["tcp_payload_max"])),
        )