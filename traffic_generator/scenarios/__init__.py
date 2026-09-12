"""Scenario registry for the traffic generator."""

from __future__ import annotations

from typing import Dict, Type

from .base import BaseScenario
from .benign import BenignScenario
from .c2_beacon import C2BeaconScenario
from .ddos import DDoSScenario
from .dns_anomaly import DNSAnomalyScenario
from .encrypted_anomaly import EncryptedAnomalyScenario
from .exfiltration import ExfiltrationScenario
from .port_scan import PortScanScenario

SCENARIO_REGISTRY: Dict[str, Type[BaseScenario]] = {
    "benign": BenignScenario,
    "ddos": DDoSScenario,
    "c2_beacon": C2BeaconScenario,
    "dns_anomaly": DNSAnomalyScenario,
    "port_scan": PortScanScenario,
    "exfiltration": ExfiltrationScenario,
    "encrypted_anomaly": EncryptedAnomalyScenario,
}


def get_scenario_class(name: str) -> Type[BaseScenario]:
    """Return the scenario class for the given name."""
    if name not in SCENARIO_REGISTRY:
        raise ValueError(
            f"Unknown scenario '{name}'. Supported: {sorted(SCENARIO_REGISTRY)}"
        )
    return SCENARIO_REGISTRY[name]


__all__ = [
    "BaseScenario",
    "BenignScenario",
    "DDoSScenario",
    "C2BeaconScenario",
    "DNSAnomalyScenario",
    "PortScanScenario",
    "ExfiltrationScenario",
    "EncryptedAnomalyScenario",
    "SCENARIO_REGISTRY",
    "get_scenario_class",
]