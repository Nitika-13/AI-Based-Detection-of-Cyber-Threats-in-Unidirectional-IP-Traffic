"""Configuration dataclasses for the traffic generator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

# The seven supported flow labels (approved design).
SUPPORTED_LABELS: List[str] = [
    "benign",
    "ddos",
    "c2_beacon",
    "dns_anomaly",
    "port_scan",
    "exfiltration",
    "encrypted_anomaly",
]

# Approved unidirectional 5-tuple flow key.
# (src_ip, src_port, dst_ip, dst_port, protocol)

# Flow segmentation assumptions (approved design):
# Block 2 uses idle timeout = 15s, active timeout = 30s.
# Block 1 guarantees inter-packet gaps within a flow never exceed 5s
# (3x margin under the 15s idle timeout) so segmentation is unambiguous.
MAX_INTER_PACKET_GAP_SECONDS = 5.0
IDLE_TIMEOUT_SECONDS = 15.0
ACTIVE_TIMEOUT_SECONDS = 30.0

# Byte-count convention: sum of IP total_length (IP header + payload).
BYTE_COUNT_CONVENTION = "ip_total_length"

# Link layer: Ethernet (DLT_EN10MB), IPv4 only.
LINK_TYPE = "ethernet"
IP_VERSION = 4

# Default private/research IP ranges for synthetic traffic.
DEFAULT_SRC_RANGES: List[str] = ["10.0.0.0/24"]
DEFAULT_DST_RANGES: List[str] = ["10.0.1.0/24"]


@dataclass
class ScenarioConfig:
    """Per-scenario generation parameters."""

    name: str
    label: str
    flow_count: int = 20
    duration_seconds: float = 60.0
    benign_background_flows: int = 10
    # Optional per-scenario overrides.
    packet_rate: Optional[float] = None  # packets per second (approx)
    packet_size_min: int = 64
    packet_size_max: int = 1500
    # Scenario-specific knobs (interpreted by each scenario module).
    params: dict = field(default_factory=dict)


@dataclass
class GeneratorConfig:
    """Top-level generator configuration."""

    dataset_id: str = "sih26145"
    seed: int = 42
    outdir: str = "data/raw"
    runs: int = 1
    scenarios: List[str] = field(
        default_factory=lambda: list(SUPPORTED_LABELS)
    )
    # Base epoch for deterministic timestamps (seconds since epoch).
    base_epoch: float = 1726135200.0  # 2024-09-12T10:00:00Z
    src_ranges: List[str] = field(default_factory=lambda: list(DEFAULT_SRC_RANGES))
    dst_ranges: List[str] = field(default_factory=lambda: list(DEFAULT_DST_RANGES))
    # Per-scenario flow counts (defaults applied if not specified).
    scenario_flow_counts: dict = field(default_factory=dict)
    scenario_durations: dict = field(default_factory=dict)
    scenario_params: dict = field(default_factory=dict)

    def scenario_config(self, name: str) -> ScenarioConfig:
        """Build a ScenarioConfig for the given scenario name."""
        label = name if name in SUPPORTED_LABELS else "benign"
        params = dict(self.scenario_params.get(name, {}))
        benign_bg = params.pop("benign_background_flows", 10)
        return ScenarioConfig(
            name=name,
            label=label,
            flow_count=self.scenario_flow_counts.get(name, 20),
            duration_seconds=self.scenario_durations.get(name, 60.0),
            benign_background_flows=benign_bg,
            params=params,
        )