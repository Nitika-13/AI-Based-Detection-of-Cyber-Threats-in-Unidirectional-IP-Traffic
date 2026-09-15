"""Configuration dataclasses for the traffic generator."""

from __future__ import annotations
from collections.abc import Sequence
from typing import List, Optional, Sequence as _Sequence, Tuple


from dataclasses import dataclass, field
from typing import Dict, List, Optional

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

# Dataset schema version (changes when the output contract changes) and the
# generator implementation version (imported from package __init__).
DATASET_VERSION = "1.0.0"

# Controlled difficulty levels. Difficulty is expressed purely through
# OBSERVABLE traffic behaviour (rates, volumes, fan-out, timing regularity)
# so that a future severity engine can be evaluated on it. Difficulty is
# NEVER written into the feature matrix as a model input.
DIFFICULTY_LEVELS: List[str] = ["low", "medium", "high"]
DEFAULT_DIFFICULTY = "medium"

# Run-level split names. Splitting happens strictly at the RUN level (never at
# the packet or flow level) so that traffic generated from one run can never
# appear in two different splits.
SPLIT_NAMES: List[str] = ["train", "val", "test"]
DEFAULT_SPLIT_RATIOS: Dict[str, float] = {"train": 0.6, "val": 0.2, "test": 0.2}

# Approved unidirectional 5-tuple flow key.
# (src_ip, src_port, dst_ip, dst_port, protocol)

# Flow segmentation assumptions (approved design):
# Block 2 uses idle timeout = 15s, active timeout = 30s.
# Block 1 guarantees inter-packet gaps within a flow never exceed 5s
# (3x margin under the 15s idle timeout) so segmentation is unambiguous.
MAX_INTER_PACKET_GAP_SECONDS = 5.0
IDLE_TIMEOUT_SECONDS = 15.0
ACTIVE_TIMEOUT_SECONDS = 30.0

# Hard generator invariant: no generated ground-truth flow may span longer
# than this. It is deliberately equal to Block 2's active timeout so that a
# ground-truth flow can never be split by the active timeout during
# extraction. ``generator.py`` enforces this on every flow it emits.
MAX_FLOW_DURATION_SECONDS = ACTIVE_TIMEOUT_SECONDS

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
    difficulty: str = DEFAULT_DIFFICULTY
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
    # Controlled difficulty, applied to every scenario unless overridden.
    difficulty: str = DEFAULT_DIFFICULTY
    # Base epoch for deterministic timestamps (seconds since epoch).
    base_epoch: float = 1726135200.0  # 2024-09-12T10:00:00Z
    src_ranges: List[str] = field(default_factory=lambda: list(DEFAULT_SRC_RANGES))
    dst_ranges: List[str] = field(default_factory=lambda: list(DEFAULT_DST_RANGES))
    # Per-scenario flow counts (defaults applied if not specified).
    scenario_flow_counts: dict = field(default_factory=dict)
    scenario_durations: dict = field(default_factory=dict)
    scenario_params: dict = field(default_factory=dict)
    # Optional per-scenario difficulty override: {"ddos": "high", ...}.
    scenario_difficulty: dict = field(default_factory=dict)
    # Run-level split ratios (train/val/test). Splitting is by RUN, never by
    # packet or flow, to prevent near-identical traffic leaking across splits.
    split_ratios: Dict[str, float] = field(
        default_factory=lambda: dict(DEFAULT_SPLIT_RATIOS)
    )
    # Explicit run_id -> split override; wins over split_ratios when set.
    run_splits: Dict[str, str] = field(default_factory=dict)
    # Optional random seed for deterministic grouped splitting permutations.
    split_seed: Optional[int] = None

    def difficulty_for(self, name: str) -> str:
        """Return the difficulty to use for the given scenario name."""
        return self.scenario_difficulty.get(name, self.difficulty)

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
            difficulty=self.difficulty_for(name),
            params=params,
        )
def build_grouped_run_ids(
    scenarios: Sequence[str],
    runs_per_group: int,
    *,
    prefix: str = "grp",
) -> List[Tuple[str, str, str]]:
    """Return a deterministic list of (group_id, run_id, scenario) triples.

    Each ``group_id`` is one independent generation group. All scenarios in the
    same group share the same global seed and run index, so they are related
    captures that must NEVER be split across train/val/test.

    ``run_id`` is still the per-capture scheduling identity (used for manifest
    ``run_id`` / Block 1 metadata), but it is NOT the grouping unit any more.
    ``scenario`` is the per-capture traffic mix.

    This helper is purely for dataset/workflow construction. The splitter
    operates on the explicit ``group_id -> split`` mapping, not on run_id.
    """

    scenarios = list(scenarios)
    if not scenarios:
        return []

    # Deterministic group ids from the scenario list so fixtures are stable.
    groups: List[Tuple[str, str, str]] = []
    for group_index, scenario in enumerate(scenarios):
        group_id = f"{prefix}_{group_index:03d}"
        for run_offset in range(runs_per_group):
            run_index = group_index * runs_per_group + run_offset
            run_id = f"run_{run_index:03d}"
            groups.append((group_id, run_id, scenario))
    return groups
