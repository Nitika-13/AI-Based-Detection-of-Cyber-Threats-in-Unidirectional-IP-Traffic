"""Configuration for the NetFlow feature extractor (Block 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# Approved flow boundary rules (must match Block 1 contract).
IDLE_TIMEOUT_SECONDS = 15.0
ACTIVE_TIMEOUT_SECONDS = 30.0
# Block 1 guarantees inter-packet gaps within a flow never exceed this.
MAX_INTER_PACKET_GAP_SECONDS = 5.0

# Byte-count convention: sum of IP total_length (NetFlow convention).
BYTE_COUNT_CONVENTION = "ip_total_length"

# Timestamp comparison tolerance for validation (microsecond precision).
TIMESTAMP_TOLERANCE = 1e-6

# Denominator floor for rate features (single-packet flows have duration 0).
MIN_DURATION_FOR_RATES = 1e-6

# Supported protocols (Block 1 conventions).
SUPPORTED_PROTOCOLS = ("tcp", "udp", "icmp")


@dataclass
class ExtractorConfig:
    """Top-level extractor configuration."""

    dataset_dir: str = "data/raw/sih26145"
    outdir: str = "data/processed"
    strict: bool = True
    idle_timeout: float = IDLE_TIMEOUT_SECONDS
    active_timeout: float = ACTIVE_TIMEOUT_SECONDS
    extractor_version: str = "0.2.0"
    # Runs/scenarios filter (empty = all from manifest).
    scenarios: List[str] = field(default_factory=list)