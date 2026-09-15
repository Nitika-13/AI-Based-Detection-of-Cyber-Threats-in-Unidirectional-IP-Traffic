"""Block 1: Synthetic Unidirectional IP Traffic Generator.

Generates deterministic, lab-only synthetic network traffic as PCAP files
with flow-level ground-truth labels for the SIH 26145 pipeline.

This module NEVER transmits packets onto a real network interface.
Scapy is used only for packet construction and PCAP file writing.
"""

__version__ = "0.2.0"

from .config import (
    DATASET_VERSION,
    DIFFICULTY_LEVELS,
    SPLIT_NAMES,
    GeneratorConfig,
    ScenarioConfig,
)
from .generator import TrafficGenerator
from .models import Flow, GroundTruthRecord, PacketSpec
from .splits import assign_run_splits, split_summary

__all__ = [
    "DATASET_VERSION",
    "DIFFICULTY_LEVELS",
    "SPLIT_NAMES",
    "GeneratorConfig",
    "ScenarioConfig",
    "Flow",
    "GroundTruthRecord",
    "PacketSpec",
    "TrafficGenerator",
    "assign_run_splits",
    "split_summary",
    "__version__",
]