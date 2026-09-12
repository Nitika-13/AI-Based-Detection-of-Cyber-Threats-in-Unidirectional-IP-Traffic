"""Block 1: Synthetic Unidirectional IP Traffic Generator.

Generates deterministic, lab-only synthetic network traffic as PCAP files
with flow-level ground-truth labels for the SIH 26145 pipeline.

This module NEVER transmits packets onto a real network interface.
Scapy is used only for packet construction and PCAP file writing.
"""

__version__ = "0.1.0"

from .config import GeneratorConfig, ScenarioConfig
from .generator import TrafficGenerator
from .models import Flow, GroundTruthRecord, PacketSpec

__all__ = [
    "GeneratorConfig",
    "ScenarioConfig",
    "Flow",
    "GroundTruthRecord",
    "PacketSpec",
    "TrafficGenerator",
    "__version__",
]