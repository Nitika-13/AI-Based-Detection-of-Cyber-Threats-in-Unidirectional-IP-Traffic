"""Block 2: NetFlow Feature Extractor.

Reads Block 1 PCAP files (read-only, no live network interaction),
reconstructs unidirectional flows using the approved 5-tuple and boundary
rules, computes ML-ready NetFlow-style features, and validates against
Block 1 ground truth (labels/joining only — never a feature source).
"""

__version__ = "0.2.0"

from .config import ExtractorConfig
from .extractor import extract_run, run_extraction
from .models import ExtractedFlow, FEATURE_COLUMNS, PacketRecord, make_flow_key

__all__ = [
    "ExtractorConfig",
    "ExtractedFlow",
    "FEATURE_COLUMNS",
    "PacketRecord",
    "make_flow_key",
    "extract_run",
    "run_extraction",
    "__version__",
]