"""Ground-truth label reading and joining (labels only, never features).

The GT CSV is used exclusively for:
  - attaching labels to extracted flows (flows_with_labels.csv)
  - post-extraction validation comparisons

It must NEVER be a source of feature values: extracted features are fully
computed from the PCAP before this module is ever consulted.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional


class GroundTruthRecord(NamedTuple):
    """Block 1 GT row (identity + label + expected feature columns)."""

    run_id: str
    scenario: str
    label: str
    flow_key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int
    byte_count: int
    tcp_flags: str


def read_ground_truth(csv_path: Path) -> Dict[str, GroundTruthRecord]:
    """Read a Block 1 ground-truth CSV, keyed by flow_key.

    Note: each GT file belongs to a single scenario, so flow_key alone is
    sufficient as a key. When multiple scenarios' GT rows are combined in
    one dict (e.g. in tests), join_labels must also filter by scenario.
    """
    records: Dict[str, GroundTruthRecord] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rec = GroundTruthRecord(
                run_id=row["run_id"],
                scenario=row["scenario"],
                label=row["label"],
                flow_key=row["flow_key"],
                src_ip=row["src_ip"],
                src_port=int(row["src_port"]),
                dst_ip=row["dst_ip"],
                dst_port=int(row["dst_port"]),
                protocol=row["protocol"],
                packet_count=int(row["packet_count"]),
                byte_count=int(row["byte_count"]),
                tcp_flags=row["tcp_flags"],
            )
            records[rec.flow_key] = rec
    return records


def join_labels(
    flows: list,
    gt_by_key: Dict[str, GroundTruthRecord],
    scenario: str = "",
) -> List[dict]:
    """Join extracted flows with GT labels by (flow_key, scenario).

    When ``scenario`` is given, only GT rows matching that scenario are
    considered — this prevents a flow from being labeled by another
    scenario's GT row when multiple scenarios share the same flow_key
    (e.g. when the same run_id is reused across scenarios).
    """
    rows: List[dict] = []
    for flow in flows:
        gt: Optional[GroundTruthRecord] = gt_by_key.get(flow.flow_key)
        if gt is not None and scenario and gt.scenario != scenario:
            gt = None
        row = flow.to_csv_row()
        row["label"] = gt.label if gt else ""
        rows.append(row)
    return rows
