"""Ground-truth CSV, metadata JSON, and manifest JSON writers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List

from .models import Flow, GroundTruthRecord

CSV_COLUMNS = [
    "flow_id",
    "run_id",
    "scenario",
    "label",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "flow_key",
    "start_ts",
    "end_ts",
    "duration",
    "packet_count",
    "byte_count",
    "tcp_flags",
]


def write_labels_csv(path: Path, flows: List[Flow]) -> None:
    """Write the flow-level ground-truth CSV for a run."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for flow in flows:
            record = GroundTruthRecord.from_flow(flow)
            writer.writerow(record.to_csv_row())


def write_metadata_json(
    path: Path,
    *,
    dataset_id: str,
    run_id: str,
    scenario: str,
    scenario_type: str,
    seed: int,
    generator_version: str,
    generated_at: str,
    pcap_file: str,
    label_file: str,
    flow_count: int,
    packet_count: int,
    duration_seconds: float,
    ip_ranges: List[str],
    notes: str,
) -> None:
    """Write the per-run metadata JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "dataset_id": dataset_id,
        "run_id": run_id,
        "scenario": scenario,
        "scenario_type": scenario_type,
        "seed": seed,
        "generator_version": generator_version,
        "generated_at": generated_at,
        "pcap_file": pcap_file,
        "label_file": label_file,
        "flow_count": flow_count,
        "packet_count": packet_count,
        "duration_seconds": duration_seconds,
        "ip_ranges": ip_ranges,
        "notes": notes,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
        f.write("\n")


def write_manifest_json(
    path: Path,
    *,
    dataset_id: str,
    seed: int,
    generator_version: str,
    created_at: str,
    runs: List[Dict],
) -> None:
    """Write the dataset manifest.json (Block 2 entry point)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "dataset_id": dataset_id,
        "seed": seed,
        "generator_version": generator_version,
        "created_at": created_at,
        "runs": runs,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")