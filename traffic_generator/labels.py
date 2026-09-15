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
    # --- added in dataset schema 1.0.0 (all optional for backward compat) ---
    dataset_version: str = "",
    capture_id: str = "",
    capture_index: int = 0,
    split: str = "",
    difficulty: str = "",
    metadata_file: str = "",
    generation_params: dict | None = None,
) -> None:
    """Write the per-run metadata JSON.

    Existing keys keep their meaning so anything that already reads Block 1
    metadata (including Block 2) continues to work; the schema additions are
    purely additive.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "run_id": run_id,
        "capture_id": capture_id,
        "capture_index": capture_index,
        "split": split,
        "scenario": scenario,
        "scenario_type": scenario_type,
        "difficulty": difficulty,
        "seed": seed,
        "generator_version": generator_version,
        "generated_at": generated_at,
        "pcap_file": pcap_file,
        "label_file": label_file,
        "metadata_file": metadata_file,
        "flow_count": flow_count,
        "packet_count": packet_count,
        "duration_seconds": duration_seconds,
        "generation_params": generation_params or {},
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
    # --- added in dataset schema 1.0.0 (all optional for backward compat) ---
    dataset_version: str = "",
    difficulty: str = "",
    split_ratios: dict | None = None,
    splits: dict | None = None,
    conventions: dict | None = None,
) -> None:
    """Write the dataset manifest.json (Block 2 entry point).

    ``runs[]`` entries keep the original ``run_id`` / ``scenario`` / ``pcap`` /
    ``labels`` / ``metadata`` keys and add identity, split, difficulty, seed and
    parameter detail.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "dataset_id": dataset_id,
        "dataset_version": dataset_version,
        "generator_version": generator_version,
        "seed": seed,
        "difficulty": difficulty,
        "created_at": created_at,
        "split_ratios": split_ratios or {},
        "splits": splits or {},
        "conventions": conventions or {},
        "runs": runs,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")