"""Output writers: flows CSV, labeled CSV, validation report, manifest."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List

from .models import FEATURE_COLUMNS

LABELED_COLUMNS = FEATURE_COLUMNS + ["label"]


def write_flows_csv(path: Path, flows: List) -> None:
    """Write features-only CSV (no label column)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        for flow in flows:
            writer.writerow(flow.to_csv_row())


def write_labeled_csv(path: Path, rows: List[Dict]) -> None:
    """Write flows + joined label CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LABELED_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(path: Path, data: Dict) -> None:
    """Write a JSON file with deterministic formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")