"""Block 2 orchestrator: manifest → extract → validate → write outputs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .config import ExtractorConfig
from .features import assign_flow_ids, compute_flow_features
from .flow_reconstructor import reconstruct_flows
from .labels import join_labels, read_ground_truth
from .models import FEATURE_COLUMNS, ExtractedFlow
from .pcap_reader import read_pcap
from .validation import validate_run
from .writer import write_flows_csv, write_json, write_labeled_csv


def extract_run(
    dataset_dir: Path,
    run: Dict,
    config: ExtractorConfig,
) -> List[ExtractedFlow]:
    """Extract flows for one manifest run entry (PCAP-only features)."""
    pcap_path = dataset_dir / run["pcap"]
    packets = read_pcap(pcap_path)

    raw_flows = reconstruct_flows(
        packets,
        idle_timeout=config.idle_timeout,
        active_timeout=config.active_timeout,
    )

    run_id = run["run_id"]
    scenario = run["scenario"]
    flows = [
        compute_flow_features(
            flow_id="",  # assigned deterministically below
            run_id=run_id,
            scenario=scenario,
            packets=flow_packets,
        )
        for flow_packets in raw_flows
    ]
    return assign_flow_ids(flows, run_id, scenario)


def run_extraction(config: ExtractorConfig) -> Dict:
    """Run full extraction over a Block 1 dataset. Returns summary dict."""
    dataset_dir = Path(config.dataset_dir)
    manifest_path = dataset_dir / "manifest.json"

    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found: {manifest_path}")

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    runs = manifest["runs"]
    if config.scenarios:
        runs = [r for r in runs if r["scenario"] in config.scenarios]

    out_dir = Path(config.outdir) / manifest["dataset_id"]
    all_flows: List[ExtractedFlow] = []
    run_reports: List[Dict] = []

    for run in runs:
        flows = extract_run(dataset_dir, run, config)
        all_flows.extend(flows)

        # Validation AFTER extraction: GT used only for comparison here.
        report = validate_run(flows, dataset_dir / run["labels"])
        report["run_id"] = run["run_id"]
        report["scenario"] = run["scenario"]
        run_reports.append(report)

        status = report["status"]
        print(
            f"[{status}] {run['scenario']}/{run['run_id']}: "
            f"{report['extracted_flow_count']} flows extracted, "
            f"{len(report['errors'])} error(s)"
        )

    # Write outputs.
    write_flows_csv(out_dir / "flows.csv", all_flows)

    # Labeled convenience file: join labels per run.
    # Filter by BOTH run_id AND scenario so that when multiple manifest
    # entries reuse the same run_id (e.g. all Block 1 runs use
    # run_id="run_001"), each scenario only receives its own flows.
    labeled_rows: List[Dict] = []
    for run in runs:
        run_flows = [
            f for f in all_flows
            if f.run_id == run["run_id"] and f.scenario == run["scenario"]
        ]
        gt_by_key = read_ground_truth(dataset_dir / run["labels"])
        labeled_rows.extend(join_labels(run_flows, gt_by_key, scenario=run["scenario"]))
    write_labeled_csv(out_dir / "flows_with_labels.csv", labeled_rows)

    overall_status = (
        "PASS" if all(r["status"] == "PASS" for r in run_reports) else "FAIL"
    )
    validation_report = {
        "dataset_id": manifest["dataset_id"],
        "overall_status": overall_status,
        "total_runs": len(run_reports),
        "total_flows": len(all_flows),
        "total_errors": sum(len(r["errors"]) for r in run_reports),
        "runs": run_reports,
    }
    write_json(out_dir / "validation_report.json", validation_report)

    extraction_manifest = {
        "dataset_id": manifest["dataset_id"],
        "extractor_version": config.extractor_version,
        "source_dataset_dir": str(dataset_dir),
        "idle_timeout_seconds": config.idle_timeout,
        "active_timeout_seconds": config.active_timeout,
        "byte_count_convention": "ip_total_length",
        "std_deviation": "population (ddof=0)",
        "flow_id_rule": "{scenario}__{run_id}__{seq:04d} sorted by (start_ts, flow_key)",
        "join_key": "(run_id, flow_key)",
        "feature_columns": FEATURE_COLUMNS,
        "total_flows": len(all_flows),
        "runs_processed": len(runs),
        "validation_status": overall_status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    write_json(out_dir / "extraction_manifest.json", extraction_manifest)

    print(
        f"\nExtraction {'PASSED' if overall_status == 'PASS' else 'FAILED'}: "
        f"{len(all_flows)} flows, "
        f"{validation_report['total_errors']} validation error(s)"
    )
    print(f"Output: {out_dir}/")

    return validation_report