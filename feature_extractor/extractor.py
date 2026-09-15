"""Block 2 orchestrator: manifest → extract → validate → write outputs.

Canonical pipeline (ONE definition for training AND inference)::

    PCAP sequential / PCAP replay / future live source
                        ↓
                   PacketSource
                        ↓
                   FlowManager        (owns idle/active/FIN-RST rules)
                        ↓
              compute_flow_features  (PCAP-only values)
                        ↓
               canonical feature tables

No competing schema exists: CICFlowMeter/Zeek-style alternatives are
explicitly out of scope for the ML input. Ground truth is consulted only
AFTER extraction, for labels and for validation comparisons.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .aggregates import HOST_WINDOW_COLUMNS, compute_host_windows
from .config import ExtractorConfig
from .feature_schema import (
    FEATURE_SCHEMA_VERSION,
    FLOW_ML_FEATURES,
    FLOW_TABLE,
    HOST_WINDOW_ML_FEATURES,
    HOST_WINDOW_TABLE,
    all_feature_names,
    as_dict as schema_as_dict,
    table_columns,
    write_feature_schema,
)
from .features import assign_flow_ids, compute_flow_features
from .flow_manager import FlowManager
from .labels import join_labels, read_ground_truth
from .models import EVIDENCE_COLUMNS, FEATURE_COLUMNS, IDENTITY_COLUMNS, ML_FEATURE_COLUMNS, ExtractedFlow
from .sensor import build_source
from .validation import validate_run
from .writer import write_flows_csv, write_host_windows_csv, write_json, write_labeled_csv


def label_direction(
    src_ip: str, dst_ip: str, monitored_prefixes: List[str]
) -> str:
    """Label a flow's direction from observed addresses (passive only).

    ``outbound`` when the source falls inside a monitored prefix,
    ``inbound`` when only the destination does, otherwise ``unknown``.
    Pure local bookkeeping on already-observed addresses: no probe, no
    handshake, no transmission. Traceability metadata only, never a
    model input.
    """
    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)
    except ValueError:
        return "unknown"
    nets = []
    for prefix in monitored_prefixes or []:
        try:
            nets.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            continue
    src_in = any(src in net for net in nets)
    dst_in = any(dst in net for net in nets)
    if src_in and not dst_in:
        return "outbound"
    if dst_in and not src_in:
        return "inbound"
    return "unknown"


def extract_run(
    dataset_dir: Path,
    run: Dict,
    config: ExtractorConfig,
) -> List[ExtractedFlow]:
    """Extract flows for one manifest run entry (PCAP-only features).

    Packets stream through ONE :class:`PacketSource` and ONE
    :class:`FlowManager` — the same objects inference will use — so the
    features here have identical semantics to a future live run.
    """
    pcap_path = dataset_dir / run["pcap"]
    source = build_source(
        config.mode,
        pcap_path=pcap_path,
        speed=config.replay_speed,
    )
    manager = FlowManager(
        idle_timeout=config.idle_timeout,
        active_timeout=config.active_timeout,
        close_on_fin_rst=True,
    )
    raw_flows: List[List] = []
    with source:
        for packet in source.packets():
            raw_flows.extend(manager.add(packet))
        raw_flows.extend(manager.flush())

    # Deterministic order: (first timestamp, flow key).
    raw_flows.sort(key=lambda flow: (flow[0].timestamp, flow[0].flow_key))

    run_id = run["run_id"]
    scenario = run["scenario"]
    flows = [
        compute_flow_features(
            flow_id="",  # assigned deterministically below
            run_id=run_id,
            scenario=scenario,
            packets=flow_packets,
            direction=label_direction(
                flow_packets[0].src_ip,
                flow_packets[0].dst_ip,
                list(config.monitored_prefixes),
            ),
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

    # Cross-flow aggregates: one host_windows.csv for the whole dataset
    # (tumbling windows are per-run so run-level splitting still holds).
    host_rows: List[Dict] = []
    for run in runs:
        run_flows = [
            f for f in all_flows
            if f.run_id == run["run_id"] and f.scenario == run["scenario"]
        ]
        host_rows.extend(
            compute_host_windows(
                run_flows, run["run_id"], run["scenario"], config.window_seconds
            )
        )
    write_host_windows_csv(out_dir / "host_windows.csv", host_rows, HOST_WINDOW_COLUMNS)

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
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "source_dataset_dir": str(dataset_dir),
        "input_mode": config.mode,
        "replay_speed": config.replay_speed,
        "idle_timeout_seconds": config.idle_timeout,
        "active_timeout_seconds": config.active_timeout,
        "window_seconds": config.window_seconds,
        "monitored_prefixes": list(config.monitored_prefixes),
        "byte_count_convention": "ip_total_length",
        "std_deviation": "population (ddof=0)",
        "flow_id_rule": "{scenario}__{run_id}__{seq:04d} sorted by (start_ts, flow_key)",
        "join_key": "(run_id, flow_key)",
        "feature_columns": FEATURE_COLUMNS,
        "ml_feature_columns": list(ML_FEATURE_COLUMNS),
        "identity_columns": list(IDENTITY_COLUMNS),
        "evidence_columns": list(EVIDENCE_COLUMNS),
        "host_window_columns": list(HOST_WINDOW_COLUMNS),
        "host_window_ml_feature_columns": [row[0] for row in HOST_WINDOW_ML_FEATURES],
        "total_flows": len(all_flows),
        "total_host_windows": len(host_rows),
        "runs_processed": len(runs),
        "validation_status": overall_status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    write_json(out_dir / "extraction_manifest.json", extraction_manifest)

    write_feature_schema(out_dir / "feature_schema.json")

    print(
        f"\nExtraction {'PASSED' if overall_status == 'PASS' else 'FAILED'}: "
        f"{len(all_flows)} flows, "
        f"{validation_report['total_errors']} validation error(s)"
    )
    print(f"Output: {out_dir}/")

    return validation_report