"""Main traffic generator orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from . import __version__
from .config import (
    ACTIVE_TIMEOUT_SECONDS,
    BYTE_COUNT_CONVENTION,
    DATASET_VERSION,
    IDLE_TIMEOUT_SECONDS,
    MAX_FLOW_DURATION_SECONDS,
    MAX_INTER_PACKET_GAP_SECONDS,
    GeneratorConfig,
)
from .labels import write_labels_csv, write_manifest_json, write_metadata_json
from .models import Flow
from .pcap_writer import write_pcap
from .scenarios import get_scenario_class
from .splits import (
    assert_no_group_leakage,
    assign_group_splits,
    group_to_run_splits,
    split_summary,
)

# Safety note stored in the manifest and in every metadata file.
SAFETY_NOTE = (
    "Synthetic lab traffic for defensive research only. Packets are only ever "
    "serialized to a PCAP file; the generator never opens or transmits on a "
    "real network interface."
)


class TrafficGenerator:
    """Generates a deterministic synthetic dataset (PCAP + labels + metadata)."""

    def __init__(self, config: GeneratorConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _run_ids(count: int) -> List[str]:
        return [f"run_{i:03d}" for i in range(1, count + 1)]

    @staticmethod
    def _check_flow_invariants(flow: Flow, run_id: str, scenario: str) -> None:
        """Enforce the guarantees Block 2's segmentation relies on.

        These are hard errors rather than warnings: if a ground-truth flow can
        exceed the active timeout or contain an over-long idle gap, Block 2
        would legitimately split it and the label join would silently break.
        """
        if not flow.packets:
            raise RuntimeError(
                f"Flow {flow.flow_id} in run {run_id} scenario {scenario} "
                "has no packets."
            )
        timestamps = [p.timestamp for p in flow.packets]
        if timestamps != sorted(timestamps):
            raise RuntimeError(
                f"Flow {flow.flow_id} in run {run_id} scenario {scenario} "
                "has out-of-order timestamps."
            )
        if flow.duration > MAX_FLOW_DURATION_SECONDS:
            raise RuntimeError(
                f"Flow {flow.flow_id} in run {run_id} scenario {scenario} "
                f"spans {flow.duration:.3f}s, exceeding "
                f"MAX_FLOW_DURATION_SECONDS={MAX_FLOW_DURATION_SECONDS}s "
                "(Block 2 active timeout)."
            )
        gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
        if gaps and max(gaps) > MAX_INTER_PACKET_GAP_SECONDS:
            raise RuntimeError(
                f"Flow {flow.flow_id} in run {run_id} scenario {scenario} "
                f"has a {max(gaps):.3f}s gap, exceeding "
                f"MAX_INTER_PACKET_GAP_SECONDS={MAX_INTER_PACKET_GAP_SECONDS}s "
                "(Block 2 idle timeout)."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> Dict[str, List[Flow]]:
        """Generate all runs for all configured scenarios.

        Returns a mapping of ``{run_id/scenario: [Flow, ...]}`` for
        inspection/testing. The key format is unchanged from previous versions.
        """
        dataset_dir = Path(self.config.outdir) / self.config.dataset_id
        pcap_dir = dataset_dir / "pcap"
        labels_dir = dataset_dir / "labels"
        metadata_dir = dataset_dir / "metadata"

        run_ids = self._run_ids(self.config.runs)

        # Pre-compute the ordered list of (generation_group_id, run_id) pairs.
        # One group per capture: every (run_id, scenario) pair has its own
        # deterministic seed, so it is its own independent generation unit.
        groups: List[Tuple[str, str]] = []
        gi = 0
        for run_id in run_ids:
            for _scenario_name in self.config.scenarios:
                group_id = f"g{gi:03d}"
                groups.append((group_id, run_id))
                gi += 1

        # Assign splits at the generation-group level. All captures that share
        # a generation_group_id are kept together; with the current seed model
        # each group contains exactly one capture, so this is equivalent to
        # per-capture splitting but validates the no-leakage invariant explicitly.
        capture_splits = assign_group_splits(
            groups, self.config.split_ratios, self.config.run_splits
        )

        runs_manifest: List[Dict] = []
        all_runs: Dict[str, List[Flow]] = {}
        capture_index = 0
        gi = 0

        for run_idx, run_id in enumerate(run_ids, start=1):
            split = capture_splits[run_id]
            for scenario_name in self.config.scenarios:
                scenario_config = self.config.scenario_config(scenario_name)
                scenario_cls = get_scenario_class(scenario_name)
                # Each capture gets a deterministic sub-seed derived from the
                # global seed + run index + scenario name.
                sub_seed = (
                    self.config.seed
                    + run_idx * 1000
                    + sum(ord(c) for c in scenario_name)
                )
                scenario = scenario_cls(
                    scenario_config,
                    run_id=run_id,
                    seed=sub_seed,
                    src_ranges=self.config.src_ranges,
                    dst_ranges=self.config.dst_ranges,
                    base_epoch=self.config.base_epoch,
                )
                flows = scenario.generate()

                # Hard invariants Block 2's segmentation depends on.
                for flow in flows:
                    self._check_flow_invariants(flow, run_id, scenario_name)

                # No two flows may share a 5-tuple within one capture.
                keys = [f.flow_key for f in flows]
                if len(keys) != len(set(keys)):
                    duplicates = sorted({k for k in keys if keys.count(k) > 1})
                    raise RuntimeError(
                        f"Duplicate flow keys detected in run {run_id} "
                        f"scenario {scenario_name}: {duplicates[:5]}"
                    )

                capture_id = f"{self.config.dataset_id}__{scenario_name}__{run_id}"
                pcap_file = f"{capture_id}.pcap"
                label_file = f"{capture_id}.csv"
                metadata_file = f"{capture_id}.json"

                pcap_path = pcap_dir / pcap_file
                label_path = labels_dir / label_file
                metadata_path = metadata_dir / metadata_file

                # Write PCAP (all packets sorted by timestamp).
                all_packets = [p for f in flows for p in f.packets]
                write_pcap(str(pcap_path), all_packets)

                # Write ground-truth CSV.
                write_labels_csv(label_path, flows)

                # Explicit generation group identity.
                generation_group_id = f"g{gi:03d}"

                generation_params = {
                    "flow_count": scenario_config.flow_count,
                    "benign_background_flows": scenario_config.benign_background_flows,
                    "duration_seconds": scenario_config.duration_seconds,
                    "difficulty": scenario_config.difficulty,
                    "scenario_params": scenario_config.params,
                    "base_epoch": self.config.base_epoch,
                    "src_ranges": self.config.src_ranges,
                    "dst_ranges": self.config.dst_ranges,
                }

                # Write metadata JSON.
                generated_at = datetime.now(timezone.utc).isoformat()
                write_metadata_json(
                    metadata_path,
                    dataset_id=self.config.dataset_id,
                    dataset_version=DATASET_VERSION,
                    run_id=run_id,
                    capture_id=capture_id,
                    capture_index=capture_index,
                    split=split,
                    scenario=scenario_name,
                    scenario_type=scenario_name,
                    difficulty=scenario_config.difficulty,
                    seed=sub_seed,
                    generator_version=__version__,
                    generated_at=generated_at,
                    pcap_file=f"pcap/{pcap_file}",
                    label_file=f"labels/{label_file}",
                    metadata_file=f"metadata/{metadata_file}",
                    flow_count=len(flows),
                    packet_count=len(all_packets),
                    duration_seconds=scenario_config.duration_seconds,
                    generation_params=generation_params,
                    ip_ranges=self.config.src_ranges + self.config.dst_ranges,
                    notes=SAFETY_NOTE,
                    generation_group_id=generation_group_id,
                )

                runs_manifest.append(
                    {
                        "run_id": run_id,
                        "capture_id": capture_id,
                        "capture_index": capture_index,
                        "split": split,
                        "scenario": scenario_name,
                        "difficulty": scenario_config.difficulty,
                        "seed": sub_seed,
                        "flow_count": len(flows),
                        "packet_count": len(all_packets),
                        "duration_seconds": scenario_config.duration_seconds,
                        "params": scenario_config.params,
                        "pcap": f"pcap/{pcap_file}",
                        "labels": f"labels/{label_file}",
                        "metadata": f"metadata/{metadata_file}",
                        "generation_group_id": generation_group_id,
                    }
                )

                all_runs[f"{run_id}/{scenario_name}"] = flows
                capture_index += 1
                gi += 1

        # Write manifest.json (Block 2 entry point).
        created_at = datetime.now(timezone.utc).isoformat()
        write_manifest_json(
            dataset_dir / "manifest.json",
            dataset_id=self.config.dataset_id,
            dataset_version=DATASET_VERSION,
            generator_version=__version__,
            seed=self.config.seed,
            difficulty=self.config.difficulty,
            created_at=created_at,
            split_ratios=self.config.split_ratios,
            splits=split_summary(capture_splits),
            conventions={
                "flow_key": "(src_ip, src_port, dst_ip, dst_port, protocol)",
                "byte_count": BYTE_COUNT_CONVENTION,
                "idle_timeout_seconds": IDLE_TIMEOUT_SECONDS,
                "active_timeout_seconds": ACTIVE_TIMEOUT_SECONDS,
                "max_inter_packet_gap_seconds": MAX_INTER_PACKET_GAP_SECONDS,
                "max_flow_duration_seconds": MAX_FLOW_DURATION_SECONDS,
                "split_unit": "generation_group_id",
            },
            runs=runs_manifest,
        )

        return all_runs