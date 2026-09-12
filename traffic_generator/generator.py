"""Main traffic generator orchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from . import __version__
from .config import GeneratorConfig
from .labels import write_labels_csv, write_manifest_json, write_metadata_json
from .models import Flow
from .pcap_writer import write_pcap
from .scenarios import get_scenario_class


class TrafficGenerator:
    """Generates a deterministic synthetic dataset (PCAP + labels + metadata)."""

    def __init__(self, config: GeneratorConfig) -> None:
        self.config = config

    def generate(self) -> Dict[str, List[Flow]]:
        """Generate all runs for all configured scenarios.

        Returns a mapping of ``{run_id: [Flow, ...]}`` for inspection/testing.
        """
        dataset_dir = Path(self.config.outdir) / self.config.dataset_id
        pcap_dir = dataset_dir / "pcap"
        labels_dir = dataset_dir / "labels"
        metadata_dir = dataset_dir / "metadata"

        runs_manifest: List[Dict] = []
        all_runs: Dict[str, List[Flow]] = {}

        for run_idx in range(1, self.config.runs + 1):
            run_id = f"run_{run_idx:03d}"
            for scenario_name in self.config.scenarios:
                scenario_config = self.config.scenario_config(scenario_name)
                scenario_cls = get_scenario_class(scenario_name)
                # Each scenario gets a deterministic sub-seed derived from the
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

                # Validate: every flow has at least one packet.
                for flow in flows:
                    if not flow.packets:
                        raise RuntimeError(
                            f"Flow {flow.flow_id} in run {run_id} scenario "
                            f"{scenario_name} has no packets."
                        )

                # Validate: no duplicate flow keys within the run.
                keys = [f.flow_key for f in flows]
                if len(keys) != len(set(keys)):
                    raise RuntimeError(
                        f"Duplicate flow keys detected in run {run_id} "
                        f"scenario {scenario_name}."
                    )

                pcap_file = f"{self.config.dataset_id}__{scenario_name}__{run_id}.pcap"
                label_file = f"{self.config.dataset_id}__{scenario_name}__{run_id}.csv"
                metadata_file = f"{self.config.dataset_id}__{scenario_name}__{run_id}.json"

                pcap_path = pcap_dir / pcap_file
                label_path = labels_dir / label_file
                metadata_path = metadata_dir / metadata_file

                # Write PCAP (all packets sorted by timestamp).
                all_packets = [p for f in flows for p in f.packets]
                write_pcap(str(pcap_path), all_packets)

                # Write ground-truth CSV.
                write_labels_csv(label_path, flows)

                # Write metadata JSON.
                generated_at = datetime.now(timezone.utc).isoformat()
                write_metadata_json(
                    metadata_path,
                    dataset_id=self.config.dataset_id,
                    run_id=run_id,
                    scenario=scenario_name,
                    scenario_type=scenario_name,
                    seed=sub_seed,
                    generator_version=__version__,
                    generated_at=generated_at,
                    pcap_file=f"pcap/{pcap_file}",
                    label_file=f"labels/{label_file}",
                    flow_count=len(flows),
                    packet_count=len(all_packets),
                    duration_seconds=scenario_config.duration_seconds,
                    ip_ranges=self.config.src_ranges + self.config.dst_ranges,
                    notes=(
                        "Synthetic lab traffic for defensive research only. "
                        "Never transmitted to a real network interface."
                    ),
                )

                runs_manifest.append(
                    {
                        "run_id": run_id,
                        "scenario": scenario_name,
                        "pcap": f"pcap/{pcap_file}",
                        "labels": f"labels/{label_file}",
                        "metadata": f"metadata/{metadata_file}",
                    }
                )

                all_runs[f"{run_id}/{scenario_name}"] = flows

        # Write manifest.json (Block 2 entry point).
        created_at = datetime.now(timezone.utc).isoformat()
        write_manifest_json(
            dataset_dir / "manifest.json",
            dataset_id=self.config.dataset_id,
            seed=self.config.seed,
            generator_version=__version__,
            created_at=created_at,
            runs=runs_manifest,
        )

        return all_runs