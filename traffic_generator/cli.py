"""Command-line interface for the traffic generator."""

from __future__ import annotations

import argparse
import sys
from typing import List

from . import __version__
from .config import GeneratorConfig, SUPPORTED_LABELS
from .generator import TrafficGenerator


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="traffic_generator",
        description=(
            "Block 1: Synthetic unidirectional IP traffic generator for "
            "SIH 26145. Generates PCAP + ground-truth labels + metadata. "
            "Never transmits packets to a real network interface."
        ),
    )
    parser.add_argument("--dataset-id", default="sih26145", help="Dataset identifier")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--outdir", default="data/raw", help="Output root directory")
    parser.add_argument("--runs", type=int, default=1, help="Runs per scenario")
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=list(SUPPORTED_LABELS),
        help=f"Scenarios (default: all {len(SUPPORTED_LABELS)})",
    )
    parser.add_argument("--flow-count", type=int, default=20, help="Attack flows per scenario")
    parser.add_argument("--benign-background", type=int, default=10, help="Benign background flows")
    parser.add_argument("--duration", type=float, default=60.0, help="Scenario duration (s)")
    parser.add_argument("--version", action="version", version=f"traffic_generator {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    for s in args.scenarios:
        if s not in SUPPORTED_LABELS:
            parser.error(f"Unknown scenario '{s}'. Supported: {', '.join(SUPPORTED_LABELS)}")

    config = GeneratorConfig(
        dataset_id=args.dataset_id,
        seed=args.seed,
        outdir=args.outdir,
        runs=args.runs,
        scenarios=args.scenarios,
        scenario_flow_counts={s: args.flow_count for s in args.scenarios},
        scenario_durations={s: args.duration for s in args.scenarios},
        scenario_params={
            s: {"benign_background_flows": args.benign_background}
            for s in args.scenarios
        },
    )

    generator = TrafficGenerator(config)
    runs = generator.generate()

    total_flows = sum(len(flows) for flows in runs.values())
    total_packets = sum(
        len(f.packets) for flows in runs.values() for f in flows
    )
    print(f"Generated {len(runs)} run/scenario combinations")
    print(f"  Total flows: {total_flows}")
    print(f"  Total packets: {total_packets}")
    print(f"  Output: {args.outdir}/{args.dataset_id}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())