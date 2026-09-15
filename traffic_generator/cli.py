"""Command-line interface for the traffic generator."""

from __future__ import annotations

import argparse
import sys
from typing import Dict, List

from . import __version__
from .config import (
    DEFAULT_DIFFICULTY,
    DIFFICULTY_LEVELS,
    SPLIT_NAMES,
    GeneratorConfig,
    SUPPORTED_LABELS,
)
from .generator import TrafficGenerator


def parse_split_ratios(text: str) -> Dict[str, float]:
    """Parse ``--splits train=0.6,val=0.2,test=0.2`` into a dict."""
    ratios: Dict[str, float] = {}
    for chunk in text.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise argparse.ArgumentTypeError(
                f"Expected NAME=RATIO, got '{chunk}'"
            )
        name, _, value = chunk.partition("=")
        name = name.strip()
        if name not in SPLIT_NAMES:
            raise argparse.ArgumentTypeError(
                f"Unknown split '{name}'. Supported: {', '.join(SPLIT_NAMES)}"
            )
        try:
            ratio = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"Invalid ratio '{value}' for split '{name}'"
            ) from None
        if ratio < 0:
            raise argparse.ArgumentTypeError(
                f"Ratio for split '{name}' must not be negative"
            )
        ratios[name] = ratio
    if not ratios or sum(ratios.values()) <= 0:
        raise argparse.ArgumentTypeError("Split ratios must sum to a positive value")
    return ratios


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="traffic_generator",
        description=(
            "Block 1: Synthetic unidirectional IP traffic generator for "
            "SIH 26145. Generates PCAP + ground-truth labels + metadata. "
            "Packets are only written to a PCAP file; the generator never "
            "transmits on a real network interface."
        ),
    )
    parser.add_argument("--dataset-id", default="sih26145", help="Dataset identifier")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    parser.add_argument("--outdir", default="data/raw", help="Output root directory")
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        help="Independent runs per scenario (each run is one split unit)",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=list(SUPPORTED_LABELS),
        help=f"Scenarios (default: all {len(SUPPORTED_LABELS)})",
    )
    parser.add_argument("--flow-count", type=int, default=20, help="Attack flows per scenario")
    parser.add_argument("--benign-background", type=int, default=10, help="Benign background flows")
    parser.add_argument("--duration", type=float, default=30.0, help="Scenario duration (s)")
    parser.add_argument(
        "--difficulty",
        choices=DIFFICULTY_LEVELS,
        default=DEFAULT_DIFFICULTY,
        help=f"Controlled traffic difficulty (default: {DEFAULT_DIFFICULTY})",
    )
    parser.add_argument(
        "--splits",
        type=parse_split_ratios,
        default=None,
        metavar="train=R,val=R,test=R",
        help="Run-level split ratios (default: train=0.6,val=0.2,test=0.2)",
    )
    parser.add_argument("--version", action="version", version=f"traffic_generator {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    for s in args.scenarios:
        if s not in SUPPORTED_LABELS:
            parser.error(f"Unknown scenario '{s}'. Supported: {', '.join(SUPPORTED_LABELS)}")

    config_kwargs = dict(
        dataset_id=args.dataset_id,
        seed=args.seed,
        outdir=args.outdir,
        runs=args.runs,
        scenarios=args.scenarios,
        difficulty=args.difficulty,
        scenario_flow_counts={s: args.flow_count for s in args.scenarios},
        scenario_durations={s: args.duration for s in args.scenarios},
        scenario_params={
            s: {"benign_background_flows": args.benign_background}
            for s in args.scenarios
        },
    )
    if args.splits is not None:
        config_kwargs["split_ratios"] = args.splits

    config = GeneratorConfig(**config_kwargs)

    generator = TrafficGenerator(config)
    runs = generator.generate()

    total_flows = sum(len(flows) for flows in runs.values())
    total_packets = sum(
        len(f.packets) for flows in runs.values() for f in flows
    )
    print(f"Generated {len(runs)} run/scenario captures")
    print(f"  Runs: {args.runs}   Difficulty: {args.difficulty}")
    print(f"  Total flows: {total_flows}")
    print(f"  Total packets: {total_packets}")
    print(f"  Output: {args.outdir}/{args.dataset_id}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())