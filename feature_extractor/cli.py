"""Command-line interface for the NetFlow feature extractor."""

from __future__ import annotations

import argparse
import sys
from typing import List

from .config import ExtractorConfig
from .extractor import run_extraction


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="feature_extractor",
        description=(
            "Block 2: NetFlow-style feature extractor for SIH 26145. "
            "Reads Block 1 PCAPs (read-only), reconstructs unidirectional "
            "flows, computes ML-ready features, validates against "
            "ground truth, and writes data/processed outputs."
        ),
    )
    parser.add_argument(
        "--dataset-dir",
        default="data/raw/sih26145",
        help="Block 1 dataset directory (default: data/raw/sih26145)",
    )
    parser.add_argument(
        "--outdir",
        default="data/processed",
        help="Output root directory (default: data/processed)",
    )
    parser.add_argument(
        "--scenarios",
        nargs="+",
        default=[],
        help="Optional scenario filter (default: all in manifest)",
    )
    parser.add_argument(
        "--no-strict",
        action="store_true",
        help="Do not exit non-zero on validation mismatches",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    config = ExtractorConfig(
        dataset_dir=args.dataset_dir,
        outdir=args.outdir,
        strict=not args.no_strict,
        scenarios=args.scenarios,
    )

    report = run_extraction(config)

    if config.strict and report["overall_status"] != "PASS":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())