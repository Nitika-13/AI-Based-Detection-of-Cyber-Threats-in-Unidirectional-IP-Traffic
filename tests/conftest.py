"""Shared pytest fixtures and helpers for the SIH 26145 pipeline tests.

The repository root is added to ``sys.path`` here so that every test module can
import ``traffic_generator`` and ``feature_extractor`` without packaging.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Iterable, Optional

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from traffic_generator.config import (  # noqa: E402
    DIFFICULTY_LEVELS,
    SUPPORTED_LABELS,
    GeneratorConfig,
)
from traffic_generator.generator import TrafficGenerator  # noqa: E402


def generate_dataset(
    outdir: Path,
    *,
    dataset_id: str = "t",
    seed: int = 7,
    runs: int = 3,
    scenarios: Optional[Iterable[str]] = None,
    flow_count: int = 4,
    benign_background: int = 2,
    difficulty: str = "medium",
    duration: float = 30.0,
    split_ratios: Optional[Dict[str, float]] = None,
) -> Path:
    """Generate a small Block 1 dataset under ``outdir`` and return its dir.

    Kept deliberately tiny (a handful of flows per scenario) so the test suite
    stays fast while still exercising every generator code path.
    """
    scenarios = list(scenarios if scenarios is not None else SUPPORTED_LABELS)
    kwargs = dict(
        dataset_id=dataset_id,
        seed=seed,
        outdir=str(outdir),
        runs=runs,
        scenarios=scenarios,
        difficulty=difficulty,
        scenario_flow_counts={s: flow_count for s in scenarios},
        scenario_durations={s: duration for s in scenarios},
        scenario_params={
            s: {"benign_background_flows": benign_background} for s in scenarios
        },
    )
    if split_ratios is not None:
        kwargs["split_ratios"] = split_ratios
    TrafficGenerator(GeneratorConfig(**kwargs)).generate()
    return Path(outdir) / dataset_id


@pytest.fixture(scope="session")
def block1_dataset(tmp_path_factory) -> Path:
    """A 3-run, all-scenario, medium-difficulty Block 1 dataset."""
    outdir = tmp_path_factory.mktemp("block1_raw")
    return generate_dataset(outdir, dataset_id="t", seed=7, runs=3)


@pytest.fixture(scope="session")
def block1_manifest(block1_dataset: Path) -> dict:
    import json

    with open(block1_dataset / "manifest.json", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def difficulty_datasets(tmp_path_factory) -> Dict[str, Path]:
    """One all-scenario dataset per difficulty level (low / medium / high).

    Used to verify that difficulty is expressed through *observable* traffic
    behaviour and that every scenario still satisfies the segmentation
    invariants at every level.
    """
    outdir = tmp_path_factory.mktemp("block1_difficulty")
    datasets: Dict[str, Path] = {}
    for level in DIFFICULTY_LEVELS:
        datasets[level] = generate_dataset(
            outdir,
            dataset_id=f"d_{level}",
            seed=11,
            runs=1,
            scenarios=SUPPORTED_LABELS,
            flow_count=12,
            benign_background=2,
            difficulty=level,
        )
    return datasets


@pytest.fixture(scope="session")
def block2_output(tmp_path_factory, block1_dataset: Path) -> Path:
    """Run Block 2 over the small Block 1 dataset and return the output dir."""
    from feature_extractor.config import ExtractorConfig
    from feature_extractor.extractor import run_extraction

    outdir = tmp_path_factory.mktemp("block2_processed")
    config = ExtractorConfig(dataset_dir=str(block1_dataset), outdir=str(outdir))
    run_extraction(config)
    return Path(outdir) / "t"
