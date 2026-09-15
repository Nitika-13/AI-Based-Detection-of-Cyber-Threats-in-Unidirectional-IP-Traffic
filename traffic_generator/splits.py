"""Run-level train/validation/test splitting for the generated dataset.

Splitting is deliberately done at the RUN level, not at the packet or flow
from __future__ import annotations

import math
from typing import Dict, List, Mapping, Sequence

from .config import SPLIT_NAMES


level. All captures generated from one run share the same global seed and the
same scenario parameters, and their flows are only small random variations of
each other. Putting half of one run into training and the other half into
testing would therefore leak near-identical traffic across the split boundary
and make evaluation meaningless.

Rules implemented here:

* every ``run_id`` is assigned to exactly one split ("train" / "val" / "test");
* the assignment is a pure function of the ordered run list and the requested
  ratios, so it is fully reproducible for a fixed number of runs;
* an explicit ``overrides`` mapping always wins, so a specific split can be
  frozen (recommended for a demo or for comparing two model versions);
* assignment is contiguous (runs 1..k -> train, then val, then test) and every
  requested split receives at least one run once there are enough runs, so a
  3-run dataset yields a usable train/val/test triple.

Known limitation (documented deliberately): because the boundaries come from
the requested *ratios* and the *number of runs*, appending runs to an existing
dataset can move a run that sat near a boundary into the neighbouring split.
Block 3 must therefore pin the run count (or use ``overrides``) when it needs a
split that is frozen across dataset regenerations.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Mapping, Sequence, Tuple

from .config import SPLIT_NAMES


def assign_run_splits(
    run_ids: Sequence[str],
    ratios: Mapping[str, float] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> Dict[str, str]:
    """Assign each run_id to a split.

    ``ratios`` must only use the names in :data:`SPLIT_NAMES` and must sum to a
    positive value (it is normalised). ``overrides`` maps individual run_ids to
    a split name and takes precedence over ``ratios``.

    Raises:
        ValueError: on unknown split names, non-positive ratios, or unknown
            run_ids in ``overrides``.
    """
    from .config import DEFAULT_SPLIT_RATIOS

    ratios = dict(ratios if ratios is not None else DEFAULT_SPLIT_RATIOS)
    overrides = dict(overrides or {})

    unknown = set(ratios) - set(SPLIT_NAMES)
    if unknown:
        raise ValueError(
            f"Unknown split name(s) {sorted(unknown)}; expected {SPLIT_NAMES}"
        )
    total_ratio = sum(ratios.values())
    if total_ratio <= 0:
        raise ValueError("Split ratios must sum to a positive value")
    ratios = {name: value / total_ratio for name, value in ratios.items()}

    ordered = list(run_ids)
    unknown_overrides = set(overrides) - set(ordered)
    if unknown_overrides:
        raise ValueError(
            f"Split override for unknown run_id(s): {sorted(unknown_overrides)}"
        )
    bad_values = set(overrides.values()) - set(SPLIT_NAMES)
    if bad_values:
        raise ValueError(
            f"Unknown split name(s) in overrides: {sorted(bad_values)}"
        )

    # Contiguous assignment over the runs that are not explicitly overridden.
    free = [rid for rid in ordered if rid not in overrides]
    counts = _allocate_counts(len(free), ratios)

    splits: Dict[str, str] = {}
    cursor = 0
    for name in SPLIT_NAMES:
        for _ in range(counts.get(name, 0)):
            splits[free[cursor]] = name
            cursor += 1

    splits.update(overrides)
    return {rid: splits[rid] for rid in ordered}


def _allocate_counts(n_runs: int, ratios: Mapping[str, float]) -> Dict[str, int]:
    """Split ``n_runs`` into per-split counts using largest-remainder rounding.

    The counts are computed directly from the full run count (not from a fixed
    per-split minimum), which is as faithful to the requested ratios as integer
    counts allow. Afterwards, any requested split left with zero runs borrows
    one from the currently largest split, so a small dataset still yields a
    usable train/val/test triple.
    """
    if n_runs <= 0:
        return {name: 0 for name in SPLIT_NAMES}

    active = [name for name in SPLIT_NAMES if ratios.get(name, 0.0) > 0.0]
    counts = {name: 0 for name in SPLIT_NAMES}
    if n_runs < len(active):
        # Not enough runs for every requested split: fill in priority order.
        for name in active[:n_runs]:
            counts[name] = 1
        return counts

    exact = {name: n_runs * ratios.get(name, 0.0) for name in active}
    for name in active:
        counts[name] = int(math.floor(exact[name]))

    leftover = n_runs - sum(counts.values())
    if leftover > 0:
        # Largest-remainder, ties broken by SPLIT_NAMES order (deterministic).
        order = sorted(
            active,
            key=lambda n: (-(exact[n] - math.floor(exact[n])), SPLIT_NAMES.index(n)),
        )
        for name in order[:leftover]:
            counts[name] += 1

    # Guarantee at least one run per requested split.
    for name in active:
        if counts[name] > 0:
            continue
        donor = max(active, key=lambda n: (counts[n], -SPLIT_NAMES.index(n)))
        counts[donor] -= 1
        counts[name] = 1
    return counts


def split_summary(splits: Mapping[str, str]) -> Dict[str, Dict[str, object]]:
    """Summarise a run_id -> split mapping for the dataset manifest."""
    summary: Dict[str, Dict[str, object]] = {}
    for name in SPLIT_NAMES:
        run_ids = sorted(rid for rid, split in splits.items() if split == name)
        if not run_ids:
            continue
        summary[name] = {"run_count": len(run_ids), "run_ids": run_ids}
    return summary


def assert_no_run_leakage(splits: Mapping[str, str]) -> None:
    """Raise if any run_id appears in more than one split.

    ``splits`` maps run_id -> split name, so a duplicate key is impossible by
    construction. This guard exists for callers that build per-split run lists
    (e.g. Block 3 loaders) and want to validate them before training.
    """
    seen: Dict[str, str] = {}
    for run_id, split in splits.items():
        if split not in SPLIT_NAMES:
            raise ValueError(f"Unknown split '{split}' for run '{run_id}'")
        if run_id in seen:
            raise ValueError(
                f"Run '{run_id}' appears in splits '{seen[run_id]}' and '{split}'"
            )

def assign_group_splits(
    groups: Sequence[Tuple[str, str]],
    ratios: Mapping[str, float] | None = None,
    overrides: Mapping[str, str] | None = None,
) -> Dict[str, str]:
    """Assign each generation group to a split, keeping the group intact.

    ``groups`` is ordered and contains ``(generation_group_id, run_id)`` pairs
    for every capture. All captures sharing the same ``generation_group_id`` are
    treated as a single atomic unit: they are all assigned to the same split, or
    the function raises.

    Raises:
        ValueError: if captures from the same generation group are assigned to
            more than one split, or if overrides are inconsistent with the group.
    """

    from .config import DEFAULT_SPLIT_RATIOS

    ratios = dict(ratios if ratios is not None else DEFAULT_SPLIT_RATIOS)
    overrides = dict(overrides or {})

    unknown = set(ratios) - set(SPLIT_NAMES)
    if unknown:
        raise ValueError(f"Unknown split name(s) {sorted(unknown)}; expected {SPLIT_NAMES}")
    total_ratio = sum(ratios.values())
    if total_ratio <= 0:
        raise ValueError("Split ratios must sum to a positive value")
    ratios = {name: value / total_ratio for name, value in ratios.items()}

    # Group captures by generation_group_id, preserving first-seen order.
    group_order: List[str] = []
    group_run_ids: Dict[str, List[str]] = defaultdict(list)
    for group_id, run_id in groups:
        if group_id not in group_run_ids:
            group_order.append(group_id)
        group_run_ids[group_id].append(run_id)

    group_splits: Dict[str, str] = {}

    # Apply overrides at the group level: every capture from an overridden group
    # must agree on the same split, otherwise the group is internally split.
    for group_id, run_ids_for_group in group_run_ids.items():
        overrides_for_group = {rid: overrides[rid] for rid in run_ids_for_group if rid in overrides}
        if overrides_for_group:
            if len(set(overrides_for_group.values())) > 1:
                raise ValueError(
                    f"Generation group '{group_id}' contains captures assigned to "
                    f"different splits via overrides: {overrides_for_group}"
                )
            group_splits[group_id] = next(iter(overrides_for_group.values()))

    free_groups = [g for g in group_order if g not in group_splits]
    counts = _allocate_counts(len(free_groups), ratios)

    cursor = 0
    for name in SPLIT_NAMES:
        for _ in range(counts.get(name, 0)):
            group_splits[free_groups[cursor]] = name
            cursor += 1

    # Expand group assignments to every capture.
    capture_splits: Dict[str, str] = {}
    for group_id, run_id in groups:
        if group_id not in group_splits:
            raise ValueError(f"Generation group '{group_id}' was not assigned a split")
        capture_splits[run_id] = group_splits[group_id]

    # Ensure overrides are still honoured.
    capture_splits.update(overrides)
    return capture_splits


def group_to_run_splits(
    groups: Sequence[Tuple[str, str]],
) -> Dict[str, str]:
    """Return the generation_group_id for every run_id, based on the group order.

    This is a helper for manifest/reporting paths that already have per-capture
    ``(generation_group_id, run_id)`` pairs and want a run_id -> group mapping.
    """

    group_of: Dict[str, str] = {}
    for group_id, run_id in groups:
        group_of[run_id] = group_id
    return group_of


def assert_no_group_leakage(
    splits: Mapping[str, str],
    groups: Mapping[str, str],
) -> None:
    """Raise if any generation group appears in more than one split.

    ``splits`` maps run_id -> split.
    ``groups`` maps run_id -> generation_group_id.
    """

    group_split: Dict[str, str] = {}
    for run_id, split in splits.items():
        if split not in SPLIT_NAMES:
            raise ValueError(f"Unknown split '{split}' for run '{run_id}'")
        group_id = groups[run_id]
        if group_id in group_split and group_split[group_id] != split:
            raise ValueError(
                f"Generation group '{group_id}' spans splits '{group_split[group_id]}' "
                f"and '{split}' via run '{run_id}'"
            )
        group_split[group_id] = split


__all__ = [
    "assign_run_splits",
    "assign_group_splits",
    "group_to_run_splits",
    "assert_no_run_leakage",
    "assert_no_group_leakage",
    "split_summary",
]
