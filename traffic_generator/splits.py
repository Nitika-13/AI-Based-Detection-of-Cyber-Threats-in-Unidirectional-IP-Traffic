from __future__ import annotations

import math
import random
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


def split_summary(
    splits: Mapping[str, str],
    group_splits: Mapping[str, str] | None = None,
    capture_splits: Mapping[str, str] | None = None,
) -> Dict[str, Dict[str, object]]:
    """Summarise a run_id / group_id -> split mapping for the dataset manifest."""
    summary: Dict[str, Dict[str, object]] = {}
    for name in SPLIT_NAMES:
        run_ids = sorted(rid for rid, split in splits.items() if split == name)
        if not run_ids and not (group_splits and any(s == name for s in group_splits.values())):
            continue
        entry: Dict[str, object] = {
            "run_count": len(run_ids),
            "run_ids": run_ids,
        }
        if group_splits is not None:
            gids = sorted(gid for gid, split in group_splits.items() if split == name)
            entry["group_count"] = len(gids)
            entry["group_ids"] = gids
        if capture_splits is not None:
            cids = sorted(cid for cid, split in capture_splits.items() if split == name)
            entry["capture_count"] = len(cids)
            entry["capture_ids"] = cids
        summary[name] = entry
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
    seed: int | None = None,
) -> Dict[str, str]:
    """Assign each generation group to a split, keeping the group intact.

    ``groups`` is ordered and contains ``(generation_group_id, item_id)`` pairs
    for every capture (or run). All captures sharing the same ``generation_group_id``
    are treated as a single atomic unit: they are all assigned to the same split.

    If ``seed`` is provided, the unique groups are permuted deterministically
    prior to allocation.

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

    # Group items by generation_group_id, preserving first-seen order.
    group_order: List[str] = []
    group_item_ids: Dict[str, List[str]] = defaultdict(list)
    for group_id, item_id in groups:
        if group_id not in group_item_ids:
            group_order.append(group_id)
        group_item_ids[group_id].append(item_id)

    group_splits: Dict[str, str] = {}

    # Apply overrides at the group level: every capture from an overridden group
    # must agree on the same split, otherwise the group is internally split.
    for group_id, items_for_group in group_item_ids.items():
        overrides_for_group = {}
        if group_id in overrides:
            overrides_for_group[group_id] = overrides[group_id]
        for item_id in items_for_group:
            if item_id in overrides:
                overrides_for_group[item_id] = overrides[item_id]
        if overrides_for_group:
            unique_splits = set(overrides_for_group.values())
            if len(unique_splits) > 1:
                raise ValueError(
                    f"Generation group '{group_id}' contains captures assigned to "
                    f"different splits via overrides: {overrides_for_group}"
                )
            group_splits[group_id] = next(iter(unique_splits))

    free_groups = [g for g in group_order if g not in group_splits]

    # Permute groups deterministically if a seed is provided
    if seed is not None:
        rng = random.Random(seed)
        shuffled = list(free_groups)
        rng.shuffle(shuffled)
        free_groups = shuffled

    counts = _allocate_counts(len(free_groups), ratios)

    cursor = 0
    for name in SPLIT_NAMES:
        for _ in range(counts.get(name, 0)):
            group_splits[free_groups[cursor]] = name
            cursor += 1

    # Expand group assignments to every capture / item.
    item_splits: Dict[str, str] = {}
    for group_id, item_id in groups:
        if group_id not in group_splits:
            raise ValueError(f"Generation group '{group_id}' was not assigned a split")
        item_splits[item_id] = group_splits[group_id]

    # Ensure overrides are still honoured.
    item_splits.update(overrides)
    return item_splits


def group_to_run_splits(
    groups: Sequence[Tuple[str, str]],
) -> Dict[str, str]:
    """Return the generation_group_id for every item_id, based on the group order.

    This is a helper for manifest/reporting paths that already have per-capture
    ``(generation_group_id, item_id)`` pairs and want an item_id -> group mapping.
    """

    group_of: Dict[str, str] = {}
    for group_id, item_id in groups:
        group_of[item_id] = group_id
    return group_of


def assert_no_group_leakage(
    splits: Mapping[str, str],
    groups: Mapping[str, str],
) -> None:
    """Raise if any generation group appears in more than one split.

    ``splits`` maps item_id -> split.
    ``groups`` maps item_id -> generation_group_id.
    """

    group_split: Dict[str, str] = {}
    for item_id, split in splits.items():
        if split not in SPLIT_NAMES:
            raise ValueError(f"Unknown split '{split}' for item '{item_id}'")
        group_id = groups.get(item_id, item_id)
        if group_id in group_split and group_split[group_id] != split:
            raise ValueError(
                f"Generation group '{group_id}' spans splits '{group_split[group_id]}' "
                f"and '{split}' via item '{item_id}'"
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
