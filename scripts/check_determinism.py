"""Determinism check: compare two generated datasets byte-for-byte."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    dir_a = Path(sys.argv[1])
    dir_b = Path(sys.argv[2])
    prefix_a = f"{dir_a.name}__"
    prefix_b = f"{dir_b.name}__"

    mismatches = 0
    checked = 0

    for sub in ("labels", "pcap"):
        for path_a in sorted((dir_a / sub).iterdir()):
            name_b = path_a.name.replace(prefix_a, prefix_b)
            path_b = dir_b / sub / name_b
            if not path_b.exists():
                print(f"MISSING: {path_b}")
                mismatches += 1
                continue
            checked += 1
            if sha256(path_a) != sha256(path_b):
                print(f"MISMATCH: {sub}/{path_a.name}")
                mismatches += 1

    if mismatches == 0:
        print(f"ALL DETERMINISTIC: {checked} file pairs identical")
        return 0
    print(f"{mismatches} mismatch(es) found")
    return 1


if __name__ == "__main__":
    sys.exit(main())