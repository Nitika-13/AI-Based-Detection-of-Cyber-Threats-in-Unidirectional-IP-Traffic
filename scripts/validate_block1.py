"""Validation script for Block 1 output.

Verifies that:
1. Every flow in the ground-truth CSV has corresponding packets in the PCAP.
2. Flow keys are unique within each run.
3. Extracted features (packet_count, byte_count) match the CSV.
4. All labels are in the supported set.
5. Every packet's declared IP.len equals its actual serialized IP length.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from scapy.config import conf
from scapy.layers.inet import IP, TCP, UDP  # noqa: F401
from scapy.layers.l2 import Ether
from scapy.utils import rdpcap

# Scapy 2.7.0 on Python 3.14 does not auto-register linktype 1 (Ethernet).
conf.l2types.register(1, Ether)


def validate_run(dataset_dir: Path, run: dict) -> list[str]:
    """Validate a single run/scenario combination. Returns list of errors."""
    errors: list[str] = []
    pcap_path = dataset_dir / run["pcap"]
    labels_path = dataset_dir / run["labels"]

    if not pcap_path.exists():
        errors.append(f"Missing PCAP: {pcap_path}")
        return errors
    if not labels_path.exists():
        errors.append(f"Missing labels: {labels_path}")
        return errors

    # Read ground truth.
    with open(labels_path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        errors.append(f"Empty labels file: {labels_path}")
        return errors

    # Check labels are valid.
    valid_labels = {
        "benign", "ddos", "c2_beacon", "dns_anomaly",
        "port_scan", "exfiltration", "encrypted_anomaly",
    }
    for row in rows:
        if row["label"] not in valid_labels:
            errors.append(f"Invalid label '{row['label']}' in {labels_path}")

    # Check flow keys are unique.
    keys = [r["flow_key"] for r in rows]
    if len(keys) != len(set(keys)):
        errors.append(f"Duplicate flow keys in {labels_path}")

    # Read PCAP and group packets by flow key.
    packets = rdpcap(str(pcap_path))
    pcap_flows: dict[str, list] = {}
    for pkt in packets:
        if "IP" not in pkt:
            continue
        ip = pkt["IP"]
        proto = "tcp" if "TCP" in pkt else "udp" if "UDP" in pkt else "icmp"
        if proto == "tcp":
            sport, dport = pkt["TCP"].sport, pkt["TCP"].dport
        elif proto == "udp":
            sport, dport = pkt["UDP"].sport, pkt["UDP"].dport
        else:
            sport, dport = 0, 0
        key = f"{ip.src}:{sport}->{ip.dst}:{dport}/{proto}"
        pcap_flows.setdefault(key, []).append(pkt)

    # Verify every packet's declared IP.len matches its actual serialized
    # IP length (catches malformed packets with inconsistent headers).
    for pkt in packets:
        if "IP" not in pkt:
            continue
        ip = pkt["IP"]
        actual_len = len(bytes(ip))
        if ip.len != actual_len:
            errors.append(
                f"IP.len mismatch: declared {ip.len}, actual {actual_len} "
                f"({ip.src} -> {ip.dst})"
            )

    # Verify every CSV flow has packets in the PCAP.
    for row in rows:
        key = row["flow_key"]
        if key not in pcap_flows:
            errors.append(f"Flow {key} in CSV has no packets in PCAP")
            continue
        pkts = pcap_flows[key]
        # Verify packet count.
        if len(pkts) != int(row["packet_count"]):
            errors.append(
                f"Flow {key}: packet_count mismatch "
                f"(CSV={row['packet_count']}, PCAP={len(pkts)})"
            )
        # Verify byte count (sum of IP total_length).
        total = sum(p["IP"].len for p in pkts)
        if total != int(row["byte_count"]):
            errors.append(
                f"Flow {key}: byte_count mismatch "
                f"(CSV={row['byte_count']}, PCAP={total})"
            )

    return errors


def main() -> int:
    dataset_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/raw/sih26145")
    manifest_path = dataset_dir / "manifest.json"

    if not manifest_path.exists():
        print(f"ERROR: manifest.json not found at {manifest_path}")
        return 1

    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)

    all_errors: list[str] = []
    for run in manifest["runs"]:
        errors = validate_run(dataset_dir, run)
        status = "OK" if not errors else "FAIL"
        print(f"[{status}] {run['scenario']}/{run['run_id']}")
        for e in errors:
            print(f"  - {e}")
            all_errors.append(e)

    if all_errors:
        print(f"\n{len(all_errors)} error(s) found.")
        return 1

    print(f"\nAll {len(manifest['runs'])} runs validated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())