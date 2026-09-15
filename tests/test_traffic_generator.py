"""Tests for Block 1 (traffic_generator).

Covers: the seven scenarios, C2 flow-boundary consistency (the headline fix),
per-flow segmentation invariants, determinism across seeds, run-level
split assignment, the manifest contract, and difficulty observability.
"""

from __future__ import annotations

import collections
import csv
import hashlib
import json
from pathlib import Path

import pytest

from conftest import generate_dataset
from traffic_generator.config import (
    DATASET_VERSION,
    DIFFICULTY_LEVELS,
    MAX_FLOW_DURATION_SECONDS,
    MAX_INTER_PACKET_GAP_SECONDS,
    SPLIT_NAMES,
    SUPPORTED_LABELS,
)
from traffic_generator.labels import CSV_COLUMNS
from traffic_generator.scenarios import SCENARIO_REGISTRY
from traffic_generator.splits import (
    assert_no_run_leakage,
    assign_run_splits,
    split_summary,
)

# Ground-truth columns are a frozen contract (Block 2 joins on them).
EXPECTED_CSV_COLUMNS = [
    "flow_id",
    "run_id",
    "scenario",
    "label",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "flow_key",
    "start_ts",
    "end_ts",
    "duration",
    "packet_count",
    "byte_count",
    "tcp_flags",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def read_packets(pcap_path: Path):
    """Read a Block 1 PCAP with Scapy (read-only)."""
    from scapy.config import conf
    from scapy.layers.inet import IP, TCP, UDP  # noqa: F401  (enable dissection)
    from scapy.layers.l2 import Ether
    from scapy.utils import rdpcap

    conf.l2types.register(1, Ether)
    return rdpcap(str(pcap_path))


def tcp_flow_index(pcap_path: Path) -> "collections.OrderedDict[str, dict]":
    """Summarise TCP flows in a PCAP in file (= timestamp) order.

    Returns ``{flow_key: {...}}`` with SYN/FIN/RST counts, packet count, the
    flags of the final packet and total transport payload bytes.
    """
    info: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
    for pkt in read_packets(pcap_path):
        if "IP" not in pkt or "TCP" not in pkt:
            continue
        ip, tcp = pkt["IP"], pkt["TCP"]
        key = f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}/tcp"
        rec = info.setdefault(
            key,
            {"syn": 0, "fin": 0, "rst": 0, "count": 0, "last_flags": "",
             "payload_bytes": 0, "timestamps": []},
        )
        flags = str(tcp.flags)
        rec["syn"] += int("S" in flags)
        rec["fin"] += int("F" in flags)
        rec["rst"] += int("R" in flags)
        rec["count"] += 1
        rec["last_flags"] = flags
        rec["payload_bytes"] += len(bytes(tcp.payload))
        rec["timestamps"].append(float(pkt.time))
    return info


def read_gt_rows(dataset_dir: Path, pattern: str = "*.csv"):
    """Yield every ground-truth row from the dataset's label files."""
    for label_file in sorted((dataset_dir / "labels").glob(pattern)):
        with open(label_file, newline="", encoding="utf-8") as f:
            yield from csv.DictReader(f)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Scenario coverage
# ---------------------------------------------------------------------------


class TestScenarioCoverage:
    def test_registry_has_exactly_the_seven_scenarios(self):
        assert sorted(SCENARIO_REGISTRY) == sorted(SUPPORTED_LABELS)
        assert len(SUPPORTED_LABELS) == 7

    def test_every_attack_scenario_emits_its_own_label_and_benign(self, block1_dataset):
        rows = list(read_gt_rows(block1_dataset))
        labels = {r["label"] for r in rows}
        assert labels == set(SUPPORTED_LABELS)
        # Each attack scenario capture must contain both anomaly + benign flows.
        per_capture: dict = collections.defaultdict(set)
        for row in rows:
            per_capture[(row["run_id"], row["scenario"])].add(row["label"])
        for (run_id, scenario), seen in per_capture.items():
            if scenario == "benign":
                assert seen == {"benign"}, (run_id, scenario, seen)
            else:
                assert scenario in seen, (run_id, scenario, seen)
                assert "benign" in seen, (run_id, scenario, seen)

    def test_ground_truth_columns_unchanged(self, block1_dataset):
        """The GT CSV header is a frozen Block 1 -> Block 2 contract."""
        first = sorted((block1_dataset / "labels").glob("*.csv"))[0]
        with open(first, newline="", encoding="utf-8") as f:
            header = next(csv.reader(f))
        assert header == EXPECTED_CSV_COLUMNS
        assert CSV_COLUMNS == EXPECTED_CSV_COLUMNS

    def test_every_flow_has_packets_and_one_label(self, block1_dataset):
        for label_file in sorted((block1_dataset / "labels").glob("*.csv")):
            with open(label_file, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            assert rows, f"empty labels file {label_file}"
            keys = [r["flow_key"] for r in rows]
            assert len(keys) == len(set(keys)), f"duplicate flow_key in {label_file}"
            ids = [r["flow_id"] for r in rows]
            assert len(ids) == len(set(ids)), f"duplicate flow_id in {label_file}"
            for row in rows:
                assert int(row["packet_count"]) >= 1
                assert int(row["byte_count"]) >= 40
                assert row["label"] in SUPPORTED_LABELS


# ---------------------------------------------------------------------------
# C2 flow-boundary consistency (the core generator fix)
# ---------------------------------------------------------------------------


class TestC2FlowConsistency:
    """A C2 channel must be ONE TCP connection, so plain flow reconstruction
    (including FIN/RST closing) yields exactly one flow per ground-truth row."""

    def _c2_captures(self, dataset_dir: Path):
        for pcap in sorted((dataset_dir / "pcap").glob("*c2_beacon*.pcap")):
            yield pcap, dataset_dir / "labels" / (pcap.stem + ".csv")

    def test_exactly_one_syn_and_one_fin_per_c2_flow(self, block1_dataset):
        checked = 0
        for pcap, label_path in self._c2_captures(block1_dataset):
            with open(label_path, newline="", encoding="utf-8") as f:
                gt = {
                    r["flow_key"]: r
                    for r in csv.DictReader(f)
                    if r["label"] == "c2_beacon"
                }
            assert gt, f"no c2_beacon flows in {label_path}"
            index = tcp_flow_index(pcap)
            for key, row in gt.items():
                rec = index[key]
                assert rec["syn"] == 1, f"{key}: {rec['syn']} SYNs (expected 1)"
                assert rec["fin"] == 1, f"{key}: {rec['fin']} FINs (expected 1)"
                assert rec["rst"] == 0, f"{key}: unexpected RST packets"
                # The single close must be the LAST packet of the flow.
                assert "F" in rec["last_flags"], f"{key}: last packet is not FIN"
                checked += 1
        assert checked > 0

    def test_gt_packet_count_matches_pcap(self, block1_dataset):
        for pcap, label_path in self._c2_captures(block1_dataset):
            with open(label_path, newline="", encoding="utf-8") as f:
                gt = {
                    r["flow_key"]: r
                    for r in csv.DictReader(f)
                    if r["label"] == "c2_beacon"
                }
            index = tcp_flow_index(pcap)
            for key, row in gt.items():
                assert index[key]["count"] == int(row["packet_count"]), key

    def test_first_packet_is_syn(self, block1_dataset):
        """The connection must OPEN before any beacon is sent."""
        for pcap, label_path in self._c2_captures(block1_dataset):
            packets = read_packets(pcap)
            with open(label_path, newline="", encoding="utf-8") as f:
                gt = {
                    r["flow_key"]
                    for r in csv.DictReader(f)
                    if r["label"] == "c2_beacon"
                }
            first_flags: dict = {}
            for pkt in packets:
                if "TCP" not in pkt:
                    continue
                ip, tcp = pkt["IP"], pkt["TCP"]
                key = f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}/tcp"
                if key in gt and key not in first_flags:
                    first_flags[key] = str(tcp.flags)
            assert set(first_flags) == gt
            for key, flags in first_flags.items():
                assert flags == "S", f"{key}: first packet flags '{flags}'"

    def test_beacons_are_periodic(self, block1_dataset):
        """Inter-arrival variability must be low: that is the C2 signature."""
        for pcap, label_path in self._c2_captures(block1_dataset):
            index = tcp_flow_index(pcap)
            with open(label_path, newline="", encoding="utf-8") as f:
                gt = {
                    r["flow_key"]
                    for r in csv.DictReader(f)
                    if r["label"] == "c2_beacon"
                }
            for key in gt:
                ts = index[key]["timestamps"]
                gaps = [b - a for a, b in zip(ts, ts[1:])]
                assert gaps, key
                mean = sum(gaps) / len(gaps)
                assert mean > 0.5, f"{key}: beacons are not spaced out"
                spread = max(gaps) - min(gaps)
                assert spread < 0.35 * mean, f"{key}: beacons are not regular"

    def test_c2_flows_carry_small_volumes(self, block1_dataset):
        """C2 must look low-volume (small beacons), not bulk transfer."""
        for pcap, label_path in self._c2_captures(block1_dataset):
            index = tcp_flow_index(pcap)
            with open(label_path, newline="", encoding="utf-8") as f:
                gt = [r for r in csv.DictReader(f) if r["label"] == "c2_beacon"]
            for row in gt:
                rec = index[row["flow_key"]]
                per_packet = int(row["byte_count"]) / int(row["packet_count"])
                assert per_packet < 300, f"{row['flow_key']}: not low volume"
                assert rec["payload_bytes"] > 0, "beacons must carry data"


# ---------------------------------------------------------------------------
# Segmentation invariants (what Block 2's boundary rules depend on)
# ---------------------------------------------------------------------------


def captures(dataset_dir: Path):
    """Yield (pcap_path, label_path) for every capture in a dataset."""
    for pcap in sorted((dataset_dir / "pcap").glob("*.pcap")):
        yield pcap, dataset_dir / "labels" / (pcap.stem + ".csv")


class TestSegmentationInvariants:
    def test_no_flow_exceeds_duration_limit(self, difficulty_datasets):
        """Every GT flow at every difficulty must respect the active timeout.

        If this fails, Block 2 would legitimately split a ground-truth flow.
        """
        checked = 0
        for level, dataset in difficulty_datasets.items():
            for pcap, label_path in captures(dataset):
                with open(label_path, newline="", encoding="utf-8") as f:
                    rows = list(csv.DictReader(f))
                assert rows
                for row in rows:
                    duration = float(row["duration"])
                    assert duration <= MAX_FLOW_DURATION_SECONDS, (
                        f"{level}/{pcap.stem}/{row['flow_key']}: "
                        f"duration {duration}"
                    )
                    checked += 1
        assert checked > 0

    def test_no_intra_flow_gap_exceeds_idle_guarantee(self, difficulty_datasets):
        """Checked at the packet level, since GT only stores total duration."""
        for level, dataset in difficulty_datasets.items():
            for pcap, _ in captures(dataset):
                by_key: dict = collections.defaultdict(list)
                for pkt in read_packets(pcap):
                    if "IP" not in pkt:
                        continue
                    ip = pkt["IP"]
                    if "TCP" in pkt:
                        proto, sp, dp = "tcp", pkt["TCP"].sport, pkt["TCP"].dport
                    elif "UDP" in pkt:
                        proto, sp, dp = "udp", pkt["UDP"].sport, pkt["UDP"].dport
                    else:
                        proto, sp, dp = "icmp", 0, 0
                    by_key[f"{ip.src}:{sp}->{ip.dst}:{dp}/{proto}"].append(float(pkt.time))
                for key, ts in by_key.items():
                    gaps = [b - a for a, b in zip(ts, ts[1:])]
                    if not gaps:
                        continue
                    assert max(gaps) <= MAX_INTER_PACKET_GAP_SECONDS + 1e-9, (
                        f"{level}/{pcap.stem}/{key}: max gap {max(gaps)}"
                    )

    def test_pcap_structure_and_ip_lengths(self, block1_dataset):
        """Ethernet/IPv4 structure, IP total-length correctness, timestamps."""
        for pcap, _ in captures(block1_dataset):
            last_ts = -1.0
            for pkt in read_packets(pcap):
                assert "Ether" in pkt, f"{pcap.name}: non-Ethernet frame"
                assert "IP" in pkt, f"{pcap.name}: non-IPv4 frame"
                ip = pkt["IP"]
                assert ip.version == 4
                assert int(ip.len) == len(bytes(ip)), (
                    f"{pcap.name}: IP.len {ip.len} != actual {len(bytes(ip))}"
                )
                assert ip.proto in (1, 6, 17), f"unexpected IP proto {ip.proto}"
                ts = float(pkt.time)
                assert ts > 0
                assert ts >= last_ts, f"{pcap.name}: timestamps not monotonic"
                last_ts = ts


# ---------------------------------------------------------------------------
# Difficulty must be observable in the traffic (and must not be a feature)
# ---------------------------------------------------------------------------


def rows_for(dataset: Path, scenario: str, label: str) -> list:
    """Return ground-truth rows for one scenario/label from a dataset."""
    matches = sorted((dataset / "labels").glob(f"*__{scenario}__run_001.csv"))
    assert matches, f"no capture for scenario '{scenario}' in {dataset}"
    with open(matches[0], newline="", encoding="utf-8") as f:
        rows = [r for r in csv.DictReader(f) if r["label"] == label]
    assert rows, f"no {label} rows in {matches[0]}"
    return rows


def mean_packet_size(rows: list) -> float:
    return sum(int(r["byte_count"]) / int(r["packet_count"]) for r in rows) / len(rows)


def mean_iat(rows: list) -> float:
    """Mean inter-arrival time derived from GT duration / packet_count.

    Only multi-packet flows have a defined inter-arrival time.
    """
    values = []
    for row in rows:
        n = int(row["packet_count"])
        if n > 1:
            values.append(float(row["duration"]) / (n - 1))
    assert values, "no multi-packet flows to measure inter-arrival time from"
    return sum(values) / len(values)


class TestDifficultyObservability:
    def test_ddos_intensity_increases_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "ddos", "ddos")
        high = rows_for(difficulty_datasets["high"], "ddos", "ddos")
        low_pkts = sum(int(r["packet_count"]) for r in low) / len(low)
        high_pkts = sum(int(r["packet_count"]) for r in high) / len(high)
        assert high_pkts > low_pkts, "HIGH DDoS should send more packets per flow"
        assert mean_iat(high) < mean_iat(low), "HIGH DDoS should be faster"

    def test_ddos_source_diversity_grows_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "ddos", "ddos")
        high = rows_for(difficulty_datasets["high"], "ddos", "ddos")
        low_src = len({r["src_ip"] for r in low})
        high_src = len({r["src_ip"] for r in high})
        assert low_src <= 5, f"LOW DDoS should use a small source pool, got {low_src}"
        assert high_src > low_src, f"HIGH sources {high_src} vs LOW {low_src}"

    def test_port_scan_host_fanout_grows_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "port_scan", "port_scan")
        high = rows_for(difficulty_datasets["high"], "port_scan", "port_scan")
        low_hosts = len({r["dst_ip"] for r in low})
        high_hosts = len({r["dst_ip"] for r in high})
        assert low_hosts == 1, "LOW scan targets a single host"
        assert high_hosts > low_hosts, "HIGH scan should fan out across hosts"

    def test_port_scan_rate_increases_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "port_scan", "port_scan")
        high = rows_for(difficulty_datasets["high"], "port_scan", "port_scan")
        assert mean_iat(high) < mean_iat(low), "HIGH scan should probe faster"

    def test_c2_beacon_interval_decreases_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "c2_beacon", "c2_beacon")
        high = rows_for(difficulty_datasets["high"], "c2_beacon", "c2_beacon")
        assert mean_iat(low) > mean_iat(high), "HIGH C2 beacons faster than LOW"

    def test_c2_destination_set_grows_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "c2_beacon", "c2_beacon")
        high = rows_for(difficulty_datasets["high"], "c2_beacon", "c2_beacon")
        assert len({r["dst_ip"] for r in low}) == 1
        assert len({r["dst_ip"] for r in high}) > 1

    def test_dns_qname_length_grows_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "dns_anomaly", "dns_anomaly")
        high = rows_for(difficulty_datasets["high"], "dns_anomaly", "dns_anomaly")
        assert mean_packet_size(high) > mean_packet_size(low)

    def test_exfiltration_volume_grows_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "exfiltration", "exfiltration")
        high = rows_for(difficulty_datasets["high"], "exfiltration", "exfiltration")
        low_bytes = sum(int(r["byte_count"]) for r in low) / len(low)
        high_bytes = sum(int(r["byte_count"]) for r in high) / len(high)
        assert high_bytes > low_bytes

    def test_encrypted_record_size_grows_with_difficulty(self, difficulty_datasets):
        low = rows_for(difficulty_datasets["low"], "encrypted_anomaly", "encrypted_anomaly")
        high = rows_for(difficulty_datasets["high"], "encrypted_anomaly", "encrypted_anomaly")
        assert mean_packet_size(high) > mean_packet_size(low)

    def test_difficulty_is_not_written_into_ground_truth(self, difficulty_datasets):
        """Difficulty is an evaluation knob, never an ML input or a label field."""
        for dataset in difficulty_datasets.values():
            for label_file in sorted((dataset / "labels").glob("*.csv")):
                with open(label_file, newline="", encoding="utf-8") as f:
                    header = next(csv.reader(f))
                assert "difficulty" not in header


# ---------------------------------------------------------------------------
# Determinism and multiple independent runs
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_seed_is_byte_identical(self, tmp_path):
        a = generate_dataset(tmp_path, dataset_id="a", seed=123, runs=2,
                             flow_count=3, benign_background=2, duration=20.0)
        b = generate_dataset(tmp_path, dataset_id="b", seed=123, runs=2,
                             flow_count=3, benign_background=2, duration=20.0)
        compared = 0
        for sub in ("pcap", "labels"):
            for path_a in sorted((a / sub).iterdir()):
                path_b = b / sub / path_a.name.replace("a__", "b__")
                assert path_b.exists(), f"missing {path_b}"
                assert sha256(path_a) == sha256(path_b), f"differs: {path_a.name}"
                compared += 1
        assert compared > 0

    def test_different_seed_produces_different_traffic(self, tmp_path):
        a = generate_dataset(tmp_path, dataset_id="a", seed=1, runs=1,
                             scenarios=["benign"], flow_count=5, duration=20.0)
        b = generate_dataset(tmp_path, dataset_id="b", seed=2, runs=1,
                             scenarios=["benign"], flow_count=5, duration=20.0)
        pa = sorted((a / "pcap").glob("*.pcap"))[0]
        pb = sorted((b / "pcap").glob("*.pcap"))[0]
        assert sha256(pa) != sha256(pb)

    def test_runs_are_independent(self, tmp_path):
        """Different runs must not be near-duplicates of each other."""
        dataset = generate_dataset(tmp_path, dataset_id="t", seed=9, runs=4,
                                   scenarios=["exfiltration"], flow_count=4,
                                   benign_background=0, duration=20.0)
        digests = {sha256(p) for p in sorted((dataset / "pcap").glob("*.pcap"))}
        assert len(digests) == 4, "runs produced identical captures"

    def test_metadata_is_valid_json_with_identity(self, block1_dataset):
        for path in sorted((block1_dataset / "metadata").glob("*.json")):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            assert data["run_id"]
            assert data["capture_id"]
            assert data["difficulty"] in DIFFICULTY_LEVELS


# ---------------------------------------------------------------------------
# Run-level split assignment (no data leakage)
# ---------------------------------------------------------------------------


class TestRunSplits:
    def test_every_run_gets_exactly_one_split(self):
        run_ids = [f"run_{i:03d}" for i in range(1, 8)]
        splits = assign_run_splits(run_ids)
        assert set(splits) == set(run_ids)
        assert set(splits.values()) <= set(SPLIT_NAMES)
        assert_no_run_leakage(splits)

    def test_all_splits_used_when_runs_allow(self):
        splits = assign_run_splits([f"run_{i:03d}" for i in range(1, 4)])
        assert sorted(splits.values()) == ["test", "train", "val"]

    def test_assignment_is_deterministic(self):
        run_ids = [f"run_{i:03d}" for i in range(1, 11)]
        assert assign_run_splits(run_ids) == assign_run_splits(run_ids)

    def test_split_counts_follow_the_requested_ratios(self):
        """Counts must be as close to the ratios as integer counts allow."""
        expected = {
            3: {"train": 1, "val": 1, "test": 1},
            4: {"train": 2, "val": 1, "test": 1},
            5: {"train": 3, "val": 1, "test": 1},
            7: {"train": 4, "val": 2, "test": 1},
            10: {"train": 6, "val": 2, "test": 2},
            15: {"train": 9, "val": 3, "test": 3},
            20: {"train": 12, "val": 4, "test": 4},
        }
        for n_runs, want in expected.items():
            splits = assign_run_splits([f"run_{i:03d}" for i in range(1, n_runs + 1)])
            got: dict = collections.Counter(splits.values())
            assert dict(got) == want, f"n_runs={n_runs}: got {dict(got)} want {want}"
            assert sum(got.values()) == n_runs

    def test_split_is_a_function_of_run_count_not_of_run_identity(self):
        """Documents the intended semantics: the split unit is the run index.

        A run's split may move when the total number of runs changes, so Block 3
        must pin the run count (or use ``overrides``) for a frozen split. This
        test exists to make that limitation explicit rather than silent.
        """
        ten = assign_run_splits([f"run_{i:03d}" for i in range(1, 11)])
        fifteen = assign_run_splits([f"run_{i:03d}" for i in range(1, 16)])
        assert ten != fifteen
        # run_001 is always train; the tail run is always test.
        assert ten["run_001"] == fifteen["run_001"] == "train"
        assert ten["run_010"] == fifteen["run_015"] == "test"

    def test_explicit_overrides_give_a_frozen_split(self):
        """The supported way to pin a split across dataset regenerations."""
        run_ids = [f"run_{i:03d}" for i in range(1, 6)]
        overrides = {"run_001": "train", "run_002": "val", "run_003": "test"}
        small = assign_run_splits(run_ids, overrides=overrides)
        larger = assign_run_splits(
            run_ids + [f"run_{i:03d}" for i in range(6, 11)], overrides=overrides
        )
        for run_id, split in overrides.items():
            assert small[run_id] == split
            assert larger[run_id] == split

    def test_explicit_overrides_win(self):
        run_ids = ["run_001", "run_002", "run_003"]
        splits = assign_run_splits(run_ids, overrides={"run_003": "test"})
        assert splits["run_003"] == "test"

    def test_unknown_split_name_is_rejected(self):
        with pytest.raises(ValueError):
            assign_run_splits(["run_001"], {"everything": 1.0})

    def test_all_zero_ratios_rejected(self):
        with pytest.raises(ValueError):
            assign_run_splits(["run_001"], {"train": 0.0, "val": 0.0, "test": 0.0})

    def test_split_summary_counts(self):
        summary = split_summary({"run_001": "train", "run_002": "test"})
        assert summary["train"]["run_count"] == 1
        assert summary["test"]["run_ids"] == ["run_002"]
        assert "val" not in summary

    def test_manifest_carries_run_level_splits(self, block1_manifest):
        """Splits must be declared in the manifest so Block 3 never guesses."""
        splits_by_run: dict = {}
        for run in block1_manifest["runs"]:
            splits_by_run.setdefault(run["run_id"], set()).add(run["split"])
        for run_id, seen in splits_by_run.items():
            assert len(seen) == 1, f"{run_id} spans multiple splits: {seen}"
        assert "run_ids" in block1_manifest["splits"]["train"]


# ---------------------------------------------------------------------------
# Manifest contract
# ---------------------------------------------------------------------------


class TestManifestContract:
    def test_required_keys_present(self, block1_manifest):
        for key in (
            "dataset_id",
            "dataset_version",
            "generator_version",
            "seed",
            "difficulty",
            "created_at",
            "split_ratios",
            "splits",
            "conventions",
            "runs",
        ):
            assert key in block1_manifest, f"manifest missing '{key}'"
        assert block1_manifest["dataset_version"] == DATASET_VERSION

    def test_run_entries_keep_legacy_keys_and_add_identity(self, block1_manifest):
        for run in block1_manifest["runs"]:
            for key in ("run_id", "scenario", "pcap", "labels", "metadata"):
                assert key in run, f"run entry missing legacy key '{key}'"
            for key in (
                "capture_id",
                "capture_index",
                "split",
                "difficulty",
                "seed",
                "flow_count",
                "packet_count",
                "params",
            ):
                assert key in run, f"run entry missing new key '{key}'"
            assert run["difficulty"] in DIFFICULTY_LEVELS
            assert run["split"] in SPLIT_NAMES

    def test_capture_ids_unique_and_files_exist(self, block1_dataset, block1_manifest):
        capture_ids = [r["capture_id"] for r in block1_manifest["runs"]]
        assert len(capture_ids) == len(set(capture_ids))
        identifiers = [(r["run_id"], r["scenario"]) for r in block1_manifest["runs"]]
        assert len(identifiers) == len(set(identifiers))
        for run in block1_manifest["runs"]:
            for key in ("pcap", "labels", "metadata"):
                assert (block1_dataset / run[key]).exists(), run[key]

    def test_manifest_run_count_matches_configuration(self, block1_manifest):
        assert len(block1_manifest["runs"]) == 3 * len(SUPPORTED_LABELS)

    def test_conventions_document_segmentation_contract(self, block1_manifest):
        conventions = block1_manifest["conventions"]
        assert conventions["idle_timeout_seconds"] == 15.0
        assert conventions["active_timeout_seconds"] == 30.0
        assert conventions["max_flow_duration_seconds"] == MAX_FLOW_DURATION_SECONDS
        assert conventions["split_unit"] == "run_id"

    def test_metadata_seed_matches_manifest(self, block1_dataset, block1_manifest):
        for run in block1_manifest["runs"]:
            with open(block1_dataset / run["metadata"], encoding="utf-8") as f:
                meta = json.load(f)
            assert meta["seed"] == run["seed"]
            assert meta["capture_id"] == run["capture_id"]
            assert meta["split"] == run["split"]
            assert meta["difficulty"] == run["difficulty"]
            assert meta["flow_count"] == run["flow_count"]