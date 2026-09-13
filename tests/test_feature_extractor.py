"""Tests for Block 2 (feature_extractor).

Covers: packet parsing, flow reconstruction (boundary rules), feature
calculation, GT joining, and validation. Unit tests use synthetic
PacketRecords; integration tests use the Block 1 dataset when present.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from feature_extractor.config import (  # noqa: E402
    ACTIVE_TIMEOUT_SECONDS,
    IDLE_TIMEOUT_SECONDS,
)
from feature_extractor.features import (  # noqa: E402
    assign_flow_ids,
    compute_flow_features,
)
from feature_extractor.flow_reconstructor import (  # noqa: E402
    reconstruct_flows,
    segment_flow,
)
from feature_extractor.labels import join_labels, read_ground_truth  # noqa: E402
from feature_extractor.models import PacketRecord, make_flow_key  # noqa: E402
from feature_extractor.validation import validate_run  # noqa: E402

IDLE = IDLE_TIMEOUT_SECONDS
ACTIVE = ACTIVE_TIMEOUT_SECONDS


def mk(
    ts: float,
    *,
    src="10.0.0.1",
    sport=1000,
    dst="10.0.1.1",
    dport=80,
    proto="tcp",
    ip_len=40,
    flags=None,
) -> PacketRecord:
    return PacketRecord(
        src_ip=src,
        src_port=sport,
        dst_ip=dst,
        dst_port=dport,
        protocol=proto,
        timestamp=ts,
        ip_len=ip_len,
        tcp_flags=flags,
    )


# ---------------------------------------------------------------------------
# Flow reconstruction
# ---------------------------------------------------------------------------


class TestFlowReconstruction:
    def test_single_flow_same_tuple(self):
        pkts = [mk(1.0), mk(2.0), mk(3.0)]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 1
        assert len(flows[0]) == 3

    def test_direction_sensitive_split(self):
        # Reverse direction = different 5-tuple = different flow.
        pkts = [mk(1.0), mk(1.1, src="10.0.1.1", sport=80, dst="10.0.0.1", dport=1000)]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 2

    def test_idle_timeout_splits(self):
        pkts = [mk(1.0), mk(1.0 + IDLE + 0.1)]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 2

    def test_gap_within_idle_does_not_split(self):
        # Block 1 guarantees gaps <= 5s; 5s gap must NOT split.
        pkts = [mk(1.0), mk(1.0 + 5.0)]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 1

    def test_active_timeout_splits(self):
        pkts = [mk(1.0), mk(1.0 + ACTIVE + 0.1)]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 2

    def test_fin_does_not_split_documented_deviation(self):
        # Option 2: FIN/RST marks connection end but packets re-join.
        pkts = [mk(1.0, flags="S"), mk(1.1, flags="PA"), mk(1.2, flags="FA"), mk(4.2, flags="S")]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 1
        assert len(flows[0]) == 4

    def test_icmp_ports_zero(self):
        pkts = [mk(1.0, proto="icmp", sport=0, dport=0)]
        flows = reconstruct_flows(pkts, IDLE, ACTIVE)
        assert len(flows) == 1
        assert flows[0][0].flow_key == "10.0.0.1:0->10.0.1.1:0/icmp"

    def test_segment_flow_empty(self):
        assert segment_flow([], IDLE, ACTIVE) == []


# ---------------------------------------------------------------------------
# Feature calculation (PCAP-only values)
# ---------------------------------------------------------------------------


class TestFeatureComputation:
    def test_basic_counts_and_bytes(self):
        pkts = [mk(1.0, ip_len=40, flags="S"), mk(1.5, ip_len=100, flags="PA")]
        flow = compute_flow_features("f0", "run_001", "ddos", pkts)
        assert flow.packet_count == 2
        assert flow.byte_count == 140
        assert flow.start_ts == 1.0
        assert flow.end_ts == 1.5
        assert flow.duration == 0.5
        assert flow.min_packet_size == 40
        assert flow.max_packet_size == 100
        assert flow.mean_packet_size == 70.0

    def test_rates(self):
        pkts = [mk(1.0, ip_len=40), mk(2.0, ip_len=60)]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.packets_per_second == pytest.approx(2.0)
        assert flow.bytes_per_second == pytest.approx(100.0)

    def test_single_packet_flow(self):
        pkts = [mk(1.0, ip_len=40)]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.packet_count == 1
        assert flow.duration == 0.0
        assert flow.iat_count == 0
        assert flow.iat_mean == 0.0
        assert flow.iat_std == 0.0
        # Rates use max(duration, 1e-6) denominator.
        assert flow.packets_per_second == pytest.approx(1_000_000.0)

    def test_iat_stats(self):
        pkts = [mk(1.0), mk(2.0), mk(4.0)]  # IATs: 1.0, 2.0
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.iat_count == 2
        assert flow.iat_mean == pytest.approx(1.5)
        assert flow.iat_min == pytest.approx(1.0)
        assert flow.iat_max == pytest.approx(2.0)
        assert flow.iat_std == pytest.approx(0.5)  # population std

    def test_tcp_flag_counts(self):
        pkts = [
            mk(1.0, flags="S"),
            mk(1.1, flags="PA"),
            mk(1.2, flags="PA"),
            mk(1.3, flags="FA"),
        ]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.tcp_flags == "A,F,P,S"
        assert flow.tcp_syn_count == 1
        assert flow.tcp_psh_count == 2
        assert flow.tcp_ack_count == 3  # PA, PA, FA all carry ACK
        assert flow.tcp_fin_count == 1
        assert flow.tcp_rst_count == 0
        assert flow.tcp_urg_count == 0

    def test_non_tcp_flags_empty(self):
        pkts = [mk(1.0, proto="udp", sport=53, dport=53)]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.tcp_flags == ""
        assert flow.tcp_syn_count == 0

    def test_flow_id_assignment_deterministic(self):
        pkts_a = [mk(5.0, sport=1)]
        pkts_b = [mk(1.0, sport=2)]
        fa = compute_flow_features("", "run_001", "x", pkts_a)
        fb = compute_flow_features("", "run_001", "x", pkts_b)
        ordered = assign_flow_ids([fa, fb], "run_001", "x")
        assert ordered[0].flow_id == "x__run_001__0000"
        assert ordered[1].flow_id == "x__run_001__0001"
        assert ordered[0].src_port == 2  # earlier start_ts first

    def test_flow_id_global_uniqueness_across_scenarios(self):
        """Same run_id reused across scenarios must still produce unique IDs."""
        pkts_a = [mk(1.0, sport=1)]
        pkts_b = [mk(1.0, sport=2)]
        fa = compute_flow_features("", "run_001", "ddos", pkts_a)
        fb = compute_flow_features("", "run_001", "c2_beacon", pkts_b)
        # Process ddos flows first (they get ddos-scoped IDs).
        ordered = assign_flow_ids([fa, fb], "run_001", "ddos")
        assert ordered[0].flow_id == "ddos__run_001__0000"
        assert ordered[1].flow_id == "ddos__run_001__0001"
        assert ordered[0].scenario == "ddos"
        assert ordered[1].scenario == "c2_beacon"

    def test_join_labels_scenario_filter(self, tmp_path):
        """join_labels with scenario filter must only match GT rows of that scenario.

        This mirrors real usage: each scenario has its own GT file, and
        join_labels is called with that scenario so a flow cannot be labeled
        by another scenario's GT row when flow_keys collide.
        """
        import csv

        gt_path = tmp_path / "gt.csv"
        cols = [
            "flow_id", "run_id", "scenario", "label", "src_ip", "src_port",
            "dst_ip", "dst_port", "protocol", "flow_key", "start_ts",
            "end_ts", "duration", "packet_count", "byte_count", "tcp_flags",
        ]
        with open(gt_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cols)
            writer.writeheader()
            writer.writerow({
                "flow_id": "f0", "run_id": "run_001", "scenario": "ddos",
                "label": "ddos",
                "src_ip": "10.0.0.1", "src_port": "1000",
                "dst_ip": "10.0.1.1", "dst_port": "80", "protocol": "tcp",
                "flow_key": make_flow_key("10.0.0.1", 1000, "10.0.1.1", 80, "tcp"),
                "start_ts": "1.0", "end_ts": "2.0", "duration": "1.0",
                "packet_count": "2", "byte_count": "140", "tcp_flags": "S,PA",
            })
            writer.writerow({
                "flow_id": "f1", "run_id": "run_001", "scenario": "c2_beacon",
                "label": "c2_beacon",
                "src_ip": "10.0.0.2", "src_port": "2000",
                "dst_ip": "10.0.1.1", "dst_port": "443", "protocol": "tcp",
                "flow_key": make_flow_key("10.0.0.2", 2000, "10.0.1.1", 443, "tcp"),
                "start_ts": "1.0", "end_ts": "2.0", "duration": "1.0",
                "packet_count": "2", "byte_count": "140", "tcp_flags": "A,P,S",
            })

        gt_by_key = read_ground_truth(gt_path)
        # Two flows with the SAME run_id but different scenarios.
        fa = compute_flow_features("", "run_001", "ddos", [
            mk(1.0, ip_len=40, flags="S"),
            mk(1.5, ip_len=100, flags="PA"),
        ])
        fb = compute_flow_features("", "run_001", "c2_beacon", [
            mk(1.0, src="10.0.0.2", sport=2000, dst="10.0.1.1", dport=443, ip_len=40, flags="PA"),
            mk(1.5, src="10.0.0.2", sport=2000, dst="10.0.1.1", dport=443, ip_len=100, flags="PA"),
        ])
        # Assign flow_ids (as the extractor does) before joining.
        flows = assign_flow_ids([fa, fb], "run_001", "ddos")

        # Without scenario filter, both flows match their respective GT rows
        # because read_ground_truth keys by flow_key only and the two flows
        # have different flow_keys.
        rows_no_filter = join_labels(flows, gt_by_key)
        assert rows_no_filter[0]["label"] == "ddos"
        assert rows_no_filter[1]["label"] == "c2_beacon"

        # With scenario="ddos" filter, only the ddos flow gets a label;
        # the c2_beacon flow gets "" because its scenario doesn't match.
        rows_ddos = join_labels(flows, gt_by_key, scenario="ddos")
        assert rows_ddos[0]["label"] == "ddos"
        assert rows_ddos[1]["label"] == ""

        # With scenario="c2_beacon" filter, only the c2_beacon flow gets a label.
        rows_c2 = join_labels(flows, gt_by_key, scenario="c2_beacon")
        assert rows_c2[0]["label"] == ""
        assert rows_c2[1]["label"] == "c2_beacon"

        # flow_ids are scenario-scoped and unique.
        assert rows_no_filter[0]["flow_id"].startswith("ddos__")
        assert rows_no_filter[1]["flow_id"].startswith("ddos__")
        assert rows_no_filter[0]["flow_id"] != rows_no_filter[1]["flow_id"]


# ---------------------------------------------------------------------------
# GT joining and validation
# ---------------------------------------------------------------------------


class TestLabelsAndValidation:
    def _write_gt(self, tmp_path: Path, rows: list[dict]) -> Path:
        import csv

        path = tmp_path / "gt.csv"
        cols = [
            "flow_id", "run_id", "scenario", "label", "src_ip", "src_port",
            "dst_ip", "dst_port", "protocol", "flow_key", "start_ts",
            "end_ts", "duration", "packet_count", "byte_count", "tcp_flags",
        ]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cols)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return path

    def test_join_labels(self, tmp_path):
        gt = self._write_gt(
            tmp_path,
            [
                {
                    "flow_id": "f0000", "run_id": "run_001", "scenario": "ddos",
                    "label": "ddos", "src_ip": "10.0.0.1", "src_port": "1000",
                    "dst_ip": "10.0.1.1", "dst_port": "80", "protocol": "tcp",
                    "flow_key": make_flow_key("10.0.0.1", 1000, "10.0.1.1", 80, "tcp"),
                    "start_ts": "1.0", "end_ts": "2.0", "duration": "1.0",
                    "packet_count": "2", "byte_count": "140", "tcp_flags": "S,PA",
                }
            ],
        )
        gt_by_key = read_ground_truth(gt)
        pkts = [mk(1.0, ip_len=40, flags="S"), mk(1.5, ip_len=100, flags="PA")]
        flow = compute_flow_features("f0", "run_001", "ddos", pkts)
        rows = join_labels([flow], gt_by_key)
        assert rows[0]["label"] == "ddos"

    def test_validation_pass(self, tmp_path):
        gt = self._write_gt(
            tmp_path,
            [
                {
                    "flow_id": "f0000", "run_id": "run_001", "scenario": "x",
                    "label": "benign", "src_ip": "10.0.0.1", "src_port": "1000",
                    "dst_ip": "10.0.1.1", "dst_port": "80", "protocol": "tcp",
                    "flow_key": make_flow_key("10.0.0.1", 1000, "10.0.1.1", 80, "tcp"),
                    "start_ts": "1.0", "end_ts": "1.5", "duration": "0.5",
                    "packet_count": "2", "byte_count": "140", "tcp_flags": "A,P,S",
                }
            ],
        )
        pkts = [mk(1.0, ip_len=40, flags="S"), mk(1.5, ip_len=100, flags="PA")]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        report = validate_run([flow], gt)
        assert report["status"] == "PASS"
        assert report["matched"] == 1

    def test_validation_detects_mismatch(self, tmp_path):
        gt = self._write_gt(
            tmp_path,
            [
                {
                    "flow_id": "f0000", "run_id": "run_001", "scenario": "x",
                    "label": "benign", "src_ip": "10.0.0.1", "src_port": "1000",
                    "dst_ip": "10.0.1.1", "dst_port": "80", "protocol": "tcp",
                    "flow_key": make_flow_key("10.0.0.1", 1000, "10.0.1.1", 80, "tcp"),
                    "start_ts": "1.0", "end_ts": "1.5", "duration": "0.5",
                    "packet_count": "5", "byte_count": "999", "tcp_flags": "S",
                }
            ],
        )
        pkts = [mk(1.0, ip_len=40, flags="S"), mk(1.5, ip_len=100, flags="PA")]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        report = validate_run([flow], gt)
        assert report["status"] == "FAIL"
        assert len(report["errors"]) == 3  # packet_count, byte_count, tcp_flags

    def test_validation_detects_missing_flow(self, tmp_path):
        gt = self._write_gt(
            tmp_path,
            [
                {
                    "flow_id": "f0000", "run_id": "run_001", "scenario": "x",
                    "label": "benign", "src_ip": "10.0.0.9", "src_port": "1",
                    "dst_ip": "10.0.1.1", "dst_port": "80", "protocol": "tcp",
                    "flow_key": make_flow_key("10.0.0.9", 1, "10.0.1.1", 80, "tcp"),
                    "start_ts": "1.0", "end_ts": "1.0", "duration": "0.0",
                    "packet_count": "1", "byte_count": "40", "tcp_flags": "",
                }
            ],
        )
        pkts = [mk(1.0, ip_len=40)]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        report = validate_run([flow], gt)
        assert report["status"] == "FAIL"
        assert len(report["missing"]) == 1
        assert len(report["extra"]) == 1


# ---------------------------------------------------------------------------
# Integration with the real Block 1 dataset (skipped if not generated)
# ---------------------------------------------------------------------------

DATASET_DIR = ROOT / "data" / "raw" / "sih26145"


@pytest.mark.skipif(not DATASET_DIR.exists(), reason="Block 1 dataset not generated")
class TestIntegration:
    def test_extraction_passes(self):
        from feature_extractor.config import ExtractorConfig
        from feature_extractor.extractor import run_extraction

        config = ExtractorConfig(
            dataset_dir=str(DATASET_DIR),
            outdir=str(ROOT / "data" / "processed"),
        )
        report = run_extraction(config)
        assert report["overall_status"] == "PASS"
        assert report["total_errors"] == 0
        assert report["total_flows"] == 53

    def test_features_independent_of_gt(self):
        """Corrupt GT byte_count; extracted features must be unchanged."""
        import csv

        from feature_extractor.extractor import extract_run

        manifest = DATASET_DIR / "manifest.json"
        import json

        with open(manifest, encoding="utf-8") as f:
            runs = json.load(f)["runs"]
        run = runs[0]

        # Extract normally.
        from feature_extractor.config import ExtractorConfig

        config = ExtractorConfig(dataset_dir=str(DATASET_DIR), outdir="data/processed")
        flows = extract_run(DATASET_DIR, run, config)
        original = {f.flow_key: f.byte_count for f in flows}

        # Corrupt a copy of the GT and re-extract: features must not change.
        import shutil

        tmp_gt = DATASET_DIR / (run["labels"] + ".corrupt_test")
        shutil.copy(DATASET_DIR / run["labels"], tmp_gt)
        try:
            with open(tmp_gt, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            for row in rows:
                row["byte_count"] = "1"
                row["packet_count"] = "1"
            with open(tmp_gt, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)

            flows2 = extract_run(DATASET_DIR, run, config)
            corrupted = {f.flow_key: f.byte_count for f in flows2}
            assert corrupted == original
        finally:
            tmp_gt.unlink()


# ---------------------------------------------------------------------------
# DNS/TLS payload metadata (PCAP-derived, no decryption)
# ---------------------------------------------------------------------------


def _dns_payload(qname: bytes, qtype: int = 1) -> bytes:
    """Build a Block 1-style synthetic DNS query fragment."""
    return qname + b"\x00" + qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")


def _tls_payload(content_type=22, version=0x0303, inner_len=32) -> bytes:
    """Build a Block 1-style synthetic TLS record."""
    return (
        bytes([content_type])
        + version.to_bytes(2, "big")
        + inner_len.to_bytes(2, "big")
        + bytes(range(inner_len))
    )


class TestPayloadParsers:
    def test_entropy_empty(self):
        from feature_extractor.payload_features import shannon_entropy

        assert shannon_entropy(b"") == 0.0

    def test_entropy_constant(self):
        from feature_extractor.payload_features import shannon_entropy

        assert shannon_entropy(b"\x41" * 16) == pytest.approx(0.0)

    def test_entropy_uniform(self):
        from feature_extractor.payload_features import shannon_entropy

        assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)

    def test_parse_dns_benign_style(self):
        from feature_extractor.payload_features import parse_dns_payload

        parsed = parse_dns_payload(_dns_payload(b"\x03abc\x02xy", qtype=1))
        assert parsed is not None
        assert parsed.qname_len == (1 + 3) + (1 + 2) + 1  # labels + root
        assert parsed.qtype == 1
        assert parsed.qname_entropy >= 0.0

    def test_parse_dns_long_qname(self):
        from feature_extractor.payload_features import parse_dns_payload

        qname = b"\x20" + b"a" * 32 + b"\x20" + b"b" * 32
        parsed = parse_dns_payload(_dns_payload(qname, qtype=28))
        assert parsed is not None
        assert parsed.qtype == 28
        assert parsed.qname_len > 40

    def test_parse_dns_rejects_garbage(self):
        from feature_extractor.payload_features import parse_dns_payload

        assert parse_dns_payload(b"") is None
        assert parse_dns_payload(b"\x01") is None
        assert parse_dns_payload(b"\xff" + b"a" * 70) is None  # label > 63
        assert parse_dns_payload(b"\x03abc") is None  # truncated

    def test_parse_tls_record(self):
        from feature_extractor.payload_features import parse_tls_record

        parsed = parse_tls_record(_tls_payload(22, 0x0303, 32))
        assert parsed is not None
        assert parsed.content_type == 22
        assert parsed.version == 0x0303
        assert parsed.declared_len == 32
        assert parsed.inner_entropy > 0.0

    def test_parse_tls_rejects_unknown(self):
        from feature_extractor.payload_features import parse_tls_record

        assert parse_tls_record(b"") is None
        assert parse_tls_record(b"\x16\x03") is None  # truncated
        assert parse_tls_record(b"\x99\x03\x03\x00\x20" + b"\x00" * 32) is None
        assert parse_tls_record(b"\x16\x04\x04\x00\x20" + b"\x00" * 32) is None

    def test_mode_smallest_tiebreak(self):
        from feature_extractor.payload_features import mode_smallest

        assert mode_smallest([]) == 0
        assert mode_smallest([28, 1, 28, 1]) == 1  # tie -> smallest
        assert mode_smallest([15, 15, 1]) == 15


class TestDnsTlsFeatures:
    def _dns_pkt(self, ts, payload, dport=53):
        return PacketRecord(
            src_ip="10.0.0.1", src_port=1000, dst_ip="10.0.1.1",
            dst_port=dport, protocol="udp", timestamp=ts,
            ip_len=28 + len(payload), tcp_flags=None, payload=payload,
        )

    def _tls_pkt(self, ts, payload):
        return PacketRecord(
            src_ip="10.0.0.1", src_port=1000, dst_ip="10.0.1.1",
            dst_port=443, protocol="tcp", timestamp=ts,
            ip_len=40 + len(payload), tcp_flags="PA", payload=payload,
        )

    def test_dns_flow_features(self):
        p1 = self._dns_pkt(1.0, _dns_payload(b"\x03abc\x02xy", qtype=1))
        p2 = self._dns_pkt(1.1, _dns_payload(b"\x04abcd\x02xy", qtype=28))
        flow = compute_flow_features("f0", "run_001", "dns_anomaly", [p1, p2])
        assert flow.dns_packet_count == 2
        assert flow.dns_qname_len_max > 0
        assert flow.dns_qname_len_mean > 0
        assert flow.dns_qname_entropy_mean >= 0.0
        assert flow.dns_qtype_mode in (1, 28)
        assert flow.tls_record_count == 0

    def test_non_dns_flow_zeros(self):
        pkts = [mk(1.0, proto="udp", sport=53, dport=53)]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.dns_packet_count == 0
        assert flow.dns_qname_len_max == 0
        assert flow.dns_qtype_mode == 0

    def test_tls_flow_features(self):
        p1 = self._tls_pkt(1.0, _tls_payload(22, 0x0303, 32))
        p2 = self._tls_pkt(1.1, _tls_payload(23, 0x0303, 64))
        flow = compute_flow_features("f0", "run_001", "encrypted_anomaly", [p1, p2])
        assert flow.tls_record_count == 2
        assert flow.tls_version_mode == 0x0303
        assert flow.tls_content_type_mode in (22, 23)
        assert flow.tls_record_len_max == 64
        assert flow.tls_payload_entropy_mean > 0.0
        assert flow.dns_packet_count == 0

    def test_non_tls_flow_zeros(self):
        pkts = [mk(1.0, flags="PA")]
        flow = compute_flow_features("f0", "run_001", "x", pkts)
        assert flow.tls_record_count == 0
        assert flow.tls_version_mode == 0
        assert flow.tls_record_len_max == 0
