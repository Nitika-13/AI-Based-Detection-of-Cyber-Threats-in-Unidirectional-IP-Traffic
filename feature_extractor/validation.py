"""Post-extraction validation: compare extracted flows vs ground truth.

Features are computed BEFORE this module runs and never from GT values.
Validation only compares already-extracted features against the GT CSV.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from .labels import read_ground_truth
from .models import ExtractedFlow


def validate_run(
    extracted: List[ExtractedFlow],
    gt_csv_path: Path,
) -> Dict:
    """Compare extracted flows against GT for one run.

    Returns a report dict with missing/extra flows and per-flow mismatches.
    """
    gt_by_key = read_ground_truth(gt_csv_path)
    extracted_by_key = {f.flow_key: f for f in extracted}

    errors: List[str] = []
    missing = sorted(set(gt_by_key) - set(extracted_by_key))
    extra = sorted(set(extracted_by_key) - set(gt_by_key))

    for key in missing:
        errors.append(f"missing flow in extraction: {key}")
    for key in extra:
        errors.append(f"extra flow not in ground truth: {key}")

    # Structural checks on PCAP-derived DNS/TLS metadata (no GT involved:
    # the GT CSV has no DNS/TLS columns). These catch parser regressions.
    for flow in extracted:
        if flow.protocol == "udp" and flow.dst_port == 53:
            if flow.dns_packet_count < 0 or flow.dns_packet_count > flow.packet_count:
                errors.append(
                    f"{flow.flow_key}: dns_packet_count out of range "
                    f"({flow.dns_packet_count} vs {flow.packet_count} packets)"
                )
            if flow.dns_packet_count > 0 and flow.dns_qname_len_max <= 0:
                errors.append(
                    f"{flow.flow_key}: dns packets present but qname_len_max <= 0"
                )
        else:
            if flow.dns_packet_count != 0:
                errors.append(
                    f"{flow.flow_key}: non-DNS flow has dns_packet_count != 0"
                )
        if flow.protocol == "tcp" and flow.dst_port == 443:
            if flow.tls_record_count < 0 or flow.tls_record_count > flow.packet_count:
                errors.append(
                    f"{flow.flow_key}: tls_record_count out of range "
                    f"({flow.tls_record_count} vs {flow.packet_count} packets)"
                )
        else:
            if flow.tls_record_count != 0:
                errors.append(
                    f"{flow.flow_key}: non-TLS flow has tls_record_count != 0"
                )

    matched = 0
    for key in sorted(set(gt_by_key) & set(extracted_by_key)):
        flow = extracted_by_key[key]
        gt = gt_by_key[key]
        matched += 1

        # GT values are read ONLY to compare against extracted features.
        if flow.packet_count != gt.packet_count:
            errors.append(
                f"{key}: packet_count extracted={flow.packet_count} "
                f"gt={gt.packet_count}"
            )
        if flow.byte_count != gt.byte_count:
            errors.append(
                f"{key}: byte_count extracted={flow.byte_count} "
                f"gt={gt.byte_count}"
            )
        if flow.tcp_flags != gt.tcp_flags:
            errors.append(
                f"{key}: tcp_flags extracted='{flow.tcp_flags}' "
                f"gt='{gt.tcp_flags}'"
            )

    return {
        "gt_flow_count": len(gt_by_key),
        "extracted_flow_count": len(extracted),
        "matched": matched,
        "missing": missing,
        "extra": extra,
        "errors": errors,
        "status": "PASS" if not errors else "FAIL",
    }