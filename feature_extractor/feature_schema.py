"""Canonical, versioned feature schema for Block 2 (single source of truth).

Every feature the extractor can emit is documented exactly once, here, with its
provenance. The ``feature_schema.json`` written into the processed output is
generated from this module, so documentation and behaviour cannot drift apart.

Each entry records:

``dtype``
    Type as written to CSV: ``int``, ``float`` or ``str``.
``unit``
    Physical unit where one exists (seconds, bytes, bits, packets_per_second,
    bytes_per_second, ratio, count); empty for dimensionless/categorical values.
``definition``
    How the value is calculated, in words.
``source``
    Where the value comes from. ``pcap`` = derived from observed packets only.
    ``identity`` = flow identity from the unidirectional 5-tuple.
    ``run`` = run context from the Block 1 dataset manifest.
``missing``
    The value used when the feature does not apply to a flow. Block 2 never
    emits blank cells, so every feature has a defined zero/empty value.
``role``
    One of:

    * ``metadata``      - traceability only; MUST NOT be a model input.
    * ``evidence_only`` - human-readable alert evidence; not a numeric input.
    * ``ml_feature``    - a behavioural/numerical model input.

The ``ml_feature`` rows of the ``flow`` table are exactly the canonical model
input for BOTH training and inference. Block 3 must select columns by role from
this schema rather than hard-coding a list, so a schema change cannot silently
change what the model sees.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

# Version of the canonical feature schema. Bump when a feature is added,
# removed, or has its numeric definition changed.
FEATURE_SCHEMA_VERSION = "1.0.0"

# Canonical table names.
FLOW_TABLE = "flow"            # written to flows.csv
HOST_WINDOW_TABLE = "host_window"  # written to host_windows.csv

# (name, dtype, unit, definition, source, missing, role)
_Row = Tuple[str, str, str, str, str, str, str]

_ROW_KEYS = ("name", "dtype", "unit", "definition", "source", "missing", "role")


def _rows_to_dicts(rows: List[_Row]) -> List[Dict[str, str]]:
    """Convert compact schema tuples into JSON-friendly dicts."""
    return [dict(zip(_ROW_KEYS, row)) for row in rows]


# ---------------------------------------------------------------------------
# flow table - identity / traceability metadata (never model inputs)
# ---------------------------------------------------------------------------

FLOW_METADATA: List[_Row] = [
    ("flow_id", "str", "", "Unique flow id: {scenario}__{run_id}__{seq:04d}, assigned deterministically by (start_ts, flow_key).", "run", "always present", "metadata"),
    ("run_id", "str", "", "Run identifier from the dataset manifest (the split unit).", "run", "always present", "metadata"),
    ("scenario", "str", "", "Run-level scenario name from the dataset manifest.", "run", "always present", "metadata"),
    ("flow_key", "str", "", "Unidirectional 5-tuple src_ip:src_port->dst_ip:dst_port/protocol.", "identity", "always present", "metadata"),
    ("src_ip", "str", "", "Source IPv4 address of the observed direction.", "identity", "always present", "metadata"),
    ("src_port", "int", "", "Source port (0 for ICMP).", "identity", "always present", "metadata"),
    ("dst_ip", "str", "", "Destination IPv4 address of the observed direction.", "identity", "always present", "metadata"),
    ("dst_port", "int", "", "Destination port (0 for ICMP).", "identity", "always present", "metadata"),
    ("protocol", "str", "", "Transport protocol: tcp, udp or icmp.", "identity", "always present", "metadata"),
    ("start_ts", "float", "seconds since epoch", "Timestamp of the first packet in the flow.", "pcap", "always present", "metadata"),
    ("end_ts", "float", "seconds since epoch", "Timestamp of the last packet in the flow.", "pcap", "always present", "metadata"),
    ("direction", "str", "", "outbound when src_ip falls inside a configured monitored prefix, inbound when dst_ip does, otherwise unknown. Derived passively; evidence, not a model input.", "run", "unknown", "metadata"),
]

# ---------------------------------------------------------------------------
# flow table - evidence-only (human-readable, not a numeric model input)
# ---------------------------------------------------------------------------

FLOW_EVIDENCE: List[_Row] = [
    ("tcp_flags", "str", "", "Comma-joined sorted set of distinct TCP flag letters observed, e.g. A,F,P,S. Empty for non-TCP flows.", "pcap", "empty string", "evidence_only"),
]


# ---------------------------------------------------------------------------
# flow table - canonical ML features (behavioural / numerical model inputs)
# ---------------------------------------------------------------------------

FLOW_ML_FEATURES: List[_Row] = [
    # --- timing ---
    ("duration", "float", "seconds", "end_ts - start_ts. Zero for a single-packet flow.", "pcap", "0.0", "ml_feature"),
    ("iat_mean", "float", "seconds", "Mean inter-arrival time between consecutive packets. Zero when packet_count < 2.", "pcap", "0.0", "ml_feature"),
    ("iat_std", "float", "seconds", "Population standard deviation (ddof=0) of inter-arrival times.", "pcap", "0.0", "ml_feature"),
    ("iat_min", "float", "seconds", "Minimum inter-arrival time. Zero when packet_count < 2.", "pcap", "0.0", "ml_feature"),
    ("iat_max", "float", "seconds", "Maximum inter-arrival time. Zero when packet_count < 2.", "pcap", "0.0", "ml_feature"),
    ("iat_count", "int", "count", "Number of inter-arrival samples, i.e. packet_count - 1.", "pcap", "0", "ml_feature"),
    ("iat_cv", "float", "ratio", "Coefficient of variation of inter-arrival times: iat_std / iat_mean. Near 0 means machine-like periodicity (beaconing); large means bursty or irregular. Zero when iat_mean is 0.", "pcap", "0.0", "ml_feature"),
    # --- volume ---
    ("packet_count", "int", "count", "Number of packets in the flow.", "pcap", "always >= 1", "ml_feature"),
    ("byte_count", "int", "bytes", "Sum of IP total_length over the flow's packets (NetFlow byte convention).", "pcap", "always >= 40", "ml_feature"),
    ("packets_per_second", "float", "packets_per_second", "packet_count / max(duration, 1e-6). The floor stops a single-packet flow dividing by zero.", "pcap", "0.0", "ml_feature"),
    ("bytes_per_second", "float", "bytes_per_second", "byte_count / max(duration, 1e-6).", "pcap", "0.0", "ml_feature"),
    # --- packet-size distribution ---
    ("min_packet_size", "int", "bytes", "Smallest IP total_length in the flow.", "pcap", "always present", "ml_feature"),
    ("max_packet_size", "int", "bytes", "Largest IP total_length in the flow.", "pcap", "always present", "ml_feature"),
    ("mean_packet_size", "float", "bytes", "Arithmetic mean IP total_length.", "pcap", "0.0", "ml_feature"),
    ("std_packet_size", "float", "bytes", "Population standard deviation (ddof=0) of IP total_length.", "pcap", "0.0", "ml_feature"),
    # --- payload (metadata only: entropy on raw bytes, never decrypted) ---
    ("payload_bytes_total", "int", "bytes", "Total transport payload bytes. Zero for header-only flows.", "pcap", "0", "ml_feature"),
    ("payload_ratio", "float", "ratio", "payload_bytes_total / byte_count: how much of the flow is bulk data versus headers.", "pcap", "0.0", "ml_feature"),
    ("payload_entropy_mean", "float", "bits", "Mean Shannon entropy (bits per byte, 0-8) of each packet's transport payload. High means encrypted or incompressible content; low means structured or text data.", "pcap", "0.0", "ml_feature"),
    ("payload_entropy_max", "float", "bits", "Maximum per-packet payload Shannon entropy in the flow.", "pcap", "0.0", "ml_feature"),

    # --- TCP flags ---
    ("tcp_syn_count", "int", "count", "Packets with the SYN flag set. Zero for non-TCP flows.", "pcap", "0", "ml_feature"),
    ("tcp_fin_count", "int", "count", "Packets with the FIN flag set. Zero for non-TCP flows.", "pcap", "0", "ml_feature"),
    ("tcp_rst_count", "int", "count", "Packets with the RST flag set. Zero for non-TCP flows.", "pcap", "0", "ml_feature"),
    ("tcp_psh_count", "int", "count", "Packets with the PSH flag set. Zero for non-TCP flows.", "pcap", "0", "ml_feature"),
    ("tcp_ack_count", "int", "count", "Packets with the ACK flag set. Zero for non-TCP flows.", "pcap", "0", "ml_feature"),
    ("tcp_urg_count", "int", "count", "Packets with the URG flag set. Zero for non-TCP flows.", "pcap", "0", "ml_feature"),
    ("tcp_syn_ratio", "float", "ratio", "tcp_syn_count / packet_count. Near 1.0 for a SYN flood or a SYN-only scan probe. Zero for non-TCP flows.", "pcap", "0.0", "ml_feature"),
    ("tcp_flag_diversity", "int", "count", "Number of distinct TCP flag letters observed in the flow (0 for non-TCP). A full connection shows several; a bare scan probe shows one.", "pcap", "0", "ml_feature"),
    # --- DNS metadata (UDP dst port 53 only; parsed from the cleartext query fragment) ---
    ("dns_packet_count", "int", "count", "UDP/53 packets whose payload parsed as a DNS query fragment. Zero for non-DNS flows.", "pcap", "0", "ml_feature"),
    ("dns_qname_len_mean", "float", "bytes", "Mean QNAME wire length (including the root byte). Zero when no QNAME parsed.", "pcap", "0.0", "ml_feature"),
    ("dns_qname_len_max", "int", "bytes", "Maximum QNAME wire length. Zero when no QNAME parsed.", "pcap", "0", "ml_feature"),
    ("dns_qname_entropy_mean", "float", "bits", "Mean Shannon entropy of the QNAME label bytes. Random tunnelling labels score far higher than word-like names.", "pcap", "0.0", "ml_feature"),
    ("dns_qname_entropy_max", "float", "bits", "Maximum QNAME label entropy in the flow.", "pcap", "0.0", "ml_feature"),
    ("dns_qtype_mode", "int", "categorical code", "Most common DNS query type (1=A, 2=NS, 15=MX, 16=TXT, 28=AAAA); ties resolve to the smallest value. Zero when no QNAME parsed.", "pcap", "0", "ml_feature"),
    # --- TLS-like record metadata (TCP dst port 443 only; no decryption) ---
    ("tls_record_count", "int", "count", "TCP/443 packets whose payload began with a plausible TLS record header. Zero for non-TLS flows.", "pcap", "0", "ml_feature"),
    ("tls_version_mode", "int", "categorical code", "Most common TLS record version (0x0301-0x0304); ties resolve to the smallest value. Zero when no record parsed.", "pcap", "0", "ml_feature"),
    ("tls_content_type_mode", "int", "categorical code", "Most common TLS record content type (20-23); ties resolve to the smallest value. Zero when no record parsed.", "pcap", "0", "ml_feature"),
    ("tls_record_len_mean", "float", "bytes", "Mean TLS record declared length field. NOTE: this is the TLS *record* length, NOT a ClientHello length.", "pcap", "0.0", "ml_feature"),
    ("tls_record_len_max", "int", "bytes", "Maximum TLS record declared length field.", "pcap", "0", "ml_feature"),
    ("tls_payload_entropy_mean", "float", "bits", "Mean Shannon entropy of the bytes inside the TLS records (bits per byte, 0-8).", "pcap", "0.0", "ml_feature"),
]


# ---------------------------------------------------------------------------
# host_window table - cross-flow aggregates (Block 3 correlation input)
# ---------------------------------------------------------------------------

# Some threat characteristics are NOT properties of a single unidirectional
# flow, and therefore cannot live in flows.csv. Destination-port fan-out,
# destination-host fan-out, source diversity and C2 destination repetition are
# properties of a HOST over a TIME WINDOW, so they are emitted as a separate
# canonical table instead of being smuggled into the flow feature matrix.

HOST_WINDOW_METADATA: List[_Row] = [
    ("run_id", "str", "", "Run identifier (the split unit).", "run", "always present", "metadata"),
    ("scenario", "str", "", "Run-level scenario name.", "run", "always present", "metadata"),
    ("window_index", "int", "count", "Index of the tumbling time window summarised, relative to the capture's first packet.", "run", "always present", "metadata"),
    ("window_start_ts", "float", "seconds since epoch", "Inclusive start timestamp of the window.", "run", "always present", "metadata"),
    ("window_end_ts", "float", "seconds since epoch", "Exclusive end timestamp of the window.", "run", "always present", "metadata"),
    ("ip", "str", "", "The host whose activity is summarised.", "identity", "always present", "metadata"),
    ("role", "str", "", "src when the host is the source of the observed flows, dst when it is the destination. A host can appear twice per window, once per role.", "identity", "always present", "metadata"),
]

HOST_WINDOW_ML_FEATURES: List[_Row] = [
    ("flow_count", "int", "count", "Number of flows for this host/role inside the window.", "pcap", "0", "ml_feature"),
    ("packet_count", "int", "count", "Total packets across those flows.", "pcap", "0", "ml_feature"),
    ("byte_count", "int", "bytes", "Total bytes (IP total_length convention) across those flows.", "pcap", "0", "ml_feature"),
    ("unique_peer_ip_count", "int", "count", "Number of distinct peers. For role=src this is destination-host fan-out; for role=dst it is source diversity (the DDoS signal).", "pcap", "0", "ml_feature"),
    ("unique_peer_port_count", "int", "count", "Number of distinct transport ports among the peers. For role=src this is destination-port fan-out (the port-scan signal).", "pcap", "0", "ml_feature"),
    ("peer_ip_entropy", "float", "bits", "Shannon entropy (0-8) of the peer-IP distribution. 0 means all traffic went to or came from one peer; high means spread out.", "pcap", "0.0", "ml_feature"),
    ("peer_port_entropy", "float", "bits", "Shannon entropy (0-8) of the peer-port distribution.", "pcap", "0.0", "ml_feature"),
    ("syn_flow_count", "int", "count", "Number of those flows whose only observed flag set was SYN (probe-like).", "pcap", "0", "ml_feature"),
    ("syn_flow_ratio", "float", "ratio", "syn_flow_count / flow_count. Near 1.0 means the host was probing rather than talking.", "pcap", "0.0", "ml_feature"),
    ("mean_flow_duration", "float", "seconds", "Mean duration of those flows.", "pcap", "0.0", "ml_feature"),
    ("mean_packets_per_flow", "float", "packets", "Mean packet_count of those flows.", "pcap", "0.0", "ml_feature"),
    ("packet_rate_pps", "float", "packets_per_second", "packet_count spread over the window length.", "pcap", "0.0", "ml_feature"),
    ("byte_rate_bps", "float", "bytes_per_second", "byte_count spread over the window length.", "pcap", "0.0", "ml_feature"),
]


# Role -> ordered column groups, as written to disk.
_SCHEMA = {
    FLOW_TABLE: {
        "metadata": _rows_to_dicts(FLOW_METADATA),
        "evidence_only": _rows_to_dicts(FLOW_EVIDENCE),
        "ml_feature": _rows_to_dicts(FLOW_ML_FEATURES),
    },
    HOST_WINDOW_TABLE: {
        "metadata": _rows_to_dicts(HOST_WINDOW_METADATA),
        "ml_feature": _rows_to_dicts(HOST_WINDOW_ML_FEATURES),
    },
}

# The order columns appear in flows.csv / host_windows.csv.
def table_columns(table: str, role: str) -> List[str]:
    """Return the ordered column names of one table for one role."""
    return [row["name"] for row in _SCHEMA[table][role]]


def feature_document(name: str, table: str = FLOW_TABLE) -> Dict[str, str]:
    """Return the schema entry for one feature name, or raise KeyError."""
    for role_rows in _SCHEMA[table].values():
        for row in role_rows:
            if row["name"] == name:
                return row
    raise KeyError(f"Feature '{name}' is not documented in the {table} schema")


def all_feature_names(table: str = FLOW_TABLE) -> List[str]:
    """Return every documented column name for a table, in written order."""
    names: List[str] = []
    for role in ("metadata", "evidence_only", "ml_feature"):
        if role in _SCHEMA[table]:
            names.extend(table_columns(table, role))
    return names


def as_dict() -> Dict:
    """Return the full schema as a JSON-serialisable dict."""
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "role_definitions": {
            "metadata": "Traceability/identity columns. MUST NOT be model inputs.",
            "evidence_only": "Human-readable alert evidence. Not a numeric model input.",
            "ml_feature": "Behavioural/numerical model input (canonical ML matrix).",
        },
        "source_definitions": {
            "pcap": "Derived from observed packets only.",
            "identity": "Flow identity from the unidirectional 5-tuple.",
            "run": "Run context from the Block 1 dataset manifest.",
        },
        "tables": {
            FLOW_TABLE: {
                "file": "flows.csv",
                "description": (
                    "One row per reconstructed unidirectional flow. The "
                    "ml_feature columns are the canonical model input for "
                    "training AND inference."
                ),
                **_SCHEMA[FLOW_TABLE],
            },
            HOST_WINDOW_TABLE: {
                "file": "host_windows.csv",
                "description": (
                    "One row per (run, scenario, window, host, role). "
                    "Cross-flow aggregates for Block 3's correlation layer."
                ),
                **_SCHEMA[HOST_WINDOW_TABLE],
            },
        },
        "not_implemented": {
            "ja3_ja4_fingerprints": (
                "Block 1 emits TLS record headers only: no ClientHello body, no "
                "SNI, no cipher-suite or extension lists. JA3/JA4 and SNI "
                "features are genuinely impossible and are not attempted."
            ),
            "payload_decryption": (
                "Never performed. All statistics and entropies are computed on "
                "raw observed bytes."
            ),
        },
    }


def write_feature_schema(path: Path) -> None:
    """Write feature_schema.json next to the extracted outputs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(as_dict(), f, indent=2)
        f.write("\n")

