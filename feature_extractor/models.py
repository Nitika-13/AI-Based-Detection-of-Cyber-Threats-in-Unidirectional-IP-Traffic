"""Data models for the NetFlow feature extractor (Block 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


def make_flow_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
) -> str:
    """Canonical unidirectional 5-tuple flow key (Block 1 convention)."""
    return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"


@dataclass
class PacketRecord:
    """A single packet parsed from a PCAP (feature-extraction view)."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp" | "udp" | "icmp"
    timestamp: float  # epoch seconds
    ip_len: int  # IP total length (byte-count convention)
    tcp_flags: Optional[str] = None  # Scapy flag string, e.g. "PA"; None for non-TCP
    payload: bytes = b""  # transport-layer payload bytes (for DNS/TLS parsing)

    @property
    def flow_key(self) -> str:
        return make_flow_key(
            self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol
        )


@dataclass
class ExtractedFlow:
    """One reconstructed unidirectional flow with computed features."""

    flow_id: str
    run_id: str
    scenario: str
    flow_key: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    start_ts: float
    end_ts: float
    duration: float
    packet_count: int
    byte_count: int
    packets_per_second: float
    bytes_per_second: float
    min_packet_size: int
    max_packet_size: int
    mean_packet_size: float
    std_packet_size: float
    iat_mean: float
    iat_std: float
    iat_min: float
    iat_max: float
    iat_count: int
    tcp_flags: str
    tcp_syn_count: int
    tcp_fin_count: int
    tcp_rst_count: int
    tcp_psh_count: int
    tcp_ack_count: int
    tcp_urg_count: int
    # DNS metadata (UDP dst port 53 with parseable payload; else zeros).
    dns_packet_count: int = 0
    dns_qname_len_mean: float = 0.0
    dns_qname_len_max: int = 0
    dns_qname_entropy_mean: float = 0.0
    dns_qname_entropy_max: float = 0.0
    dns_qtype_mode: int = 0
    # TLS record metadata (TCP dst port 443 with valid record header;
    # else zeros). NOTE: synthetic records only — no real ClientHello,
    # no SNI, no JA3/JA4. tls_record_len_* is the TLS *record* declared
    # length, NOT a ClientHello length.
    tls_record_count: int = 0
    tls_version_mode: int = 0
    tls_content_type_mode: int = 0
    tls_record_len_mean: float = 0.0
    tls_record_len_max: int = 0
    tls_payload_entropy_mean: float = 0.0

    def to_csv_row(self) -> dict:
        row = {}
        for col in FEATURE_COLUMNS:
            value = getattr(self, col)
            if isinstance(value, float):
                row[col] = f"{value:.6f}"
            else:
                row[col] = value
        return row


# Fixed column order for flows.csv (approved feature schema).
FEATURE_COLUMNS: List[str] = [
    "flow_id",
    "run_id",
    "scenario",
    "flow_key",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "start_ts",
    "end_ts",
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "min_packet_size",
    "max_packet_size",
    "mean_packet_size",
    "std_packet_size",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "iat_count",
    "tcp_flags",
    "tcp_syn_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "tcp_ack_count",
    "tcp_urg_count",
    # DNS metadata extension (appended; existing order preserved).
    "dns_packet_count",
    "dns_qname_len_mean",
    "dns_qname_len_max",
    "dns_qname_entropy_mean",
    "dns_qname_entropy_max",
    "dns_qtype_mode",
    # TLS record metadata extension (appended; existing order preserved).
    "tls_record_count",
    "tls_version_mode",
    "tls_content_type_mode",
    "tls_record_len_mean",
    "tls_record_len_max",
    "tls_payload_entropy_mean",
]
