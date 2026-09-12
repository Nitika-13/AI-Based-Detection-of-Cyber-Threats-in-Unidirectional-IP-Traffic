"""PCAP-derived DNS and TLS-record metadata parsers (no decryption).

Block 1's synthetic payloads are NOT real protocol messages:
- DNS payloads are bare ``[label_len][label]...[0x00][qtype][qclass]``
  fragments with NO DNS header, so Scapy's DNS layer cannot dissect them.
  A small custom byte-level parser is used instead.
- TLS-like payloads are ``[content_type][version][length][bytes]`` record
  headers with random inner bytes. There is NO ClientHello body, NO SNI,
  NO cipher-suite/extension lists — so JA3/JA4 fingerprints are genuinely
  impossible. Only record-level metadata is extracted.

All functions are pure and deterministic.
"""

from __future__ import annotations

import math
from typing import List, NamedTuple, Optional

# Known TLS record content types emitted by the Block 1 generator.
TLS_CONTENT_TYPES = frozenset({20, 21, 22, 23})
# Known TLS record versions emitted by the Block 1 generator.
TLS_VERSIONS = frozenset({0x0301, 0x0302, 0x0303, 0x0304})


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string in bits (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


class DnsQuery(NamedTuple):
    """Parsed synthetic DNS query fragment."""

    qname_len: int  # length of the QNAME wire section incl. root byte
    qname_entropy: float  # Shannon entropy of the QNAME label bytes
    qtype: int  # DNS query type (e.g. 1=A, 28=AAAA)


def parse_dns_payload(payload: bytes) -> Optional[DnsQuery]:
    """Parse a Block 1 synthetic DNS query fragment.

    Expected layout: ``[len][label]...[0x00][qtype:2][qclass:2]``.
    Returns None when the payload does not match this layout.
    """
    if len(payload) < 1 + 1 + 2 + 2:  # shortest: 1 label + root + qtype + qclass
        return None

    offset = 0
    label_bytes = bytearray()
    while True:
        if offset >= len(payload):
            return None
        label_len = payload[offset]
        if label_len == 0:
            offset += 1
            break
        if label_len > 63:
            return None
        offset += 1
        if offset + label_len > len(payload):
            return None
        label_bytes.extend(payload[offset : offset + label_len])
        offset += label_len

    qname_len = offset  # includes the terminating root byte
    if offset + 4 > len(payload):
        return None
    qtype = int.from_bytes(payload[offset : offset + 2], "big")
    # qclass = payload[offset + 2 : offset + 4]  (parsed for completeness)

    return DnsQuery(
        qname_len=qname_len,
        qname_entropy=shannon_entropy(bytes(label_bytes)),
        qtype=qtype,
    )


class TlsRecord(NamedTuple):
    """Parsed synthetic TLS record header."""

    content_type: int  # e.g. 22 = handshake
    version: int  # e.g. 0x0303 = TLS 1.2
    declared_len: int  # record length field (NOT a ClientHello length)
    inner_entropy: float  # Shannon entropy of the record inner bytes


def parse_tls_record(payload: bytes) -> Optional[TlsRecord]:
    """Parse a Block 1 synthetic TLS-like record header.

    Expected layout: ``[content_type:1][version:2][length:2][bytes...]``.
    Returns None when the header is absent or uses unknown values.
    """
    if len(payload) < 5:
        return None
    content_type = payload[0]
    version = int.from_bytes(payload[1:3], "big")
    declared_len = int.from_bytes(payload[3:5], "big")
    if content_type not in TLS_CONTENT_TYPES:
        return None
    if version not in TLS_VERSIONS:
        return None
    inner = payload[5:]
    return TlsRecord(
        content_type=content_type,
        version=version,
        declared_len=declared_len,
        inner_entropy=shannon_entropy(inner),
    )


def mode_smallest(values: List[int]) -> int:
    """Most common value; ties broken by smallest value (deterministic)."""
    if not values:
        return 0
    counts: dict[int, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    best_count = max(counts.values())
    return min(value for value, count in counts.items() if count == best_count)