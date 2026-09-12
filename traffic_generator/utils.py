"""Utility helpers: seeded RNG, IP/port/timestamp generation."""

from __future__ import annotations

import ipaddress
import random
from typing import Optional, Tuple

from .config import MAX_INTER_PACKET_GAP_SECONDS


def make_rng(seed: int) -> random.Random:
    """Create a deterministic random.Random instance."""
    return random.Random(seed)


def random_ip(rng: random.Random, cidr: str) -> str:
    """Return a random host IP within the given CIDR (excluding network/broadcast)."""
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = list(net.hosts())
    if not hosts:
        return str(net.network_address)
    return str(rng.choice(hosts))


def random_port(rng: random.Random, lo: int = 1024, hi: int = 65535) -> int:
    """Return a random ephemeral port."""
    return rng.randint(lo, hi)


def random_payload(rng: random.Random, size: int) -> bytes:
    """Return deterministic random payload bytes of the given size."""
    return bytes(rng.getrandbits(8) for _ in range(size))


def random_payload_ascii(rng: random.Random, size: int) -> bytes:
    """Return deterministic random printable-ASCII payload bytes."""
    alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
    return bytes(rng.choice(alphabet) for _ in range(size))


def random_payload_dns(rng: random.Random, qname_len: int = 20) -> bytes:
    """Return a synthetic DNS query payload (QNAME + QTYPE/QCLASS)."""
    labels = []
    remaining = qname_len
    while remaining > 0:
        label_len = rng.randint(1, min(63, remaining))
        labels.append(
            bytes(
                rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789-")
                for _ in range(label_len)
            )
        )
        remaining -= label_len
    qname = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
    qtype = rng.choice([1, 28, 15, 16, 2])  # A, AAAA, MX, TXT, NS
    qclass = 1  # IN
    return qname + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")


def random_tls_like_payload(rng: random.Random, size: int) -> bytes:
    """Return a synthetic TLS-like record payload (pattern-based, not real TLS).

    Structure: [content_type(1)][version(2)][length(2)][payload]
    Content types: 20 (change_cipher_spec), 21 (alert), 22 (handshake), 23 (app data)
    """
    content_type = rng.choice([20, 21, 22, 23])
    version = rng.choice([0x0301, 0x0302, 0x0303, 0x0304])  # TLS 1.0-1.3
    inner_size = max(0, size - 5)
    inner = random_payload(rng, inner_size)
    return (
        bytes([content_type])
        + version.to_bytes(2, "big")
        + inner_size.to_bytes(2, "big")
        + inner
    )


def next_timestamp(
    rng: random.Random,
    current: float,
    min_gap: float = 0.001,
    max_gap: float = MAX_INTER_PACKET_GAP_SECONDS,
) -> float:
    """Return the next packet timestamp with a deterministic gap in [min_gap, max_gap]."""
    gap = rng.uniform(min_gap, max_gap)
    return round(current + gap, 6)


def unique_flow_key(
    used_keys: set,
    rng: random.Random,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port_lo: int = 1024,
    src_port_hi: int = 65535,
    dst_port: Optional[int] = None,
) -> Tuple[int, int, str]:
    """Generate a unique (src_port, dst_port, flow_key) triple.

    Guarantees no two flows within a run share the same 5-tuple.
    """
    from .models import make_flow_key

    for _ in range(10000):
        sp = rng.randint(src_port_lo, src_port_hi)
        dp = dst_port if dst_port is not None else rng.randint(1, 65535)
        key = make_flow_key(src_ip, sp, dst_ip, dp, protocol)
        if key not in used_keys:
            used_keys.add(key)
            return sp, dp, key
    raise RuntimeError("Could not allocate a unique flow key after 10000 attempts")