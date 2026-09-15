"""Utility helpers: seeded RNG, IP/port/timestamp generation."""

from __future__ import annotations

import ipaddress
import random
from typing import Optional, Sequence, Tuple

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


def random_tls_like_payload(
    rng: random.Random,
    size: int,
    content_type: Optional[int] = None,
    version: Optional[int] = None,
) -> bytes:
    """Return a synthetic TLS-like record payload (pattern-based, not real TLS).

    Structure: [content_type(1)][version(2)][length(2)][payload]
    Content types: 20 (change_cipher_spec), 21 (alert), 22 (handshake), 23 (app data)

    ``content_type`` / ``version`` may be pinned by the caller so that a flow
    can look like a realistic TLS session (one handshake record followed by
    application-data records) instead of a random mix. When left as ``None``
    the historical random behaviour is preserved.

    This is NOT real TLS: there is no ClientHello body, no SNI and no
    cipher-suite/extension list, so JA3/JA4 fingerprints remain impossible.
    """
    if content_type is None:
        content_type = rng.choice([20, 21, 22, 23])
    if version is None:
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


# ---------------------------------------------------------------------------
# Helpers used by the controlled-difficulty generators
# ---------------------------------------------------------------------------

def distinct_ip_pool(rng: random.Random, cidr: str, size: int) -> Tuple[str, ...]:
    """Return ``size`` distinct host IPs drawn deterministically from ``cidr``.

    Used to make source/host diversity observable: a low-difficulty DDoS
    resolves to a handful of sources, a high-difficulty one to many more.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    size = max(1, min(size, len(hosts)))
    return tuple(rng.sample(hosts, size))


def jittered(rng: random.Random, value: float, fraction: float) -> float:
    """Return ``value`` perturbed by up to ``+/- fraction`` (deterministic).

    ``fraction = 0`` yields a perfectly regular interval, which is what makes a
    high-confidence C2 beacon observable as a low inter-arrival coefficient of
    variation.
    """
    if fraction <= 0:
        return round(value, 6)
    delta = value * fraction
    return round(value + rng.uniform(-delta, delta), 6)


def random_payload_dns(
    rng: random.Random,
    qname_len: int = 20,
    alphabet: Optional[bytes] = None,
    qtypes: Optional[Sequence[int]] = None,
) -> bytes:
    """Return a synthetic DNS query payload (QNAME + QTYPE/QCLASS).

    ``alphabet`` defaults to the historical ``[a-z0-9-]`` set so existing
    behaviour is unchanged. Passing a narrower alphabet (e.g. lowercase
    letters plus a small word list) produces lower-entropy, benign-looking
    QNAMEs, while the default random alphabet produces the high-entropy QNAMEs
    that a DNS-tunnelling/beacon anomaly should exhibit.

    ``qtypes`` restricts the query type pool (default: A, AAAA, MX, TXT, NS).
    """
    if alphabet is None:
        alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789-"
    if qtypes is None:
        qtypes = (1, 28, 15, 16, 2)  # A, AAAA, MX, TXT, NS
    labels = []
    remaining = qname_len
    while remaining > 0:
        label_len = rng.randint(1, min(63, remaining))
        labels.append(
            bytes(rng.choice(alphabet) for _ in range(label_len))
        )
        remaining -= label_len
    qname = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
    qtype = rng.choice(tuple(qtypes))
    qclass = 1  # IN
    return qname + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")


# Low-entropy alphabet + vocabulary used for BENIGN DNS lookups.
BENIGN_DNS_ALPHABET = b"aeioulmnrst"
BENIGN_DNS_WORDS = (
    b"www", b"mail", b"api", b"static", b"cdn", b"docs", b"shop", b"news",
    b"login", b"help", b"images", b"video", b"search", b"update", b"portal",
)


def random_payload_dns_benign(
    rng: random.Random,
    max_qname_len: int = 40,
    qtypes: Optional[Sequence[int]] = None,
) -> bytes:
    """Return a low-entropy, word-like synthetic DNS query payload.

    Benign traffic in the lab looks like ``www.api.docs`` rather than like the
    random high-entropy labels used by the anomaly scenario, so the QNAME
    entropy and length features are genuinely discriminating instead of noise.
    """
    if qtypes is None:
        qtypes = (1, 28)  # A, AAAA
    n_labels = rng.randint(1, 3)
    labels = []
    total = 0
    for _ in range(n_labels):
        word = rng.choice(BENIGN_DNS_WORDS)
        if total + len(word) + 1 > max_qname_len:
            break
        labels.append(word + bytes(rng.choice(b"aeiou") for _ in range(rng.randint(0, 2))))
        total += len(labels[-1]) + 1
    if not labels:
        labels.append(b"www")
    qname = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
    qtype = rng.choice(tuple(qtypes))
    qclass = 1
    return qname + qtype.to_bytes(2, "big") + qclass.to_bytes(2, "big")