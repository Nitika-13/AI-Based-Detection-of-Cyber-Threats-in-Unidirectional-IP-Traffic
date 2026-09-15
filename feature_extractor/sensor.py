"""Packet sources: the single entry point for every Block 2 input mode.

The SIH problem statement requires near-real-time behaviour, so Block 2 is
built around ONE sensor interface rather than three different pipelines. Every
input mode yields the same :class:`PacketRecord` objects, which feed the same
:class:`feature_extractor.flow_manager.FlowManager` and therefore produce
features with identical semantics.

Modes
-----
``sequential`` (MODE A)
    Read a PCAP and yield packets in timestamp order. Used for training and
    batch evaluation.

``replay`` (MODE B)
    Read the same PCAP but pace the yield according to packet timestamps, so
    the downstream pipeline runs as if the capture were arriving live. Pacing
    is disabled by default so tests stay fast and outputs stay byte-identical
    to MODE A.

``live`` (MODE C)
    Reserved for a future live interface source. Deliberately NOT implemented:
    attaching to an interface is an OS/network action this read-only prototype
    does not perform. The stub exists so Block 3 can select ``mode="live"``
    and get an explicit failure instead of a silent fallback to a PCAP.

Passive/read-only guarantee
---------------------------
No mode opens a socket, transmits a packet, sends a probe, or completes a
handshake with anything on a monitored network. Reading a PCAP is a local file
operation. This prototype uses software-enforced passive/read-only processing
to emulate the unidirectional monitoring constraint; it is NOT
security-equivalent to a certified physical hardware data diode.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Iterator, List, Optional

from .models import PacketRecord

MODE_SEQUENTIAL = "sequential"
MODE_REPLAY = "replay"
MODE_LIVE = "live"

# Every mode Block 2 can be asked for. Used for CLI/validation errors.
SUPPORTED_MODES = (MODE_SEQUENTIAL, MODE_REPLAY, MODE_LIVE)


class PacketSource(ABC):
    """Abstract source of :class:`PacketRecord` objects."""

    #: One of ``sequential`` / ``replay`` / ``live``.
    mode: str = "abstract"

    @abstractmethod
    def packets(self) -> Iterator[PacketRecord]:
        """Yield packets in timestamp order."""
        raise NotImplementedError

    def close(self) -> None:
        """Release any underlying resource. Default: nothing to release."""

    def __enter__(self) -> "PacketSource":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class PcapFileSource(PacketSource):
    """MODE A: sequential PCAP processing (timestamp ordered)."""

    mode = MODE_SEQUENTIAL

    def __init__(self, path) -> None:
        self.path = str(path)

    def packets(self) -> Iterator[PacketRecord]:
        from .pcap_reader import iter_pcap_records

        yield from iter_pcap_records(self.path)


class PcapReplaySource(PcapFileSource):
    """MODE B: replay a PCAP according to its packet timestamps.

    ``speed`` scales the replay clock: ``1.0`` is real time, ``10.0`` is ten
    times faster, ``0`` disables pacing entirely (output identical to MODE A).
    The yielded records are identical to MODE A; only wall-clock pacing
    differs, so features never depend on the mode.
    """

    mode = MODE_REPLAY

    def __init__(self, path, speed: float = 0.0) -> None:
        super().__init__(path)
        if speed < 0:
            raise ValueError(f"replay speed must be >= 0, got {speed}")
        self.speed = float(speed)

    def packets(self) -> Iterator[PacketRecord]:
        if self.speed == 0:
            yield from super().packets()
            return

        previous_ts: Optional[float] = None
        for record in super().packets():
            if previous_ts is not None:
                # Scale the capture-time delta into wall-clock time.
                delay = (record.timestamp - previous_ts) / self.speed
                if delay > 0:
                    time.sleep(delay)
            previous_ts = record.timestamp
            yield record


class LiveInterfaceSource(PacketSource):
    """MODE C: placeholder for a future live interface capture.

    Deliberately unimplemented. This prototype is strictly passive/read-only:
    it never puts an interface into promiscuous mode, never transmits, and
    never interacts with a monitored network. When a live source is added it
    MUST implement the same :class:`PacketSource` interface so that the flow
    manager and feature extraction are reused unchanged.
    """

    mode = MODE_LIVE

    def __init__(self, interface: str = "") -> None:
        self.interface = interface

    def packets(self) -> Iterator[PacketRecord]:
        raise NotImplementedError(
            "Live interface capture (MODE C) is not implemented in this "
            "prototype. Block 2 is a passive, read-only sensor: it supports "
            "PCAP sequential processing and PCAP timestamp replay. A live "
            "source must implement PacketSource without transmitting or "
            "probing the monitored network."
        )
        yield  # pragma: no cover - keeps this a generator function


def build_source(mode, pcap_path=None, interface: str = "", speed: float = 0.0) -> PacketSource:
    """Build the packet source for the requested mode.

    ``pcap_path`` is required for the sequential and replay modes.
    """
    if mode == MODE_SEQUENTIAL:
        if pcap_path is None:
            raise ValueError("mode 'sequential' requires a pcap path")
        return PcapFileSource(pcap_path)
    if mode == MODE_REPLAY:
        if pcap_path is None:
            raise ValueError("mode 'replay' requires a pcap path")
        return PcapReplaySource(pcap_path, speed=speed)
    if mode == MODE_LIVE:
        return LiveInterfaceSource(interface)
    raise ValueError(
        f"Unknown mode '{mode}'. Supported modes: {', '.join(SUPPORTED_MODES)}"
    )


def source_modes() -> List[str]:
    """Return the supported mode names (for CLI help / diagnostics)."""
    return list(SUPPORTED_MODES)

