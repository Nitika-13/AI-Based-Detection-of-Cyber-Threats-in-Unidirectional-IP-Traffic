# Architecture — SIH 26145

## System Blocks

| Block | Directory | Status | Role |
|---|---|---|---|
| **Block 1** | `traffic_generator/` | ✅ Implemented | Generates synthetic unidirectional IP traffic (PCAP + labels + metadata) |
| **Block 2** | `feature_extractor/` | ⬜ Planned | Extracts NetFlow-style features from PCAPs |
| **Block 3** | `ml_engine/` | ⬜ Planned | ML-based threat detection/classification |
| **Block 4** | `dashboard/` | ⬜ Planned | Visualization / user interface |

## Block 1 — Traffic Generator

**Purpose:** Deterministically generate lab-only synthetic unidirectional IP
traffic for defensive research. Never transmits packets to a real interface.

**Modules:**

```
traffic_generator/
├── __init__.py          # Package exports
├── __main__.py          # python -m traffic_generator
├── cli.py               # argparse CLI
├── config.py            # GeneratorConfig, ScenarioConfig, constants
├── generator.py         # Orchestrator: scenarios → PCAP + CSV + JSON + manifest
├── labels.py            # CSV/JSON writers
├── models.py            # Flow, PacketSpec, GroundTruthRecord, flow_key
├── pcap_writer.py       # Scapy packet construction + wrpcap (no live TX)
├── utils.py             # Seeded RNG, IP/port/payload/timestamp helpers
└── scenarios/
    ├── base.py          # BaseScenario (abstract)
    ├── benign.py
    ├── ddos.py
    ├── c2_beacon.py
    ├── dns_anomaly.py
    ├── port_scan.py
    ├── exfiltration.py
    └── encrypted_anomaly.py
```

**Key design decisions:**

- **Unidirectional 5-tuple flow key:** `(src_ip, src_port, dst_ip, dst_port, protocol)`.
- **Byte-count convention:** sum of IP `total_length` (NetFlow convention).
- **Flow segmentation:** Block 1 guarantees inter-packet gaps ≤ 5s (Block 2
  idle timeout = 15s) and no two flows share a 5-tuple per run, so Block 2's
  segmentation (idle 15s / active 30s / TCP FIN-RST) is unambiguous.
- **Determinism:** global seed → per-scenario sub-seed; byte-identical output
  for the same seed.
- **Safety:** Scapy used only for packet construction and `wrpcap`; no live
  transmission. `encrypted_anomaly` is purely synthetic/pattern-based.

**Output:** `data/raw/{dataset_id}/` with `manifest.json`, `pcap/`, `labels/`,
`metadata/`. See `docs/dataset.md` for the full schema and Block 1 → Block 2
interface contract.

## Data Flow

```
Block 1 (traffic_generator)
  → data/raw/{dataset_id}/ (PCAP + labels + metadata + manifest)
  → Block 2 (feature_extractor)   [planned]
  → data/processed/ (NetFlow features)
  → Block 3 (ml_engine)           [planned]
  → models/ (trained artifacts)
  → Block 4 (dashboard)           [planned]