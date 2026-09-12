# Architecture — SIH 26145

## System Blocks

| Block | Directory | Status | Role |
|---|---|---|---|
| **Block 1** | `traffic_generator/` | ✅ Implemented | Generates synthetic unidirectional IP traffic (PCAP + labels + metadata) |
| **Block 2** | `feature_extractor/` | ✅ Implemented | Extracts NetFlow-style features from PCAPs |
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

## Block 2 — Feature Extractor

**Purpose:** Read Block 1 PCAPs (read-only), reconstruct unidirectional flows,
compute ML-ready NetFlow-style features, validate against ground truth.

**Modules:** `feature_extractor/` — `models.py` (PacketRecord, ExtractedFlow,
FEATURE_COLUMNS), `pcap_reader.py` (Scapy rdpcap wrapper, captures transport
payload bytes), `payload_features.py` (DNS/TLS-record parsers, Shannon
entropy — no decryption), `flow_reconstructor.py` (5-tuple grouping +
boundary rules), `features.py` (feature computation), `labels.py` (GT
reader/join — labels only), `validation.py` (extracted-vs-GT comparison +
DNS/TLS structural checks), `writer.py`, `extractor.py` (orchestrator),
`cli.py`.

**Key design decisions:**

- **Features come ONLY from PCAPs.** GT CSV is used exclusively for labels
  and post-extraction validation (verified by a dedicated test).
- **Flow rules:** direction-sensitive 5-tuple; idle timeout 15s; active
  timeout 30s.
- **Documented deviation (user-approved Option 2):** TCP FIN/RST marks the
  end of a connection attempt but does NOT split a flow — same-5-tuple
  packets re-join. Rationale: frozen Block 1 GT defines one flow per
  5-tuple per run (c2_beacon emits repeated FIN-terminated beacon
  connections within a single GT flow). FIN/RST remain as features
  (tcp_fin_count/tcp_rst_count).
- **Output:** `data/processed/{dataset_id}/` — `flows.csv` (features only),
  `flows_with_labels.csv` (join by `run_id + flow_key`),
  `validation_report.json`, `extraction_manifest.json`.
- **Determinism:** no randomness; deterministic flow_id assignment
  (`{run_id}__{seq:04d}` sorted by `(start_ts, flow_key)`); byte-identical
  output across runs.
- **DNS metadata (PCAP-derived):** for UDP dst-port-53 flows —
  `dns_packet_count`, `dns_qname_len_mean/max`, `dns_qname_entropy_mean/max`,
  `dns_qtype_mode`. Parsed with a custom byte-level parser because Block 1
  emits bare QNAME fragments with no DNS header (Scapy DNS cannot dissect
  them). Zero for non-DNS flows.
- **TLS record metadata (PCAP-derived, no decryption):** for TCP dst-port-443
  flows — `tls_record_count`, `tls_version_mode`, `tls_content_type_mode`,
  `tls_record_len_mean/max`, `tls_payload_entropy_mean`.
- **Synthetic TLS limitation (explicit):** Block 1 emits TLS-like *record
  headers only* — there is NO real ClientHello body, NO SNI, NO
  cipher-suite/extension lists. Therefore JA3/JA4 fingerprints and SNI
  features are genuinely impossible with the current generator, and
  `tls_record_len_*` is the TLS *record* declared length, NOT a ClientHello
  length. No payload decryption is performed at any point.

## Data Flow

```
Block 1 (traffic_generator)
  → data/raw/{dataset_id}/ (PCAP + labels + metadata + manifest)
  → Block 2 (feature_extractor)
  → data/processed/ (NetFlow features)
  → Block 3 (ml_engine)           [planned]
  → models/ (trained artifacts)
  → Block 4 (dashboard)           [planned]