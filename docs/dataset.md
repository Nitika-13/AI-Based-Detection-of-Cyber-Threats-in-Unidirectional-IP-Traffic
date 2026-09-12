# Dataset — Block 1 Output (Traffic Generator)

## Overview

Block 1 (`traffic_generator/`) generates deterministic, lab-only synthetic
unidirectional IP traffic for defensive research. It produces PCAP files,
flow-level ground-truth labels, per-run metadata, and a dataset manifest.

**Safety:** No packets are ever transmitted to a real network interface.
Scapy is used only for packet construction and PCAP file writing.

## Output Layout

```
data/raw/{dataset_id}/
├── manifest.json                  # Block 2 entry point
├── pcap/
│   └── {dataset_id}__{scenario}__{run_id}.pcap
├── labels/
│   └── {dataset_id}__{scenario}__{run_id}.csv
└── metadata/
    └── {dataset_id}__{scenario}__{run_id}.json
```

## Supported Scenarios & Labels

| Scenario | Flow label | Synthetic profile |
|---|---|---|
| `benign` | `benign` | Mixed web (TCP/80,443), DNS (UDP/53), ICMP echo |
| `ddos` | `ddos` + `benign` background | High-rate SYN flood + UDP flood to a victim |
| `c2_beacon` | `c2_beacon` + `benign` background | Periodic low-rate TCP/443 beacons |
| `dns_anomaly` | `dns_anomaly` + `benign` background | High-volume DNS queries, long QNAMEs |
| `port_scan` | `port_scan` + `benign` background | Sequential/random TCP SYN scans |
| `exfiltration` | `exfiltration` + `benign` background | Large sustained outbound transfers |
| `encrypted_anomaly` | `encrypted_anomaly` + `benign` background | Synthetic TLS-like flows, pattern-based only |

**Scenario vs. Label:** `scenario` is the run-level traffic mix; `label` is the
per-flow class. Attack scenario runs contain both `benign` background flows and
anomalous flows, each with exactly one label.

## Ground-Truth CSV Schema

| Column | Type | Notes |
|---|---|---|
| `flow_id` | str | Unique within a run |
| `run_id` | str | Matches PCAP filename |
| `scenario` | str | Run-level scenario name |
| `label` | str | Flow-level class (one of 7) |
| `src_ip` / `src_port` | str / int | Unidirectional source |
| `dst_ip` / `dst_port` | str / int | Unidirectional destination (0 for ICMP) |
| `protocol` | str | `tcp` / `udp` / `icmp` |
| `flow_key` | str | `src_ip:src_port->dst_ip:dst_port/protocol` |
| `start_ts` / `end_ts` | float | Epoch seconds, 6 decimal places |
| `duration` | float | `end_ts - start_ts` |
| `packet_count` | int | Packets in flow |
| `byte_count` | int | Sum of IP `total_length` (NetFlow convention) |
| `tcp_flags` | str | Comma-joined sorted unique flags; empty for non-TCP |

## Block 1 → Block 2 Interface Contract

1. **manifest.json** — Block 2 iterates `runs[]` for PCAP/labels/metadata paths.
2. **PCAP** — sole source of feature values. Block 2 reconstructs all features
   independently from the PCAP (never from the CSV).
3. **Label CSV** — sole source of `label`; join on `(run_id, flow_key)`.
4. **Metadata JSON** — reproducibility context (seed, version, IP ranges).

**Flow boundary rules (Block 2):** group by unidirectional 5-tuple
`(src_ip, src_port, dst_ip, dst_port, protocol)`; idle timeout 15s; active
timeout 30s; TCP closes on FIN/RST. Block 1 guarantees inter-packet gaps
within a flow never exceed 5s and no two flows share a 5-tuple per run,
making segmentation and the 1:1 join unambiguous.

## Determinism

Same `--seed` produces byte-identical PCAPs and CSVs. Each scenario derives a
deterministic sub-seed from the global seed, run index, and scenario name.

## Block 2 Output (Feature Extractor)

```
data/processed/{dataset_id}/
├── flows.csv                  # 44 feature columns, no label
├── flows_with_labels.csv      # 44 features + label (join by run_id + flow_key)
├── validation_report.json     # extracted-vs-GT comparison per run
└── extraction_manifest.json   # versions, timeouts, conventions, counts
```

`flows.csv` = the 32 base NetFlow-style columns (5-tuple, timing, volume,
rates, size stats, IAT stats, TCP flags + per-flag counts) plus 12
PCAP-derived DNS/TLS metadata columns appended in fixed order:

| Column | Type | Notes |
|---|---|---|
| `dns_packet_count` | int | UDP/53 packets with parseable query fragment |
| `dns_qname_len_mean` / `dns_qname_len_max` | float / int | QNAME wire length incl. root byte |
| `dns_qname_entropy_mean` / `dns_qname_entropy_max` | float | Shannon entropy of QNAME label bytes (bits) |
| `dns_qtype_mode` | int | Most common query type (ties → smallest) |
| `tls_record_count` | int | TCP/443 packets with valid record header |
| `tls_version_mode` | int | Most common record version (e.g. 771 = 0x0303) |
| `tls_content_type_mode` | int | Most common content type (20–23) |
| `tls_record_len_mean` / `tls_record_len_max` | float / int | TLS *record* declared length (**not** ClientHello length) |
| `tls_payload_entropy_mean` | float | Shannon entropy of record inner bytes (bits) |

All 12 are `0`/`0.0` for non-applicable flows. No decryption is performed;
all values come from cleartext synthetic metadata in the PCAP.

**Synthetic TLS limitation (explicit):** Block 1 emits TLS-like *record
headers only* — no real ClientHello body, no SNI, no cipher-suite/extension
lists. JA3/JA4 fingerprints and SNI features are therefore genuinely
impossible with the current generator and are not attempted.
