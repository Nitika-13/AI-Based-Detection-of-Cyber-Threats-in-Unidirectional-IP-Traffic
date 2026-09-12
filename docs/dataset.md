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