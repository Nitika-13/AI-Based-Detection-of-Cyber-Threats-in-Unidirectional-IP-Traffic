// Auto-generated from data/processed-final-check/sih26145/feature_schema.json
export const FEATURE_SCHEMA = {
  "schema_version": "1.0.0",
  "role_definitions": {
    "metadata": "Traceability/identity columns. MUST NOT be model inputs.",
    "evidence_only": "Human-readable alert evidence. Not a numeric model input.",
    "ml_feature": "Behavioural/numerical model input (canonical ML matrix)."
  },
  "source_definitions": {
    "pcap": "Derived from observed packets only.",
    "identity": "Flow identity from the unidirectional 5-tuple.",
    "run": "Run context from the Block 1 dataset manifest."
  },
  "tables": {
    "flow": {
      "file": "flows.csv",
      "description": "One row per reconstructed unidirectional flow. The ml_feature columns are the canonical model input for training AND inference.",
      "metadata": [
        {
          "name": "flow_id",
          "dtype": "str",
          "unit": "",
          "definition": "Unique flow id: {scenario}__{run_id}__{seq:04d}, assigned deterministically by (start_ts, flow_key).",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "run_id",
          "dtype": "str",
          "unit": "",
          "definition": "Run identifier from the dataset manifest (the split unit).",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "scenario",
          "dtype": "str",
          "unit": "",
          "definition": "Run-level scenario name from the dataset manifest.",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "flow_key",
          "dtype": "str",
          "unit": "",
          "definition": "Unidirectional 5-tuple src_ip:src_port->dst_ip:dst_port/protocol.",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "src_ip",
          "dtype": "str",
          "unit": "",
          "definition": "Source IPv4 address of the observed direction.",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "src_port",
          "dtype": "int",
          "unit": "",
          "definition": "Source port (0 for ICMP).",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "dst_ip",
          "dtype": "str",
          "unit": "",
          "definition": "Destination IPv4 address of the observed direction.",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "dst_port",
          "dtype": "int",
          "unit": "",
          "definition": "Destination port (0 for ICMP).",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "protocol",
          "dtype": "str",
          "unit": "",
          "definition": "Transport protocol: tcp, udp or icmp.",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "start_ts",
          "dtype": "float",
          "unit": "seconds since epoch",
          "definition": "Timestamp of the first packet in the flow.",
          "source": "pcap",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "end_ts",
          "dtype": "float",
          "unit": "seconds since epoch",
          "definition": "Timestamp of the last packet in the flow.",
          "source": "pcap",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "direction",
          "dtype": "str",
          "unit": "",
          "definition": "outbound when src_ip falls inside a configured monitored prefix, inbound when dst_ip does, otherwise unknown. Derived passively; evidence, not a model input.",
          "source": "run",
          "missing": "unknown",
          "role": "metadata"
        }
      ],
      "evidence_only": [
        {
          "name": "tcp_flags",
          "dtype": "str",
          "unit": "",
          "definition": "Comma-joined sorted set of distinct TCP flag letters observed, e.g. A,F,P,S. Empty for non-TCP flows.",
          "source": "pcap",
          "missing": "empty string",
          "role": "evidence_only"
        }
      ],
      "ml_feature": [
        {
          "name": "duration",
          "dtype": "float",
          "unit": "seconds",
          "definition": "end_ts - start_ts. Zero for a single-packet flow.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "iat_mean",
          "dtype": "float",
          "unit": "seconds",
          "definition": "Mean inter-arrival time between consecutive packets. Zero when packet_count < 2.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "iat_std",
          "dtype": "float",
          "unit": "seconds",
          "definition": "Population standard deviation (ddof=0) of inter-arrival times.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "iat_min",
          "dtype": "float",
          "unit": "seconds",
          "definition": "Minimum inter-arrival time. Zero when packet_count < 2.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "iat_max",
          "dtype": "float",
          "unit": "seconds",
          "definition": "Maximum inter-arrival time. Zero when packet_count < 2.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "iat_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of inter-arrival samples, i.e. packet_count - 1.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "iat_cv",
          "dtype": "float",
          "unit": "ratio",
          "definition": "Coefficient of variation of inter-arrival times: iat_std / iat_mean. Near 0 means machine-like periodicity (beaconing); large means bursty or irregular. Zero when iat_mean is 0.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "packet_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of packets in the flow.",
          "source": "pcap",
          "missing": "always >= 1",
          "role": "ml_feature"
        },
        {
          "name": "byte_count",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Sum of IP total_length over the flow's packets (NetFlow byte convention).",
          "source": "pcap",
          "missing": "always >= 40",
          "role": "ml_feature"
        },
        {
          "name": "packets_per_second",
          "dtype": "float",
          "unit": "packets_per_second",
          "definition": "packet_count / max(duration, 1e-6). The floor stops a single-packet flow dividing by zero.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "bytes_per_second",
          "dtype": "float",
          "unit": "bytes_per_second",
          "definition": "byte_count / max(duration, 1e-6).",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "min_packet_size",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Smallest IP total_length in the flow.",
          "source": "pcap",
          "missing": "always present",
          "role": "ml_feature"
        },
        {
          "name": "max_packet_size",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Largest IP total_length in the flow.",
          "source": "pcap",
          "missing": "always present",
          "role": "ml_feature"
        },
        {
          "name": "mean_packet_size",
          "dtype": "float",
          "unit": "bytes",
          "definition": "Arithmetic mean IP total_length.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "std_packet_size",
          "dtype": "float",
          "unit": "bytes",
          "definition": "Population standard deviation (ddof=0) of IP total_length.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "payload_bytes_total",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Total transport payload bytes. Zero for header-only flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "payload_ratio",
          "dtype": "float",
          "unit": "ratio",
          "definition": "payload_bytes_total / byte_count: how much of the flow is bulk data versus headers.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "payload_entropy_mean",
          "dtype": "float",
          "unit": "bits",
          "definition": "Mean Shannon entropy (bits per byte, 0-8) of each packet's transport payload. High means encrypted or incompressible content; low means structured or text data.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "payload_entropy_max",
          "dtype": "float",
          "unit": "bits",
          "definition": "Maximum per-packet payload Shannon entropy in the flow.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_syn_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Packets with the SYN flag set. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_fin_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Packets with the FIN flag set. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_rst_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Packets with the RST flag set. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_psh_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Packets with the PSH flag set. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_ack_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Packets with the ACK flag set. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_urg_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Packets with the URG flag set. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_syn_ratio",
          "dtype": "float",
          "unit": "ratio",
          "definition": "tcp_syn_count / packet_count. Near 1.0 for a SYN flood or a SYN-only scan probe. Zero for non-TCP flows.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "tcp_flag_diversity",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of distinct TCP flag letters observed in the flow (0 for non-TCP). A full connection shows several; a bare scan probe shows one.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "dns_packet_count",
          "dtype": "int",
          "unit": "count",
          "definition": "UDP/53 packets whose payload parsed as a DNS query fragment. Zero for non-DNS flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "dns_qname_len_mean",
          "dtype": "float",
          "unit": "bytes",
          "definition": "Mean QNAME wire length (including the root byte). Zero when no QNAME parsed.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "dns_qname_len_max",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Maximum QNAME wire length. Zero when no QNAME parsed.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "dns_qname_entropy_mean",
          "dtype": "float",
          "unit": "bits",
          "definition": "Mean Shannon entropy of the QNAME label bytes. Random tunnelling labels score far higher than word-like names.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "dns_qname_entropy_max",
          "dtype": "float",
          "unit": "bits",
          "definition": "Maximum QNAME label entropy in the flow.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "dns_qtype_mode",
          "dtype": "int",
          "unit": "categorical code",
          "definition": "Most common DNS query type (1=A, 2=NS, 15=MX, 16=TXT, 28=AAAA); ties resolve to the smallest value. Zero when no QNAME parsed.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tls_record_count",
          "dtype": "int",
          "unit": "count",
          "definition": "TCP/443 packets whose payload began with a plausible TLS record header. Zero for non-TLS flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tls_version_mode",
          "dtype": "int",
          "unit": "categorical code",
          "definition": "Most common TLS record version (0x0301-0x0304); ties resolve to the smallest value. Zero when no record parsed.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tls_content_type_mode",
          "dtype": "int",
          "unit": "categorical code",
          "definition": "Most common TLS record content type (20-23); ties resolve to the smallest value. Zero when no record parsed.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tls_record_len_mean",
          "dtype": "float",
          "unit": "bytes",
          "definition": "Mean TLS record declared length field. NOTE: this is the TLS *record* length, NOT a ClientHello length.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "tls_record_len_max",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Maximum TLS record declared length field.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "tls_payload_entropy_mean",
          "dtype": "float",
          "unit": "bits",
          "definition": "Mean Shannon entropy of the bytes inside the TLS records (bits per byte, 0-8).",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        }
      ]
    },
    "host_window": {
      "file": "host_windows.csv",
      "description": "One row per (run, scenario, window, host, role). Cross-flow aggregates for Block 3's correlation layer.",
      "metadata": [
        {
          "name": "run_id",
          "dtype": "str",
          "unit": "",
          "definition": "Run identifier (the split unit).",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "scenario",
          "dtype": "str",
          "unit": "",
          "definition": "Run-level scenario name.",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "window_index",
          "dtype": "int",
          "unit": "count",
          "definition": "Index of the tumbling time window summarised, relative to the capture's first packet.",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "window_start_ts",
          "dtype": "float",
          "unit": "seconds since epoch",
          "definition": "Inclusive start timestamp of the window.",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "window_end_ts",
          "dtype": "float",
          "unit": "seconds since epoch",
          "definition": "Exclusive end timestamp of the window.",
          "source": "run",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "ip",
          "dtype": "str",
          "unit": "",
          "definition": "The host whose activity is summarised.",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        },
        {
          "name": "role",
          "dtype": "str",
          "unit": "",
          "definition": "src when the host is the source of the observed flows, dst when it is the destination. A host can appear twice per window, once per role.",
          "source": "identity",
          "missing": "always present",
          "role": "metadata"
        }
      ],
      "ml_feature": [
        {
          "name": "flow_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of flows for this host/role inside the window.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "packet_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Total packets across those flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "byte_count",
          "dtype": "int",
          "unit": "bytes",
          "definition": "Total bytes (IP total_length convention) across those flows.",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "unique_peer_ip_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of distinct peers. For role=src this is destination-host fan-out; for role=dst it is source diversity (the DDoS signal).",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "unique_peer_port_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of distinct transport ports among the peers. For role=src this is destination-port fan-out (the port-scan signal).",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "peer_ip_entropy",
          "dtype": "float",
          "unit": "bits",
          "definition": "Shannon entropy (0-8) of the peer-IP distribution. 0 means all traffic went to or came from one peer; high means spread out.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "peer_port_entropy",
          "dtype": "float",
          "unit": "bits",
          "definition": "Shannon entropy (0-8) of the peer-port distribution.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "syn_flow_count",
          "dtype": "int",
          "unit": "count",
          "definition": "Number of those flows whose only observed flag set was SYN (probe-like).",
          "source": "pcap",
          "missing": "0",
          "role": "ml_feature"
        },
        {
          "name": "syn_flow_ratio",
          "dtype": "float",
          "unit": "ratio",
          "definition": "syn_flow_count / flow_count. Near 1.0 means the host was probing rather than talking.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "mean_flow_duration",
          "dtype": "float",
          "unit": "seconds",
          "definition": "Mean duration of those flows.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "mean_packets_per_flow",
          "dtype": "float",
          "unit": "packets",
          "definition": "Mean packet_count of those flows.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "packet_rate_pps",
          "dtype": "float",
          "unit": "packets_per_second",
          "definition": "packet_count spread over the window length.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        },
        {
          "name": "byte_rate_bps",
          "dtype": "float",
          "unit": "bytes_per_second",
          "definition": "byte_count spread over the window length.",
          "source": "pcap",
          "missing": "0.0",
          "role": "ml_feature"
        }
      ]
    }
  },
  "not_implemented": {
    "ja3_ja4_fingerprints": "Block 1 emits TLS record headers only: no ClientHello body, no SNI, no cipher-suite or extension lists. JA3/JA4 and SNI features are genuinely impossible and are not attempted.",
    "payload_decryption": "Never performed. All statistics and entropies are computed on raw observed bytes."
  }
} as const;
