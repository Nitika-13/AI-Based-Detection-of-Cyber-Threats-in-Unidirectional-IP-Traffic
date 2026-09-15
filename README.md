This prototype uses software-enforced passive/read-only processing to emulate the unidirectional monitoring constraint. It is NOT security-equivalent to a certified physical hardware data diode.

Block 2 is the canonical sensor + feature extraction layer. It exists so that:

- one flow manager defines flow boundaries for training AND inference,
- one feature computation module defines the ML feature vector for training AND inference,
- one feature schema documents every feature's purpose, source, missing-value behaviour, and role (metadata / evidence_only / ml_feature).

The pipeline is identical for every input mode::

    PCAP sequential / PCAP replay / future live source
                        ↓
                   PacketSource
                        ↓
                   FlowManager        (one definition of a flow)
                        ↓
               compute_flow_features  (one definition of the features)
                        ↓
                canonical feature tables
                        ↓
           flows.csv + host_windows.csv + feature_schema.json

CICFlowMeter and Zeek may be used later for comparison/validation only. They must NOT become the ML input schema. The canonical schema is the one documented in feature_extractor/feature_schema.py.

Passive / read-only guarantee
-----------------------------

Block 2:

- READS: observed packets (from a PCAP, a replayed PCAP, or a future live interface),
- PROCESSES: packets → flows → features → aggregates → local logs/alerts/dashboard data,
- WRITES BACK TO THE MONITORED NETWORK: nothing.

It never:

- probes the source,
- initiates a handshake with the monitored source/destination,
- sends traffic back toward the monitored network,
- issues mitigation commands,
- decrypts TLS/QUIC payloads.

If an OS firewall/container/VM restriction is used to reinforce this, document it as software enforcement. This prototype does NOT claim physical security guarantees equivalent to a hardware data diode.