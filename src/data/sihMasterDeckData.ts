export interface SIHSlide {
  id: string;
  slideNumber: number;
  title: string;
  subtitle: string;
  badge: string;
}

export const SIH_METADATA = {
  problem_statement_id: '26145',
  problem_title: 'AI-Based Detection of Cyber Threat in Unidirectional IP Traffic',
  theme: 'Blockchain & Cybersecurity',
  category: 'Software',
  team_id: 'SNATCH01',
  team_name: 'SNATCH01',
  organization: 'National Technical Research Organisation (NTRO)',
  department: 'Cyber Security Operations / Strategic Technology Group',
  solution_name: 'UniSentry',
  solution_tagline: 'AI-Powered Passive Cyber Threat Detection and Intelligence Platform for Unidirectional IP Traffic',
  core_proposition: 'When you cannot safely talk back to the network, make the traffic itself your source of intelligence.',
  solution_statement: 'A passive AI/ML pipeline that analyses one-way traffic using CICFlowMeter + Zeek, specialist detectors and correlation/fusion to detect multiple cyber threats. It generates explainable alerts with threat class, confidence, severity and evidence through a Streamlit dashboard — without probing, payload decryption or any return path to the protected network.'
};

export const PIPELINE_DETECTION_STEPS = [
  {
    step: 1,
    title: 'One-Way Traffic Capture (Passive Mirroring)',
    tools: 'Network Switch → SPAN / TAP (Read-only) → Captured Traffic',
    details: 'Passive mirroring (no packets sent back), Scapy / PCAP capture, 500 flows/sec (benchmark)'
  },
  {
    step: 2,
    title: 'Feature Extraction (Parallel Processing)',
    tools: 'CICFlowMeter (Flow statistics, 5-10s windows, no decryption) + Zeek (DNS / TLS / QUIC, Metadata, Connection details)',
    details: 'Flow statistics, 5-10s rolling windows, DNS/TLS metadata without payload decryption'
  },
  {
    step: 3,
    title: 'Preprocessing',
    tools: 'Missing value handling, Encoding, Normalization, Feature scaling',
    details: 'Robust scalar normalization, NaN imputation, categorical encoding for Zeek metadata'
  },
  {
    step: 4,
    title: 'Specialist Detectors (Parallel)',
    tools: 'Flow RF (DDoS, Port Scan, Botnet C2, Exfiltration) | DNS RF (DGA, DNS Tunneling) | TLS/JA3 Rules (Suspicious encrypted flow)',
    details: 'Dedicated AI models & rule sets tailored to specific attack behaviors'
  },
  {
    step: 5,
    title: 'Fusion & Classification',
    tools: 'Weighted fusion, Rule + model, Confidence score, Assign threat class',
    details: 'Multi-specialist consensus, confidence weighting, deterministic rule override'
  },
  {
    step: 6,
    title: 'Alert Generation',
    tools: 'Timestamp, Flow ID, Threat class, Confidence & severity, Evidence (features/rule)',
    details: 'Outputs standardized alert: Classification, Confidence score (0-100%), Severity level, Evidence'
  }
];

export const PIPELINE_LEARNING_STEPS = [
  { step: 1, title: 'Alert Generation', desc: 'Detailed alert (timestamp, flow ID, class, severity), evidence, enriched metadata' },
  { step: 2, title: 'Storage (PostgreSQL)', desc: 'Store alerts, historical flow data, security audit logs' },
  { step: 3, title: 'Dashboard & Trend Analysis', desc: 'Real-time alerts, attack trends & patterns, source/destination analysis, visualizations & filters' },
  { step: 4, title: 'Analyst Review', desc: 'Validate alerts, inspect evidence, approve / reject verdict' },
  { step: 5, title: 'Feedback Loop', desc: 'True positive / False positive labeling, new rules, analyst comments' },
  { step: 6, title: 'Safe Learning & Retraining', desc: 'Human-in-the-loop approval, golden test set validation, shadow deployment, scheduled retraining' },
  { step: 7, title: 'Model & Rule Update', desc: 'Update models, update behavioral rules, version control' },
  { step: 8, title: 'Continuous Improvement', desc: 'Higher accuracy, fewer false positives, new attack patterns, stronger defenses' }
];

export const TECHNOLOGIES_USED = [
  { name: 'Python', role: 'Development & Orchestration' },
  { name: 'Pandas + NumPy', role: 'Data Processing & Feature Engineering' },
  { name: 'Scikit-learn', role: 'ML Models & Preprocessing' },
  { name: 'Scapy', role: 'Packet Capture (Read-Only Replay)' },
  { name: 'CICFlowMeter', role: 'Flow Extraction' },
  { name: 'Zeek', role: 'Protocol Analytics (DNS + TLS/QUIC)' },
  { name: 'Streamlit / Web', role: 'Dashboard & Visualization' }
];

export const FEASIBILITY_STRATEGIES = [
  {
    id: 1,
    title: '1. Data Enhancement',
    points: ['Use diverse datasets & traffic simulation', 'Apply data augmentation (SMOTE)', 'Continuous data collection & labelling'],
    badge: 'Better Model Generalization'
  },
  {
    id: 2,
    title: '2. Robust Detection',
    points: ['Ensemble of models + rule sets', 'Confidence & severity scoring', 'Human validation for critical alerts'],
    badge: 'Higher Accuracy'
  },
  {
    id: 3,
    title: '3. Optimized Pipeline',
    points: ['Efficient streaming (rolling windows)', 'Parallel processing (CICFlowMeter + Zeek)', 'Resource monitoring & scaling'],
    badge: 'Low Latency'
  },
  {
    id: 4,
    title: '4. Continuous Learning',
    points: ['Scheduled retraining', 'Multi-analyst agreement (>80%)', 'Shadow deployment & golden set validation'],
    badge: 'Stable Performance'
  },
  {
    id: 5,
    title: '5. Security Measures',
    points: ['Encrypted storage & secure access', 'Role-based control (RBAC)', 'Audit logs & tampering monitoring'],
    badge: 'Data Safety'
  },
  {
    id: 6,
    title: '6. Scalable Architecture',
    points: ['Containerized setup', 'Modular microservice design', 'Easy integration with enterprise SIEM/SOAR'],
    badge: 'Real-world Ready'
  }
];

export const FEASIBILITY_CHAIN = [
  { letter: 'V', title: 'Validated Tech Stack', desc: 'Mature open-source tools (Python, Scikit-learn, Scapy, Zeek)' },
  { letter: 'I', title: 'Integration-Ready', desc: 'Fits hardware data-diode setups with strictly zero return packets' },
  { letter: 'A', title: 'Accurate Detection', desc: 'Specialist models per attack (Flow RF, DNS RF, JA3 TLS rules)' },
  { letter: 'B', title: 'Bounded Latency', desc: 'Alerts generated within seconds (< 2.0s) for line-rate traffic' },
  { letter: 'L', title: 'Low-Cost Deployment', desc: 'Free-tier & laptop capable, no costly proprietary black boxes' },
  { letter: 'E', title: 'Explainable Alerts', desc: 'Every alert ships mathematical proof, rules, and Gini feature values' }
];

export const IMPACT_BENEFITS_RADIAL = [
  {
    id: 1,
    title: '1. Multi-Layered Detection',
    desc: 'Flow, DNS, TLS/QUIC signals + rule-based checks catch DDoS, port scans, botnet C2, DGA & tunneling.'
  },
  {
    id: 2,
    title: '2. Fused Threat Scoring',
    desc: 'Cross-branch correlation combines detector outputs to sharply cut false positives.'
  },
  {
    id: 3,
    title: '3. Evidence-Backed Alerts',
    desc: 'Every alert ships with confidence score, severity & supporting pattern evidence.'
  },
  {
    id: 4,
    title: '4. Live Performance Visibility',
    desc: 'Continuous throughput & alert-latency tracking keeps the pipeline accountable.'
  },
  {
    id: 5,
    title: '5. Faster Security Response',
    desc: 'Automated detect-alert-visualize pipeline shrinks time between attack and action.'
  },
  {
    id: 6,
    title: '6. Prioritized Threat Triage',
    desc: 'Severity-ranked alerts help analysts focus on the most dangerous threats first.'
  },
  {
    id: 7,
    title: '7. Human-in-the-Loop Learning',
    desc: 'Analyst feedback plus validation & human approval drive safe model retraining.'
  },
  {
    id: 8,
    title: '8. Scalable, Low-Burden Security',
    desc: 'Absorbs rising traffic automatically, cutting repetitive manual analysis load.'
  }
];

export const RESEARCH_TECH_TABLE = [
  {
    layer: 'Programming',
    chosenTech: 'Python',
    reason: 'One language can cover packet handling, feature processing, and ML. Its versatility simplifies workflows, accelerates development, and ensures maintainability.'
  },
  {
    layer: 'Data Processing',
    chosenTech: 'Pandas + NumPy',
    reason: "Simple, mature tools for the prototype's tabular flow and DNS features. Their reliability, efficiency, and widespread adoption make them ideal."
  },
  {
    layer: 'ML Library',
    chosenTech: 'Scikit-learn',
    reason: 'Provides Random Forest, preprocessing, and evaluation in one lightweight stack. Its simplicity, flexibility, and efficiency streamline experimentation effectively.'
  },
  {
    layer: 'PCAP Handling',
    chosenTech: 'Scapy — PCAP replay',
    reason: 'Python-native packet parsing and controlled replay fit the prototype pipeline, ensuring efficiency, reproducibility, and seamless integration across multiple stages.'
  },
  {
    layer: 'Flow Features',
    chosenTech: 'CICFlowMeter',
    reason: 'Generates bidirectional flow records with statistical features suited to ML, enabling accurate detection, robust classification, and streamlined model training.'
  },
  {
    layer: 'Network Metadata',
    chosenTech: 'Zeek — DNS + TLS/QUIC',
    reason: 'Produces structured protocol metadata while operating as a passive analyzer, ensuring non-intrusive monitoring, reliable insights, and comprehensive network visibility.'
  },
  {
    layer: 'Flow Detection',
    chosenTech: 'Flow RF — DDoS, Scan, Botnet C2, Exfiltration',
    reason: 'Handles non-linear flow features with a straightforward training workflow, simplifying model design, improving accuracy, and supporting flexible experimentation effectively.'
  },
  {
    layer: 'DNS Detection',
    chosenTech: 'DNS RF — DGA, DNS Tunnelling',
    reason: "A compact classifier is easier to train and integrate for the prototype's DNS features, reducing complexity, improving performance, and enhancing adaptability."
  },
  {
    layer: 'Encrypted Traffic',
    chosenTech: 'TLS/QUIC Rules',
    reason: 'Works from observable encrypted-flow metadata instead of relying on decrypted payloads, ensuring privacy, maintaining security, and enabling effective anomaly detection.'
  },
  {
    layer: 'Visualization + Input',
    chosenTech: 'Streamlit + PCAP / Simulated Traffic',
    reason: 'Python-native dashboard plus reproducible inputs keeps testing and demonstration controlled, ensuring clarity, consistency, and reliable evaluation during prototype presentations.'
  }
];

export const SOLUTION_GAP_ANALYSIS = [
  {
    gap: 'Lack of threat detection in one-way traffic',
    solution: 'Uses flow + protocol metadata with specialist detectors (Flow RF, DNS RF, TLS/QUIC).',
    impact: 'Detects attacks even without return traffic.'
  },
  {
    gap: 'Encrypted traffic analysis',
    solution: "Works on metadata (not payload), so encryption isn't a blocker.",
    impact: 'Still analyses and flags threats accurately.'
  },
  {
    gap: 'Missed multi-step / correlated attacks',
    solution: 'Correlation + fusion of alerts with temporal analysis.',
    impact: 'Finds larger, complex attack patterns.'
  },
  {
    gap: 'High false positives',
    solution: 'Analyst review + confidence & severity scoring.',
    impact: 'More accurate and reliable alerts.'
  },
  {
    gap: 'Lack of explainability',
    solution: 'Provides evidence (key features and patterns) in alerts.',
    impact: 'Helps analysts understand and act faster.'
  },
  {
    gap: 'No continuous improvement',
    solution: 'Feedback loop with model update (retraining + human approval).',
    impact: 'Adapts to new attack patterns over time.'
  },
  {
    gap: 'No clear actionable insights',
    solution: 'Streamlit dashboard with threat class, confidence, severity and evidence.',
    impact: 'Enables quick, informed response and investigation.'
  }
];

export const INNOVATION_PILLARS = [
  {
    id: 1,
    title: 'Specialist Detection',
    desc: 'Different threats, different detectors (Flow RF, DNS RF, TLS/QUIC rules).'
  },
  {
    id: 2,
    title: 'Alert Correlation',
    desc: 'Connects related alerts over time to find larger attack patterns.'
  },
  {
    id: 3,
    title: 'Explainable Alerts',
    desc: 'Shows why an alert was generated: key features, Gini values, and pattern proof.'
  },
  {
    id: 4,
    title: 'Alert Accountability',
    desc: 'Prioritised and reviewed as Confirmed Threat, False Positive, or Needs Investigation.'
  },
  {
    id: 5,
    title: 'Safe Learning',
    desc: 'Feedback + retraining → updates → human approval for controlled improvement.'
  },
  {
    id: 6,
    title: 'One-Way Security Boundary',
    desc: 'Adds intelligence without creating a return path to the protected network.'
  }
];

export const SIH_COMPARISON_TABLE = [
  {
    dimension: 'Architecture Model',
    unisentry: '3-Specialist Ensemble (Flow RF + DNS RF + JA3) with Weighted Fusion',
    academic: 'Single Generalist Model (e.g. Single MLP / RF on CICIDS)',
    snortSuricata: 'Signature & Static Heuristics only',
    commercialNDR: 'Proprietary Unsupervised Anomaly Engine'
  },
  {
    dimension: 'Data Diode Support',
    unisentry: 'Native Unidirectional (Strictly 0 return packets, passive timeouts)',
    academic: 'Assumes Bidirectional NetFlow / TCP handshake pairs',
    snortSuricata: 'Breaks stateful tracking without bidirectional ACKs',
    commercialNDR: 'Requires bidirectional mirror or dual TAP spans'
  },
  {
    dimension: 'DGA & Encrypted Threats',
    unisentry: 'Dedicated DNS Lexical Classifier + JA3/JA4 Fingerprint Specialist',
    academic: 'Fails (CICIDS2017 has zero DGA or encrypted malware)',
    snortSuricata: 'Needs explicit IP/domain blacklist (zero-day blind)',
    commercialNDR: 'Heuristic SSL cert inspection'
  },
  {
    dimension: 'Explainability & Evidence',
    unisentry: 'Full transparent evidence: Matched Rules + Top Gini Features + STIX 2.1',
    academic: 'Black-box prediction score with no root-cause trace',
    snortSuricata: 'Rule ID only, no confidence or feature weighting',
    commercialNDR: 'Proprietary risk score with limited feature telemetry'
  },
  {
    dimension: 'Continuous Learning Safety',
    unisentry: '5-Stage Poisoning-Resistant Safe Learning Loop with Golden Set gate',
    academic: 'Static offline model (never retrains) or naive online updates',
    snortSuricata: 'Manual signature updates only',
    commercialNDR: 'Unsupervised baseline drift (vulnerable to slow poisoning)'
  },
  {
    dimension: 'Inference Throughput',
    unisentry: '95,928 flows/sec per CPU core (measured on 252K test set)',
    academic: '< 5,000 flows/sec (heavy deep learning overhead)',
    snortSuricata: 'High (pattern matching in C)',
    commercialNDR: 'High (requires dedicated proprietary appliance)'
  },
  {
    dimension: 'Noise & Jitter Tolerance',
    unisentry: '100% accuracy preserved under 2% realistic network jitter',
    academic: 'Rapid degradation without robust feature engineering',
    snortSuricata: 'High tolerance to jitter, brittle to packet fragmentation',
    commercialNDR: 'Moderate tolerance with sliding time-windowing'
  }
];

export const SIH_RISK_MITIGATIONS = [
  {
    id: 'R1',
    title: 'Absence of Return Packets (Unidirectional Constraint)',
    risk: 'Traditional stateful firewalls track SYN-ACK-ACK handshakes. In a diode, reverse traffic never reaches the sensor.',
    mitigation: 'UniSentry engineered unidirectional forward-only features (Out_In_Byte_Ratio, TCP SYN Ratio, Incomplete_Handshake flag) and autonomous idle/active flow timeouts (15s/30s).'
  },
  {
    id: 'R2',
    title: 'Adversarial Data Poisoning via Analyst Feedback',
    risk: 'An insider or deceived analyst might mark malicious traffic as benign, poisoning future retrained models.',
    mitigation: 'Implemented 5-Stage Safe Learning Loop: multi-analyst consensus (>80%), statistical outlier isolation, silent shadow model deployment, and strictly immutable Golden Test Set validation with human sign-off.'
  },
  {
    id: 'R3',
    title: 'Zero-Day DGA & DNS Tunneling in CICIDS2017 Gap',
    risk: 'CICIDS2017 dataset contains zero DGA examples. A single model trained exclusively on it cannot classify DGA.',
    mitigation: 'Integrated Specialist 2: a dedicated lexical Random Forest model trained on Bambenek DGA feeds vs Tranco benign domains, computing Shannon entropy, n-gram pronounceability, and QNAME length.'
  },
  {
    id: 'R4',
    title: 'Encrypted Malware Traffic without Decryption Keys',
    risk: 'National security diodes cannot decrypt arbitrary TLS 1.3 traffic without violating secrecy and performance.',
    mitigation: 'Integrated Specialist 3: passive TLS Client Hello JA3/JA3S/JA4 fingerprinting, TLS record length variance, and payload entropy framing without payload decryption.'
  },
  {
    id: 'R5',
    title: 'Analyst Alert Fatigue from Redundant Packet Bursts',
    risk: 'A single volumetric flood generates thousands of individual flow alerts within seconds, overwhelming SOC operators.',
    mitigation: 'Temporal Alert Correlation Engine aggregates related alerts within 10-second host windows or IP subnets into unified Security Incidents, reducing raw alert volume by up to 88%.'
  },
  {
    id: 'R6',
    title: 'High-Throughput Line Rate Degradation',
    risk: 'Heavy deep learning architectures (LSTMs, Transformers) drop packets at multi-gigabit line rates.',
    mitigation: 'Lightweight Random Forest architecture evaluated at 95,928 flows/second in scikit-learn, easily scaling to 10 Gbps with multi-threading and eBPF kernel offload.'
  }
];

export const SIH_JURY_QA = [
  {
    question: 'Why did you use Random Forest instead of Deep Learning (LSTM, GRU, or Transformers)?',
    answer: 'Random Forest delivers three decisive operational advantages for unidirectional diodes: (1) Inference speed: 95,928 flows/sec vs ~2,000 for LSTMs, meeting strict line-rate requirements; (2) Deterministic Explainability: Gini feature importances are mathematically traceable for defense audits, whereas deep networks remain opaque black boxes; (3) Sample efficiency: with SMOTE augmentation on rare classes, RF achieved 100% accuracy and 0.91 macro F1 on 252K test samples in just 408s training time.'
  },
  {
    question: 'How does your solution detect encrypted threats without decrypting packets?',
    answer: 'We deploy Specialist 3, which inspects unencrypted metadata and behavioral statistical patterns: (1) JA3/JA4 cryptographic fingerprints extracted from the plaintext TLS Client Hello (cipher suites, TLS extensions, elliptic curves); (2) TLS record length distribution and inter-record timing; (3) Shannon entropy of payload segments. Known malware strains (e.g. Cobalt Strike, Emotet) exhibit distinctive JA3 hashes regardless of certificate encryption.'
  },
  {
    question: 'How do you prevent an attacker from poisoning your model through the feedback loop?',
    answer: 'We enforce an ironclad 5-stage defensive gate: (1) Multi-analyst consensus requires independent agreement from multiple security officers; (2) Statistical outlier filtering strips anomalous labels; (3) Scheduled batch retraining prevents continuous poison injection; (4) Silent shadow deployment runs the new model in parallel against an immutable Golden Test Set; if accuracy drops by >0.1%, deployment is automatically aborted; (5) Human Security Officer digital sign-off is mandatory before promotion to production.'
  },
  {
    question: 'Why does your architecture feature 3 separate specialists instead of 1 combined model?',
    answer: 'No single public dataset contains all threat types: CICIDS2017 contains volumetric floods and port scans, but zero DGA or encrypted malware. By decoupling into Specialist 1 (Flow RF on CICIDS2017), Specialist 2 (DNS RF on DGA feeds), and Specialist 3 (JA3/TLS behavioral rules), each model is an expert in its domain. Their decisions are synthesized via our Weighted Fusion Engine, completely eliminating single-point classification failure.'
  },
  {
    question: 'What is the physical security boundary for unidirectional operation?',
    answer: 'The sensor connects via a hardware optical TAP or receive-only fiber diode. Only the Rx fiber strand is physically connected to the sensor network interface card (NIC); the Tx strand is physically severed or absent. Software drivers are locked into passive promiscuous mode (IFF_PROMISC, NOARP). The system has zero physical or logical ability to emit an outbound packet into the protected network.'
  },
  {
    question: 'How did you handle the severe class imbalance in CICIDS2017?',
    answer: 'In the cleaned 1.26M dataset, Botnet accounted for only 1,948 flows (0.15%) and Infiltration/Exfiltration just 36 flows (0.003%). In our notebook training pipeline, we applied SMOTE (Synthetic Minority Over-sampling Technique) to augment Botnet and Exfiltration to 20,000 synthetic samples each during training, while keeping the 252K test set 100% authentic. This lifted Exfiltration test recall to 71% and Botnet recall to 88% with zero false alarms on benign traffic.'
  }
];

