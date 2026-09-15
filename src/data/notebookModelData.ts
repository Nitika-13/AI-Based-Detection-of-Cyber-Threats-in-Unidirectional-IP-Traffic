import { NotebookModelSpecs, AnalystReview, RetrainingAuditCycle } from '../types';

export const NOTEBOOK_MODEL_SPECS: NotebookModelSpecs = {
  dataset_name: 'CICIDS2017 (Canadian Institute for Cybersecurity) + Custom Unidirectional Feature Pipeline',
  total_flows: 1428805,
  cleaned_flows: 1261092,
  benign_count: 974669,
  ddos_count: 193745,
  portscan_count: 90694,
  botnet_count: 1948,
  exfiltration_count: 36,
  smote_augmented_botnet: 20000,
  smote_augmented_exfiltration: 20000,
  estimators: 100,
  max_depth: 15,
  training_time_sec: 408.4,
  measured_throughput_flows_sec: 95928,
  inference_duration_sec: 2.629,
  clean_accuracy: 100.0,
  clean_macro_f1: 0.91,
  clean_weighted_f1: 1.00,
  noisy_2pct_accuracy: 100.0,
  noisy_2pct_macro_f1: 0.89,
  noisy_2pct_weighted_f1: 1.00,
  noisy_5pct_accuracy: 79.0,
  noisy_5pct_macro_f1: 0.27,
  top_features: [
    { feature: 'Packet Length Std', importance: 0.073074, description: 'Measures dispersion of packet payloads; key discriminator for DoS vs human HTTP' },
    { feature: 'Bwd Packet Length Std', importance: 0.060005, description: 'Backward response packet variance; distinguishes automated servers from bots' },
    { feature: 'Bwd Packet Length Max', importance: 0.057032, description: 'Maximum backward packet size observed in flow' },
    { feature: 'Packet Length Variance', importance: 0.056992, description: 'Second-order variance of all packets in flow' },
    { feature: 'Bwd Packet Length Mean', importance: 0.051426, description: 'Average byte volume per return packet' },
    { feature: 'Average Packet Size', importance: 0.039085, description: 'Aggregate flow byte-to-packet density' },
    { feature: 'Total Length of Fwd Packets', importance: 0.036389, description: 'Total egress byte payload emitted towards destination' },
    { feature: 'Avg Bwd Segment Size', importance: 0.032789, description: 'Average TCP segment size in return direction' },
    { feature: 'Idle Max', importance: 0.026280, description: 'Maximum inactivity gap between successive packets in flow' },
    { feature: 'Packet Length Mean', importance: 0.026230, description: 'Average packet length across bidirectional session' },
    { feature: 'Destination Port', importance: 0.023934, description: 'Service identifier (53=DNS, 80=HTTP, 443=HTTPS, 22=SSH)' },
    { feature: 'Subflow Bwd Bytes', importance: 0.023133, description: 'Subflow return byte count accumulator' },
    { feature: 'Subflow Fwd Bytes', importance: 0.021505, description: 'Subflow forward byte count accumulator' },
    { feature: 'Fwd IAT Std', importance: 0.020450, description: 'Standard deviation of forward inter-arrival time' },
    { feature: 'Max Packet Length', importance: 0.020341, description: 'Peak single frame wire length' }
  ]
};

// Exact confusion matrix from user's notebook run
export const NOTEBOOK_CONFUSION_MATRIX = {
  classes: ['BENIGN', 'Botnet', 'DDoS', 'Exfiltration', 'PortScan'],
  matrix: {
    BENIGN: { BENIGN: 194595, Botnet: 130, DDoS: 15, Exfiltration: 1, PortScan: 193 },
    Botnet: { BENIGN: 46, Botnet: 344, DDoS: 0, Exfiltration: 0, PortScan: 0 },
    DDoS: { BENIGN: 139, Botnet: 0, DDoS: 38610, Exfiltration: 0, PortScan: 0 },
    Exfiltration: { BENIGN: 2, Botnet: 0, DDoS: 0, Exfiltration: 5, PortScan: 0 },
    PortScan: { BENIGN: 10, Botnet: 0, DDoS: 6, Exfiltration: 0, PortScan: 18123 }
  },
  classMetrics: [
    { label: 'BENIGN', precision: 1.00, recall: 1.00, f1: 1.00, support: 194934 },
    { label: 'Botnet', precision: 0.73, recall: 0.88, f1: 0.80, support: 390 },
    { label: 'DDoS', precision: 1.00, recall: 1.00, f1: 1.00, support: 38749 },
    { label: 'Exfiltration', precision: 0.83, recall: 0.71, f1: 0.77, support: 7 },
    { label: 'PortScan', precision: 0.99, recall: 1.00, f1: 0.99, support: 18139 },
  ]
};

// Realistic Noisy Traffic (2% noise) evaluation from user's notebook
export const NOTEBOOK_NOISY_2PCT_REPORT = [
  { label: 'BENIGN', precision: 1.00, recall: 1.00, f1: 1.00, support: 194934 },
  { label: 'Botnet', precision: 0.77, recall: 0.53, f1: 0.62, support: 390 },
  { label: 'DDoS', precision: 1.00, recall: 0.98, f1: 0.99, support: 38749 },
  { label: 'Exfiltration', precision: 1.00, recall: 0.71, f1: 0.83, support: 7 },
  { label: 'PortScan', precision: 0.99, recall: 1.00, f1: 0.99, support: 18139 },
];

// Harsh 5% Unnormalized Column Noise evaluation from user's notebook
export const NOTEBOOK_NOISY_5PCT_REPORT = [
  { label: 'BENIGN', precision: 0.79, recall: 1.00, f1: 0.88, support: 194934 },
  { label: 'Botnet', precision: 0.00, recall: 0.00, f1: 0.00, support: 390 },
  { label: 'DDoS', precision: 1.00, recall: 0.11, f1: 0.20, support: 38749 },
  { label: 'Exfiltration', precision: 1.00, recall: 0.14, f1: 0.25, support: 7 },
  { label: 'PortScan', precision: 0.00, recall: 0.00, f1: 0.00, support: 18139 },
];

// Initial mock analyst review records for Triage tab
export const INITIAL_ANALYST_REVIEWS: AnalystReview[] = [
  {
    id: 'AR-2026-0891',
    flow_id: 'FLOW-DDoS-001',
    threat_label: 'ddos',
    analyst_name: 'Lead Analyst Sharma (NTRO SOC)',
    disposition: 'CONFIRMED_THREAT',
    timestamp: '2026-09-15 10:14:22 UTC',
    notes: 'Massive SYN flood packet burst (94.2 pps) to internal gateway port 80 with incomplete handshakes. Confirmed high-volume volumetric attack.',
    consensus_score: 98.4,
    eligible_for_retraining: true
  },
  {
    id: 'AR-2026-0892',
    flow_id: 'FLOW-C2-004',
    threat_label: 'c2_beacon',
    analyst_name: 'Senior Analyst Verma',
    disposition: 'CONFIRMED_THREAT',
    timestamp: '2026-09-15 10:32:05 UTC',
    notes: 'Unnatural IAT CV of 0.098 observed across 35 beacons to external port 443. Cobalt Strike Malleable C2 heartbeat signature confirmed.',
    consensus_score: 96.0,
    eligible_for_retraining: true
  },
  {
    id: 'AR-2026-0893',
    flow_id: 'FLOW-DNS-009',
    threat_label: 'dns_anomaly',
    analyst_name: 'Analyst Patel',
    disposition: 'CONFIRMED_THREAT',
    timestamp: '2026-09-15 11:05:18 UTC',
    notes: 'Shannon entropy 3.94 bits in base64-encoded subdomains of dga-botnet-c2.net. Exfiltration tunnel confirmed.',
    consensus_score: 99.1,
    eligible_for_retraining: true
  },
  {
    id: 'AR-2026-0894',
    flow_id: 'FLOW-SCAN-012',
    threat_label: 'port_scan',
    analyst_name: 'Analyst Roy',
    disposition: 'CONFIRMED_THREAT',
    timestamp: '2026-09-15 11:22:40 UTC',
    notes: 'Horizontal port scan targeting SSH port 22 across 18 sequential IPs. Zero ACK received.',
    consensus_score: 94.5,
    eligible_for_retraining: true
  },
  {
    id: 'AR-2026-0895',
    flow_id: 'FLOW-BENIGN-044',
    threat_label: 'benign',
    analyst_name: 'Senior Analyst Verma',
    disposition: 'FALSE_POSITIVE',
    timestamp: '2026-09-15 11:39:10 UTC',
    notes: 'Large software repository sync caused transient byte spike. Re-evaluated as legitimate internal mirror sync.',
    consensus_score: 91.0,
    eligible_for_retraining: true
  }
];

// Retraining audit cycles
export const RETRAINING_AUDIT_CYCLES: RetrainingAuditCycle[] = [
  {
    cycle_id: 'CYCLE-2026-W37',
    timestamp: '2026-09-14 02:00:00 UTC',
    feedback_samples_total: 482,
    consensus_passed: 461,
    outliers_rejected: 21,
    clean_test_accuracy: 99.8,
    golden_set_accuracy: 99.6,
    golden_set_drift: 0.04,
    shadow_f1_score: 0.94,
    active_f1_score: 0.92,
    human_signoff_status: 'APPROVED' as const,
    signoff_officer: 'Col. K. R. Nair (Chief Information Security Officer)'
  },
  {
    cycle_id: 'CYCLE-2026-W36',
    timestamp: '2026-09-07 02:00:00 UTC',
    feedback_samples_total: 395,
    consensus_passed: 380,
    outliers_rejected: 15,
    clean_test_accuracy: 99.7,
    golden_set_accuracy: 99.5,
    golden_set_drift: 0.02,
    shadow_f1_score: 0.93,
    active_f1_score: 0.91,
    human_signoff_status: 'APPROVED' as const,
    signoff_officer: 'Dr. M. S. Sen (Head of Cyber Defense - NTRO)'
  }
];
