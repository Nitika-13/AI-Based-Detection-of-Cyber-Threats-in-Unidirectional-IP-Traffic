export type ThreatLabel = 
  | 'benign' 
  | 'ddos' 
  | 'c2_beacon' 
  | 'dns_anomaly' 
  | 'port_scan' 
  | 'exfiltration' 
  | 'encrypted_anomaly';

export type Protocol = 'tcp' | 'udp' | 'icmp';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NORMAL';

export interface FlowRecord {
  flow_id: string;
  run_id: string;
  scenario: string;
  flow_key: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  start_ts: number;
  end_ts: number;
  duration: number;
  packet_count: number;
  byte_count: number;
  packets_per_second: number;
  bytes_per_second: number;
  min_packet_size: number;
  max_packet_size: number;
  mean_packet_size: number;
  std_packet_size: number;
  iat_mean: number;
  iat_std: number;
  iat_min: number;
  iat_max: number;
  iat_count: number;
  tcp_flags: string;
  tcp_syn_count: number;
  tcp_fin_count: number;
  tcp_rst_count: number;
  tcp_psh_count: number;
  tcp_ack_count: number;
  tcp_urg_count: number;
  dns_packet_count: number;
  dns_qname_len_mean: number;
  dns_qname_len_max: number;
  dns_qname_entropy_mean: number;
  dns_qname_entropy_max: number;
  dns_qtype_mode: number;
  tls_record_count: number;
  tls_version_mode: number;
  tls_content_type_mode: number;
  tls_record_len_mean: number;
  tls_record_len_max: number;
  tls_payload_entropy_mean: number;
  iat_cv: number;
  tcp_syn_ratio: number;
  tcp_flag_diversity: number;
  payload_bytes_total: number;
  payload_ratio: number;
  payload_entropy_mean: number;
  payload_entropy_max: number;
  direction: string;
  label: ThreatLabel | string;
  // Notebook engineered features
  out_in_byte_ratio?: number;
  incomplete_handshake?: number;
  ja3_hash?: string;
  ja4_hash?: string;
  sni_hostname?: string;
  specialist_detector?: 'Model 1 (Flow RF)' | 'Model 2 (DNS RF)' | 'Rule Set 2 (JA3/TLS)' | 'Fusion Engine';
  correlated_incident_id?: string;
}

export interface STIXAlert {
  type: 'indicator';
  spec_version: '2.1';
  id: string;
  created: string;
  modified: string;
  name: string;
  description: string;
  pattern_type: 'stix';
  pattern: string;
  confidence: number;
  severity: SeverityLevel;
  threat_label: ThreatLabel;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  evidence: {
    matched_rules: string[];
    top_gini_features: { feature: string; value: string | number; importance: number }[];
    anomaly_score: number;
    specialist_origin: string;
    correlated_incident?: string;
  };
}

export type AnalystDisposition = 'PENDING' | 'CONFIRMED_THREAT' | 'FALSE_POSITIVE' | 'ESCALATED_INCIDENT';

export interface AnalystReviewItem {
  id: string;
  flow_id: string;
  threat_label: ThreatLabel;
  analyst_name: string;
  disposition: AnalystDisposition;
  timestamp: string;
  notes: string;
  consensus_score: number;
  eligible_for_retraining: boolean;
}

export type AnalystReview = AnalystReviewItem;

export interface RetrainingAuditCycle {
  cycle_id: string;
  timestamp: string;
  feedback_samples_total: number;
  consensus_passed: number;
  outliers_rejected: number;
  clean_test_accuracy: number;
  golden_set_accuracy: number;
  golden_set_drift: number;
  shadow_f1_score: number;
  active_f1_score: number;
  human_signoff_status: 'PENDING' | 'APPROVED' | 'REJECTED';
  signoff_officer?: string;
}

export interface NotebookModelSpecs {
  dataset_name: string;
  total_flows: number;
  cleaned_flows: number;
  benign_count: number;
  ddos_count: number;
  portscan_count: number;
  botnet_count: number;
  exfiltration_count: number;
  smote_augmented_botnet: number;
  smote_augmented_exfiltration: number;
  estimators: number;
  max_depth: number;
  training_time_sec: number;
  measured_throughput_flows_sec: number;
  inference_duration_sec: number;
  clean_accuracy: number;
  clean_macro_f1: number;
  clean_weighted_f1: number;
  noisy_2pct_accuracy: number;
  noisy_2pct_macro_f1: number;
  noisy_2pct_weighted_f1: number;
  noisy_5pct_accuracy: number;
  noisy_5pct_macro_f1: number;
  top_features: { feature: string; importance: number; description: string }[];
}

export interface HostWindowRecord {
  run_id: string;
  scenario: string;
  window_index: number;
  window_start_ts: number;
  window_end_ts: number;
  ip: string;
  role: string;
  flow_count: number;
  packet_count: number;
  byte_count: number;
  unique_peer_ip_count: number;
  unique_peer_port_count: number;
  peer_ip_entropy: number;
  peer_port_entropy: number;
  syn_flow_count: number;
  syn_flow_ratio: number;
  mean_flow_duration: number;
  mean_packets_per_flow: number;
  packet_rate_pps: number;
  byte_rate_bps: number;
}

export interface DetectionResult {
  predictedLabel: ThreatLabel;
  confidence: number;
  anomalyScore: number;
  severity: SeverityLevel;
  triggeredRules: string[];
  keyFactors: {
    feature: string;
    value: number | string;
    benchmark: string;
    description: string;
  }[];
}

export interface ScenarioDefinition {
  id: ThreatLabel;
  name: string;
  category: string;
  description: string;
  attackVector: string;
  primaryFeatures: string[];
  threatSeverity: SeverityLevel;
  detectionThresholds: string;
  defenseMitigation: string;
}
