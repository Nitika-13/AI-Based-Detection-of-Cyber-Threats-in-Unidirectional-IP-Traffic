import { FlowRecord, ThreatLabel } from '../types';

export interface SimulationParams {
  scenario: ThreatLabel;
  targetIp: string;
  targetPort: number;
  sourceIp: string;
  packetCount: number;
  duration: number;
  seed: number;
}

export function generateSyntheticFlow(params: SimulationParams): FlowRecord {
  const { scenario, targetIp, targetPort, sourceIp, packetCount, duration, seed } = params;
  
  // Deterministic pseudo-random based on seed
  let s = seed || Math.floor(Math.random() * 10000);
  const random = () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };

  const start_ts = 1726135200 + random() * 120;
  const end_ts = start_ts + duration;
  const protocol = (scenario === 'dns_anomaly' || (scenario === 'benign' && targetPort === 53)) 
    ? 'udp' 
    : (scenario === 'benign' && targetPort === 0) ? 'icmp' : 'tcp';

  const flow_key = `${sourceIp}:${scenario === 'benign' && targetPort === 0 ? 0 : 40000 + Math.floor(random() * 20000)}->${targetIp}:${targetPort}/${protocol}`;
  const seq = Math.floor(random() * 9000) + 1000;
  const flow_id = `sim__${scenario}__${seq}`;

  let min_packet_size = 40;
  let max_packet_size = 1500;
  let mean_packet_size = 500;
  let std_packet_size = 120;
  let byte_count = packetCount * mean_packet_size;
  let tcp_syn_count = 1;
  let tcp_fin_count = 1;
  let tcp_rst_count = 0;
  let tcp_psh_count = Math.floor(packetCount * 0.4);
  let tcp_ack_count = Math.floor(packetCount * 0.8);
  let tcp_urg_count = 0;
  let tcp_flags = 'A,F,P,S';
  let iat_cv = 0.45;
  let dns_packet_count = 0;
  let dns_qname_len_mean = 0;
  let dns_qname_len_max = 0;
  let dns_qname_entropy_mean = 0;
  let dns_qname_entropy_max = 0;
  let dns_qtype_mode = 0;
  let tls_record_count = 0;
  let tls_version_mode = 0;
  let tls_content_type_mode = 0;
  let tls_record_len_mean = 0;
  let tls_record_len_max = 0;
  let tls_payload_entropy_mean = 0;
  let payload_bytes_total = Math.floor(byte_count * 0.7);
  let payload_ratio = 0.7;
  let payload_entropy_mean = 4.8;
  let payload_entropy_max = 5.6;

  // Custom scenario signatures
  switch (scenario) {
    case 'ddos':
      mean_packet_size = 64;
      min_packet_size = 54;
      max_packet_size = 74;
      std_packet_size = 5.2;
      byte_count = packetCount * mean_packet_size;
      tcp_syn_count = packetCount;
      tcp_fin_count = 0;
      tcp_rst_count = 0;
      tcp_psh_count = 0;
      tcp_ack_count = 0;
      tcp_flags = 'S';
      iat_cv = 0.12 + random() * 0.08;
      payload_bytes_total = 0;
      payload_ratio = 0;
      payload_entropy_mean = 0;
      payload_entropy_max = 0;
      break;

    case 'c2_beacon':
      mean_packet_size = 118;
      min_packet_size = 54;
      max_packet_size = 240;
      std_packet_size = 35;
      byte_count = packetCount * mean_packet_size;
      iat_cv = 0.04 + random() * 0.12; // Very low CV - strict clockwork
      tcp_syn_count = 1;
      tcp_fin_count = 1;
      tcp_flags = 'A,F,P,S';
      tls_record_count = Math.floor(packetCount * 0.6);
      tls_version_mode = 771; // TLS 1.2
      tls_content_type_mode = 23; // Application Data
      tls_record_len_mean = 85;
      tls_record_len_max = 140;
      tls_payload_entropy_mean = 5.8;
      payload_bytes_total = Math.floor(byte_count * 0.45);
      payload_ratio = 0.45;
      break;

    case 'dns_anomaly':
      mean_packet_size = 195;
      min_packet_size = 120;
      max_packet_size = 280;
      std_packet_size = 40;
      byte_count = packetCount * mean_packet_size;
      dns_packet_count = packetCount;
      dns_qname_len_mean = 38.5 + random() * 15;
      dns_qname_len_max = Math.floor(dns_qname_len_mean + 12);
      dns_qname_entropy_mean = 3.42 + random() * 0.45; // high Shannon entropy
      dns_qname_entropy_max = dns_qname_entropy_mean + 0.3;
      dns_qtype_mode = 16; // TXT record or query
      payload_bytes_total = Math.floor(byte_count * 0.85);
      payload_ratio = 0.85;
      payload_entropy_mean = 6.2;
      payload_entropy_max = 7.1;
      tcp_flags = '';
      tcp_syn_count = 0;
      tcp_fin_count = 0;
      tcp_ack_count = 0;
      break;

    case 'port_scan':
      min_packet_size = 44;
      max_packet_size = 44;
      mean_packet_size = 44;
      std_packet_size = 0;
      byte_count = packetCount * 44;
      tcp_syn_count = packetCount;
      tcp_fin_count = 0;
      tcp_ack_count = 0;
      tcp_flags = 'S';
      payload_bytes_total = 0;
      payload_ratio = 0;
      iat_cv = 0.25;
      break;

    case 'exfiltration':
      min_packet_size = 64;
      max_packet_size = 1460;
      mean_packet_size = 1280;
      std_packet_size = 210;
      byte_count = packetCount * mean_packet_size;
      payload_bytes_total = Math.floor(byte_count * 0.94);
      payload_ratio = 0.94;
      payload_entropy_mean = 6.8;
      payload_entropy_max = 7.6;
      tcp_flags = 'A,F,P,S';
      iat_cv = 0.32;
      break;

    case 'encrypted_anomaly':
      mean_packet_size = 920;
      min_packet_size = 64;
      max_packet_size = 1420;
      std_packet_size = 310;
      byte_count = packetCount * mean_packet_size;
      tls_record_count = Math.floor(packetCount * 0.7);
      tls_version_mode = 771;
      tls_content_type_mode = 23;
      tls_record_len_mean = 860;
      tls_record_len_max = 1380;
      tls_payload_entropy_mean = 7.45 + random() * 0.35; // high entropy
      payload_bytes_total = Math.floor(byte_count * 0.88);
      payload_ratio = 0.88;
      payload_entropy_mean = 7.3;
      payload_entropy_max = 7.9;
      iat_cv = 0.38;
      break;

    case 'benign':
    default:
      if (protocol === 'icmp') {
        min_packet_size = 28;
        max_packet_size = 28;
        mean_packet_size = 28;
        std_packet_size = 0;
        byte_count = packetCount * 28;
        tcp_flags = '';
        tcp_syn_count = 0;
        payload_bytes_total = 0;
        payload_ratio = 0;
      } else if (protocol === 'udp') {
        dns_packet_count = packetCount;
        dns_qname_len_mean = 16.5;
        dns_qname_len_max = 22;
        dns_qname_entropy_mean = 2.75;
        dns_qname_entropy_max = 3.1;
        dns_qtype_mode = 1; // A record
        payload_bytes_total = Math.floor(byte_count * 0.42);
        payload_ratio = 0.42;
      } else {
        mean_packet_size = 460;
        min_packet_size = 40;
        max_packet_size = 1024;
        std_packet_size = 340;
        byte_count = packetCount * mean_packet_size;
        payload_bytes_total = Math.floor(byte_count * 0.65);
        payload_ratio = 0.65;
      }
      iat_cv = 0.48 + random() * 0.25;
      break;
  }

  const denom = Math.max(duration, 0.001);
  const packets_per_second = packetCount / denom;
  const bytes_per_second = byte_count / denom;
  const tcp_syn_ratio = packetCount > 0 ? tcp_syn_count / packetCount : 0;
  const tcp_flag_diversity = (tcp_flags ? tcp_flags.split(',').length : 0);

  const iat_mean = duration / Math.max(1, packetCount - 1);
  const iat_std = iat_mean * iat_cv;
  const iat_min = Math.max(0.001, iat_mean * (1 - iat_cv * 0.8));
  const iat_max = iat_mean * (1 + iat_cv * 1.5);

  return {
    flow_id,
    run_id: 'sim_run',
    scenario,
    flow_key,
    src_ip: sourceIp,
    src_port: scenario === 'benign' && targetPort === 0 ? 0 : 45120,
    dst_ip: targetIp,
    dst_port: targetPort,
    protocol,
    start_ts,
    end_ts,
    duration,
    packet_count: packetCount,
    byte_count,
    packets_per_second,
    bytes_per_second,
    min_packet_size,
    max_packet_size,
    mean_packet_size,
    std_packet_size,
    iat_mean,
    iat_std,
    iat_min,
    iat_max,
    iat_count: Math.max(0, packetCount - 1),
    tcp_flags,
    tcp_syn_count,
    tcp_fin_count,
    tcp_rst_count,
    tcp_psh_count,
    tcp_ack_count,
    tcp_urg_count,
    dns_packet_count,
    dns_qname_len_mean,
    dns_qname_len_max,
    dns_qname_entropy_mean,
    dns_qname_entropy_max,
    dns_qtype_mode,
    tls_record_count,
    tls_version_mode,
    tls_content_type_mode,
    tls_record_len_mean,
    tls_record_len_max,
    tls_payload_entropy_mean,
    iat_cv,
    tcp_syn_ratio,
    tcp_flag_diversity,
    payload_bytes_total,
    payload_ratio,
    payload_entropy_mean,
    payload_entropy_max,
    direction: 'outbound',
    label: scenario
  };
}
