import { ScenarioDefinition, ThreatLabel } from '../types';

export const SCENARIOS: Record<ThreatLabel, ScenarioDefinition> = {
  benign: {
    id: 'benign',
    name: 'Benign Network Baseline',
    category: 'Normal Traffic',
    threatSeverity: 'NORMAL',
    description: 'Legitimate everyday enterprise traffic comprising web browsing (HTTP/HTTPS), standard DNS lookups, and ICMP diagnostic pings with standard statistical variance.',
    attackVector: 'N/A (Legitimate traffic)',
    primaryFeatures: ['mean_packet_size', 'iat_mean', 'payload_ratio'],
    detectionThresholds: 'iat_cv > 0.35, normal DNS entropy (<3.0), balanced TCP flag distribution, payload ratio commensurate with web transactions.',
    defenseMitigation: 'Permitted traffic profile. Continuous passive baseline profiling to detect subtle drift.'
  },
  ddos: {
    id: 'ddos',
    name: 'Distributed Denial of Service (DDoS)',
    category: 'Volumetric / Flood',
    threatSeverity: 'CRITICAL',
    description: 'High-rate SYN flooding and high-volume UDP amplification targeted at a designated monitored victim to exhaust connection state tables and bandwidth.',
    attackVector: 'TCP SYN flood / UDP flood targeting internal servers',
    primaryFeatures: ['packets_per_second', 'tcp_syn_ratio', 'bytes_per_second', 'packet_count'],
    detectionThresholds: 'Extreme packet arrival rate (pps > 100), tcp_syn_ratio approaching 1.0 without subsequent data or FIN/ACK completion, abnormal packet rate bursts.',
    defenseMitigation: 'Rate limiting on ingress router, syncookie activation, upstream BGP blackholing, victim server isolation.'
  },
  c2_beacon: {
    id: 'c2_beacon',
    name: 'Command & Control (C2) Beacon',
    category: 'Persistence / Evasion',
    threatSeverity: 'HIGH',
    description: 'Periodic, automated low-rate heartbeat signals over TCP/443 outbound to external C2 infrastructure, characterized by unnaturally rigid inter-arrival timing.',
    attackVector: 'Compromised internal host communicating with external listener',
    primaryFeatures: ['iat_cv', 'duration', 'mean_packet_size', 'dst_port'],
    detectionThresholds: 'Very low inter-arrival time coefficient of variation (iat_cv < 0.20) indicating automated machine timer rather than human browsing jitter, consistent small packet sizes.',
    defenseMitigation: 'Host containment, threat intelligence IP blocking, credential revocation, behavioral sandbox analysis.'
  },
  dns_anomaly: {
    id: 'dns_anomaly',
    name: 'DNS Tunneling & Data Exfiltration',
    category: 'Covert Channel',
    threatSeverity: 'HIGH',
    description: 'Covert data encapsulation inside DNS query packets (port 53), exhibiting unusually long query names (QNAMEs) with elevated Shannon entropy indicating encoded ciphertext/base64.',
    attackVector: 'Data exfiltration / command channel over port 53 UDP bypassing standard proxy inspect',
    primaryFeatures: ['dns_qname_entropy_mean', 'dns_qname_len_mean', 'dns_packet_count', 'payload_entropy_max'],
    detectionThresholds: 'dns_qname_entropy_mean > 3.0 bits, dns_qname_len_mean > 20 bytes, high query packet count per destination server.',
    defenseMitigation: 'DNS sinkholing, response policy zones (RPZ), enforcement of strict DNS length and entropy thresholds at recursive resolvers.'
  },
  port_scan: {
    id: 'port_scan',
    name: 'Reconnaissance / Port Scan',
    category: 'Reconnaissance',
    threatSeverity: 'MEDIUM',
    description: 'Rapid sequential or randomized TCP SYN probing across diverse destination ports to identify accessible services on victim endpoints, yielding unestablished flows.',
    attackVector: 'Attacker probing network surface for open listening ports',
    primaryFeatures: ['unique_peer_port_count', 'peer_port_entropy', 'tcp_syn_count', 'mean_packets_per_flow'],
    detectionThresholds: 'Host window exhibiting high unique peer ports (>10), high peer_port_entropy, low packet count per flow (1-2 pkts), syn_flow_ratio > 0.8.',
    defenseMitigation: 'Dynamic firewall port-knocking or blacklisting of scanner source IP, network segmentation, honeypot diversion.'
  },
  exfiltration: {
    id: 'exfiltration',
    name: 'Bulk Data Exfiltration',
    category: 'Data Theft',
    threatSeverity: 'CRITICAL',
    description: 'Large sustained outbound data transfers over standard ports, characterized by massive payload volumes, high payload-to-header ratios, and persistent flow durations.',
    attackVector: 'Unauthorized data upload to external cloud storage or remote repository',
    primaryFeatures: ['byte_count', 'bytes_per_second', 'payload_bytes_total', 'payload_ratio'],
    detectionThresholds: 'payload_ratio > 0.85, byte_count > 10,000 bytes per flow, sustained high bytes_per_second to external IP prefixes.',
    defenseMitigation: 'Data Loss Prevention (DLP) enforcement, immediate session termination, bandwidth throttling on outbound external routes.'
  },
  encrypted_anomaly: {
    id: 'encrypted_anomaly',
    name: 'Suspicious Encrypted Channel Anomaly',
    category: 'Anomalous Encrypted',
    threatSeverity: 'HIGH',
    description: 'Encrypted flows over TLS/443 exhibiting structural anomalies in record framing and entropy patterns without performing TLS payload decryption.',
    attackVector: 'Malware using custom TLS wrapper or non-standard TLS record lengths',
    primaryFeatures: ['tls_payload_entropy_mean', 'tls_record_len_mean', 'tls_record_count', 'tls_version_mode'],
    detectionThresholds: 'tls_payload_entropy_mean > 7.2 with atypical record length variance or non-standard TLS record structures under passive inspection.',
    defenseMitigation: 'TLS fingerprinting (JA4), certificate validation enforcement, destination reputation analysis.'
  }
};
