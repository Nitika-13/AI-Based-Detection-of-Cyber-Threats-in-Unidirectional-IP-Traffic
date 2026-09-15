import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Cpu, 
  Activity, 
  Eye, 
  Layers, 
  Copy, 
  Check, 
  ArrowRight, 
  ArrowDown, 
  Zap, 
  Lock, 
  Server, 
  Radio, 
  FileCode, 
  CheckCircle2,
  BarChart3,
  Timer,
  HardDrive
} from 'lucide-react';
import { StructuredThreatAlert } from '../types';

export const ArchitectureDiagramView: React.FC = () => {
  const [copiedSchema, setCopiedSchema] = useState<boolean>(false);
  const [selectedThreatExample, setSelectedThreatExample] = useState<'dns' | 'ddos' | 'c2' | 'tor'>('dns');

  const sampleAlerts: Record<'dns' | 'ddos' | 'c2' | 'tor', StructuredThreatAlert> = {
    dns: {
      timestamp: '2026-09-16T00:50:00Z',
      flow_id: '192.168.1.50 -> 10.0.0.1 (UDP/53)',
      threat_type: 'DNS Tunnelling / DGA',
      confidence_score: 0.94,
      supporting_evidence: {
        domain_entropy: 4.12,
        subdomain_length: 68
      }
    },
    ddos: {
      timestamp: '2026-09-16T01:14:22Z',
      flow_id: '10.0.0.45 -> 192.168.1.100 (TCP/80)',
      threat_type: 'Volumetric SYN Flood / DDoS',
      confidence_score: 0.98,
      supporting_evidence: {
        syn_ratio: 0.99,
        packets_per_second: 1240.5,
        incomplete_handshake: 1
      }
    },
    c2: {
      timestamp: '2026-09-16T02:08:15Z',
      flow_id: '192.168.1.42 -> 185.220.101.5 (TCP/443)',
      threat_type: 'Botnet Command & Control Beaconing',
      confidence_score: 0.95,
      supporting_evidence: {
        iat_coefficient_of_variation: 0.084,
        beacon_duration_seconds: 25.0,
        packet_interval_uniformity: 0.96
      }
    },
    tor: {
      timestamp: '2026-09-16T02:45:30Z',
      flow_id: '192.168.1.77 -> 198.51.100.77 (TCP/443)',
      threat_type: 'Suspicious Encrypted Session (JA4/JA3 Anomaly)',
      confidence_score: 0.92,
      supporting_evidence: {
        ja3_hash: 'a0e9f5d64349fb13191bc781f81f42e1',
        ja4_fingerprint: 't13d1516h2_8daaf6152771_0271d1822839',
        tls_payload_entropy: 7.42,
        sni_hostname: 'hidden.onion'
      }
    }
  };

  const currentAlertJson = JSON.stringify(sampleAlerts[selectedThreatExample], null, 2);

  const handleCopyAlert = () => {
    navigator.clipboard.writeText(currentAlertJson);
    setCopiedSchema(true);
    setTimeout(() => setCopiedSchema(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Enterprise Overview */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600 shrink-0">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 text-[11px] font-mono font-semibold border border-emerald-200">
                  SYSTEM ARCHITECTURE SPECIFICATION
                </span>
                <span className="text-slate-300">•</span>
                <span className="text-xs font-mono text-slate-500">NTRO PS: 26145</span>
              </div>
              <h2 className="text-lg font-bold text-slate-900 mt-0.5">
                4-Tier Decoupled Architecture &amp; High-Throughput Benchmarks
              </h2>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 text-slate-700 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-indigo-600" />
              <span>Physical Diode Ingress (0 TX)</span>
            </span>
            <span className="px-3 py-1.5 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-900 font-semibold flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-indigo-600" />
              <span>25,000 flows/sec @ &lt;50ms</span>
            </span>
          </div>
        </div>
      </div>

      {/* Benchmark Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
            <span>Peak Ingestion</span>
            <Activity className="w-3.5 h-3.5 text-indigo-600" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 mt-1">25,000</div>
          <div className="text-[11px] text-slate-500 mt-0.5">flows/second tested</div>
        </div>

        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
            <span>Detection Latency</span>
            <Timer className="w-3.5 h-3.5 text-emerald-700" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-700 mt-1">&lt; 50 ms</div>
          <div className="text-[11px] text-slate-500 mt-0.5">p99: 47.8ms • p50: 18.4ms</div>
        </div>

        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
            <span>Line-Rate Ingress</span>
            <Zap className="w-3.5 h-3.5 text-amber-700" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 mt-1">10 Gbps</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Zero packet drops</div>
        </div>

        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
            <span>Return Traffic</span>
            <Lock className="w-3.5 h-3.5 text-emerald-700" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-800 mt-1">0 bps</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Tx fiber severed physically</div>
        </div>

        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
            <span>Memory Footprint</span>
            <HardDrive className="w-3.5 h-3.5 text-indigo-600" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 mt-1">&lt; 380 MB</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Optimized ring buffers</div>
        </div>

        <div className="bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div className="text-[11px] font-mono text-slate-500 uppercase flex items-center justify-between">
            <span>CPU Load</span>
            <Cpu className="w-3.5 h-3.5 text-slate-600" />
          </div>
          <div className="text-xl font-bold font-mono text-slate-900 mt-1">&lt; 32%</div>
          <div className="text-[11px] text-slate-500 mt-0.5">8-Core Xeon @ 25k/s</div>
        </div>
      </div>

      {/* Explicit 4-Layer Architecture Diagram */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-6">
        <div>
          <div className="text-xs font-mono uppercase text-indigo-600 font-bold">
            ARCHITECTURAL SEPARATION OF CONCERNS
          </div>
          <h3 className="text-base font-bold text-slate-900 mt-0.5">
            Explicit Flow Diagram: Hardware Diode → Feature Engine → AI Inference → Read-Only UI
          </h3>
          <p className="text-xs text-slate-600 mt-1 max-w-4xl">
            Each layer operates in an isolated execution sandbox. The inference engine and read-only UI possess no network interface or physical cable capable of transmitting signals back into the protected domain.
          </p>
        </div>

        {/* 4 Architectural Blocks */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 relative">
          
          {/* Layer 1: Unidirectional Ingest Pipeline */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50 flex flex-col justify-between space-y-4 hover:border-slate-300 transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-800 text-[10px] font-mono font-bold">
                  LAYER 1
                </span>
                <span className="text-[10px] font-mono text-emerald-700 font-semibold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  PHYSICAL Rx
                </span>
              </div>
              <h4 className="font-bold text-sm text-slate-900">
                Unidirectional Ingest Pipeline
              </h4>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                Single-strand optical fiber hardware data diode taps the high-security network. Laser transmit (Tx) line is physically cut.
              </p>
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-200 text-xs font-mono">
              <div className="bg-white p-2 rounded border border-slate-200 text-[11px] space-y-1">
                <div className="font-semibold text-slate-800">Hardware &amp; Kernel Sink:</div>
                <div className="text-slate-600">• Single optical photodiode (Rx)</div>
                <div className="text-slate-600">• Zero-copy eBPF ring buffer</div>
                <div className="text-slate-600">• Autonomous timeouts: 15s/30s</div>
              </div>
              <div className="text-[10px] text-emerald-800 font-bold bg-emerald-50 p-1.5 rounded border border-emerald-200 text-center">
                Strict Guarantee: 0 TX Bytes Emitted
              </div>
            </div>
          </div>

          {/* Layer 2: Feature Extraction Layer */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50 flex flex-col justify-between space-y-4 hover:border-slate-300 transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-800 text-[10px] font-mono font-bold">
                  LAYER 2
                </span>
                <span className="text-[10px] font-mono text-indigo-700 font-semibold flex items-center gap-1">
                  <Cpu className="w-3.5 h-3.5" />
                  52 FEATURES
                </span>
              </div>
              <h4 className="font-bold text-sm text-slate-900">
                Feature Extraction Layer (JA4 / Entropy)
              </h4>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                Computes directional flow vectors in real time without waiting for return TCP acknowledgments or decrypting TLS payloads.
              </p>
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-200 text-xs font-mono">
              <div className="bg-white p-2 rounded border border-slate-200 text-[11px] space-y-1">
                <div className="font-semibold text-slate-800">Key Feature Extractors:</div>
                <div className="text-slate-600">• JA3 / JA4 client fingerprints</div>
                <div className="text-slate-600">• Shannon payload / DNS entropy</div>
                <div className="text-slate-600">• IAT coefficient of variation</div>
                <div className="text-slate-600">• Incomplete handshake flags</div>
              </div>
              <div className="text-[10px] text-indigo-900 font-bold bg-indigo-50 p-1.5 rounded border border-indigo-200 text-center">
                Forward-Only Reconstructed Matrix
              </div>
            </div>
          </div>

          {/* Layer 3: Inference Engine */}
          <div className="border border-indigo-200 rounded-xl p-4 bg-indigo-50/30 flex flex-col justify-between space-y-4 hover:border-indigo-300 transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-indigo-100 text-indigo-800 text-[10px] font-mono font-bold">
                  LAYER 3
                </span>
                <span className="text-[10px] font-mono text-indigo-700 font-semibold flex items-center gap-1">
                  <Zap className="w-3.5 h-3.5" />
                  HYBRID AI
                </span>
              </div>
              <h4 className="font-bold text-sm text-slate-900">
                Multi-Specialist Inference Engine
              </h4>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                Parallel specialist models evaluate flow traits simultaneously. Fusion layer combines outputs into confidence and severity scores.
              </p>
            </div>

            <div className="space-y-2 pt-2 border-t border-indigo-100 text-xs font-mono">
              <div className="bg-white p-2 rounded border border-indigo-100 text-[11px] space-y-1">
                <div className="font-semibold text-slate-800">Specialist Ensemble:</div>
                <div className="text-slate-600">• Flow RF (1.26M trained baseline)</div>
                <div className="text-slate-600">• DNS RF (Bambenek + Tranco)</div>
                <div className="text-slate-600">• Rule Set 2 (JA3/TLS signatures)</div>
                <div className="text-slate-600">• Isolation Forest (0-day hypersphere)</div>
              </div>
              <div className="text-[10px] text-slate-900 font-bold bg-white p-1.5 rounded border border-slate-200 text-center">
                Latency: &lt; 50ms per batch
              </div>
            </div>
          </div>

          {/* Layer 4: Read-Only Dashboard */}
          <div className="border border-slate-200 rounded-xl p-4 bg-slate-50/50 flex flex-col justify-between space-y-4 hover:border-slate-300 transition-all">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded bg-slate-200 text-slate-800 text-[10px] font-mono font-bold">
                  LAYER 4
                </span>
                <span className="text-[10px] font-mono text-slate-600 font-semibold flex items-center gap-1">
                  <Eye className="w-3.5 h-3.5" />
                  READ-ONLY UI
                </span>
              </div>
              <h4 className="font-bold text-sm text-slate-900">
                Air-Gapped SOC Dashboard &amp; Export
              </h4>
              <p className="text-[11px] text-slate-600 leading-relaxed">
                Analyst console for threat triage, structured alert JSON extraction, OASIS STIX 2.1 indicator exports, and signed audit cycles.
              </p>
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-200 text-xs font-mono">
              <div className="bg-white p-2 rounded border border-slate-200 text-[11px] space-y-1">
                <div className="font-semibold text-slate-800">Outputs &amp; Formats:</div>
                <div className="text-slate-600">• Clean Structured Alert JSON</div>
                <div className="text-slate-600">• OASIS STIX 2.1 Threat Objects</div>
                <div className="text-slate-600">• Human-in-the-Loop Signoff</div>
                <div className="text-slate-600">• Golden Set Regression Gate</div>
              </div>
              <div className="text-[10px] text-slate-700 font-bold bg-slate-200 p-1.5 rounded text-center">
                Zero Feedback to Diode Ingress
              </div>
            </div>
          </div>

        </div>
      </div>

      {/* Structured Alert Schema Section */}
      <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <div className="text-xs font-mono uppercase text-indigo-600 font-bold">
              CLEAN STRUCTURED ALERT OUTPUT SCHEMA
            </div>
            <h3 className="text-base font-bold text-slate-900 mt-0.5">
              Standard JSON Threat Alert Emitter
            </h3>
            <p className="text-xs text-slate-600 mt-0.5">
              Standardized lightweight JSON output with clean flow identifier, normalized confidence score (0-1), and supporting forensic evidence.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyAlert}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-sm transition-all cursor-pointer"
            >
              {copiedSchema ? <Check className="w-3.5 h-3.5 text-white" /> : <Copy className="w-3.5 h-3.5 text-white" />}
              <span>{copiedSchema ? 'COPIED TO CLIPBOARD' : 'COPY STRUCTURED JSON'}</span>
            </button>
          </div>
        </div>

        {/* Threat Type Selector for Schema Preview */}
        <div className="flex items-center gap-2 pt-2 border-t border-slate-100 overflow-x-auto text-xs font-mono">
          <span className="text-slate-500 shrink-0">Sample Threat Payload:</span>
          {[
            { id: 'dns', label: 'DNS Tunnelling / DGA' },
            { id: 'ddos', label: 'SYN Flood / DDoS' },
            { id: 'c2', label: 'Botnet C2 Beacon' },
            { id: 'tor', label: 'JA4 Encrypted Anomaly' },
          ].map(item => (
            <button
              key={item.id}
              onClick={() => setSelectedThreatExample(item.id as any)}
              className={`px-2.5 py-1 rounded-md transition-all cursor-pointer ${
                selectedThreatExample === item.id
                  ? 'bg-slate-900 text-white font-bold'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>

        {/* JSON Code Viewer */}
        <div className="relative">
          <pre className="bg-slate-900 text-slate-100 p-4 rounded-xl font-mono text-xs overflow-x-auto border border-slate-800 leading-relaxed shadow-sm">
            {currentAlertJson}
          </pre>
          <div className="absolute top-3 right-3 text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
            application/json
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs text-slate-600">
          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
            <span className="font-bold text-slate-800 block mb-1">`flow_id` Format:</span>
            Compact, unambiguous string syntax: `[src_ip] -&gt; [dst_ip] ([PROTO]/[dst_port])` for rapid SIEM indexing.
          </div>
          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
            <span className="font-bold text-slate-800 block mb-1">`confidence_score` (0.00 - 1.00):</span>
            Statistical model certainty isolated from operational severity, preventing alert fatigue in Tier-1 SOCs.
          </div>
          <div className="p-3 bg-slate-50 rounded-lg border border-slate-200">
            <span className="font-bold text-slate-800 block mb-1">`supporting_evidence` Dict:</span>
            Top discriminating mathematical features (Shannon entropy, IAT CV, SYN ratio) explaining the classification.
          </div>
        </div>
      </div>
    </div>
  );
};
