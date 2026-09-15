import React, { useState } from 'react';
import { X, ShieldAlert, ShieldCheck, Activity, Database, AlertCircle, Hash, ExternalLink, Copy, Check, FileText, Sparkles } from 'lucide-react';
import { FlowRecord } from '../types';
import { classifyFlow, generateSTIXAlert } from '../lib/detector';

interface FlowDetailModalProps {
  flow: FlowRecord | null;
  onClose: () => void;
}

export const FlowDetailModal: React.FC<FlowDetailModalProps> = ({ flow, onClose }) => {
  const [copiedStix, setCopiedStix] = useState(false);
  if (!flow) return null;

  const detection = classifyFlow(flow);
  const stixAlert = generateSTIXAlert(flow, detection);

  const copyStix = () => {
    navigator.clipboard.writeText(JSON.stringify(stixAlert, null, 2));
    setCopiedStix(true);
    setTimeout(() => setCopiedStix(false), 2000);
  };

  const getSeverityBadge = () => {
    switch (detection.severity) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-400 border border-rose-800 text-xs font-mono font-bold">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 rounded bg-amber-950 text-amber-400 border border-amber-800 text-xs font-mono font-bold">HIGH RISK</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 rounded bg-yellow-950 text-yellow-400 border border-yellow-800 text-xs font-mono font-bold">MEDIUM RISK</span>;
      default:
        return <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs font-mono font-bold">BENIGN / SAFE</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-950/70 flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
                {flow.flow_id}
              </span>
              <span className="text-xs text-slate-400 font-mono">Run: {flow.run_id}</span>
              {getSeverityBadge()}
            </div>
            <h3 className="text-base sm:text-lg font-mono font-bold text-white tracking-wide break-all">
              {flow.flow_key}
            </h3>
            <p className="text-xs text-slate-400">
              Extracted via Block 2 Passive Flow Reconstructor • 52 Feature Vector Inspection
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
          {/* AI Threat Classification Banner */}
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-sky-400" />
                <span className="text-sm font-bold text-white">AI Classification & Decision Rationale</span>
              </div>
              <div className="flex items-center space-x-3 font-mono">
                <span className="text-slate-400">Predicted: <strong className="text-white uppercase">{detection.predictedLabel}</strong></span>
                <span className="text-slate-400">Confidence: <strong className="text-sky-400">{detection.confidence}%</strong></span>
                <span className="text-slate-400">Anomaly Index: <strong className="text-rose-400">{detection.anomalyScore}/100</strong></span>
              </div>
            </div>

            {/* Anomaly score bar */}
            <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
              <div
                className={`h-full transition-all ${
                  detection.anomalyScore > 70
                    ? 'bg-rose-500'
                    : detection.anomalyScore > 40
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
                }`}
                style={{ width: `${detection.anomalyScore}%` }}
              />
            </div>

            {/* Triggered rules list */}
            <div className="space-y-1">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Triggered Heuristics:</span>
              <div className="flex flex-wrap gap-1.5">
                {detection.triggeredRules.map((rule, idx) => (
                  <span key={idx} className="px-2.5 py-1 rounded bg-slate-800 text-sky-300 border border-slate-700 font-mono text-[11px]">
                    {rule}
                  </span>
                ))}
              </div>
            </div>

            {/* STIX 2.1 Standardized Alert Export Action */}
            <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-800 font-mono text-[10px] font-bold">
                  STIX 2.1
                </span>
                <span className="text-slate-400 text-[11px]">
                  Specialist Origin: <strong className="text-white">{detection.specialist_detector}</strong>
                </span>
                {detection.ja3_fingerprint && (
                  <span className="text-slate-400 text-[11px] font-mono">
                    JA3: <span className="text-amber-300">{detection.ja3_fingerprint.slice(0, 8)}...</span>
                  </span>
                )}
              </div>

              <button
                onClick={copyStix}
                className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-semibold rounded flex items-center gap-1.5 transition-all cursor-pointer"
              >
                {copiedStix ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedStix ? 'STIX 2.1 Copied' : 'Copy STIX 2.1 JSON'}</span>
              </button>
            </div>

            {/* Key Explainability Factors */}
            <div className="pt-2 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 gap-2">
              {detection.keyFactors.map((factor, idx) => (
                <div key={idx} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px]">
                  <div className="flex justify-between font-mono text-slate-300">
                    <span className="text-sky-400 font-semibold">{factor.feature}</span>
                    <span>Observed: <strong className="text-white">{factor.value}</strong></span>
                  </div>
                  <div className="text-[10px] text-slate-500 font-mono">Baseline benchmark: {factor.benchmark}</div>
                  <div className="text-slate-400 text-[10px] mt-0.5">{factor.description}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Custom Notebook Engineered Features Section */}
          <div className="bg-slate-950/80 p-4 rounded-xl border border-indigo-900/50 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                <span>Notebook Engineered Unidirectional Features</span>
              </span>
              <span className="text-[10px] font-mono text-slate-400">Scikit-Learn ML Ingest</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs pt-1">
              <div className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">Out_In_Byte_Ratio</div>
                <div className="text-sm font-bold text-white mt-0.5">
                  {(flow.byte_count / Math.max(1, flow.packet_count)).toFixed(1)}
                </div>
                <div className="text-[10px] text-slate-500">Exfiltration density</div>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">SYN_Ratio</div>
                <div className="text-sm font-bold text-white mt-0.5">
                  {((flow.tcp_syn_count / Math.max(1, flow.packet_count)) * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-500">SYN / Total Packets</div>
              </div>
              <div className="p-2 bg-slate-900 rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">Incomplete_Handshake</div>
                <div className="text-sm font-bold text-white mt-0.5">
                  {(flow.tcp_syn_count > 0 && flow.tcp_ack_count === 0) ? '1 (TRUE)' : '0 (FALSE)'}
                </div>
                <div className="text-[10px] text-slate-500">SYN=1, ACK=0 Probe</div>
              </div>
            </div>
          </div>

          {/* Canonical 52-Feature Schema Categorized Breakdown */}
          <div className="space-y-4">
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-sky-400" />
              <span>Full Canonical Feature Vector (52 Dimensions)</span>
            </h4>

            {/* Section 1: Flow Identity & Metadata */}
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <div className="text-[11px] font-bold text-sky-400 uppercase tracking-wider mb-2">
                1. Flow Identity & Metadata (12 Features)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">src_ip:</span> <span className="text-slate-200">{flow.src_ip}</span></div>
                <div><span className="text-slate-500">src_port:</span> <span className="text-slate-200">{flow.src_port}</span></div>
                <div><span className="text-slate-500">dst_ip:</span> <span className="text-slate-200">{flow.dst_ip}</span></div>
                <div><span className="text-slate-500">dst_port:</span> <span className="text-slate-200">{flow.dst_port}</span></div>
                <div><span className="text-slate-500">protocol:</span> <span className="text-slate-200 uppercase">{flow.protocol}</span></div>
                <div><span className="text-slate-500">direction:</span> <span className="text-slate-200">{flow.direction}</span></div>
                <div><span className="text-slate-500">start_ts:</span> <span className="text-slate-200">{flow.start_ts?.toFixed(3)}</span></div>
                <div><span className="text-slate-500">end_ts:</span> <span className="text-slate-200">{flow.end_ts?.toFixed(3)}</span></div>
                <div><span className="text-slate-500">duration:</span> <span className="text-slate-200">{flow.duration?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">scenario:</span> <span className="text-slate-200">{flow.scenario}</span></div>
                <div><span className="text-slate-500">ground_truth:</span> <span className="text-emerald-400 font-bold">{flow.label}</span></div>
                <div><span className="text-slate-500">run_id:</span> <span className="text-slate-200">{flow.run_id}</span></div>
              </div>
            </div>

            {/* Section 2: Volume & Statistical Rates */}
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <div className="text-[11px] font-bold text-sky-400 uppercase tracking-wider mb-2">
                2. Volume & Statistical Packet Metrics
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">packet_count:</span> <span className="text-slate-200 font-bold">{flow.packet_count}</span></div>
                <div><span className="text-slate-500">byte_count:</span> <span className="text-slate-200 font-bold">{flow.byte_count} B</span></div>
                <div><span className="text-slate-500">packets_per_sec:</span> <span className="text-sky-300 font-bold">{flow.packets_per_second?.toFixed(2)}</span></div>
                <div><span className="text-slate-500">bytes_per_sec:</span> <span className="text-sky-300 font-bold">{flow.bytes_per_second?.toFixed(1)}</span></div>
                <div><span className="text-slate-500">min_packet_size:</span> <span className="text-slate-200">{flow.min_packet_size} B</span></div>
                <div><span className="text-slate-500">max_packet_size:</span> <span className="text-slate-200">{flow.max_packet_size} B</span></div>
                <div><span className="text-slate-500">mean_packet_size:</span> <span className="text-slate-200">{flow.mean_packet_size?.toFixed(1)} B</span></div>
                <div><span className="text-slate-500">std_packet_size:</span> <span className="text-slate-200">{flow.std_packet_size?.toFixed(2)}</span></div>
              </div>
            </div>

            {/* Section 3: Inter-Arrival Time (IAT) Dynamics */}
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <div className="text-[11px] font-bold text-sky-400 uppercase tracking-wider mb-2">
                3. Inter-Arrival Time (IAT) Dynamics (Crucial for C2 Beacon Detection)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div>
                  <span className="text-slate-500">iat_cv:</span>{' '}
                  <span className={`font-bold ${flow.iat_cv < 0.20 && flow.duration > 2 ? 'text-rose-400' : 'text-slate-200'}`}>
                    {flow.iat_cv?.toFixed(4)}
                  </span>
                </div>
                <div><span className="text-slate-500">iat_mean:</span> <span className="text-slate-200">{flow.iat_mean?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">iat_std:</span> <span className="text-slate-200">{flow.iat_std?.toFixed(4)}</span></div>
                <div><span className="text-slate-500">iat_min:</span> <span className="text-slate-200">{flow.iat_min?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">iat_max:</span> <span className="text-slate-200">{flow.iat_max?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">iat_count:</span> <span className="text-slate-200">{flow.iat_count}</span></div>
              </div>
            </div>

            {/* Section 4: TCP Flags & State Counts */}
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <div className="text-[11px] font-bold text-sky-400 uppercase tracking-wider mb-2">
                4. TCP Flags & Control Signatures
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">tcp_flags:</span> <span className="text-slate-200 font-bold">{flow.tcp_flags || 'NONE'}</span></div>
                <div><span className="text-slate-500">tcp_syn_count:</span> <span className="text-slate-200">{flow.tcp_syn_count}</span></div>
                <div><span className="text-slate-500">tcp_syn_ratio:</span> <span className="text-slate-200">{(flow.tcp_syn_ratio * 100).toFixed(1)}%</span></div>
                <div><span className="text-slate-500">tcp_fin_count:</span> <span className="text-slate-200">{flow.tcp_fin_count}</span></div>
                <div><span className="text-slate-500">tcp_rst_count:</span> <span className="text-slate-200">{flow.tcp_rst_count}</span></div>
                <div><span className="text-slate-500">tcp_psh_count:</span> <span className="text-slate-200">{flow.tcp_psh_count}</span></div>
                <div><span className="text-slate-500">tcp_ack_count:</span> <span className="text-slate-200">{flow.tcp_ack_count}</span></div>
                <div><span className="text-slate-500">flag_diversity:</span> <span className="text-slate-200">{flow.tcp_flag_diversity}</span></div>
              </div>
            </div>

            {/* Section 5: DNS & TLS Metadata (PCAP Deep Extraction) */}
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <div className="text-[11px] font-bold text-sky-400 uppercase tracking-wider mb-2">
                5. Passive Protocol Metrology (DNS / TLS 12 Dimensions)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">dns_packet_count:</span> <span className="text-slate-200">{flow.dns_packet_count}</span></div>
                <div>
                  <span className="text-slate-500">dns_qname_entropy:</span>{' '}
                  <span className={`font-bold ${flow.dns_qname_entropy_mean > 3.0 ? 'text-purple-400' : 'text-slate-200'}`}>
                    {flow.dns_qname_entropy_mean?.toFixed(3)}
                  </span>
                </div>
                <div><span className="text-slate-500">dns_qname_len_mean:</span> <span className="text-slate-200">{flow.dns_qname_len_mean?.toFixed(1)}</span></div>
                <div><span className="text-slate-500">dns_qtype_mode:</span> <span className="text-slate-200">{flow.dns_qtype_mode}</span></div>
                <div><span className="text-slate-500">tls_record_count:</span> <span className="text-slate-200">{flow.tls_record_count}</span></div>
                <div><span className="text-slate-500">tls_version_mode:</span> <span className="text-slate-200">{flow.tls_version_mode ? `0x${flow.tls_version_mode.toString(16)}` : '0'}</span></div>
                <div><span className="text-slate-500">tls_record_len_mean:</span> <span className="text-slate-200">{flow.tls_record_len_mean?.toFixed(1)}</span></div>
                <div><span className="text-slate-500">tls_entropy_mean:</span> <span className="text-slate-200">{flow.tls_payload_entropy_mean?.toFixed(3)}</span></div>
              </div>
            </div>

            {/* Section 6: Payload Attributes */}
            <div className="bg-slate-950/60 p-3 rounded-xl border border-slate-800">
              <div className="text-[11px] font-bold text-sky-400 uppercase tracking-wider mb-2">
                6. Payload Entropy & Ratio (Exfiltration & Covert Channel Detection)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">payload_bytes_total:</span> <span className="text-slate-200 font-bold">{flow.payload_bytes_total?.toLocaleString()} B</span></div>
                <div><span className="text-slate-500">payload_ratio:</span> <span className="text-slate-200">{(flow.payload_ratio * 100).toFixed(1)}%</span></div>
                <div><span className="text-slate-500">payload_entropy_mean:</span> <span className="text-slate-200">{flow.payload_entropy_mean?.toFixed(3)}</span></div>
                <div><span className="text-slate-500">payload_entropy_max:</span> <span className="text-slate-200">{flow.payload_entropy_max?.toFixed(3)}</span></div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex items-center justify-between">
          <div className="text-xs text-slate-500 font-mono">
            Unidirectional Flow Invariant: Guaranteed Inter-packet Gap ≤ 5s
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-medium text-xs transition-colors cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
