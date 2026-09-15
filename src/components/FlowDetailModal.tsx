import React, { useState } from 'react';
import { X, ShieldAlert, ShieldCheck, Activity, Database, AlertCircle, Hash, ExternalLink, Copy, Check, FileText, Code } from 'lucide-react';
import { FlowRecord, StructuredThreatAlert } from '../types';
import { classifyFlow, generateSTIXAlert, generateStructuredAlert } from '../lib/detector';

interface FlowDetailModalProps {
  flow: FlowRecord | null;
  onClose: () => void;
}

export const FlowDetailModal: React.FC<FlowDetailModalProps> = ({ flow, onClose }) => {
  const [copiedStix, setCopiedStix] = useState(false);
  const [copiedCleanJson, setCopiedCleanJson] = useState(false);
  const [activeJsonTab, setActiveJsonTab] = useState<'structured' | 'stix'>('structured');

  if (!flow) return null;

  const detection = classifyFlow(flow);
  const stixAlert = generateSTIXAlert(flow, detection);
  const structuredAlert: StructuredThreatAlert = generateStructuredAlert(flow, detection);

  const copyStix = () => {
    navigator.clipboard.writeText(JSON.stringify(stixAlert, null, 2));
    setCopiedStix(true);
    setTimeout(() => setCopiedStix(false), 2000);
  };

  const copyCleanJson = () => {
    navigator.clipboard.writeText(JSON.stringify(structuredAlert, null, 2));
    setCopiedCleanJson(true);
    setTimeout(() => setCopiedCleanJson(false), 2000);
  };

  const getSeverityBadge = () => {
    switch (detection.severity) {
      case 'CRITICAL':
        return <span className="px-2.5 py-1 rounded bg-rose-50 text-rose-800 border border-rose-200 text-xs font-mono font-bold">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="px-2.5 py-1 rounded bg-amber-50 text-amber-800 border border-amber-200 text-xs font-mono font-bold">HIGH RISK</span>;
      case 'MEDIUM':
        return <span className="px-2.5 py-1 rounded bg-amber-50 text-amber-700 border border-amber-200 text-xs font-mono font-bold">MEDIUM RISK</span>;
      default:
        return <span className="px-2.5 py-1 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 text-xs font-mono font-bold">BENIGN / NORMAL</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
      <div className="bg-white border border-slate-200 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-200 bg-slate-50/70 flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
                {flow.flow_id}
              </span>
              <span className="text-xs text-slate-500 font-mono">Run: {flow.run_id}</span>
              {getSeverityBadge()}
            </div>
            <h3 className="text-base sm:text-lg font-mono font-bold text-slate-900 tracking-wide break-all">
              {flow.flow_key}
            </h3>
            <p className="text-xs text-slate-500">
              Extracted via Block 2 Passive Flow Reconstructor • 52 Feature Vector Inspection
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-500 hover:text-slate-800 transition-colors cursor-pointer border border-slate-200"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-6 text-xs text-slate-700">
          {/* AI Threat Classification Banner */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center space-x-2">
                <ShieldAlert className="w-5 h-5 text-indigo-600" />
                <span className="text-sm font-bold text-slate-900">AI Classification &amp; Decision Rationale</span>
              </div>
              <div className="flex items-center space-x-3 font-mono">
                <span className="text-slate-600">Predicted: <strong className="text-slate-900 uppercase font-bold">{detection.predictedLabel}</strong></span>
                <span className="text-slate-600">Confidence: <strong className="text-indigo-700 font-bold">{detection.confidence}%</strong></span>
                <span className="text-slate-600">Anomaly Index: <strong className="text-rose-700 font-bold">{detection.anomalyScore}/100</strong></span>
              </div>
            </div>

            {/* Anomaly score bar */}
            <div className="w-full bg-slate-200 rounded-full h-2 overflow-hidden">
              <div
                className={`h-full transition-all ${
                  detection.anomalyScore > 70
                    ? 'bg-rose-600'
                    : detection.anomalyScore > 40
                    ? 'bg-amber-500'
                    : 'bg-emerald-600'
                }`}
                style={{ width: `${detection.anomalyScore}%` }}
              />
            </div>

            {/* Triggered rules list */}
            <div className="space-y-1">
              <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">Triggered Heuristics:</span>
              <div className="flex flex-wrap gap-1.5">
                {detection.triggeredRules.map((rule, idx) => (
                  <span key={idx} className="px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-700 font-mono text-[11px]">
                    {rule}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Clean Structured JSON Alert & STIX Export Preview */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3 shadow-xs">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center space-x-2">
                <div className="flex rounded-lg border border-slate-200 p-0.5 bg-slate-100 text-xs font-mono">
                  <button
                    onClick={() => setActiveJsonTab('structured')}
                    className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                      activeJsonTab === 'structured'
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-500 hover:text-slate-900'
                    }`}
                  >
                    Clean Structured Alert JSON
                  </button>
                  <button
                    onClick={() => setActiveJsonTab('stix')}
                    className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                      activeJsonTab === 'stix'
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-500 hover:text-slate-900'
                    }`}
                  >
                    OASIS STIX 2.1
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                {activeJsonTab === 'structured' ? (
                  <button
                    onClick={copyCleanJson}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-mono text-xs font-semibold cursor-pointer shadow-xs"
                  >
                    {copiedCleanJson ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedCleanJson ? 'COPIED ALERT JSON' : 'COPY CLEAN ALERT JSON'}</span>
                  </button>
                ) : (
                  <button
                    onClick={copyStix}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-mono text-xs font-semibold cursor-pointer shadow-xs"
                  >
                    {copiedStix ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedStix ? 'COPIED STIX' : 'COPY STIX 2.1'}</span>
                  </button>
                )}
              </div>
            </div>

            <div className="relative">
              <pre className="bg-slate-900 text-slate-100 p-3.5 rounded-lg font-mono text-[11px] overflow-x-auto max-h-48 border border-slate-800 leading-relaxed">
                {JSON.stringify(activeJsonTab === 'structured' ? structuredAlert : stixAlert, null, 2)}
              </pre>
            </div>
          </div>

          {/* 52 Forensic Feature Matrix */}
          <div className="space-y-4">
            <h4 className="font-bold text-sm text-slate-900 uppercase tracking-wider font-mono">
              Canonical 52-Feature Schema Extraction
            </h4>

            {/* Section 1: Identification & Timing */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <div className="text-[11px] font-bold text-indigo-700 uppercase tracking-wider mb-2">
                1. Network Invariants &amp; 5-Tuple
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">src_ip:</span> <span className="text-slate-900 font-semibold">{flow.src_ip}</span></div>
                <div><span className="text-slate-500">dst_ip:</span> <span className="text-slate-900 font-semibold">{flow.dst_ip}</span></div>
                <div><span className="text-slate-500">src_port:</span> <span className="text-slate-900">{flow.src_port}</span></div>
                <div><span className="text-slate-500">dst_port:</span> <span className="text-slate-900 font-semibold">{flow.dst_port}</span></div>
                <div><span className="text-slate-500">protocol:</span> <span className="text-slate-900 uppercase">{flow.protocol}</span></div>
                <div><span className="text-slate-500">duration:</span> <span className="text-slate-900">{flow.duration.toFixed(3)}s</span></div>
                <div><span className="text-slate-500">direction:</span> <span className="text-emerald-700 font-bold">{flow.direction}</span></div>
                <div><span className="text-slate-500">run_id:</span> <span className="text-slate-900">{flow.run_id}</span></div>
              </div>
            </div>

            {/* Section 2: Volumetric Rates */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <div className="text-[11px] font-bold text-indigo-700 uppercase tracking-wider mb-2">
                2. Volumetric Rates &amp; Size Distribution
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">packet_count:</span> <span className="text-slate-900 font-bold">{flow.packet_count}</span></div>
                <div><span className="text-slate-500">byte_count:</span> <span className="text-slate-900 font-bold">{flow.byte_count} B</span></div>
                <div><span className="text-slate-500">pps:</span> <span className="text-slate-900 font-semibold">{flow.packets_per_second?.toFixed(1)}</span></div>
                <div><span className="text-slate-500">bps:</span> <span className="text-slate-900">{flow.bytes_per_second?.toFixed(0)}</span></div>
                <div><span className="text-slate-500">pkt_len_mean:</span> <span className="text-slate-900">{flow.mean_packet_size?.toFixed(1)} B</span></div>
                <div><span className="text-slate-500">pkt_len_std:</span> <span className="text-slate-900">{flow.std_packet_size?.toFixed(1)}</span></div>
                <div><span className="text-slate-500">pkt_len_min:</span> <span className="text-slate-900">{flow.min_packet_size} B</span></div>
                <div><span className="text-slate-500">pkt_len_max:</span> <span className="text-slate-900">{flow.max_packet_size} B</span></div>
              </div>
            </div>

            {/* Section 3: Timing & Periodicity */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <div className="text-[11px] font-bold text-indigo-700 uppercase tracking-wider mb-2">
                3. Inter-Arrival Time (IAT) Dynamics &amp; Jitter Profile
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div>
                  <span className="text-slate-500">iat_cv:</span>{' '}
                  <span className={`font-bold ${flow.iat_cv < 0.25 ? 'text-amber-700' : 'text-slate-900'}`}>
                    {flow.iat_cv?.toFixed(4)}
                  </span>
                </div>
                <div><span className="text-slate-500">iat_mean:</span> <span className="text-slate-900">{flow.iat_mean?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">iat_std:</span> <span className="text-slate-900">{flow.iat_std?.toFixed(4)}</span></div>
                <div><span className="text-slate-500">iat_min:</span> <span className="text-slate-900">{flow.iat_min?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">iat_max:</span> <span className="text-slate-900">{flow.iat_max?.toFixed(4)}s</span></div>
                <div><span className="text-slate-500">iat_count:</span> <span className="text-slate-900">{flow.iat_count}</span></div>
              </div>
            </div>

            {/* Section 4: TCP Flags & State Counts */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <div className="text-[11px] font-bold text-indigo-700 uppercase tracking-wider mb-2">
                4. TCP Flags &amp; Control Signatures
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">tcp_flags:</span> <span className="text-slate-900 font-bold">{flow.tcp_flags || 'NONE'}</span></div>
                <div><span className="text-slate-500">tcp_syn_count:</span> <span className="text-slate-900">{flow.tcp_syn_count}</span></div>
                <div><span className="text-slate-500">tcp_syn_ratio:</span> <span className="text-slate-900 font-semibold">{((flow.tcp_syn_ratio ?? (flow.tcp_syn_count / Math.max(1, flow.packet_count))) * 100).toFixed(1)}%</span></div>
                <div><span className="text-slate-500">tcp_fin_count:</span> <span className="text-slate-900">{flow.tcp_fin_count}</span></div>
                <div><span className="text-slate-500">tcp_rst_count:</span> <span className="text-slate-900">{flow.tcp_rst_count}</span></div>
                <div><span className="text-slate-500">tcp_ack_count:</span> <span className="text-slate-900">{flow.tcp_ack_count}</span></div>
                <div><span className="text-slate-500">flag_diversity:</span> <span className="text-slate-900">{flow.tcp_flag_diversity}</span></div>
              </div>
            </div>

            {/* Section 5: DNS & TLS Metadata (PCAP Deep Extraction) */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <div className="text-[11px] font-bold text-indigo-700 uppercase tracking-wider mb-2">
                5. Passive Protocol Metrology (DNS / TLS Dimensions &amp; JA3)
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">dns_packet_count:</span> <span className="text-slate-900">{flow.dns_packet_count}</span></div>
                <div>
                  <span className="text-slate-500">dns_qname_entropy:</span>{' '}
                  <span className={`font-bold ${flow.dns_qname_entropy_mean > 3.0 ? 'text-indigo-700' : 'text-slate-900'}`}>
                    {flow.dns_qname_entropy_mean?.toFixed(3)}
                  </span>
                </div>
                <div><span className="text-slate-500">dns_qname_len_mean:</span> <span className="text-slate-900">{flow.dns_qname_len_mean?.toFixed(1)}</span></div>
                <div><span className="text-slate-500">dns_qtype_mode:</span> <span className="text-slate-900">{flow.dns_qtype_mode}</span></div>
                <div><span className="text-slate-500">tls_record_count:</span> <span className="text-slate-900">{flow.tls_record_count}</span></div>
                <div><span className="text-slate-500">tls_entropy_mean:</span> <span className="text-slate-900">{flow.tls_payload_entropy_mean?.toFixed(3)}</span></div>
                <div><span className="text-slate-500">ja3_hash:</span> <span className="text-slate-900 truncate">{flow.ja3_hash || 'N/A'}</span></div>
              </div>
            </div>

            {/* Section 6: Payload Attributes */}
            <div className="bg-slate-50 p-3 rounded-xl border border-slate-200">
              <div className="text-[11px] font-bold text-indigo-700 uppercase tracking-wider mb-2">
                6. Payload Entropy &amp; Exfiltration Indicators
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 font-mono">
                <div><span className="text-slate-500">payload_bytes_total:</span> <span className="text-slate-900 font-bold">{flow.payload_bytes_total?.toLocaleString()} B</span></div>
                <div><span className="text-slate-500">payload_ratio:</span> <span className="text-slate-900 font-semibold">{(flow.payload_ratio * 100).toFixed(1)}%</span></div>
                <div><span className="text-slate-500">payload_entropy_mean:</span> <span className="text-slate-900">{flow.payload_entropy_mean?.toFixed(3)}</span></div>
                <div><span className="text-slate-500">payload_entropy_max:</span> <span className="text-slate-900">{flow.payload_entropy_max?.toFixed(3)}</span></div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="text-xs text-slate-500 font-mono">
            Unidirectional Flow Invariant: Guaranteed Inter-packet Gap ≤ 5s
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-medium text-xs transition-colors cursor-pointer"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
