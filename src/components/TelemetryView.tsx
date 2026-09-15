import React, { useMemo, useState } from 'react';
import { FlowRecord, ThreatLabel, StructuredThreatAlert } from '../types';
import { classifyFlow, generateStructuredAlert } from '../lib/detector';
import { ShieldAlert, Activity, Radio, AlertTriangle, ArrowRight, ShieldCheck, Zap, Server, Code, Copy, Check } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, Cell } from 'recharts';

interface TelemetryViewProps {
  flows: FlowRecord[];
  onSelectFlow: (flow: FlowRecord) => void;
  onOpenSimulator: () => void;
}

export const TelemetryView: React.FC<TelemetryViewProps> = ({
  flows,
  onSelectFlow,
  onOpenSimulator
}) => {
  const [activeJsonAlert, setActiveJsonAlert] = useState<StructuredThreatAlert | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  // Recent threats
  const threatAlerts = useMemo(() => {
    return flows
      .filter(f => f.label !== 'benign')
      .map(flow => ({
        flow,
        detection: classifyFlow(flow)
      }))
      .slice(0, 10);
  }, [flows]);

  // Threat count by scenario
  const scenarioData = useMemo(() => {
    const counts: Record<string, number> = {};
    flows.forEach(f => {
      const s = f.scenario || 'unknown';
      counts[s] = (counts[s] || 0) + 1;
    });

    const colors: Record<string, string> = {
      benign: '#166534',
      ddos: '#991B1B',
      c2_beacon: '#D97706',
      dns_anomaly: '#4F46E5',
      port_scan: '#D97706',
      exfiltration: '#B91C1C',
      encrypted_anomaly: '#0284C7',
    };

    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
      color: colors[name] || '#64748b'
    }));
  }, [flows]);

  // Protocol distribution
  const protocolData = useMemo(() => {
    const counts: Record<string, number> = { tcp: 0, udp: 0, icmp: 0 };
    flows.forEach(f => {
      const p = (f.protocol || 'tcp').toLowerCase();
      counts[p] = (counts[p] || 0) + 1;
    });
    return [
      { name: 'TCP', count: counts.tcp, color: '#4F46E5' },
      { name: 'UDP', count: counts.udp, color: '#0284C7' },
      { name: 'ICMP', count: counts.icmp, color: '#166534' },
    ];
  }, [flows]);

  const handleCopyAlertJson = (alert: StructuredThreatAlert) => {
    navigator.clipboard.writeText(JSON.stringify(alert, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Enterprise Passive Monitoring Guarantee Banner */}
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start space-x-3.5">
          <div className="p-2.5 rounded-xl bg-emerald-50 text-emerald-800 border border-emerald-200 mt-0.5 shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm sm:text-base font-bold text-slate-900">
                Unidirectional Passive Monitoring Emulation
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold">
                Rx-ONLY ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1 max-w-3xl leading-relaxed">
              Strict passive operation: PacketSource receives mirror PCAP streams, FlowManager groups by unidirectional 5-tuple, and computes NetFlow features with zero packets or ACKs emitted back.
            </p>
          </div>
        </div>

        <button
          onClick={onOpenSimulator}
          className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs flex items-center space-x-2 shrink-0 transition-all cursor-pointer shadow-xs"
        >
          <Zap className="w-4 h-4 text-amber-300" />
          <span>Launch Attack Simulation</span>
        </button>
      </div>

      {/* Visualizer Row: Scenario Distribution & Protocol Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Threat Distribution Chart */}
        <div className="md:col-span-2 p-4 bg-white border border-slate-200 shadow-sm rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-indigo-600" />
              <span>Observed Flow Distribution by Scenario</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-500">{flows.length} Total Flows</span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scenarioData} margin={{ bottom: 25, top: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
                <XAxis dataKey="name" stroke="#64748B" tick={{ fontSize: 10, fill: '#64748B' }} angle={-15} textAnchor="end" />
                <YAxis stroke="#64748B" tick={{ fontSize: 10, fill: '#64748B' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#E2E8F0', borderRadius: '8px', fontSize: '11px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                  labelStyle={{ color: '#0F172A', fontWeight: 600 }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {scenarioData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Breakdown */}
        <div className="p-4 bg-white border border-slate-200 shadow-sm rounded-xl space-y-3 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5">
              <Server className="w-4 h-4 text-indigo-600" />
              <span>Transport Layer Mix</span>
            </h3>
            <p className="text-[11px] text-slate-500 mt-1">
              Unidirectional IP distribution
            </p>
          </div>

          <div className="space-y-2 font-mono text-xs my-auto">
            {protocolData.map(p => (
              <div key={p.name} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: p.color }}></span>
                  <span className="font-bold text-slate-900">{p.name}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-slate-700 font-bold">{p.count} flows</span>
                  <span className="text-slate-500 text-[10px]">
                    ({((p.count / Math.max(1, flows.length)) * 100).toFixed(0)}%)
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-[11px] text-slate-600 font-mono">
            <span>Timeout Invariants: 15s Idle / 30s Active</span>
          </div>
        </div>
      </div>

      {/* Real-time Threat Alerts Feed */}
      <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/50">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-rose-50 text-rose-800 border border-rose-200">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-900">Active Threat Detections Feed</h3>
              <p className="text-[11px] text-slate-500">Classified anomalous flows sorted by occurrence</p>
            </div>
          </div>
          <span className="text-xs font-mono text-slate-600 font-medium">
            {threatAlerts.length} High Priority Alerts
          </span>
        </div>

        <div className="divide-y divide-slate-100">
          {threatAlerts.map(({ flow, detection }) => {
            const structuredAlert = generateStructuredAlert(flow, detection);
            return (
              <div
                key={flow.flow_id}
                onClick={() => onSelectFlow(flow)}
                className="p-3.5 sm:p-4 hover:bg-slate-50 cursor-pointer transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                    <span className="font-mono text-slate-500">{flow.flow_id}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      detection.severity === 'CRITICAL' 
                        ? 'bg-rose-50 text-rose-800 border border-rose-200'
                        : detection.severity === 'HIGH'
                        ? 'bg-amber-50 text-amber-800 border border-amber-200'
                        : 'bg-slate-100 text-slate-800 border border-slate-200'
                    }`}>
                      {detection.predictedLabel} ({detection.severity})
                    </span>
                    <span className="text-slate-500 font-mono text-[11px]">
                      Confidence: <strong className="text-indigo-700">{Math.round(detection.confidence)}%</strong>
                    </span>
                  </div>

                  <div className="font-mono text-slate-800 font-medium text-xs">
                    {flow.flow_key}
                  </div>

                  <div className="text-[11px] text-slate-500 flex flex-wrap gap-2 pt-0.5">
                    <span className="text-indigo-700 font-mono font-semibold">
                      {flow.packet_count} pkts ({flow.packets_per_second.toFixed(1)} pps)
                    </span>
                    <span className="text-slate-300">•</span>
                    <span className="text-slate-600">
                      Trigger: <em className="text-slate-800 font-medium not-italic">{detection.triggeredRules[0]}</em>
                    </span>
                  </div>
                </div>

                <div className="flex items-center space-x-2 self-end sm:self-center shrink-0">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setActiveJsonAlert(structuredAlert);
                    }}
                    className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 font-mono text-xs flex items-center space-x-1 transition-colors border border-slate-200"
                    title="View Clean Structured Alert JSON"
                  >
                    <Code className="w-3 h-3 text-indigo-600" />
                    <span>JSON Alert</span>
                  </button>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onSelectFlow(flow);
                    }}
                    className="px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-white font-mono text-xs flex items-center space-x-1 transition-colors"
                  >
                    <span>Inspect 52 Features</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Clean Structured Alert JSON Modal */}
      {activeJsonAlert && (
        <div className="fixed inset-0 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-xl border border-slate-200 shadow-xl max-w-lg w-full p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <Code className="w-4 h-4 text-indigo-600" />
                <h4 className="text-sm font-bold text-slate-900 font-mono">
                  Structured Threat Alert JSON
                </h4>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold">
                VALIDATED SCHEMA
              </span>
            </div>

            <div className="relative">
              <pre className="bg-slate-900 text-slate-100 p-3.5 rounded-lg text-xs font-mono overflow-x-auto leading-relaxed border border-slate-800">
                {JSON.stringify(activeJsonAlert, null, 2)}
              </pre>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-slate-500 font-mono">
                SIEM / SOAR Ingestion Ready
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleCopyAlertJson(activeJsonAlert)}
                  className="px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'COPIED' : 'COPY JSON'}</span>
                </button>
                <button
                  onClick={() => setActiveJsonAlert(null)}
                  className="px-3 py-1.5 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold cursor-pointer border border-slate-200"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
