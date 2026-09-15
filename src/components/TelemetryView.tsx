import React, { useMemo } from 'react';
import { FlowRecord, ThreatLabel } from '../types';
import { classifyFlow } from '../lib/detector';
import { ShieldAlert, Activity, Radio, AlertTriangle, ArrowRight, ShieldCheck, Zap, Server } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, PieChart, Pie, Cell } from 'recharts';

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
      benign: '#10b981',
      ddos: '#f43f5e',
      c2_beacon: '#f59e0b',
      dns_anomaly: '#a855f7',
      port_scan: '#eab308',
      exfiltration: '#ef4444',
      encrypted_anomaly: '#06b6d4',
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
      { name: 'TCP', count: counts.tcp, color: '#38bdf8' },
      { name: 'UDP', count: counts.udp, color: '#818cf8' },
      { name: 'ICMP', count: counts.icmp, color: '#34d399' },
    ];
  }, [flows]);

  return (
    <div className="space-y-6">
      {/* Diode Architecture Guarantee Banner */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-slate-900 via-sky-950/40 to-slate-900 border border-sky-800/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start space-x-3">
          <div className="p-2.5 rounded-xl bg-sky-900/60 text-sky-400 border border-sky-700/60 mt-0.5">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm sm:text-base font-bold text-white">
                Unidirectional Passive Monitoring Emulation
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl">
              Strict passive operation: PacketSource reads synthetic PCAP streams, FlowManager groups by unidirectional 5-tuple, and computes NetFlow features with zero packets transmitted back to the network.
            </p>
          </div>
        </div>

        <button
          onClick={onOpenSimulator}
          className="px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs flex items-center space-x-2 shrink-0 transition-all cursor-pointer shadow-md shadow-sky-950"
        >
          <Zap className="w-4 h-4" />
          <span>Launch Attack Simulation</span>
        </button>
      </div>

      {/* Visualizer Row: Scenario Distribution & Protocol Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Threat Distribution Chart */}
        <div className="md:col-span-2 p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-sky-400" />
              <span>Observed Flow Distribution by Scenario</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-500">{flows.length} Total Flows</span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scenarioData} margin={{ bottom: 25, top: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} angle={-15} textAnchor="end" />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                  labelStyle={{ color: '#94a3b8' }}
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
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Server className="w-4 h-4 text-sky-400" />
              <span>Transport Layer Mix</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-1">
              Unidirectional IP distribution
            </p>
          </div>

          <div className="space-y-2 font-mono text-xs my-auto">
            {protocolData.map(p => (
              <div key={p.name} className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: p.color }}></span>
                  <span className="font-bold text-white">{p.name}</span>
                </div>
                <div className="flex items-center space-x-2">
                  <span className="text-slate-300 font-bold">{p.count} flows</span>
                  <span className="text-slate-500 text-[10px]">
                    ({((p.count / Math.max(1, flows.length)) * 100).toFixed(0)}%)
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="p-2.5 rounded-lg bg-slate-950/50 border border-slate-800/60 text-[11px] text-slate-400 font-mono">
            <span>Timeout Invariants: 15s Idle / 30s Active</span>
          </div>
        </div>
      </div>

      {/* Real-time Threat Alerts Feed */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-lg bg-rose-950/80 text-rose-400 border border-rose-800/40">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">Active Threat Detections Feed</h3>
              <p className="text-[11px] text-slate-400">Classified anomalous flows sorted by occurrence</p>
            </div>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {threatAlerts.length} High Priority Alerts
          </span>
        </div>

        <div className="divide-y divide-slate-800/60">
          {threatAlerts.map(({ flow, detection }) => (
            <div
              key={flow.flow_id}
              onClick={() => onSelectFlow(flow)}
              className="p-3.5 sm:p-4 hover:bg-slate-800/40 cursor-pointer transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
            >
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-slate-400">{flow.flow_id}</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-rose-950/80 text-rose-400 border border-rose-800/40">
                    {detection.predictedLabel} ({detection.severity})
                  </span>
                  <span className="text-slate-500 font-mono">
                    Anomaly Index: <strong className="text-rose-400">{detection.anomalyScore}%</strong>
                  </span>
                </div>

                <div className="font-mono text-slate-200 font-medium">
                  {flow.flow_key}
                </div>

                <div className="text-[11px] text-slate-400 flex flex-wrap gap-2 pt-0.5">
                  <span className="text-sky-300 font-mono">
                    {flow.packet_count} pkts ({flow.packets_per_second.toFixed(1)} pps)
                  </span>
                  <span className="text-slate-600">•</span>
                  <span className="text-slate-300">
                    Trigger: <em className="text-amber-300 not-italic">{detection.triggeredRules[0]}</em>
                  </span>
                </div>
              </div>

              <div className="flex items-center space-x-2 self-end sm:self-center">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelectFlow(flow);
                  }}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-sky-900 text-slate-300 hover:text-white font-mono text-xs flex items-center space-x-1 transition-colors"
                >
                  <span>Inspect 52 Features</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
