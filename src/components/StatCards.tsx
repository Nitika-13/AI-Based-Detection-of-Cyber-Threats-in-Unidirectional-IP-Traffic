import React from 'react';
import { ShieldCheck, ShieldAlert, Cpu, Network, Zap } from 'lucide-react';
import { FlowRecord, ThreatLabel } from '../types';

interface StatCardsProps {
  flows: FlowRecord[];
  onSelectScenarioFilter: (scenario: string) => void;
  selectedScenario: string;
}

export const StatCards: React.FC<StatCardsProps> = ({
  flows,
  onSelectScenarioFilter,
  selectedScenario
}) => {
  const totalFlows = flows.length;
  const threatFlows = flows.filter(f => f.label !== 'benign');
  const criticalFlows = flows.filter(f => f.label === 'ddos' || f.label === 'exfiltration');
  const highFlows = flows.filter(f => f.label === 'c2_beacon' || f.label === 'dns_anomaly' || f.label === 'encrypted_anomaly');
  const mediumFlows = flows.filter(f => f.label === 'port_scan');

  const totalPackets = flows.reduce((acc, f) => acc + (f.packet_count || 0), 0);
  const totalBytes = flows.reduce((acc, f) => acc + (f.byte_count || 0), 0);

  const scenarioCounts: Record<ThreatLabel, number> = {
    benign: 0,
    ddos: 0,
    c2_beacon: 0,
    dns_anomaly: 0,
    port_scan: 0,
    exfiltration: 0,
    encrypted_anomaly: 0
  };

  flows.forEach(f => {
    const lbl = (f.label || 'benign') as ThreatLabel;
    if (scenarioCounts[lbl] !== undefined) {
      scenarioCounts[lbl]++;
    }
  });

  return (
    <div className="space-y-4">
      {/* 4 Main Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Total Flows */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Flows Monitored</span>
            <div className="p-2 rounded-lg bg-sky-950/70 text-sky-400 border border-sky-800/40">
              <Network className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-white">{totalFlows}</span>
            <span className="text-xs text-emerald-400">100% Unidirectional</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center justify-between">
            <span>{totalPackets.toLocaleString()} packets</span>
            <span>{(totalBytes / 1024).toFixed(1)} KB captured</span>
          </div>
        </div>

        {/* Card 2: Threat Detections */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Threat Alerts</span>
            <div className="p-2 rounded-lg bg-rose-950/70 text-rose-400 border border-rose-800/40">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-rose-400">{threatFlows.length}</span>
            <span className="text-xs text-rose-400 font-mono">
              ({((threatFlows.length / Math.max(1, totalFlows)) * 100).toFixed(0)}% attack density)
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400 flex items-center space-x-3">
            <span className="text-rose-400">{criticalFlows.length} Crit</span>
            <span className="text-amber-400">{highFlows.length} High</span>
            <span className="text-yellow-400">{mediumFlows.length} Med</span>
          </div>
        </div>

        {/* Card 3: Anomaly Ratio */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Diode Security Status</span>
            <div className="p-2 rounded-lg bg-emerald-950/70 text-emerald-400 border border-emerald-800/40">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-emerald-400">ISOLATED</span>
            <span className="text-xs text-emerald-500/80">0 Bytes TX</span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Passive tap emulation • No back-channel packet egress
          </p>
        </div>

        {/* Card 4: AI Model Confidence */}
        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">ML Engine Status</span>
            <div className="p-2 rounded-lg bg-indigo-950/70 text-indigo-400 border border-indigo-800/40">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-mono text-indigo-400">98.5%</span>
            <span className="text-xs text-indigo-300">Mean Confidence</span>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            Canonical 52-Feature Schema • Decision Tree Matrix
          </p>
        </div>
      </div>

      {/* Scenario Quick Filter Chips */}
      <div className="p-3 bg-slate-900/60 rounded-xl border border-slate-800/80 flex items-center justify-between flex-wrap gap-2 text-xs">
        <div className="flex items-center space-x-2 text-slate-400 font-medium">
          <Zap className="w-3.5 h-3.5 text-sky-400" />
          <span>Quick Scenario Filter:</span>
        </div>
        <div className="flex items-center flex-wrap gap-1.5">
          <button
            onClick={() => onSelectScenarioFilter('ALL')}
            className={`px-2.5 py-1 rounded-md font-mono transition-all cursor-pointer ${
              selectedScenario === 'ALL'
                ? 'bg-sky-600 text-white font-semibold shadow'
                : 'bg-slate-800/80 text-slate-400 hover:text-white'
            }`}
          >
            ALL ({totalFlows})
          </button>
          
          {(
            [
              { id: 'benign', label: 'Benign', color: 'text-emerald-400', count: scenarioCounts.benign },
              { id: 'ddos', label: 'DDoS', color: 'text-rose-400', count: scenarioCounts.ddos },
              { id: 'c2_beacon', label: 'C2 Beacon', color: 'text-amber-400', count: scenarioCounts.c2_beacon },
              { id: 'dns_anomaly', label: 'DNS Anomaly', color: 'text-purple-400', count: scenarioCounts.dns_anomaly },
              { id: 'port_scan', label: 'Port Scan', color: 'text-yellow-400', count: scenarioCounts.port_scan },
              { id: 'exfiltration', label: 'Exfiltration', color: 'text-red-400', count: scenarioCounts.exfiltration },
              { id: 'encrypted_anomaly', label: 'Encrypted Anomaly', color: 'text-cyan-400', count: scenarioCounts.encrypted_anomaly },
            ] as const
          ).map(s => (
            <button
              key={s.id}
              onClick={() => onSelectScenarioFilter(s.id)}
              className={`px-2.5 py-1 rounded-md font-mono transition-all cursor-pointer flex items-center space-x-1.5 ${
                selectedScenario === s.id
                  ? 'bg-slate-700 text-white border border-slate-600 font-semibold'
                  : 'bg-slate-800/60 text-slate-400 hover:text-white'
              }`}
            >
              <span className={s.color}>{s.label}</span>
              <span className="text-[10px] bg-slate-900/80 px-1 py-0.2 rounded text-slate-400">{s.count}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
