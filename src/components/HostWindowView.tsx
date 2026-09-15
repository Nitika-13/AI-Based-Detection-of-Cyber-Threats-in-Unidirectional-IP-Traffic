import React, { useState, useMemo } from 'react';
import { HostWindowRecord } from '../types';
import { Search, Radio, Activity, ShieldAlert, Filter, Server, ArrowUpDown } from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, BarChart, Bar } from 'recharts';

interface HostWindowViewProps {
  hostWindows: HostWindowRecord[];
}

export const HostWindowView: React.FC<HostWindowViewProps> = ({ hostWindows }) => {
  const [selectedIp, setSelectedIp] = useState<string>('ALL');
  const [roleFilter, setRoleFilter] = useState<string>('ALL');
  const [scenarioFilter, setScenarioFilter] = useState<string>('ALL');

  // Distinct IPs
  const uniqueIps = useMemo(() => {
    const set = new Set<string>();
    hostWindows.forEach(w => set.add(w.ip));
    return Array.from(set).sort();
  }, [hostWindows]);

  const filteredWindows = useMemo(() => {
    return hostWindows.filter(w => {
      if (selectedIp !== 'ALL' && w.ip !== selectedIp) return false;
      if (roleFilter !== 'ALL' && w.role !== roleFilter) return false;
      if (scenarioFilter !== 'ALL' && w.scenario !== scenarioFilter) return false;
      return true;
    });
  }, [hostWindows, selectedIp, roleFilter, scenarioFilter]);

  // Chart data: Window indices and rate trends
  const chartData = useMemo(() => {
    // Take top 30 windows or group by window_index
    const byWindow: Record<number, { window_index: number; pps: number; bps: number; syn_ratio: number; peer_ports: number }> = {};
    filteredWindows.slice(0, 50).forEach(w => {
      const idx = w.window_index;
      if (!byWindow[idx]) {
        byWindow[idx] = {
          window_index: idx,
          pps: 0,
          bps: 0,
          syn_ratio: 0,
          peer_ports: 0
        };
      }
      byWindow[idx].pps += w.packet_rate_pps || 0;
      byWindow[idx].bps += w.byte_rate_bps || 0;
      byWindow[idx].syn_ratio = Math.max(byWindow[idx].syn_ratio, w.syn_flow_ratio || 0);
      byWindow[idx].peer_ports = Math.max(byWindow[idx].peer_ports, w.unique_peer_port_count || 0);
    });

    return Object.values(byWindow).sort((a, b) => a.window_index - b.window_index);
  }, [filteredWindows]);

  // Key stats
  const totalWindows = filteredWindows.length;
  const avgSynRatio = totalWindows > 0 
    ? (filteredWindows.reduce((acc, w) => acc + (w.syn_flow_ratio || 0), 0) / totalWindows) * 100 
    : 0;
  const maxPps = filteredWindows.reduce((max, w) => Math.max(max, w.packet_rate_pps || 0), 0);
  const maxPeerPorts = filteredWindows.reduce((max, w) => Math.max(max, w.unique_peer_port_count || 0), 0);

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Radio className="w-5 h-5 text-sky-400" />
            <span>Host-Level 10-Second Time Window Aggregations</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Monitored subnet (10.0.0.0/24) vs External (10.0.1.0/24) • Windowing metrics for reconnaissance, scanning & volumetric anomaly detection.
          </p>
        </div>

        {/* Filter dropdowns */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <select
            value={selectedIp}
            onChange={(e) => setSelectedIp(e.target.value)}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-slate-300 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Host IPs ({uniqueIps.length})</option>
            {uniqueIps.map(ip => (
              <option key={ip} value={ip}>{ip}</option>
            ))}
          </select>

          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-slate-300 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Roles</option>
            <option value="src">Source Host (Egress)</option>
            <option value="dst">Destination Host (Ingress)</option>
          </select>

          <select
            value={scenarioFilter}
            onChange={(e) => setScenarioFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-slate-300 focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Scenarios</option>
            <option value="benign">Benign</option>
            <option value="ddos">DDoS</option>
            <option value="c2_beacon">C2 Beacon</option>
            <option value="dns_anomaly">DNS Anomaly</option>
            <option value="port_scan">Port Scan</option>
            <option value="exfiltration">Exfiltration</option>
            <option value="encrypted_anomaly">Encrypted Anomaly</option>
          </select>
        </div>
      </div>

      {/* Summary KPI grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
          <span className="text-[10px] uppercase font-semibold text-slate-400">Total 10s Windows</span>
          <div className="text-xl font-bold font-mono text-white mt-1">{totalWindows}</div>
          <span className="text-[10px] text-slate-500">275 in canonical dataset</span>
        </div>
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
          <span className="text-[10px] uppercase font-semibold text-slate-400">Max Host Packet Rate</span>
          <div className="text-xl font-bold font-mono text-sky-400 mt-1">{maxPps.toFixed(1)} pps</div>
          <span className="text-[10px] text-slate-500">Peak window throughput</span>
        </div>
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
          <span className="text-[10px] uppercase font-semibold text-slate-400">Mean SYN Flow Ratio</span>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">{avgSynRatio.toFixed(1)}%</div>
          <span className="text-[10px] text-slate-500">SYN imbalance metric</span>
        </div>
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl">
          <span className="text-[10px] uppercase font-semibold text-slate-400">Max Unique Peer Ports</span>
          <div className="text-xl font-bold font-mono text-rose-400 mt-1">{maxPeerPorts} ports</div>
          <span className="text-[10px] text-slate-500">Port scan fan-out indicator</span>
        </div>
      </div>

      {/* Recharts Host Window Rate Trends */}
      {chartData.length > 0 && (
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-sky-400" />
              <span>Host Window Temporal Dynamics (Across 10-Second Windows)</span>
            </h3>
            <span className="text-[11px] font-mono text-slate-400">PPS & Peer Port Probes</span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="window_index" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} label={{ value: 'Window Index (10s increments)', position: 'insideBottom', offset: -4, fill: '#64748b', fontSize: 10 }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Line type="monotone" dataKey="pps" stroke="#38bdf8" strokeWidth={2} name="Packet Rate (PPS)" dot={false} />
                <Line type="monotone" dataKey="peer_ports" stroke="#f43f5e" strokeWidth={2} name="Unique Peer Ports" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Host Windows Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-3 border-b border-slate-800 flex items-center justify-between text-xs">
          <span className="font-bold text-white">Aggregated Window Records</span>
          <span className="font-mono text-slate-400">Showing {filteredWindows.length} records</span>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-950/80 text-slate-400 text-[11px] sticky top-0 border-b border-slate-800 uppercase">
              <tr>
                <th className="py-2.5 px-3">Win #</th>
                <th className="py-2.5 px-3">Scenario</th>
                <th className="py-2.5 px-3">Host IP</th>
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Flows / Pkts</th>
                <th className="py-2.5 px-3">PPS / BPS</th>
                <th className="py-2.5 px-3">Peer IPs (Entropy)</th>
                <th className="py-2.5 px-3">Peer Ports (Entropy)</th>
                <th className="py-2.5 px-3">SYN Ratio</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredWindows.slice(0, 100).map((w, idx) => (
                <tr key={idx} className="hover:bg-slate-800/40">
                  <td className="py-2 px-3 text-slate-400">#{w.window_index}</td>
                  <td className="py-2 px-3 font-semibold text-sky-400">{w.scenario}</td>
                  <td className="py-2 px-3 font-semibold text-white">{w.ip}</td>
                  <td className="py-2 px-3 uppercase text-slate-400 text-[10px]">{w.role}</td>
                  <td className="py-2 px-3">
                    {w.flow_count} flows / {w.packet_count} pkts
                  </td>
                  <td className="py-2 px-3">
                    <span className="text-sky-300">{w.packet_rate_pps?.toFixed(1)} pps</span>
                    <span className="text-slate-500 text-[10px] block">{w.byte_rate_bps?.toFixed(0)} bps</span>
                  </td>
                  <td className="py-2 px-3">
                    {w.unique_peer_ip_count} ({w.peer_ip_entropy?.toFixed(2)})
                  </td>
                  <td className="py-2 px-3">
                    <span className={w.unique_peer_port_count > 5 ? 'text-amber-400 font-bold' : 'text-slate-300'}>
                      {w.unique_peer_port_count} ({w.peer_port_entropy?.toFixed(2)})
                    </span>
                  </td>
                  <td className="py-2 px-3">
                    <span className={w.syn_flow_ratio > 0.5 ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                      {(w.syn_flow_ratio * 100).toFixed(0)}%
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
