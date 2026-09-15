import React, { useState, useMemo } from 'react';
import { Search, Filter, ArrowUpDown, Info, AlertTriangle, ShieldCheck, ChevronLeft, ChevronRight } from 'lucide-react';
import { FlowRecord } from '../types';
import { classifyFlow } from '../lib/detector';

interface FlowsTableProps {
  flows: FlowRecord[];
  onSelectFlow: (flow: FlowRecord) => void;
  selectedScenarioFilter: string;
}

export const FlowsTable: React.FC<FlowsTableProps> = ({
  flows,
  onSelectFlow,
  selectedScenarioFilter
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState<keyof FlowRecord>('start_ts');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  const pageSize = 15;

  const filteredFlows = useMemo(() => {
    return flows.filter(flow => {
      // Scenario filter
      if (selectedScenarioFilter !== 'ALL') {
        if (flow.scenario !== selectedScenarioFilter && flow.label !== selectedScenarioFilter) {
          return false;
        }
      }

      // Protocol filter
      if (protocolFilter !== 'ALL' && flow.protocol.toLowerCase() !== protocolFilter.toLowerCase()) {
        return false;
      }

      // Severity filter
      if (severityFilter !== 'ALL') {
        const detection = classifyFlow(flow);
        if (detection.severity !== severityFilter) {
          return false;
        }
      }

      // Search term
      if (searchTerm.trim() !== '') {
        const term = searchTerm.toLowerCase();
        const matchesKey = flow.flow_key?.toLowerCase().includes(term);
        const matchesId = flow.flow_id?.toLowerCase().includes(term);
        const matchesScenario = flow.scenario?.toLowerCase().includes(term);
        const matchesLabel = String(flow.label || '').toLowerCase().includes(term);
        const matchesSrc = flow.src_ip?.toLowerCase().includes(term);
        const matchesDst = flow.dst_ip?.toLowerCase().includes(term);
        return matchesKey || matchesId || matchesScenario || matchesLabel || matchesSrc || matchesDst;
      }

      return true;
    });
  }, [flows, selectedScenarioFilter, protocolFilter, severityFilter, searchTerm]);

  // Sort
  const sortedFlows = useMemo(() => {
    return [...filteredFlows].sort((a, b) => {
      const aVal = a[sortField];
      const bVal = b[sortField];
      if (typeof aVal === 'number' && typeof bVal === 'number') {
        return sortOrder === 'asc' ? aVal - bVal : bVal - aVal;
      }
      return sortOrder === 'asc' 
        ? String(aVal).localeCompare(String(bVal))
        : String(bVal).localeCompare(String(aVal));
    });
  }, [filteredFlows, sortField, sortOrder]);

  // Pagination
  const totalPages = Math.ceil(sortedFlows.length / pageSize) || 1;
  const paginatedFlows = sortedFlows.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleSort = (field: keyof FlowRecord) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const getSeverityBadge = (flow: FlowRecord) => {
    const { severity, anomalyScore } = classifyFlow(flow);
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/80 text-rose-400 border border-rose-800/40 font-mono">
            CRITICAL ({anomalyScore}%)
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/80 text-amber-400 border border-amber-800/40 font-mono">
            HIGH ({anomalyScore}%)
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-yellow-950/80 text-yellow-400 border border-yellow-800/40 font-mono">
            MEDIUM ({anomalyScore}%)
          </span>
        );
      case 'NORMAL':
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/80 text-emerald-400 border border-emerald-800/40 font-mono">
            BENIGN ({anomalyScore}%)
          </span>
        );
    }
  };

  const getScenarioBadge = (scenario: string) => {
    const s = scenario?.toLowerCase();
    const colors: Record<string, string> = {
      benign: 'text-emerald-400 bg-emerald-950/60 border-emerald-800/40',
      ddos: 'text-rose-400 bg-rose-950/60 border-rose-800/40',
      c2_beacon: 'text-amber-400 bg-amber-950/60 border-amber-800/40',
      dns_anomaly: 'text-purple-400 bg-purple-950/60 border-purple-800/40',
      port_scan: 'text-yellow-400 bg-yellow-950/60 border-yellow-800/40',
      exfiltration: 'text-red-400 bg-red-950/60 border-red-800/40',
      encrypted_anomaly: 'text-cyan-400 bg-cyan-950/60 border-cyan-800/40'
    };
    const cls = colors[s] || 'text-slate-300 bg-slate-800 border-slate-700';
    return (
      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${cls}`}>
        {scenario}
      </span>
    );
  };

  return (
    <div className="bg-slate-900/80 rounded-xl border border-slate-800 shadow-md overflow-hidden">
      {/* Table Header & Controls */}
      <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span>Reconstructed Unidirectional Flows</span>
            <span className="text-xs font-mono font-normal text-sky-400 bg-sky-950 px-2 py-0.5 rounded border border-sky-800/50">
              {filteredFlows.length} Matching
            </span>
          </h2>
          <p className="text-xs text-slate-400">
            Click any row to inspect all 52 canonical NetFlow & PCAP metadata features.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              placeholder="Search IP, port, flow key..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 w-48 sm:w-60 font-mono"
            />
          </div>

          {/* Protocol dropdown */}
          <select
            value={protocolFilter}
            onChange={(e) => {
              setProtocolFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-300 font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Protocols</option>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="icmp">ICMP</option>
          </select>

          {/* Severity dropdown */}
          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="py-1.5 px-2.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs text-slate-300 font-mono focus:outline-none focus:border-sky-500"
          >
            <option value="ALL">All Severity</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="NORMAL">Normal / Benign</option>
          </select>
        </div>
      </div>

      {/* Table Element */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/70 text-slate-400 font-mono text-[11px] border-b border-slate-800 uppercase tracking-wider">
            <tr>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('flow_id')}>
                <div className="flex items-center space-x-1">
                  <span>Flow ID</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4">Scenario</th>
              <th className="py-3 px-4">Unidirectional 5-Tuple</th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('packet_count')}>
                <div className="flex items-center space-x-1">
                  <span>Packets / Bytes</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-white" onClick={() => handleSort('packets_per_second')}>
                <div className="flex items-center space-x-1">
                  <span>Rate (PPS / BPS)</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4">Behavioral Signature</th>
              <th className="py-3 px-4">AI Threat Rating</th>
              <th className="py-3 px-4 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {paginatedFlows.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  No unidirectional flows matched your filters.
                </td>
              </tr>
            ) : (
              paginatedFlows.map((flow) => {
                const { predictedLabel, anomalyScore } = classifyFlow(flow);
                return (
                  <tr
                    key={flow.flow_id}
                    onClick={() => onSelectFlow(flow)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      {flow.flow_id}
                    </td>
                    <td className="py-3 px-4">
                      {getScenarioBadge(flow.scenario)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-col">
                        <span className="text-slate-200 font-medium">
                          {flow.src_ip}:{flow.src_port} <span className="text-slate-500">→</span> {flow.dst_ip}:{flow.dst_port}
                        </span>
                        <span className="text-[10px] text-slate-500 uppercase">
                          Protocol: {flow.protocol} • Dir: {flow.direction}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-slate-200 font-medium">
                        {flow.packet_count} pkts
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {flow.byte_count.toLocaleString()} bytes
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-slate-200 font-medium">
                        {flow.packets_per_second.toFixed(1)} pps
                      </div>
                      <div className="text-[10px] text-slate-400">
                        {flow.bytes_per_second.toFixed(0)} bps
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      {flow.scenario === 'c2_beacon' ? (
                        <span className="text-amber-400">IAT CV: {flow.iat_cv?.toFixed(3)}</span>
                      ) : flow.scenario === 'dns_anomaly' ? (
                        <span className="text-purple-400">DNS Ent: {flow.dns_qname_entropy_mean?.toFixed(2)}</span>
                      ) : flow.scenario === 'ddos' ? (
                        <span className="text-rose-400">SYN Ratio: {(flow.tcp_syn_ratio * 100).toFixed(0)}%</span>
                      ) : flow.scenario === 'exfiltration' ? (
                        <span className="text-red-400">Payload: {(flow.payload_ratio * 100).toFixed(0)}%</span>
                      ) : flow.scenario === 'encrypted_anomaly' ? (
                        <span className="text-cyan-400">TLS Ent: {(flow.tls_payload_entropy_mean || flow.payload_entropy_mean)?.toFixed(2)}</span>
                      ) : flow.scenario === 'port_scan' ? (
                        <span className="text-yellow-400">Flags: {flow.tcp_flags || 'SYN'}</span>
                      ) : (
                        <span className="text-emerald-400">Baseline Var</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {getSeverityBadge(flow)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFlow(flow);
                        }}
                        className="p-1.5 rounded-lg bg-slate-800 hover:bg-sky-950 text-slate-400 hover:text-sky-400 transition-colors"
                        title="View 52 features"
                      >
                        <Info className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 bg-slate-950/60 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
        <div>
          Showing {(currentPage - 1) * pageSize + 1} to{' '}
          {Math.min(currentPage * pageSize, sortedFlows.length)} of {sortedFlows.length} flows
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-slate-200">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="p-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
