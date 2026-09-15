import React, { useState, useMemo } from 'react';
import { Search, Filter, ArrowUpDown, Info, AlertTriangle, ShieldCheck, ChevronLeft, ChevronRight, Code } from 'lucide-react';
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
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-50 text-rose-800 border border-rose-200 font-mono">
            CRITICAL ({anomalyScore}%)
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-50 text-amber-800 border border-amber-200 font-mono">
            HIGH ({anomalyScore}%)
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-50 text-amber-700 border border-amber-200 font-mono">
            MEDIUM ({anomalyScore}%)
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200 font-mono">
            BENIGN ({anomalyScore}%)
          </span>
        );
    }
  };

  const getScenarioBadge = (scenario: string) => {
    switch (scenario) {
      case 'ddos':
        return <span className="px-2 py-0.5 rounded text-[10px] bg-rose-50 text-rose-800 border border-rose-200 font-mono font-bold">DDoS</span>;
      case 'c2_beacon':
        return <span className="px-2 py-0.5 rounded text-[10px] bg-amber-50 text-amber-800 border border-amber-200 font-mono font-bold">C2 Beacon</span>;
      case 'dns_anomaly':
        return <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-50 text-indigo-800 border border-indigo-200 font-mono font-bold">DNS Anomaly</span>;
      case 'port_scan':
        return <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 text-slate-800 border border-slate-200 font-mono font-bold">Port Scan</span>;
      case 'exfiltration':
        return <span className="px-2 py-0.5 rounded text-[10px] bg-rose-50 text-rose-800 border border-rose-200 font-mono font-bold">Exfiltration</span>;
      case 'encrypted_anomaly':
        return <span className="px-2 py-0.5 rounded text-[10px] bg-indigo-50 text-indigo-700 border border-indigo-200 font-mono font-bold">JA4 Anomaly</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-50 text-emerald-800 border border-emerald-200 font-mono font-bold">Benign</span>;
    }
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden space-y-0">
      {/* Top Filter & Search Controls */}
      <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter by IP, 5-tuple, protocol, scenario, or run ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          />
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-700 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            <option value="ALL">Protocol: All</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-white border border-slate-200 rounded-lg text-xs font-mono text-slate-700 focus:outline-none focus:ring-1 focus:ring-indigo-500"
          >
            <option value="ALL">Severity: All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="NORMAL">Normal / Benign</option>
          </select>
        </div>
      </div>

      {/* Table Element */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-700">
          <thead className="bg-slate-50 text-slate-600 font-mono text-[11px] border-b border-slate-200 uppercase tracking-wider">
            <tr>
              <th className="py-3 px-4 cursor-pointer hover:text-slate-900" onClick={() => handleSort('flow_id')}>
                <div className="flex items-center space-x-1">
                  <span>Flow ID</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4">Scenario</th>
              <th className="py-3 px-4">Unidirectional 5-Tuple</th>
              <th className="py-3 px-4 cursor-pointer hover:text-slate-900" onClick={() => handleSort('packet_count')}>
                <div className="flex items-center space-x-1">
                  <span>Packets / Bytes</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3 px-4 cursor-pointer hover:text-slate-900" onClick={() => handleSort('packets_per_second')}>
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
          <tbody className="divide-y divide-slate-100 font-mono">
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
                    className="hover:bg-slate-50 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 font-semibold text-slate-900">
                      {flow.flow_id}
                    </td>
                    <td className="py-3 px-4">
                      {getScenarioBadge(flow.scenario)}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex flex-col">
                        <span className="text-slate-900 font-medium">
                          {flow.src_ip}:{flow.src_port} <span className="text-slate-400">→</span> {flow.dst_ip}:{flow.dst_port}
                        </span>
                        <span className="text-[10px] text-slate-500 uppercase">
                          Protocol: {flow.protocol} • Dir: {flow.direction}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-slate-900 font-medium">
                        {flow.packet_count} pkts
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {flow.byte_count.toLocaleString()} bytes
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <div className="text-slate-900 font-medium">
                        {flow.packets_per_second.toFixed(1)} pps
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {flow.bytes_per_second.toFixed(0)} bps
                      </div>
                    </td>
                    <td className="py-3 px-4 text-slate-700">
                      {flow.scenario === 'c2_beacon' ? (
                        <span className="text-amber-800">IAT CV: {flow.iat_cv?.toFixed(3)}</span>
                      ) : flow.scenario === 'dns_anomaly' ? (
                        <span className="text-indigo-800">DNS Ent: {flow.dns_qname_entropy_mean?.toFixed(2)}</span>
                      ) : flow.scenario === 'ddos' ? (
                        <span className="text-rose-800">SYN Ratio: {(flow.tcp_syn_ratio * 100).toFixed(0)}%</span>
                      ) : flow.scenario === 'exfiltration' ? (
                        <span className="text-rose-800">Payload: {(flow.payload_ratio * 100).toFixed(0)}%</span>
                      ) : flow.scenario === 'encrypted_anomaly' ? (
                        <span className="text-indigo-700">TLS Ent: {(flow.tls_payload_entropy_mean || flow.payload_entropy_mean)?.toFixed(2)}</span>
                      ) : flow.scenario === 'port_scan' ? (
                        <span className="text-slate-800">Flags: {flow.tcp_flags || 'SYN'}</span>
                      ) : (
                        <span className="text-emerald-800">Baseline Var</span>
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
                        className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-600 hover:text-slate-900 transition-colors border border-slate-200"
                        title="View 52 features & JSON alert"
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
      <div className="p-3 bg-slate-50/70 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500 font-mono">
        <div>
          Showing {(currentPage - 1) * pageSize + 1} to{' '}
          {Math.min(currentPage * pageSize, sortedFlows.length)} of {sortedFlows.length} flows
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="p-1 rounded bg-white border border-slate-200 hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed text-slate-700"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="font-mono text-slate-800 font-semibold">
            Page {currentPage} of {totalPages}
          </span>
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="p-1 rounded bg-white border border-slate-200 hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed text-slate-700"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
