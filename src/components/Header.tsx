import React from 'react';
import { Shield, ShieldAlert, Radio, Activity, Eye, Zap, FileCode, FileText, Presentation, Play, Layers } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  onOpenSimulator: () => void;
  threatCount: number;
  totalFlows: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onOpenSimulator,
  threatCount,
  totalFlows
}) => {
  const tabs = [
    { id: 'telemetry', label: 'Threat Telemetry', icon: Activity },
    { id: 'architecture', label: 'Architecture & Benchmarks', icon: Layers },
    { id: 'pcap_lab', label: 'PCAP Replay & Pipeline', icon: Play },
    { id: 'notebook', label: 'Notebook ML Lab (1.26M Flows)', icon: FileCode },
    { id: 'triage', label: 'SOC Triage & STIX 2.1', icon: FileText },
    { id: 'sih_pitch', label: 'SIH Solution Deck (NTRO)', icon: Presentation },
    { id: 'flows', label: 'Flow Matrix (52 Features)', icon: Eye },
    { id: 'hosts', label: 'Host Windows (10s)', icon: Radio },
    { id: 'scenarios', label: '7 Attack Vectors', icon: ShieldAlert },
    { id: 'model', label: 'AI Detection & Audit', icon: Shield },
  ];

  return (
    <header className="border-b border-slate-200 bg-white sticky top-0 z-30 shadow-xs">
      {/* Top enterprise status bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex flex-wrap items-center justify-between border-b border-slate-100 text-xs font-mono">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 font-semibold">
            <span className="w-2 h-2 rounded-full bg-emerald-600 animate-pulse"></span>
            <span>DATA DIODE: PASSIVE READ-ONLY (Rx-ONLY)</span>
          </div>
          <div className="hidden sm:flex items-center space-x-1.5 text-slate-500">
            <span className="text-slate-300">|</span>
            <span className="font-semibold text-slate-700">0 TX BACK (Tx CUT)</span>
            <span className="text-slate-300">|</span>
            <span>NTRO PS: 26145</span>
            <span className="text-slate-300">|</span>
            <span>TEAM SNATCH01</span>
          </div>
        </div>

        <div className="flex items-center space-x-4 mt-1 sm:mt-0 text-slate-600">
          <span>
            Ingested Flows: <strong className="text-slate-900 font-bold">{totalFlows}</strong>
          </span>
          <span>
            Threats: <strong className="text-rose-700 font-bold">{threatCount}</strong>
          </span>
          <div className="flex items-center space-x-1 text-amber-800 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded text-[11px] font-semibold">
            <span>SIH 2026 SUBMISSION</span>
          </div>
        </div>
      </div>

      {/* Main enterprise navigation header */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="w-10 h-10 rounded-xl bg-slate-900 flex items-center justify-center text-white shadow-xs shrink-0">
            <Shield className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-slate-900">
                UniSentry: Cyber Threat Detection in Unidirectional IP Traffic
              </h1>
              <span className="hidden md:inline-block px-2 py-0.5 rounded bg-slate-100 text-slate-700 text-[10px] font-mono border border-slate-200 font-semibold">
                NTRO 26145
              </span>
            </div>
            <p className="text-xs text-slate-500 mt-0.5">
              Multi-Specialist AI Engine • SMOTE Random Forest (1.26M Flows) • OASIS STIX 2.1 • Safe Learning Loop
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={onOpenSimulator}
            className="flex items-center space-x-2 px-3.5 py-2 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded-lg shadow-xs transition-all cursor-pointer border border-slate-900"
          >
            <Zap className="w-4 h-4 text-amber-400" />
            <span>Simulate Traffic Attack</span>
          </button>
        </div>
      </div>

      {/* Sub-tabs with Linear / Stripe clean aesthetic */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 overflow-x-auto pb-2 scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-3 py-1.5 text-xs rounded-md whitespace-nowrap transition-all cursor-pointer ${
                isActive
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200 shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-indigo-600' : 'text-slate-400'}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
