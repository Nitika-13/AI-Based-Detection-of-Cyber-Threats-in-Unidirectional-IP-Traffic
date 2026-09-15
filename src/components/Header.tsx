import React from 'react';
import { Shield, ShieldAlert, Radio, Activity, Eye, Zap, FileCode, FileText, Presentation, Play } from 'lucide-react';

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
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur-md sticky top-0 z-30">
      {/* Top status bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-2 flex flex-wrap items-center justify-between border-b border-slate-800/60 text-xs">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-600/40 text-emerald-400 font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>DATA DIODE: PASSIVE READ-ONLY (Rx-ONLY)</span>
          </div>
          <div className="hidden sm:flex items-center space-x-1.5 text-slate-400 font-mono">
            <span className="text-slate-600">|</span>
            <span>0 TX BACK</span>
            <span className="text-slate-600">|</span>
            <span>NTRO PS: 26145</span>
            <span className="text-slate-600">|</span>
            <span>TEAM SNATCH01</span>
          </div>
        </div>

        <div className="flex items-center space-x-4 mt-1 sm:mt-0 font-mono text-slate-300">
          <span className="text-slate-400">
            Flows: <strong className="text-white">{totalFlows}</strong>
          </span>
          <span className="text-slate-400">
            Threats: <strong className="text-rose-400">{threatCount}</strong>
          </span>
          <div className="flex items-center space-x-1.5 text-amber-300 bg-amber-950/70 border border-amber-700/50 px-2 py-0.5 rounded font-semibold">
            <span>SIH 2026</span>
          </div>
        </div>
      </div>

      {/* Main navigation */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-sky-600 to-indigo-700 flex items-center justify-center text-white shadow-lg shadow-sky-900/30 shrink-0">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-white">
                UniSentry: Cyber Threat Detection in Unidirectional IP Traffic
              </h1>
              <span className="hidden md:inline-block px-2 py-0.5 rounded bg-sky-950 text-sky-400 text-[10px] font-mono border border-sky-800/50">
                NTRO 26145
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Multi-Specialist AI Engine • SMOTE-Balanced Random Forest (1.26M Flows) • OASIS STIX 2.1 • Safe Learning Loop
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <button
            onClick={onOpenSimulator}
            className="flex items-center space-x-2 px-3.5 py-2 bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white text-xs font-semibold rounded-lg shadow-md shadow-rose-950/40 transition-all cursor-pointer"
          >
            <Zap className="w-4 h-4" />
            <span>Simulate Traffic Attack</span>
          </button>
        </div>
      </div>

      {/* Sub-tabs */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 overflow-x-auto pb-2 scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center space-x-2 px-3 py-2 text-xs font-medium rounded-md whitespace-nowrap transition-all cursor-pointer ${
                isActive
                  ? 'bg-slate-800 text-sky-400 border-b-2 border-sky-500 font-semibold shadow-sm shadow-sky-950'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
