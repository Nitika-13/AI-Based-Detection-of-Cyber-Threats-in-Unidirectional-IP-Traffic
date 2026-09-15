import React from 'react';
import { SCENARIOS } from '../lib/scenarios';
import { ShieldAlert, Zap, AlertTriangle, CheckCircle2, Lock, ArrowRight } from 'lucide-react';
import { ThreatLabel } from '../types';

interface ScenariosGuideProps {
  onSimulateScenario: (scenario: ThreatLabel) => void;
}

export const ScenariosGuide: React.FC<ScenariosGuideProps> = ({ onSimulateScenario }) => {
  const scenarioList = Object.values(SCENARIOS);

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-800">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950 text-yellow-400 border border-yellow-800">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">SAFE / BASELINE</span>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <span>7 Supported Cyber Threat & Attack Scenarios</span>
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-4xl">
          Designed for unidirectional passive network monitoring under SIH 26145. No payload decryption is performed; all classifications stem from timing, volume, flag distribution, and protocol header metrology.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {scenarioList.map((sc) => (
          <div
            key={sc.id}
            className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between space-y-4 shadow-sm"
          >
            <div className="space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-sky-400 uppercase">{sc.category}</span>
                    {getSeverityBadge(sc.threatSeverity)}
                  </div>
                  <h3 className="text-sm sm:text-base font-bold text-white mt-1">{sc.name}</h3>
                </div>

                <button
                  onClick={() => onSimulateScenario(sc.id)}
                  className="px-2.5 py-1.5 rounded-lg bg-sky-950 hover:bg-sky-900 text-sky-300 border border-sky-800/60 text-xs font-mono font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer shrink-0"
                >
                  <Zap className="w-3.5 h-3.5" />
                  <span>Simulate</span>
                </button>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                {sc.description}
              </p>

              <div className="space-y-2 pt-2 border-t border-slate-800/80 text-xs">
                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block font-mono">
                    Attack Vector:
                  </span>
                  <span className="text-slate-300 text-xs">{sc.attackVector}</span>
                </div>

                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block font-mono">
                    Detection Thresholds & Triggers:
                  </span>
                  <span className="text-amber-300 font-mono text-[11px]">{sc.detectionThresholds}</span>
                </div>

                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block font-mono">
                    Key Discriminating Features:
                  </span>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {sc.primaryFeatures.map((feat) => (
                      <span key={feat} className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 font-mono text-[10px]">
                        {feat}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block font-mono">
                    Passive Defense & Mitigation:
                  </span>
                  <span className="text-emerald-400 text-xs">{sc.defenseMitigation}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
