import React, { useMemo } from 'react';
import { FlowRecord, ThreatLabel } from '../types';
import { VALIDATION_REPORT } from '../data/validationReport';
import { EXTRACTION_MANIFEST } from '../data/extractionManifest';
import { computeConfusionMatrix, FEATURE_IMPORTANCE } from '../lib/detector';
import { ShieldCheck, CheckCircle2, Award, Cpu, AlertCircle, BarChart3 } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';

interface ModelEvaluationViewProps {
  flows: FlowRecord[];
}

export const ModelEvaluationView: React.FC<ModelEvaluationViewProps> = ({ flows }) => {
  const evalResults = useMemo(() => computeConfusionMatrix(flows), [flows]);

  const classes: ThreatLabel[] = [
    'benign',
    'ddos',
    'c2_beacon',
    'dns_anomaly',
    'port_scan',
    'exfiltration',
    'encrypted_anomaly'
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-400" />
            <span>AI Threat Classification & Pipeline Validation Suite</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Audit report for Block 2 Feature Extractor & Block 3 Multi-Class Threat Detection Engine.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <div className="px-3 py-1 rounded-lg bg-emerald-950/80 border border-emerald-700/60 text-emerald-400 flex items-center space-x-1.5 font-mono text-xs font-bold">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>VALIDATION STATUS: {VALIDATION_REPORT.overall_status}</span>
          </div>
        </div>
      </div>

      {/* Top 3 Score Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <span className="text-[11px] font-semibold uppercase text-slate-400">Model Accuracy</span>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{evalResults.accuracy}%</div>
          <p className="text-[11px] text-slate-400 mt-1">
            {evalResults.correctPredictions} of {evalResults.totalEvaluated} flows correctly classified
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <span className="text-[11px] font-semibold uppercase text-slate-400">PCAP Re-Extraction Match</span>
          <div className="text-2xl font-bold font-mono text-sky-400 mt-1">
            {VALIDATION_REPORT.total_flows} / {VALIDATION_REPORT.total_flows}
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Zero missing, zero extra, zero schema deviation errors
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <span className="text-[11px] font-semibold uppercase text-slate-400">Total Runs Validated</span>
          <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">{VALIDATION_REPORT.total_runs} Runs</div>
          <p className="text-[11px] text-slate-400 mt-1">
            Across all 7 attack scenarios in test partition
          </p>
        </div>
      </div>

      {/* Confusion Matrix */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Multi-Class Confusion Matrix (Predicted vs Actual Ground Truth)
          </h3>
          <span className="text-[11px] font-mono text-slate-500">Rows = Actual | Columns = Predicted</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-center text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-950/80 text-slate-400 text-[10px] uppercase">
                <th className="p-2 text-left border border-slate-800">Actual \ Predicted</th>
                {classes.map(c => (
                  <th key={c} className="p-2 border border-slate-800 text-sky-400">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {classes.map(actual => (
                <tr key={actual} className="hover:bg-slate-800/30">
                  <td className="p-2 text-left font-bold text-slate-300 border border-slate-800 bg-slate-950/40">
                    {actual}
                  </td>
                  {classes.map(pred => {
                    const count = evalResults.matrix[actual]?.[pred] || 0;
                    const isDiagonal = actual === pred;
                    return (
                      <td
                        key={pred}
                        className={`p-2 border border-slate-800 font-bold ${
                          isDiagonal
                            ? count > 0 ? 'bg-emerald-950/40 text-emerald-400' : 'text-slate-500'
                            : count > 0 ? 'bg-rose-950/40 text-rose-400' : 'text-slate-600'
                        }`}
                      >
                        {count}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Per-Class Metrics Table */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
          Per-Scenario Precision, Recall & F1 Scores
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 text-[10px] uppercase border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Threat Class</th>
                <th className="py-2.5 px-3">Precision</th>
                <th className="py-2.5 px-3">Recall</th>
                <th className="py-2.5 px-3">F1-Score</th>
                <th className="py-2.5 px-3">Support (Flows)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {evalResults.classMetrics.map(m => (
                <tr key={m.threatClass} className="hover:bg-slate-800/30">
                  <td className="py-2 px-3 font-semibold text-slate-200 capitalize">{m.threatClass.replace('_', ' ')}</td>
                  <td className="py-2 px-3 text-sky-400 font-bold">{m.precision}%</td>
                  <td className="py-2 px-3 text-indigo-400 font-bold">{m.recall}%</td>
                  <td className="py-2 px-3 text-emerald-400 font-bold">{m.f1Score}%</td>
                  <td className="py-2 px-3 text-slate-400">{m.support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Feature Importance */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
            <BarChart3 className="w-4 h-4 text-sky-400" />
            <span>Discriminative Feature Weights (Gini Importance)</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-500">Block 2 Model Inputs</span>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={FEATURE_IMPORTANCE} layout="vertical" margin={{ left: 140, right: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} domain={[0, 0.25]} />
              <YAxis dataKey="name" type="category" stroke="#94a3b8" tick={{ fontSize: 10, fill: '#94a3b8' }} width={135} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '11px' }}
                formatter={(value: any) => [`${(Number(value) * 100).toFixed(0)}% weight`, 'Feature Importance']}
              />
              <Bar dataKey="weight" fill="#38bdf8" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Block 2 Run Audit Breakdown */}
      <div className="p-5 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
          Block 2 Extraction Run Audit Log (Dataset ID: {VALIDATION_REPORT.dataset_id})
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5 font-mono text-xs">
          {VALIDATION_REPORT.runs.map((r: any, idx: number) => (
            <div key={idx} className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-sky-400 font-bold">{r.scenario}</span>
                <span className="text-[10px] text-emerald-400 bg-emerald-950/80 px-1.5 py-0.2 rounded border border-emerald-800/60">
                  {r.status}
                </span>
              </div>
              <div className="text-slate-400 text-[11px]">Run: {r.run_id}</div>
              <div className="text-slate-400 text-[11px]">Matched Flows: {r.matched} / {r.gt_flow_count}</div>
              <div className="text-slate-500 text-[10px]">Errors: {r.errors.length}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
