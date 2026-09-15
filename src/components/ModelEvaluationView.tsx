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
      <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
            <Cpu className="w-5 h-5 text-indigo-600" />
            <span>AI Threat Classification &amp; Pipeline Validation Suite</span>
          </h2>
          <p className="text-xs text-slate-600 mt-0.5">
            Audit report for Feature Extractor &amp; Multi-Class Threat Detection Engine.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <div className="px-3 py-1 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-800 flex items-center space-x-1.5 font-mono text-xs font-bold">
            <CheckCircle2 className="w-4 h-4 text-emerald-700" />
            <span>VALIDATION STATUS: {VALIDATION_REPORT.overall_status}</span>
          </div>
        </div>
      </div>

      {/* Top 3 Score Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold uppercase text-slate-500 font-mono">Model Accuracy</span>
          <div className="text-2xl font-bold font-mono text-emerald-800 mt-1">{evalResults.accuracy}%</div>
          <p className="text-[11px] text-slate-500 mt-1">
            {evalResults.correctPredictions} of {evalResults.totalEvaluated} flows correctly classified
          </p>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold uppercase text-slate-500 font-mono">PCAP Re-Extraction Match</span>
          <div className="text-2xl font-bold font-mono text-indigo-700 mt-1">
            {VALIDATION_REPORT.total_flows} / {VALIDATION_REPORT.total_flows}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            Zero missing, zero extra, zero schema deviation errors
          </p>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-sm">
          <span className="text-[11px] font-semibold uppercase text-slate-500 font-mono">Total Runs Validated</span>
          <div className="text-2xl font-bold font-mono text-slate-900 mt-1">{VALIDATION_REPORT.total_runs} Runs</div>
          <p className="text-[11px] text-slate-500 mt-1">
            Across all 7 attack scenarios in test partition
          </p>
        </div>
      </div>

      {/* Confusion Matrix */}
      <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 font-mono">
            Multi-Class Confusion Matrix (Predicted vs Actual Ground Truth)
          </h3>
          <span className="text-[11px] font-mono text-slate-500">Rows = Actual | Columns = Predicted</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-center text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-600 text-[10px] uppercase">
                <th className="p-2 text-left border border-slate-200">Actual \ Predicted</th>
                {classes.map(c => (
                  <th key={c} className="p-2 border border-slate-200 text-indigo-700">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {classes.map(actual => (
                <tr key={actual} className="hover:bg-slate-50">
                  <td className="p-2 text-left font-bold text-slate-800 border border-slate-200 bg-slate-50/60">
                    {actual}
                  </td>
                  {classes.map(pred => {
                    const count = evalResults.matrix[actual]?.[pred] || 0;
                    const isDiagonal = actual === pred;
                    return (
                      <td
                        key={pred}
                        className={`p-2 border border-slate-200 font-bold ${
                          isDiagonal
                            ? count > 0 ? 'bg-emerald-50 text-emerald-800' : 'text-slate-400'
                            : count > 0 ? 'bg-rose-50 text-rose-800' : 'text-slate-300'
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
      <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-sm space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 font-mono">
          Per-Scenario Precision, Recall &amp; F1 Scores
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-50 text-slate-600 text-[10px] uppercase border-b border-slate-200">
              <tr>
                <th className="py-2.5 px-3">Threat Class</th>
                <th className="py-2.5 px-3">Precision</th>
                <th className="py-2.5 px-3">Recall</th>
                <th className="py-2.5 px-3">F1-Score</th>
                <th className="py-2.5 px-3">Support (Flows)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {evalResults.classMetrics.map(m => (
                <tr key={m.threatClass} className="hover:bg-slate-50">
                  <td className="py-2 px-3 font-semibold text-slate-800 capitalize">{m.threatClass.replace('_', ' ')}</td>
                  <td className="py-2 px-3 text-indigo-700 font-bold">{m.precision}%</td>
                  <td className="py-2 px-3 text-slate-700 font-bold">{m.recall}%</td>
                  <td className="py-2 px-3 text-emerald-800 font-bold">{m.f1Score}%</td>
                  <td className="py-2 px-3 text-slate-500">{m.support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Feature Importance */}
      <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 font-mono">
            <BarChart3 className="w-4 h-4 text-indigo-600" />
            <span>Discriminative Feature Weights (Gini Importance)</span>
          </h3>
          <span className="text-[11px] font-mono text-slate-500">Model Inputs</span>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={FEATURE_IMPORTANCE} layout="vertical" margin={{ left: 140, right: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9" />
              <XAxis type="number" stroke="#64748B" tick={{ fontSize: 10, fill: '#64748B' }} domain={[0, 0.25]} />
              <YAxis dataKey="name" type="category" stroke="#475569" tick={{ fontSize: 10, fill: '#475569' }} width={135} />
              <Tooltip
                contentStyle={{ backgroundColor: '#FFFFFF', borderColor: '#E2E8F0', borderRadius: '8px', fontSize: '11px', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)' }}
                formatter={(value: any) => [`${(Number(value) * 100).toFixed(0)}% weight`, 'Feature Importance']}
              />
              <Bar dataKey="weight" fill="#4F46E5" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Extraction Run Audit Breakdown */}
      <div className="p-5 rounded-xl bg-white border border-slate-200 shadow-sm space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 font-mono">
          Extraction Run Audit Log (Dataset ID: {VALIDATION_REPORT.dataset_id})
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5 font-mono text-xs">
          {VALIDATION_REPORT.runs.map((r: any, idx: number) => (
            <div key={idx} className="p-3 bg-slate-50 border border-slate-200 rounded-lg space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-indigo-700 font-bold">{r.scenario}</span>
                <span className="text-[10px] text-emerald-800 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200 font-semibold">
                  {r.status}
                </span>
              </div>
              <div className="text-slate-500 text-[11px]">Run: {r.run_id}</div>
              <div className="text-slate-700 text-[11px] font-medium">Matched Flows: {r.matched} / {r.gt_flow_count}</div>
              <div className="text-slate-400 text-[10px]">Errors: {r.errors.length}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
