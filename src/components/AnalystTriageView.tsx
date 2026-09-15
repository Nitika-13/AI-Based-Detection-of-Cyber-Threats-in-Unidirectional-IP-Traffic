import React, { useState } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  FileText, 
  Copy, 
  Check, 
  Download, 
  UserCheck, 
  Clock, 
  Lock, 
  CheckCircle2, 
  XCircle, 
  AlertOctagon, 
  ArrowRight,
  Send,
  Eye,
  Search
} from 'lucide-react';
import { FlowRecord, STIXAlert, AnalystDisposition, AnalystReview, RetrainingAuditCycle } from '../types';
import { classifyFlow, generateSTIXAlert } from '../lib/detector';
import { INITIAL_ANALYST_REVIEWS, RETRAINING_AUDIT_CYCLES } from '../data/notebookModelData';

interface AnalystTriageViewProps {
  flows: FlowRecord[];
}

export const AnalystTriageView: React.FC<AnalystTriageViewProps> = ({ flows }) => {
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(flows.find(f => f.label !== 'benign') || flows[0]);
  const [copiedStix, setCopiedStix] = useState(false);
  const [analystName, setAnalystName] = useState('Officer R. V. Patel (SOC Tier 2)');
  const [analystNotes, setAnalystNotes] = useState('');
  const [disposition, setDisposition] = useState<AnalystDisposition>('CONFIRMED_THREAT');
  const [reviews, setReviews] = useState<AnalystReview[]>(INITIAL_ANALYST_REVIEWS);
  const [filterClass, setFilterClass] = useState<string>('all');
  const [auditCycles, setAuditCycles] = useState<RetrainingAuditCycle[]>(RETRAINING_AUDIT_CYCLES);
  const [pendingApproval, setPendingApproval] = useState(false);

  // Filter threats for triage
  const threatFlows = flows.filter(f => {
    if (filterClass === 'all') return true;
    return f.label === filterClass;
  });

  const currentDetection = selectedFlow ? classifyFlow(selectedFlow) : null;
  const currentStixAlert: STIXAlert | null = (selectedFlow && currentDetection) 
    ? generateSTIXAlert(selectedFlow, currentDetection) 
    : null;

  const copyStixToClipboard = () => {
    if (!currentStixAlert) return;
    navigator.clipboard.writeText(JSON.stringify(currentStixAlert, null, 2));
    setCopiedStix(true);
    setTimeout(() => setCopiedStix(false), 2000);
  };

  const downloadStixFile = () => {
    if (!currentStixAlert) return;
    const blob = new Blob([JSON.stringify(currentStixAlert, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentStixAlert.id}.stix.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const submitReview = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFlow || !currentDetection) return;

    const newReview: AnalystReview = {
      id: `AR-2026-${(reviews.length + 896).toString()}`,
      flow_id: selectedFlow.flow_id,
      threat_label: currentDetection.predictedLabel,
      analyst_name: analystName,
      disposition,
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      notes: analystNotes || `Triage completed for ${currentDetection.predictedLabel}. Evidence verified against baseline.`,
      consensus_score: 95.0,
      eligible_for_retraining: disposition === 'CONFIRMED_THREAT' || disposition === 'FALSE_POSITIVE'
    };

    setReviews([newReview, ...reviews]);
    setAnalystNotes('');
    setPendingApproval(true);
  };

  const approvePendingCycle = () => {
    const newCycle: RetrainingAuditCycle = {
      cycle_id: `CYCLE-2026-W38`,
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      feedback_samples_total: reviews.length,
      consensus_passed: Math.round(reviews.length * 0.95),
      outliers_rejected: Math.max(1, Math.round(reviews.length * 0.05)),
      clean_test_accuracy: 99.8,
      golden_set_accuracy: 99.6,
      golden_set_drift: 0.01,
      shadow_f1_score: 0.95,
      active_f1_score: 0.93,
      human_signoff_status: 'APPROVED',
      signoff_officer: analystName
    };

    setAuditCycles([newCycle, ...auditCycles]);
    setPendingApproval(false);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner: Analyst Operations & STIX 2.1 Standard */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-950 text-indigo-400 border border-indigo-800/50 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5" />
                <span>OASIS STIX 2.1 COMPLIANT ALERTS</span>
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-950 text-emerald-400 border border-emerald-800/50 flex items-center gap-1">
                <Lock className="w-3 h-3" />
                <span>Poisoning-Resistant Safe Learning Loop</span>
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              SOC Analyst Triage & Explainable Evidence Console
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Inspect unidirectional threats, review transparent Gini-weighted evidence, generate standardized STIX 2.1 JSON feeds, 
              and govern model retraining through an immutable 5-stage golden-set verification gate.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3 py-2 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono">
              <span className="text-slate-400">Total Audited: </span>
              <span className="text-emerald-400 font-bold">{reviews.length} alerts</span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Left Column (Threat Queue) & Right Column (STIX / Triage Form) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Alerts Queue (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <span>Detected Threat Queue</span>
              </h3>
              
              {/* Scenario Filter */}
              <select
                value={filterClass}
                onChange={(e) => setFilterClass(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-sky-500"
              >
                <option value="all">All Traffic ({flows.length})</option>
                <option value="ddos">DDoS Volumetric</option>
                <option value="c2_beacon">C2 Beacon (Periodic)</option>
                <option value="dns_anomaly">DNS Tunnel / DGA</option>
                <option value="port_scan">Port Scan</option>
                <option value="exfiltration">Exfiltration</option>
                <option value="encrypted_anomaly">Encrypted Anomaly</option>
                <option value="benign">Benign Flows</option>
              </select>
            </div>

            {/* List */}
            <div className="space-y-2 max-h-[540px] overflow-y-auto pr-1 scrollbar-thin">
              {threatFlows.slice(0, 35).map((flow) => {
                const isSelected = selectedFlow?.flow_id === flow.flow_id;
                const det = classifyFlow(flow);
                const isThreat = det.predictedLabel !== 'benign';

                return (
                  <div
                    key={flow.flow_id}
                    onClick={() => setSelectedFlow(flow)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer text-xs ${
                      isSelected
                        ? 'bg-slate-800 border-sky-500 shadow-md shadow-sky-950/50'
                        : 'bg-slate-950/60 border-slate-800/80 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-slate-300 font-semibold truncate max-w-[170px]">
                        {flow.flow_id}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                        det.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800/60' :
                        det.severity === 'HIGH' ? 'bg-amber-950 text-amber-400 border border-amber-800/60' :
                        det.severity === 'MEDIUM' ? 'bg-indigo-950 text-indigo-400 border border-indigo-800/60' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {det.predictedLabel.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                      <span>{flow.src_ip} &rarr; {flow.dst_ip}:{flow.dst_port}</span>
                      <span className="text-sky-400">{det.confidence}% Conf</span>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[10px] pt-1.5 border-t border-slate-800/60">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                        {det.specialist_detector}
                      </span>
                      <span className="text-slate-400 font-mono">
                        {flow.packets_per_second.toFixed(1)} pps
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right: STIX 2.1 Viewer & Analyst Disposition (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {selectedFlow && currentDetection && currentStixAlert ? (
            <>
              {/* Alert Inspector & Explainability */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-sky-400">{selectedFlow.flow_id}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        currentDetection.severity === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border border-rose-800' :
                        currentDetection.severity === 'HIGH' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                        'bg-slate-800 text-slate-300'
                      }`}>
                        {currentDetection.severity}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-white mt-1">
                      {currentStixAlert.name}
                    </h3>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={copyStixToClipboard}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      {copiedStix ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedStix ? 'Copied!' : 'Copy STIX'}</span>
                    </button>
                    <button
                      onClick={downloadStixFile}
                      className="px-3 py-1.5 bg-sky-950 hover:bg-sky-900 text-sky-300 border border-sky-700/60 text-xs font-semibold rounded flex items-center gap-1.5 transition-all cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download JSON</span>
                    </button>
                  </div>
                </div>

                {/* Evidence & Root Cause */}
                <div className="bg-slate-950 rounded-lg p-3.5 border border-slate-800 space-y-2.5 text-xs mb-4">
                  <div className="text-slate-400 font-semibold uppercase text-[11px] tracking-wider">
                    Transparent Evidence & Root Cause (Specialist: {currentDetection.specialist_detector})
                  </div>

                  <div className="space-y-1.5">
                    {currentDetection.triggeredRules.map((rule, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-slate-300">
                        <span className="text-rose-400 font-bold shrink-0">&bull;</span>
                        <span>{rule}</span>
                      </div>
                    ))}
                  </div>

                  {currentDetection.ja3_fingerprint && (
                    <div className="p-2 bg-indigo-950/40 rounded border border-indigo-800/40 font-mono text-[11px] text-indigo-300">
                      JA3 Client Hello Hash: <span className="text-white">{currentDetection.ja3_fingerprint}</span> (Unencrypted Passive Fingerprint)
                    </div>
                  )}
                </div>

                {/* STIX 2.1 Pattern Specification */}
                <div className="bg-slate-950 rounded-lg p-3 border border-slate-800 font-mono text-xs text-slate-400 mb-4 overflow-x-auto">
                  <div className="text-[11px] text-slate-400 uppercase font-semibold font-sans mb-1">
                    STIX 2.1 Indicator Pattern:
                  </div>
                  <code className="text-emerald-400 text-[11px]">{currentStixAlert.pattern}</code>
                </div>

                {/* Triage Action Form */}
                <form onSubmit={submitReview} className="pt-4 border-t border-slate-800 space-y-4">
                  <div className="text-sm font-semibold text-white flex items-center gap-2">
                    <UserCheck className="w-4 h-4 text-emerald-400" />
                    <span>Analyst Triage & Disposition</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-slate-400 block mb-1">Assigned Analyst</label>
                      <input
                        type="text"
                        value={analystName}
                        onChange={(e) => setAnalystName(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                        required
                      />
                    </div>
                    <div>
                      <label className="text-xs text-slate-400 block mb-1">Triage Decision</label>
                      <select
                        value={disposition}
                        onChange={(e) => setDisposition(e.target.value as AnalystDisposition)}
                        className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      >
                        <option value="CONFIRMED_THREAT">Confirmed Threat (Queue for Safe Learning)</option>
                        <option value="FALSE_POSITIVE">Mark False Positive (Peer Consensus Req)</option>
                        <option value="ESCALATED_INCIDENT">Escalate to Tier 3 CIRT Incident</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Analyst Justification & Evidence Notes</label>
                    <textarea
                      rows={2}
                      value={analystNotes}
                      onChange={(e) => setAnalystNotes(e.target.value)}
                      placeholder="Specify rationale (e.g., volumetric burst matched DDoS profile, verified lack of internal ACKs)..."
                      className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full py-2.5 bg-gradient-to-r from-emerald-600 to-sky-600 hover:from-emerald-500 hover:to-sky-500 text-white text-xs font-semibold rounded-lg flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/40 transition-all cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Submit Triage & Trigger Safe Learning Verification</span>
                  </button>
                </form>
              </div>

              {/* Safe Learning Gate Simulator & Historical Cycles */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                    <Lock className="w-4 h-4 text-sky-400" />
                    <span>5-Stage Poisoning-Resistant Safe Learning Pipeline</span>
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800">
                    ANTI-DATA POISONING ACTIVE
                  </span>
                </div>

                {/* 5 Stages Diagram */}
                <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-center text-xs">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">STAGE 1</div>
                    <div className="font-semibold text-white mt-1">Multi-Analyst</div>
                    <div className="text-[11px] text-emerald-400 mt-0.5">&gt;80% Consensus</div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">STAGE 2</div>
                    <div className="font-semibold text-white mt-1">Outlier Rejection</div>
                    <div className="text-[11px] text-sky-400 mt-0.5">Isolation Forest</div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">STAGE 3</div>
                    <div className="font-semibold text-white mt-1">Batch Retrain</div>
                    <div className="text-[11px] text-indigo-400 mt-0.5">No Live Streaming</div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">STAGE 4</div>
                    <div className="font-semibold text-white mt-1">Golden Set Gate</div>
                    <div className="text-[11px] text-amber-400 mt-0.5">Drift &lt; 0.1%</div>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono">STAGE 5</div>
                    <div className="font-semibold text-white mt-1">Lead Sign-Off</div>
                    <div className="text-[11px] text-purple-400 mt-0.5">Human Authority</div>
                  </div>
                </div>

                {pendingApproval && (
                  <div className="p-4 rounded-lg bg-indigo-950/60 border border-indigo-600/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div>
                      <div className="font-semibold text-white">Retraining Batch Ready for Production Gate:</div>
                      <div className="text-slate-300 text-xs mt-0.5">
                        Shadow model evaluated against Immutable Golden Test Set (0.01% drift). Awaiting Lead Officer sign-off.
                      </div>
                    </div>
                    <button
                      onClick={approvePendingCycle}
                      className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded text-xs transition-all cursor-pointer self-start sm:self-auto"
                    >
                      Approve &amp; Deploy Shadow Model
                    </button>
                  </div>
                )}

                {/* Audit History */}
                <div className="pt-2">
                  <div className="text-xs font-semibold text-slate-300 mb-2">Verified Retraining Cycles (Audit Log):</div>
                  <div className="space-y-2">
                    {auditCycles.map((cycle) => (
                      <div key={cycle.cycle_id} className="p-3 bg-slate-950 rounded border border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-sky-400 font-bold">{cycle.cycle_id}</span>
                            <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 text-[10px] font-semibold border border-emerald-800/50">
                              {cycle.human_signoff_status}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            Signed off by: <strong className="text-slate-300">{cycle.signoff_officer}</strong> • {cycle.timestamp}
                          </div>
                        </div>

                        <div className="flex items-center gap-4 text-right font-mono text-[11px]">
                          <div>
                            <div className="text-slate-400">Golden Set Acc</div>
                            <div className="text-emerald-400 font-bold">{cycle.golden_set_accuracy}%</div>
                          </div>
                          <div>
                            <div className="text-slate-400">Shadow F1</div>
                            <div className="text-sky-400 font-bold">{cycle.shadow_f1_score}</div>
                          </div>
                          <div>
                            <div className="text-slate-400">Drift</div>
                            <div className="text-amber-300 font-bold">{cycle.golden_set_drift}%</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-slate-400 bg-slate-900 border border-slate-800 rounded-xl">
              <FileText className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              <span>Select an alert from the queue to view its STIX 2.1 payload and perform triage.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
