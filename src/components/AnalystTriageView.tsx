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
  Search,
  Code
} from 'lucide-react';
import { FlowRecord, STIXAlert, StructuredThreatAlert, AnalystDisposition, AnalystReview, RetrainingAuditCycle } from '../types';
import { classifyFlow, generateSTIXAlert, generateStructuredAlert } from '../lib/detector';
import { INITIAL_ANALYST_REVIEWS, RETRAINING_AUDIT_CYCLES } from '../data/notebookModelData';

interface AnalystTriageViewProps {
  flows: FlowRecord[];
}

export const AnalystTriageView: React.FC<AnalystTriageViewProps> = ({ flows }) => {
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(flows.find(f => f.label !== 'benign') || flows[0]);
  const [copiedStix, setCopiedStix] = useState(false);
  const [copiedCleanJson, setCopiedCleanJson] = useState(false);
  const [activeJsonFormat, setActiveJsonFormat] = useState<'structured' | 'stix'>('structured');
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
  const currentStructuredAlert: StructuredThreatAlert | null = (selectedFlow && currentDetection)
    ? generateStructuredAlert(selectedFlow, currentDetection)
    : null;

  const copyStixToClipboard = () => {
    if (!currentStixAlert) return;
    navigator.clipboard.writeText(JSON.stringify(currentStixAlert, null, 2));
    setCopiedStix(true);
    setTimeout(() => setCopiedStix(false), 2000);
  };

  const copyCleanJsonToClipboard = () => {
    if (!currentStructuredAlert) return;
    navigator.clipboard.writeText(JSON.stringify(currentStructuredAlert, null, 2));
    setCopiedCleanJson(true);
    setTimeout(() => setCopiedCleanJson(false), 2000);
  };

  const downloadJsonFile = () => {
    const data = activeJsonFormat === 'structured' ? currentStructuredAlert : currentStixAlert;
    if (!data) return;
    const filename = activeJsonFormat === 'structured' 
      ? `alert_${selectedFlow?.flow_id || 'threat'}.json` 
      : `${currentStixAlert?.id}.stix.json`;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
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
      {/* Top Banner: Analyst Operations & Enterprise Security */}
      <div className="bg-white border border-slate-200 shadow-sm rounded-xl p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200 flex items-center gap-1.5">
                <Code className="w-3.5 h-3.5" />
                <span>STRUCTURED ALERT SCHEMA &amp; STIX 2.1</span>
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-1">
                <Lock className="w-3 h-3" />
                <span>Poisoning-Resistant Safe Learning Loop</span>
              </span>
            </div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">
              SOC Analyst Triage &amp; Explainable Evidence Console
            </h2>
            <p className="text-xs text-slate-600 mt-1 max-w-3xl leading-relaxed">
              Inspect unidirectional threats, review transparent evidence, generate standardized JSON feeds (SIEM &amp; STIX 2.1), 
              and govern model retraining through an immutable 5-stage golden-set verification gate.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3 py-2 bg-slate-50 rounded-lg border border-slate-200 text-xs font-mono">
              <span className="text-slate-500">Total Audited: </span>
              <span className="text-emerald-800 font-bold">{reviews.length} alerts</span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Left Column (Threat Queue) & Right Column (JSON / Triage Form) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Alerts Queue (5 cols) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-white border border-slate-200 shadow-sm rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-600" />
                <span>Detected Threat Queue</span>
              </h3>
              
              {/* Scenario Filter */}
              <select
                value={filterClass}
                onChange={(e) => setFilterClass(e.target.value)}
                className="bg-white border border-slate-200 rounded px-2.5 py-1 text-xs text-slate-700 focus:outline-none focus:ring-1 focus:ring-indigo-500"
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
            <div className="space-y-2 max-h-[540px] overflow-y-auto pr-1">
              {threatFlows.slice(0, 35).map((flow) => {
                const isSelected = selectedFlow?.flow_id === flow.flow_id;
                const det = classifyFlow(flow);

                return (
                  <div
                    key={flow.flow_id}
                    onClick={() => setSelectedFlow(flow)}
                    className={`p-3 rounded-lg border transition-all cursor-pointer text-xs ${
                      isSelected
                        ? 'bg-indigo-50/50 border-indigo-500 shadow-xs'
                        : 'bg-white border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-slate-800 font-semibold truncate max-w-[170px]">
                        {flow.flow_id}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                        det.severity === 'CRITICAL' ? 'bg-rose-50 text-rose-800 border border-rose-200' :
                        det.severity === 'HIGH' ? 'bg-amber-50 text-amber-800 border border-amber-200' :
                        det.severity === 'MEDIUM' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                        'bg-slate-100 text-slate-700'
                      }`}>
                        {det.predictedLabel.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-600 font-mono">
                      <span>{flow.src_ip} &rarr; {flow.dst_ip}:{flow.dst_port}</span>
                      <span className="text-indigo-700 font-semibold">{det.confidence}% Conf</span>
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[10px] pt-1.5 border-t border-slate-100">
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200">
                        {det.specialist_detector}
                      </span>
                      <span className="text-slate-500 font-mono">
                        {flow.packets_per_second.toFixed(1)} pps
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right: Alert Formats Viewer & Analyst Disposition (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {selectedFlow && currentDetection ? (
            <>
              {/* Alert Inspector & Explainability */}
              <div className="bg-white border border-slate-200 shadow-sm rounded-xl p-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-indigo-700 font-semibold">{selectedFlow.flow_id}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        currentDetection.severity === 'CRITICAL' ? 'bg-rose-50 text-rose-800 border border-rose-200' :
                        currentDetection.severity === 'HIGH' ? 'bg-amber-50 text-amber-800 border border-amber-200' :
                        'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}>
                        {currentDetection.severity}
                      </span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-900 mt-1">
                      {currentStructuredAlert?.threat_type || currentStixAlert?.name}
                    </h3>
                  </div>

                  {/* Format toggle & action buttons */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <div className="flex rounded-lg border border-slate-200 p-0.5 bg-slate-100 text-xs font-mono">
                      <button
                        onClick={() => setActiveJsonFormat('structured')}
                        className={`px-2 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                          activeJsonFormat === 'structured'
                            ? 'bg-white text-slate-900 shadow-xs'
                            : 'text-slate-500 hover:text-slate-900'
                        }`}
                      >
                        Structured Alert JSON
                      </button>
                      <button
                        onClick={() => setActiveJsonFormat('stix')}
                        className={`px-2 py-1 rounded-md font-semibold transition-all cursor-pointer ${
                          activeJsonFormat === 'stix'
                            ? 'bg-white text-slate-900 shadow-xs'
                            : 'text-slate-500 hover:text-slate-900'
                        }`}
                      >
                        STIX 2.1
                      </button>
                    </div>

                    {activeJsonFormat === 'structured' ? (
                      <button
                        onClick={copyCleanJsonToClipboard}
                        className="px-2.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
                      >
                        {copiedCleanJson ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedCleanJson ? 'Copied' : 'Copy'}</span>
                      </button>
                    ) : (
                      <button
                        onClick={copyStixToClipboard}
                        className="px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold rounded flex items-center gap-1.5 transition-all cursor-pointer shadow-xs"
                      >
                        {copiedStix ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                        <span>{copiedStix ? 'Copied' : 'Copy'}</span>
                      </button>
                    )}

                    <button
                      onClick={downloadJsonFile}
                      className="px-2.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 text-xs font-semibold rounded flex items-center gap-1.5 transition-all cursor-pointer"
                      title="Download JSON file"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                {/* Evidence & Root Cause */}
                <div className="bg-slate-50 rounded-lg p-3.5 border border-slate-200 space-y-2.5 text-xs mb-4">
                  <div className="text-slate-700 font-semibold uppercase text-[11px] tracking-wider font-mono">
                    Transparent Evidence &amp; Heuristic Drivers (Specialist: {currentDetection.specialist_detector})
                  </div>

                  <div className="space-y-1.5">
                    {currentDetection.triggeredRules.map((rule, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-slate-700">
                        <span className="text-indigo-600 font-bold shrink-0">&bull;</span>
                        <span>{rule}</span>
                      </div>
                    ))}
                  </div>

                  {currentDetection.ja3_fingerprint && (
                    <div className="p-2 bg-white rounded border border-slate-200 font-mono text-[11px] text-slate-700">
                      JA3 / TLS Client Hello Hash: <span className="text-indigo-700 font-semibold">{currentDetection.ja3_fingerprint}</span> (Passive Metrology)
                    </div>
                  )}
                </div>

                {/* Live JSON Payload Viewer */}
                <div className="bg-slate-900 rounded-lg p-3 border border-slate-800 font-mono text-xs text-slate-200 mb-4 overflow-x-auto">
                  <div className="text-[11px] text-slate-400 uppercase font-semibold font-sans mb-1">
                    {activeJsonFormat === 'structured' ? 'SIEM-Ready Structured Threat Alert JSON:' : 'OASIS STIX 2.1 Bundle:'}
                  </div>
                  <pre className="text-[11px] leading-relaxed max-h-48 overflow-y-auto">
                    {JSON.stringify(activeJsonFormat === 'structured' ? currentStructuredAlert : currentStixAlert, null, 2)}
                  </pre>
                </div>

                {/* Triage Action Form */}
                <form onSubmit={submitReview} className="pt-4 border-t border-slate-200 space-y-4">
                  <div className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                    <UserCheck className="w-4 h-4 text-emerald-700" />
                    <span>Analyst Triage &amp; Disposition</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-slate-600 block mb-1">Assigned Analyst</label>
                      <input
                        type="text"
                        value={analystName}
                        onChange={(e) => setAnalystName(e.target.value)}
                        className="w-full bg-white border border-slate-200 rounded px-3 py-2 text-xs text-slate-900 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                        required
                      />
                    </div>
                    <div>
                      <label className="text-xs text-slate-600 block mb-1">Triage Decision</label>
                      <select
                        value={disposition}
                        onChange={(e) => setDisposition(e.target.value as AnalystDisposition)}
                        className="w-full bg-white border border-slate-200 rounded px-3 py-2 text-xs text-slate-900 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                      >
                        <option value="CONFIRMED_THREAT">Confirmed Threat (Queue for Safe Learning)</option>
                        <option value="FALSE_POSITIVE">Mark False Positive (Peer Consensus Req)</option>
                        <option value="ESCALATED_INCIDENT">Escalate to Tier 3 CIRT Incident</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-xs text-slate-600 block mb-1">Analyst Justification &amp; Evidence Notes</label>
                    <textarea
                      rows={2}
                      value={analystNotes}
                      onChange={(e) => setAnalystNotes(e.target.value)}
                      placeholder="Specify rationale (e.g., volumetric burst matched DDoS profile, verified lack of internal ACKs)..."
                      className="w-full bg-white border border-slate-200 rounded px-3 py-2 text-xs text-slate-900 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded-lg flex items-center justify-center gap-2 shadow-xs transition-all cursor-pointer"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>Submit Triage &amp; Trigger Safe Learning Verification</span>
                  </button>
                </form>
              </div>

              {/* Safe Learning Gate Simulator & Historical Cycles */}
              <div className="bg-white border border-slate-200 shadow-sm rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                    <Lock className="w-4 h-4 text-indigo-600" />
                    <span>5-Stage Poisoning-Resistant Safe Learning Pipeline</span>
                  </h3>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold">
                    ANTI-DATA POISONING ACTIVE
                  </span>
                </div>

                {/* 5 Stages Diagram */}
                <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-center text-xs">
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
                    <div className="text-[10px] text-slate-500 font-mono">STAGE 1</div>
                    <div className="font-semibold text-slate-900 mt-1">Multi-Analyst</div>
                    <div className="text-[11px] text-emerald-700 font-medium mt-0.5">&gt;80% Consensus</div>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
                    <div className="text-[10px] text-slate-500 font-mono">STAGE 2</div>
                    <div className="font-semibold text-slate-900 mt-1">Outlier Rejection</div>
                    <div className="text-[11px] text-indigo-700 font-medium mt-0.5">Isolation Forest</div>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
                    <div className="text-[10px] text-slate-500 font-mono">STAGE 3</div>
                    <div className="font-semibold text-slate-900 mt-1">Batch Retrain</div>
                    <div className="text-[11px] text-indigo-700 font-medium mt-0.5">No Live Streaming</div>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
                    <div className="text-[10px] text-slate-500 font-mono">STAGE 4</div>
                    <div className="font-semibold text-slate-900 mt-1">Golden Set Gate</div>
                    <div className="text-[11px] text-amber-800 font-medium mt-0.5">Drift &lt; 0.1%</div>
                  </div>
                  <div className="bg-slate-50 p-2.5 rounded border border-slate-200">
                    <div className="text-[10px] text-slate-500 font-mono">STAGE 5</div>
                    <div className="font-semibold text-slate-900 mt-1">Lead Sign-Off</div>
                    <div className="text-[11px] text-slate-800 font-medium mt-0.5">Human Authority</div>
                  </div>
                </div>

                {pendingApproval && (
                  <div className="p-4 rounded-lg bg-indigo-50 border border-indigo-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                    <div>
                      <div className="font-semibold text-slate-900">Retraining Batch Ready for Production Gate:</div>
                      <div className="text-slate-600 text-xs mt-0.5">
                        Shadow model evaluated against Immutable Golden Test Set (0.01% drift). Awaiting Lead Officer sign-off.
                      </div>
                    </div>
                    <button
                      onClick={approvePendingCycle}
                      className="px-3.5 py-1.5 bg-emerald-800 hover:bg-emerald-900 text-white font-semibold rounded text-xs transition-all cursor-pointer self-start sm:self-auto shadow-xs"
                    >
                      Approve &amp; Deploy Shadow Model
                    </button>
                  </div>
                )}

                {/* Audit History */}
                <div className="pt-2">
                  <div className="text-xs font-semibold text-slate-700 mb-2 font-mono uppercase tracking-wider">Verified Retraining Cycles (Audit Log):</div>
                  <div className="space-y-2">
                    {auditCycles.map((cycle) => (
                      <div key={cycle.cycle_id} className="p-3 bg-slate-50 rounded border border-slate-200 flex flex-wrap items-center justify-between gap-3 text-xs">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-indigo-700 font-bold">{cycle.cycle_id}</span>
                            <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-800 text-[10px] font-semibold border border-emerald-200">
                              {cycle.human_signoff_status}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-500 mt-0.5">
                            Signed off by: <strong className="text-slate-700">{cycle.signoff_officer}</strong> • {cycle.timestamp}
                          </div>
                        </div>

                        <div className="flex items-center gap-4 text-right font-mono text-[11px]">
                          <div>
                            <div className="text-slate-500">Golden Set Acc</div>
                            <div className="text-emerald-800 font-bold">{cycle.golden_set_accuracy}%</div>
                          </div>
                          <div>
                            <div className="text-slate-500">Shadow F1</div>
                            <div className="text-indigo-700 font-bold">{cycle.shadow_f1_score}</div>
                          </div>
                          <div>
                            <div className="text-slate-500">Drift</div>
                            <div className="text-amber-800 font-bold">{cycle.golden_set_drift}%</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-slate-500 bg-white border border-slate-200 rounded-xl">
              <FileText className="w-8 h-8 mx-auto mb-2 text-slate-400" />
              <span>Select an alert from the queue to view its structured payload and perform triage.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
