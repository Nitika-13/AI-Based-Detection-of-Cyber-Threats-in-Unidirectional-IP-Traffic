import React, { useState } from 'react';
import { X, Zap, ShieldAlert, Cpu, ArrowRight, CheckCircle2 } from 'lucide-react';
import { ThreatLabel, FlowRecord } from '../types';
import { SCENARIOS } from '../lib/scenarios';
import { generateSyntheticFlow, SimulationParams } from '../lib/trafficSimulator';
import { classifyFlow } from '../lib/detector';

interface AttackSimulatorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInjectFlow: (flow: FlowRecord) => void;
  defaultScenario?: ThreatLabel;
}

export const AttackSimulatorModal: React.FC<AttackSimulatorModalProps> = ({
  isOpen,
  onClose,
  onInjectFlow,
  defaultScenario = 'ddos'
}) => {
  const [scenario, setScenario] = useState<ThreatLabel>(defaultScenario);
  const [sourceIp, setSourceIp] = useState('10.0.0.88');
  const [targetIp, setTargetIp] = useState('10.0.1.160');
  const [targetPort, setTargetPort] = useState(80);
  const [packetCount, setPacketCount] = useState(25);
  const [duration, setDuration] = useState(4.5);
  const [seed, setSeed] = useState(42);

  const [simulatedFlow, setSimulatedFlow] = useState<FlowRecord | null>(null);
  const [injectedSuccess, setInjectedSuccess] = useState(false);

  if (!isOpen) return null;

  const handleScenarioChange = (sc: ThreatLabel) => {
    setScenario(sc);
    setInjectedSuccess(false);
    setSimulatedFlow(null);

    // Contextual port & packet defaults
    switch (sc) {
      case 'ddos':
        setTargetPort(80);
        setPacketCount(120);
        setDuration(0.8);
        break;
      case 'c2_beacon':
        setTargetPort(443);
        setPacketCount(15);
        setDuration(12.0);
        break;
      case 'dns_anomaly':
        setTargetPort(53);
        setPacketCount(30);
        setDuration(2.5);
        break;
      case 'port_scan':
        setTargetPort(22);
        setPacketCount(2);
        setDuration(0.05);
        break;
      case 'exfiltration':
        setTargetPort(443);
        setPacketCount(80);
        setDuration(6.0);
        break;
      case 'encrypted_anomaly':
        setTargetPort(443);
        setPacketCount(45);
        setDuration(3.2);
        break;
      case 'benign':
        setTargetPort(80);
        setPacketCount(10);
        setDuration(2.0);
        break;
    }
  };

  const handleRunSimulation = () => {
    const params: SimulationParams = {
      scenario,
      sourceIp,
      targetIp,
      targetPort,
      packetCount,
      duration,
      seed
    };

    const flow = generateSyntheticFlow(params);
    setSimulatedFlow(flow);
    setInjectedSuccess(false);
  };

  const handleInject = () => {
    if (!simulatedFlow) return;
    onInjectFlow(simulatedFlow);
    setInjectedSuccess(true);
    setTimeout(() => {
      onClose();
    }, 1200);
  };

  const currentDef = SCENARIOS[scenario];
  const detection = simulatedFlow ? classifyFlow(simulatedFlow) : null;

  return (
    <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="p-2 rounded-lg bg-rose-950 text-rose-400 border border-rose-800">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Block 1 Traffic Generator & Live Injector</h3>
              <p className="text-xs text-slate-400">
                Synthesize unidirectional IP packets and extract canonical NetFlow features
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 sm:p-6 overflow-y-auto space-y-5 text-xs text-slate-300">
          {/* Scenario Select Buttons */}
          <div>
            <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-2 font-mono">
              Select Attack Vector or Scenario:
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {(Object.keys(SCENARIOS) as ThreatLabel[]).map(sc => (
                <button
                  key={sc}
                  onClick={() => handleScenarioChange(sc)}
                  className={`p-2.5 rounded-lg text-left border font-mono text-xs transition-all cursor-pointer ${
                    scenario === sc
                      ? 'bg-sky-950 border-sky-500 text-white font-bold shadow-sm'
                      : 'bg-slate-950/70 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <div className="font-semibold capitalize text-sky-400">{sc.replace('_', ' ')}</div>
                  <div className="text-[10px] text-slate-500 truncate mt-0.5">{SCENARIOS[sc].category}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Scenario Description snippet */}
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            <span className="text-sky-400 font-semibold">{currentDef.name}:</span>{' '}
            <span className="text-slate-300">{currentDef.description}</span>
          </div>

          {/* Parameter Inputs */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Source IP (Monitored Subnet)</label>
              <input
                type="text"
                value={sourceIp}
                onChange={e => setSourceIp(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200"
              />
            </div>
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Target Destination IP</label>
              <input
                type="text"
                value={targetIp}
                onChange={e => setTargetIp(e.target.value)}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200"
              />
            </div>
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Target Destination Port</label>
              <input
                type="number"
                value={targetPort}
                onChange={e => setTargetPort(Number(e.target.value))}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200"
              />
            </div>
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Packet Count</label>
              <input
                type="number"
                value={packetCount}
                onChange={e => setPacketCount(Number(e.target.value))}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200"
              />
            </div>
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">Duration (Seconds)</label>
              <input
                type="number"
                step="0.1"
                value={duration}
                onChange={e => setDuration(Number(e.target.value))}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200"
              />
            </div>
            <div>
              <label className="text-[10px] text-slate-400 block mb-1">RNG Seed (Determinism)</label>
              <input
                type="number"
                value={seed}
                onChange={e => setSeed(Number(e.target.value))}
                className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-slate-200"
              />
            </div>
          </div>

          {/* Action to run generation */}
          <div className="flex justify-end">
            <button
              onClick={handleRunSimulation}
              className="px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs flex items-center space-x-2 transition-all cursor-pointer shadow-md shadow-sky-950"
            >
              <Zap className="w-4 h-4" />
              <span>Generate Flow & Extract Features</span>
            </button>
          </div>

          {/* Result Inspection */}
          {simulatedFlow && detection && (
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 animate-in fade-in">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <span className="text-xs font-bold text-white uppercase font-mono">
                    Reconstructed Flow ID: {simulatedFlow.flow_id}
                  </span>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                    {simulatedFlow.flow_key}
                  </div>
                </div>

                <div className="flex items-center space-x-2 font-mono">
                  <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 text-xs font-bold uppercase">
                    AI Predicted: {detection.predictedLabel} ({detection.confidence}%)
                  </span>
                </div>
              </div>

              {/* Quick feature overview */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px] bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                <div><span className="text-slate-500">Packets:</span> <span className="text-white">{simulatedFlow.packet_count}</span></div>
                <div><span className="text-slate-500">Bytes:</span> <span className="text-white">{simulatedFlow.byte_count.toLocaleString()}</span></div>
                <div><span className="text-slate-500">Rate:</span> <span className="text-sky-300">{simulatedFlow.packets_per_second.toFixed(1)} pps</span></div>
                <div><span className="text-slate-500">IAT CV:</span> <span className="text-amber-400">{simulatedFlow.iat_cv?.toFixed(3)}</span></div>
                <div><span className="text-slate-500">SYN Ratio:</span> <span className="text-white">{(simulatedFlow.tcp_syn_ratio * 100).toFixed(0)}%</span></div>
                <div><span className="text-slate-500">Payload %:</span> <span className="text-white">{(simulatedFlow.payload_ratio * 100).toFixed(0)}%</span></div>
                <div><span className="text-slate-500">DNS Entropy:</span> <span className="text-purple-400">{simulatedFlow.dns_qname_entropy_mean?.toFixed(2)}</span></div>
                <div><span className="text-slate-500">TLS Entropy:</span> <span className="text-cyan-400">{(simulatedFlow.tls_payload_entropy_mean || simulatedFlow.payload_entropy_mean)?.toFixed(2)}</span></div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-xs text-slate-400">
                  Ready to stream into the passive monitoring console.
                </span>

                <button
                  onClick={handleInject}
                  disabled={injectedSuccess}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold font-mono flex items-center space-x-1.5 transition-all cursor-pointer ${
                    injectedSuccess
                      ? 'bg-emerald-600 text-white'
                      : 'bg-gradient-to-r from-rose-600 to-amber-600 hover:from-rose-500 hover:to-amber-500 text-white shadow-md'
                  }`}
                >
                  {injectedSuccess ? (
                    <>
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Injected Successfully!</span>
                    </>
                  ) : (
                    <>
                      <ArrowRight className="w-4 h-4" />
                      <span>Inject into Live Flow Monitor</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
