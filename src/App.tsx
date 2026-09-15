import React, { useState } from 'react';
import { Header } from './components/Header';
import { StatCards } from './components/StatCards';
import { TelemetryView } from './components/TelemetryView';
import { FlowsTable } from './components/FlowsTable';
import { HostWindowView } from './components/HostWindowView';
import { ScenariosGuide } from './components/ScenariosGuide';
import { ModelEvaluationView } from './components/ModelEvaluationView';
import { NotebookLabView } from './components/NotebookLabView';
import { AnalystTriageView } from './components/AnalystTriageView';
import { SIHPresentationDeck } from './components/SIHPresentationDeck';
import { PCAPReplayLabView } from './components/PCAPReplayLabView';
import { FlowDetailModal } from './components/FlowDetailModal';
import { AttackSimulatorModal } from './components/AttackSimulatorModal';

import { CANONICAL_FLOWS } from './data/canonicalFlows';
import { HOST_WINDOWS } from './data/hostWindows';
import { FlowRecord, ThreatLabel } from './types';

export function App() {
  const [activeTab, setActiveTab] = useState<string>('telemetry');
  const [flows, setFlows] = useState<FlowRecord[]>(CANONICAL_FLOWS);
  const [selectedFlow, setSelectedFlow] = useState<FlowRecord | null>(null);
  const [isSimulatorOpen, setIsSimulatorOpen] = useState<boolean>(false);
  const [simulatorScenario, setSimulatorScenario] = useState<ThreatLabel>('ddos');
  const [selectedScenarioFilter, setSelectedScenarioFilter] = useState<string>('ALL');

  const threatCount = flows.filter(f => f.label !== 'benign').length;

  const handleOpenSimulatorWithScenario = (sc: ThreatLabel) => {
    setSimulatorScenario(sc);
    setIsSimulatorOpen(true);
  };

  const handleInjectFlow = (newFlow: FlowRecord) => {
    setFlows(prev => [newFlow, ...prev]);
  };

  const handleScenarioFilterSelect = (scenario: string) => {
    setSelectedScenarioFilter(scenario);
    if (activeTab !== 'flows') {
      setActiveTab('flows');
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col selection:bg-sky-500/30 selection:text-sky-200">
      {/* Top Header & Navigation */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenSimulator={() => setIsSimulatorOpen(true)}
        threatCount={threatCount}
        totalFlows={flows.length}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* KPI Stat Cards (always available on top for instant operational awareness) */}
        <StatCards
          flows={flows}
          onSelectScenarioFilter={handleScenarioFilterSelect}
          selectedScenario={selectedScenarioFilter}
        />

        {/* Tab Views */}
        {activeTab === 'telemetry' && (
          <TelemetryView
            flows={flows}
            onSelectFlow={setSelectedFlow}
            onOpenSimulator={() => setIsSimulatorOpen(true)}
          />
        )}

        {activeTab === 'pcap_lab' && (
          <PCAPReplayLabView />
        )}

        {activeTab === 'notebook' && (
          <NotebookLabView />
        )}

        {activeTab === 'triage' && (
          <AnalystTriageView flows={flows} />
        )}

        {activeTab === 'sih_pitch' && (
          <SIHPresentationDeck />
        )}

        {activeTab === 'flows' && (
          <FlowsTable
            flows={flows}
            onSelectFlow={setSelectedFlow}
            selectedScenarioFilter={selectedScenarioFilter}
          />
        )}

        {activeTab === 'hosts' && (
          <HostWindowView hostWindows={HOST_WINDOWS} />
        )}

        {activeTab === 'scenarios' && (
          <ScenariosGuide onSimulateScenario={handleOpenSimulatorWithScenario} />
        )}

        {activeTab === 'model' && (
          <ModelEvaluationView flows={flows} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>
            UniSentry: AI-Based Cyber Threat Detection in Unidirectional IP Traffic • Smart India Hackathon 2026 (NTRO 26145)
          </span>
          <span className="text-slate-400">
            Team SNATCH01 • Multi-Specialist AI (Flow RF + DNS RF + JA3) • OASIS STIX 2.1 • Safe Learning Loop
          </span>
        </div>
      </footer>

      {/* Modals */}
      <FlowDetailModal
        flow={selectedFlow}
        onClose={() => setSelectedFlow(null)}
      />

      <AttackSimulatorModal
        isOpen={isSimulatorOpen}
        onClose={() => setIsSimulatorOpen(false)}
        onInjectFlow={handleInjectFlow}
        defaultScenario={simulatorScenario}
      />
    </div>
  );
}

export default App;
