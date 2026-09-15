import React, { useState } from 'react';
import { 
  Presentation, 
  ChevronLeft, 
  ChevronRight, 
  ShieldCheck, 
  Lock, 
  Cpu, 
  Layers, 
  AlertTriangle, 
  HelpCircle, 
  FileText, 
  Award,
  Zap,
  CheckCircle,
  BarChart4,
  Target,
  Terminal,
  ExternalLink,
  Radio,
  Share2,
  Database,
  Eye,
  RefreshCw,
  GitBranch,
  ArrowRight,
  Shield,
  Activity
} from 'lucide-react';
import { 
  SIH_METADATA, 
  PIPELINE_DETECTION_STEPS,
  PIPELINE_LEARNING_STEPS,
  TECHNOLOGIES_USED,
  FEASIBILITY_STRATEGIES,
  FEASIBILITY_CHAIN,
  IMPACT_BENEFITS_RADIAL,
  RESEARCH_TECH_TABLE,
  SOLUTION_GAP_ANALYSIS,
  INNOVATION_PILLARS,
  SIH_COMPARISON_TABLE,
  SIH_JURY_QA 
} from '../data/sihMasterDeckData';

export const SIHPresentationDeck: React.FC = () => {
  const [currentSlide, setCurrentSlide] = useState<number>(1);
  const [selectedPillar, setSelectedPillar] = useState<number>(1);
  const [activeTabSlide6, setActiveTabSlide6] = useState<'gaps' | 'pillars' | 'jury'>('gaps');
  const totalSlides = 6;

  const nextSlide = () => setCurrentSlide(prev => Math.min(totalSlides, prev + 1));
  const prevSlide = () => setCurrentSlide(prev => Math.max(1, prev - 1));

  return (
    <div className="space-y-6">
      {/* Slide Navigation Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-sky-950 border border-sky-700/50 flex items-center justify-center text-sky-400 shrink-0">
            <Presentation className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-sky-400">SMART INDIA HACKATHON 2026</span>
              <span className="text-slate-600">&bull;</span>
              <span className="text-xs font-mono text-amber-400 font-semibold">PS ID: 26145</span>
              <span className="text-slate-600">&bull;</span>
              <span className="text-xs text-slate-400">Team {SIH_METADATA.team_name}</span>
            </div>
            <h2 className="text-sm sm:text-base font-bold text-white">
              Slide {currentSlide} of {totalSlides}: {
                currentSlide === 1 ? 'Title Page & Problem Statement' :
                currentSlide === 2 ? 'Detection Pipeline & Continuous Safe Learning' :
                currentSlide === 3 ? 'Feasibility and Viability (V-I-A-B-L-E)' :
                currentSlide === 4 ? 'Impact and Benefits (8 Strategic Dimensions)' :
                currentSlide === 5 ? 'Research, References & Technology Selection' :
                'Proposed Solution & Gap Analysis'
              }
            </h2>
          </div>
        </div>

        {/* Slide Controls */}
        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={prevSlide}
            disabled={currentSlide === 1}
            className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
            title="Previous Slide"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>

          <div className="flex items-center gap-1 px-2">
            {[1, 2, 3, 4, 5, 6].map(num => (
              <button
                key={num}
                onClick={() => setCurrentSlide(num)}
                className={`w-7 h-7 rounded text-xs font-mono transition-all cursor-pointer ${
                  currentSlide === num 
                    ? 'bg-sky-600 text-white font-bold shadow-md shadow-sky-950' 
                    : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {num}
              </button>
            ))}
          </div>

          <button
            onClick={nextSlide}
            disabled={currentSlide === totalSlides}
            className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 hover:text-white hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed transition-all cursor-pointer"
            title="Next Slide"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Active Slide Canvas */}
      <div className="min-h-[620px] bg-slate-900 border border-slate-800 rounded-xl p-6 sm:p-8 relative overflow-hidden flex flex-col justify-between">
        
        {/* ========================================================================= */}
        {/* SLIDE 1: Title Page (Matching Image 1) */}
        {/* ========================================================================= */}
        {currentSlide === 1 && (
          <div className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
              <div className="text-xl sm:text-2xl font-black text-sky-400 tracking-wider font-mono">
                SMART INDIA HACKATHON 2026
              </div>
              <div className="flex items-center gap-2">
                <span className="px-3 py-1 rounded bg-amber-950 text-amber-300 border border-amber-700/60 font-mono text-xs font-bold">
                  THEME: {SIH_METADATA.theme.toUpperCase()}
                </span>
                <span className="px-3 py-1 rounded bg-sky-950 text-sky-300 border border-sky-700/60 font-mono text-xs font-bold">
                  PS ID: {SIH_METADATA.problem_statement_id}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center py-4">
              {/* Left Column: Title & Metadata */}
              <div className="lg:col-span-8 space-y-6">
                <div>
                  <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono text-xs uppercase tracking-widest font-semibold">
                    TITLE PAGE
                  </span>
                  <h1 className="text-2xl sm:text-3xl lg:text-4xl font-black text-white tracking-tight mt-3 leading-tight">
                    {SIH_METADATA.problem_title}
                  </h1>
                  <p className="text-sm text-sky-400 font-mono mt-2 font-semibold">
                    {SIH_METADATA.solution_name}: {SIH_METADATA.solution_tagline}
                  </p>
                </div>

                {/* Exact bullets from Slide 1 */}
                <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-5 space-y-3 font-mono text-xs sm:text-sm">
                  <div className="flex items-start gap-3">
                    <span className="text-sky-400 font-bold">•</span>
                    <div>
                      <strong className="text-white">Problem Statement ID — </strong>
                      <span className="text-sky-300 font-bold">{SIH_METADATA.problem_statement_id}</span>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <span className="text-sky-400 font-bold">•</span>
                    <div>
                      <strong className="text-white">Problem Statement Title — </strong>
                      <span className="text-slate-200">{SIH_METADATA.problem_title}</span>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <span className="text-sky-400 font-bold">•</span>
                    <div>
                      <strong className="text-white">Theme — </strong>
                      <span className="text-amber-300">{SIH_METADATA.theme}</span>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <span className="text-sky-400 font-bold">•</span>
                    <div>
                      <strong className="text-white">PS Category — </strong>
                      <span className="text-emerald-300">{SIH_METADATA.category}</span>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <span className="text-sky-400 font-bold">•</span>
                    <div>
                      <strong className="text-white">Team ID — </strong>
                      <span className="text-slate-400 font-semibold">{SIH_METADATA.team_id}</span>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <span className="text-sky-400 font-bold">•</span>
                    <div>
                      <strong className="text-white">Team Name — </strong>
                      <span className="text-white font-extrabold px-2 py-0.5 rounded bg-sky-950 border border-sky-800">
                        {SIH_METADATA.team_name}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Core philosophy quote */}
                <div className="p-4 bg-gradient-to-r from-sky-950/60 to-indigo-950/40 rounded-xl border border-sky-800/40">
                  <div className="text-xs uppercase font-mono tracking-widest text-sky-400 font-bold mb-1">
                    Core Operational Proposition
                  </div>
                  <div className="text-sm font-serif italic text-slate-200">
                    &ldquo;{SIH_METADATA.core_proposition}&rdquo;
                  </div>
                </div>
              </div>

              {/* Right Column: Official SIH 2026 Motif Art */}
              <div className="lg:col-span-4 flex flex-col items-center justify-center">
                <div className="w-56 h-56 rounded-full bg-slate-950 border-2 border-slate-800 p-6 flex flex-col items-center justify-center relative shadow-2xl shadow-sky-950/50">
                  {/* Glowing ambient ring */}
                  <div className="absolute inset-0 rounded-full border border-sky-500/20 animate-pulse"></div>

                  {/* Brain / Lightbulb Motif SVG */}
                  <div className="relative w-28 h-28 flex items-center justify-center mb-2">
                    <div className="absolute left-3 w-10 h-16 rounded-l-full bg-amber-500/20 border-l-2 border-amber-500 flex items-center justify-center">
                      <Cpu className="w-6 h-6 text-amber-400" />
                    </div>
                    <div className="absolute right-3 w-10 h-16 rounded-r-full bg-emerald-500/20 border-r-2 border-emerald-500 flex items-center justify-center">
                      <Activity className="w-6 h-6 text-emerald-400" />
                    </div>
                    <div className="w-6 h-6 rounded-full bg-white/10 border border-white/40 z-10 flex items-center justify-center">
                      <Zap className="w-3.5 h-3.5 text-amber-300" />
                    </div>
                  </div>

                  <div className="text-center">
                    <div className="text-xs font-black text-white tracking-wider">SMART INDIA</div>
                    <div className="text-[11px] font-black text-amber-400 tracking-wider">HACKATHON</div>
                    <div className="text-xs font-mono font-bold text-sky-400">2026</div>
                  </div>
                </div>

                <div className="mt-4 text-center">
                  <span className="text-xs font-mono text-slate-400">Autonomous Sensor</span>
                  <div className="text-xs font-bold text-emerald-400">Strictly 0 Return Packets</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SLIDE 2: Detection & Decision Pipeline + Continuous Learning (Matching Image 2) */}
        {/* ========================================================================= */}
        {currentSlide === 2 && (
          <div className="space-y-5">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-6 h-6 rounded bg-sky-600 text-white font-bold text-xs flex items-center justify-center">1</span>
                <h2 className="text-lg sm:text-xl font-bold text-white">
                  Detection &amp; Decision Pipeline <span className="text-xs text-sky-400 font-normal font-mono ml-2">(From one-way traffic to intelligent threat detection)</span>
                </h2>
              </div>
            </div>

            {/* Pipeline Row 1: 6 Steps */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-2.5 text-xs">
              {PIPELINE_DETECTION_STEPS.map((s) => (
                <div key={s.step} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex flex-col justify-between hover:border-sky-700/60 transition-colors">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="w-5 h-5 rounded-full bg-sky-950 text-sky-400 border border-sky-800 text-[10px] font-bold flex items-center justify-center">
                        {s.step}
                      </span>
                      <span className="text-[9px] font-mono text-slate-500 uppercase">Stage {s.step}</span>
                    </div>
                    <div className="font-semibold text-white text-[11px] leading-tight mb-1">{s.title}</div>
                    <div className="text-[10px] text-sky-300/80 font-mono mb-1">{s.tools}</div>
                  </div>
                  <div className="text-[10px] text-slate-400 leading-snug pt-1 border-t border-slate-900">{s.details}</div>
                </div>
              ))}
            </div>

            {/* Threat Output Callout */}
            <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg flex flex-wrap items-center justify-between text-xs gap-2">
              <span className="text-slate-400 font-mono text-[11px]">THREAT OUTPUT SPECIFICATION:</span>
              <div className="flex items-center gap-4 text-[11px] font-mono">
                <span className="text-white"><strong className="text-sky-400">Class:</strong> Multi-Class Anomaly</span>
                <span className="text-white"><strong className="text-emerald-400">Confidence:</strong> 0% - 100% Certainty</span>
                <span className="text-white"><strong className="text-amber-400">Severity:</strong> LOW / MED / HIGH / CRIT</span>
                <span className="text-white"><strong className="text-purple-400">Evidence:</strong> Features + Rules</span>
              </div>
            </div>

            {/* Section 2: Monitoring, Security & Continuous Learning */}
            <div className="pt-2">
              <div className="flex items-center gap-2 mb-2">
                <span className="w-6 h-6 rounded bg-indigo-600 text-white font-bold text-xs flex items-center justify-center">2</span>
                <h3 className="text-base font-bold text-white">
                  Monitoring, Security &amp; Continuous Learning <span className="text-xs text-indigo-400 font-normal font-mono ml-2">(From alerts to action, feedback and improvement)</span>
                </h3>
              </div>

              {/* 8-step continuous learning horizontal grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 text-xs">
                {PIPELINE_LEARNING_STEPS.map((st) => (
                  <div key={st.step} className="bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-[10px] flex flex-col justify-between hover:border-indigo-700/60 transition-colors">
                    <div>
                      <span className="font-bold text-indigo-400 font-mono">{st.step}.</span>
                      <div className="font-semibold text-white leading-tight mt-0.5">{st.title}</div>
                    </div>
                    <div className="text-slate-400 text-[9px] mt-1 leading-snug">{st.desc}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Technologies Used (Minimal & Focused Stack) */}
            <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-mono font-bold text-slate-400 uppercase">Technologies Used (Minimal &amp; Focused Stack):</span>
              <div className="flex flex-wrap items-center gap-2">
                {TECHNOLOGIES_USED.map((t) => (
                  <span key={t.name} className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300">
                    <strong className="text-sky-400">{t.name}</strong> <span className="text-slate-500">({t.role})</span>
                  </span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SLIDE 3: Feasibility & Viability (Matching Image 3) */}
        {/* ========================================================================= */}
        {currentSlide === 3 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono font-bold text-sky-400 uppercase tracking-wider">TEAM {SIH_METADATA.team_name}</span>
                <h2 className="text-xl sm:text-2xl font-black text-white mt-0.5">FEASIBILITY AND VIABILITY</h2>
              </div>
              <span className="px-3 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60 font-mono text-xs font-bold">
                SIH 2026 DEPLOYMENT READY
              </span>
            </div>

            {/* Strategies for Overcoming the Challenges (6 Cards) */}
            <div>
              <div className="text-xs font-bold uppercase text-slate-400 font-mono mb-2 flex items-center gap-1.5">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                <span>Strategies for Overcoming the Challenges</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {FEASIBILITY_STRATEGIES.map((item) => (
                  <div key={item.id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex flex-col justify-between">
                    <div>
                      <div className="font-bold text-white text-xs mb-2">{item.title}</div>
                      <ul className="space-y-1 text-[11px] text-slate-300">
                        {item.points.map((pt, idx) => (
                          <li key={idx} className="flex items-start gap-1.5">
                            <span className="text-sky-400">•</span>
                            <span>{pt}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div className="mt-3 pt-2 border-t border-slate-900">
                      <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60 text-[10px] font-mono font-semibold">
                        ✔ {item.badge}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Lower Section: Tech Stack & Feasibility Chain (V-I-A-B-L-E) */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 pt-2">
              {/* Tech Stack Breakdown */}
              <div className="lg:col-span-6 bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                <div className="font-bold text-white uppercase font-mono text-[11px] text-sky-400">TECH STACK-</div>
                <div className="grid grid-cols-2 gap-3 text-[11px]">
                  <div>
                    <div className="font-semibold text-slate-300">Programming &amp; Data:</div>
                    <div className="text-slate-400 font-mono">Python, Pandas+NumPy, Scikit-learn</div>
                  </div>
                  <div>
                    <div className="font-semibold text-slate-300">Network Analysis:</div>
                    <div className="text-slate-400 font-mono">Scapy (PCAP replay), CICFlowMeter, Zeek</div>
                  </div>
                  <div>
                    <div className="font-semibold text-slate-300">AI / ML Models:</div>
                    <div className="text-slate-400 font-mono">Flow RF, DNS RF, TLS/QUIC Rules</div>
                  </div>
                  <div>
                    <div className="font-semibold text-slate-300">Visualization &amp; Input:</div>
                    <div className="text-slate-400 font-mono">Streamlit / Web, PCAP / Simulated Traffic</div>
                  </div>
                </div>
              </div>

              {/* Feasibility Chain: V-I-A-B-L-E */}
              <div className="lg:col-span-6 bg-slate-950 p-4 rounded-xl border border-slate-800">
                <div className="font-bold text-white uppercase font-mono text-[11px] text-amber-400 mb-2">
                  Cyber Threat Detection — Feasibility Chain (V-I-A-B-L-E)
                </div>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                  {FEASIBILITY_CHAIN.map((ch) => (
                    <div key={ch.letter} className="bg-slate-900 p-2 rounded-lg border border-slate-800 text-center">
                      <div className="w-6 h-6 mx-auto rounded-full bg-gradient-to-br from-amber-500 to-rose-600 text-white font-black text-xs flex items-center justify-center shadow-md">
                        {ch.letter}
                      </div>
                      <div className="font-bold text-white text-[10px] mt-1 leading-tight">{ch.title}</div>
                      <div className="text-[9px] text-slate-400 mt-0.5 leading-tight">{ch.desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SLIDE 4: Impact & Benefits (Matching Image 4) */}
        {/* ========================================================================= */}
        {currentSlide === 4 && (
          <div className="space-y-6">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono font-bold text-sky-400 uppercase tracking-wider">TEAM {SIH_METADATA.team_name}</span>
                <h2 className="text-xl sm:text-2xl font-black text-white mt-0.5">IMPACT AND BENEFITS</h2>
              </div>
              <span className="px-3 py-1 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60 font-mono text-xs font-bold">
                8 STRATEGIC CAPABILITIES
              </span>
            </div>

            {/* Central Radial / Grid Representation of the 8 Nodes in Slide 4 */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {IMPACT_BENEFITS_RADIAL.map((item) => (
                <div 
                  key={item.id} 
                  className="bg-slate-950 p-4 rounded-xl border border-slate-800 hover:border-sky-500/50 transition-all flex flex-col justify-between group"
                >
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-6 h-6 rounded-full bg-sky-950 text-sky-400 border border-sky-800 font-mono font-bold text-xs flex items-center justify-center group-hover:bg-sky-600 group-hover:text-white transition-colors">
                        {item.id}
                      </span>
                      <h3 className="font-bold text-white text-xs leading-snug">{item.title}</h3>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {item.desc}
                    </p>
                  </div>
                </div>
              ))}
            </div>

            {/* Performance Visibility Metrics */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-center">
                <div className="text-[10px] text-slate-400 uppercase font-mono">Detection Latency</div>
                <div className="text-2xl font-bold font-mono text-emerald-400 mt-0.5">&lt; 2.0 sec</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Automated line-rate alert dispatch</div>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-center">
                <div className="text-[10px] text-slate-400 uppercase font-mono">Tested Throughput</div>
                <div className="text-2xl font-bold font-mono text-sky-400 mt-0.5">95,928 /s</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Flows processed per single CPU core</div>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-center">
                <div className="text-[10px] text-slate-400 uppercase font-mono">Alert Fatigue Cut</div>
                <div className="text-2xl font-bold font-mono text-indigo-400 mt-0.5">-88%</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Via 10s temporal window correlation</div>
              </div>
              <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 text-center">
                <div className="text-[10px] text-slate-400 uppercase font-mono">Safe Learning Gate</div>
                <div className="text-2xl font-bold font-mono text-purple-400 mt-0.5">0.0%</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Vulnerability to feedback poisoning</div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SLIDE 5: Research and References (Matching Image 5) */}
        {/* ========================================================================= */}
        {currentSlide === 5 && (
          <div className="space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono font-bold text-sky-400 uppercase tracking-wider">TEAM {SIH_METADATA.team_name}</span>
                <h2 className="text-xl sm:text-2xl font-black text-white mt-0.5">RESEARCH AND REFERENCES</h2>
              </div>
              <span className="px-3 py-1 rounded bg-purple-950 text-purple-300 border border-purple-800/60 font-mono text-xs font-bold">
                GROUNDED IN PEER-REVIEWED LITERATURE
              </span>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              {/* Left Column: References, Research, Resources */}
              <div className="lg:col-span-4 space-y-4">
                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <div className="font-bold text-sky-400 uppercase font-mono text-[11px]">REFERENCES —</div>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-[11px]">
                    <li>CICFlowMeter / CIC-IDS research</li>
                    <li>CICIDS2018</li>
                    <li>CICIDS2017</li>
                    <li>Scikit-learn Random Forest documentation</li>
                  </ol>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <div className="font-bold text-emerald-400 uppercase font-mono text-[11px]">RESEARCH —</div>
                  <ol className="list-decimal list-inside space-y-1 text-slate-300 text-[11px]">
                    <li>Flow-based Network Intrusion Detection</li>
                    <li>Encrypted / VPN traffic analysis</li>
                    <li>DNS and TLS metadata visibility</li>
                    <li>Flow-based ML intrusion classification</li>
                  </ol>
                </div>

                <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2 text-xs">
                  <div className="font-bold text-amber-400 uppercase font-mono text-[11px]">RESOURCES &amp; PROTOTYPE —</div>
                  <ul className="space-y-1 text-slate-300 text-[11px]">
                    <li>• Python + Pandas + NumPy</li>
                    <li>• Scapy + CICFlowMeter</li>
                    <li>• Zeek</li>
                    <li>• Scikit-learn + Streamlit / React</li>
                  </ul>
                </div>
              </div>

              {/* Right Column: Complete 10-Row Technology Selection Table */}
              <div className="lg:col-span-8 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                <div className="p-3 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                  <span className="font-bold text-white text-xs font-mono">TECHNOLOGY SELECTION &amp; JUSTIFICATION MATRIX</span>
                  <span className="text-[10px] font-mono text-slate-400">10 Defense-Grade Layers</span>
                </div>

                <div className="max-h-[380px] overflow-y-auto scrollbar-thin">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-slate-950 text-slate-400 text-[10px] font-mono uppercase sticky top-0 border-b border-slate-800">
                      <tr>
                        <th className="p-2.5">Layer / Area</th>
                        <th className="p-2.5 text-sky-400">✔ Chosen Technology</th>
                        <th className="p-2.5">💡 Reason for Choice</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-[11px]">
                      {RESEARCH_TECH_TABLE.map((row, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/40">
                          <td className="p-2.5 font-bold text-white whitespace-nowrap">{row.layer}</td>
                          <td className="p-2.5 text-sky-300 font-mono whitespace-nowrap bg-sky-950/20">{row.chosenTech}</td>
                          <td className="p-2.5 text-slate-300 leading-snug">{row.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================================= */}
        {/* SLIDE 6: Proposed Solution & Gap Analysis (Matching Image 6) */}
        {/* ========================================================================= */}
        {currentSlide === 6 && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-2">
              <div>
                <span className="text-xs font-mono font-bold text-sky-400 uppercase tracking-wider">TEAM {SIH_METADATA.team_name}</span>
                <h2 className="text-lg sm:text-xl font-black text-white mt-0.5">
                  Problem Statement Title: {SIH_METADATA.problem_title}
                </h2>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTabSlide6('gaps')}
                  className={`px-3 py-1 rounded text-xs font-mono transition-all cursor-pointer ${
                    activeTabSlide6 === 'gaps' ? 'bg-sky-600 text-white font-bold' : 'bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  How It Fills The Gaps
                </button>
                <button
                  onClick={() => setActiveTabSlide6('pillars')}
                  className={`px-3 py-1 rounded text-xs font-mono transition-all cursor-pointer ${
                    activeTabSlide6 === 'pillars' ? 'bg-sky-600 text-white font-bold' : 'bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  6 Innovation Pillars
                </button>
                <button
                  onClick={() => setActiveTabSlide6('jury')}
                  className={`px-3 py-1 rounded text-xs font-mono transition-all cursor-pointer ${
                    activeTabSlide6 === 'jury' ? 'bg-sky-600 text-white font-bold' : 'bg-slate-950 text-slate-400 hover:text-white'
                  }`}
                >
                  Jury Defense Q&amp;A
                </button>
              </div>
            </div>

            {/* Proposed Solution Pipeline Banner */}
            <div className="bg-slate-950 p-3 rounded-xl border border-slate-800">
              <div className="text-[10px] font-mono text-sky-400 uppercase font-bold mb-1">PROPOSED SOLUTION ARCHITECTURE:</div>
              <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-1.5 text-center text-[10px]">
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">1. PCAP Traffic</div>
                  <div>One-way Ingest</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">2. Metadata</div>
                  <div>CICFlow + Zeek</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">3. Specialists</div>
                  <div>Flow RF / DNS / TLS</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">4. Correlation</div>
                  <div>Weighted Fusion</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">5. Classification</div>
                  <div>Confidence + Sev</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">6. Alert + Proof</div>
                  <div>Streamlit UI</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-sky-400">7. Review</div>
                  <div>Analyst Triage</div>
                </div>
                <div className="p-1.5 rounded bg-slate-900 border border-slate-800 text-slate-200">
                  <div className="font-bold text-emerald-400">8. Model Update</div>
                  <div>Safe Retraining</div>
                </div>
              </div>
            </div>

            {/* TAB CONTENT: How It Fills The Gaps (Matching Slide 6 Table) */}
            {activeTabSlide6 === 'gaps' && (
              <div className="space-y-3">
                <div className="p-3 bg-sky-950/40 rounded-xl border border-sky-800/40 text-xs text-slate-200">
                  <strong>Solution Statement: </strong>{SIH_METADATA.solution_statement}
                </div>

                <div className="overflow-x-auto bg-slate-950 rounded-xl border border-slate-800 max-h-[340px] overflow-y-auto scrollbar-thin">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-slate-900 text-slate-400 text-[10px] font-mono uppercase sticky top-0 border-b border-slate-800">
                      <tr>
                        <th className="p-2.5">Identified Gap</th>
                        <th className="p-2.5 text-sky-400">How Our Solution Fills It</th>
                        <th className="p-2.5 text-emerald-400">Operational Impact</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 text-[11px]">
                      {SOLUTION_GAP_ANALYSIS.map((row, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30">
                          <td className="p-2.5 font-bold text-white">{row.gap}</td>
                          <td className="p-2.5 text-slate-300 bg-sky-950/20">{row.solution}</td>
                          <td className="p-2.5 text-emerald-300 font-medium">{row.impact}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB CONTENT: 6 Innovation Pillars (Matching Slide 6 Wheel) */}
            {activeTabSlide6 === 'pillars' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {INNOVATION_PILLARS.map((pil) => (
                  <div key={pil.id} className="bg-slate-950 p-4 rounded-xl border border-slate-800 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="w-6 h-6 rounded-full bg-sky-950 text-sky-400 border border-sky-800 font-mono font-bold text-xs flex items-center justify-center">
                        {pil.id}
                      </span>
                      <h3 className="font-bold text-white text-xs">{pil.title}</h3>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed pl-8">
                      {pil.desc}
                    </p>
                  </div>
                ))}
              </div>
            )}

            {/* TAB CONTENT: Jury Defense Q&A */}
            {activeTabSlide6 === 'jury' && (
              <div className="space-y-2.5 max-h-[340px] overflow-y-auto pr-1 scrollbar-thin">
                {SIH_JURY_QA.slice(0, 4).map((qa, idx) => (
                  <div key={idx} className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                    <div className="font-semibold text-sky-300 mb-1">
                      <span className="font-mono text-slate-400 mr-2">Q{idx + 1}:</span>
                      {qa.question}
                    </div>
                    <p className="text-slate-300 text-[11px] leading-relaxed">
                      <strong className="text-emerald-400">Defense: </strong>{qa.answer}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Slide Footer */}
        <div className="pt-4 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>SIH 2026 Problem Statement ID: 26145 (NTRO) • Team {SIH_METADATA.team_name}</span>
          </div>
          <div className="font-mono">
            Slide {currentSlide} of {totalSlides}
          </div>
        </div>
      </div>
    </div>
  );
};

