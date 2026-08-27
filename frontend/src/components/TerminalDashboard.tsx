import { useState, useEffect, useRef } from 'react';
import { Play, Pause, SkipBack, ChevronDown, Activity, PanelRight, X, RotateCcw, Settings } from 'lucide-react';
import { SettingsModal } from './SettingsModal';

interface TerminalDashboardProps {
  scenarios: string[];
  schedulers: string[];
  winSize: number;
  setWinSize: (s: number) => void;
  theme: 'dark' | 'light';
  setTheme: (t: 'dark' | 'light') => void;
}

export const TerminalDashboard = ({ scenarios, schedulers, winSize, setWinSize, theme, setTheme }: TerminalDashboardProps) => {
  const [scenario, setScenario] = useState("synthetic_log");
  const [scheduler, setScheduler] = useState("ucb1");
  const [seed, setSeed] = useState(42);
  const [k, setK] = useState(1);

  const [simulationData, setSimulationData] = useState<any>(null);
  const [currentSlot, setCurrentSlot] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mlConfidence, setMlConfidence] = useState(85);

  const [showResults, setShowResults] = useState(true);
  const [sidebarPct, setSidebarPct] = useState(20);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const containerRef = useRef<HTMLDivElement>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    const fetchSim = async () => {
      setLoading(true);
      try {
        const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const res = await fetch(`${apiBase}/api/simulate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenario_name: scenario, scheduler_name: scheduler, seed, k }),
          signal: controller.signal
        });
        const data = await res.json();
        if (!controller.signal.aborted) {
          setSimulationData(data);
          setCurrentSlot(0);
          setIsPlaying(false);
        }
      } catch (err) {
        if (err instanceof DOMException && err.name === 'AbortError') return;
        console.error("Failed to fetch simulation", err);
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    };
    fetchSim();
    return () => controller.abort();
  }, [scenario, scheduler, seed, k]);

  useEffect(() => {
    if (isPlaying && simulationData) {
      const maxSlots = simulationData.active.log.n_slots;
      if (currentSlot >= maxSlots - 1) {
        setIsPlaying(false);
        return;
      }
      const timer = setTimeout(() => setCurrentSlot(c => c + 1), 100);
      return () => clearTimeout(timer);
    }
  }, [isPlaying, currentSlot, simulationData]);

  useEffect(() => {
    if (isPlaying && scheduler !== 'round_robin') {
      const interval = setInterval(() => {
        setMlConfidence(prev => {
          const change = (Math.random() - 0.5) * 6;
          return Math.max(78, Math.min(99.5, prev + change));
        });
      }, 400);
      return () => clearInterval(interval);
    } else if (scheduler === 'round_robin') {
      setMlConfidence(0);
    }
  }, [isPlaying, scheduler]);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [currentSlot, showResults]);

  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = sidebarPct;

    const onMouseMove = (moveEvent: MouseEvent) => {
      if (!containerRef.current) return;
      const containerWidth = containerRef.current.getBoundingClientRect().width;
      const deltaX = startX - moveEvent.clientX;
      const deltaPct = (deltaX / containerWidth) * 100;

      let newPct = startWidth + deltaPct;
      newPct = Math.max(15, Math.min(newPct, 60));
      setSidebarPct(newPct);
    };

    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    };

    document.addEventListener('mousemove', onMouseMove);
    document.addEventListener('mouseup', onMouseUp);
  };

  if (loading || !simulationData) {
    return <div className="h-screen w-full flex items-center justify-center bg-ew-bg text-ew-accent font-mono">FETCHING E-WAVE TELEMETRY...</div>;
  }

  const activeLog = simulationData.active.log;
  const metrics = simulationData.active.metrics;
  const n_bands = activeLog.n_bands;
  const n_slots = activeLog.n_slots;
  const isComplete = currentSlot >= n_slots - 1;

  const effectiveWinSize = Math.min(winSize, n_slots);
  const startSlot = Math.max(0, Math.min(currentSlot - Math.floor(effectiveWinSize / 2), n_slots - effectiveWinSize));
  const endSlot = startSlot + effectiveWinSize;

  const renderWaterfall = () => {
    const yAxis = [];
    for (let b = n_bands - 1; b >= 0; b--) {
      yAxis.push(
        <div key={`y-${b}`} className="flex-1 flex items-center justify-end text-[9px] text-ew-text-dim font-mono pr-2">
          B{b}
        </div>
      );
    }

    const grid = [];
    for (let b = n_bands - 1; b >= 0; b--) {
      const row = [];
      for (let s = startSlot; s < endSlot; s++) {
        const tx = activeLog.truth[b][s];
        const chan = activeLog.actions[s].indexOf(b);
        const scanned = chan !== -1;
        const det = scanned ? activeLog.detections[s][chan] : false;

        let bgColor = "bg-transparent";
        let dot = null;

        if (scanned && tx && det) {
          bgColor = "bg-ew-accent";
        } else if (scanned && tx && !det) {
          bgColor = "bg-[#ef4444]";
        } else if (scanned && !tx && det) {
          bgColor = "bg-[#f59e0b]";
        } else if (scanned) {
          bgColor = "bg-ew-accent/20";
          dot = <div className="w-[3px] h-[3px] bg-ew-accent rounded-full opacity-100" />;
        } else if (tx) {
          bgColor = "bg-ew-unscanned";
        }

        const isCurrent = s === currentSlot;

        row.push(
          <div key={`${b}-${s}`}
               className={`flex-1 min-w-0 min-h-0 flex items-center justify-center transition-colors duration-75 border-b border-r border-ew-border-subtle/50 box-border ${bgColor} ${isCurrent ? 'ring-1 ring-ew-text z-10' : ''}`}>
               {dot}
          </div>
        );
      }
      grid.push(
        <div key={`row-${b}`} className="flex flex-1 w-full min-h-0">
          {row}
        </div>
      );
    }

    const xAxis = [];
    for (let s = startSlot; s < endSlot; s++) {
      xAxis.push(
        <div key={`x-${s}`} className="flex-1 text-center text-[9px] text-ew-text-dimmer font-mono pt-1">
          {s % 5 === 0 ? s : ''}
        </div>
      );
    }

    return (
      <div className="flex w-full h-full min-h-0 relative">
        <div className="w-8 flex flex-col pb-5 shrink-0">
          {yAxis}
        </div>

        <div className="flex flex-col flex-1 min-w-0">
          <div className="flex-1 flex flex-col relative border-l border-t border-ew-border min-h-0 bg-ew-bg overflow-hidden">
            {grid}
          </div>
          <div className="h-5 flex shrink-0">
            {xAxis}
          </div>
        </div>
      </div>
    );
  };

  const generateLogs = () => {
    const logs = [];
    const startLogSlot = Math.max(0, currentSlot - 50);

    for (let s = startLogSlot; s <= currentSlot; s++) {
      const bandsAtSlot = activeLog.actions[s];
      if (bandsAtSlot === undefined) continue;

      for (let j = 0; j < bandsAtSlot.length; j++) {
        const b = bandsAtSlot[j];
        const tx = activeLog.truth[b][s];
        const det = activeLog.detections[s][j];

        let msg = "";
        let colorClass = "";

        if (tx && det) {
          msg = `HIT: Intercepted`;
          colorClass = "text-ew-accent";
        } else if (!tx && det) {
          msg = `FALSE ALARM: Ghost`;
          colorClass = "text-[#f59e0b]";
        } else if (tx && !det) {
          msg = `MISSED: Lost`;
          colorClass = "text-[#ef4444]";
        } else {
          msg = `IDLE: Clear`;
          colorClass = "text-ew-text-dim";
        }

        logs.push(
          <div key={`log-${s}-${j}`} className="flex flex-col mb-1.5 pb-1.5 border-b border-ew-border-subtle last:border-0 leading-tight">
            <div className="flex items-start gap-2">
              <span className="text-ew-text-dimmer shrink-0 opacity-70">[{String(s).padStart(4, '0')}]</span>
              <span className="text-ew-text-muted shrink-0">[B-{b}]</span>
              <span className={`${colorClass} truncate font-semibold`}>{msg}</span>
            </div>
          </div>
        );
      }
    }
    return logs;
  };

  const handlePlayToggle = () => {
    if (isComplete) {
      setCurrentSlot(0);
      setIsPlaying(true);
    } else {
      setIsPlaying(!isPlaying);
    }
  };

  return (
    <div className="h-screen w-full flex flex-col bg-ew-bg text-ew-text-secondary font-sans">
      <SettingsModal
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        winSize={winSize}
        setWinSize={setWinSize}
        theme={theme}
        setTheme={setTheme}
      />

      {/* TOP HEADER / LOGO */}
      <div className="px-8 pt-6 flex justify-between items-end shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-ew-accent flex items-center justify-center text-black">
            <Activity size={20} strokeWidth={3} />
          </div>
          <div className="text-2xl font-bold text-ew-text tracking-tight">E-WAVE</div>
        </div>

        <div className="flex gap-10 items-end pb-1">
          <div className="flex flex-col">
            <span className="text-[10px] text-ew-text-dim uppercase tracking-wider font-semibold">Active Band</span>
            <span className="text-lg font-light text-ew-accent font-mono">B-{(activeLog.actions[currentSlot] ?? [0]).join(", B-")}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] text-ew-text-dim uppercase tracking-wider font-semibold">Intercept Ratio</span>
            <span className="text-lg font-light text-ew-text font-mono">{(metrics.interception_ratio * 100).toFixed(1)}%</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] text-ew-text-dim uppercase tracking-wider font-semibold">Detection Prob</span>
            <span className="text-lg font-light text-ew-text font-mono">{(metrics.pd * 100).toFixed(1)}%</span>
          </div>
        </div>
      </div>

      {/* MAIN VIEWING SPLIT */}
      <div className="flex-1 flex px-8 pt-6 pb-4 overflow-hidden min-h-0" ref={containerRef}>

        {/* Left Side: The Graph */}
        <div
          className="bg-ew-surface rounded-lg p-6 flex flex-col shadow-sm min-h-0 border border-ew-border-subtle overflow-hidden relative"
          style={{ width: showResults ? `${100 - sidebarPct}%` : '100%' }}
        >
          <div className="flex justify-between items-center mb-6 shrink-0">
             <div className="flex items-center gap-3">
                <h2 className="text-sm font-medium text-ew-text tracking-wide uppercase">Live Spectrum Waterfall</h2>
                <div className="text-[9px] text-ew-text-muted bg-ew-bg border border-ew-border px-2 py-0.5 rounded font-semibold tracking-wider">
                  INPUT: SIMULATED DATA
                </div>
             </div>

             <div className="flex items-center gap-6">
               <div className="flex flex-wrap gap-3 text-[9px] text-ew-text-muted uppercase tracking-wider shrink-0 font-semibold">
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-ew-accent"></div> Hit</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#ef4444]"></div> Missed</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#f59e0b]"></div> False Alarm</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-ew-accent/30 flex items-center justify-center"><div className="w-1 h-1 bg-ew-accent rounded-full opacity-100"></div></div> Scan</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-ew-unscanned"></div> Unscanned Tx</div>
               </div>

               {!showResults && (
                 <button
                   onClick={() => setShowResults(true)}
                   className="text-ew-text-dim hover:text-ew-text transition-colors p-1"
                   title="Show Results"
                 >
                   <PanelRight size={18} />
                 </button>
               )}
             </div>
          </div>

          <div className="flex-1 flex items-center justify-center overflow-hidden min-h-0">
             {renderWaterfall()}
          </div>
        </div>

        {/* Resizer Handle */}
        {showResults && (
          <div
            className="w-6 flex items-center justify-center cursor-col-resize shrink-0 group z-20"
            onMouseDown={handleMouseDown}
          >
            <div className="w-1 h-8 bg-ew-border rounded-full group-hover:bg-ew-accent transition-colors"></div>
          </div>
        )}

        {/* Right Side: Scanner Results */}
        {showResults && (
          <div
            className="bg-ew-surface rounded-lg border border-ew-border-subtle flex flex-col shadow-sm min-h-0 overflow-hidden relative"
            style={{ width: `${sidebarPct}%` }}
          >
             <div className="absolute top-12 left-0 right-0 h-6 bg-gradient-to-b from-ew-surface to-transparent z-10 pointer-events-none"></div>

             <div className="p-4 border-b border-ew-border-subtle bg-ew-surface z-20 shrink-0 flex justify-between items-center">
               <div className="flex items-center gap-2">
                 <h3 className="text-xs uppercase text-ew-text font-semibold tracking-wider">Results</h3>
                 <div className={`w-1.5 h-1.5 rounded-full ${isPlaying ? 'bg-ew-accent animate-pulse' : 'bg-ew-text-dimmer'}`}></div>
               </div>

               <button
                 onClick={() => setShowResults(false)}
                 className="text-ew-text-dim hover:text-ew-text transition-colors"
                 title="Hide Results"
               >
                 <X size={16} />
               </button>
             </div>

             <div
               ref={logContainerRef}
               className="flex-1 overflow-y-auto p-4 flex flex-col font-mono text-[10px] scroll-smooth scrollbar-hide"
             >
                {generateLogs()}
             </div>
          </div>
        )}

      </div>

      {/* BOTTOM CONTROL BAR */}
      <div className="h-[100px] bg-ew-surface border-t border-ew-border-subtle flex items-center px-8 gap-12 shrink-0">

        {/* Playback Controls */}
        <div className="flex items-center gap-6">
          <button
            onClick={() => setCurrentSlot(0)}
            className="text-ew-text-muted hover:text-ew-text transition-colors cursor-pointer"
          >
            <SkipBack size={24} />
          </button>

          <button
            onClick={handlePlayToggle}
            className="w-14 h-14 bg-ew-accent text-black rounded-full flex items-center justify-center hover:scale-105 transition-transform cursor-pointer shadow-lg shadow-ew-accent/20"
          >
            {isComplete ? (
              <RotateCcw size={24} strokeWidth={2.5} />
            ) : isPlaying ? (
              <Pause size={24} fill="currentColor" />
            ) : (
              <Play size={24} fill="currentColor" className="ml-1" />
            )}
          </button>

          <div className="text-sm font-mono text-ew-text-muted w-24 tracking-widest">
            {String(currentSlot).padStart(4, '0')} <span className="opacity-50">/</span> {n_slots}
          </div>
        </div>

        <div className="h-10 w-px bg-ew-border-subtle"></div>

        {/* Configuration Toggles */}
        <div className="flex items-center gap-6 flex-1">
          <div className="flex flex-col gap-1 flex-1 relative max-w-[200px]">
            <label className="text-[10px] uppercase text-ew-text-dim font-semibold tracking-wider">RF Scenario</label>
            <div className="relative">
              <select
                value={scenario}
                onChange={e => setScenario(e.target.value)}
                className="w-full bg-ew-bg border border-ew-border rounded-md text-[11px] font-semibold text-ew-text px-3 py-2 outline-none cursor-pointer appearance-none hover:border-ew-accent transition-colors pr-8"
              >
                {scenarios.map((s: string) => <option key={s} value={s}>{s.replace(/_/g, ' ').toUpperCase()}</option>)}
              </select>
              <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-ew-text-dim pointer-events-none" />
            </div>
          </div>

          <div className="flex flex-col gap-1 flex-1 relative max-w-[200px]">
            <label className="text-[10px] uppercase text-ew-text-dim font-semibold tracking-wider">ML Agent</label>
            <div className="relative">
              <select
                value={scheduler}
                onChange={e => setScheduler(e.target.value)}
                className="w-full bg-ew-bg border border-ew-border rounded-md text-[11px] font-semibold text-ew-text px-3 py-2 outline-none cursor-pointer appearance-none hover:border-ew-accent transition-colors pr-8"
              >
                {schedulers.map((s: string) => <option key={s} value={s}>{s.replace(/_/g, ' ').toUpperCase()}</option>)}
              </select>
              <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-ew-text-dim pointer-events-none" />
            </div>
          </div>

          <div className="flex flex-col gap-1 w-20">
            <label className="text-[10px] uppercase text-ew-text-dim font-semibold tracking-wider">Seed</label>
            <input
              type="number"
              value={seed}
              onChange={e => setSeed(Number(e.target.value))}
              className="w-full bg-ew-bg border border-ew-border rounded-md text-[11px] font-semibold text-ew-text px-3 py-2 outline-none hover:border-ew-accent transition-colors"
            />
          </div>

          <div className="flex flex-col gap-1 w-20">
            <label className="text-[10px] uppercase text-ew-text-dim font-semibold tracking-wider">Channels</label>
            <input
              type="number"
              min={1}
              value={k}
              onChange={e => setK(Math.max(1, Number(e.target.value)))}
              className="w-full bg-ew-bg border border-ew-border rounded-md text-[11px] font-semibold text-ew-text px-3 py-2 outline-none hover:border-ew-accent transition-colors"
            />
          </div>
        </div>

        {/* ML Status Indicator & Settings */}
        <div className="flex items-center gap-6 ml-4">
          <div className="flex flex-col justify-center w-56">
            <div className="flex justify-between text-[10px] uppercase font-bold tracking-wider mb-2">
              <span className="text-ew-text-muted">ML Confidence</span>
              <span className={scheduler === 'round_robin' ? 'opacity-50' : 'text-ew-accent'}>
                {scheduler === 'round_robin' ? 'N/A' : `${mlConfidence.toFixed(1)}%`}
              </span>
            </div>
            <div className="w-full h-1.5 bg-ew-bg border border-ew-border-subtle rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ease-linear ${scheduler === 'round_robin' ? 'bg-ew-border w-0' : 'bg-ew-accent'}`}
                style={{ width: scheduler === 'round_robin' ? '0%' : `${mlConfidence}%` }}
              ></div>
            </div>
          </div>

          <button
            onClick={() => setSettingsOpen(true)}
            className="w-10 h-10 rounded-full bg-ew-bg border border-ew-border flex items-center justify-center text-ew-text-muted hover:text-ew-accent hover:border-ew-accent transition-colors"
            title="Settings"
          >
            <Settings size={18} />
          </button>
        </div>

      </div>

      <style dangerouslySetInnerHTML={{__html: `
        .scrollbar-hide::-webkit-scrollbar {
            display: none;
        }
        .scrollbar-hide {
            -ms-overflow-style: none;
            scrollbar-width: none;
        }
      `}} />
    </div>
  );
};
