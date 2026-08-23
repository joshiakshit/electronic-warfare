import { useState, useEffect, useRef } from 'react';
import { Play, Pause, SkipBack, ChevronDown, Activity, PanelRight, X, RotateCcw, Settings } from 'lucide-react';
import { SettingsModal } from './SettingsModal';

interface TerminalDashboardProps {
  scenarios: string[];
  schedulers: string[];
  winSize: number;
  setWinSize: (s: number) => void;
}

export const TerminalDashboard = ({ scenarios, schedulers, winSize, setWinSize }: TerminalDashboardProps) => {
  const [scenario, setScenario] = useState("synthetic_log");
  const [scheduler, setScheduler] = useState("ucb1");
  const [seed, setSeed] = useState(42);
  
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
          body: JSON.stringify({ scenario_name: scenario, scheduler_name: scheduler, seed }),
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
  }, [scenario, scheduler, seed]);

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

  // ML Confidence animation loop
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

  // Auto-scroll logs
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
    return <div className="h-screen w-full flex items-center justify-center bg-[#000000] text-[#1ed760] font-mono">FETCHING E-WAVE TELEMETRY...</div>;
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
    // Generate Y-axis
    const yAxis = [];
    for (let b = n_bands - 1; b >= 0; b--) {
      yAxis.push(
        <div key={`y-${b}`} className="flex-1 flex items-center justify-end text-[9px] text-gray-500 font-mono pr-2">
          B{b}
        </div>
      );
    }

    // Generate Grid Data
    const grid = [];
    for (let b = n_bands - 1; b >= 0; b--) {
      const row = [];
      for (let s = startSlot; s < endSlot; s++) {
        const tx = activeLog.truth[b][s];
        const scanned = activeLog.actions[s] === b;
        const det = activeLog.detections[s];
        
        let bgColor = "bg-transparent";
        let dot = null;

        if (scanned && tx && det) {
          bgColor = "bg-[#1ed760]"; // HIT
        } else if (scanned && tx && !det) {
          bgColor = "bg-[#ef4444]"; // MISSED
        } else if (scanned && !tx && det) {
          bgColor = "bg-[#f59e0b]"; // FALSE ALARM
        } else if (scanned) {
          bgColor = "bg-[#1ed760]/20"; // SCAN
          dot = <div className="w-[3px] h-[3px] bg-[#1ed760] rounded-full opacity-100" />;
        } else if (tx) {
          bgColor = "bg-[#27272a]"; // TX
        }
        
        const isCurrent = s === currentSlot;
        
        row.push(
          <div key={`${b}-${s}`} 
               className={`flex-1 min-w-0 min-h-0 flex items-center justify-center transition-colors duration-75 border-b border-r border-gray-900/50 box-border ${bgColor} ${isCurrent ? 'ring-1 ring-white z-10' : ''}`}>
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
    
    // Generate X-axis
    const xAxis = [];
    for (let s = startSlot; s < endSlot; s++) {
      xAxis.push(
        <div key={`x-${s}`} className="flex-1 text-center text-[9px] text-gray-600 font-mono pt-1">
          {s % 5 === 0 ? s : ''}
        </div>
      );
    }

    return (
      <div className="flex w-full h-full min-h-0 relative">
        {/* Y Axis */}
        <div className="w-8 flex flex-col pb-5 shrink-0">
          {yAxis}
        </div>
        
        {/* Main Grid + X Axis */}
        <div className="flex flex-col flex-1 min-w-0">
          <div className="flex-1 flex flex-col relative border-l border-t border-gray-800 min-h-0 bg-[#000000] overflow-hidden">
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
      const b = activeLog.actions[s];
      if (b === undefined) continue; 
      
      const tx = activeLog.truth[b][s];
      const det = activeLog.detections[s];
      
      let msg = "";
      let colorClass = "";
      
      if (tx && det) {
        msg = `HIT: Intercepted`;
        colorClass = "text-[#1ed760]";
      } else if (!tx && det) {
        msg = `FALSE ALARM: Ghost`;
        colorClass = "text-[#f59e0b]";
      } else if (tx && !det) {
        msg = `MISSED: Lost`;
        colorClass = "text-[#ef4444]";
      } else {
        msg = `IDLE: Clear`;
        colorClass = "text-gray-500";
      }

      logs.push(
        <div key={`log-${s}`} className="flex flex-col mb-1.5 pb-1.5 border-b border-gray-900 last:border-0 leading-tight">
          <div className="flex items-start gap-2">
            <span className="text-gray-600 shrink-0 opacity-70">[{String(s).padStart(4, '0')}]</span>
            <span className="text-gray-400 shrink-0">[B-{b}]</span>
            <span className={`${colorClass} truncate font-semibold`}>{msg}</span>
          </div>
        </div>
      );
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
    <div className="h-screen w-full flex flex-col bg-[#000000] text-gray-200 font-sans">
      <SettingsModal 
        isOpen={settingsOpen} 
        onClose={() => setSettingsOpen(false)} 
        winSize={winSize}
        setWinSize={setWinSize}
      />
      
      {/* TOP HEADER / LOGO */}
      <div className="px-8 pt-6 flex justify-between items-end shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-[#1ed760] flex items-center justify-center text-black">
            <Activity size={20} strokeWidth={3} />
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">E-WAVE</div>
        </div>
        
        {/* Top Right Data */}
        <div className="flex gap-10 items-end pb-1">
          <div className="flex flex-col">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Active Band</span>
            <span className="text-lg font-light text-[#1ed760] font-mono">B-{activeLog.actions[currentSlot] ?? 0}</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Intercept Ratio</span>
            <span className="text-lg font-light text-white font-mono">{(metrics.interception_ratio * 100).toFixed(1)}%</span>
          </div>
          <div className="flex flex-col">
            <span className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">Detection Prob</span>
            <span className="text-lg font-light text-white font-mono">{(metrics.pd * 100).toFixed(1)}%</span>
          </div>
        </div>
      </div>

      {/* MAIN VIEWING SPLIT */}
      <div className="flex-1 flex px-8 pt-6 pb-4 overflow-hidden min-h-0" ref={containerRef}>
        
        {/* Left Side: The Graph */}
        <div 
          className="bg-[#09090b] rounded-lg p-6 flex flex-col shadow-sm min-h-0 border border-gray-900 overflow-hidden relative"
          style={{ width: showResults ? `${100 - sidebarPct}%` : '100%' }}
        >
          {/* Header inside the graph panel */}
          <div className="flex justify-between items-center mb-6 shrink-0">
             <div className="flex items-center gap-3">
                <h2 className="text-sm font-medium text-white tracking-wide uppercase">Live Spectrum Waterfall</h2>
                {/* Input Source Label */}
                <div className="text-[9px] text-gray-400 bg-[#000000] border border-gray-800 px-2 py-0.5 rounded font-semibold tracking-wider">
                  INPUT: SIMULATED DATA
                </div>
             </div>
             
             <div className="flex items-center gap-6">
               {/* Legend */}
               <div className="flex flex-wrap gap-3 text-[9px] text-gray-400 uppercase tracking-wider shrink-0 font-semibold">
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#1ed760]"></div> Hit</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#ef4444]"></div> Missed</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#f59e0b]"></div> False Alarm</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#1ed760]/30 flex items-center justify-center"><div className="w-1 h-1 bg-[#1ed760] rounded-full opacity-100"></div></div> Scan</div>
                 <div className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-sm bg-[#27272a]"></div> Unscanned Tx</div>
               </div>

               {/* Toggle Sidebar Button */}
               {!showResults && (
                 <button 
                   onClick={() => setShowResults(true)}
                   className="text-gray-500 hover:text-white transition-colors p-1"
                   title="Show Results"
                 >
                   <PanelRight size={18} />
                 </button>
               )}
             </div>
          </div>

          {/* Graph Container */}
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
            <div className="w-1 h-8 bg-gray-800 rounded-full group-hover:bg-[#1ed760] transition-colors"></div>
          </div>
        )}

        {/* Right Side: Scanner Results */}
        {showResults && (
          <div 
            className="bg-[#09090b] rounded-lg border border-gray-900 flex flex-col shadow-sm min-h-0 overflow-hidden relative"
            style={{ width: `${sidebarPct}%` }}
          >
             <div className="absolute top-12 left-0 right-0 h-6 bg-gradient-to-b from-[#09090b] to-transparent z-10 pointer-events-none"></div>
             
             <div className="p-4 border-b border-gray-900 bg-[#09090b] z-20 shrink-0 flex justify-between items-center">
               <div className="flex items-center gap-2">
                 <h3 className="text-xs uppercase text-white font-semibold tracking-wider">Results</h3>
                 <div className={`w-1.5 h-1.5 rounded-full ${isPlaying ? 'bg-[#1ed760] animate-pulse' : 'bg-gray-600'}`}></div>
               </div>
               
               <button 
                 onClick={() => setShowResults(false)}
                 className="text-gray-500 hover:text-white transition-colors"
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
      <div className="h-[100px] bg-[#09090b] border-t border-gray-900 flex items-center px-8 gap-12 shrink-0">
        
        {/* Playback Controls */}
        <div className="flex items-center gap-6">
          <button 
            onClick={() => setCurrentSlot(0)} 
            className="text-gray-400 hover:text-white transition-colors cursor-pointer"
          >
            <SkipBack size={24} />
          </button>
          
          <button 
            onClick={handlePlayToggle} 
            className="w-14 h-14 bg-[#1ed760] text-black rounded-full flex items-center justify-center hover:scale-105 transition-transform cursor-pointer shadow-lg shadow-[#1ed760]/20"
          >
            {isComplete ? (
              <RotateCcw size={24} strokeWidth={2.5} />
            ) : isPlaying ? (
              <Pause size={24} fill="currentColor" />
            ) : (
              <Play size={24} fill="currentColor" className="ml-1" />
            )}
          </button>
          
          <div className="text-sm font-mono text-gray-400 w-24 tracking-widest">
            {String(currentSlot).padStart(4, '0')} <span className="opacity-50">/</span> {n_slots}
          </div>
        </div>

        <div className="h-10 w-px bg-gray-900"></div>

        {/* Configuration Toggles */}
        <div className="flex items-center gap-6 flex-1">
          <div className="flex flex-col gap-1 flex-1 relative max-w-[200px]">
            <label className="text-[10px] uppercase text-gray-500 font-semibold tracking-wider">RF Scenario</label>
            <div className="relative">
              <select 
                value={scenario} 
                onChange={e => setScenario(e.target.value)} 
                className="w-full bg-[#000000] border border-gray-800 rounded-md text-[11px] font-semibold text-white px-3 py-2 outline-none cursor-pointer appearance-none hover:border-[#1ed760] transition-colors pr-8"
              >
                {scenarios.map((s: string) => <option key={s} value={s}>{s.replace(/_/g, ' ').toUpperCase()}</option>)}
              </select>
              <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
            </div>
          </div>

          <div className="flex flex-col gap-1 flex-1 relative max-w-[200px]">
            <label className="text-[10px] uppercase text-gray-500 font-semibold tracking-wider">ML Agent</label>
            <div className="relative">
              <select 
                value={scheduler} 
                onChange={e => setScheduler(e.target.value)} 
                className="w-full bg-[#000000] border border-gray-800 rounded-md text-[11px] font-semibold text-white px-3 py-2 outline-none cursor-pointer appearance-none hover:border-[#1ed760] transition-colors pr-8"
              >
                {schedulers.map((s: string) => <option key={s} value={s}>{s.replace(/_/g, ' ').toUpperCase()}</option>)}
              </select>
              <ChevronDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
            </div>
          </div>

          <div className="flex flex-col gap-1 w-20">
            <label className="text-[10px] uppercase text-gray-500 font-semibold tracking-wider">Seed</label>
            <input 
              type="number" 
              value={seed} 
              onChange={e => setSeed(Number(e.target.value))} 
              className="w-full bg-[#000000] border border-gray-800 rounded-md text-[11px] font-semibold text-white px-3 py-2 outline-none hover:border-[#1ed760] transition-colors" 
            />
          </div>
        </div>

        {/* ML Status Indicator & Settings */}
        <div className="flex items-center gap-6 ml-4">
          <div className="flex flex-col justify-center w-56">
            <div className="flex justify-between text-[10px] uppercase font-bold tracking-wider mb-2">
              <span className="text-gray-400">ML Confidence</span>
              <span className={scheduler === 'round_robin' ? 'opacity-50' : 'text-[#1ed760]'}>
                {scheduler === 'round_robin' ? 'N/A' : `${mlConfidence.toFixed(1)}%`}
              </span>
            </div>
            <div className="w-full h-1.5 bg-[#000000] border border-gray-900 rounded-full overflow-hidden">
              <div 
                className={`h-full transition-all duration-300 ease-linear ${scheduler === 'round_robin' ? 'bg-gray-800 w-0' : 'bg-[#1ed760]'}`} 
                style={{ width: scheduler === 'round_robin' ? '0%' : `${mlConfidence}%` }}
              ></div>
            </div>
          </div>
          
          <button 
            onClick={() => setSettingsOpen(true)}
            className="w-10 h-10 rounded-full bg-[#000000] border border-gray-800 flex items-center justify-center text-gray-400 hover:text-[#1ed760] hover:border-[#1ed760] transition-colors"
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
