import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  BarChart3,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Clock3,
  Crosshair,
  Gauge,
  Layers3,
  LogOut,
  Pause,
  Play,
  Radio,
  RotateCcw,
  Settings,
  ShieldCheck,
  SkipBack,
  SlidersHorizontal,
  TimerReset,
  Zap,
} from 'lucide-react';
import { SettingsModal, type SettingsTab } from './SettingsModal';
import { fetchApi, type SimulationResponse, type SimulationResult } from '../api';
import {
  bandSummaries,
  comparisonRows,
  formatMetric,
  learningBandRows,
  outcomeCounts,
  type BandSummary,
  type ComparisonRow,
  type OutcomeCounts,
} from '../dashboardUtils';
import { dashboardViews, demoAccount, environmentSummary, missionVerdict, performanceSeries, schedulerProfile, threatAssessment, type DashboardView } from '../viewUtils';

interface TerminalDashboardProps {
  scenarios: string[];
  schedulers: string[];
  winSize: number;
  setWinSize: (s: number) => void;
  theme: 'dark' | 'light';
  setTheme: (t: 'dark' | 'light') => void;
}

type RunKey = 'active' | 'baseline' | 'oracle';

const runNames: Record<RunKey, string> = { active: 'Active scheduler', baseline: 'Round-robin baseline', oracle: 'Oracle ceiling' };
const runColors: Record<RunKey, string> = { active: 'text-ew-accent', baseline: 'text-[#f59e0b]', oracle: 'text-[#8b9cff]' };

function signedValue(value: number | null, format: 'percent' | 'number'): string {
  if (value === null || !Number.isFinite(value)) return 'N/A';
  return `${value > 0 ? '+' : ''}${formatMetric(value, format)}`;
}

function deltaClass(row: ComparisonRow): string {
  if (row.delta === null || row.delta === 0) return 'text-ew-text-dim';
  return row.lowerIsBetter ? (row.delta < 0 ? 'text-ew-accent' : 'text-[#ef6b73]') : (row.delta > 0 ? 'text-ew-accent' : 'text-[#ef6b73]');
}

function Panel({ title, eyebrow, icon, action, children, className = '' }: { title: string; eyebrow?: string; icon?: ReactNode; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`rounded-xl border border-ew-border-subtle bg-ew-surface/90 shadow-[0_12px_40px_rgba(0,0,0,0.12)] ${className}`}><div className="flex items-center justify-between gap-3 border-b border-ew-border-subtle px-4 py-3"><div className="flex min-w-0 items-center gap-2">{icon && <span className="text-ew-accent">{icon}</span>}<div className="min-w-0">{eyebrow && <div className="text-[9px] font-semibold uppercase tracking-[0.18em] text-ew-text-dimmer">{eyebrow}</div>}<h2 className="truncate text-[11px] font-semibold uppercase tracking-[0.15em] text-ew-text">{title}</h2></div></div>{action}</div>{children}</section>;
}

function MetricReadout({ label, value, detail, icon }: { label: string; value: string; detail: string; icon: ReactNode }) {
  return <div className="min-w-0 py-2 sm:border-r sm:border-ew-border-subtle sm:px-5 sm:first:pl-0"><div className="flex items-center gap-2 text-ew-accent">{icon}<div className="text-[9px] font-semibold uppercase tracking-[0.17em] text-ew-text-dim">{label}</div></div><div className="mt-2 font-mono text-2xl font-medium tracking-tight text-ew-text">{value}</div><div className="mt-1 text-[10px] text-ew-text-muted">{detail}</div></div>;
}

function MissionBanner({ scenario, active, baseline, oracle }: { scenario: string; active: SimulationResult; baseline: SimulationResult; oracle: SimulationResult }) {
  const profile = schedulerProfile(active.scheduler_name);
  const verdict = missionVerdict(active, baseline, oracle);
  const environment = environmentSummary(scenario, active);
  return (
    <section className="border-b border-ew-border-subtle pb-5">
      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.45fr)_minmax(340px,0.55fr)]">
        <div>
          <div className="mb-2 text-[9px] font-semibold uppercase tracking-[0.2em] text-ew-accent">Active scheduling algorithm</div>
          <h1 className="text-2xl font-semibold tracking-tight text-ew-text md:text-3xl">{profile.label}</h1>
          <p className="mt-2 max-w-3xl text-xs leading-relaxed text-ew-text-muted">{profile.advantage}</p>
          <div className="mt-5 grid gap-3 border-t border-ew-border-subtle pt-4 text-[11px] md:grid-cols-3">
            <div><span className="text-ew-text-muted">Interception achieved</span><span className="ml-2 font-mono text-ew-text">{formatMetric(verdict.activeRatio, 'percent')}</span></div>
            <div><span className="text-ew-text-muted">Gain over round-robin</span><span className={`ml-2 font-mono font-semibold ${verdict.baselineDelta !== null && verdict.baselineDelta >= 0 ? 'text-ew-accent' : 'text-[#ef6b73]'}`}>{signedValue(verdict.baselineDelta, 'percent')}</span></div>
            <div><span className="text-ew-text-muted">Distance from oracle</span><span className="ml-2 font-mono font-semibold text-[#8b9cff]">{signedValue(verdict.oracleGap, 'percent')}</span></div>
          </div>
        </div>
        <aside className="border-t border-ew-border-subtle pt-5 xl:border-l xl:border-t-0 xl:pl-6 xl:pt-0">
          <div className="mb-4 flex items-center gap-2 text-ew-accent"><Layers3 size={15} /><h2 className="text-[11px] font-semibold uppercase tracking-[0.15em] text-ew-text">Environment</h2></div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-4 text-[10px]">
            <div><dt className="uppercase tracking-wider text-ew-text-dimmer">Scenario</dt><dd className="mt-1 text-ew-text">{environment.scenario}</dd></div>
            <div><dt className="uppercase tracking-wider text-ew-text-dimmer">Scale</dt><dd className="mt-1 font-mono text-ew-text">{environment.scale}</dd></div>
            <div><dt className="uppercase tracking-wider text-ew-text-dimmer">Receiver</dt><dd className="mt-1 text-ew-text">{environment.channels}</dd></div>
            <div><dt className="uppercase tracking-wider text-ew-text-dimmer">Threat field</dt><dd className="mt-1 text-ew-text">{environment.emitters}</dd></div>
            <div><dt className="uppercase tracking-wider text-ew-text-dimmer">Detector</dt><dd className="mt-1 text-ew-text">{environment.dwell} / Pfa {formatMetric(active.config.pfa, 'percent')}</dd></div>
            <div><dt className="uppercase tracking-wider text-ew-text-dimmer">Retune</dt><dd className="mt-1 text-ew-text">{environment.retune}</dd></div>
          </dl>
        </aside>
      </div>
    </section>
  );
}

function Waterfall({ result, currentSlot, winSize, onSelectSlot }: { result: SimulationResult; currentSlot: number; winSize: number; onSelectSlot: (slot: number) => void }) {
  const { log } = result;
  const [inspectedCell, setInspectedCell] = useState<{
    slot: number;
    band: number;
    result: string;
    channel: string;
    signal: string;
    emitter: string;
    snr: string;
    sample: string;
    tuning: string;
    reward: string;
  } | null>(null);
  const visibleSlots = Math.max(1, Math.min(winSize, log.n_slots));
  const startSlot = Math.max(0, Math.min(currentSlot - Math.floor(visibleSlots / 2), log.n_slots - visibleSlots));
  const slots = Array.from({ length: visibleSlots }, (_, index) => startSlot + index);
  const bands = Array.from({ length: log.n_bands }, (_, index) => log.n_bands - index - 1);

  return (
    <div className="flex min-h-[560px] h-full w-full flex-col">
      <div className="mb-3 min-h-14 border border-ew-border-subtle bg-ew-bg/70 px-3 py-2">
        {inspectedCell ? (
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[9px] md:grid-cols-5 xl:grid-cols-10">
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Position</span><span className="font-mono text-ew-text">Slot {inspectedCell.slot} / B{inspectedCell.band}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Outcome</span><span className="font-semibold text-ew-accent">{inspectedCell.result}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Receiver</span><span className="text-ew-text">{inspectedCell.channel}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Signal</span><span className="text-ew-text">{inspectedCell.signal}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Emitter</span><span className="text-ew-text">{inspectedCell.emitter}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">SNR</span><span className="font-mono text-ew-text">{inspectedCell.snr}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Sample</span><span className="text-ew-text">{inspectedCell.sample}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Tuning</span><span className="text-ew-text">{inspectedCell.tuning}</span></div>
            <div><span className="block uppercase tracking-wider text-ew-text-dimmer">Reward</span><span className="font-mono text-ew-text">{inspectedCell.reward}</span></div>
            <div className="hidden xl:block"><span className="block uppercase tracking-wider text-ew-text-dimmer">Action</span><span className="text-ew-text-muted">Click to seek</span></div>
          </div>
        ) : (
          <div className="flex h-full items-center text-[10px] text-ew-text-muted">Hover a spectrum cell to inspect the simulated receiver decision. Click a cell to seek.</div>
        )}
      </div>

      <div className="flex min-h-0 flex-1">
        <div className="flex w-10 shrink-0 flex-col pb-6">
          {bands.map(band => <div key={band} className="flex min-h-0 flex-1 items-center justify-end pr-2 font-mono text-[9px] text-ew-text-dim">B{band}</div>)}
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden border-l border-t border-ew-border bg-ew-bg shadow-[inset_0_0_35px_rgba(0,0,0,0.28)]">
            {bands.map(band => (
              <div key={band} className="flex min-h-0 flex-1">
                {slots.map(slot => {
                  const truthOn = log.truth?.[band]?.[slot] ?? false;
                  const channel = log.actions[slot]?.indexOf(band) ?? -1;
                  const scanned = channel >= 0;
                  const detected = scanned && Boolean(log.detections[slot]?.[channel]);
                  const valid = log.valid_slots[slot] !== false;
                  const emitters = (log.emitters ?? result.per_emitter).filter(emitter => emitter.band === band);
                  let outcome = truthOn ? 'UNSCANNED TRANSMISSION' : 'QUIET';
                  let color = 'bg-transparent';
                  if (!valid) { outcome = 'SETTLING'; color = 'bg-[#1b2530]'; }
                  else if (scanned && truthOn && detected) { outcome = 'INTERCEPT'; color = 'bg-ew-accent'; }
                  else if (scanned && truthOn) { outcome = 'MISS'; color = 'bg-[#ef6b73]'; }
                  else if (scanned && detected) { outcome = 'FALSE ALARM'; color = 'bg-[#f59e0b]'; }
                  else if (scanned) { outcome = 'CLEAR SCAN'; color = 'bg-ew-accent/20'; }
                  else if (truthOn) color = 'bg-[#39414d]';
                  const details = {
                    slot,
                    band,
                    result: outcome,
                    channel: scanned ? `Channel ${channel + 1}` : 'Not scanned',
                    signal: truthOn ? 'Emitter active' : 'Quiet',
                    emitter: emitters.length > 0 ? emitters.map(emitter => emitter.type.replace(/_/g, ' ')).join(', ') : 'None configured',
                    snr: emitters.length > 0 ? emitters.map(emitter => emitter.snr === null ? 'N/A' : `${emitter.snr.toFixed(1)} dB`).join(', ') : 'N/A',
                    sample: valid ? 'Valid' : 'Settling',
                    tuning: log.retune_events[slot] ? 'Retune' : 'Stable',
                    reward: (log.per_slot_rewards[slot] ?? 0).toFixed(2),
                  };
                  const title = `Slot ${slot}, Band ${band}: ${outcome}. ${details.channel}. ${details.signal}.`;
                  return (
                    <button key={`${band}-${slot}`} type="button" title={title} aria-label={title} onMouseEnter={() => setInspectedCell(details)} onFocus={() => setInspectedCell(details)} onClick={() => onSelectSlot(slot)} className={`relative flex min-w-0 flex-1 appearance-none items-center justify-center border-b border-r border-ew-border-subtle/60 p-0 transition-[filter,box-shadow] duration-100 hover:z-20 hover:brightness-150 hover:shadow-[inset_0_0_0_1px_rgb(var(--ew-text))] focus:z-20 focus:outline-none focus:ring-1 focus:ring-ew-text ${color} ${slot === currentSlot ? 'z-10 shadow-[inset_2px_0_0_rgb(var(--ew-text)),inset_-2px_0_0_rgb(var(--ew-text))]' : ''}`}>
                      {scanned && !truthOn && !detected && <CircleDot size={5} className="text-ew-accent" />}
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
          <div className="flex h-6 shrink-0 border-l border-ew-border">
            {slots.map(slot => <div key={slot} className={`flex-1 pt-1 text-center font-mono text-[8px] ${slot === currentSlot ? 'text-ew-text' : 'text-ew-text-dimmer'}`}>{slot % 10 === 0 ? slot : ''}</div>)}
          </div>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 text-[9px] font-semibold uppercase tracking-[0.12em] text-ew-text-muted"><span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-sm bg-ew-accent" /> Intercept</span><span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-sm bg-[#ef6b73]" /> Miss</span><span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-sm bg-[#f59e0b]" /> False alarm</span><span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-sm bg-ew-accent/25" /> Clear scan</span><span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-sm bg-[#39414d]" /> Unscanned TX</span><span className="flex items-center gap-1.5"><i className="h-2 w-2 rounded-sm bg-[#1b2530]" /> Settling</span></div>
    </div>
  );
}

function TimelineControls({ result, currentSlot, setCurrentSlot, isPlaying, setIsPlaying }: { result: SimulationResult; currentSlot: number; setCurrentSlot: (slot: number) => void; isPlaying: boolean; setIsPlaying: (playing: boolean) => void }) {
  const isComplete = currentSlot >= result.log.n_slots - 1;
  const toggle = () => { if (isComplete) { setCurrentSlot(0); setIsPlaying(true); } else setIsPlaying(!isPlaying); };
  return <div className="border-t border-ew-border-subtle bg-ew-bg/40 p-4"><div className="flex items-center gap-3"><button onClick={() => setCurrentSlot(0)} title="Reset playback" className="text-ew-text-muted transition-colors hover:text-ew-text"><SkipBack size={18} /></button><button onClick={toggle} title={isPlaying ? 'Pause playback' : 'Play playback'} className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-ew-accent text-black shadow-[0_0_20px_rgba(30,215,96,0.2)] transition-transform hover:scale-105">{isComplete ? <RotateCcw size={17} /> : isPlaying ? <Pause size={17} fill="currentColor" /> : <Play size={17} fill="currentColor" className="ml-0.5" />}</button><input aria-label="Timeline position" type="range" min={0} max={Math.max(0, result.log.n_slots - 1)} value={currentSlot} onChange={event => setCurrentSlot(Number(event.target.value))} className="h-1.5 min-w-0 flex-1 accent-ew-accent" /><span className="w-24 text-right font-mono text-[11px] tracking-wider text-ew-text-muted">{String(currentSlot).padStart(4, '0')} <span className="text-ew-text-dimmer">/</span> {result.log.n_slots.toLocaleString()}</span></div><div className="mt-2 flex items-center justify-between text-[9px] uppercase tracking-wider text-ew-text-dimmer"><span>Replay timeline</span><span>{isPlaying ? 'Running' : 'Paused'} / 100ms step</span></div></div>;
}

function EventFeed({ result, currentSlot }: { result: SimulationResult; currentSlot: number }) {
  const events: Array<{ slot: number; band: number; label: string; tone: string }> = [];
  const truth = result.log.truth;
  for (let slot = Math.max(0, currentSlot - 18); slot <= currentSlot; slot += 1) result.log.actions[slot]?.forEach((band, channel) => { const tx = truth?.[band]?.[slot] ?? false; const detected = Boolean(result.log.detections[slot]?.[channel]); const label = tx && detected ? 'INTERCEPT' : tx ? 'MISS' : detected ? 'FALSE ALARM' : 'CLEAR'; const tone = tx && detected ? 'text-ew-accent' : tx ? 'text-[#ef6b73]' : detected ? 'text-[#f59e0b]' : 'text-ew-text-dim'; events.push({ slot, band, label, tone }); });
  return <div className="max-h-[270px] overflow-y-auto p-3 scrollbar-hide">{events.reverse().map((event, index) => <div key={`${event.slot}-${event.band}-${index}`} className="flex items-center gap-2 border-b border-ew-border-subtle/70 py-2 font-mono text-[10px] last:border-0"><span className="text-ew-text-dimmer">{String(event.slot).padStart(4, '0')}</span><span className="text-ew-text-muted">B{event.band}</span><span className={`ml-auto font-semibold tracking-[0.1em] ${event.tone}`}>{event.label}</span></div>)}</div>;
}

function OutcomeDonut({ counts, currentSlot, totalSlots }: { counts: OutcomeCounts; currentSlot: number; totalSlots: number }) {
  const observedTotal = counts.hits + counts.misses + counts.falseAlarms + counts.idle;
  const total = observedTotal || 1;
  const needleAngle = totalSlots > 1 ? (currentSlot / (totalSlots - 1)) * 360 : 0;
  const items = [
    { label: 'Hits', value: counts.hits, color: 'bg-ew-accent', chartColor: 'rgb(var(--ew-accent))' },
    { label: 'Misses', value: counts.misses, color: 'bg-[#ef6b73]', chartColor: '#ef6b73' },
    { label: 'False alarms', value: counts.falseAlarms, color: 'bg-[#f59e0b]', chartColor: '#f59e0b' },
    { label: 'Clear', value: counts.idle, color: 'bg-[#64748b]', chartColor: '#64748b' },
  ];
  let position = 0;
  const segments = items.map(item => {
    const start = position;
    position += (item.value / total) * 100;
    return `${item.chartColor} ${start}% ${position}%`;
  });
  return (
    <div className="flex flex-wrap items-center gap-6">
      <div role="img" aria-label={`${counts.hits} hits, ${counts.misses} misses, ${counts.falseAlarms} false alarms, ${counts.idle} clear scans through slot ${currentSlot}`} className="relative h-36 w-36 shrink-0 rounded-full" style={{ background: observedTotal > 0 ? `conic-gradient(${segments.join(', ')})` : 'rgb(var(--ew-bg))' }}>
        <div className="pointer-events-none absolute -inset-1 z-10 rounded-full transition-transform duration-100 ease-linear" style={{ background: 'conic-gradient(from -3deg, rgb(var(--ew-text)) 0deg 6deg, transparent 6deg 360deg)', WebkitMaskImage: 'radial-gradient(circle, transparent 68%, black 70%)', maskImage: 'radial-gradient(circle, transparent 68%, black 70%)', transform: `rotate(${needleAngle}deg)` }} />
        <div className="absolute inset-8 flex flex-col items-center justify-center rounded-full bg-ew-surface">
          <span className="font-mono text-xl text-ew-text">{observedTotal.toLocaleString()}</span>
          <span className="text-[8px] uppercase tracking-wider text-ew-text-dimmer">Scans</span>
        </div>
      </div>
      <div className="grid min-w-[180px] flex-1 grid-cols-2 gap-4">
        {items.map(item => <div key={item.label} className="flex items-center gap-2"><span className={`h-2.5 w-2.5 shrink-0 rounded-sm ${item.color}`} /><div><div className="font-mono text-sm text-ew-text">{item.value.toLocaleString()}</div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">{item.label}</div></div></div>)}
      </div>
    </div>
  );
}

function ScannerState({ result, currentSlot }: { result: SimulationResult; currentSlot: number }) {
  const scannedBands = (result.log.actions[currentSlot] ?? []).map(band => `B${band}`).join(' / ') || 'N/A';
  const settling = result.log.settling_slots[currentSlot];
  const retuning = result.log.retune_events[currentSlot];
  return (
    <section className="py-2 xl:border-l xl:border-ew-border-subtle xl:pl-8">
      <div className="mb-4 flex items-center gap-2 text-ew-accent"><Activity size={15} /><h2 className="text-[11px] font-semibold uppercase tracking-[0.15em] text-ew-text">Scanner state</h2></div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-3">
        <div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Slot</div><div className="mt-1 font-mono text-sm text-ew-text">{String(currentSlot).padStart(4, '0')}</div></div>
        <div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Bands</div><div className="mt-1 font-mono text-sm text-ew-accent">{scannedBands}</div></div>
        <div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Sample</div><div className={`mt-1 font-mono text-sm ${settling ? 'text-[#f59e0b]' : 'text-ew-accent'}`}>{settling ? 'SETTLING' : 'VALID'}</div></div>
        <div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Tuning</div><div className="mt-1 font-mono text-sm text-ew-text">{retuning ? 'RETUNE' : 'STABLE'}</div></div>
      </div>
    </section>
  );
}

function BandAllocation({ summaries }: { summaries: BandSummary[] }) {
  const maxScans = Math.max(1, ...summaries.map(summary => summary.scans));
  return <div className="space-y-2.5 p-4">{summaries.map(summary => <div key={summary.band} className="grid grid-cols-[28px_1fr_34px] items-center gap-2"><span className="font-mono text-[10px] text-ew-text-muted">B{summary.band}</span><div className="h-2 overflow-hidden rounded-full bg-ew-bg"><div className="h-full rounded-full bg-ew-accent/75" style={{ width: `${(summary.scans / maxScans) * 100}%` }} /></div><span className="text-right font-mono text-[10px] text-ew-text-muted">{summary.scans}</span></div>)}</div>;
}

function LearningState({ result, currentSlot }: { result: SimulationResult; currentSlot: number }) {
  const rows = learningBandRows(result, currentSlot);
  if (!result.learning || rows.length === 0) return null;
  const metric = result.learning.metric.replace(/_/g, ' ');
  return (
    <Panel title="Online learning state" eyebrow={`${metric} / after hit and miss updates`} icon={<Activity size={15} />} action={<span className="font-mono text-[9px] text-ew-text-dimmer">SLOT {String(currentSlot).padStart(4, '0')}</span>}>
      <div className="grid gap-x-6 gap-y-2 p-4 md:grid-cols-2">
        {rows.map(row => <div key={row.band} className="grid grid-cols-[30px_1fr_48px_70px] items-center gap-2"><span className="font-mono text-[10px] text-ew-text-muted">B{row.band}</span><div className="h-2 overflow-hidden rounded-full bg-ew-bg"><div className="h-full rounded-full bg-ew-accent/80 transition-[width] duration-200" style={{ width: `${Math.max(0, Math.min(100, row.value * 100))}%` }} /></div><span className="text-right font-mono text-[10px] text-ew-text">{formatMetric(row.value, 'percent')}</span><span className="text-right font-mono text-[9px] text-ew-text-dimmer">{row.detections}/{row.scans} hits</span></div>)}
      </div>
    </Panel>
  );
}

function LiveScreen({ active, baseline, oracle, focusRun, setFocusRun, currentSlot, setCurrentSlot, isPlaying, setIsPlaying, winSize, onOpenScannerSettings }: { active: SimulationResult; baseline: SimulationResult; oracle: SimulationResult; focusRun: RunKey; setFocusRun: (run: RunKey) => void; currentSlot: number; setCurrentSlot: (slot: number) => void; isPlaying: boolean; setIsPlaying: (playing: boolean) => void; winSize: number; onOpenScannerSettings: () => void }) {
  const runs = { active, baseline, oracle };
  const focused = runs[focusRun];
  const counts = outcomeCounts(focused, currentSlot);
  return (
    <div className="space-y-5">
      <Panel title="Spectrum timeline" eyebrow={`${runNames[focusRun]} / slot ${String(currentSlot).padStart(4, '0')}`} icon={<Radio size={15} />} action={<div className="flex items-center gap-2"><button onClick={onOpenScannerSettings} className="flex h-7 items-center gap-1.5 rounded border border-ew-border-subtle px-2 text-[9px] font-semibold uppercase tracking-wider text-ew-text-muted transition-colors hover:border-ew-accent hover:text-ew-accent"><SlidersHorizontal size={12} /><span className="hidden sm:inline">Scanner settings</span></button><div className="flex rounded-md border border-ew-border-subtle bg-ew-bg p-0.5">{(['active', 'baseline', 'oracle'] as RunKey[]).map(run => <button key={run} onClick={() => setFocusRun(run)} className={`rounded px-2 py-1 text-[9px] font-semibold uppercase tracking-wider transition-colors ${focusRun === run ? `bg-ew-surface ${runColors[run]}` : 'text-ew-text-dimmer hover:text-ew-text'}`}>{run === 'baseline' ? 'Base' : run}</button>)}</div></div>}>
        <div className="p-4 md:p-5"><Waterfall result={focused} currentSlot={currentSlot} winSize={winSize} onSelectSlot={setCurrentSlot} /></div>
        <TimelineControls result={focused} currentSlot={currentSlot} setCurrentSlot={setCurrentSlot} isPlaying={isPlaying} setIsPlaying={setIsPlaying} />
      </Panel>

      <LearningState result={focused} currentSlot={currentSlot} />

      <div className="grid grid-cols-1 gap-6 border-b border-ew-border-subtle pb-5 lg:grid-cols-[minmax(320px,0.8fr)_minmax(0,1.2fr)]">
        <section>
          <div className="mb-5 flex items-center gap-2 text-ew-accent"><Crosshair size={15} /><div><div className="text-[9px] font-semibold uppercase tracking-[0.18em] text-ew-text-dimmer">{runNames[focusRun]} / valid samples</div><h2 className="text-[11px] font-semibold uppercase tracking-[0.15em] text-ew-text">Scan outcomes</h2></div></div>
          <OutcomeDonut counts={counts} currentSlot={currentSlot} totalSlots={focused.log.n_slots} />
        </section>
        <section className="border-t border-ew-border-subtle pt-5 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
          <div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2 text-ew-accent"><CircleDot size={15} /><div><div className="text-[9px] font-semibold uppercase tracking-[0.18em] text-ew-text-dimmer">Recent receiver activity</div><h2 className="text-[11px] font-semibold uppercase tracking-[0.15em] text-ew-text">Event feed</h2></div></div><span className="font-mono text-[9px] text-ew-text-dimmer">LAST 19</span></div>
          <EventFeed result={focused} currentSlot={currentSlot} />
        </section>
      </div>
    </div>
  );
}

function PerformanceBars({ active, baseline, oracle }: { active: SimulationResult; baseline: SimulationResult; oracle: SimulationResult }) {
  const series = performanceSeries(active, baseline, oracle);
  const runs = [
    { key: 'active' as const, label: 'Active', color: 'bg-ew-accent' },
    { key: 'baseline' as const, label: 'Baseline', color: 'bg-[rgb(var(--ew-warning))]' },
    { key: 'oracle' as const, label: 'Oracle', color: 'bg-[rgb(var(--ew-reference))]' },
  ];
  return <div className="space-y-5 p-5">{series.map(metric => <div key={metric.label}><div className="mb-2 flex items-center justify-between"><span className="text-[10px] font-semibold uppercase tracking-wider text-ew-text">{metric.label}</span><span className="text-[9px] text-ew-text-dimmer">Higher is better</span></div><div className="space-y-2">{runs.map(run => <div key={run.key} className="grid grid-cols-[58px_1fr_44px] items-center gap-2"><span className="text-[9px] uppercase text-ew-text-muted">{run.label}</span><div className="h-2.5 bg-ew-bg"><div className={`h-full transition-[width] duration-500 ${run.color}`} style={{ width: `${Math.max(0, Math.min(100, (metric[run.key] ?? 0) * 100))}%` }} /></div><span className="text-right font-mono text-[9px] text-ew-text">{formatMetric(metric[run.key], 'percent')}</span></div>)}</div></div>)}</div>;
}

function RewardTrend({ active, baseline }: { active: SimulationResult; baseline: SimulationResult }) {
  const cumulative = (values: number[]) => {
    let total = 0;
    return values.map(value => (total += value));
  };
  const activeValues = cumulative(active.log.per_slot_rewards);
  const baselineValues = cumulative(baseline.log.per_slot_rewards);
  const allValues = [...activeValues, ...baselineValues, 0];
  const minimum = Math.min(...allValues);
  const maximum = Math.max(...allValues);
  const range = maximum - minimum || 1;
  const points = (values: number[]) => {
    const step = Math.max(1, Math.ceil(values.length / 60));
    const sampled = values.filter((_, index) => index % step === 0 || index === values.length - 1);
    return sampled.map((value, index) => `${(index / Math.max(1, sampled.length - 1)) * 100},${34 - ((value - minimum) / range) * 30}`).join(' ');
  };
  return <div className="p-5"><svg role="img" aria-label="Cumulative reward trend for active and baseline schedulers" viewBox="0 0 100 38" preserveAspectRatio="none" className="h-48 w-full overflow-visible"><line x1="0" y1="34" x2="100" y2="34" stroke="rgb(var(--ew-border))" strokeWidth="0.4" /><line x1="0" y1="19" x2="100" y2="19" stroke="rgb(var(--ew-border-subtle))" strokeWidth="0.3" /><polyline points={points(baselineValues)} fill="none" stroke="rgb(var(--ew-warning))" strokeWidth="1" vectorEffect="non-scaling-stroke" /><polyline points={points(activeValues)} fill="none" stroke="rgb(var(--ew-accent))" strokeWidth="1.5" vectorEffect="non-scaling-stroke" /></svg><div className="mt-3 flex items-center justify-between text-[9px] uppercase tracking-wider"><span className="text-ew-text-dimmer">Slot 0</span><div className="flex gap-4"><span className="text-ew-accent">Active {formatMetric(active.metrics.total_reward, 'number')}</span><span className="text-[rgb(var(--ew-warning))]">Baseline {formatMetric(baseline.metrics.total_reward, 'number')}</span></div><span className="text-ew-text-dimmer">Slot {active.log.n_slots.toLocaleString()}</span></div></div>;
}

function PerformanceScreen({ scenario, active, baseline, oracle }: { scenario: string; active: SimulationResult; baseline: SimulationResult; oracle: SimulationResult }) {
  const rows = comparisonRows(active, baseline, oracle);
  const bars = rows.slice(0, 4);
  return <div className="space-y-5"><MissionBanner scenario={scenario} active={active} baseline={baseline} oracle={oracle} /><div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]"><Panel title="Performance comparison" eyebrow="Mission capture against references" icon={<BarChart3 size={15} />}><PerformanceBars active={active} baseline={baseline} oracle={oracle} /></Panel><Panel title="Cumulative reward" eyebrow="Decision value across the episode" icon={<Activity size={15} />}><RewardTrend active={active} baseline={baseline} /></Panel></div><Panel title="Figures of merit" eyebrow="Active scheduler against references" icon={<BarChart3 size={15} />}><ComparisonTable rows={rows} /></Panel><div className="grid grid-cols-1 gap-5 lg:grid-cols-3"><Panel title="Detector" eyebrow="Sensor quality" icon={<Gauge size={15} />}><div className="grid grid-cols-2 gap-px bg-ew-border-subtle"><div className="bg-ew-surface p-4"><div className="text-[9px] uppercase text-ew-text-dimmer">Requested Pfa</div><div className="mt-1 font-mono text-lg text-ew-text">{formatMetric(active.detector.requested_pfa, 'percent')}</div></div><div className="bg-ew-surface p-4"><div className="text-[9px] uppercase text-ew-text-dimmer">Effective Pfa</div><div className="mt-1 font-mono text-lg text-ew-text">{formatMetric(active.detector.effective_pfa, 'percent')}</div></div><div className="bg-ew-surface p-4"><div className="text-[9px] uppercase text-ew-text-dimmer">Threshold</div><div className="mt-1 font-mono text-lg text-ew-text">{formatMetric(active.detector.threshold, 'number')}</div></div><div className="bg-ew-surface p-4"><div className="text-[9px] uppercase text-ew-text-dimmer">Sensitivity</div><div className="mt-1 font-mono text-lg text-ew-text">{active.metrics.sensitivity === null ? 'N/A' : `${active.metrics.sensitivity.toFixed(1)} dB`}</div></div></div></Panel><Panel title="Reward" eyebrow="Decision economics" icon={<Zap size={15} />}><div className="space-y-4 p-4">{[['Hit reward', active.metrics.hit_reward, 'text-ew-accent'], ['Miss cost', active.metrics.miss_cost, 'text-[#ef6b73]'], ['Novelty bonus', active.metrics.novelty_bonus, 'text-ew-text'], ['Retune penalty', active.metrics.retune_penalty, 'text-[#f59e0b]']].map(([label, value, color]) => <div key={String(label)} className="flex items-center justify-between border-b border-ew-border-subtle pb-3 last:border-0 last:pb-0"><span className="text-[10px] text-ew-text-muted">{label}</span><span className={`font-mono text-sm ${color}`}>{formatMetric(value as number | null, 'number')}</span></div>)}</div></Panel><Panel title="Timing" eyebrow="Latency and bursts" icon={<Clock3 size={15} />}><div className="space-y-4 p-4">{[['Mean TTFI', active.metrics.mean_ttfi, 'slots'], ['Penalized TTFI', active.metrics.ttfi_penalized, 'slots'], ['Time error', active.metrics.time_error, 'slots'], ['Burst interception', active.metrics.burst_interception_ratio, '']].map(([label, value, suffix]) => <div key={String(label)} className="flex items-center justify-between border-b border-ew-border-subtle pb-3 last:border-0 last:pb-0"><span className="text-[10px] text-ew-text-muted">{label}</span><span className="font-mono text-sm text-ew-text">{formatMetric(value as number | null, suffix === '%' ? 'percent' : String(label).includes('interception') ? 'percent' : 'number')} {suffix}</span></div>)}</div></Panel></div><Panel title="Comparison bars" eyebrow="Relative performance" icon={<ShieldCheck size={15} />}><div className="grid gap-5 p-5 md:grid-cols-2">{bars.map(row => <div key={row.key}><div className="mb-2 flex items-center justify-between text-[10px]"><span className="text-ew-text-muted">{row.label}</span><span className={`font-mono font-semibold ${deltaClass(row)}`}>{signedValue(row.delta, row.format === 'percent' ? 'percent' : 'number')} vs base</span></div><div className="space-y-1.5"><div className="flex items-center gap-2"><span className="w-14 text-[9px] uppercase text-ew-accent">Active</span><div className="h-2 flex-1 rounded-full bg-ew-bg"><div className="h-full rounded-full bg-ew-accent" style={{ width: `${Math.min(100, Math.max(0, (row.active ?? 0) * (row.format === 'percent' ? 100 : 1)))}%` }} /></div></div><div className="flex items-center gap-2"><span className="w-14 text-[9px] uppercase text-[#8b9cff]">Oracle</span><div className="h-2 flex-1 rounded-full bg-ew-bg"><div className="h-full rounded-full bg-[#8b9cff]" style={{ width: `${Math.min(100, Math.max(0, (row.oracle ?? 0) * (row.format === 'percent' ? 100 : 1)))}%` }} /></div></div></div></div>)}</div></Panel></div>;
}

function ComparisonTable({ rows }: { rows: ComparisonRow[] }) {
  return <div className="overflow-x-auto"><table className="w-full min-w-[640px] border-collapse text-left"><thead><tr className="border-b border-ew-border-subtle text-[9px] uppercase tracking-[0.16em] text-ew-text-dimmer"><th className="px-4 py-2.5 font-semibold">Figure of merit</th><th className="px-3 py-2.5 text-right font-semibold text-ew-accent">Active</th><th className="px-3 py-2.5 text-right font-semibold text-[#f59e0b]">Baseline</th><th className="px-3 py-2.5 text-right font-semibold text-[#8b9cff]">Oracle</th><th className="px-4 py-2.5 text-right font-semibold">Δ vs base</th></tr></thead><tbody>{rows.map(row => <tr key={row.key} className="border-b border-ew-border-subtle/70 last:border-0 hover:bg-ew-bg/40"><td className="px-4 py-2.5 text-[11px] text-ew-text-secondary">{row.label}{row.lowerIsBetter && <span className="ml-2 text-[9px] text-ew-text-dimmer">LOW</span>}</td><td className="px-3 py-2.5 text-right font-mono text-[11px] text-ew-text">{formatMetric(row.active, row.format)}</td><td className="px-3 py-2.5 text-right font-mono text-[11px] text-ew-text-muted">{formatMetric(row.baseline, row.format)}</td><td className="px-3 py-2.5 text-right font-mono text-[11px] text-[#aeb9ff]">{formatMetric(row.oracle, row.format)}</td><td className={`px-4 py-2.5 text-right font-mono text-[11px] font-semibold ${deltaClass(row)}`}>{signedValue(row.delta, row.format === 'percent' ? 'percent' : 'number')}</td></tr>)}</tbody></table></div>;
}

function ThreatSituation({ result, scenario }: { result: SimulationResult; scenario: string }) {
  const assessment = threatAssessment(result);
  const postureTone = assessment.posture === 'CRITICAL' ? 'text-[rgb(var(--ew-danger))]' : assessment.posture === 'ELEVATED' ? 'text-[rgb(var(--ew-warning))]' : 'text-ew-accent';
  return <section className="border-y border-[rgb(var(--ew-danger)/0.35)] bg-[linear-gradient(90deg,rgb(var(--ew-danger)/0.1),transparent_62%)] px-5 py-4"><div className="flex flex-wrap items-start justify-between gap-4"><div><div className="flex items-center gap-2 text-[rgb(var(--ew-danger))]"><AlertTriangle size={17} /><span className="text-[9px] font-semibold uppercase tracking-[0.2em]">Threat picture / {scenario.replace(/_/g, ' ')}</span></div><div className={`mt-2 text-2xl font-semibold tracking-wide ${postureTone}`}>{assessment.posture}</div><p className="mt-1 text-[11px] text-ew-text-muted">Receiver exposure based on missed transmissions, emitter priority, and burst containment.</p></div><div className="grid grid-cols-2 gap-x-8 gap-y-3 sm:grid-cols-4"><div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Missed transmissions</div><div className="mt-1 font-mono text-xl text-[rgb(var(--ew-danger))]">{assessment.missedTransmissions.toLocaleString()}</div></div><div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Uncontained emitters</div><div className="mt-1 font-mono text-xl text-[rgb(var(--ew-warning))]">{assessment.uncontainedEmitters}</div></div><div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Strongest signal</div><div className="mt-1 font-mono text-xl text-ew-text">{assessment.highestSnr === null ? 'N/A' : `${assessment.highestSnr.toFixed(1)} dB`}</div></div><div><div className="text-[9px] uppercase tracking-wider text-ew-text-dimmer">Exposed bursts</div><div className="mt-1 font-mono text-xl text-[rgb(var(--ew-danger))]">{assessment.exposedBursts}</div></div></div></div></section>;
}

function EmitterThreatCards({ result, summaries }: { result: SimulationResult; summaries: BandSummary[] }) {
  return <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{result.per_emitter.map(emitter => {
    const containment = emitter.interception_ratio ?? 0;
    const missed = Math.max(0, emitter.transmissions - emitter.interception_hits);
    const critical = (emitter.threat ?? 0) >= 0.8 && containment < 0.5;
    const severity = critical ? 'CRITICAL' : containment < 0.5 ? 'HIGH' : 'TRACKED';
    const tone = critical ? 'border-[rgb(var(--ew-danger))] text-[rgb(var(--ew-danger))]' : containment < 0.5 ? 'border-[rgb(var(--ew-warning))] text-[rgb(var(--ew-warning))]' : 'border-ew-accent text-ew-accent';
    return <article key={emitter.index} className={`border-l-2 bg-ew-surface px-4 py-3 ${tone}`}><div className="flex items-start justify-between gap-3"><div><div className="text-[9px] font-semibold uppercase tracking-[0.16em]">{severity} / BAND {emitter.band}</div><h3 className="mt-1 text-sm font-semibold uppercase text-ew-text">{emitter.type.replace(/_/g, ' ')}</h3></div><span className="font-mono text-xs">{emitter.snr?.toFixed(1) ?? 'N/A'} dB</span></div><div className="mt-4 grid grid-cols-3 gap-3"><div><div className="text-[8px] uppercase text-ew-text-dimmer">Priority</div><div className="mt-1 font-mono text-xs text-ew-text">{emitter.threat?.toFixed(2) ?? 'N/A'}</div></div><div><div className="text-[8px] uppercase text-ew-text-dimmer">Occupancy</div><div className="mt-1 font-mono text-xs text-ew-text">{formatMetric(summaries[emitter.band]?.occupancy ?? null, 'percent')}</div></div><div><div className="text-[8px] uppercase text-ew-text-dimmer">Missed</div><div className="mt-1 font-mono text-xs text-[rgb(var(--ew-danger))]">{missed}</div></div></div><div className="mt-4"><div className="mb-1 flex justify-between text-[8px] uppercase tracking-wider text-ew-text-dimmer"><span>Containment</span><span>{formatMetric(containment, 'percent')}</span></div><div className="h-1.5 bg-ew-bg"><div className={`h-full ${containment < 0.5 ? 'bg-[rgb(var(--ew-danger))]' : 'bg-ew-accent'}`} style={{ width: `${containment * 100}%` }} /></div></div></article>;
  })}</div>;
}

function ThreatsScreen({ scenario, active, baseline, oracle, focusRun, setFocusRun }: { scenario: string; active: SimulationResult; baseline: SimulationResult; oracle: SimulationResult; focusRun: RunKey; setFocusRun: (run: RunKey) => void }) {
  const focused = { active, baseline, oracle }[focusRun];
  const summaries = bandSummaries(focused);
  return <div className="space-y-5"><ThreatSituation result={focused} scenario={scenario} /><EmitterThreatCards result={focused} summaries={summaries} /><Panel title="Threat register" eyebrow={`${runNames[focusRun]} / electronic order of battle`} icon={<AlertTriangle size={15} />} action={<div className="flex rounded-md border border-ew-border-subtle bg-ew-bg p-0.5">{(['active', 'baseline', 'oracle'] as RunKey[]).map(run => <button key={run} onClick={() => setFocusRun(run)} className={`rounded px-2 py-1 text-[9px] font-semibold uppercase tracking-wider ${focusRun === run ? `bg-ew-surface ${runColors[run]}` : 'text-ew-text-dimmer'}`}>{run === 'baseline' ? 'Base' : run}</button>)}</div>}><div className="overflow-x-auto"><table className="w-full min-w-[850px] border-collapse text-left"><thead><tr className="border-b border-ew-border-subtle text-[9px] uppercase tracking-[0.15em] text-ew-text-dimmer"><th className="px-4 py-2.5 font-semibold">Emitter</th><th className="px-3 py-2.5 text-right font-semibold">Threat</th><th className="px-3 py-2.5 text-right font-semibold">SNR</th><th className="px-3 py-2.5 text-right font-semibold">Occupancy</th><th className="px-3 py-2.5 text-right font-semibold">Pd</th><th className="px-3 py-2.5 text-right font-semibold">Intercept</th><th className="px-3 py-2.5 text-right font-semibold">First slot</th><th className="px-4 py-2.5 text-right font-semibold">Bursts</th></tr></thead><tbody>{focused.per_emitter.map(emitter => <tr key={emitter.index} className="border-b border-ew-border-subtle/70 last:border-0 hover:bg-ew-bg/40"><td className="px-4 py-3"><div className="flex items-center gap-2"><span className="flex h-6 w-6 items-center justify-center rounded bg-ew-accent/10 font-mono text-[9px] text-ew-accent">B{emitter.band}</span><div><div className="text-[11px] font-semibold uppercase text-ew-text">{emitter.type.replace(/_/g, ' ')}</div><div className="text-[9px] text-ew-text-dimmer">Emitter {String(emitter.index + 1).padStart(2, '0')}</div></div></div></td><td className="px-3 py-3 text-right font-mono text-[11px] text-[#f59e0b]">{emitter.threat?.toFixed(2) ?? 'N/A'}</td><td className="px-3 py-3 text-right font-mono text-[11px] text-ew-text-muted">{emitter.snr?.toFixed(1) ?? 'N/A'} dB</td><td className="px-3 py-3 text-right font-mono text-[11px] text-ew-text-muted">{formatMetric(summaries[emitter.band]?.occupancy ?? null, 'percent')}</td><td className="px-3 py-3 text-right font-mono text-[11px] text-ew-text">{formatMetric(emitter.pd, 'percent')}</td><td className="px-3 py-3 text-right font-mono text-[11px] text-ew-text">{formatMetric(emitter.interception_ratio, 'percent')}</td><td className="px-3 py-3 text-right font-mono text-[11px] text-ew-text-muted">{emitter.first_intercept_slot ?? '—'}</td><td className="px-4 py-3 text-right font-mono text-[11px] text-ew-text-muted">{emitter.n_intercepted_bursts}/{emitter.n_bursts}</td></tr>)}</tbody></table></div></Panel><div className="grid grid-cols-1 gap-5 lg:grid-cols-[minmax(0,1.2fr)_minmax(300px,0.8fr)]"><Panel title="Band allocation" eyebrow="Receiver scan concentration" icon={<Layers3 size={15} />} action={<span className="font-mono text-[9px] text-ew-text-dimmer">{runNames[focusRun]}</span>}><BandAllocation summaries={summaries} /></Panel><Panel title="Threat reading guide" eyebrow="How to read the board" icon={<ShieldCheck size={15} />}><div className="space-y-3 p-4 text-[11px] leading-relaxed text-ew-text-muted"><p><span className="text-ew-text">Threat</span> is configured mission priority.</p><p><span className="text-ew-text">Occupancy</span> is how often a band transmits in the scenario.</p><p><span className="text-ew-text">Pd</span> measures detector success when that emitter is scanned while transmitting.</p><p><span className="text-ew-text">Intercept</span> measures the share of the emitter's transmissions captured by the scheduler.</p></div></Panel></div></div>;
}

export const TerminalDashboard = ({ scenarios, schedulers, winSize, setWinSize, theme, setTheme }: TerminalDashboardProps) => {
  const [scenario, setScenario] = useState('contested_spectrum');
  const [scheduler, setScheduler] = useState('sniper');
  const [seed, setSeed] = useState(42);
  const [k, setK] = useState(1);
  const [simulationData, setSimulationData] = useState<SimulationResponse | null>(null);
  const [currentSlot, setCurrentSlot] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<DashboardView>('live');
  const [focusRun, setFocusRun] = useState<RunKey>('active');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>('Display');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(true);
  const mainRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const controller = new AbortController();
    const fetchSim = async () => {
      setLoading(true);
      try {
        const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const data = await fetchApi<SimulationResponse>(`${apiBase}/api/simulate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario_name: scenario, scheduler_name: scheduler, seed, k, debug: true }), signal: controller.signal });
        if (!controller.signal.aborted) { setSimulationData(data); setError(null); setCurrentSlot(0); setFocusRun('active'); setIsPlaying(false); mainRef.current?.scrollTo({ top: 0 }); }
      } catch (err) { if (err instanceof DOMException && err.name === 'AbortError') return; setError(err instanceof Error ? err.message : 'Simulation request failed.'); }
      finally { if (!controller.signal.aborted) setLoading(false); }
    };
    const timer = setTimeout(fetchSim, 50);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [scenario, scheduler, seed, k]);

  useEffect(() => {
    if (!isPlaying || !simulationData) return undefined;
    const timer = setTimeout(() => { if (currentSlot >= simulationData.active.log.n_slots - 1) setIsPlaying(false); else setCurrentSlot(slot => slot + 1); }, 100);
    return () => clearTimeout(timer);
  }, [currentSlot, isPlaying, simulationData]);

  if (loading) return <div className="flex h-screen w-full items-center justify-center bg-ew-bg font-mono text-sm tracking-[0.2em] text-ew-accent">BUILDING RECEIVER PICTURE...</div>;
  if (error || !simulationData) return <div className="flex h-screen w-full items-center justify-center bg-ew-bg font-mono text-sm tracking-[0.15em] text-[#ef4444]">{error ?? 'No simulation data available.'}</div>;

  const { active, baseline, oracle } = simulationData;
  const openSettings = (tab: SettingsTab) => {
    setSettingsTab(tab);
    setSettingsOpen(true);
  };
  const sidebarExpanded = !sidebarCollapsed;

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-ew-bg text-ew-text-secondary">
      <SettingsModal
        key={`${settingsTab}-${settingsOpen}`}
        isOpen={settingsOpen}
        initialTab={settingsTab}
        onClose={() => setSettingsOpen(false)}
        scenarios={scenarios}
        schedulers={schedulers}
        scenario={scenario}
        setScenario={setScenario}
        scheduler={scheduler}
        setScheduler={setScheduler}
        seed={seed}
        setSeed={setSeed}
        k={k}
        setK={setK}
        maxBands={active.config.n_bands}
        winSize={winSize}
        setWinSize={setWinSize}
        theme={theme}
        setTheme={setTheme}
      />

      <header className="flex h-14 shrink-0 items-center justify-between bg-ew-bg/95 px-4 backdrop-blur md:px-6">
        <span className="text-lg font-bold tracking-[0.08em] text-ew-text">E-WAVE</span>
        <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-ew-text-dimmer">Input: simulated data</span>
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className={`flex shrink-0 flex-col border-r border-ew-border-subtle bg-ew-surface/70 transition-[width] duration-200 ${sidebarExpanded ? 'w-16 md:w-56' : 'w-16'}`}>
          <nav className="flex flex-1 flex-col gap-1 p-2" aria-label="Dashboard views">
            {dashboardViews.map(item => {
              const icon = item.key === 'live' ? <Radio size={17} /> : item.key === 'performance' ? <BarChart3 size={17} /> : <AlertTriangle size={17} />;
              return (
                <button key={item.key} onClick={() => setView(item.key)} title={item.label} className={`flex h-11 items-center gap-3 rounded-md px-3 text-sm transition-colors ${view === item.key ? 'bg-ew-accent text-black' : 'text-ew-text-muted hover:bg-ew-bg hover:text-ew-text'}`}>
                  <span className="shrink-0">{icon}</span>
                  <span className={`${sidebarExpanded ? 'hidden md:inline' : 'hidden'} whitespace-nowrap font-medium`}>{item.label}</span>
                </button>
              );
            })}
          </nav>

          <div className="m-2 rounded-lg border border-ew-border-subtle bg-ew-bg/70 p-2">
            <div className={`flex items-center ${sidebarExpanded ? 'gap-2' : 'justify-center'}`} title={`${demoAccount.name} / ${demoAccount.role}`}>
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded bg-ew-accent/15 text-[10px] font-bold text-ew-accent">MO</div>
              {sidebarExpanded && <div className="hidden min-w-0 md:block"><div className="truncate text-[11px] font-semibold text-ew-text">{demoAccount.name}</div><div className="truncate text-[9px] uppercase tracking-wider text-ew-text-dimmer">{demoAccount.role}</div></div>}
            </div>
            <div className="mt-2 space-y-1 border-t border-ew-border-subtle pt-2">
              <button onClick={() => openSettings('Display')} aria-label="Settings" title="Settings" className={`flex h-8 w-full items-center rounded text-ew-text-muted transition-colors hover:bg-ew-surface hover:text-ew-accent ${sidebarExpanded ? 'gap-2 px-2' : 'justify-center'}`}><Settings size={15} />{sidebarExpanded && <span className="hidden text-[10px] font-medium md:inline">Settings</span>}</button>
              <button type="button" aria-label="Sign out" title="Sign out (demo only)" className={`flex h-8 w-full items-center rounded text-ew-text-muted transition-colors hover:bg-ew-surface hover:text-[#ef6b73] ${sidebarExpanded ? 'gap-2 px-2' : 'justify-center'}`}><LogOut size={15} />{sidebarExpanded && <span className="hidden text-[10px] font-medium md:inline">Sign out</span>}</button>
              <button onClick={() => setSidebarCollapsed(value => !value)} aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'} className={`flex h-8 w-full items-center rounded text-ew-text-muted transition-colors hover:bg-ew-surface hover:text-ew-accent ${sidebarExpanded ? 'gap-2 px-2' : 'justify-center'}`}>
                {sidebarCollapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
                {sidebarExpanded && <span className="hidden text-[10px] font-medium md:inline">Collapse</span>}
              </button>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <main ref={mainRef} className="min-h-0 flex-1 overflow-y-auto px-4 py-4 md:px-6">
            <div className="mx-auto max-w-[1760px] space-y-4">
              {view === 'live' && <><MissionBanner scenario={scenario} active={active} baseline={baseline} oracle={oracle} /><section className="grid grid-cols-1 gap-6 border-b border-ew-border-subtle pb-5 xl:grid-cols-[minmax(0,1.15fr)_minmax(380px,0.85fr)]"><div className="grid grid-cols-1 sm:grid-cols-3"><MetricReadout label="Interception ratio" value={formatMetric(active.metrics.interception_ratio, 'percent')} detail={`${active.metrics.interception_hits.toLocaleString()} / ${active.metrics.transmissions.toLocaleString()} opportunities`} icon={<Crosshair size={16} />} /><MetricReadout label="Probability of detection" value={formatMetric(active.metrics.pd, 'percent')} detail={`False alarm rate ${formatMetric(active.metrics.pfa, 'percent')}`} icon={<Gauge size={16} />} /><MetricReadout label="Mean TTFI" value={formatMetric(active.metrics.mean_ttfi, 'number')} detail={`${formatMetric(active.metrics.intercept_fraction, 'percent')} of emitters intercepted`} icon={<Clock3 size={16} />} /></div><ScannerState result={active} currentSlot={currentSlot} /></section><LiveScreen active={active} baseline={baseline} oracle={oracle} focusRun={focusRun} setFocusRun={setFocusRun} currentSlot={currentSlot} setCurrentSlot={setCurrentSlot} isPlaying={isPlaying} setIsPlaying={setIsPlaying} winSize={winSize} onOpenScannerSettings={() => openSettings('Scanner')} /></>}
              {view === 'performance' && <PerformanceScreen scenario={scenario} active={active} baseline={baseline} oracle={oracle} />}
              {view === 'threats' && <ThreatsScreen scenario={scenario} active={active} baseline={baseline} oracle={oracle} focusRun={focusRun} setFocusRun={setFocusRun} />}
            </div>
          </main>

          {view === 'live' && <footer className="shrink-0 border-t border-ew-border-subtle bg-ew-surface px-4 py-2 text-[9px] uppercase tracking-[0.12em] text-ew-text-dimmer md:px-8"><div className="mx-auto flex max-w-[1700px] items-center justify-between"><span className="flex items-center gap-2"><TimerReset size={12} /> Live scan view</span><span className="hidden sm:inline">Use the sidebar to inspect performance and threats</span></div></footer>}
        </div>
      </div>
    </div>
  );
};
