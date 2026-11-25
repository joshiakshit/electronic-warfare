import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Radio, Wifi, Shield, Eye, Radar, ScanSearch, Network, Clock3, Settings, CircleHelp, RefreshCw, AlertTriangle, Unplug } from 'lucide-react';
import { get, send, snapshotModules, subscribe, type AccessPointObservation, type ReportModule, type SavedSnapshot, type SnapshotModule, type CaptureHealth, type CaptureStatus, type InspectorAccessPoint, type InspectorReport, type Json, type MyNetwork, type Recording, type SniperReport, type SpotterObservations, type TrackerReport } from './api';
import { activeRoute, captureStateLabel, channelReading, modulePath, readTab, rememberTab, rememberedTab, sessionSummary } from './navigation';
import { applyTheme, rememberTheme, themes, type Theme } from './theme';
import { channelRows, date, deviceClassification, hiddenNameRow, isActiveLink, observationValue, observedClientsByAp, roamApLabel, short, spotterClientLabel, title } from './observations';
import { ObservationReport } from './ObservationReport';
import { ProbeAnalytics } from './ProbeAnalytics';
import { Overview } from './Overview';
import { essSizes, SpotterApTags, SpotterTopology } from './SpotterTopology';
import { endpointKey, linkTouches, type TopologyEndpoint } from './spotterTopology';
import { CaptureControls, CaptureFeedback, SavedRecordings, type CaptureActions, type RunCaptureAction } from './SessionControls';
import { SavedSnapshots } from './SavedSnapshots';
import { MyNetworkSettings } from './MyNetworkSettings';
import { startSnapshotPolling } from './snapshotPolling';
import { Sniper } from './Sniper';
import { Ops } from './Ops';
import type { OpsLaunchIntent } from './ops';

type Tab = { id: string; label: string; hint: string; endpoint: string; kind: string };
type Section = { id: string; label: string; icon: typeof Wifi; hint: string; tabs?: Tab[] };
const modules: Section[] = [
  { id:'overview',label:'Overview',icon:Activity,hint:'Session summary and the latest observations.' },
  { id:'discovery',label:'Discovery',icon:Radar,hint:'Find access points and observe client relationships.',tabs:[{id:'sniper',label:'Sniper',hint:'Find an access point and follow its observed channel.',endpoint:'/api/sniper',kind:'sniper'},{id:'spotter',label:'Spotter',hint:'Show clients ewave observed associating or exchanging traffic with an access point.',endpoint:'/api/spotter',kind:'edges'}]},
  { id:'privacy',label:'Privacy',icon:Eye,hint:'Review hidden network names and probe requests.',tabs:[{id:'whistleblower',label:'Whistleblower',hint:'Review hidden access points, the evidence behind each observed name, and visible networks they share a radio or link with.',endpoint:'/api/whistleblower',kind:'hidden'},{id:'de-cloaker',label:'De-cloaker',hint:'Review probed network names, Short-SSID hashes, and evidence linking addresses.',endpoint:'/api/decloaker',kind:'probes'}]},
  { id:'identification',label:'Identification',icon:ScanSearch,hint:'Inspect access point security and device fingerprints.',tabs:[{id:'inspector',label:'Inspector',hint:'Read advertised security and radio capabilities from observed access points.',endpoint:'/api/inspector',kind:'aps'},{id:'profiler',label:'Profiler',hint:'Review the observed device inventory and fingerprint evidence.',endpoint:'/api/profiler',kind:'inventory'}]},
  { id:'movement',label:'Movement & activity',icon:Network,hint:'Review observed client movement and radio channel activity.',tabs:[{id:'tracker',label:'Tracker',hint:'Show access point changes recorded with explicit evidence methods.',endpoint:'/api/tracker',kind:'roams'},{id:'lookout',label:'Lookout',hint:'Compare scanner occupancy estimates across sampled channels.',endpoint:'/api/lookout',kind:'channels'}]},
  { id:'ops',label:'Ops',icon:Shield,hint:'Lab operations are available only when the backend enables them.'},
  { id:'session',label:'Session',icon:Clock3,hint:'Capture health, retained results, and application settings.',tabs:[{id:'capture-health',label:'Capture health',hint:'Control passive capture and review the receiver, frame counts, and diagnostics.',endpoint:'/api/capture/health',kind:'health'},{id:'saved-results',label:'Saved results',hint:'Import PCAPs and save or open passive session snapshots on this machine.',endpoint:'/api/recordings',kind:'saved'},{id:'settings',label:'Settings',hint:'Choose a theme and manage local enrollments, capture scope, and fingerprint samples.',endpoint:'/api/profiler/network',kind:'settings'}]}
];
const byTab = new Map(modules.flatMap(s => (s.tabs||[]).map(t=>[t.id,t])));
const overviewReport = { id: 'overview', endpoint: '/api/topology' };
const scanEnabledMessage = 'Switched to adaptive scan';
function captureKey(status?: CaptureStatus) {
  return status && `${status.startedAt}/${status.wifi.sessionId ?? ''}`;
}
const emptyMessages: Record<string, string> = {
  hidden: 'No hidden networks observed',
  inventory: 'No devices observed',
  roams: 'No AP changes observed',
};
function Help({text}:{text:string}) { const [open,setOpen]=useState(false); useEffect(()=>{const f=(e:KeyboardEvent)=>e.key==='Escape'&&setOpen(false);window.addEventListener('keydown',f);return()=>window.removeEventListener('keydown',f)},[]);return <span className="help-wrap"><button className="help" aria-label={`Help: ${text}`} aria-expanded={open} onClick={e=>{e.stopPropagation();setOpen(true)}} onMouseEnter={()=>setOpen(true)} onMouseLeave={()=>setOpen(false)} onFocus={()=>setOpen(true)} onBlur={()=>setOpen(false)}><CircleHelp size={14}/></button>{open&&<span className="tooltip" role="tooltip">{text}</span>}</span> }
export function records(data: Json | null, kind: string, legacyAccessPoints?: AccessPointObservation[]): Json[] {
  if (!data) return [];
  switch (kind) {
    case 'aps': return data.accessPoints ?? [];
    case 'hidden': return (data.accessPoints ?? []).map(hiddenNameRow);
    case 'edges': return data.edges ?? [];
    case 'roams': {
      const tracker = data as TrackerReport;
      const aps = new Map((tracker.accessPoints ?? legacyAccessPoints ?? []).map(ap => [ap.bssid, ap]));
      const devices = new Map(tracker.devices?.map(device => [device.id, device]));
      return (tracker.roams ?? []).map(roam => {
        const device = devices.get(roam.clientId);
        const clientLabel = device?.enrolledLabel || [deviceClassification(device ?? {}), device?.osHint].filter(Boolean).join(' · ')
          || spotterClientLabel(device) || 'Client';
        return { ...roam, clientLabel,
          fromApLabel: roamApLabel(aps.get(roam.fromBssid), roam.fromChannel, roam.fromBand),
          toApLabel: roamApLabel(aps.get(roam.toBssid), roam.toChannel, roam.toBand),
        };
      });
    }
    case 'inventory': return Array.isArray(data) ? data : data.devices ?? [];
    case 'probes': return data.corpus ?? [];
    case 'channels': return channelRows(data);
    case 'sniper': return data.run ? [data.run] : [];
    default: return Array.isArray(data) ? data : [data];
  }
}
function spotterObservations(report: Json): SpotterObservations {
  return {
    accessPoints: report.accessPoints ?? [],
    edges: report.edges ?? [],
    devices: report.devices ?? [],
    essGroups: report.essGroups ?? {},
    meshLinks: report.meshLinks ?? [],
  };
}
function ThemePicker({ selected, onChange }: { selected: Theme; onChange: (theme: Theme) => void }) {
 return (
   <fieldset className="theme-picker">
     <legend>Color theme</legend>
     <div className="theme-options">
       {themes.map(({ id, label }) => (
         <label className="theme-option" key={id}>
           <span className="theme-preview" data-theme={id} aria-hidden="true">
             <span />
             <span />
             <span />
           </span>
           <span className="theme-option-label">
             <input type="radio" name="color-theme" value={id} checked={selected === id} onChange={() => onChange(id)} />
             {label}
           </span>
         </label>
       ))}
     </div>
   </fieldset>
 );
}

export default function App({ initialTheme }: { initialTheme: Theme }) {
 const [theme, setTheme] = useState(initialTheme);
 const selectTheme = (next: Theme) => {
   applyTheme(next);
   setTheme(next);
   rememberTheme(next);
 };
 const [route,setRoute]=useState(location.pathname);const [data,setData]=useState<Record<string,any>>({});const [errors,setErrors]=useState<Record<string,string>>({});const [busy,setBusy]=useState(true);const [ws,setWs]=useState(false);
 const [snapshot, setSnapshot] = useState<SavedSnapshot>();
 const [opsIntent, setOpsIntent] = useState<OpsLaunchIntent | null>(null);
 const streamReady = useRef(false);
 const reportModule = useRef<ReportModule>();
 const [captureFeedback, setCaptureFeedback] = useState({ pending: false, error: '', message: '' });
 const actionPending = useRef(false);
 const captureRevision = useRef(0);
 const acceptedStatus = useRef<CaptureStatus>();
 const reportPoll = useRef<ReturnType<typeof startSnapshotPolling>>();
 const statusPoll = useRef<ReturnType<typeof startSnapshotPolling>>();
 const status: CaptureStatus | undefined = data.status;
 const sessionKey = captureKey(status);
 const connected = !!status && !errors.status;
 const refresh = useCallback(() => {
   void statusPoll.current?.refresh();
   void reportPoll.current?.refresh();
 }, []);
 const acceptStatus = useCallback((nextStatus: CaptureStatus, health: CaptureHealth | null) => {
   const previousStatus = acceptedStatus.current;
   const changed = captureKey(previousStatus) !== captureKey(nextStatus);
   const sameBackend = previousStatus?.startedAt === nextStatus.startedAt;
   acceptedStatus.current = nextStatus;
   if (changed) captureRevision.current++;
   setData(previous => {
     const reports = !changed ? previous : sameBackend
       ? { 'saved-results': previous['saved-results'], settings: previous.settings } : {};
     return { ...reports, status: nextStatus, 'capture-health': health };
   });
   setErrors(previous => changed ? {} : { ...previous, status: '' });
 }, []);
 const runCaptureAction: RunCaptureAction = async (request, message) => {
   if (actionPending.current) return;
   actionPending.current = true;
   setCaptureFeedback({ pending: true, error: '', message: '' });
   try {
     const wifi = await request();
     setSnapshot(undefined);
     captureRevision.current++;
     if (acceptedStatus.current) acceptStatus({ ...acceptedStatus.current, wifi }, null);
     setCaptureFeedback({ pending: false, error: '', message });
   } catch (failure) {
     setCaptureFeedback({ pending: false, error: failure instanceof Error ? failure.message : 'Capture request failed', message: '' });
   } finally {
     actionPending.current = false;
     refresh();
   }
 };
 const actions = { ...captureFeedback, run: runCaptureAction };
 const addRecording = (entry: Recording) => {
   captureRevision.current++;
   setData(previous => ({
     ...previous,
     'saved-results': [entry, ...((previous['saved-results'] ?? []) as Recording[]).filter(row => row.id !== entry.id)],
   }));
   refresh();
 };
 const updateSniper = (report: SniperReport) => {
   captureRevision.current++;
   setData(previous => captureKey(previous.status) === sessionKey ? { ...previous, sniper: report } : previous);
   refresh();
 };
 const updateMyNetwork = (profile: MyNetwork) => {
   captureRevision.current++;
   setData(previous => ({
     status: previous.status, 'capture-health': previous['capture-health'],
     'saved-results': previous['saved-results'], settings: profile,
   }));
   setErrors(previous => ({ status: previous.status }));
   refresh();
 };
 const pathId=activeRoute(route);const section=modules.find(s=>s.id===pathId)||modules.find(s=>s.tabs?.some(t=>t.id===pathId))||modules[0];const activeId=section.id===pathId&&section.tabs?rememberedTab(section.id,pathId,section.tabs.map(t=>t.id),readTab(section.id)):pathId;const tab=byTab.get(activeId);
 const navigate=useCallback((id:string)=>{const cat=modules.find(s=>s.id===id)||modules.find(s=>s.tabs?.some(t=>t.id===id));if(!cat)return;const tabs=cat.tabs?.map(t=>t.id)||[];const chosen=cat.tabs?rememberedTab(cat.id,id,tabs,readTab(cat.id)):cat.id;history.pushState({},'',modulePath(cat.id,cat.tabs?chosen:undefined));setRoute(location.pathname);if(cat.tabs)rememberTab(cat.id,chosen)},[]);
 const openInOps = useCallback((intent: Omit<OpsLaunchIntent, 'id'>) => {
   setOpsIntent({ ...intent, id: Date.now() });
   navigate('ops');
 }, [navigate]);
 useEffect(()=>{const pop=()=>setRoute(location.pathname);window.addEventListener('popstate',pop);return()=>window.removeEventListener('popstate',pop)},[]);
 const snapshotModule = activeId === 'de-cloaker' ? 'decloaker' : activeId;
 const viewingSnapshot = !!snapshot && (section.id === 'overview' || snapshotModules.includes(snapshotModule as SnapshotModule));
 const activeReport = viewingSnapshot ? undefined
   : section.id === 'overview' ? overviewReport : tab?.kind === 'health' ? undefined : tab;
 useEffect(() => {
   if (!activeReport) return;
   reportModule.current = (activeReport.id === 'de-cloaker' ? 'decloaker' : activeReport.id) as ReportModule;
   const poll = startSnapshotPolling(async signal => {
     const revision = captureRevision.current;
     setBusy(true);
     try {
       const report = await get(activeReport.endpoint, signal);
       if (signal.aborted || revision !== captureRevision.current) return;
       setData(previous => ({ ...previous, [activeReport.id]: report }));
       setErrors(previous => ({ ...previous, [activeReport.id]: '' }));
     } catch (failure) {
       if (signal.aborted || revision !== captureRevision.current) return;
       setErrors(previous => ({ ...previous, [activeReport.id]: failure instanceof Error ? failure.message : 'Backend unavailable' }));
     } finally {
       if (!signal.aborted && revision === captureRevision.current) setBusy(false);
     }
   }, () => streamReady.current ? 15000 : 4000);
   reportPoll.current = poll;
   return () => {
     poll.stop();
     reportPoll.current = undefined;
     reportModule.current = undefined;
   };
 }, [activeReport, sessionKey]);
 useEffect(() => {
   return subscribe(event => {
     if (event.type === 'summary') {
       refresh();
       return;
     }
     const changed = event.payload.modules;
     if (changed.includes('status')) void statusPoll.current?.refresh();
     if (reportModule.current && changed.includes(reportModule.current)) void reportPoll.current?.refresh();
   }, up => {
     streamReady.current = up;
     setWs(up);
     if (!up) refresh();
   });
 }, [refresh]);
 const current = viewingSnapshot && snapshot && tab ? snapshot.reports[snapshotModule as SnapshotModule] : tab ? data[tab.id] : null;
 const legacyAccessPoints = viewingSnapshot && tab?.kind === 'roams' ? (snapshot?.reports.spotter as Json | null)?.accessPoints : undefined;
 const rows = useMemo(() => records(current, tab?.kind || '', legacyAccessPoints), [current, tab, legacyAccessPoints]);
 useEffect(() => {
   const poll = startSnapshotPolling(async signal => {
     const revision = captureRevision.current;
     try {
       const [nextStatus, nextHealth] = await Promise.all([
         get<CaptureStatus>('/api/status', signal),
         get<CaptureHealth>('/api/capture/health', signal).catch(() => null),
       ]);
       if (!signal.aborted && revision === captureRevision.current) acceptStatus(nextStatus, nextHealth);
     } catch (failure) {
       if (signal.aborted || revision !== captureRevision.current) return;
       setErrors(previous => ({ ...previous, status: failure instanceof Error ? failure.message : 'Backend unavailable' }));
     }
   }, () => streamReady.current ? 15000 : 5000);
   statusPoll.current = poll;
   return () => {
     poll.stop();
     statusPoll.current = undefined;
   };
 }, [acceptStatus]);
 const health = data['capture-health'] || data.health;
 const capture = sessionSummary(status, health);
 const displayedChannel = channelReading(capture.channel, capture.frequency);
 const titleText = tab?.label || section.label;
 const subtitle = tab?.hint || section.hint;
 const error = viewingSnapshot ? '' : tab ? errors[tab.id] : '';
 const archivedTopology = snapshot && {
   ...spotterObservations(snapshot.reports.spotter as Json),
   accessPoints: (snapshot.reports.tracker as TrackerReport | null)?.accessPoints ?? (snapshot.reports.spotter as Json)?.accessPoints ?? [],
   roams: (snapshot.reports.tracker as TrackerReport | null)?.roams ?? [],
 };
 const scannerUnavailable = tab?.kind === 'channels' && error === 'no scanner attached';
 const sessionLabel = captureStateLabel(capture);

 return (
  <div className="shell">
   <aside className="sidebar">
    <div className="brand"><Activity size={26} strokeWidth={1.6} /><span>ewave</span></div>
    <nav aria-label="Main navigation">
     {modules.map(item => {
      const Icon = item.icon;
      const active = section.id === item.id;
      return (
       <div className={`nav-group ${active ? 'active' : ''}`} key={item.id}>
        <button className="nav-item" onClick={() => navigate(item.id)} aria-current={active ? 'page' : undefined}>
         <Icon size={18} strokeWidth={1.6} /><span>{item.label}</span>
         {active && <span className="nav-active-mark" />}
        </button>
       </div>
      );
     })}
    </nav>
    <div className="side-foot"><span className={`ws-dot ${ws ? 'up' : ''}`} />{ws ? 'Connected' : 'Disconnected'}</div>
   </aside>
   <main className="main">
    <header className="sessionbar" aria-label="Capture session">
     <div className="session-left">
      <span className={`mode-tag ${!viewingSnapshot && capture.running ? 'receiving' : ''}`}><i />{viewingSnapshot ? 'Saved reports' : sessionLabel}</span>
      {!viewingSnapshot && capture.mode !== 'idle' && <span className="session-source" title={capture.source}><Radio size={14} /><span>{capture.source}</span></span>}
      {!viewingSnapshot && displayedChannel && (
       <span className="mono session-meta">{capture.channelLabel && `${capture.channelLabel} `}{displayedChannel}</span>
      )}
      {!viewingSnapshot && capture.selectedAp && <span className="mono session-meta">AP {capture.selectedAp}</span>}
     </div>
     <div className="session-right">
      {!viewingSnapshot && (status?.wifi.captureStartedAt
        ? <span className="session-meta">Started {date(status.wifi.captureStartedAt)}</span>
        : status?.startedAt && <span className="session-meta">API started {date(status.startedAt)}</span>)}
      <button className="icon-btn" aria-label="Refresh data" title="Refresh data" onClick={refresh}>
       <RefreshCw size={15} />
      </button>
     </div>
    </header>
    <section className="page">
     <div className="page-head"><h1>{titleText}</h1><Help text={subtitle} /></div>
     {section.tabs && tab && (
      <div className="tabs" role="tablist" aria-label={`${section.label} modules`}>
       {section.tabs.map(item => (
        <button role="tab" aria-selected={item.id === activeId} className={item.id === activeId ? 'active' : ''}
                onClick={() => navigate(item.id)} key={item.id}>{item.label}</button>
       ))}
      </div>
     )}
     {tab?.kind === 'settings' && <ThemePicker selected={theme} onChange={selectTheme} />}
     {snapshot && (
      <section className="session-controls" aria-label="Open snapshot">
       <div className="session-controls-heading">
        <h2>Saved snapshot · {snapshot.name}</h2>
        <button type="button" className="text-button" onClick={() => setSnapshot(undefined)}>Close snapshot</button>
       </div>
       <p className="micro-note">Saved {date(snapshot.savedAt)} · Read-only passive reports</p>
      </section>
     )}
     {!viewingSnapshot && (section.id === 'overview' || tab?.kind === 'health') && errors.status && (
      <div className="notice error"><Unplug size={17} /><div>
       <b>No session connected</b><span>Start a session with ./ewave to load observations.</span>
      </div></div>
     )}
     {error && (
      <ReportErrorNotice error={error} scannerUnavailable={scannerUnavailable} capture={capture}
        captureInterface={status?.wifi.captureInterface} actions={actions} />
     )}
     {!viewingSnapshot && tab?.kind === 'channels' && actions.message === scanEnabledMessage && (
      <p className="micro-note" role="status">{scanEnabledMessage}</p>
     )}
     {section.id === 'overview' && (
      <Overview status={viewingSnapshot ? undefined : status} health={viewingSnapshot ? null : health}
        probes={viewingSnapshot ? (snapshot?.reports.decloaker as Json).totalProbes : undefined}
        topology={viewingSnapshot ? archivedTopology : errors.overview ? null : data.overview} onNavigate={navigate} />
     )}
     {section.id === 'ops' && <Ops status={status} launchIntent={opsIntent} />}
     {tab?.kind === 'health' && (
      <CaptureControls wifi={status?.wifi} connected={connected} actions={actions} onRecordings={() => navigate('saved-results')} />
     )}
     {tab?.kind === 'saved' && (
      <>
       <SavedSnapshots connected={connected} sessionId={status?.wifi.sessionId}
         onOpen={saved => { setSnapshot(saved); navigate('overview'); }} />
       <SavedRecordings entries={current ?? undefined} wifi={status?.wifi} connected={connected} actions={actions} onImported={addRecording} />
      </>
     )}
     {viewingSnapshot && tab?.kind === 'channels' && current === null && (
      <div className="report-empty"><strong>No scanner report saved</strong></div>
     )}
     {!viewingSnapshot && tab && tab.kind !== 'health' && busy && !current && !error && (
      <div className="report-empty" role="status"><RefreshCw className="spin" size={16} /><strong>Loading report…</strong></div>
     )}
     {tab && current && (
      <>
       {tab.kind === 'sniper' && <Sniper key={sessionKey} data={current} onChanged={updateSniper} />}
       {tab.kind === 'probes' && <ProbeAnalytics data={current} />}
       {!['edges', 'probes'].includes(tab.kind) && <Summary kind={tab.kind} data={current} rows={rows} />}
       {tab.kind === 'health' && <Health data={current} />}
       {tab.kind === 'settings' && <MyNetworkSettings profile={current} onChanged={updateMyNetwork} />}
       {tab.kind === 'edges' && <SpotterReport key={viewingSnapshot ? snapshot?.id : sessionKey}
         {...spotterObservations(current)}
         running={!viewingSnapshot && capture.running} stale={!!error}
         onOpenInOps={!viewingSnapshot && status?.operationsEnabled !== false ? openInOps : undefined} />}
       {!['edges', 'health', 'saved', 'settings', 'sniper'].includes(tab.kind) && (
        <ObservationReport key={`${tab.id}/${viewingSnapshot ? snapshot?.id : sessionKey}`} kind={tab.kind} rows={rows} archived={viewingSnapshot} running={!viewingSnapshot && capture.running} stale={!!error}
                           emptyMessage={emptyMessages[tab.kind]} activeFrequencyMhz={current.activeFrequencyMhz}
                           onOpenInOps={!viewingSnapshot && status?.operationsEnabled !== false ? openInOps : undefined} />
       )}
       {!viewingSnapshot && health?.referenceTime && <p className="source-note">Replay reference {date(health.referenceTime)}</p>}
      </>
     )}
    </section>
   </main>
  </div>
 );
}
export function ReportErrorNotice({ error, scannerUnavailable, capture, captureInterface, actions }: {
  error: string; scannerUnavailable: boolean; capture: Pick<ReturnType<typeof sessionSummary>, 'running' | 'mode'>;
  captureInterface?: string | null; actions: CaptureActions;
}) {
  const enableScan = scannerUnavailable && capture.running && capture.mode === 'watch';
  return (
    <div className="notice error"><AlertTriangle size={17} /><div>
      <b>{scannerUnavailable ? 'Scanner unavailable' : error.includes('503') || error.toLowerCase().includes('unavailable') ? 'Capture mode unavailable' : 'Backend unavailable'}</b>
      <span>{scannerUnavailable ? 'Lookout requires adaptive capture with a scanner attached.' : error}</span>
      {!scannerUnavailable && error.toLowerCase().includes('wifi') && <span>This report requires a Wi-Fi capture or replay session.</span>}
      {enableScan && <>
        <button type="button" className="session-secondary notice-action" disabled={actions.pending}
          onClick={() => actions.run(() => send('/api/capture/start', 'POST', {
            mode: 'scan', ...(captureInterface ? { interface: captureInterface } : {}),
          }), scanEnabledMessage)}>Enable adaptive scan</button>
        <CaptureFeedback actions={{ ...actions, message: '' }} />
      </>}
    </div></div>
  );
}

export function Summary({ kind, data, rows }: { kind: string; data: Json; rows: Json[] }) {
  const unique = (key: string) => new Set(rows.map(row => row[key]).filter(Boolean)).size;
  let metrics: [string, number | string, string?][];
  switch (kind) {
    case 'aps': {
      const { essGroups, findingsCount, evilTwinSuspects } = data as InspectorReport;
      const accessPoints = rows as InspectorAccessPoint[];
      const high = accessPoints.flatMap(ap => ap.securityFindings ?? [])
        .filter(finding => finding.severity === 'HIGH').length;
      const alert = [high > 0 && `${high} HIGH`,
        evilTwinSuspects && `${evilTwinSuspects} suspected ${evilTwinSuspects === 1 ? 'evil twin' : 'evil twins'}`]
        .filter(Boolean).join(' · ');
      metrics = [
        ['Access points', rows.length], ['ESS networks', Object.keys(essGroups ?? {}).length],
        ['Wi-Fi 6 / 6E / 7 APs', accessPoints.filter(ap => /^Wi-Fi (6E?|7)$/.test(ap.apRadio?.wifiGeneration ?? '')).length],
        ['Security findings', findingsCount ?? '—', alert],
      ];
      break;
    }
    case 'hidden': {
      const observed = rows.filter(row => row.nameStatus === 'Name observed').length;
      metrics = [['Hidden APs', rows.length], ['Names observed', observed], ['Still hidden', rows.length - observed]];
      break;
    }
    case 'edges': {
      const { accessPoints, edges } = data as SpotterObservations;
      const active = edges.filter(isActiveLink);
      const historical = edges.length - active.length;
      const clients = new Set(active.map(row => row.clientId)).size;
      const clientsByAp = observedClientsByAp(active);
      const withStationCounts = accessPoints.filter(ap => ap.stationCount != null);
      metrics = [
        ['Active observed clients', clients], ['Active client links', active.length],
      ];
      if (historical > 0) metrics.push(['Historical links', historical]);
      if (withStationCounts.length > 0)
        metrics.push(['Unobserved stations', withStationCounts.reduce((total, ap) =>
          total + Math.max(0, ap.stationCount! - (clientsByAp.get(ap.bssid)?.size ?? 0)), 0)]);
      break;
    }
    case 'roams': {
      const spatial = rows.filter(row => row.transitionType === 'INTER_AP_ROAM').length;
      const bandSteers = rows.filter(row => row.transitionType === 'BAND_STEER').length;
      const ft = rows.filter(row => ['FT', 'FT_REASSOC', 'FT_OVER_DS'].includes(row.method)).length;
      const btm = rows.filter(row => row.btmSteered || row.method === 'BTM_STEER').length;
      metrics = [
        ['Observed AP changes', rows.length],
        ['Spatial roams / Band steers', `${spatial} / ${bandSteers}`],
        ['802.11r / 802.11v assisted', `${ft} / ${btm}`],
        ['Ping-pong / BTM rejections', `${rows.filter(row => row.pingPong).length} / ${data.btmRejections?.length ?? 0}`],
      ];
      break;
    }
    case 'inventory':
      metrics = [
        ['Devices', rows.length],
        ['Classified devices', rows.filter(deviceClassification).length],
        ['Randomized MACs', rows.filter(row => row.locallyAdministered || row.randomizedScanSeen).length],
        ['Correlated MAC clusters', new Set(rows.flatMap(row => row.inferredCorrelation?.id ? [row.inferredCorrelation.id] : [])).size],
      ];
      break;
    case 'channels':
      metrics = [
        ['Sampled channels', rows.some(row => row.sampleCount != null) || Array.isArray(data.counts)
          ? rows.filter(row => row.sampleCount > 0).length : '—'],
        ['Active receiver', channelReading(data.activeChannel, data.activeFrequencyMhz) || '—'],
        ['Coupled hopping groups', data.coupledMembers?.length
          ? `${data.coupledMembers.length} channels · ${data.coupledPeriod * (data.tickMs || 20)} ms` : 'None'],
        ['Anomalies', rows.filter(row => row.anomaly).length],
        ['Mean retune', data.radio?.meanRetuneMs != null ? `${Math.round(data.radio.meanRetuneMs)} ms` : '—'],
      ];
      break;
    default: return null;
  }
  return (
    <div className={kind === 'aps' ? 'metrics inspector-metrics' : kind === 'roams' ? 'metrics tracker-metrics'
      : kind === 'channels' ? 'metrics lookout-metrics' : 'metrics'}>
      {metrics.map(([label, value, alert]) => (
        <div className="metric" key={label}><span>{label}</span><b>{value}</b>
          {alert && <small className="finding-badge" data-severity="HIGH">{alert}</small>}
        </div>
      ))}
    </div>
  );
}
export function SpotterReport({ accessPoints, edges, devices, essGroups, meshLinks, running, stale, onOpenInOps }:
  SpotterObservations & { running: boolean; stale: boolean; onOpenInOps?: (intent: Omit<OpsLaunchIntent, 'id'>) => void }) {
  const [view, setView] = useState<'table' | 'topology'>('table');
  const [selection, setSelection] = useState<TopologyEndpoint | null>(null);
  const [activeOnly, setActiveOnly] = useState(false);
  const activeEdges = useMemo(() => edges.filter(isActiveLink), [edges]);
  const displayedEdges = activeOnly ? activeEdges : edges;
  const selectedAp = selection?.kind === 'ap' ? accessPoints.find(ap => ap.bssid === selection.id) : undefined;
  const selected = selection && (selectedAp || displayedEdges.some(edge => linkTouches(selection, edge))) ? selection : null;
  const activeClients = useMemo(() => observedClientsByAp(activeEdges), [activeEdges]);
  const historicalClients = useMemo(() => observedClientsByAp(edges.filter(edge => !isActiveLink(edge))), [edges]);
  const deviceLabels = useMemo(() => new Map(devices?.map(device => [device.id, spotterClientLabel(device)])), [devices]);
  const groupSizes = useMemo(() => essSizes(essGroups), [essGroups]);
  const links = useMemo(() => displayedEdges.filter(edge => !selected || linkTouches(selected, edge))
    .map(edge => ({ ...edge, state: edge.state ?? 'ACTIVE', clientLabel: deviceLabels.get(edge.clientId) })), [displayedEdges, selected, deviceLabels]);
  const topology = view === 'topology';

  return (
    <>
      <Summary kind="edges" data={{ accessPoints, edges }} rows={edges} />
      <section className="spotter-aps" aria-labelledby="spotter-access-points">
        <div className="spotter-heading">
          <h2 id="spotter-access-points">{topology ? 'Observed topology' : 'Access points'}</h2>
          <Help text={topology ? 'Wires represent captured evidence of client links. Select an access point or client to filter the links below.'
            : 'Unobserved stations are the difference between the AP-reported count and distinct active observed clients.'} />
          <div className="spotter-view" role="group" aria-label="Spotter view">
            <button type="button" aria-pressed={!topology} onClick={() => setView('table')}>Table</button>
            <button type="button" aria-pressed={topology} onClick={() => setView('topology')}>Topology</button>
          </div>
        </div>
        {topology ? (
          <SpotterTopology accessPoints={accessPoints} edges={displayedEdges} devices={devices} essGroups={essGroups}
            meshLinks={meshLinks} selected={selected} onSelect={setSelection} />
        ) : accessPoints.length > 0 ? (
          <div className="table-wrap report-table">
            <table>
              <thead>
                <tr>
                  <th scope="col">Access point</th><th scope="col">AP-reported stations</th>
                  <th scope="col">Observed clients</th><th scope="col">Unobserved stations</th>
                  <th scope="col">Last observed</th>
                </tr>
              </thead>
              <tbody>
                {accessPoints.map(ap => {
                  const active = selected?.kind === 'ap' && ap.bssid === selected.id;
                  const select = () => setSelection(active ? null : { kind: 'ap', id: ap.bssid });
                  const name = observationValue('ssid', ap);
                  const activeCount = activeClients.get(ap.bssid)?.size ?? 0;
                  const historicalCount = historicalClients.get(ap.bssid)?.size ?? 0;
                  return (
                    <tr key={ap.bssid} className={active ? 'is-selected' : undefined} onClick={select}>
                      <td>
                        <button type="button" className="row-subject spotter-ap"
                                aria-pressed={active} aria-controls="spotter-client-links"
                                onClick={event => { event.stopPropagation(); select(); }}>
                          <span title={name}>{name}</span>
                          <code>{ap.channel ? `CH ${ap.channel} · ` : ''}{ap.bssid}</code>
                          <SpotterApTags ap={ap} essSize={groupSizes.get(ap.bssid)} />
                        </button>
                      </td>
                      <td>{ap.stationCount ?? '—'}</td>
                      <td>{activeCount} active{historicalCount > 0 && <small className="spotter-historical">{historicalCount} historical</small>}</td>
                      <td>{ap.stationCount == null ? '—' : Math.max(0, ap.stationCount - activeCount)}</td>
                      <td className="mono" title={date(ap.lastSeen)}>{date(ap.lastSeen, true)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <div className="report-empty"><strong>No access points observed</strong></div>}
      </section>

      <section id="spotter-client-links" aria-labelledby="spotter-links-heading">
        <div className="spotter-heading spotter-links-heading">
          <h2 id="spotter-links-heading">Client links</h2>
          {selected && (
            <span className="spotter-scope" role="status">
              {selected.kind === 'client' ? `${deviceLabels.get(selected.id) ?? 'Client'} · ` : selectedAp ? `${observationValue('ssid', selectedAp)} · ` : 'AP '}
              <code>{selected.id}</code>
            </span>
          )}
          <div className="spotter-link-controls">
            <label><input type="checkbox" checked={activeOnly} onChange={event => setActiveOnly(event.target.checked)} /> Active links only</label>
            {selected && <button type="button" className="spotter-all" onClick={() => setSelection(null)}>Clear selection</button>}
          </div>
        </div>
        <ObservationReport key={selected ? endpointKey(selected) : 'all'} kind="edges" rows={links} running={running} stale={stale}
                           emptyMessage={activeOnly ? 'No active client links observed'
                             : selected?.kind === 'ap' ? 'No client links observed for this access point' : 'No client links observed'}
                           onOpenInOps={onOpenInOps} />
      </section>
      {!!meshLinks?.length && (
        <section id="spotter-mesh" className="spotter-mesh" aria-labelledby="spotter-mesh-heading">
          <div className="spotter-heading"><h2 id="spotter-mesh-heading">Mesh / WDS Backhaul Links</h2></div>
          <div className="table-wrap report-table">
            <table>
              <thead><tr>
                <th scope="col">Peer A</th><th scope="col">Peer B</th><th scope="col">Channel</th>
                <th scope="col">Frames</th><th scope="col">Last observed</th>
              </tr></thead>
              <tbody>{meshLinks.map(link => (
                <tr key={JSON.stringify([link.peerA, link.peerB])}>
                  <td><code>{link.peerA}</code></td><td><code>{link.peerB}</code></td>
                  <td>{channelReading(link.channel, link.frequencyMhz) || '—'}</td>
                  <td>{link.frameCount}</td><td className="mono" title={date(link.lastSeen)}>{date(link.lastSeen, true)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
    </>
  );
}

function Health({ data }: { data: CaptureHealth }) {
  const receiver = channelReading(data.radio?.channel, data.radio?.frequencyMhz);
  const lastFrameChannel = channelReading(data.observedChannel, data.observedFrequencyMhz);
  return (
    <>
      <div className="metrics health-metrics">
        {Object.entries(data.frameCounts ?? {}).map(([kind, count]) => (
          <div className="metric" key={kind}><span>{title(kind)} frames</span><b>{short(count)}</b></div>
        ))}
      </div>
      <div className="detail-grid">
        <div><span>Capture mode</span><b>{short(data.mode)}</b></div>
        <div><span>Source</span><b>{short(data.source)}</b></div>
        {receiver && <div><span>Receiver reading</span><b>{receiver}</b></div>}
        {lastFrameChannel && <div><span>Last frame channel</span><b>{lastFrameChannel}</b></div>}
        <div><span>Last frame</span><b>{date(data.lastPacketAt)}</b></div>
        <div><span>Last frame age</span><b>{data.sinceLastFrameMs == null ? '—' : `${data.sinceLastFrameMs} ms`}</b></div>
        <div><span>Decoded / rejected</span><b>{short(data.decoded)} / {short(data.rejected)}</b></div>
        <div><span>Replay state</span><b>{short(data.replayState)}</b></div>
        {data.error && <div><span>Capture error</span><b className="error-text">{short(data.error)}</b></div>}
      </div>
    </>
  );
}
