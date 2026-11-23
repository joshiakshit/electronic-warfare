import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Activity, Radio, Wifi, Shield, Eye, Radar, ScanSearch, Network, Clock3, Settings, CircleHelp, RefreshCw, AlertTriangle, Unplug } from 'lucide-react';
import { get, subscribe, type AccessPointObservation, type CaptureHealth, type CaptureStatus, type ClientLink, type Json, type MyNetwork, type Recording, type SniperReport } from './api';
import { activeRoute, captureStateLabel, channelReading, modulePath, rememberedTab, sessionSummary } from './navigation';
import { applyTheme, rememberTheme, themes, type Theme } from './theme';
import { channelRows, date, deviceClassification, hiddenNameRow, observationValue, observedClientsByAp, short, title } from './observations';
import { ObservationReport } from './ObservationReport';
import { Overview } from './Overview';
import { SpotterTopology } from './SpotterTopology';
import { endpointKey, linkTouches, type TopologyEndpoint } from './spotterTopology';
import { CaptureControls, SavedRecordings, type RunCaptureAction } from './SessionControls';
import { MyNetworkSettings } from './MyNetworkSettings';
import { startSnapshotPolling } from './snapshotPolling';
import { Sniper } from './Sniper';
import { Ops } from './Ops';

type Tab = { id: string; label: string; hint: string; endpoint: string; kind: string };
type Section = { id: string; label: string; icon: typeof Wifi; hint: string; tabs?: Tab[] };
const modules: Section[] = [
  { id:'overview',label:'Overview',icon:Activity,hint:'Session summary and the latest observations.' },
  { id:'discovery',label:'Discovery',icon:Radar,hint:'Find access points and observe client relationships.',tabs:[{id:'sniper',label:'Sniper',hint:'Find an access point and follow its observed channel.',endpoint:'/api/sniper',kind:'sniper'},{id:'spotter',label:'Spotter',hint:'Show clients ewave observed associating or exchanging traffic with an access point.',endpoint:'/api/spotter',kind:'edges'}]},
  { id:'privacy',label:'Privacy',icon:Eye,hint:'Review hidden network names and probe requests.',tabs:[{id:'whistleblower',label:'Whistleblower',hint:'Show hidden access points and later frames that revealed their names.',endpoint:'/api/whistleblower',kind:'hidden'},{id:'de-cloaker',label:'De-cloaker',hint:'Review named and general probe requests, subject to backend privacy settings.',endpoint:'/api/decloaker',kind:'probes'}]},
  { id:'identification',label:'Identification',icon:ScanSearch,hint:'Inspect access point security and device fingerprints.',tabs:[{id:'inspector',label:'Inspector',hint:'Read advertised security and radio capabilities from observed access points.',endpoint:'/api/inspector',kind:'aps'},{id:'profiler',label:'Profiler',hint:'Review the observed device inventory and fingerprint evidence.',endpoint:'/api/profiler',kind:'inventory'}]},
  { id:'movement',label:'Movement & activity',icon:Network,hint:'Review observed client movement and radio channel activity.',tabs:[{id:'tracker',label:'Tracker',hint:'Show access point changes recorded with explicit evidence methods.',endpoint:'/api/tracker',kind:'roams'},{id:'lookout',label:'Lookout',hint:'Compare scanner occupancy estimates across sampled channels.',endpoint:'/api/lookout',kind:'channels'}]},
  { id:'ops',label:'Ops',icon:Shield,hint:'Lab operations are available only when the backend enables them.'},
  { id:'session',label:'Session',icon:Clock3,hint:'Capture health, retained results, and application settings.',tabs:[{id:'capture-health',label:'Capture health',hint:'Control passive capture and review the receiver, frame counts, and diagnostics.',endpoint:'/api/capture/health',kind:'health'},{id:'saved-results',label:'Saved results',hint:'Import recordings and replay saved captures on this machine.',endpoint:'/api/recordings',kind:'saved'},{id:'settings',label:'Settings',hint:'Choose a theme and manage local enrollments, capture scope, and fingerprint samples.',endpoint:'/api/profiler/network',kind:'settings'}]}
];
const byTab = new Map(modules.flatMap(s => (s.tabs||[]).map(t=>[t.id,t])));
const overviewReport = { id: 'overview', endpoint: '/api/topology' };
function captureKey(status?: CaptureStatus) {
  return status && `${status.startedAt}/${status.wifi.sessionId ?? ''}`;
}
const emptyMessages: Record<string, string> = {
  hidden: 'No hidden networks observed',
  inventory: 'No devices observed',
  roams: 'No AP changes observed',
};
function Help({text}:{text:string}) { const [open,setOpen]=useState(false); useEffect(()=>{const f=(e:KeyboardEvent)=>e.key==='Escape'&&setOpen(false);window.addEventListener('keydown',f);return()=>window.removeEventListener('keydown',f)},[]);return <span className="help-wrap"><button className="help" aria-label={`Help: ${text}`} aria-expanded={open} onClick={e=>{e.stopPropagation();setOpen(true)}} onMouseEnter={()=>setOpen(true)} onMouseLeave={()=>setOpen(false)} onFocus={()=>setOpen(true)} onBlur={()=>setOpen(false)}><CircleHelp size={14}/></button>{open&&<span className="tooltip" role="tooltip">{text}</span>}</span> }
function records(data: Json | null, kind: string): Json[] {
  if (!data) return [];
  switch (kind) {
    case 'aps': return data.accessPoints ?? [];
    case 'hidden': return (data.accessPoints ?? []).map(hiddenNameRow);
    case 'edges': return data.edges ?? [];
    case 'roams': return data.roams ?? [];
    case 'inventory': return Array.isArray(data) ? data : data.devices ?? [];
    case 'probes': return data.corpus ?? [];
    case 'channels': return channelRows(data);
    case 'sniper': return data.run ? [data.run] : [];
    default: return Array.isArray(data) ? data : [data];
  }
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
 const pathId=activeRoute(route);const section=modules.find(s=>s.id===pathId)||modules.find(s=>s.tabs?.some(t=>t.id===pathId))||modules[0];const activeId=section.id===pathId&&section.tabs?rememberedTab(section.id,pathId,section.tabs.map(t=>t.id),localStorage.getItem(`ewave.tab.${section.id}`)):pathId;const tab=byTab.get(activeId);
 const navigate=useCallback((id:string)=>{const cat=modules.find(s=>s.id===id)||modules.find(s=>s.tabs?.some(t=>t.id===id));if(!cat)return;const tabs=cat.tabs?.map(t=>t.id)||[];const chosen=cat.tabs?rememberedTab(cat.id,id,tabs,localStorage.getItem(`ewave.tab.${cat.id}`)):cat.id;history.pushState({},'',modulePath(cat.id,cat.tabs?chosen:undefined));setRoute(location.pathname);if(cat.tabs)localStorage.setItem(`ewave.tab.${cat.id}`,chosen)},[]);
 useEffect(()=>{const pop=()=>setRoute(location.pathname);window.addEventListener('popstate',pop);return()=>window.removeEventListener('popstate',pop)},[]);
 const activeReport = section.id === 'overview' ? overviewReport : tab?.kind === 'health' ? undefined : tab;
 useEffect(() => {
   if (!activeReport) return;
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
   }, 4000);
   reportPoll.current = poll;
   return () => {
     poll.stop();
     reportPoll.current = undefined;
   };
 }, [activeReport, sessionKey]);
 useEffect(() => {
   let timer: number | undefined;
   const requestRefresh = () => {
     if (timer !== undefined) return;
     timer = window.setTimeout(() => {
       timer = undefined;
       refresh();
     }, 1000);
   };
   const stop = subscribe(requestRefresh, up => {
     setWs(up);
     if (up) requestRefresh();
   });
   return () => {
     window.clearTimeout(timer);
     stop();
   };
 }, [refresh]);
 const current=tab?data[tab.id]:null;const rows=useMemo(()=>records(current,tab?.kind||''),[current,tab]);
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
   }, 5000);
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
 const error = tab ? errors[tab.id] : '';
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
      <span className={`mode-tag ${capture.running ? 'receiving' : ''}`}><i />{sessionLabel}</span>
      {capture.mode !== 'idle' && <span className="session-source" title={capture.source}><Radio size={14} /><span>{capture.source}</span></span>}
      {displayedChannel && (
       <span className="mono session-meta">{capture.channelLabel && `${capture.channelLabel} `}{displayedChannel}</span>
      )}
      {capture.selectedAp && <span className="mono session-meta">AP {capture.selectedAp}</span>}
     </div>
     <div className="session-right">
      {status?.wifi.captureStartedAt
        ? <span className="session-meta">Started {date(status.wifi.captureStartedAt)}</span>
        : status?.startedAt && <span className="session-meta">API started {date(status.startedAt)}</span>}
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
     {(section.id === 'overview' || tab?.kind === 'health') && errors.status && (
      <div className="notice error"><Unplug size={17} /><div>
       <b>No session connected</b><span>Start a session with ./ewave to load observations.</span>
      </div></div>
     )}
     {error && (
      <div className="notice error"><AlertTriangle size={17} /><div>
       <b>{scannerUnavailable ? 'Scanner unavailable' : error.includes('503') || error.toLowerCase().includes('unavailable') ? 'Capture mode unavailable' : 'Backend unavailable'}</b>
       <span>{scannerUnavailable ? 'Lookout requires adaptive capture with a scanner attached.' : error}</span>
       {!scannerUnavailable && error.toLowerCase().includes('wifi') && <span>This report requires a Wi-Fi capture or replay session.</span>}
      </div></div>
     )}
     {section.id === 'overview' && (
      <Overview status={status} health={health} topology={errors.overview ? null : data.overview} onNavigate={navigate} />
     )}
     {section.id === 'ops' && <Ops status={status} />}
     {tab?.kind === 'health' && (
      <CaptureControls wifi={status?.wifi} connected={connected} actions={actions} onRecordings={() => navigate('saved-results')} />
     )}
     {tab?.kind === 'saved' && (
      <SavedRecordings entries={current ?? undefined} wifi={status?.wifi} connected={connected} actions={actions} onImported={addRecording} />
     )}
     {tab && tab.kind !== 'health' && busy && !current && !error && (
      <div className="report-empty" role="status"><RefreshCw className="spin" size={16} /><strong>Loading report…</strong></div>
     )}
     {tab && current && (
      <>
       {tab.kind === 'sniper' && <Sniper key={sessionKey} data={current} onChanged={updateSniper} />}
       <Summary kind={tab.kind} data={current} rows={rows} />
       {tab.kind === 'health' && <Health data={current} />}
       {tab.kind === 'settings' && <MyNetworkSettings profile={current} onChanged={updateMyNetwork} />}
       {tab.kind === 'edges' && <SpotterReport accessPoints={current.accessPoints ?? []} edges={current.edges ?? []} running={capture.running} stale={!!error} />}
       {!['edges', 'health', 'saved', 'settings', 'sniper'].includes(tab.kind) && (
        <ObservationReport key={tab.id} kind={tab.kind} rows={rows} running={capture.running} stale={!!error}
                           emptyMessage={emptyMessages[tab.kind]} />
       )}
       {health?.referenceTime && <p className="source-note">Replay reference {date(health.referenceTime)}</p>}
      </>
     )}
    </section>
   </main>
  </div>
 );
}
function Summary({ kind, data, rows }: { kind: string; data: Json; rows: Json[] }) {
  const unique = (key: string) => new Set(rows.map(row => row[key]).filter(Boolean)).size;
  let metrics: [string, number | string][];
  switch (kind) {
    case 'aps':
      metrics = [
        ['Access points', rows.length], ['Hidden names', rows.filter(row => row.ssidHidden).length],
        ['AP channels observed', unique('channel')],
      ];
      break;
    case 'hidden': {
      const observed = rows.filter(row => row.nameStatus === 'Name observed').length;
      metrics = [['Hidden APs', rows.length], ['Names observed', observed], ['Still hidden', rows.length - observed]];
      break;
    }
    case 'edges': {
      const association = rows.filter(row => /ASSOC/.test(row.source || '')).length;
      const dataLinks = rows.filter(row => /DATA/.test(row.source || '')).length;
      metrics = [
        ['Observed clients', unique('clientId')], ['Observed AP links', rows.length],
        ['Association / data links', `${association} / ${dataLinks}`],
      ];
      break;
    }
    case 'roams':
      metrics = [['Observed AP changes', rows.length], ['Clients with changes', unique('clientId')], ['Evidence methods', unique('method')]];
      break;
    case 'inventory':
      metrics = [['Devices', rows.length], ['Inferred labels', rows.filter(deviceClassification).length]];
      break;
    case 'probes':
      metrics = [
        ['Probe requests', data.totalProbes ?? '—'], ['Directed requests', data.directedProbes ?? '—'],
        ['Distinct network names', data.distinctDirectedSsids ?? '—'],
      ];
      break;
    case 'channels':
      metrics = [
        ['Sampled channels', Array.isArray(data.counts) ? rows.filter(row => row.sampleCount > 0).length : '—'],
        ['Anomalies', rows.filter(row => row.anomaly).length],
      ];
      break;
    default: return null;
  }
  return (
    <div className="metrics">
      {metrics.map(([label, value]) => (
        <div className="metric" key={label}><span>{label}</span><b>{value}</b></div>
      ))}
    </div>
  );
}
function SpotterReport({ accessPoints, edges, running, stale }: {
  accessPoints: AccessPointObservation[]; edges: ClientLink[]; running: boolean; stale: boolean;
}) {
  const [view, setView] = useState<'table' | 'topology'>('table');
  const [selection, setSelection] = useState<TopologyEndpoint | null>(null);
  const selectedAp = selection?.kind === 'ap' ? accessPoints.find(ap => ap.bssid === selection.id) : undefined;
  const selected = selection && (selectedAp || edges.some(edge => linkTouches(selection, edge))) ? selection : null;
  const clients = useMemo(() => observedClientsByAp(edges), [edges]);
  const links = selected ? edges.filter(edge => linkTouches(selected, edge)) : edges;
  const topology = view === 'topology';

  return (
    <>
      <section className="spotter-aps" aria-labelledby="spotter-access-points">
        <div className="spotter-heading">
          <h2 id="spotter-access-points">{topology ? 'Observed topology' : 'Access points'}</h2>
          <Help text={topology ? 'Wires represent captured evidence of client links. Select an access point or client to filter the links below.'
            : 'AP-reported stations come from the access point. Observed clients count distinct clients with association or data evidence in this report.'} />
          <div className="spotter-view" role="group" aria-label="Spotter view">
            <button type="button" aria-pressed={!topology} onClick={() => setView('table')}>Table</button>
            <button type="button" aria-pressed={topology} onClick={() => setView('topology')}>Topology</button>
          </div>
        </div>
        {topology ? (
          <SpotterTopology accessPoints={accessPoints} edges={edges} selected={selected} onSelect={setSelection} />
        ) : accessPoints.length > 0 ? (
          <div className="table-wrap report-table">
            <table>
              <thead>
                <tr>
                  <th scope="col">Access point</th><th scope="col">AP-reported stations</th>
                  <th scope="col">Observed clients</th><th scope="col">Last observed</th>
                </tr>
              </thead>
              <tbody>
                {accessPoints.map(ap => {
                  const active = selected?.kind === 'ap' && ap.bssid === selected.id;
                  const select = () => setSelection(active ? null : { kind: 'ap', id: ap.bssid });
                  const name = observationValue('ssid', ap);
                  return (
                    <tr key={ap.bssid} className={active ? 'is-selected' : undefined} onClick={select}>
                      <td>
                        <button type="button" className="row-subject spotter-ap"
                                aria-pressed={active} aria-controls="spotter-client-links"
                                onClick={event => { event.stopPropagation(); select(); }}>
                          <span title={name}>{name}</span>
                          <code>{ap.bssid}</code>
                        </button>
                      </td>
                      <td>{ap.stationCount ?? '—'}</td>
                      <td>{clients.get(ap.bssid)?.size ?? 0}</td>
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
              {selected.kind === 'client' ? 'Client ' : selectedAp ? `${observationValue('ssid', selectedAp)} · ` : 'AP '}
              <code>{selected.id}</code>
            </span>
          )}
          {(accessPoints.length > 0 || edges.length > 0) && (
            <button type="button" className="spotter-all" aria-pressed={!selected} onClick={() => setSelection(null)}>All links</button>
          )}
        </div>
        <ObservationReport key={selected ? endpointKey(selected) : 'all'} kind="edges" rows={links} running={running} stale={stale}
                           emptyMessage={selected?.kind === 'ap' ? 'No client links observed for this access point' : 'No client links observed'} />
      </section>
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
