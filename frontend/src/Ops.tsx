import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity, AlertTriangle, CheckCircle2, CircleStop, Play, Radio, RefreshCw, Shield, Wifi, XCircle,
} from 'lucide-react';
import type { Json } from './api';
import {
  accessPointLabel, errorMessage, operationReadiness, opsApi, startPath, targetLabel, toolSummary,
  type ObservedAp, type OpsCapabilities, type OpsStatus, type OpsTarget,
} from './ops';

type OperationId = 'deauth' | 'uncloak' | 'handshake' | 'pmkid' | 'beacon' | 'evil-twin';
type Operation = { id: OperationId; label: string; blurb: string; icon: typeof Shield };
const OPERATIONS: Operation[] = [
  { id: 'deauth', label: 'Deauthentication', blurb: 'Tune to a target AP and inject deauthentication frames.', icon: Radio },
  { id: 'uncloak', label: 'Network name reveal', blurb: 'Force a hidden AP client to reconnect so its name can be observed.', icon: Wifi },
  { id: 'handshake', label: 'Handshake capture', blurb: 'Capture a WPA handshake and verify it against a wordlist.', icon: Activity },
  { id: 'pmkid', label: 'PMKID capture', blurb: 'Capture PMKID material and test it against a wordlist.', icon: Shield },
  { id: 'beacon', label: 'Beacon flood', blurb: 'Transmit beacon frames for a chosen SSID and channel.', icon: Radio },
  { id: 'evil-twin', label: 'Evil twin', blurb: 'Start an open AP, DHCP/DNS, and the local portal helper.', icon: Wifi },
];
const FIELD_LABELS: Record<string, string> = {
  deauth: 'deauthentication', uncloak: 'network name reveal', handshake: 'handshake capture',
  pmkid: 'PMKID capture', beacon: 'beacon flood', 'evil-twin': 'evil twin',
};
function numberIn(value: string, min: number, max: number) {
  if (value.trim() === '') return false;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= min && parsed <= max;
}

export function Ops({ status }: { status?: { operationsEnabled?: boolean } }) {
  const [capabilities, setCapabilities] = useState<OpsCapabilities | null>(null);
  const [capabilitiesError, setCapabilitiesError] = useState('');
  const [targets, setTargets] = useState<OpsTarget[]>([]);
  const [observedAps, setObservedAps] = useState<ObservedAp[]>([]);
  const [operation, setOperation] = useState<OperationId>('handshake');
  const [selectedTarget, setSelectedTarget] = useState('');
  const [selectedAp, setSelectedAp] = useState('');
  const [interfaceName, setInterfaceName] = useState('');
  const [apInterface, setApInterface] = useState('wlo1ap');
  const [count, setCount] = useState('5');
  const [ssid, setSsid] = useState('');
  const [channel, setChannel] = useState('6');
  const [rate, setRate] = useState('100');
  const [duration, setDuration] = useState('30');
  const [wordlist, setWordlist] = useState('');
  const [portalPort, setPortalPort] = useState('80');
  const [hiddenBssid, setHiddenBssid] = useState('');
  const [capFile, setCapFile] = useState('');
  const [verifyWordlist, setVerifyWordlist] = useState('');
  const [result, setResult] = useState<Json | null>(null);
  const [operationStatus, setOperationStatus] = useState<OpsStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [active, setActive] = useState<string | null>(null);
  const stopping = useRef(false);
  const initialized = useRef(false);

  const refreshCapabilities = useCallback(async () => {
    try {
      setCapabilities(await opsApi.capabilities());
      setCapabilitiesError('');
    } catch (failure) {
      setCapabilities(null);
      setCapabilitiesError(status?.operationsEnabled === false
        ? 'Lab Ops requires a live capture session. Replay is analysis-only; start Live Wi-Fi with ./ewave.'
        : errorMessage(failure));
    }
  }, [status?.operationsEnabled]);

  const refreshLive = useCallback(async () => {
    const [nextTargets, nextInspector] = await Promise.allSettled([opsApi.targets(), opsApi.inspector()]);
    if (nextTargets.status === 'fulfilled') setTargets(Array.isArray(nextTargets.value) ? nextTargets.value : []);
    if (nextInspector.status === 'fulfilled') setObservedAps(nextInspector.value?.accessPoints ?? []);
  }, []);

  const refreshInventory = useCallback(async () => {
    await Promise.all([refreshCapabilities(), refreshLive()]);
  }, [refreshCapabilities, refreshLive]);

  useEffect(() => {
    void refreshInventory();
    const liveTimer = window.setInterval(() => void refreshLive(), 4000);
    const capabilitiesTimer = window.setInterval(() => void refreshCapabilities(), 20000);
    return () => {
      window.clearInterval(liveTimer);
      window.clearInterval(capabilitiesTimer);
    };
  }, [refreshInventory, refreshLive, refreshCapabilities]);

  useEffect(() => {
    if (!capabilities || initialized.current) return;
    initialized.current = true;
    setWordlist(capabilities.wordlist.path ?? '');
    setVerifyWordlist(capabilities.wordlist.path ?? '');
    const captureStatus = (capabilities.capture?.status ?? {}) as Json;
    setInterfaceName(capabilities.monitorInterfaces[0] || captureStatus.captureInterface || '');
  }, [capabilities]);

  useEffect(() => {
    const evidenced = targets.filter(target => !!target.apBssid);
    if (selectedTarget && !evidenced.some(target => target.id === selectedTarget)) setSelectedTarget('');
  }, [targets, selectedTarget]);

  const evidencedTargets = useMemo(
    () => targets.filter(target => !!target.apBssid),
    [targets],
  );
  const hiddenAps = useMemo(
    () => observedAps.filter(ap => ap.ssidHidden && (ap.clients?.length ?? 0) > 0),
    [observedAps],
  );
  useEffect(() => {
    if (operation !== 'uncloak' || hiddenBssid || hiddenAps.length === 0) return;
    setHiddenBssid(hiddenAps[0].bssid);
  }, [operation, hiddenBssid, hiddenAps]);

  const selectedTargetRow = evidencedTargets.find(target => target.id === selectedTarget);
  const selectedApRow = observedAps.find(ap => ap.bssid === selectedAp);
  const selectedHiddenRow = hiddenAps.find(ap => ap.bssid === hiddenBssid);
  const readiness = operationReadiness(capabilities, operation);
  const isRunning = busy || !!operationStatus?.running;
  const activeLabel = active === 'handshake-verify'
    ? 'PSK verification'
    : OPERATIONS.find(item => item.id === active)?.label ?? active;
  const pollOperation = active && (busy || !!operationStatus?.running) ? active : null;

  useEffect(() => {
    if (!pollOperation) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const next = await opsApi.status(pollOperation);
        if (!cancelled) setOperationStatus(next);
      } catch {
        /* The operation may have completed between polls. */
      }
    };
    void tick();
    const timer = window.setInterval(() => void tick(), 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [pollOperation]);

  const canStart = !busy && (() => {
    switch (operation) {
      case 'deauth': return (!!selectedTarget || !!selectedAp) && !!interfaceName.trim() && numberIn(count, 0, 1_000_000);
      case 'uncloak': return !!hiddenBssid.trim() && !!interfaceName.trim();
      case 'handshake': return (!!selectedTarget || !!selectedAp) && !!interfaceName.trim();
      case 'pmkid': return !!interfaceName.trim() && !!wordlist.trim() && numberIn(duration, 1, 300);
      case 'beacon': return !!interfaceName.trim() && !!ssid.trim() && numberIn(channel, 1, 233) && numberIn(rate, 1, 10_000);
      case 'evil-twin': return !!apInterface.trim() && !!ssid.trim() && numberIn(channel, 1, 233) && numberIn(portalPort, 1, 65_535);
    }
  })();
  const canVerify = !busy && !!capFile.trim() && !!verifyWordlist.trim();

  const requestBody = (): Json | null => {
    switch (operation) {
      case 'deauth':
        return { ...(selectedTarget ? { targetId: selectedTarget } : { apId: selectedAp }), count: Number(count), interface: interfaceName };
      case 'uncloak':
        return { bssid: hiddenBssid.trim(), interface: interfaceName };
      case 'handshake':
        return { ...(selectedTarget ? { targetId: selectedTarget } : { apId: selectedAp }), interface: interfaceName };
      case 'pmkid':
        return { interface: interfaceName, wordlistPath: wordlist.trim(), durationSeconds: Number(duration) };
      case 'beacon':
        return { interface: interfaceName, ssid, channel: Number(channel), rate: Number(rate) };
      case 'evil-twin':
        return { interface: apInterface.trim(), ssid, channel: Number(channel), portalPort: Number(portalPort) };
    }
  };

  async function run(path: string, body: Json, activeId: string) {
    setBusy(true);
    stopping.current = false;
    setError('');
    setResult(null);
    setOperationStatus(null);
    setActive(activeId);
    try {
      const response = await opsApi.start(path, body);
      setResult(response);
      if (activeId === 'handshake' && typeof response.capFilePath === 'string') setCapFile(response.capFilePath);
      try { setOperationStatus(await opsApi.status(activeId)); } catch { /* Result already returned. */ }
      void refreshInventory();
    } catch (failure) {
      if (!stopping.current) setError(errorMessage(failure));
    } finally {
      stopping.current = false;
      setBusy(false);
    }
  }

  function start() {
    const body = requestBody();
    if (!body) return;
    void run(startPath(operation), body, operation);
  }

  function verify() {
    void run('/api/ops/handshake/verify', { capFilePath: capFile.trim(), wordlistPath: verifyWordlist.trim() }, 'handshake-verify');
  }

  async function stop() {
    stopping.current = true;
    try {
      await opsApi.stop();
      setResult(null);
      if (active) setOperationStatus(await opsApi.status(active));
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
    }
  }

  function changeOperation(next: OperationId) {
    if (busy) return;
    setOperation(next);
    setResult(null);
    setOperationStatus(null);
    setError('');
    setActive(null);
  }

  const captureStatus = (capabilities?.capture?.status ?? {}) as Json;
  const missing = capabilities?.operations.filter(item => !item.ready) ?? [];

  return (
    <div className="ops-console">
      <div className="ops-head">
        <div className="ops-title">
          <span className="ops-icon"><Shield size={24} /></span>
          <div>
            <h2>Lab operations</h2>
            <p>Live control for the local backend. {capabilities ? toolSummary(capabilities) : 'Checking prerequisites…'}</p>
          </div>
        </div>
        <div className="ops-head-actions">
          <span className={`ops-live ${isRunning ? 'running' : ''}`}>
            <Activity size={14} />{isRunning ? `${activeLabel ?? 'Operation'} running` : 'Live ready'}
          </span>
          <button className="icon-btn" aria-label="Refresh Ops state" title="Refresh Ops state"
                  onClick={() => void refreshInventory()}>
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      {capabilitiesError && (
        <div className="notice compact"><AlertTriangle size={16} /><div>
          <b>Ops unavailable</b><span>{capabilitiesError}</span>
        </div></div>
      )}

      {capabilities && (
        <>
          <div className="ops-readiness">
            <Metric label="Operations" value={`${capabilities.operations.filter(item => item.ready).length}/${capabilities.operations.length} ready`} />
            <Metric label="Targets" value={`${evidencedTargets.length} evidenced`} />
            <Metric label="Monitor interface" value={interfaceName || 'Not selected'} />
            <Metric label="Capture" value={String(captureStatus.captureMode ?? 'idle')} />
            <Metric label="Active" value={capabilities.activeOperation ?? 'None'} />
          </div>
          <div className="ops-tools">
            {capabilities.tools.map(tool => (
              <span key={tool.name} className={`ops-chip ${tool.available ? 'ok' : 'missing'}`}
                    title={tool.path ?? 'Not found on PATH'}>
                {tool.available ? <CheckCircle2 size={12} /> : <XCircle size={12} />}{tool.name}
              </span>
            ))}
          </div>
          <div className="ops-caches">
            <span>AP cache: {capabilities.caches.accessPoints.available
              ? `${capabilities.caches.accessPoints.entries} entries`
              : 'optional, unavailable'}</span>
            <span>LAN cache: {capabilities.caches.lanHosts.available
              ? `${capabilities.caches.lanHosts.entries} entries`
              : 'optional, unavailable'}</span>
            <span>Wordlist: {capabilities.wordlist.available ? 'ready' : 'not set'}</span>
          </div>
          {missing.length > 0 && (
            <div className="ops-missing">
              <b>Missing tools</b>
              {missing.map(item => <span key={item.id}>{item.label}: {item.missing.join(', ')}</span>)}
            </div>
          )}
        </>
      )}

      <div className="ops-grid">
        <aside className="ops-ops">
          {OPERATIONS.map(item => {
            const row = operationReadiness(capabilities, item.id);
            const Icon = item.icon;
            return (
              <button key={item.id} className={`ops-op ${operation === item.id ? 'active' : ''}`}
                      disabled={busy} onClick={() => changeOperation(item.id)}>
                <Icon size={18} />
                <span className="ops-op-text"><b>{item.label}</b><small>{item.blurb}</small></span>
                <span className={`ops-ready ${row?.ready ? 'ok' : row ? 'warn' : ''}`}>
                  {row ? (row.ready ? 'Ready' : 'Missing tools') : '—'}
                </span>
              </button>
            );
          })}
        </aside>

        <section className="ops-work">
          <div className="ops-section-head">
            <h3>{OPERATIONS.find(item => item.id === operation)?.label}</h3>
            {readiness && !readiness.ready && <span className="ops-warn">Missing {readiness.missing.join(', ')}</span>}
          </div>

          {(operation === 'deauth' || operation === 'handshake') && (
            <>
              <div className="ops-form-grid">
                <Field label="Client target" hint="Live evidenced client and AP from passive capture.">
                  <select value={selectedTarget} onChange={event => {
                    setSelectedTarget(event.target.value);
                    if (event.target.value) setSelectedAp('');
                  }}>
                    <option value="">Select a client target</option>
                    {evidencedTargets.map(target => <option key={target.id} value={target.id}>{targetLabel(target)}</option>)}
                  </select>
                </Field>
                <Field label="Access point" hint="Use an observed AP for broadcast deauth or an AP-only handshake.">
                  <select value={selectedAp} onChange={event => {
                    setSelectedAp(event.target.value);
                    if (event.target.value) setSelectedTarget('');
                  }}>
                    <option value="">Select an observed AP</option>
                    {observedAps.map(ap => <option key={ap.bssid} value={ap.bssid}>{accessPointLabel(ap)}</option>)}
                  </select>
                </Field>
              </div>
              <div className="ops-form-grid">
                <Field label="Monitor interface" hint="An interface already in monitor mode.">
                  <input list="ops-monitor-interfaces" value={interfaceName}
                         onChange={event => setInterfaceName(event.target.value)} placeholder="wlo1" />
                  <datalist id="ops-monitor-interfaces">
                    {capabilities?.monitorInterfaces.map(name => <option key={name} value={name} />)}
                  </datalist>
                </Field>
                {operation === 'deauth' && (
                  <Field label="Deauth count" hint="0 runs the bounded 30-second test window.">
                    <input type="number" min={0} value={count} onChange={event => setCount(event.target.value)} />
                  </Field>
                )}
              </div>
              {(selectedTargetRow || selectedApRow) && (
                <TargetDetail target={selectedTargetRow} ap={selectedApRow} />
              )}
            </>
          )}

          {operation === 'uncloak' && (
            <>
              <div className="ops-form-grid">
                <Field label="Hidden access point" hint="Hidden APs with at least one observed client.">
                  <select value={selectedHiddenRow ? hiddenBssid : ''} onChange={event => setHiddenBssid(event.target.value)}>
                    <option value="">Select a hidden AP</option>
                    {hiddenAps.map(ap => <option key={ap.bssid} value={ap.bssid}>{accessPointLabel(ap)}</option>)}
                  </select>
                </Field>
                <Field label="Monitor interface">
                  <input list="ops-monitor-interfaces-uncloak" value={interfaceName}
                         onChange={event => setInterfaceName(event.target.value)} placeholder="wlo1" />
                  <datalist id="ops-monitor-interfaces-uncloak">
                    {capabilities?.monitorInterfaces.map(name => <option key={name} value={name} />)}
                  </datalist>
                </Field>
              </div>
              <Field label="AP token or BSSID" hint="Use a token from the capture or a direct lab BSSID.">
                <input value={hiddenBssid} onChange={event => setHiddenBssid(event.target.value)}
                       placeholder="wifi:… or 02:11:22:33:44:55" />
              </Field>
              {selectedHiddenRow && <ApDetail ap={selectedHiddenRow} />}
            </>
          )}

          {operation === 'pmkid' && (
            <div className="ops-form-grid">
              <Field label="Monitor interface">
                <input list="ops-monitor-interfaces-pmkid" value={interfaceName}
                       onChange={event => setInterfaceName(event.target.value)} placeholder="wlo1" />
                <datalist id="ops-monitor-interfaces-pmkid">
                  {capabilities?.monitorInterfaces.map(name => <option key={name} value={name} />)}
                </datalist>
              </Field>
              <Field label="Wordlist path">
                <input value={wordlist} onChange={event => setWordlist(event.target.value)} placeholder="/path/to/wordlist" />
              </Field>
              <Field label="Capture seconds" hint="1–300 seconds.">
                <input type="number" min={1} max={300} value={duration} onChange={event => setDuration(event.target.value)} />
              </Field>
            </div>
          )}

          {operation === 'beacon' && (
            <div className="ops-form-grid">
              <Field label="Monitor interface">
                <input list="ops-monitor-interfaces-beacon" value={interfaceName}
                       onChange={event => setInterfaceName(event.target.value)} placeholder="wlo1" />
                <datalist id="ops-monitor-interfaces-beacon">
                  {capabilities?.monitorInterfaces.map(name => <option key={name} value={name} />)}
                </datalist>
              </Field>
              <Field label="SSID">
                <input value={ssid} maxLength={32} onChange={event => setSsid(event.target.value)} placeholder="Lab network" />
              </Field>
              <Field label="Channel" hint="1–233.">
                <input type="number" min={1} max={233} value={channel} onChange={event => setChannel(event.target.value)} />
              </Field>
              <Field label="Rate" hint="Beacons per second, 1–10000.">
                <input type="number" min={1} max={10000} value={rate} onChange={event => setRate(event.target.value)} />
              </Field>
            </div>
          )}

          {operation === 'evil-twin' && (
            <div className="ops-form-grid">
              <Field label="AP interface" hint="The interface hostapd will own; it must not be the monitor interface.">
                <input list="ops-all-interfaces" value={apInterface}
                       onChange={event => setApInterface(event.target.value)} placeholder="wlo1ap" />
                <datalist id="ops-all-interfaces">
                  {capabilities?.interfaces.filter(item => !item.loopback).map(item =>
                    <option key={item.name} value={item.name} />)}
                </datalist>
              </Field>
              <Field label="SSID">
                <input value={ssid} maxLength={32} onChange={event => setSsid(event.target.value)} placeholder="Lab network" />
              </Field>
              <Field label="Channel">
                <input type="number" min={1} max={233} value={channel} onChange={event => setChannel(event.target.value)} />
              </Field>
              <Field label="Portal port" hint="The local portal helper listens on this port.">
                <input type="number" min={1} max={65535} value={portalPort} onChange={event => setPortalPort(event.target.value)} />
              </Field>
            </div>
          )}

          <div className="ops-actions">
            <button disabled={!canStart} onClick={start}><Play size={14} /> Start {FIELD_LABELS[operation]}</button>
            <button className="secondary" disabled={!isRunning} onClick={() => void stop()}><CircleStop size={14} /> Stop operation</button>
          </div>

          {operation === 'handshake' && (
            <div className="ops-verify">
              <div className="ops-section-head"><h3>Verify a capture</h3></div>
              <div className="ops-form-grid">
                <Field label="Capture file" hint="A .cap written by a handshake capture.">
                  <input value={capFile} onChange={event => setCapFile(event.target.value)} placeholder="/tmp/ewave-captures/hs-….cap" />
                </Field>
                <Field label="Wordlist">
                  <input value={verifyWordlist} onChange={event => setVerifyWordlist(event.target.value)} placeholder="/path/to/wordlist" />
                </Field>
              </div>
              <button className="secondary" disabled={!canVerify} onClick={verify}><CheckCircle2 size={14} /> Verify PSK</button>
            </div>
          )}

          {error && (
            <div className="notice error"><AlertTriangle size={16} /><div>
              <b>Operation failed</b><span>{error}</span>
            </div></div>
          )}

          <div className="ops-output-panel">
            <div className="ops-section-head">
              <h3>Operation output</h3>
              {active && <span className="mono">{active === 'handshake-verify' ? 'PSK verification' : active}</span>}
            </div>
            <ResultView operation={active ?? operation} result={result} status={operationStatus} />
          </div>
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><span>{label}</span><b>{value}</b></div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="ops-field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

function TargetDetail({ target, ap }: { target?: OpsTarget; ap?: ObservedAp }) {
  if (target) {
    return (
      <div className="ops-target-detail">
        <span>Client <b className="mono">{target.mac}</b></span>
        <span>AP <b className="mono">{target.apBssid || 'unknown'}</b></span>
        <span>Network <b>{target.apSsid || 'hidden'}</b></span>
        <span>Channel <b>{target.channel ?? '—'}</b></span>
        <span>Frequency <b>{target.frequencyMhz ? `${target.frequencyMhz} MHz` : '—'}</b></span>
        <span>Evidence <b>{target.evidenceSource || '—'}</b></span>
      </div>
    );
  }
  if (!ap) return null;
  return <ApDetail ap={ap} />;
}

function ApDetail({ ap }: { ap: ObservedAp }) {
  return (
    <div className="ops-target-detail">
      <span>AP token <b className="mono">{ap.bssid}</b></span>
      <span>Network <b>{ap.ssid || 'hidden'}</b></span>
      <span>Channel <b>{ap.channel ?? '—'}</b></span>
      <span>Band <b>{ap.band || '—'}</b></span>
      <span>Observed clients <b>{ap.clients?.length ?? 0}</b></span>
      <span>Advertised clients <b>{ap.stationCount ?? '—'}</b></span>
    </div>
  );
}

function ResultView({ operation, result, status }: { operation: string; result: Json | null; status: OpsStatus | null }) {
  if (!result && !status) return <p className="ops-placeholder">Start an operation to see live progress and results.</p>;
  return (
    <div className="ops-result">
      {status && <StatusSummary status={status} />}
      {result && <ResultBody operation={operation} result={result} />}
    </div>
  );
}

function StatusSummary({ status }: { status: OpsStatus }) {
  const credentials = Array.isArray(status.credentials) ? status.credentials : [];
  return (
    <>
      <div className="ops-status-line">
        <span className={`ops-state ${status.running ? 'running' : 'done'}`}>{status.running ? 'Running' : 'Stopped'}</span>
        {status.stage && <b>{status.stage}</b>}
        {status.tool && <span className="mono">{status.tool}</span>}
      </div>
      {status.command && <pre className="ops-command">{status.command}</pre>}
      {status.error && <div className="ops-error-line">{status.error}</div>}
      {typeof status.output === 'string' && status.output.trim() !== '' && <pre className="ops-output">{status.output}</pre>}
      {credentials.length > 0 && (
        <table className="ops-credentials">
          <thead><tr><th>Time</th><th>Client</th><th>Username</th><th>Password</th></tr></thead>
          <tbody>
            {credentials.map((credential, index) => (
              <tr key={`${credential.time}-${credential.client}-${index}`}>
                <td className="mono">{credential.time}</td><td className="mono">{credential.client}</td>
                <td>{credential.username}</td><td className="mono">{credential.password}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

function ResultBody({ operation, result }: { operation: string; result: Json }) {
  if (operation === 'deauth') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.success ? 'done' : 'failed'}`}>{result.success ? 'Injection completed' : 'Injection failed'}</span>
          <span className="mono">{result.attackType}</span>
          <span>{typeof result.durationMs === 'number' ? `${result.durationMs} ms` : ''}</span>
        </div>
        {result.command && <pre className="ops-command">{result.command}</pre>}
        {result.channelWarning && <div className="ops-warn">{result.channelWarning}</div>}
        {typeof result.output === 'string' && <pre className="ops-output">{result.output}</pre>}
      </div>
    );
  }
  if (operation === 'uncloak') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line"><span className="ops-state done">{result.status}</span>
          <span>Client <b className="mono">{result.targetClient}</b></span></div>
        <p>{result.message}</p>
      </div>
    );
  }
  if (operation === 'handshake') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.handshakeDetected ? 'done' : 'failed'}`}>{result.outcome}</span>
          <span>Client <b className="mono">{result.clientMac || 'unknown'}</b></span>
          <span>{result.frequencyMhz ? `${result.frequencyMhz} MHz` : ''}</span>
        </div>
        <div className="ops-target-detail">
          <span>AP <b className="mono">{result.apBssid}</b></span>
          <span>Messages <b>{Array.isArray(result.messages) ? result.messages.join(', ') : '—'}</b></span>
          <span>Capture <b className="mono">{result.capFilePath}</b></span>
        </div>
        {typeof result.captureOutput === 'string' && <pre className="ops-output">{result.captureOutput}</pre>}
      </div>
    );
  }
  if (operation === 'handshake-verify') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.vulnerable ? 'failed' : 'done'}`}>
            {result.vulnerable ? 'PSK found' : 'PSK not found'}
          </span>
          {result.psk && <span>Key <b className="mono">{result.psk}</b></span>}
        </div>
        {typeof result.fullOutput === 'string' && <pre className="ops-output">{result.fullOutput}</pre>}
      </div>
    );
  }
  if (operation === 'pmkid') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.captured ? 'done' : 'failed'}`}>{result.captured ? 'PMKID captured' : 'No PMKID captured'}</span>
          <span>{result.vulnerable ? 'Vulnerable' : 'Not vulnerable'}</span>
          {result.psk && <span>Key <b className="mono">{result.psk}</b></span>}
        </div>
        <div className="ops-target-detail">
          <span>Capture <b className="mono">{result.pcapngPath || '—'}</b></span>
          <span>Hash <b className="mono">{result.hashPath || '—'}</b></span>
        </div>
        {typeof result.output === 'string' && result.output.trim() !== '' && <pre className="ops-output">{result.output}</pre>}
      </div>
    );
  }
  if (operation === 'evil-twin') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.running ? 'running' : 'done'}`}>{result.stage || (result.running ? 'Running' : 'Stopped')}</span>
          {result.portalUrl && <span className="mono">{result.portalUrl}</span>}
        </div>
        {result.error && <div className="ops-error-line">{result.error}</div>}
      </div>
    );
  }
  if (operation === 'beacon') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.running ? 'running' : 'done'}`}>{result.running ? 'Flooding' : 'Stopped'}</span>
          {result.tool && <span className="mono">{result.tool}</span>}
        </div>
        {result.command && <pre className="ops-command">{result.command}</pre>}
        {result.error && <div className="ops-error-line">{result.error}</div>}
        {typeof result.output === 'string' && result.output.trim() !== '' && <pre className="ops-output">{result.output}</pre>}
      </div>
    );
  }
  return <pre className="ops-output">{JSON.stringify(result, null, 2)}</pre>;
}
