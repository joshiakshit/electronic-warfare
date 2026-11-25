import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity, AlertTriangle, CheckCircle2, CircleStop, Play, Radio, RefreshCw, Shield, Wifi, XCircle,
} from 'lucide-react';
import type { Json } from './api';
import {
  accessPointLabel, adoptBackendOperation, errorMessage, evilTwinAddressSummary, evilTwinChannelSupported,
  formatHistoryDuration, isDfsChannel, isLocallyAdministeredMac, matchesTargetFilter, operationIsRunning,
  operationReadiness, operationTabForActive, opsApi, parseSsidList, pmkidRequestBody, pmfDeauthWarning,
  polledOperation, pskSuitabilityWarning, sortObservedAps, sortOpsTargets, startPath, targetLabel, toolSummary,
  uncloakCandidates,
  type ConnectedStation, type DhcpLease, type ExtractedPmkid, type LanHostsReport, type ObservedAp,
  type OperationHistoryEntry, type OperationTabId, type OpsCapabilities, type OpsLaunchIntent, type OpsStatus,
  type OpsTarget,
} from './ops';

type OperationId = OperationTabId;
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

export function Ops({ status, launchIntent }: {
  status?: { operationsEnabled?: boolean };
  launchIntent?: OpsLaunchIntent | null;
}) {
  const [capabilities, setCapabilities] = useState<OpsCapabilities | null>(null);
  const [capabilitiesError, setCapabilitiesError] = useState('');
  const [targets, setTargets] = useState<OpsTarget[]>([]);
  const [observedAps, setObservedAps] = useState<ObservedAp[]>([]);
  const [targetFilter, setTargetFilter] = useState('');
  const [lanHosts, setLanHosts] = useState<LanHostsReport | null>(null);
  const [showLanHosts, setShowLanHosts] = useState(false);
  const [operation, setOperation] = useState<OperationId>('handshake');
  const [selectedTarget, setSelectedTarget] = useState('');
  const [selectedAp, setSelectedAp] = useState('');
  const [interfaceName, setInterfaceName] = useState('');
  const [apInterface, setApInterface] = useState('wlo1ap');
  const [count, setCount] = useState('5');
  const [ssid, setSsid] = useState('');
  const [beaconMultiMode, setBeaconMultiMode] = useState(false);
  const [ssidListText, setSsidListText] = useState('');
  const [channel, setChannel] = useState('6');
  const [rate, setRate] = useState('100');
  const [duration, setDuration] = useState('30');
  const [handshakeTimeout, setHandshakeTimeout] = useState('90');
  const [wordlist, setWordlist] = useState('');
  const [portalPort, setPortalPort] = useState('80');
  const [hiddenBssid, setHiddenBssid] = useState('');
  const [capFile, setCapFile] = useState('');
  const [verifyWordlist, setVerifyWordlist] = useState('');
  const [verifyBssid, setVerifyBssid] = useState('');
  const [savingRecording, setSavingRecording] = useState(false);
  const [savedRecordingMsg, setSavedRecordingMsg] = useState('');
  const [pmkidAp, setPmkidAp] = useState('');
  const [pmkidBssid, setPmkidBssid] = useState('');
  const [pmkidFrequency, setPmkidFrequency] = useState('');
  const [pmkidCaptureOnly, setPmkidCaptureOnly] = useState(false);
  const [pmkidHashPath, setPmkidHashPath] = useState('');
  const [pmkidVerifyBssid, setPmkidVerifyBssid] = useState('');
  const [allowMacRotation, setAllowMacRotation] = useState(false);
  const [configureAddress, setConfigureAddress] = useState(false);
  const [uncloakWatch, setUncloakWatch] = useState<{
    apId: string; remaining: number; revealedSsid: string | null; pmfStatus?: string | null;
  } | null>(null);
  const [history, setHistory] = useState<OperationHistoryEntry[]>([]);
  const [result, setResult] = useState<Json | null>(null);
  const [operationStatus, setOperationStatus] = useState<OpsStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [active, setActive] = useState<string | null>(null);
  const stopping = useRef(false);
  const initialized = useRef(false);
  const uncloakTimer = useRef<number | null>(null);
  const handledLaunchId = useRef<number | null>(null);
  const pendingLaunchIntent = useRef<OpsLaunchIntent | null>(null);
  // Invalidates status responses that were requested before a start/stop completed.
  const statusEpoch = useRef(0);
  // Identifies the current start request so a superseded one cannot clear newer state.
  const runSequence = useRef(0);

  const stopUncloakWatch = useCallback(() => {
    if (uncloakTimer.current != null) {
      window.clearInterval(uncloakTimer.current);
      uncloakTimer.current = null;
    }
  }, []);

  useEffect(() => stopUncloakWatch, [stopUncloakWatch]);

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
    const [nextTargets, nextInspector, nextHistory, nextLan] = await Promise.allSettled([
      opsApi.targets(), opsApi.accessPoints(), opsApi.history(), opsApi.lanHosts(),
    ]);
    if (nextTargets.status === 'fulfilled') setTargets(Array.isArray(nextTargets.value) ? nextTargets.value : []);
    if (nextInspector.status === 'fulfilled') setObservedAps(nextInspector.value?.accessPoints ?? []);
    if (nextHistory.status === 'fulfilled') setHistory(Array.isArray(nextHistory.value) ? nextHistory.value : []);
    if (nextLan.status === 'fulfilled') setLanHosts(nextLan.value);
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

  const evidencedTargets = useMemo(
    () => sortOpsTargets(targets.filter(target => !!target.apBssid)),
    [targets],
  );
  const sortedObservedAps = useMemo(
    () => sortObservedAps(observedAps),
    [observedAps],
  );
  const hiddenAps = useMemo(
    () => sortObservedAps(uncloakCandidates(observedAps)),
    [observedAps],
  );
  const visibleTargets = useMemo(
    () => evidencedTargets.filter(target => target.id === selectedTarget || matchesTargetFilter(targetFilter, [
      target.apSsid, target.apBssid, target.mac, target.label, target.channel, target.lanIp,
    ])),
    [evidencedTargets, selectedTarget, targetFilter],
  );
  const visibleObservedAps = useMemo(
    () => sortedObservedAps.filter(ap => ap.bssid === selectedAp || ap.bssid === pmkidAp || matchesTargetFilter(targetFilter, [
      ap.ssid, ap.bssid, ap.channel, ap.band, ap.security,
    ])),
    [sortedObservedAps, selectedAp, pmkidAp, targetFilter],
  );
  const visibleHiddenAps = useMemo(
    () => hiddenAps.filter(ap => ap.bssid === hiddenBssid || matchesTargetFilter(targetFilter, [
      ap.bssid, ap.channel, ap.band, ap.security,
    ])),
    [hiddenAps, hiddenBssid, targetFilter],
  );
  const parsedSsids = useMemo(() => parseSsidList(ssidListText), [ssidListText]);

  const applyIntentTarget = useCallback((intent: OpsLaunchIntent, liveTargets: OpsTarget[]) => {
    if (intent.tab === 'uncloak') {
      if (intent.apId) setHiddenBssid(intent.apId);
      return;
    }
    if (intent.tab === 'pmkid') {
      if (intent.apId) setPmkidAp(intent.apId);
      return;
    }
    if (intent.tab === 'beacon' || intent.tab === 'evil-twin') {
      if (intent.ssid) setSsid(intent.ssid);
      if (typeof intent.channel === 'number') setChannel(String(intent.channel));
      return;
    }
    const matched = liveTargets.find(t =>
      (intent.targetId && (t.id === intent.targetId || (intent.apId && t.id === `${intent.targetId}:${intent.apId}`)))
      || (intent.apId && t.apId === intent.apId));
    if (matched) {
      setSelectedTarget(matched.id);
      setSelectedAp('');
      setAllowMacRotation(isLocallyAdministeredMac(matched.mac));
      return;
    }
    if (intent.apId) {
      setSelectedAp(intent.apId);
      setSelectedTarget('');
      setAllowMacRotation(false);
    }
  }, []);

  useEffect(() => {
    if (!launchIntent || handledLaunchId.current === launchIntent.id) return;
    handledLaunchId.current = launchIntent.id;
    setOperation(launchIntent.tab);
    setResult(null);
    setOperationStatus(null);
    setError('');
    setActive(null);
    setUncloakWatch(null);
    stopUncloakWatch();
    applyIntentTarget(launchIntent, evidencedTargets);
    if ((launchIntent.tab === 'deauth' || launchIntent.tab === 'handshake')
        && evidencedTargets.length === 0 && observedAps.length === 0) {
      pendingLaunchIntent.current = launchIntent;
    } else {
      pendingLaunchIntent.current = null;
    }
  }, [launchIntent, evidencedTargets, observedAps.length, applyIntentTarget, stopUncloakWatch]);

  useEffect(() => {
    if (pendingLaunchIntent.current && (evidencedTargets.length > 0 || observedAps.length > 0)) {
      const intent = pendingLaunchIntent.current;
      pendingLaunchIntent.current = null;
      applyIntentTarget(intent, evidencedTargets);
      return;
    }
    if (pendingLaunchIntent.current) return;
    if (selectedTarget && !evidencedTargets.some(target => target.id === selectedTarget)) setSelectedTarget('');
  }, [evidencedTargets, observedAps.length, selectedTarget, applyIntentTarget]);

  useEffect(() => {
    if (operation !== 'uncloak') return;
    if (hiddenAps.some(ap => ap.bssid === hiddenBssid)) return;
    if (!hiddenBssid && hiddenAps.length > 0) setHiddenBssid(hiddenAps[0].bssid);
  }, [operation, hiddenBssid, hiddenAps]);

  const selectedTargetRow = evidencedTargets.find(target => target.id === selectedTarget);
  useEffect(() => {
    if (pendingLaunchIntent.current) return;
    if (selectedAp && !observedAps.some(ap => ap.bssid === selectedAp)) setSelectedAp('');
    if (pmkidAp && !observedAps.some(ap => ap.bssid === pmkidAp)) setPmkidAp('');
  }, [observedAps, selectedAp, pmkidAp]);

  const selectedApRow = observedAps.find(ap => ap.bssid === selectedAp);
  const selectedPmkidApRow = observedAps.find(ap => ap.bssid === pmkidAp);
  const selectedHiddenRow = hiddenAps.find(ap => ap.bssid === hiddenBssid);
  const readiness = operationReadiness(capabilities, operation);
  const isRunning = operationIsRunning(busy, active, operationStatus);
  const activeLabel = active === 'handshake-verify'
    ? 'PSK verification'
    : active === 'pmkid-verify'
      ? 'PMKID verification'
      : OPERATIONS.find(item => item.id === active)?.label ?? active;
  const pollOperation = polledOperation(active, busy, operationStatus);

  // Beacon and evil twin outlive their start request, and navigating away remounts
  // this console. Re-adopt the backend's slot so polling and Stop are not orphaned.
  const backendActive = capabilities?.activeOperation ?? null;
  useEffect(() => {
    const adopted = adoptBackendOperation(backendActive, active, busy);
    const tab = operationTabForActive(adopted);
    if (!adopted || !tab) return;
    // Drop state that belonged to a different operation so the first poll decides
    // whether the adopted operation is running.
    setActive(adopted);
    setOperation(tab);
    setOperationStatus(null);
    setResult(null);
  }, [backendActive, active, busy]);

  useEffect(() => {
    if (!pollOperation) return;
    let cancelled = false;
    const tick = async () => {
      const epoch = statusEpoch.current;
      try {
        const next = await opsApi.status(pollOperation);
        if (!cancelled && epoch === statusEpoch.current) setOperationStatus(next);
      } catch {
        /* The operation may have completed between polls. */
      }
    };
    void tick();
    const capsRefresh = window.setTimeout(() => void refreshCapabilities(), 250);
    const timer = window.setInterval(() => void tick(), 1000);
    return () => {
      cancelled = true;
      window.clearTimeout(capsRefresh);
      window.clearInterval(timer);
    };
  }, [pollOperation, refreshCapabilities]);

  const beaconSsidsValid = beaconMultiMode
    ? parsedSsids.length >= 1 && parsedSsids.length <= 50
      && parsedSsids.every(name => new TextEncoder().encode(name).length <= 32)
    : !!ssid.trim();

  const canStart = !isRunning && (() => {
    switch (operation) {
      case 'deauth': return (!!selectedTarget || !!selectedAp) && !!interfaceName.trim() && numberIn(count, 0, 1_000_000);
      case 'uncloak': return !!hiddenBssid.trim() && !!interfaceName.trim();
      case 'handshake': return (!!selectedTarget || !!selectedAp) && !!interfaceName.trim() && numberIn(handshakeTimeout, 10, 180);
      case 'pmkid':
        return !!interfaceName.trim() && (pmkidCaptureOnly || !!wordlist.trim()) && numberIn(duration, 1, 300)
          && (pmkidFrequency.trim() === '' || numberIn(pmkidFrequency, 2300, 7125));
      case 'beacon': return !!interfaceName.trim() && beaconSsidsValid && numberIn(channel, 1, 233) && numberIn(rate, 1, 10_000);
      case 'evil-twin': return !!apInterface.trim() && !!ssid.trim() && evilTwinChannelSupported(Number(channel)) && numberIn(portalPort, 1, 65_535);
    }
  })();
  const canVerify = !isRunning && !!capFile.trim() && !!verifyWordlist.trim();
  const canVerifyPmkid = !isRunning && !!pmkidHashPath.trim() && !!verifyWordlist.trim();

  const requestBody = (): Json | null => {
    switch (operation) {
      case 'deauth':
        return { ...(selectedTarget ? { targetId: selectedTarget } : { apId: selectedAp }), count: Number(count), interface: interfaceName };
      case 'uncloak':
        return { bssid: hiddenBssid.trim(), interface: interfaceName };
      case 'handshake':
        return {
          ...(selectedTarget ? { targetId: selectedTarget } : { apId: selectedAp }),
          interface: interfaceName,
          timeoutSeconds: Number(handshakeTimeout),
          ...(allowMacRotation && selectedTarget ? { allowMacRotation: true } : {}),
        };
      case 'pmkid':
        return pmkidRequestBody({
          interfaceName,
          wordlistPath: wordlist.trim(),
          durationSeconds: Number(duration),
          captureOnly: pmkidCaptureOnly,
          selectedApId: pmkidAp || undefined,
          apBssid: pmkidBssid,
          frequencyMhz: pmkidFrequency.trim() ? Number(pmkidFrequency) : null,
        });
      case 'beacon':
        return beaconMultiMode
          ? { interface: interfaceName, ssids: parsedSsids, channel: Number(channel), rate: Number(rate) }
          : { interface: interfaceName, ssid, channel: Number(channel), rate: Number(rate) };
      case 'evil-twin':
        return {
          interface: apInterface.trim(),
          ssid,
          channel: Number(channel),
          portalPort: Number(portalPort),
          configureAddress,
        };
    }
  };

  function startUncloakWatch(apId: string, pmfStatus: string | null) {
    stopUncloakWatch();
    if (!apId) return;
    setUncloakWatch({ apId, remaining: 10, revealedSsid: null, pmfStatus });
    let ticksLeft = 10;
    uncloakTimer.current = window.setInterval(() => {
      ticksLeft -= 1;
      void (async () => {
        try {
          const report = await opsApi.accessPoints();
          const match = (report?.accessPoints ?? []).find(ap => ap.bssid === apId && ap.ssid?.trim());
          if (match?.ssid) {
            stopUncloakWatch();
            setUncloakWatch({ apId, remaining: 0, revealedSsid: match.ssid.trim(), pmfStatus });
            void refreshLive();
            return;
          }
        } catch {
          /* Ignore transient polling errors during passive hold. */
        }
        if (ticksLeft <= 0) {
          stopUncloakWatch();
          setUncloakWatch(prev => prev ? { ...prev, remaining: 0 } : null);
        } else {
          setUncloakWatch(prev => prev ? { ...prev, remaining: ticksLeft } : null);
        }
      })();
    }, 1000);
  }

  async function run(path: string, body: Json, activeId: string) {
    const sequence = ++runSequence.current;
    statusEpoch.current += 1;
    setBusy(true);
    stopping.current = false;
    setError('');
    setResult(null);
    setOperationStatus(null);
    setSavedRecordingMsg('');
    if (activeId !== 'uncloak') {
      stopUncloakWatch();
      setUncloakWatch(null);
    }
    setActive(activeId);
    setCapabilities(prev => prev ? { ...prev, activeOperation: activeId, activeOperationId: null } : prev);
    try {
      const response = await opsApi.start(path, body);
      if (sequence !== runSequence.current) return;
      // Polls issued while the start request was in flight can predate the backend slot.
      statusEpoch.current += 1;
      setResult(response);
      if (activeId === 'handshake' && typeof response.capFilePath === 'string') {
        setCapFile(response.capFilePath);
        setVerifyBssid(typeof response.apBssid === 'string' ? response.apBssid : '');
      }
      if (activeId === 'pmkid' && typeof response.hashPath === 'string') {
        setPmkidHashPath(response.hashPath);
        setPmkidVerifyBssid(typeof response.targetApBssid === 'string' ? response.targetApBssid : '');
      }
      if (activeId === 'uncloak') {
        startUncloakWatch(
          typeof response.apId === 'string' ? response.apId : hiddenBssid.trim(),
          typeof response.pmfStatus === 'string' ? response.pmfStatus : null,
        );
      }
      const epoch = statusEpoch.current;
      try {
        const next = await opsApi.status(activeId);
        if (sequence === runSequence.current && epoch === statusEpoch.current) setOperationStatus(next);
      } catch { /* Result already returned. */ }
      void refreshInventory();
    } catch (failure) {
      if (sequence !== runSequence.current) return;
      statusEpoch.current += 1;
      if (!stopping.current) {
        setError(errorMessage(failure));
        // A rejected start (for example a 409 from a slot this console did not know
        // about) must not leave the UI claiming an operation it never started.
        setActive(null);
        setOperationStatus(null);
        void refreshInventory();
      }
    } finally {
      if (sequence === runSequence.current) {
        stopping.current = false;
        setBusy(false);
      }
    }
  }

  function start() {
    const body = requestBody();
    if (!body) return;
    void run(startPath(operation), body, operation);
  }

  function verify() {
    void run('/api/ops/handshake/verify', { capFilePath: capFile.trim(), wordlistPath: verifyWordlist.trim(),
      ...(verifyBssid.trim() ? { apBssid: verifyBssid.trim() } : {}) }, 'handshake-verify');
  }

  async function saveRecording() {
    if (!capFile.trim()) return;
    setSavingRecording(true);
    setSavedRecordingMsg('');
    try {
      const rec = await opsApi.saveHandshakeRecording({ capFilePath: capFile.trim() });
      setSavedRecordingMsg(`Saved recording: ${String(rec.name ?? rec.id ?? 'pcap')}`);
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSavingRecording(false);
    }
  }

  function verifyPmkid() {
    void run('/api/ops/pmkid/verify', {
      wordlistPath: verifyWordlist.trim(),
      hashPath: pmkidHashPath.trim(),
      ...(pmkidVerifyBssid.trim() ? { apBssid: pmkidVerifyBssid.trim() } : {}),
    }, 'pmkid-verify');
  }

  async function stop() {
    stopping.current = true;
    stopUncloakWatch();
    try {
      await opsApi.stop(capabilities?.activeOperationId);
      statusEpoch.current += 1;
      setResult(null);
      if (active) {
        const epoch = statusEpoch.current;
        try {
          const next = await opsApi.status(active);
          if (epoch === statusEpoch.current) setOperationStatus(next);
        } catch { /* Stop already succeeded; the status poll can reconcile. */ }
      }
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setBusy(false);
      void refreshInventory();
    }
  }

  async function clearHistory() {
    try {
      await opsApi.clearHistory();
      setHistory([]);
    } catch (failure) {
      setError(errorMessage(failure));
    }
  }

  function changeOperation(next: OperationId) {
    // Switching tabs must never drop the handle on a running operation (beacon and
    // evil twin keep running after their start request returns; busy is already false).
    if (isRunning) return;
    setOperation(next);
    setResult(null);
    setOperationStatus(null);
    setError('');
    setSavedRecordingMsg('');
    setUncloakWatch(null);
    stopUncloakWatch();
    setActive(null);
  }

  const captureStatus = (capabilities?.capture?.status ?? {}) as Json;
  const missing = capabilities?.operations.filter(item => !item.ready) ?? [];
  const ifaceAddress = evilTwinAddressSummary(capabilities?.interfaces, apInterface);
  const evilTwinHint = ifaceAddress.found
    ? `${ifaceAddress.addresses.length ? `IPv4: ${ifaceAddress.addresses.join(', ')}` : 'No IPv4 assigned'}${ifaceAddress.hasPortalAddress ? ' · 10.0.0.1 ready' : ''}. Must differ from monitor.`
    : 'The interface hostapd will own; it must not be the monitor interface.';

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
          {lanHosts?.available && lanHosts.hosts.length > 0 && (
            <div className="ops-lan-panel">
              <button type="button" className="ops-lan-toggle"
                      aria-expanded={showLanHosts}
                      onClick={() => setShowLanHosts(prev => !prev)}>
                {showLanHosts ? 'Hide' : 'Show'} cached LAN hosts ({lanHosts.hosts.length})
              </button>
              {showLanHosts && (
                <div className="ops-lan-table">
                  <table className="ops-credentials">
                    <thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Wi-Fi correlation</th><th /></tr></thead>
                    <tbody>
                      {lanHosts.hosts.map(host => (
                        <tr key={`${host.ip}-${host.mac}`}>
                          <td className="mono">{host.ip}</td>
                          <td className="mono">{host.mac}</td>
                          <td>{host.vendor || '—'}</td>
                          <td>{host.wirelessMatched ? `${host.apSsid || 'Observed AP'}${host.channel ? ` · CH ${host.channel}` : ''}` : 'No live match'}</td>
                          <td>
                            {host.targetId && (
                              <button type="button" className="text-button" onClick={() => {
                                setSelectedTarget(host.targetId!);
                                setSelectedAp('');
                                if (operation !== 'deauth' && operation !== 'handshake') setOperation('deauth');
                              }}>Select target</button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
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
                      disabled={isRunning} onClick={() => changeOperation(item.id)}>
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

          {['deauth', 'handshake', 'uncloak', 'pmkid'].includes(operation) && (
            <Field label="Filter targets & APs" hint="Sorted by strongest signal; type an SSID, BSSID, client, or channel.">
              <input value={targetFilter} onChange={event => setTargetFilter(event.target.value)}
                     placeholder="Filter e.g. EWAVE, CH 36…" />
            </Field>
          )}

          {(operation === 'deauth' || operation === 'handshake') && (
            <>
              <div className="ops-form-grid">
                <Field label="Client target" hint="Live evidenced client and AP from passive capture.">
                  <select value={selectedTarget} onChange={event => {
                    const nextId = event.target.value;
                    setSelectedTarget(nextId);
                    if (nextId) {
                      setSelectedAp('');
                      const nextTarget = evidencedTargets.find(target => target.id === nextId);
                      setAllowMacRotation(isLocallyAdministeredMac(nextTarget?.mac));
                    } else {
                      setAllowMacRotation(false);
                    }
                  }}>
                    <option value="">Select a client target</option>
                    {visibleTargets.map(target => <option key={target.id} value={target.id}>{targetLabel(target)}</option>)}
                  </select>
                </Field>
                <Field label="Access point" hint="Use an observed AP for broadcast deauth or an AP-only handshake.">
                  <select value={selectedAp} onChange={event => {
                    setSelectedAp(event.target.value);
                    if (event.target.value) {
                      setSelectedTarget('');
                      setAllowMacRotation(false);
                    }
                  }}>
                    <option value="">Select an observed AP</option>
                    {visibleObservedAps.map(ap => <option key={ap.bssid} value={ap.bssid}>{accessPointLabel(ap)}</option>)}
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
                {operation === 'handshake' && (
                  <Field label="Capture timeout (s)" hint="10–180 seconds passive observation window.">
                    <input type="number" min={10} max={180} value={handshakeTimeout}
                           onChange={event => setHandshakeTimeout(event.target.value)} />
                  </Field>
                )}
              </div>
              {(selectedTargetRow || selectedApRow) && (
                <TargetDetail target={selectedTargetRow} ap={selectedApRow} operation={operation} />
              )}
              {operation === 'handshake' && selectedTarget && (
                <label className="ops-checkbox">
                  <input type="checkbox" checked={allowMacRotation}
                         onChange={event => setAllowMacRotation(event.target.checked)} />
                  <span>Accept rotated client MAC on reconnect (for randomized-MAC phones)</span>
                </label>
              )}
            </>
          )}

          {operation === 'uncloak' && (
            <>
              <div className="ops-form-grid">
                <Field label="Hidden access point" hint="Hidden APs with at least one observed client.">
                  <select value={selectedHiddenRow ? hiddenBssid : ''} onChange={event => setHiddenBssid(event.target.value)}>
                    <option value="">Select a hidden AP</option>
                    {visibleHiddenAps.map(ap => <option key={ap.bssid} value={ap.bssid}>{accessPointLabel(ap)}</option>)}
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
              {selectedHiddenRow && <ApDetail ap={selectedHiddenRow} operation="uncloak" />}
            </>
          )}

          {operation === 'pmkid' && (
            <>
              <label className="ops-checkbox">
                <input type="checkbox" checked={pmkidCaptureOnly}
                       onChange={event => setPmkidCaptureOnly(event.target.checked)} />
                <span>Capture only (skip dictionary verification)</span>
              </label>
              <div className="ops-form-grid">
                <Field label="Monitor interface">
                  <input list="ops-monitor-interfaces-pmkid" value={interfaceName}
                         onChange={event => setInterfaceName(event.target.value)} placeholder="wlo1" />
                  <datalist id="ops-monitor-interfaces-pmkid">
                    {capabilities?.monitorInterfaces.map(name => <option key={name} value={name} />)}
                  </datalist>
                </Field>
                <Field label="Wordlist path" hint={pmkidCaptureOnly ? 'Skipped in capture-only mode.' : undefined}>
                  <input value={wordlist} disabled={pmkidCaptureOnly}
                         onChange={event => setWordlist(event.target.value)} placeholder="/path/to/wordlist" />
                </Field>
                <Field label="Capture seconds" hint="1–300 seconds.">
                  <input type="number" min={1} max={300} value={duration} onChange={event => setDuration(event.target.value)} />
                </Field>
                <Field label="Target access point" hint="Optional. Leave unscoped to capture nearby APs.">
                  <select value={pmkidAp} onChange={event => {
                    setPmkidAp(event.target.value);
                    if (event.target.value) {
                      setPmkidBssid('');
                      setPmkidFrequency('');
                    }
                  }}>
                    <option value="">All nearby APs (unscoped)</option>
                    {visibleObservedAps.map(ap => <option key={ap.bssid} value={ap.bssid}>{accessPointLabel(ap)}</option>)}
                  </select>
                </Field>
              </div>
              <div className="ops-form-grid">
                <Field label="Target AP BSSID (optional)" hint="Overrides unscoped capture when targeting a lab BSSID directly.">
                  <input value={pmkidBssid} disabled={!!pmkidAp}
                         onChange={event => { setPmkidBssid(event.target.value); if (event.target.value) setPmkidAp(''); }}
                         placeholder="Optional: 02:11:22:33:44:55" />
                </Field>
                <Field label="Frequency MHz (optional)" hint="2300–7125 MHz. Observed APs resolve frequency automatically.">
                  <input type="number" min={2300} max={7125} value={pmkidFrequency} disabled={!!pmkidAp}
                         onChange={event => { setPmkidFrequency(event.target.value); if (event.target.value) setPmkidAp(''); }}
                         placeholder="Optional: 2437" />
                </Field>
              </div>
              {selectedPmkidApRow && <ApDetail ap={selectedPmkidApRow} operation="pmkid" />}
            </>
          )}

          {operation === 'beacon' && (
            <>
              <label className="ops-checkbox">
                <input type="checkbox" checked={beaconMultiMode}
                       onChange={event => setBeaconMultiMode(event.target.checked)} />
                <span>Advertise multiple SSIDs (1–50 lines)</span>
              </label>
              <div className="ops-form-grid">
                <Field label="Monitor interface">
                  <input list="ops-monitor-interfaces-beacon" value={interfaceName}
                         onChange={event => setInterfaceName(event.target.value)} placeholder="wlo1" />
                  <datalist id="ops-monitor-interfaces-beacon">
                    {capabilities?.monitorInterfaces.map(name => <option key={name} value={name} />)}
                  </datalist>
                </Field>
                {beaconMultiMode ? (
                  <Field label={`SSID list (${parsedSsids.length}/50)`} hint="One SSID per non-empty line, max 32 UTF-8 bytes each.">
                    <textarea value={ssidListText} onChange={event => setSsidListText(event.target.value)}
                              placeholder={'Lab-Net-1\nLab-Net-2'} />
                  </Field>
                ) : (
                  <Field label="SSID">
                    <input value={ssid} maxLength={32} onChange={event => setSsid(event.target.value)} placeholder="Lab network" />
                  </Field>
                )}
                <Field label="Channel" hint="1–233.">
                  <input type="number" min={1} max={233} value={channel} onChange={event => setChannel(event.target.value)} />
                </Field>
                <Field label="Rate" hint="Beacons per second, 1–10000.">
                  <input type="number" min={1} max={10000} value={rate} onChange={event => setRate(event.target.value)} />
                </Field>
              </div>
            </>
          )}

          {operation === 'evil-twin' && (
            <>
              <div className="ops-form-grid">
                <Field label="AP interface" hint={evilTwinHint}>
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
                <Field label="Channel" hint="2.4/5 GHz only. 6 GHz AP setup is unavailable.">
                  <input type="number" min={1} max={177} value={channel} onChange={event => setChannel(event.target.value)} />
                </Field>
                <Field label="Portal port" hint="The local portal helper listens on this port.">
                  <input type="number" min={1} max={65535} value={portalPort} onChange={event => setPortalPort(event.target.value)} />
                </Field>
              </div>
              <label className="ops-checkbox">
                <input type="checkbox" checked={configureAddress}
                       onChange={event => setConfigureAddress(event.target.checked)} />
                <span>Assign 10.0.0.1/24 to AP interface while running (uses sudo ip; removed on stop)</span>
              </label>
            </>
          )}

          <div className="ops-actions">
            <button disabled={!canStart} onClick={start}><Play size={14} /> Start {FIELD_LABELS[operation]}</button>
            {isRunning && active === 'handshake' && (
              <button className="secondary" type="button" onClick={() => void opsApi.finishHandshake()}>
                <CheckCircle2 size={14} /> Finish &amp; keep capture
              </button>
            )}
            {isRunning && active === 'pmkid' && (
              <button className="secondary" type="button" onClick={() => void opsApi.finishPmkid()}>
                <CheckCircle2 size={14} /> Finish capture &amp; extract
              </button>
            )}
            <button className="secondary" disabled={!isRunning} onClick={() => void stop()}><CircleStop size={14} /> Stop operation</button>
          </div>

          {operation === 'handshake' && (
            <div className="ops-verify">
              <div className="ops-section-head"><h3>Verify a capture</h3></div>
              <div className="ops-form-grid">
                <Field label="Capture file" hint="A .cap written by a handshake capture.">
                  <input value={capFile} onChange={event => { setCapFile(event.target.value); setVerifyBssid(''); }} placeholder="/tmp/ewave-capture-…/hs-….cap" />
                </Field>
                <Field label="AP BSSID" hint="Required for imported captures; capture results fill this automatically.">
                  <input value={verifyBssid} onChange={event => setVerifyBssid(event.target.value)} placeholder="02:11:22:33:44:55" />
                </Field>
                <Field label="Wordlist">
                  <input value={verifyWordlist} onChange={event => setVerifyWordlist(event.target.value)} placeholder="/path/to/wordlist" />
                </Field>
              </div>
              <div className="ops-verify-actions">
                <button className="secondary" disabled={!canVerify} onClick={verify}><CheckCircle2 size={14} /> Verify PSK</button>
                <button className="secondary" type="button" disabled={isRunning || savingRecording || !capFile.trim()}
                        onClick={() => void saveRecording()}>
                  {savingRecording ? 'Saving…' : 'Save to Recording Library'}
                </button>
                {savedRecordingMsg && <span className="ops-status-line">{savedRecordingMsg}</span>}
              </div>
            </div>
          )}

          {operation === 'pmkid' && (
            <div className="ops-verify">
              <div className="ops-section-head"><h3>Verify captured PMKID</h3></div>
              <div className="ops-form-grid">
                <Field label="Hash file (.22000)" hint="Filled automatically after PMKID extraction.">
                  <input value={pmkidHashPath} onChange={event => setPmkidHashPath(event.target.value)} placeholder="/tmp/ewave-pmkid-…/pmkid.22000" />
                </Field>
                <Field label="Wordlist">
                  <input value={verifyWordlist} onChange={event => setVerifyWordlist(event.target.value)} placeholder="/path/to/wordlist" />
                </Field>
              </div>
              <div className="ops-verify-actions">
                <button className="secondary" disabled={!canVerifyPmkid} onClick={verifyPmkid}><CheckCircle2 size={14} /> Verify PMKID</button>
              </div>
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
              {active && (
                <span className="mono">
                  {active === 'handshake-verify' ? 'PSK verification' : active === 'pmkid-verify' ? 'PMKID verification' : active}
                </span>
              )}
            </div>
            <ResultView operation={active ?? operation} result={result} status={operationStatus} />
            {uncloakWatch && (
              <div className="ops-uncloak-watch" role="status">
                {uncloakWatch.revealedSsid
                  ? `SSID revealed: ${uncloakWatch.revealedSsid}`
                  : uncloakWatch.remaining > 0
                    ? `Holding passive channel · watching for client reconnect (${uncloakWatch.remaining}s)…`
                    : `10s passive hold finished without a reconnect.${uncloakWatch.pmfStatus === 'Required' ? ' Target AP requires 802.11w PMF.' : ''}`}
              </div>
            )}
          </div>
          <OperationHistoryPanel history={history} onClear={() => void clearHistory()} />
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

function TargetDetail({ target, ap, operation }: { target?: OpsTarget; ap?: ObservedAp; operation: OperationId }) {
  if (target) {
    const dfs = Boolean(target.dfsChannel) || isDfsChannel(target.channel, target.frequencyMhz);
    const warning = operation === 'deauth'
      ? pmfDeauthWarning(target.pmfStatus)
      : operation === 'handshake'
        ? pskSuitabilityWarning(target.apSecurity, target.akmSuites)
        : null;
    return (
      <div className="ops-target-detail">
        <span>Client <b className="mono">{target.mac}</b></span>
        <span>AP <b className="mono">{target.apBssid || 'unknown'}</b></span>
        <span>Network <b>{target.apSsid || 'hidden'}</b></span>
        <span>Channel <b>{target.channel ?? '—'}{dfs ? ' (DFS)' : ''}</b></span>
        <span>Frequency <b>{target.frequencyMhz ? `${target.frequencyMhz} MHz` : '—'}</b></span>
        <span>Evidence <b>{target.evidenceSource || '—'}</b></span>
        {target.apSecurity && <span>Security <b>{target.apSecurity}</b></span>}
        {target.pmfStatus && <span>PMF <b>{target.pmfStatus}</b></span>}
        {target.lanIp && <span>LAN IP <b className="mono">{target.lanIp}</b></span>}
        {warning && <span className="ops-warn">{warning}</span>}
        {dfs && <span className="ops-warn">DFS channel: adapter regulatory rules apply.</span>}
      </div>
    );
  }
  if (!ap) return null;
  return <ApDetail ap={ap} operation={operation} />;
}

function ApDetail({ ap, operation }: { ap: ObservedAp; operation?: OperationId }) {
  const dfs = Boolean(ap.dfsChannel) || isDfsChannel(ap.channel, ap.frequencyMhz);
  const warning = operation === 'deauth' || operation === 'uncloak'
    ? pmfDeauthWarning(ap.managementFrameProtection)
    : operation === 'handshake' || operation === 'pmkid'
      ? pskSuitabilityWarning(ap.security, ap.akmSuites)
      : null;
  return (
    <div className="ops-target-detail">
      <span>AP token <b className="mono">{ap.bssid}</b></span>
      <span>Network <b>{ap.ssid || 'hidden'}</b></span>
      <span>Channel <b>{ap.channel ?? '—'}{dfs ? ' (DFS)' : ''}</b></span>
      <span>Band <b>{ap.band || '—'}</b></span>
      <span>Observed clients <b>{ap.clients?.length ?? 0}</b></span>
      <span>Advertised clients <b>{ap.stationCount ?? '—'}</b></span>
      {ap.security && <span>Security <b>{ap.security}</b></span>}
      {ap.managementFrameProtection && <span>PMF <b>{ap.managementFrameProtection}</b></span>}
      {warning && <span className="ops-warn">{warning}</span>}
      {dfs && <span className="ops-warn">DFS channel: adapter regulatory rules apply.</span>}
    </div>
  );
}

export function ResultView({ operation, result, status }: { operation: string; result: Json | null; status: OpsStatus | null }) {
  if (!result && !status) return <p className="ops-placeholder">Start an operation to see live progress and results.</p>;
  // Continuous operations return a start snapshot; polling supplies their newer state and diagnostics.
  const latest = result && status && (operation === 'beacon' || operation === 'evil-twin')
    ? { ...result, ...status } : result;
  const command = latest?.command ?? status?.command;
  const error = latest?.error ?? status?.error;
  const output = latest?.output ?? latest?.captureOutput ?? latest?.fullOutput ?? status?.output;
  return (
    <div className="ops-result">
      {status && <StatusSummary status={status} />}
      {latest && <ResultBody operation={operation} result={latest} />}
      {command && <pre className="ops-command">{command}</pre>}
      {error && <div className="ops-error-line">{error}</div>}
      {typeof output === 'string' && output.trim() !== '' && <pre className="ops-output">{output}</pre>}
    </div>
  );
}

function StatusSummary({ status }: { status: OpsStatus }) {
  const credentials = Array.isArray(status.credentials) ? status.credentials : [];
  const connectedStations = Array.isArray(status.connectedStations) ? status.connectedStations as ConnectedStation[] : [];
  const dhcpLeases = Array.isArray(status.dhcpLeases) ? status.dhcpLeases as DhcpLease[] : [];
  const observedMessages = Array.isArray(status.observedMessages) ? status.observedMessages : [];
  const showHandshakeProgress = status.beaconSeen !== undefined || observedMessages.length > 0;
  const showPmkidPhase = typeof status.phase === 'string' && !['IDLE', 'RUNNING'].includes(status.phase);
  return (
    <>
      <div className="ops-status-line">
        <span className={`ops-state ${status.running ? 'running' : 'done'}`}>{status.running ? 'Running' : 'Stopped'}</span>
        {status.stage && <b>{status.stage}</b>}
        {status.tool && <span className="mono">{status.tool}</span>}
        {typeof status.remainingSeconds === 'number' && <span>{status.remainingSeconds}s remaining</span>}
        {typeof status.elapsedSeconds === 'number' && status.elapsedSeconds > 0 && <span>{status.elapsedSeconds}s elapsed</span>}
        {typeof status.ssidCount === 'number' && status.ssidCount > 0 && <span>{status.ssidCount} SSIDs</span>}
      </div>
      {showHandshakeProgress && (
        <div className="ops-steps" aria-label="Handshake progress">
          <span className={`ops-step ${status.beaconSeen ? 'done' : ''}`}>Beacon</span>
          {[1, 2, 3, 4].map(msg => (
            <span key={msg} className={`ops-step ${observedMessages.includes(msg) ? 'done' : ''}`}>{`M${msg}`}</span>
          ))}
          {status.verifiable && status.verifiablePair && (
            <span className="ops-state done">{`Verifiable (${status.verifiablePair})`}</span>
          )}
          {status.peerMac && <span className="mono">{`Peer ${status.peerMac}`}</span>}
        </div>
      )}
      {showPmkidPhase && (
        <div className="ops-status-line">
          <span>Phase <b>{status.phase}</b></span>
          <span>PMKIDs <b>{status.pmkidCount ?? 0}</b></span>
          <span>EAPOL pairs <b>{status.eapolPairCount ?? 0}</b></span>
        </div>
      )}
      {connectedStations.length > 0 && (
        <table className="ops-credentials">
          <thead><tr><th>Associated stations</th><th>Connected at</th></tr></thead>
          <tbody>
            {connectedStations.map(st => (
              <tr key={`${st.mac}-${st.connectedAt ?? ''}`}>
                <td className="mono">{st.mac}</td>
                <td className="mono">{st.connectedAt || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {dhcpLeases.length > 0 && (
        <table className="ops-credentials">
          <thead><tr><th>DHCP lease IP</th><th>MAC</th><th>Hostname</th></tr></thead>
          <tbody>
            {dhcpLeases.map(lease => (
              <tr key={`${lease.ip}-${lease.mac}`}>
                <td className="mono">{lease.ip}</td>
                <td className="mono">{lease.mac}</td>
                <td>{lease.hostname || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
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
          {typeof result.holdSeconds === 'number' && <span>{`Passive channel held ${result.holdSeconds}s`}</span>}
        </div>
        {result.pmfWarning && <div className="ops-warn">{result.pmfWarning}</div>}
        {result.channelWarning && <div className="ops-warn">{result.channelWarning}</div>}
      </div>
    );
  }
  if (operation === 'uncloak') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line"><span className="ops-state done">{result.status}</span>
          <span>Client <b className="mono">{result.targetClient}</b></span>
          {typeof result.holdSeconds === 'number' && <span>{`Passive channel held ${result.holdSeconds}s`}</span>}
        </div>
        {result.pmfWarning && <div className="ops-warn">{result.pmfWarning}</div>}
        <p>{result.message}</p>
      </div>
    );
  }
  if (operation === 'handshake') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.handshakeDetected || result.verifiable ? 'done' : 'failed'}`}>{result.outcome}</span>
          {result.verifiable && result.verifiablePair && (
            <span className="ops-state done">{`Verifiable (${result.verifiablePair})`}</span>
          )}
          <span>Client <b className="mono">{result.clientMac || 'unknown'}</b></span>
          <span>{result.frequencyMhz ? `${result.frequencyMhz} MHz` : ''}</span>
        </div>
        <div className="ops-target-detail">
          <span>AP <b className="mono">{result.apBssid}</b></span>
          <span>Messages <b>{Array.isArray(result.messages) ? result.messages.join(', ') : '—'}</b></span>
          <span>Capture <b className="mono">{result.capFilePath}</b></span>
        </div>
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
      </div>
    );
  }
  if (operation === 'pmkid' || operation === 'pmkid-verify') {
    const pmkids = Array.isArray(result.pmkids) ? result.pmkids as ExtractedPmkid[] : [];
    const skipped = Boolean(result.verificationSkipped);
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.captured ? 'done' : 'failed'}`}>{result.captured ? 'PMKID captured' : 'No PMKID captured'}</span>
          <span>{skipped ? 'Verification skipped' : result.vulnerable ? 'Vulnerable' : 'Not vulnerable'}</span>
          {typeof result.eapolPairCount === 'number' && result.eapolPairCount > 0 && (
            <span>{`${result.eapolPairCount} EAPOL pair${result.eapolPairCount === 1 ? '' : 's'}`}</span>
          )}
          {result.psk && <span>Key <b className="mono">{result.psk}</b></span>}
        </div>
        <div className="ops-target-detail">
          {result.targetApBssid && <span>Target AP <b className="mono">{result.targetApBssid}</b></span>}
          {result.frequencyMhz && <span>Frequency <b>{result.frequencyMhz} MHz</b></span>}
          <span>Capture <b className="mono">{result.pcapngPath || '—'}</b></span>
          <span>Hash <b className="mono">{result.hashPath || '—'}</b></span>
        </div>
        {pmkids.length > 0 && (
          <table className="ops-credentials">
            <thead><tr><th>Extracted PMKID</th><th>AP BSSID</th><th>Station</th><th>ESSID</th></tr></thead>
            <tbody>
              {pmkids.map((row, index) => (
                <tr key={`${row.pmkid}-${index}`}>
                  <td className="mono">{row.pmkid.slice(0, 12)}…</td>
                  <td className="mono">{row.apBssid}</td>
                  <td className="mono">{row.stationMac}</td>
                  <td>{row.essid || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
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
      </div>
    );
  }
  if (operation === 'beacon') {
    return (
      <div className="ops-result-body">
        <div className="ops-status-line">
          <span className={`ops-state ${result.running ? 'running' : 'done'}`}>{result.running ? 'Flooding' : 'Stopped'}</span>
          {result.tool && <span className="mono">{result.tool}</span>}
          {typeof result.ssidCount === 'number' && result.ssidCount > 0 && <span>{result.ssidCount} SSIDs</span>}
        </div>
      </div>
    );
  }
  return <pre className="ops-output">{JSON.stringify(result, null, 2)}</pre>;
}

export function OperationHistoryPanel({
  history,
  onClear,
}: {
  history: OperationHistoryEntry[];
  onClear: () => void;
}) {
  return (
    <div className="ops-output-panel ops-history">
      <div className="ops-section-head">
        <h3>Recent operations</h3>
        {history.length > 0 && (
          <button type="button" className="ops-history-clear" onClick={onClear}>Clear history</button>
        )}
      </div>
      {history.length === 0 ? (
        <p className="ops-placeholder">No operations recorded in this session yet.</p>
      ) : (
        <table className="ops-credentials">
          <thead>
            <tr><th>Operation</th><th>Target</th><th>Interface</th><th>Outcome</th><th>Duration</th><th>Ended</th></tr>
          </thead>
          <tbody>
            {history.map(entry => (
              <tr key={entry.id}>
                <td className="mono">{entry.operation}</td>
                <td className="mono">{entry.target || '—'}</td>
                <td className="mono">{entry.interfaceName || '—'}</td>
                <td><span className={`ops-state ${entry.success ? 'done' : 'failed'}`}>{entry.outcome}</span></td>
                <td>{formatHistoryDuration(entry.durationMs)}</td>
                <td className="mono">{entry.endedAt}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
