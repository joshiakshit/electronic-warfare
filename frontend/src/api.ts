export type Json = Record<string, any>;
export interface WifiStatus {
  captureRunning?: boolean;
  capturePausedForOps?: boolean;
  captureMode?: string;
  captureInterface?: string;
  captureSource?: string;
  captureStartedAt?: number;
  recordingId?: string;
  sessionId?: string;
  replayState?: string;
  channel?: number;
  preferredApId?: string;
  scopedBssidCount?: number;
  probeRequests?: number;
}
export interface CaptureStatus { wifi: WifiStatus; startedAt: number; operationsEnabled: boolean }
export const snapshotModules = ['spotter', 'whistleblower', 'decloaker', 'inspector', 'profiler', 'tracker', 'lookout'] as const;
export type SnapshotModule = typeof snapshotModules[number];
export interface SnapshotEntry { id: string; name: string; savedAt: number; sessionId: string }
export interface SavedSnapshot extends SnapshotEntry { version: 1; reports: Record<SnapshotModule, Json | Json[] | null> }
export interface Recording { id: string; name: string; bytes: number; importedAt: number }
export interface CaptureHealth { mode: string; source: string; running: boolean; replayState?: string; error?: string; referenceTime?: number; lastPacketAt?: number; sinceLastFrameMs?: number; radio?: { channel?: number | null; frequencyMhz?: number | null } | null; observedFrequencyMhz?: number; observedChannel?: number; frameCounts?: Record<string, number>; decoded: number; rejected: number; unsupported: number; truncated: number }
export interface AdvertisedSecurity {
  protocol: string;
  groupCipher?: string | null;
  pairwiseCiphers?: string[];
  authentication?: string[];
  managementFrameProtection?: string | null;
}
export interface ApRadioSummary {
  wifiGeneration: string; operatingWidthMhz: number; maxWidthMhz: number;
  spatialStreams: number; bssColor?: number | null;
}
export interface WpsInfo {
  state?: 'Configured' | 'Unconfigured' | null; apSetupLocked?: boolean | null;
  manufacturer?: string | null; modelName?: string | null; modelNumber?: string | null; deviceName?: string | null;
}
export interface ApSecurityDetails {
  groupManagementCipher?: string | null; rsnxeFeatures?: string[]; beaconProtection?: boolean; ocvc?: boolean;
  wpsInfo?: WpsInfo | null;
}
export interface SecurityFinding {
  code: string; severity: 'HIGH' | 'MEDIUM' | 'LOW'; summary: string;
}
export interface AccessPointObservation {
  bssid: string; ssid?: string | null; ssidHidden?: boolean; ssidRevealedVia?: string;
  channel?: number; frequencyMhz?: number; band?: string; security?: string; stationCount?: number | null;
  channelUtilization?: number | null; lastSeen?: number; advertisedSecurity?: AdvertisedSecurity[];
  hiddenSsidEvidence?: { name?: string; source?: string; observedAt?: number; beaconObservedAt?: number };
  nonTransmitted?: boolean; radioGroupId?: string | null; mldId?: string | null;
  managementFeatures?: ManagementFeatures | null;
}
export interface InspectorAccessPoint extends AccessPointObservation, ApSecurityDetails {
  vendor?: string | null; apHostname?: string | null; apRadio?: ApRadioSummary | null;
  securityFindings?: SecurityFinding[]; securityModes?: string[]; radioObservation?: RadioObservation | null;
  essId?: string | null;
}
export interface InspectorReport {
  accessPoints: InspectorAccessPoint[]; essGroups?: Record<string, string[]>;
  findingsCount?: number; evilTwinSuspects?: number;
}
export interface ClientLink {
  clientId: string; bssid: string; source: string; evidenceCount: number; firstSeen: number; lastSeen: number;
  associationSeen?: number | null; lastDataSeen?: number | null; channel?: number; frequencyMhz?: number;
  state?: 'ACTIVE' | 'ROAMED_AWAY' | 'DISCONNECTED' | null; controlFrames?: number; clientMldId?: string | null;
}
export interface SpotterDevice {
  id: string; classLabel?: string | null; vendor?: string | null; locallyAdministered?: boolean; randomizedScanSeen?: boolean;
  osHint?: string | null; enrolledLabel?: string | null;
}
export interface MeshLink {
  peerA: string; peerB: string; firstSeen: number; lastSeen: number; frameCount: number;
  channel: number; frequencyMhz: number;
}
export interface SpotterObservations {
  accessPoints: AccessPointObservation[]; edges: ClientLink[];
  devices?: SpotterDevice[]; essGroups?: Record<string, string[]>; meshLinks?: MeshLink[];
}
export interface ApChange {
  clientId: string; fromBssid: string; toBssid: string; time: number; method: string;
  transitionType?: 'INTER_AP_ROAM' | 'BAND_STEER' | 'MLO_LINK_SWITCH' | 'ESS_SWITCH' | null;
  pingPong?: boolean; btmSteered?: boolean; previousDwellMs?: number | null;
  fromRssiDbm?: number | null; toRssiDbm?: number | null;
  fromChannel?: number | null; toChannel?: number | null; fromBand?: string | null; toBand?: string | null;
}
export interface BtmRejection { clientId: string; apId: string; statusCode: number; time: number }
export interface TrackerReport extends Partial<SpotterObservations> { roams: ApChange[]; btmRejections?: BtmRejection[] }
export interface TopologyReport extends SpotterObservations { roams: ApChange[]; btmRejections?: BtmRejection[] }
export interface SignalSample { timestamp: number; rssi: number }
export interface ManagementFeatures {
  radioMeasurement?: boolean; neighborReport?: boolean; bssTransition?: boolean;
  wnmSleep?: boolean; timBroadcast?: boolean; fastTransition?: boolean; twtResponder?: boolean;
  mobilityDomain?: string | null; extendedCapabilitiesHex?: string | null;
}
export interface RadioObservation {
  timestamp: number;
  frequencyMhz: number;
  metadata: {
    channelFlags?: number | null; legacyRateMbps?: number | null; signalDbm?: number | null;
    noiseDbm?: number | null; antenna?: number | null; snrDb?: number | null;
    ht?: { mcs?: number | null; bandwidth?: string | null; shortGuardInterval?: boolean | null } | null;
    he?: { format: string; mcs?: number | null; spaceTimeStreams?: number | null; bandwidthOrRu?: string | null;
      guardIntervalUs?: number | null; dualCarrierModulation?: boolean | null } | null;
  };
}
export interface CorrelationReference { id: string; inference: string; confidence: number; memberCount: number }
export interface ProbeCorrelation {
  id: string;
  inference: string;
  confidence: number;
  memberIds: string[];
  evidence: Array<{ fromId: string; toId: string; sequenceStep: number; gapMs: number;
    sharedDirectedSsidCount: number; confidence: number; basis?: string }>;
}
export interface FingerprintObservation {
  hash: string;
  source: string;
  observations: number;
  generation?: string | null;
  maxWidthMhz?: number;
  spatialStreams?: number;
  ieOrder?: string[];
  vendorElements?: string[];
  bandCohort?: string | null;
}
export interface AssociatedAp {
  apId: string;
  ssid?: string | null;
  channel: number;
  frequencyMhz: number;
  source: string;
}
export interface DeviceProfileContext {
  enrolledLabel?: string | null;
  associatedAp?: AssociatedAp | null;
  osHint?: string | null;
  classificationBasis?: string | null;
  inferredGeneration?: string | null;
  inferredWidthMhz?: number | null;
  inferredStreams?: number | null;
}
export interface DeviceProfileDetail extends DeviceProfileContext {
  signalHistory: SignalSample[];
  fingerprints: FingerprintObservation[];
  radioObservation?: RadioObservation | null;
  inferredCorrelation?: ProbeCorrelation | null;
}
export interface NamedNetworkEntry { id: string; label: string; token?: string | null }
export interface ObservedAccessPoint { token: string; ssid?: string | null; channel: number; frequencyMhz: number }
export interface MyNetwork {
  accessPoints: NamedNetworkEntry[];
  devices: NamedNetworkEntry[];
  observedAccessPoints: ObservedAccessPoint[];
  restrictCapture: boolean;
  commandLineScope: boolean;
}
export interface FingerprintSample { id: string; family: string; osHint: string; evidence: FingerprintObservation }
export interface SniperMove {
  fromChannel: number;
  fromFrequencyMhz: number;
  toChannel: number;
  toFrequencyMhz: number;
  lostAtMs: number;
  tunedAtMs: number | null;
  rediscoveredAtMs: number;
  trigger: 'CSA' | 'SILENCE_SWEEP' | 'HEURISTIC_BSSID_ROTATION' | 'AFFILIATED_LINK_SWITCH' | 'OBSERVED';
}
export interface SniperAffiliatedLink {
  linkId: number | null;
  apId: string;
  channel: number;
  frequencyMhz: number;
  band: '2.4 GHz' | '5 GHz' | '6 GHz';
  supported: boolean;
}
export interface SniperPendingChannelSwitch {
  channel: number;
  frequencyMhz: number;
  scheduledAtMs: number;
  tunedAtMs: number | null;
}
interface SniperEvent { channel: number; timestamp: number }
interface SniperCandidate {
  apId: string;
  ssid?: string | null;
  channel: number;
  frequencyMhz: number;
  rssi?: number | null;
  beaconIntervalTu?: number;
  lastSeenAt: number;
}
export interface SniperRun {
  id: string | null;
  state: 'IDLE' | 'SEARCHING' | 'SELECTING' | 'LOCKED' | 'LOST_SEARCHING';
  targetSsid?: string | null;
  lockedApId?: string | null;
  lockedSsid?: string | null;
  lockedChannel?: number | null;
  lockedFrequencyMhz?: number | null;
  initialSweepComplete?: boolean;
  channelsSwept?: number;
  sweepChannelCount?: number;
  unavailableSweepChannels?: number;
  candidates?: SniperCandidate[];
  startedAt: number;
  endedAt?: number | null;
  lastHeard?: SniperEvent | null;
  tuned?: SniperEvent | null;
  heardAgain?: SniperEvent | null;
  moves?: SniperMove[];
  opsPaused?: boolean;
  activeSweepChannel?: number | null;
  activeSweepFrequencyMhz?: number | null;
  pendingChannelSwitch?: SniperPendingChannelSwitch | null;
  decoyFramesIgnored?: number;
  spoofWarnings?: number;
  mldId?: string | null;
  affiliatedLinks?: SniperAffiliatedLink[];
  bssidRotated?: boolean;
  pendingAffiliatedLinkFrequencyMhz?: number | null;
}
export interface SniperReport { available: boolean; run: SniperRun | null }
export type ReportModule = SnapshotModule | 'status' | 'overview' | 'sniper' | 'settings';
export interface ReportEvent {
  type: 'summary' | 'delta'; seq: number; sessionId: string | null; timestamp: number;
  payload: { modules: ReportModule[] };
}
export async function get<T = Json>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, headers: { Accept: 'application/json' } });
  if (!response.ok) { let message = `${response.status} ${response.statusText}`; try { message = (await response.json()).error || message; } catch {} throw Object.assign(new Error(message), { status: response.status }); }
  return response.json() as Promise<T>;
}
export async function send<T = Json>(path: string, method: 'POST' | 'DELETE', body?: Json): Promise<T> {
  const response = await fetch(path, { method, headers: { Accept: 'application/json', ...((body || method === 'POST') ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
  return mutationResponse<T>(response);
}
async function mutationResponse<T>(response: Response): Promise<T> {
  if (!response.ok) { let message = `${response.status} ${response.statusText}`; try { message = (await response.json()).error || message; } catch {} throw new Error(message); }
  return response.json() as Promise<T>;
}
export async function importRecording(file: File): Promise<Recording> {
  const query = new URLSearchParams({ name: file.name });
  const response = await fetch(`/api/recordings?${query}`, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/octet-stream' },
    body: file,
  });
  return mutationResponse<Recording>(response);
}
const reportModules = new Set<string>([...snapshotModules, 'status', 'overview', 'sniper', 'settings']);

export function subscribe(onEvent: (event: ReportEvent) => void, onState: (up: boolean) => void) {
  let socket: WebSocket | undefined;
  let stopped = false;
  let timer: number | undefined;

  function connect() {
    if (stopped) return;
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    let current: WebSocket;
    try {
      current = new WebSocket(`${scheme}://${location.host}/ws/events`);
    } catch {
      onState(false);
      timer = window.setTimeout(connect, 2000);
      return;
    }
    socket = current;
    let seq = 0;
    let sessionId: string | null = null;
    let recovering = false;
    function recover() {
      if (recovering) return;
      recovering = true;
      onState(false);
      current.close();
    }
    current.onmessage = ({ data }) => {
      if (stopped || recovering) return;
      let event;
      try { event = JSON.parse(data); } catch { recover(); return; }
      if (!event || event.seq !== seq + 1 || typeof event.type !== 'string'
          || !(event.sessionId === null || typeof event.sessionId === 'string')
          || (event.type !== 'summary' && (seq === 0 || event.sessionId !== sessionId))) {
        recover();
        return;
      }
      seq = event.seq;
      if (event.type !== 'summary' && event.type !== 'delta') return;
      if (!Array.isArray(event.payload?.modules)
          || !event.payload.modules.every((module: unknown) => typeof module === 'string' && reportModules.has(module))) {
        recover();
        return;
      }
      if (event.type === 'summary') {
        sessionId = event.sessionId;
        if (seq === 1) onState(true);
      }
      onEvent(event);
    };
    current.onclose = () => {
      if (stopped) return;
      if (!recovering) onState(false);
      timer = window.setTimeout(connect, 2000);
    };
    current.onerror = () => { if (!stopped) recover(); };
  }
  connect();
  return () => {
    stopped = true;
    window.clearTimeout(timer);
    socket?.close();
  };
}
