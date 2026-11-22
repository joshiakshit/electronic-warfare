export type Json = Record<string, any>;
export interface WifiStatus {
  captureRunning?: boolean;
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
export interface Recording { id: string; name: string; bytes: number; importedAt: number }
export interface CaptureHealth { mode: string; source: string; running: boolean; replayState?: string; error?: string; referenceTime?: number; lastPacketAt?: number; sinceLastFrameMs?: number; radio?: { channel?: number | null; frequencyMhz?: number | null } | null; observedFrequencyMhz?: number; observedChannel?: number; frameCounts?: Record<string, number>; decoded: number; rejected: number; unsupported: number; truncated: number }
export interface AdvertisedSecurity {
  protocol: string;
  groupCipher?: string | null;
  pairwiseCiphers?: string[];
  authentication?: string[];
  managementFrameProtection?: string | null;
}
export interface AccessPointObservation { bssid: string; ssid?: string | null; ssidHidden?: boolean; ssidRevealedVia?: string; channel?: number; band?: string; security?: string; stationCount?: number | null; channelUtilization?: number | null; lastSeen?: number; advertisedSecurity?: AdvertisedSecurity[]; hiddenSsidEvidence?: { name?: string; source?: string; observedAt?: number; beaconObservedAt?: number } }
export interface ClientLink { clientId: string; bssid: string; source: string; evidenceCount: number; firstSeen: number; lastSeen: number; associationSeen?: number; lastDataSeen?: number; channel?: number; frequencyMhz?: number }
export interface ApChange { clientId: string; fromBssid: string; toBssid: string; time: number; method: string }
export interface TopologyReport { accessPoints: AccessPointObservation[]; edges: ClientLink[]; roams: ApChange[]; essGroups?: Record<string,string[]> }
export interface SignalSample { timestamp: number; rssi: number }
export interface FingerprintObservation {
  hash: string;
  source: string;
  observations: number;
  generation?: string | null;
  maxWidthMhz?: number;
  spatialStreams?: number;
}
export interface DeviceProfileDetail { signalHistory: SignalSample[]; fingerprints: FingerprintObservation[] }
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
export interface SniperReport { available: boolean; run: null | { id: string; state: string; targetSsid?: string; lockedApId?: string; lockedSsid?: string; lockedChannel?: number; lockedFrequencyMhz?: number; candidates?: Array<{apId:string;ssid?:string;channel:number;frequencyMhz:number;rssi?:number;lastSeenAt:number}>; startedAt:number; endedAt?:number; lastHeard?:{channel:number;timestamp:number}; tuned?:{channel:number;timestamp:number}; heardAgain?:{channel:number;timestamp:number}; moves?:unknown[] } }
export interface EwaveEvent { type: string; timestamp: number; payload: unknown }
export async function get<T = Json>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, { signal, headers: { Accept: 'application/json' } });
  if (!response.ok) { let message = `${response.status} ${response.statusText}`; try { message = (await response.json()).error || message; } catch {} throw Object.assign(new Error(message), { status: response.status }); }
  return response.json() as Promise<T>;
}
export async function send<T = Json>(path: string, method: 'POST' | 'DELETE', body?: Json): Promise<T> {
  const response = await fetch(path, { method, headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
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
export function subscribe(onEvent: (event: EwaveEvent) => void, onState: (up: boolean) => void) {
  let socket: WebSocket | undefined, stopped = false, timer: number;
  const connect = () => { if (stopped) return; socket = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/events`); socket.onopen = () => onState(true); socket.onmessage = e => { try { onEvent(JSON.parse(e.data)); } catch {} }; socket.onclose = () => { onState(false); if (!stopped) timer = window.setTimeout(connect, 2000); }; socket.onerror = () => socket?.close(); };
  connect(); return () => { stopped = true; clearTimeout(timer); socket?.close(); };
}
