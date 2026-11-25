import { get, send, type Json } from './api';

export type OperationTabId = 'deauth' | 'uncloak' | 'handshake' | 'pmkid' | 'beacon' | 'evil-twin';
export type OpsTool = { name: string; available: boolean; path?: string | null };
export type OpsCache = { path: string | null; available: boolean; modifiedAt: number; entries: number; error?: string | null };
export type OpsOperation = { id: string; label: string; ready: boolean; missing: string[] };
export type OpsInterface = {
  name: string;
  up: boolean;
  loopback: boolean;
  virtual: boolean;
  ipv4Addresses?: string[];
};
export type OpsCapabilities = {
  operationsEnabled: boolean;
  tools: OpsTool[];
  operations: OpsOperation[];
  monitorInterfaces: string[];
  interfaces: OpsInterface[];
  caches: { accessPoints: OpsCache; lanHosts: OpsCache };
  wordlist: { path: string | null; available: boolean };
  capture: Json;
  activeOperation: string | null;
  activeOperationId?: string | null;
  generatedAt: number;
};
export type OperationHistoryEntry = {
  id: string;
  operation: string;
  target: string | null;
  interfaceName: string | null;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  outcome: string;
  success: boolean;
};
export type OpsTarget = {
  id: string;
  mac: string;
  type?: string;
  vendor?: string;
  label?: string;
  rssi?: number;
  apId?: string;
  apBssid?: string;
  apSsid?: string | null;
  channel?: number;
  frequencyMhz?: number;
  evidenceSource?: string;
  lastSeen?: number;
  sessionId?: string;
};
export type ObservedAp = {
  bssid: string;
  ssid?: string | null;
  ssidHidden?: boolean;
  channel?: number;
  band?: string;
  frequencyMhz?: number;
  clients?: string[];
  stationCount?: number | null;
  lastSeen?: number;
};
export type InspectorReport = { accessPoints?: ObservedAp[] };
export type OpsStatus = {
  running?: boolean;
  stage?: string;
  command?: string;
  output?: string;
  error?: string | null;
  tool?: string;
  credentials?: Array<{ time: string; client: string; username: string; password: string }>;
  [key: string]: unknown;
};

export const opsApi = {
  capabilities: (signal?: AbortSignal) => get<OpsCapabilities>('/api/ops/capabilities', signal),
  targets: (signal?: AbortSignal) => get<OpsTarget[]>('/api/ops/targets', signal),
  accessPoints: (signal?: AbortSignal) => get<InspectorReport>('/api/capture/access-points', signal),
  status: (operation: string, signal?: AbortSignal) => get<OpsStatus>(statusPath(operation), signal),
  start: (path: string, body: Json) => send<Json>(path, 'POST', body),
  stop: (operationId?: string | null) =>
    send<Json>('/api/ops/stop', 'POST', operationId ? { operationId } : {}),
  history: (signal?: AbortSignal) => get<OperationHistoryEntry[]>('/api/ops/history', signal),
  clearHistory: () => send<Json>('/api/ops/history', 'DELETE'),
};

export function statusPath(operation: string): string {
  if (operation === 'deauth' || operation === 'uncloak') return '/api/ops/status';
  if (operation === 'handshake' || operation === 'handshake-verify') return '/api/ops/handshake/status';
  return `/api/ops/${operation}/status`;
}

export function startPath(operation: string): string {
  return operation === 'handshake-verify' ? '/api/ops/handshake/verify' : `/api/ops/${operation}`;
}

export function operationReadiness(capabilities: OpsCapabilities | null, id: string): OpsOperation | undefined {
  return capabilities?.operations.find(operation => operation.id === id);
}

export function targetLabel(target: OpsTarget): string {
  const network = target.apSsid || 'hidden network';
  const channel = target.channel ? `CH ${target.channel}` : 'channel unknown';
  const frequency = target.frequencyMhz ? ` · ${target.frequencyMhz} MHz` : '';
  const owner = target.label || target.type || target.mac;
  return `${owner} · ${network} · ${channel}${frequency}`;
}

export function accessPointLabel(ap: ObservedAp): string {
  const name = ap.ssid || 'Hidden SSID';
  const channel = ap.channel ? `CH ${ap.channel}` : 'channel unknown';
  const frequency = ap.frequencyMhz ? ` · ${ap.frequencyMhz} MHz` : '';
  const clients = ap.clients?.length ? `${ap.clients.length} client${ap.clients.length === 1 ? '' : 's'}` : 'no observed clients';
  return `${name} · ${channel}${frequency} · ${clients}`;
}

export function toolSummary(capabilities: OpsCapabilities | null): string {
  if (!capabilities) return 'Checking prerequisites…';
  const ready = capabilities.operations.filter(operation => operation.ready).length;
  return `${ready}/${capabilities.operations.length} operation paths ready`;
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Continuous operations (beacon, evil twin) answer their start request while the
 * backend keeps running. `active` is therefore the source of truth for the slot:
 * a missing status means the console has not learned the state yet, not that the
 * operation stopped.
 */
export function operationIsRunning(busy: boolean, active: string | null, status: OpsStatus | null): boolean {
  return busy || (active !== null && (status === null || !!status.running));
}

/** The operation whose status should be polled, or null when polling can stop. */
export function polledOperation(active: string | null, busy: boolean, status: OpsStatus | null): string | null {
  return active !== null && operationIsRunning(busy, active, status) ? active : null;
}

/**
 * A remounted console loses its local `active` state while the backend keeps the
 * single operation slot. Adopt that operation so status polling and Stop remain
 * reachable. Returns null when the current local operation should stand.
 */
export function adoptBackendOperation(
  backendActive: string | null | undefined,
  currentActive: string | null,
  busy: boolean,
): string | null {
  if (!backendActive || busy) return null;
  if (currentActive === backendActive) return null;
  // Network name reveal runs through the injector slot, so the backend reports it as deauth.
  if (currentActive === 'uncloak' && backendActive === 'deauth') return null;
  return backendActive;
}

export function operationTabForActive(active: string | null | undefined): OperationTabId | null {
  if (active === 'handshake-verify') return 'handshake';
  if (active === 'deauth' || active === 'uncloak' || active === 'handshake'
      || active === 'pmkid' || active === 'beacon' || active === 'evil-twin') {
    return active;
  }
  return null;
}

/** Hidden is historical evidence; an already revealed name is no longer an uncloak candidate. */
export function uncloakCandidates(aps: ObservedAp[]): ObservedAp[] {
  return aps.filter(ap => ap.ssidHidden && !ap.ssid && (ap.clients?.length ?? 0) > 0);
}

export function evilTwinChannelSupported(channel: number): boolean {
  return Number.isInteger(channel) && (channel >= 1 && channel <= 14
    || channel >= 32 && channel <= 144 && channel % 4 === 0
    || channel >= 149 && channel <= 177 && (channel - 149) % 4 === 0);
}

export function pmkidRequestBody(params: {
  interfaceName: string;
  wordlistPath: string;
  durationSeconds: number;
  selectedApId?: string;
  apBssid?: string;
  frequencyMhz?: number | null;
}): Json {
  const body: Json = {
    interface: params.interfaceName,
    wordlistPath: params.wordlistPath,
    durationSeconds: params.durationSeconds,
  };
  if (params.selectedApId) {
    body.apId = params.selectedApId;
    return body;
  }
  const bssid = params.apBssid?.trim();
  if (bssid) body.apBssid = bssid;
  if (typeof params.frequencyMhz === 'number' && Number.isInteger(params.frequencyMhz) && params.frequencyMhz > 0) {
    body.frequencyMhz = params.frequencyMhz;
  }
  return body;
}

export function evilTwinAddressSummary(interfaces: OpsInterface[] | undefined, ifaceName: string) {
  const trimmed = ifaceName.trim();
  const match = trimmed ? interfaces?.find(item => item.name === trimmed) : undefined;
  const addresses = match?.ipv4Addresses ?? [];
  return {
    found: !!match,
    up: !!match?.up,
    addresses,
    hasPortalAddress: addresses.includes('10.0.0.1'),
  };
}

export function formatHistoryDuration(durationMs: number): string {
  if (!Number.isFinite(durationMs) || durationMs < 0) return '—';
  if (durationMs < 1000) return `${Math.round(durationMs)} ms`;
  return `${(durationMs / 1000).toFixed(1)} s`;
}

export function isLocallyAdministeredMac(mac?: string | null): boolean {
  if (!mac) return false;
  const match = /^([0-9a-f]{2})(?::[0-9a-f]{2}){5}$/i.exec(mac.trim());
  if (!match) return false;
  const first = Number.parseInt(match[1], 16);
  return (first & 1) === 0 && (first & 2) !== 0;
}
