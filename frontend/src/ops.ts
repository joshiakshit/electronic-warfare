import { get, send, type Json } from './api';

export type OpsTool = { name: string; available: boolean; path?: string | null };
export type OpsCache = { path: string | null; available: boolean; modifiedAt: number; entries: number; error?: string | null };
export type OpsOperation = { id: string; label: string; ready: boolean; missing: string[] };
export type OpsInterface = { name: string; up: boolean; loopback: boolean; virtual: boolean };
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
  generatedAt: number;
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
  inspector: (signal?: AbortSignal) => get<InspectorReport>('/api/inspector', signal),
  status: (operation: string, signal?: AbortSignal) => get<OpsStatus>(statusPath(operation), signal),
  start: (path: string, body: Json) => send<Json>(path, 'POST', body),
  stop: () => send<Json>('/api/ops/stop', 'POST', {}),
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
  const owner = target.label || target.type || target.mac;
  return `${owner} · ${network} · ${channel}`;
}

export function accessPointLabel(ap: ObservedAp): string {
  const name = ap.ssid || 'Hidden SSID';
  const channel = ap.channel ? `CH ${ap.channel}` : 'channel unknown';
  const clients = ap.clients?.length ? `${ap.clients.length} client${ap.clients.length === 1 ? '' : 's'}` : 'no observed clients';
  return `${name} · ${channel} · ${clients}`;
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
