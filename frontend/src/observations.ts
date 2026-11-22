import type { AdvertisedSecurity, ApChange, ClientLink, Json, SignalSample } from './api';

const tableFields: Record<string, string[]> = {
  aps: ['ssid', 'bssid', 'channel', 'security', 'rssiMedian'],
  hidden: ['observedName', 'nameStatus', 'revealFrame', 'revealedAt'],
  edges: ['clientId', 'bssid', 'source', 'evidenceCount', 'lastSeen'],
  roams: ['time', 'fromBssid', 'toBssid', 'method'],
  inventory: ['id', 'classLabel', 'classConfidence', 'lastSeen'],
  probes: ['name', 'exposure', 'deviceCount', 'lastSeen'],
  channels: ['channel', 'freqMhz', 'occupancyMean', 'sampleCount', 'anomaly'],
  saved: ['startedAt', 'operationsEnabled'],
};

const evidenceFields: Record<string, string[]> = {
  aps: ['bssid', 'channel', 'band', 'security', 'rssiMedian', 'lastSeen', 'stationCount', 'channelUtilization'],
  hidden: ['nameStatus', 'revealFrame', 'revealedAt', 'beaconObservedAt', 'bssid', 'channel', 'lastSeen'],
  edges: ['bssid', 'source', 'evidenceCount', 'associationSeen', 'firstSeen', 'lastSeen', 'uplink', 'downlink'],
  roams: ['clientId', 'fromBssid', 'toBssid', 'method'],
  inventory: ['classLabel', 'classConfidence', 'osHint', 'role', 'vendor', 'rssiMedian', 'firstSeen', 'lastSeen', 'packetCount'],
  probes: ['exposure', 'firstSeen', 'lastSeen', 'deviceCount'],
  channels: ['freqMhz', 'occupancyMean', 'sampleCount', 'anomaly', 'score'],
  saved: ['operationsEnabled'],
};

const labels: Record<string, string> = {
  anomaly: 'Anomaly',
  associationSeen: 'Association observed',
  band: 'Band',
  beaconObservedAt: 'Hidden beacon observed',
  bssid: 'AP ID',
  channelUtilization: 'AP-reported utilization',
  classConfidence: 'Classification confidence',
  classLabel: 'Inferred classification',
  clientId: 'Client',
  deviceCount: 'Observed devices',
  evidenceCount: 'Evidence count',
  firstSeen: 'First observed',
  freqMhz: 'Frequency',
  fromBssid: 'From AP',
  id: 'Device ID',
  lastSeen: 'Last observed',
  method: 'Evidence method',
  name: 'Network name',
  nameStatus: 'Name status',
  observedName: 'Network name',
  occupancyMean: 'Estimated occupancy',
  revealedAt: 'Name observed at',
  revealFrame: 'Revealing frame',
  rssiMedian: 'Median signal',
  sampleCount: 'Scanner samples',
  security: 'Advertised security',
  source: 'Evidence source',
  ssid: 'Network name',
  ssidRevealedVia: 'Revealed by',
  startedAt: 'Session started',
  stationCount: 'AP-reported stations',
  time: 'Observed at',
  toBssid: 'To AP',
};

const identityFields: Record<string, string[]> = {
  aps: ['bssid'],
  hidden: ['bssid'],
  edges: ['clientId', 'bssid'],
  roams: ['clientId', 'fromBssid', 'toBssid', 'method', 'time'],
  probes: ['id'],
  channels: ['channel', 'freqMhz'],
  saved: ['startedAt'],
};

const compactDate = new Intl.DateTimeFormat(undefined, {
  month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', second: '2-digit',
});
const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 });

export function short(value: unknown): string {
  if (value == null || value === '') return '—';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

export function title(key: string): string {
  return key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/_/g, ' ').replace(/^./, first => first.toUpperCase());
}

export function date(value: unknown, compact = false): string {
  const timestamp = Number(value);
  if (!Number.isFinite(timestamp) || timestamp <= 0) return short(value);
  const time = new Date(timestamp);
  return compact ? compactDate.format(time) : time.toLocaleString();
}

export function isTimestamp(key: string): boolean {
  return /^(time|timestamp)$|Seen$|At(?:Ms)?$/.test(key);
}

export function isIdentifier(key: string): boolean {
  return /^(id|token|bssid|mac|address)$/.test(key) || /(?:Bssid|Mac|Address|Id|Token)$/.test(key);
}

export function observationLabel(kind: string, key: string): string {
  if (kind === 'probes' && key === 'id') return 'Report ID';
  return labels[key] ?? title(key);
}

export function observationKey(kind: string, row: Json): string {
  if (kind === 'inventory') return JSON.stringify([row.id ?? row.mac]);
  return JSON.stringify(identityFields[kind]?.map(key => row[key]) ?? row);
}

export function observationColumns(kind: string, rows: Json[]): string[] {
  const [subject, ...columns] = tableFields[kind];
  if (['hidden', 'inventory', 'roams', 'channels'].includes(kind)) return [subject, ...columns];
  return [subject, ...columns.filter(key => rows.some(row => row[key] != null))];
}

export function primaryEvidence(kind: string, row: Json): string[] {
  if (kind === 'inventory') {
    return evidenceFields[kind].filter(key => key === 'classLabel' || key === 'classConfidence' || row[key] != null);
  }
  return evidenceFields[kind].filter(key => kind === 'channels' || row[key] != null);
}

export function deviceClassification(row: Json): string | null {
  const label = row.classLabel ?? row.guessedType;
  return typeof label === 'string' && label.trim() && !/^(unknown|unclassified)$/i.test(label.trim()) ? label : null;
}

const frameNames: Record<string, string> = {
  ASSOC_REQ: 'Association request',
  REASSOC_REQ: 'Reassociation request',
  PROBE_RESP: 'Probe response',
  ASSOCIATION_REQUEST: 'Association request',
  REASSOCIATION_REQUEST: 'Reassociation request',
  PROBE_REQUEST: 'Probe request',
  PROBE_RESPONSE: 'Probe response',
  BEACON: 'Beacon',
};

export function frameName(source: string): string {
  return frameNames[source] ?? source;
}

export function hiddenNameRow(row: Json): Json {
  const evidence = row.hiddenSsidEvidence;
  const observedName = row.ssid || evidence?.name || null;
  const source = evidence?.source ?? row.ssidRevealedVia;
  const revealFrame = source && source !== 'NONE' ? frameName(source) : null;
  return {
    ...row,
    observedName,
    nameStatus: observedName || revealFrame ? 'Name observed' : 'Still hidden',
    revealFrame,
    revealedAt: revealFrame ? evidence?.observedAt ?? null : null,
    beaconObservedAt: evidence?.beaconObservedAt ?? null,
  };
}

export function groupApChanges<T extends ApChange>(changes: readonly T[]) {
  const groups = new Map<string, T[]>();
  const newestFirst = [...changes].sort((a, b) => b.time - a.time);
  for (const change of newestFirst) {
    const clientChanges = groups.get(change.clientId);
    if (clientChanges) clientChanges.push(change);
    else groups.set(change.clientId, [change]);
  }
  return Array.from(groups, ([clientId, rows]) => ({ clientId, rows: rows.reverse() }));
}

export function chronologicalSignal(samples: readonly SignalSample[]): SignalSample[] {
  return samples.filter(sample => Number.isFinite(sample.timestamp) && sample.timestamp > 0
    && Number.isFinite(sample.rssi)).sort((a, b) => a.timestamp - b.timestamp);
}

export function channelRows(report: Json): Json[] {
  return (report.channels ?? []).map((row: Json) => {
    // The scanner counts array records valid observations per channel, starting at channel 1.
    const count = report.counts?.[row.channel - 1];
    return { ...row, sampleCount: Number.isSafeInteger(count) && count >= 0 ? count : null };
  });
}

export function occupancyEstimate(row: Json): number | null {
  const mean = row.occupancyMean;
  return row.sampleCount > 0 && typeof mean === 'number' && mean >= 0 && mean <= 1 ? mean : null;
}

export function occupancyLabel(row: Json): string {
  const estimate = occupancyEstimate(row);
  if (row.sampleCount == null) return 'Sample count unavailable';
  if (row.sampleCount === 0) return 'No samples';
  if (estimate === null) return 'Estimate unavailable';
  return estimate > 0 && estimate < 0.001 ? '<0.1%' : percent.format(estimate);
}

export function channelBand(freqMhz: number): string {
  if (freqMhz >= 2400 && freqMhz < 2500) return '2.4 GHz';
  if (freqMhz >= 4900 && freqMhz < 5925) return '5 GHz';
  if (freqMhz >= 5925 && freqMhz <= 7125) return '6 GHz';
  return 'Band unavailable';
}

export function observedClientsByAp(links: readonly Pick<ClientLink, 'bssid' | 'clientId'>[]) {
  const clients = new Map<string, Set<string>>();
  for (const { bssid, clientId } of links) {
    const knownClients = clients.get(bssid);
    if (knownClients) knownClients.add(clientId);
    else clients.set(bssid, new Set([clientId]));
  }
  return clients;
}

function securitySummary(profiles: AdvertisedSecurity[] | undefined, fallback: unknown): string {
  if (!profiles?.length) return short(fallback);
  return profiles.map(({ protocol, authentication }) =>
    authentication?.length ? `${protocol} · ${authentication.join(', ')}` : protocol
  ).join(' / ');
}

export function observationValue(key: string, row: Json, compact = false): string {
  const value = row[key];
  if (isTimestamp(key)) return date(value, compact);
  switch (key) {
    case 'id': return short(row.id ?? row.mac);
    case 'name': return typeof value === 'string' && value.length > 0 ? value : 'Privacy-masked';
    case 'observedName': return value || (row.nameStatus === 'Name observed' ? 'Name unavailable' : 'Hidden network');
    case 'ssid': return value || (row.ssidHidden ? 'Hidden network' : 'Name unavailable');
    case 'security': return securitySummary(row.advertisedSecurity, value);
    case 'channelUtilization':
      // The BSS Load octet encodes a fraction with 255 representing 100%.
      return Number.isInteger(value) && value >= 0 && value <= 255 ? percent.format(value / 255) : '—';
    case 'source':
      if (value === 'ASSOC') return 'Association';
      if (value === 'REASSOC') return 'Reassociation';
      if (value === 'DATA') return 'Data frames';
      return short(value);
    case 'channel': return value > 0 ? `CH ${value}` : '—';
    case 'rssiMedian': return typeof value === 'number' ? `${Math.round(value)} dBm` : short(value);
    case 'freqMhz': return value > 0 ? `${value} MHz` : '—';
    case 'exposure': return typeof value === 'string' ? title(value.toLowerCase()) : short(value);
    case 'classLabel': return deviceClassification(row) ?? 'Unclassified';
    case 'role': return value === 'AP' ? 'Access point' : typeof value === 'string' ? title(value.toLowerCase()) : short(value);
    case 'classConfidence':
      return deviceClassification(row) && typeof value === 'number' && value >= 0 && value <= 1 ? percent.format(value) : '—';
    case 'method':
      if (value === 'REASSOC') return 'Reassociation';
      if (value === 'FT') return 'Fast transition';
      if (value === 'DATA_SWITCH') return 'Data observed on another AP';
      return short(value);
    case 'occupancyMean': return occupancyLabel(row);
    case 'anomaly': return value ? value.reason || 'Flagged' : '—';
    default: return typeof value === 'boolean' ? (value ? 'Yes' : 'No') : short(value);
  }
}
