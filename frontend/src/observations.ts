import type { AccessPointObservation, AdvertisedSecurity, ApChange, AssociatedAp, ClientLink, InspectorAccessPoint, Json, SecurityFinding, SignalSample, SpotterDevice } from './api';

const hiddenContextFields = ['revealConfidenceLabel', 'concealment', 'hiddenRoleLabel', 'coHostedWith'];

const tableFields: Record<string, string[]> = {
  aps: ['ssid', 'vendor', 'channel', 'wifiGeneration', 'security', 'findingsSummary', 'rssiMedian'],
  hidden: ['observedName', 'nameStatus', 'revealFrame', 'revealedAt', ...hiddenContextFields],
  edges: ['clientId', 'bssid', 'state', 'source', 'evidenceCount', 'controlFrames', 'lastSeen'],
  roams: ['time', 'fromBssid', 'toBssid', 'transitionType', 'rssiChange', 'method'],
  inventory: ['id', 'classLabel', 'classConfidence', 'associatedAp', 'lastSeen', 'inferredCorrelation'],
  probes: ['name', 'exposure', 'source', 'deviceCount', 'lastSeen'],
  channels: ['channel', 'freqMhz', 'occupancyMean', 'sampleCount', 'estimatedAirtime', 'qbssUtilization', 'apCount', 'anomaly'],
  saved: ['startedAt', 'operationsEnabled'],
};

const evidenceFields: Record<string, string[]> = {
  aps: ['bssid', 'channel', 'band', 'security', 'rssiMedian', 'lastSeen', 'stationCount', 'channelUtilization'],
  hidden: ['nameStatus', 'revealFrame', 'revealedAt', ...hiddenContextFields, 'beaconObservedAt', 'bssid'],
  edges: ['bssid', 'state', 'source', 'evidenceCount', 'controlFrames', 'associationSeen', 'firstSeen', 'lastSeen',
    'uplink', 'downlink', 'clientMldId'],
  roams: ['clientId', 'fromBssid', 'toBssid', 'transitionType', 'rssiChange', 'method', 'previousDwellMs', 'pingPong', 'btmSteered'],
  inventory: ['classLabel', 'classConfidence', 'role', 'vendor', 'rssiMedian', 'firstSeen', 'lastSeen', 'packetCount'],
  probes: ['exposure', 'source', 'deviceCount', 'firstSeen', 'lastSeen'],
  channels: ['freqMhz', 'anomaly', 'occupancyMean', 'estimatedAirtime', 'qbssUtilization', 'dwellMs', 'sampleCount',
    'medianNoiseDbm', 'apCount', 'activeClientCount', 'nonWifiInterferenceSuspected', 'deviceHint', 'fittedPeriodMs',
    'coupledFrequenciesMhz', 'score', 'noIr', 'radarDetection'],
  saved: ['operationsEnabled'],
};

const labels: Record<string, string> = {
  activeClientCount: 'Active observed clients',
  anomaly: 'Anomaly',
  apCount: 'Observed APs',
  associationSeen: 'Association observed',
  associatedAp: 'Connection',
  band: 'Band',
  beaconObservedAt: 'Hidden beacon observed',
  bssid: 'AP ID',
  btmSteered: '802.11v BTM',
  channelUtilization: 'AP-reported utilization',
  classConfidence: 'Classification confidence',
  classLabel: 'Inferred classification',
  clientId: 'Client',
  clientMldId: 'Client MLD ID',
  coHostedWith: 'Co-hosted visible SSIDs',
  concealment: 'Concealment',
  controlFrames: 'Control frames',
  coupledFrequenciesMhz: 'Coupled hopping peers',
  deviceHint: 'Period pattern',
  deviceCount: 'Observed devices',
  dwellMs: 'Receiver dwell',
  estimatedAirtime: 'Estimated airtime',
  evidenceCount: 'Evidence count',
  firstSeen: 'First observed',
  findingsSummary: 'Findings',
  fittedPeriodMs: 'Fitted period',
  freqMhz: 'Frequency',
  fromBssid: 'From AP',
  hiddenRoleLabel: 'Hidden BSS role',
  id: 'Device ID',
  inferredCorrelation: 'Inferred probe correlation',
  lastSeen: 'Last observed',
  medianNoiseDbm: 'Median noise floor',
  method: 'Evidence method',
  name: 'Network name',
  nameStatus: 'Name status',
  noIr: 'No initiation of radiation',
  nonWifiInterferenceSuspected: 'Non-Wi-Fi interference suspected',
  observedName: 'Network name',
  occupancyMean: 'Estimated occupancy',
  pingPong: 'Ping-pong',
  previousDwellMs: 'Dwell',
  qbssUtilization: 'AP-reported QBSS load',
  radarDetection: 'Radar detection required',
  revealedAt: 'Name observed at',
  revealConfidenceLabel: 'Reveal confidence',
  revealFrame: 'Reveal evidence',
  rssiMedian: 'Median signal',
  rssiChange: 'RSSI change',
  sampleCount: 'Scanner samples',
  security: 'Advertised security',
  source: 'Evidence source',
  ssid: 'Network name',
  ssidRevealedVia: 'Revealed by',
  startedAt: 'Session started',
  stationCount: 'AP-reported stations',
  state: 'Link state',
  time: 'Observed at',
  toBssid: 'To AP',
  transitionType: 'Transition type',
  wifiGeneration: 'Wi-Fi generation',
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
  if (kind === 'probes' && key === 'source') return 'Probe source';
  return labels[key] ?? title(key);
}

export function observationKey(kind: string, row: Json): string {
  if (kind === 'inventory') return JSON.stringify([row.id ?? row.mac]);
  return JSON.stringify(identityFields[kind]?.map(key => row[key]) ?? row);
}

export function observationColumns(kind: string, rows: Json[]): string[] {
  const [subject, ...columns] = tableFields[kind];
  if (kind === 'inventory') {
    return [subject, ...columns.filter(key => !['associatedAp', 'inferredCorrelation'].includes(key)
      || rows.some(row => row[key] != null))];
  }
  if (kind === 'hidden') {
    return [subject, ...columns.filter(key => !hiddenContextFields.includes(key) || rows.some(row => row[key] != null))];
  }
  if (['aps', 'roams', 'channels', 'probes'].includes(kind)) return [subject, ...columns];
  return [subject, ...columns.filter(key => rows.some(row => row[key] != null))];
}

export function primaryEvidence(kind: string, row: Json): string[] {
  if (kind === 'inventory') {
    return evidenceFields[kind].filter(key => key === 'classLabel' || key === 'classConfidence' || row[key] != null);
  }
  if (kind === 'roams') {
    return evidenceFields[kind].filter(key => key === 'rssiChange'
      ? row.fromRssiDbm != null || row.toRssiDbm != null : row[key] != null);
  }
  return evidenceFields[kind].filter(key => row[key] != null || kind === 'channels' && key !== 'noIr' && key !== 'radarDetection');
}

export function deviceClassification(row: Json): string | null {
  const label = row.classLabel ?? row.guessedType;
  return typeof label === 'string' && label.trim() && !/^(unknown|unclassified)$/i.test(label.trim()) ? label : null;
}

const classificationBasisLabels: Record<string, string> = {
  SAVED_SAMPLE: 'Saved sample',
  SIGNATURE_TABLE: 'Signature table',
  WPS_DEVICE_TYPE: 'WPS device type',
  VENDOR_IE_HEURISTIC: 'Vendor IE signature',
  RADIO_CAPABILITY_HEURISTIC: 'Radio capability profile',
  OUI_VENDOR: 'IEEE OUI',
  RADIOTAP_DATA_HEURISTIC: 'Radiotap data profile',
};

export function classificationBasisLabel(basis?: string | null): string | null {
  return basis ? classificationBasisLabels[basis] ?? title(basis.toLowerCase()) : null;
}

export function associatedApLabel(ap: AssociatedAp): string {
  return `Connected to ${ap.ssid || ap.apId}${ap.channel > 0 ? ` · CH ${ap.channel}` : ''}`;
}

const frameNames: Record<string, string> = {
  ASSOC_REQ: 'Association request',
  REASSOC_REQ: 'Reassociation request',
  PROBE_REQ: 'Directed probe request',
  PROBE_RESP: 'Probe response',
  OWE_TRANSITION: 'OWE transition element',
  RNR_SHORT_SSID: '6 GHz RNR Short-SSID match',
  ASSOCIATION_REQUEST: 'Association request',
  REASSOCIATION_REQUEST: 'Reassociation request',
  PROBE_REQUEST: 'Probe request',
  PROBE_RESPONSE: 'Probe response',
  BEACON: 'Beacon',
};

export function frameName(source: string): string {
  return frameNames[source] ?? source;
}

const revealConfidenceLabels: Record<string, string> = {
  AP_AUTHORITATIVE: 'AP-authoritative',
  CONFIRMED_ASSOC: 'Confirmed association',
  TENTATIVE_CLIENT: 'Tentative client frame',
};

const hiddenRoleLabels: Record<string, string> = {
  MESH_POINT: 'Mesh',
  MULTI_AP_BACKHAUL: 'Multi-AP backhaul',
  OWE_TRANSITION_BSS: 'OWE transition BSS',
  HIDDEN_INFRASTRUCTURE: 'Hidden infrastructure',
};

export function hiddenNameRow(row: Json): Json {
  const evidence = row.hiddenSsidEvidence;
  const observedName = row.ssid || evidence?.name || null;
  const source = evidence?.source ?? row.ssidRevealedVia;
  const revealFrame = source && source !== 'NONE' ? frameName(source) : null;
  const concealment = row.concealmentMode === 'ZERO_LENGTH' ? 'Zero-length SSID'
    : row.concealmentMode === 'NULL_PADDED' && row.maskedSsidLength != null ? `Null-padded (${row.maskedSsidLength} bytes)` : null;
  return {
    ...row,
    observedName,
    nameStatus: observedName || revealFrame ? 'Name observed' : 'Still hidden',
    revealFrame,
    revealedAt: revealFrame ? evidence?.observedAt ?? null : null,
    beaconObservedAt: evidence?.beaconObservedAt ?? null,
    concealment,
    revealConfidenceLabel: revealConfidenceLabels[row.revealConfidence] ?? null,
    coHostedWith: row.coHostedVisibleSsids?.join(', ') || null,
    hiddenRoleLabel: row.hiddenRole === 'MESH_POINT' && row.meshId ? `Mesh · ${row.meshId}`
      : hiddenRoleLabels[row.hiddenRole] ?? null,
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

export function roamApLabel(ap?: AccessPointObservation, channel?: number | null, band?: string | null): string {
  const ch = channel ?? ap?.channel ?? 0;
  const observedBand = band ?? ap?.band;
  const radio = ch > 0 ? `CH ${ch}${observedBand ? ` (${observedBand})` : ''}` : observedBand;
  return [ap?.ssid, radio].filter(Boolean).join(' · ');
}

export function roamDwellLabel(ms: number): string {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toLocaleString(undefined, { maximumFractionDigits: 1 })} s`;
}

const transitionLabels: Record<NonNullable<ApChange['transitionType']>, string> = {
  INTER_AP_ROAM: 'Inter-AP roam',
  BAND_STEER: 'Band steer',
  MLO_LINK_SWITCH: 'MLO link switch',
  ESS_SWITCH: 'Network switch',
};

export function chronologicalSignal(samples: readonly SignalSample[]): SignalSample[] {
  return samples.filter(sample => Number.isFinite(sample.timestamp) && sample.timestamp > 0
    && Number.isFinite(sample.rssi)).sort((a, b) => a.timestamp - b.timestamp);
}

export function channelRows(report: Json): Json[] {
  return (report.channels ?? []).map((row: Json) => {
    const count = row.sampleCount ?? ((row.freqMhz == null || row.freqMhz === 2407 + row.channel * 5) && row.channel <= 13
      ? report.counts?.[row.channel - 1] : null);
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

const anomalyLabels: Record<string, string> = {
  DEAUTH_FLOOD: 'Deauth flood',
  BEACON_FLOOD: 'Beacon flood',
  DATA_BURST: 'Data burst',
  NEW_ACTIVITY: 'New activity',
  UNUSUAL_BURST: 'Unusual burst',
  PERIOD_BROKEN: 'Period disrupted',
};

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

export function isActiveLink({ state }: Pick<ClientLink, 'state'>): boolean {
  return state !== 'ROAMED_AWAY' && state !== 'DISCONNECTED';
}

export function spotterClientLabel(device?: SpotterDevice): string | null {
  if (!device) return null;
  const vendor = device.locallyAdministered || device.randomizedScanSeen ? 'Randomized' : device.vendor;
  return [deviceClassification(device) ?? 'Client', vendor && !/^unknown$/i.test(vendor) ? vendor : null]
    .filter(Boolean).join(' · ');
}

function securitySummary(profiles: AdvertisedSecurity[] | undefined, fallback: unknown): string {
  if (!profiles?.length) return short(fallback);
  return profiles.map(({ protocol, authentication }) =>
    authentication?.length ? `${protocol} · ${authentication.join(', ')}` : protocol
  ).join(' / ');
}

const probeSources: Record<string, string> = {
  PLAINTEXT_SSID: 'Plaintext SSID',
  SSID_LIST: 'SSID List',
  SHORT_SSID_MATCH: 'Short-SSID match',
  SHORT_SSID_HASH: 'Short-SSID hash',
};

function probeSourceLabel(value: unknown): string {
  return typeof value === 'string' ? probeSources[value] ?? value : short(value);
}

export function probeExposureLabel(value: unknown): string {
  if (value === 'SHORT_SSID_HASH') return 'Short-SSID hash';
  return typeof value === 'string' ? title(value.toLowerCase()) : short(value);
}

export function apHardwareSubtitle({ vendor, apHostname, wpsInfo }: Pick<InspectorAccessPoint, 'vendor' | 'apHostname' | 'wpsInfo'>) {
  const primary = vendor ?? apHostname ?? wpsInfo?.modelName;
  return [...new Set([apHostname, wpsInfo?.modelName].filter(label => label && label !== primary))].join(' · ');
}

export function highestSeverity(findings: readonly SecurityFinding[] = []) {
  return (['HIGH', 'MEDIUM', 'LOW'] as const).find(severity => findings.some(finding => finding.severity === severity));
}

export function observationValue(key: string, row: Json, compact = false): string {
  const value = row[key];
  if (isTimestamp(key)) return date(value, compact);
  switch (key) {
    case 'id': return short(row.id ?? row.mac);
    case 'associatedAp': return value ? associatedApLabel(value) : '—';
    case 'classificationBasis': return classificationBasisLabel(value) ?? '—';
    case 'inferredCorrelation': return value ? `${value.memberCount} addresses · ${percent.format(value.confidence)}` : '—';
    case 'name': return short(value);
    case 'observedName': return value || (row.nameStatus === 'Name observed' ? 'Name unavailable' : 'Hidden network');
    case 'ssid': return value || (row.ssidHidden ? 'Hidden network' : 'Name unavailable');
    case 'vendor': return short(value ?? row.apHostname ?? row.wpsInfo?.modelName);
    case 'wifiGeneration': {
      const radio = row.apRadio;
      if (!radio?.wifiGeneration || radio.wifiGeneration === 'Unknown') return '—';
      return radio.spatialStreams > 0 ? `${radio.wifiGeneration} · ${radio.spatialStreams}×${radio.spatialStreams}`
        : radio.wifiGeneration;
    }
    case 'findingsSummary': {
      const findings: SecurityFinding[] | undefined = row.securityFindings;
      if (!findings) return '—';
      if (findings.length === 0) return 'None';
      const severity = highestSeverity(findings);
      return severity ? `${findings.length} · ${severity}` : String(findings.length);
    }
    case 'security': return securitySummary(row.advertisedSecurity, value);
    case 'channelUtilization':
      // The BSS Load octet encodes a fraction with 255 representing 100%.
      return Number.isInteger(value) && value >= 0 && value <= 255 ? percent.format(value / 255) : '—';
    case 'source':
      if (Array.isArray(row.sources) && row.sources.length) return row.sources.map(probeSourceLabel).join(', ');
      if (value === 'ASSOC') return 'Association';
      if (value === 'REASSOC') return 'Reassociation';
      if (value === 'DATA') return 'Data frames';
      if (value === 'CONTROL') return 'Control frames';
      return probeSourceLabel(value);
    case 'state':
      if (value === 'ROAMED_AWAY') return 'Roamed to another AP';
      if (value === 'DISCONNECTED') return 'Disconnected';
      return value == null || value === 'ACTIVE' ? 'Active' : short(value);
    case 'channel': {
      const width = row.apRadio?.operatingWidthMhz;
      return [value > 0 ? `CH ${value}` : null, width > 0 ? `${width} MHz` : null].filter(Boolean).join(' · ') || '—';
    }
    case 'rssiMedian': return typeof value === 'number' ? `${Math.round(value)} dBm` : short(value);
    case 'rssiChange': {
      const { fromRssiDbm: from, toRssiDbm: to } = row;
      if (from == null && to == null) return '—';
      if (from == null || to == null) return `${short(from)} → ${short(to)} dBm`;
      const delta = to - from;
      return `${from} → ${to} dBm (${delta > 0 ? '+' : ''}${delta} dB)`;
    }
    case 'transitionType': return transitionLabels[value as keyof typeof transitionLabels] ?? short(value);
    case 'previousDwellMs': return typeof value === 'number' ? roamDwellLabel(value) : short(value);
    case 'freqMhz': return value > 0 ? `${value} MHz` : '—';
    case 'exposure': return probeExposureLabel(value);
    case 'classLabel': return deviceClassification(row) ?? 'Unclassified';
    case 'role': return value === 'AP' ? 'Access point' : typeof value === 'string' ? title(value.toLowerCase()) : short(value);
    case 'classConfidence':
      return deviceClassification(row) && typeof value === 'number' && value >= 0 && value <= 1 ? percent.format(value) : '—';
    case 'method':
      if (value === 'REASSOC') return 'Reassociation';
      if (value === 'FT') return 'Fast transition';
      if (value === 'FT_OVER_DS') return 'Fast transition over DS';
      if (value === 'FT_REASSOC') return 'Fast transition reassociation';
      if (value === 'BTM_STEER') return 'BSS transition steering';
      if (value === 'DATA_SWITCH') return 'Data observed on another AP';
      if (value === 'INFERRED_MAC_ROTATION') return 'Inferred MAC rotation (heuristic)';
      return short(value);
    case 'occupancyMean': return occupancyLabel(row);
    case 'estimatedAirtime':
    case 'qbssUtilization':
      if (typeof value !== 'number' || value < 0 || value > 1 || !Number.isFinite(value)) return '—';
      return value > 0 && value < 0.001 ? '<0.1%' : percent.format(value);
    case 'medianNoiseDbm': return typeof value === 'number' ? `${value} dBm` : '—';
    case 'dwellMs': return typeof value === 'number' ? `${value} ms` : '—';
    case 'fittedPeriodMs': {
      if (!(value > 0)) return '—';
      const confidence = row.fitConfidence;
      return `${value} ms` + (typeof confidence === 'number' && confidence >= 0 && confidence <= 1
        ? ` · ${percent.format(confidence)} confidence` : '');
    }
    case 'coupledFrequenciesMhz':
      if (value?.length) return value.map((frequency: number) => `${frequency} MHz`).join(', ');
      return row.coupledWith?.length ? row.coupledWith.map((channel: number) => `CH ${channel}`).join(', ') : '—';
    case 'anomaly': {
      if (!value) return '—';
      const reason = value.floodType || value.reason;
      const label = anomalyLabels[reason] ?? reason ?? 'Flagged';
      return value.activeNow === false ? `${label} · Recent` : label;
    }
    default: return typeof value === 'boolean' ? (value ? 'Yes' : 'No') : short(value);
  }
}

/** Search observed values and their display labels, without JSON field names or absent flags. */
export function observationMatches(row: Json, columns: readonly string[], search: string): boolean {
  const query = search.trim().toLowerCase();
  if (!query) return true;
  function matches(value: unknown): boolean {
    if (typeof value === 'string' || typeof value === 'number') return String(value).toLowerCase().includes(query);
    if (Array.isArray(value)) return value.some(matches);
    return value !== null && typeof value === 'object' && Object.values(value).some(matches);
  }
  return matches(row) || columns.some(key => observationValue(key, row, true).toLowerCase().includes(query))
    || (columns.includes('classLabel') && matches(classificationBasisLabel(row.classificationBasis)));
}
