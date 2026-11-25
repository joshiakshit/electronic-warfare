import { afterEach, expect, it, vi } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import App, { records, ReportErrorNotice, SpotterReport, Summary } from './ui';
import { Overview } from './Overview';
import { AccessPointEvidence, ChannelChart, ObservationReport } from './ObservationReport';
import { ProbeAnalytics } from './ProbeAnalytics';
import { hiddenNameRow, observationKey } from './observations';
import { OperationHistoryPanel, ResultView } from './Ops';
import { ProfilerEvidence } from './ProfilerEvidence';
import { ManagementEvidence } from './FrameEvidence';
import { Sniper } from './Sniper';
import { SpotterTopology } from './SpotterTopology';
import type { InspectorAccessPoint, SniperMove, SniperRun, SpotterObservations, TrackerReport } from './api';

afterEach(() => vi.unstubAllGlobals());

const lookoutReport = {
  channels: [
    { channel: 5, freqMhz: 2432, occupancyMean: 0, sampleCount: 0 },
    { channel: 5, freqMhz: 5975, occupancyMean: 0.7, sampleCount: 12,
      deviceHint: '802.11 AP (beacon cycle)', fittedPeriodMs: 120, fitConfidence: 0.92,
      estimatedAirtime: 0.16, qbssUtilization: 0.72, medianNoiseDbm: -74, dwellMs: 850,
      apCount: 2, activeClientCount: 3, nonWifiInterferenceSuspected: true, coupledFrequenciesMhz: [6055],
      anomaly: { floodType: 'DEAUTH_FLOOD', reason: 'NEW_ACTIVITY', activeNow: false } },
    { channel: 21, freqMhz: 6055, occupancyMean: 0.2, sampleCount: 6, coupledFrequenciesMhz: [5975],
      anomaly: { reason: 'UNUSUAL_BURST', activeNow: true } },
  ],
  activeChannel: 5, activeFrequencyMhz: 5975, coupledPeriod: 6, coupledMembers: [1, 2], tickMs: 20,
  radio: { meanRetuneMs: 13.7 },
};

it('renders Lookout receiver, coupling and retune summary with frequency-specific chart markers', () => {
  const rows = records(lookoutReport, 'channels');
  const summary = renderToStaticMarkup(<Summary kind="channels" data={lookoutReport} rows={rows} />);
  for (const value of ['Sampled channels</span><b>2', 'Active receiver</span><b>CH 5 · 5975 MHz',
    'Coupled hopping groups</span><b>2 channels · 120 ms', 'Anomalies</span><b>2', 'Mean retune</span><b>14 ms']) {
    expect(summary).toContain(value);
  }
  const chart = renderToStaticMarkup(<ChannelChart channels={rows} selectedKey={null} onSelect={vi.fn()}
    activeFrequencyMhz={lookoutReport.activeFrequencyMhz} />);
  expect(chart).toContain('2.4 GHz, channel 5, No samples');
  expect(chart).toContain('data-tuned="true" data-coupled="true" data-anomaly="recent"');
  expect(chart).toContain('6 GHz, channel 5, 70% · Active receiver · Coupled hopping · Deauth flood · Recent');
  expect(chart).toContain('data-coupled="true" data-anomaly="active"');
  expect(chart).toContain('6 GHz, channel 21, 20% · Coupled hopping · Unusual burst');
  expect(chart.match(/data-tuned="true"/g)).toHaveLength(1);
});

it('renders Lookout airtime, AP load, period fit and anomaly details in the table and evidence drawer', () => {
  const rows = records(lookoutReport, 'channels');
  const html = renderToStaticMarkup(<ObservationReport kind="channels" rows={rows} running stale={false}
    activeFrequencyMhz={lookoutReport.activeFrequencyMhz} initialSelectedKey={observationKey('channels', rows[1])} />);
  for (const value of ['Estimated airtime', 'AP-reported QBSS load', 'Observed APs', 'Deauth flood · Recent',
    '<dt>Estimated airtime</dt><dd>16%</dd>', '<dt>AP-reported QBSS load</dt><dd>72%</dd>',
    '<dt>Period pattern</dt><dd>802.11 AP (beacon cycle)</dd>', '<dt>Fitted period</dt><dd>120 ms · 92% confidence</dd>',
    '<dt>Coupled hopping peers</dt><dd>6055 MHz</dd>', '<dt>Median noise floor</dt><dd>-74 dBm</dd>',
    '<dt>Receiver dwell</dt><dd>850 ms</dd>', '<dt>Non-Wi-Fi interference suspected</dt><dd>Yes</dd>',
    '<dt>Active observed clients</dt><dd>3</dd>']) expect(html).toContain(value);
});

it('provides the Lookout scan action only for a running Watch session', () => {
  const actions = { run: vi.fn(), pending: false, error: '', message: '' };
  const notice = (running: boolean, mode: string, scannerUnavailable = true, pending = false) => renderToStaticMarkup(
    <ReportErrorNotice error="no scanner attached" scannerUnavailable={scannerUnavailable}
      capture={{ running, mode }} captureInterface="lab0mon" actions={{ ...actions, pending }} />,
  );
  expect(notice(true, 'watch')).toMatch(/<button[^>]*>Enable adaptive scan<\/button>/);
  expect(notice(true, 'watch', true, true)).toMatch(/<button[^>]*disabled=""[^>]*>Enable adaptive scan<\/button>/);
  expect(notice(false, 'watch')).not.toContain('Enable adaptive scan');
  expect(notice(true, 'replay')).not.toContain('Enable adaptive scan');
  expect(notice(true, 'watch', false)).not.toContain('Enable adaptive scan');
});

it('renders the active sweep frequency during discovery and reacquisition', () => {
  for (const state of ['SEARCHING', 'LOST_SEARCHING'] as const) {
    const html = renderToStaticMarkup(<Sniper data={{ available: true, run: {
      id: 'run-id', state, startedAt: 1700000000000, activeSweepChannel: 5, activeSweepFrequencyMhz: 5975,
    } }} onChanged={vi.fn()} />);
    expect(html).toContain('Active sweep channel');
    expect(html).toContain('CH 5 · 5975 MHz');
    expect(html).not.toContain('Decoy frames ignored');
  }
});

it('renders Sniper warnings, affiliated links and readable channel move history', () => {
  const startedAt = 1700000000000;
  const triggers: SniperMove['trigger'][] = ['CSA', 'SILENCE_SWEEP', 'HEURISTIC_BSSID_ROTATION', 'AFFILIATED_LINK_SWITCH'];
  const run: SniperRun = {
    id: 'run-id', state: 'LOCKED', startedAt, lockedApId: 'ap-current', lockedChannel: 1, lockedFrequencyMhz: 2412,
    pendingChannelSwitch: { channel: 5, frequencyMhz: 5975, scheduledAtMs: startedAt + 500, tunedAtMs: null },
    decoyFramesIgnored: 2, spoofWarnings: 1, bssidRotated: true, mldId: 'mld-token',
    affiliatedLinks: [
      { linkId: 0, apId: 'ap-other', channel: 36, frequencyMhz: 5180, band: '5 GHz', supported: true },
      { linkId: 1, apId: 'ap-unavailable', channel: 5, frequencyMhz: 5975, band: '6 GHz', supported: false },
    ],
    moves: triggers.map((trigger, index) => ({
      fromChannel: 1, fromFrequencyMhz: 2412, toChannel: 5, toFrequencyMhz: 5975,
      lostAtMs: startedAt, tunedAtMs: null, rediscoveredAtMs: startedAt + 142 + index, trigger,
    })),
  };
  const html = renderToStaticMarkup(<Sniper data={{ available: true, run }} onChanged={vi.fn()} />);
  for (const label of ['Pending 802.11h CSA', 'Decoy frames ignored', 'Suspected CSA spoofing',
    'mld-token', 'ap-other', '6 GHz', 'Affiliated links', 'Unavailable', 'Channel Move History',
    'Silence sweep', 'Heuristic hotspot BSSID rotation', 'Affiliated link switch', '142 ms', 'Rediscovered']) {
    expect(html).toContain(label);
  }
  expect(html.match(/>Follow link</g)).toHaveLength(1);
  expect(html).toMatch(/<button class="text-button" type="button">Follow link<\/button>/);
});

it('renders advertised management and security modes from frame evidence', () => {
  const html = renderToStaticMarkup(<ManagementEvidence modes={['OWE (Enhanced Open)']}
    features={{ neighborReport: true, bssTransition: true, fastTransition: true, extendedCapabilitiesHex: '000008' }} />);
  for (const value of ['OWE (Enhanced Open)', '802.11k', '802.11v', '802.11r', '000008']) expect(html).toContain(value);
});

const inspectorAp = {
  bssid: 'ap-token', ssid: 'Workshop', vendor: 'Workshop Networks', apHostname: 'wing-<west>', channel: 36,
  security: 'RSN', advertisedSecurity: [{ protocol: 'RSN', authentication: ['SAE'], managementFrameProtection: 'Required' }],
  apRadio: { wifiGeneration: 'Wi-Fi 6', operatingWidthMhz: 80, maxWidthMhz: 160, spatialStreams: 2, bssColor: 17 },
  wpsInfo: { state: 'Configured', apSetupLocked: false, modelName: 'Archer C20' },
  groupManagementCipher: 'BIP-CMAC-128', rsnxeFeatures: ['SAE H2E', 'SAE-PK', 'Protected TWT'],
  beaconProtection: true, ocvc: true, rssiMedian: -49, essId: 'ess-token', radioGroupId: 'radio-token',
  radioObservation: { timestamp: 1700000000000, frequencyMhz: 5180, metadata: { signalDbm: -49 } },
  securityFindings: [
    { code: 'ESS_SECURITY_DOWNGRADE', severity: 'HIGH', summary: 'Possible rogue AP.' },
    { code: 'WPS_UNLOCKED', severity: 'MEDIUM', summary: 'WPS setup is advertised as unlocked.' },
  ],
} satisfies InspectorAccessPoint;

it('renders Inspector findings, advertised configuration, and received frame metadata as separate evidence', () => {
  const html = renderToStaticMarkup(<AccessPointEvidence row={inspectorAp} priority={['bssid', 'channel']} />);
  for (const value of ['Security findings', 'Possible rogue AP.', 'HIGH', 'MEDIUM', 'Hardware &amp; radio configuration',
    'Workshop Networks', 'AP hostname', 'wing-&lt;west&gt;', 'WPS model', 'Archer C20', 'Configured · Unlocked',
    'Wi-Fi 6', '80 MHz / 160 MHz', 'BSS color', 'ess-token', 'radio-token', 'Group management cipher', 'BIP-CMAC-128',
    'RSNXE', 'SAE H2E, SAE-PK, Protected TWT', 'Beacon protection', 'OCVC', 'Captured beacon or probe response reception']) {
    expect(html).toContain(value);
  }
  expect(html.indexOf('Security findings')).toBeLessThan(html.indexOf('Hardware &amp; radio configuration'));
  expect(html).toContain('<dt>Beacon protection</dt><dd>Advertised</dd>');
  expect(html).toContain('<dt>OCVC</dt><dd>Advertised</dd>');
});

it('renders the Inspector table, selected evidence, and high severity counts that come from the report', () => {
  const older = { bssid: 'older-ap', ssid: 'Older AP', security: 'Open', channel: 1 };
  const rows = [inspectorAp, older];
  const html = renderToStaticMarkup(<ObservationReport kind="aps" rows={rows} running={false} stale={false}
    initialSelectedKey={observationKey('aps', inspectorAp)} />);
  for (const value of ['CH 36 · 80 MHz', 'Wi-Fi 6 · 2×2', '2 · HIGH', '-49 dBm', 'Older AP',
    '<small>wing-&lt;west&gt; · Archer C20</small>', 'Security findings', 'Configured · Unlocked', 'SAE H2E']) {
    expect(html).toContain(value);
  }
  const summary = renderToStaticMarkup(<Summary kind="aps" rows={rows} data={{
    accessPoints: rows, essGroups: { 'ess-token': ['ap-token'] }, findingsCount: 2, evilTwinSuspects: 1,
  }} />);
  for (const value of ['Access points</span><b>2', 'ESS networks</span><b>1', 'Wi-Fi 6 / 6E / 7 APs</span><b>1',
    'Security findings</span><b>2', '1 HIGH · 1 suspected evil twin']) expect(summary).toContain(value);
});

it('renders De-cloaker activity, exposure counts, chattiness and side-channel metrics', () => {
  const html = renderToStaticMarkup(<ProbeAnalytics data={{
    totalProbes: 29, directedProbes: 13, distinctDirectedSsids: 9, totalObservedAddresses: 8,
    locallyAdministeredPct: 75, distinctSignaturesAmongLocalAddresses: 3, correlatedClusterCount: 2,
    wpsUuidEPct: 20, distinctWpsUuids: 4, wpsMultiAddressCount: 1, passpointPct: 25,
    p2pNamedProbes: 5, p2pDeviceNames: { 'sender-opaque': 'Lab <Phone>' },
    timelineStart: 1700000000000, timeline: [...Array(19).fill(0), 4],
    ssidExposureCounts: { PERSONAL_NAME_PATTERN: 3, ROUTER_DEFAULT_PATTERN: 2, CORPORATE: 1, OTHER: 1, SHORT_SSID_HASH: 2 },
    directedPerAddress: { 0: 3, 1: 0, '2-3': 3, '4-9': 2, '10+': 0 },
  }} />);
  for (const value of ['Probe requests', 'Directed / Short-SSID', 'Distinct networks', 'Randomized MACs',
    'Signature collapse', '8 → 3', '2 correlated clusters', '75%', '25% globally administered', '20% WPS UUID-E',
    '4 distinct UUIDs', '1 across MACs', '25% Passpoint', '5 probes with P2P device names', 'sender-opaque',
    'Lab &lt;Phone&gt;', '10-Minute Probe Activity', '4 probes', 'Exposure Category Breakdown', 'Short-SSID hash',
    'PNL Chattiness Histogram', '10+ networks']) expect(html).toContain(value);
  expect(html.match(/class="channel-track"/g)).toHaveLength(20);
});

it('renders probe source and tokenized devices in the De-cloaker evidence drawer', () => {
  const row = {
    id: 'network-opaque', name: 'Lab <Guest>', exposure: 'OTHER', source: 'PLAINTEXT_SSID',
    sources: ['PLAINTEXT_SSID', 'SHORT_SSID_MATCH'], deviceCount: 2, lastSeen: 1700000000000,
    devices: [{ id: 'first-sender-token', lastSeen: 1700000000000 }, { id: 'second-sender-token', lastSeen: 1699999998000 }],
  };
  const html = renderToStaticMarkup(<ObservationReport kind="probes" rows={[row]} running={false} stale={false} archived
    initialSelectedKey={observationKey('probes', row)} />);
  for (const value of ['Network name', 'Exposure', 'Probe source', 'Observed devices', 'Last observed',
    'Plaintext SSID, Short-SSID match', 'Lab &lt;Guest&gt;', 'Probing devices', '<code>first-sender-token</code>',
    '<code>second-sender-token</code>']) expect(html).toContain(value);
  expect(html).not.toContain('&quot;lastSeen&quot;');
});

it('renders Whistleblower reveal evidence before the selected access point security and radio details', () => {
  const timestamp = 1700000000000;
  const owe = hiddenNameRow({
    bssid: 'hidden-owe', ssid: 'Enhanced network', hiddenRole: 'OWE_TRANSITION_BSS',
    concealmentMode: 'NULL_PADDED', maskedSsidLength: 16, revealConfidence: 'AP_AUTHORITATIVE',
    hiddenSsidEvidence: { source: 'OWE_TRANSITION', observedAt: timestamp, beaconObservedAt: timestamp },
    coHostedVisibleSsids: ['Public Wi-Fi', 'Guest Wi-Fi'],
    advertisedSecurity: [{ protocol: 'RSN', authentication: ['OWE'], pairwiseCiphers: ['CCMP-128'],
      groupCipher: 'CCMP-128', managementFrameProtection: 'Required' }],
    securityModes: ['OWE (Enhanced Open)'], stationCount: 5,
    managementFeatures: { neighborReport: true, bssTransition: true, fastTransition: true },
    radioObservation: { timestamp, frequencyMhz: 5975, metadata: { signalDbm: -49, snrDb: 42 } },
  });
  const association = hiddenNameRow({ bssid: 'hidden-assoc', ssid: 'Staff network',
    ssidRevealedVia: 'ASSOC_REQ', revealConfidence: 'CONFIRMED_ASSOC' });
  const mesh = hiddenNameRow({ bssid: 'hidden-mesh', hiddenRole: 'MESH_POINT', meshId: 'Lab mesh',
    concealmentMode: 'ZERO_LENGTH', coHostedVisibleSsids: ['Mesh guest'] });
  const rows = [owe, association, mesh];
  const render = (selected: typeof owe) => renderToStaticMarkup(<ObservationReport kind="hidden" rows={rows}
    running={false} stale={false} initialSelectedKey={observationKey('hidden', selected)} />);
  const html = render(owe);
  for (const label of ['OWE transition element', 'Confirmed association', 'AP-authoritative', 'Null-padded (16 bytes)',
    'Public Wi-Fi, Guest Wi-Fi', 'Still hidden', 'Mesh · Lab mesh', 'Mesh guest', 'Advertised security', 'CCMP-128',
    'OWE (Enhanced Open)', '802.11k', '802.11v', '802.11r', '-49 dBm', '42 dB', 'AP-reported stations']) {
    expect(html).toContain(label);
  }
  const drawer = (markup: string) => markup.match(/<aside.*?<\/aside>/s)?.[0] ?? '';
  const evidence = drawer(html);
  expect(evidence).toContain('OWE transition element');
  expect(evidence.indexOf('OWE transition element')).toBeLessThan(evidence.indexOf('Advertised security'));
  expect(evidence).toContain('Public Wi-Fi, Guest Wi-Fi');
  expect(drawer(render(association))).toContain('Confirmed association');
  const meshEvidence = drawer(render(mesh));
  for (const label of ['Still hidden', 'Zero-length SSID', 'Mesh · Lab mesh', 'Mesh guest']) {
    expect(meshEvidence).toContain(label);
  }
});

it('labels inferred probe links and displays recorded radiotap parameters', () => {
  const html = renderToStaticMarkup(<ProfilerEvidence observedId="device-a" detail={{ signalHistory: [], fingerprints: [],
    inferredCorrelation: { id: 'cluster', inference: 'Probabilistic inferred correlation', confidence: 0.85,
      memberIds: ['device-a', 'device-b'], evidence: [{ fromId: 'device-a', toId: 'device-b', sequenceStep: 1,
        gapMs: 300, sharedDirectedSsidCount: 1, confidence: 0.85 }] },
    radioObservation: { timestamp: 1700000000000, frequencyMhz: 5955, metadata: {
      noiseDbm: -93, snrDb: 42, antenna: 0, he: { format: 'HE SU', mcs: 0, bandwidthOrRu: '80 MHz' },
    } },
  }} />);
  for (const value of ['Probabilistic inferred correlation', '85%', 'device-b', '300 ms', '5955 MHz', '-93 dBm', '42 dB', 'MCS 0', '80 MHz']) {
    expect(html).toContain(value);
  }
});

it('renders a category route even when storage access itself throws', () => {
  vi.stubGlobal('location', { pathname: '/privacy' });
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, get() { throw new Error('Storage denied'); } });
  try {
    expect(renderToStaticMarkup(<App initialTheme="slate-cyan" />)).toContain('Whistleblower');
  } finally {
    Reflect.deleteProperty(globalThis, 'localStorage');
  }
});

it('uses readable evidence methods in Overview', () => {
  const roams = ['REASSOC', 'FT', 'DATA_SWITCH'].map((method, time) => ({
    method, time, clientId: 'client', fromBssid: 'first', toBssid: 'second',
  }));
  const html = renderToStaticMarkup(<Overview topology={{ roams, accessPoints: [], edges: [] } as any} onNavigate={() => {}} />);
  for (const label of ['Reassociation', 'Fast transition', 'Data observed on another AP']) expect(html).toContain(label);
  for (const { method } of roams) expect(html).not.toContain(`>${method}<`);
});

it('renders Tracker labels, signal delta, steering and ping-pong evidence', () => {
  const accessPoints = [
    { bssid: 'first', ssid: 'Workshop', channel: 1, band: '2.4 GHz' },
    { bssid: 'second', ssid: 'Workshop 5G', channel: 36, band: '5 GHz' },
  ];
  const data = {
    accessPoints,
    devices: [{ id: 'station-token', classLabel: 'Phone', osHint: 'iOS' }],
    roams: [{ clientId: 'station-token', fromBssid: 'first', toBssid: 'second', time: 1700000000000,
      method: 'FT_OVER_DS', transitionType: 'BAND_STEER', pingPong: true, btmSteered: true,
      fromRssiDbm: -77, toRssiDbm: -54, previousDwellMs: 750, fromChannel: 6, fromBand: '2.4 GHz' }],
    btmRejections: [{ clientId: 'station-token', apId: 'second', statusCode: 7, time: 1700000000015 }],
  } satisfies TrackerReport;
  const rows = records(data, 'roams');
  const html = renderToStaticMarkup(<><Summary kind="roams" data={data} rows={rows} />
    <ObservationReport kind="roams" rows={rows} running={false} stale={false} /></>);
  for (const label of ['Phone · iOS', '<code>station-token</code>', 'Workshop · CH 6 (2.4 GHz)', '<code>first</code>',
    'Workshop 5G · CH 36 (5 GHz)', '<code>second</code>', 'Band steer', 'Ping-pong', '802.11v BTM', 'Dwell 750 ms',
    'Fast transition over DS', '-77 → -54 dBm (+23 dB)', 'Observed AP changes', 'Spatial roams / Band steers',
    '802.11r / 802.11v assisted', 'Ping-pong / BTM rejections', '0 / 1', '1 / 1']) expect(html).toContain(label);

  const overview = renderToStaticMarkup(<Overview topology={{ ...data, edges: [] }} onNavigate={vi.fn()} />);
  for (const label of ['Workshop · CH 6 (2.4 GHz)', '<code>first</code>', 'Workshop 5G · CH 36 (5 GHz)', '<code>second</code>']) {
    expect(overview).toContain(label);
  }
});

it('uses Spotter AP names and keeps original method labels in older Tracker snapshots', () => {
  const data = {
    roams: [{ clientId: 'station-token', fromBssid: 'first', toBssid: 'second', time: 1700000000000, method: 'REASSOC' }],
    devices: [{ id: 'station-token', enrolledLabel: 'Lab phone' }],
  };
  const rows = records(data, 'roams', [{ bssid: 'first', ssid: 'Legacy AP', channel: 11 }]);
  const html = renderToStaticMarkup(<ObservationReport kind="roams" rows={rows} archived running={false} stale={false} />);
  for (const label of ['Legacy AP · CH 11', '<code>second</code>', 'Lab phone', 'Reassociation']) expect(html).toContain(label);
});

const spotterTime = 1700000000000;
const spotter: SpotterObservations = {
  accessPoints: [
    { bssid: 'ap-guest', ssid: 'Guest', stationCount: 5, channel: 5, nonTransmitted: true,
      radioGroupId: 'ap-main', mldId: 'ap-mld', managementFeatures: { twtResponder: true } },
    { bssid: 'ap-main', ssid: 'Campus', stationCount: 0, radioGroupId: 'ap-main' },
  ],
  edges: [
    { clientId: 'client-a', bssid: 'ap-guest', state: 'ACTIVE', source: 'DATA', controlFrames: 2,
      evidenceCount: 3, firstSeen: spotterTime - 1, lastSeen: spotterTime },
    { clientId: 'client-a', bssid: 'ap-main', state: 'ROAMED_AWAY', source: 'ASSOC',
      evidenceCount: 1, firstSeen: spotterTime - 2, lastSeen: spotterTime - 1 },
    { clientId: 'client-b', bssid: 'ap-guest', state: 'DISCONNECTED', source: 'CONTROL',
      evidenceCount: 3, firstSeen: spotterTime - 1, lastSeen: spotterTime },
  ],
  devices: [
    { id: 'client-a', classLabel: 'Phone', vendor: 'Apple' },
    { id: 'client-b', classLabel: 'UNCLASSIFIED', locallyAdministered: true },
  ],
  essGroups: { campus: ['ap-guest', 'ap-main'] },
  meshLinks: [{ peerA: 'peer-a', peerB: 'peer-b', channel: 36, frequencyMhz: 5180,
    frameCount: 16, firstSeen: spotterTime - 1, lastSeen: spotterTime }],
};

it('renders Spotter link states, station gaps, device context and backhaul observations', () => {
  const html = renderToStaticMarkup(<SpotterReport {...spotter} running={false} stale={false} />);
  for (const label of [
    'Phone · Apple', 'Client · Randomized', '<code>client-a</code>', 'Active links only',
    '>Active<', 'Roamed to another AP', 'Disconnected', 'Control frames', '>MBSSID<', '>MLD<',
    '>Co-hosted<', '>TWT<', 'Unobserved stations', 'Mesh / WDS Backhaul Links', '<code>peer-a</code>',
    '<code>peer-b</code>', 'CH 36 · 5180 MHz', '<td>16</td>',
  ]) expect(html).toContain(label);
  expect(html).toContain('<span>Active observed clients</span><b>1</b>');
  expect(html).toContain('<span>Historical links</span><b>2</b>');
  expect(html).toContain('<span>Unobserved stations</span><b>4</b>');
  expect(html).toContain('<td>1 active<small class="spotter-historical">1 historical</small></td><td>4</td>');
});

it('renders Spotter topology labels and distinguishes historical wires', () => {
  const html = renderToStaticMarkup(<SpotterTopology {...spotter} selected={null} onSelect={vi.fn()} />);
  expect(html).toContain('Phone · Apple');
  expect(html).toContain('Client · Randomized');
  expect(html).toContain('<code>client-b</code>');
  expect(html).toContain('topology-wire data" title="Active"');
  expect(html).toContain('topology-wire association historical" title="Roamed to another AP"');
  expect(html).toContain('topology-wire other historical" title="Disconnected"');
  expect(html).toContain('href="#spotter-mesh">Backhaul links (1)');
  for (const tag of ['MBSSID', 'MLD', 'Co-hosted', 'ESS']) expect(html).toContain(`>${tag}<`);
});

it('treats Spotter links in older reports as active and renders missing optional sections', () => {
  const [first] = spotter.edges;
  const html = renderToStaticMarkup(<SpotterReport accessPoints={spotter.accessPoints}
    edges={[{ ...first, state: undefined, controlFrames: undefined }]} running={false} stale={false} />);
  expect(html).toContain('<span>Active observed clients</span><b>1</b>');
  expect(html).toContain('>Active<');
  expect(html).toContain('<code>client-a</code>');
  expect(html).not.toContain('Mesh / WDS Backhaul Links');
});

it.each([
  ['deauth', { success: false, command: 'lab command', output: 'lab stdout' }],
  ['handshake', { captureOutput: 'lab stdout' }],
  ['handshake-verify', { fullOutput: 'lab stdout' }],
  ['pmkid', { output: 'lab stdout' }],
  ['pmkid-verify', { output: 'lab stdout' }],
  ['beacon', { command: 'lab command', error: 'lab error', output: 'lab stdout' }],
  ['evil-twin', { error: 'lab error' }],
])('renders %s diagnostics once when both final result and status are present', (operation, result) => {
  const html = renderToStaticMarkup(<ResultView operation={operation} result={result}
    status={{ running: false, command: 'lab command', error: 'lab error', output: 'lab stdout' }} />);
  for (const diagnostic of ['lab command', 'lab error', 'lab stdout']) expect(html.split(diagnostic)).toHaveLength(2);
});

it('keeps live output and credential rows while an operation runs', () => {
  const html = renderToStaticMarkup(<ResultView operation="evil-twin" result={null}
    status={{ running: true, output: 'live diagnostics', credentials: [{ time: 'now', client: 'lab', username: 'dummy', password: 'fixture' }] }} />);
  expect(html).toContain('live diagnostics');
  expect(html).toContain('dummy');
});

it.each(['beacon', 'evil-twin'])('shows newer %s polling output instead of its start snapshot', operation => {
  const html = renderToStaticMarkup(<ResultView operation={operation}
    result={{ running: true, command: 'old command', output: 'old output' }}
    status={{ running: false, command: 'new command', output: 'new output', error: 'new error' }} />);
  expect(html).toContain('new command');
  expect(html).toContain('new output');
  expect(html).toContain('new error');
  expect(html).not.toContain('old command');
  expect(html).not.toContain('old output');
});

it('renders scoped PMKID targets and recent operation history entries without secrets', () => {
  const resultHtml = renderToStaticMarkup(
    <ResultView operation="pmkid" status={null}
      result={{ captured: true, vulnerable: false, targetApBssid: 'fc:69:0c:15:82:64', frequencyMhz: 2437, pcapngPath: '/tmp/a.pcapng' }} />,
  );
  expect(resultHtml).toContain('fc:69:0c:15:82:64');
  expect(resultHtml).toContain('2437 MHz');

  const historyHtml = renderToStaticMarkup(
    <OperationHistoryPanel onClear={() => {}} history={[
      {
        id: '11111111-1111-1111-1111-111111111111',
        operation: 'evil-twin',
        target: 'ewave-portal',
        interfaceName: 'wlo1ap',
        startedAt: '2026-01-01T10:00:00Z',
        endedAt: '2026-01-01T10:00:05Z',
        durationMs: 5000,
        outcome: 'STOPPED',
        success: true,
      },
    ]} />,
  );
  expect(historyHtml).toContain('Recent operations');
  expect(historyHtml).toContain('evil-twin');
  expect(historyHtml).toContain('ewave-portal');
  expect(historyHtml).toContain('5.0 s');
  expect(historyHtml).toContain('Clear history');
});

it('renders correlation basis labels for probe-to-association, PNL and WPS evidence', () => {
  const html = renderToStaticMarkup(
    <ProfilerEvidence observedId="client-a" detail={{
      signalHistory: [],
      fingerprints: [],
      inferredCorrelation: {
        id: 'corr-1',
        inference: 'Probabilistic inferred correlation',
        confidence: 0.72,
        memberIds: ['client-a', 'client-b', 'client-c', 'client-d'],
        evidence: [
          { fromId: 'client-a', toId: 'client-b', sequenceStep: 4, gapMs: 1200, sharedDirectedSsidCount: 1, confidence: 0.82, basis: 'PROBE_TO_ASSOC' },
          { fromId: 'client-a', toId: 'client-c', sequenceStep: 900, gapMs: 15000, sharedDirectedSsidCount: 2, confidence: 0.68, basis: 'PNL_PROFILE' },
          { fromId: 'client-c', toId: 'client-d', sequenceStep: 91, gapMs: 65000, sharedDirectedSsidCount: 0, confidence: 0.95, basis: 'WPS_UUID_E' },
        ],
      },
    }} />,
  );
  expect(html).toContain('Probe-to-association capability &amp; SSID match');
  expect(html).toContain('Preferred-network list &amp; IE fingerprint match');
  expect(html).toContain('1 shared directed SSID');
  expect(html).toContain('2 shared directed SSIDs');
  expect(html).toContain('Identical WPS Enrollee UUID (UUID-E) across MACs');
  expect(html).toContain('95% confidence');
});

it.each([
  ['WPS_DEVICE_TYPE', 'WPS device type'],
  ['VENDOR_IE_HEURISTIC', 'Vendor IE signature'],
])('renders Profiler fingerprint detail and association context for %s', (classificationBasis, basisLabel) => {
  const html = renderToStaticMarkup(<ProfilerEvidence observedId="station-token" detail={{
    signalHistory: [], osHint: 'iOS / iPadOS', classificationBasis,
    associatedAp: { apId: 'ap-token', ssid: 'Lab <west>', channel: 36, frequencyMhz: 5180, source: 'ASSOC' },
    fingerprints: [{ hash: '0123456789abcdef', source: 'PROBE_REQUEST', observations: 2,
      ieOrder: ['1', '50', '45', '127', '191', '255:35'],
      vendorElements: ['00:17:f2 (Apple)', '00:50:f2:04 (WPS)'], bandCohort: 'abcd0123abcd0123' }],
  }} />);
  for (const label of ['IE tag order', '1, 50, 45, 127, 191, 255:35', 'Vendor elements', '00:17:f2 (Apple)',
    '00:50:f2:04 (WPS)', 'Band-invariant cohort', 'abcd0123abcd0123', 'Save as sample', 'iOS / iPadOS',
    basisLabel, 'Connected to Lab &lt;west&gt; · CH 36']) expect(html).toContain(label);
});

it('renders the enrolled label and device context in the Profiler table and archived evidence', () => {
  const row = {
    id: 'station-token', enrolledLabel: 'Lab phone', classLabel: 'Phone', osHint: 'Android (Samsung)',
    classificationBasis: 'VENDOR_IE_HEURISTIC', classConfidence: 0.80,
    associatedAp: { apId: 'ap-token', ssid: 'Lab Wi-Fi', channel: 6, frequencyMhz: 2437, source: 'DATA' },
  };
  const html = renderToStaticMarkup(<ObservationReport kind="inventory" rows={[row]} running={false} stale={false}
    archived initialSelectedKey={observationKey('inventory', row)} />);
  for (const value of ['Lab phone', 'station-token', 'Android (Samsung)', 'Vendor IE signature', 'Connected to Lab Wi-Fi · CH 6']) {
    expect(html.match(/<tbody.*?<\/tbody>/s)?.[0]).toContain(value);
    expect(html.match(/<aside.*?<\/aside>/s)?.[0]).toContain(value);
  }
  expect(html).not.toContain('Save as sample');
});

it('renders live handshake progress steps, verifiable partial results, PMKID captureOnly table, and evil-twin telemetry', () => {
  const hsHtml = renderToStaticMarkup(
    <ResultView
      operation="handshake"
      status={{
        running: true, stage: 'Ready — reconnect your device now', beaconSeen: true,
        observedMessages: [1, 2], verifiable: true, verifiablePair: 'M1_M2',
        peerMac: '02:11:22:33:44:66', remainingSeconds: 24,
      }}
      result={{
        handshakeDetected: false, outcome: 'PARTIAL', verifiable: true, verifiablePair: 'M1_M2',
        apBssid: '02:11:22:33:44:55', clientMac: '02:11:22:33:44:66', frequencyMhz: 2437,
        messages: [1, 2], capFilePath: '/tmp/hs-partial.cap',
      }}
    />,
  );
  for (const text of ['24s remaining', 'Beacon', 'M1', 'M2', 'Verifiable (M1_M2)', 'Peer 02:11:22:33:44:66', 'PARTIAL', '/tmp/hs-partial.cap']) {
    expect(hsHtml).toContain(text);
  }

  const pmkidHtml = renderToStaticMarkup(
    <ResultView
      operation="pmkid"
      status={{ running: false, stage: 'Capture complete', phase: 'COMPLETE', pmkidCount: 1, eapolPairCount: 2 }}
      result={{
        captured: true, vulnerable: false, verificationSkipped: true, eapolPairCount: 2,
        pcapngPath: '/tmp/p.pcapng', hashPath: '/tmp/p.22000',
        pmkids: [{ pmkid: '4d4fe7aac3a2cecab195321ceb99a7d0', apBssid: 'fc:69:0c:15:82:64', stationMac: 'f4:74:7f:87:f9:f4', essid: 'hashcat-essid' }],
      }}
    />,
  );
  for (const text of ['Verification skipped', '2 EAPOL pairs', '4d4fe7aac3a2', 'fc:69:0c:15:82:64', 'hashcat-essid']) {
    expect(pmkidHtml).toContain(text);
  }

  const twinHtml = renderToStaticMarkup(
    <ResultView
      operation="evil-twin"
      result={null}
      status={{
        running: true, stage: 'Portal running', elapsedSeconds: 12,
        connectedStations: [{ mac: 'aa:bb:cc:dd:ee:11', connectedAt: '10:00:00Z' }],
        dhcpLeases: [{ ip: '10.0.0.25', mac: 'aa:bb:cc:dd:ee:11', hostname: 'lab-phone', expiresAtEpochSeconds: 1700000000 }],
      }}
    />,
  );
  for (const text of ['12s elapsed', 'Associated stations', 'aa:bb:cc:dd:ee:11', 'DHCP lease IP', '10.0.0.25', 'lab-phone']) {
    expect(twinHtml).toContain(text);
  }
});

it('renders Passive to Ops launch buttons only for live actionable rows', () => {
  const hiddenRow = hiddenNameRow({
    bssid: 'wifi:hidden-1', ssid: null, ssidHidden: true, channel: 6, frequencyMhz: 2437,
  });
  const revealedRow = hiddenNameRow({
    bssid: 'wifi:hidden-2', ssid: 'RevealedNet', ssidHidden: true, channel: 6, frequencyMhz: 2437,
  });

  const liveHidden = renderToStaticMarkup(
    <ObservationReport kind="hidden" rows={[hiddenRow]} running={false} stale={false}
      initialSelectedKey={observationKey('hidden', hiddenRow)} onOpenInOps={() => {}} />,
  );
  expect(liveHidden).toContain('Uncloak in Ops');

  const archivedHidden = renderToStaticMarkup(
    <ObservationReport kind="hidden" rows={[hiddenRow]} archived running={false} stale={false}
      initialSelectedKey={observationKey('hidden', hiddenRow)} onOpenInOps={() => {}} />,
  );
  expect(archivedHidden).not.toContain('Uncloak in Ops');

  const liveRevealed = renderToStaticMarkup(
    <ObservationReport kind="hidden" rows={[revealedRow]} running={false} stale={false}
      initialSelectedKey={observationKey('hidden', revealedRow)} onOpenInOps={() => {}} />,
  );
  expect(liveRevealed).not.toContain('Uncloak in Ops');

  const inspectorAp = { bssid: 'wifi:ap-1', ssid: 'CampusNet', channel: 36, frequencyMhz: 5180 };
  const liveInspector = renderToStaticMarkup(
    <ObservationReport kind="aps" rows={[inspectorAp]} running={false} stale={false}
      initialSelectedKey={observationKey('aps', inspectorAp)} onOpenInOps={() => {}} />,
  );
  expect(liveInspector).toContain('Open in Ops');
});
