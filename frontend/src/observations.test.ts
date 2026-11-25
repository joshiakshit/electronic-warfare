import { describe, expect, it } from 'vitest';
import {
  channelBand, channelRows, chronologicalSignal, deviceClassification, groupApChanges, hiddenNameRow, isIdentifier,
  observationColumns, observationKey, observationMatches, observationValue, observedClientsByAp, occupancyEstimate, occupancyLabel,
} from './observations';

describe('observation presentation', () => {
  it('shows probe names and sources without exposing raw report fields as columns', () => {
    const row = { id: 'report-id', name: '<Synthetic SSID>', exposure: 'OTHER', source: 'SHORT_SSID_MATCH',
      lastSeen: 1700000000000, deviceCount: 1, timeline: [0, 1], devices: [{ id: 'sender-id', lastSeen: 1700000000000 }] };
    expect(observationValue('name', row)).toBe('<Synthetic SSID>');
    expect(observationValue('name', { ...row, name: null })).toBe('—');
    expect(observationValue('source', row)).toBe('Short-SSID match');
    expect(observationValue('source', { ...row, sources: ['PLAINTEXT_SSID', 'SSID_LIST', 'SHORT_SSID_MATCH'] }))
      .toBe('Plaintext SSID, SSID List, Short-SSID match');
    expect(observationValue('exposure', { exposure: 'SHORT_SSID_HASH' })).toBe('Short-SSID hash');
    expect(observationColumns('probes', [row])).toEqual(['name', 'exposure', 'source', 'deviceCount', 'lastSeen']);
  });

  it('keeps one selection across report refreshes and distinguishes links for the same client', () => {
    const row = { clientId: 'client', bssid: 'first-ap', lastSeen: 1700000000000 };
    expect(observationKey('edges', row)).toBe(observationKey('edges', { ...row, lastSeen: row.lastSeen + 1 }));
    expect(observationKey('edges', row)).not.toBe(observationKey('edges', { ...row, bssid: 'second-ap' }));
  });

  it('uses scanner sample counts to separate a measured zero from absent coverage', () => {
    const [withoutSamples, measuredZero, measured, unknown] = channelRows({
      counts: [0, 5, 10],
      channels: [
        { channel: 1, occupancyMean: 0.5 }, { channel: 2, occupancyMean: 0 },
        { channel: 3, occupancyMean: 0.18 }, { channel: 4, occupancyMean: 0.85 },
      ],
    });
    expect(occupancyEstimate(withoutSamples)).toBeNull();
    expect(occupancyLabel(withoutSamples)).toBe('No samples');
    expect(occupancyEstimate(measuredZero)).toBe(0);
    expect(occupancyLabel(measuredZero)).toMatch(/0\s*%/);
    expect(occupancyEstimate(measured)).toBe(0.18);
    expect(occupancyLabel(unknown)).toBe('Sample count unavailable');
  });

  it('groups channel reports by frequency even when channel numbers repeat across bands', () => {
    expect([2412, 5180, 5955].map(channelBand)).toEqual(['2.4 GHz', '5 GHz', '6 GHz']);
    expect(observationKey('channels', { channel: 1, freqMhz: 2412 }))
      .not.toBe(observationKey('channels', { channel: 1, freqMhz: 5955 }));
    const [twoFour, six] = channelRows({ counts: [50, 60], channels: [
      { channel: 1, freqMhz: 2412, sampleCount: 3, occupancyMean: 0 },
      { channel: 1, freqMhz: 5955, sampleCount: 0, occupancyMean: 0 },
    ] });
    expect(occupancyEstimate(twoFour)).toBe(0);
    expect(occupancyLabel(six)).toBe('No samples');
    expect(channelRows({ counts: [50], channels: [{channel: 1, freqMhz: 5955}] })[0].sampleCount).toBeNull();
  });

  it('counts each observed client once per access point independently of advertised station counts', () => {
    const counts = observedClientsByAp([
      { bssid: 'AP-1', clientId: 'client-1' },
      { bssid: 'AP-1', clientId: 'client-1' },
      { bssid: 'AP-2', clientId: 'client-1' },
      { bssid: 'AP-2', clientId: 'client-2' },
    ]);
    expect(counts.get('AP-1')?.size).toBe(1);
    expect(counts.get('AP-2')?.size).toBe(2);
    expect(counts.get('AP-3')).toBeUndefined();
  });

  it('uses advertised suites for the security label and preserves the AP security fallback', () => {
    expect(observationValue('security', {
      security: 'RSN[000fac04;000fac04;000fac08]',
      advertisedSecurity: [{ protocol: 'RSN', authentication: ['SAE'] }],
    })).toBe('RSN · SAE');
    expect(observationValue('security', { security: 'Open', advertisedSecurity: [] })).toBe('Open');
    expect(observationValue('security', { security: 'Privacy bit set' })).toBe('Privacy bit set');
    expect(isIdentifier('ssid')).toBe(false);
    expect(isIdentifier('bssid')).toBe(true);
  });

  it('displays the AP-reported busy fraction and leaves missing load values unavailable', () => {
    expect(observationValue('channelUtilization', { channelUtilization: 255 })).toMatch(/100\s*%/);
    expect(observationValue('channelUtilization', { channelUtilization: 51 })).toMatch(/20\s*%/);
    expect(observationValue('channelUtilization', { channelUtilization: 0 })).toMatch(/0\s*%/);
    expect(observationValue('channelUtilization', { channelUtilization: null })).toBe('—');
    expect(observationValue('channelUtilization', { channelUtilization: 256 })).toBe('—');
  });

  it('distinguishes inferred Profiler labels from unclassified rows and supports legacy device fields', () => {
    expect(deviceClassification({ classLabel: 'UNCLASSIFIED' })).toBeNull();
    expect(observationValue('classConfidence', { classLabel: 'UNCLASSIFIED', classConfidence: 0.1 })).toBe('—');
    expect(observationValue('classConfidence', { classLabel: 'Test family', classConfidence: 0.82 })).toMatch(/82\s*%/);
    expect(observationValue('classLabel', { guessedType: 'Legacy type' })).toBe('Legacy type');
    expect(observationKey('inventory', { mac: 'legacy-id' })).toBe('["legacy-id"]');
  });

  it('orders retained signal observations and drops missing or invalid samples', () => {
    const samples = [{ timestamp: 20, rssi: -70 }, { timestamp: 10, rssi: -53 }, { timestamp: 30, rssi: NaN }];
    expect(chronologicalSignal(samples)).toEqual([samples[1], samples[0]]);
    expect(samples[0].timestamp).toBe(20);
  });

  it('prioritizes the actual revealing frame and keeps hidden beacon time distinct', () => {
    const row = hiddenNameRow({
      ssid: 'Synthetic network', ssidRevealedVia: 'ASSOC_REQ', lastSeen: 100,
      hiddenSsidEvidence: { name: 'Synthetic network', source: 'REASSOC_REQ', observedAt: 90, beaconObservedAt: 80 },
    });
    expect(row).toMatchObject({
      nameStatus: 'Name observed', revealFrame: 'Reassociation request', revealedAt: 90, beaconObservedAt: 80,
    });
    expect(hiddenNameRow({ ssid: null, ssidRevealedVia: 'NONE', lastSeen: 110 })).toMatchObject({
      nameStatus: 'Still hidden', revealFrame: null, revealedAt: null,
    });
    expect(hiddenNameRow({ ssid: 'Legacy network', ssidRevealedVia: 'PROBE_RESP', lastSeen: 110 })).toMatchObject({
      nameStatus: 'Name observed', revealFrame: 'Probe response', revealedAt: null,
    });
  });

  it('groups changes by client with oldest first inside each group and preserves the event evidence', () => {
    const event = { fromBssid: 'ap-1', toBssid: 'ap-2', method: 'DATA_SWITCH' };
    const changes = [
      { ...event, clientId: 'client-a', time: 30 },
      { ...event, clientId: 'client-b', time: 20, method: 'FT' },
      { ...event, clientId: 'client-a', time: 10, fromBssid: 'ap-3', method: 'REASSOC' },
    ];
    expect(groupApChanges(changes)).toEqual([
      { clientId: 'client-a', rows: [changes[2], changes[0]] },
      { clientId: 'client-b', rows: [changes[1]] },
    ]);
    expect(observationValue('method', changes[0])).toBe('Data observed on another AP');
    expect(observationValue('method', { method: 'INFERRED_MAC_ROTATION' })).toBe('Inferred MAC rotation (heuristic)');
  });
});

it('filters observed and formatted values without matching JSON keys or absent flags', () => {
  const channel = { channel: 6, freqMhz: 2437, sampleCount: 2, anomaly: null };
  const columns = observationColumns('channels', [channel]);
  for (const query of ['anomaly', 'null', 'freqMhz']) expect(observationMatches(channel, columns, query)).toBe(false);
  expect(observationMatches({ ...channel, anomaly: { reason: 'Unusual burst' } }, columns, 'burst')).toBe(true);
  const ap = { ssid: 'Lab', ssidHidden: false, advertisedSecurity: [{ protocol: 'WPA2', authentication: ['PSK'] }] };
  const apColumns = observationColumns('aps', [ap]);
  for (const query of ['hidden', 'false', 'ssidHidden', 'authentication']) expect(observationMatches(ap, apColumns, query)).toBe(false);
  expect(observationMatches(ap, apColumns, 'wpa2')).toBe(true);
  expect(observationMatches({ ...ap, ssid: null, ssidHidden: true }, apColumns, 'hidden')).toBe(true);
  expect(observationMatches({ method: 'DATA_SWITCH' }, ['method'], 'another ap')).toBe(true);
  expect(observationMatches({ method: 'INFERRED_MAC_ROTATION' }, ['method'], 'mac rotation')).toBe(true);
});
