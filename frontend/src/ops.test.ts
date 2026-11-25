import { describe, expect, it, vi } from 'vitest';
import {
  accessPointLabel, adoptBackendOperation, errorMessage, evilTwinAddressSummary, evilTwinChannelSupported,
  formatHistoryDuration, isDfsChannel, isLocallyAdministeredMac, matchesTargetFilter, operationIsRunning,
  operationReadiness, operationTabForActive, opsApi, parseSsidList, pmkidRequestBody, pmfDeauthWarning,
  polledOperation, pskSuitabilityWarning, sortObservedAps, sortOpsTargets, startPath, statusPath, targetLabel,
  toolSummary, uncloakCandidates,
} from './ops';

describe('Ops request routing and labels', () => {
  it('routes status and start requests for every operation shape', () => {
    expect(statusPath('deauth')).toBe('/api/ops/status');
    expect(statusPath('uncloak')).toBe('/api/ops/status');
    expect(statusPath('handshake')).toBe('/api/ops/handshake/status');
    expect(statusPath('handshake-verify')).toBe('/api/ops/handshake/status');
    expect(statusPath('pmkid')).toBe('/api/ops/pmkid/status');
    expect(startPath('handshake')).toBe('/api/ops/handshake');
    expect(startPath('handshake-verify')).toBe('/api/ops/handshake/verify');
    expect(startPath('evil-twin')).toBe('/api/ops/evil-twin');
  });

  it('labels evidenced targets and observed access points with their evidence', () => {
    expect(targetLabel({
      id: 'target-1', mac: '02:aa:bb:cc:dd:01', label: 'Phone · Lab', apSsid: 'Lab', channel: 6,
    })).toBe('Phone · Lab · Lab · CH 6');
    expect(accessPointLabel({
      bssid: 'wifi:ap', ssid: null, ssidHidden: true, channel: 11, clients: ['a', 'b'],
    })).toBe('Hidden SSID · CH 11 · 2 clients');
    expect(accessPointLabel({ bssid: 'wifi:six', ssid: 'Lab', channel: 1, frequencyMhz: 5955, clients: [] }))
      .toBe('Lab · CH 1 · 5955 MHz · no observed clients');
    expect(accessPointLabel({ bssid: 'wifi:ap', ssid: 'Lab', channel: 1, clients: [] }))
      .toBe('Lab · CH 1 · no observed clients');
  });

  it('summarizes operation readiness and errors without simulating actions', () => {
    const capabilities = {
      operations: [
        { id: 'deauth', label: 'Deauthentication', ready: true, missing: [] },
        { id: 'pmkid', label: 'PMKID capture', ready: false, missing: ['hcxdumptool'] },
      ],
    } as any;
    expect(toolSummary(capabilities)).toBe('1/2 operation paths ready');
    expect(operationReadiness(capabilities, 'pmkid')?.missing).toEqual(['hcxdumptool']);
    expect(errorMessage(new Error('operation failed'))).toBe('operation failed');
    expect(errorMessage('offline')).toBe('offline');
  });
});

describe('Ops running state for continuous operations', () => {
  it('keeps a started operation running after its start request returns', () => {
    // Beacon and evil-twin answer immediately with { running: true }, so busy is already false.
    expect(operationIsRunning(false, 'beacon', { running: true })).toBe(true);
    expect(operationIsRunning(false, 'evil-twin', { running: true })).toBe(true);
    expect(polledOperation('beacon', false, { running: true })).toBe('beacon');
  });

  it('treats an active operation without a status yet as running', () => {
    // A remounted console hydrates active from capabilities before its first status poll.
    expect(operationIsRunning(false, 'beacon', null)).toBe(true);
    expect(polledOperation('evil-twin', false, null)).toBe('evil-twin');
  });

  it('stops polling once the operation reports it is no longer running', () => {
    expect(operationIsRunning(false, 'beacon', { running: false })).toBe(false);
    expect(polledOperation('beacon', false, { running: false })).toBe(null);
    expect(operationIsRunning(true, 'beacon', null)).toBe(true);
    expect(polledOperation(null, false, { running: true })).toBe(null);
  });

  it('adopts the backend operation after a remount without fighting a local run', () => {
    expect(adoptBackendOperation('beacon', null, false)).toBe('beacon');
    expect(adoptBackendOperation('evil-twin', null, false)).toBe('evil-twin');
    expect(adoptBackendOperation('handshake-verify', null, false)).toBe('handshake-verify');
    expect(operationTabForActive('handshake-verify')).toBe('handshake');
    expect(operationTabForActive('beacon')).toBe('beacon');
    expect(operationTabForActive('unknown')).toBe(null);
    expect(adoptBackendOperation('beacon', 'beacon', false)).toBe(null);
    expect(adoptBackendOperation('beacon', null, true)).toBe(null);
    expect(adoptBackendOperation(null, null, false)).toBe(null);
    // Network name reveal is reported as deauth by the shared injector slot.
    expect(adoptBackendOperation('deauth', 'uncloak', false)).toBe(null);
  });
});

describe('uncloak target eligibility', () => {
  it('excludes revealed hidden names and APs without clients', () => {
    const aps = [
      { bssid: 'hidden', ssidHidden: true, ssid: null, clients: ['client'] },
      { bssid: 'revealed', ssidHidden: true, ssid: 'Known name', clients: ['client'] },
      { bssid: 'silent', ssidHidden: true, ssid: null, clients: [] },
    ];
    expect(uncloakCandidates(aps).map(ap => ap.bssid)).toEqual(['hidden']);
  });
});

it('limits the current evil-twin configuration to supported 2.4/5 GHz channels', () => {
  for (const channel of [1, 6, 14, 36, 100, 149, 177]) expect(evilTwinChannelSupported(channel)).toBe(true);
  for (const channel of [0, 15, 31, 33, 178, 233]) expect(evilTwinChannelSupported(channel)).toBe(false);
});

describe('PMKID scoping, Evil Twin IPv4 readiness, and operationId-scoped stop', () => {
  it('builds unscoped and AP/frequency-scoped PMKID request payloads', () => {
    expect(pmkidRequestBody({ interfaceName: 'wlo1', wordlistPath: '/words.txt', durationSeconds: 30 }))
      .toEqual({ interface: 'wlo1', wordlistPath: '/words.txt', durationSeconds: 30 });
    expect(pmkidRequestBody({
      interfaceName: 'wlo1', wordlistPath: '/words.txt', durationSeconds: 20,
      selectedApId: 'wifi:ap-1', apBssid: '02:11:22:33:44:55', frequencyMhz: 2437,
    })).toEqual({ interface: 'wlo1', wordlistPath: '/words.txt', durationSeconds: 20, apId: 'wifi:ap-1' });
    expect(pmkidRequestBody({
      interfaceName: 'wlo1', wordlistPath: '/words.txt', durationSeconds: 15,
      apBssid: ' 02:11:22:33:44:55 ', frequencyMhz: 5180,
    })).toEqual({
      interface: 'wlo1', wordlistPath: '/words.txt', durationSeconds: 15,
      apBssid: '02:11:22:33:44:55', frequencyMhz: 5180,
    });
  });

  it('summarizes AP interface IPv4 readiness and formats history durations', () => {
    const interfaces = [
      { name: 'wlo1ap', up: true, loopback: false, virtual: true, ipv4Addresses: ['10.0.0.1'] },
      { name: 'wlan1', up: false, loopback: false, virtual: false, ipv4Addresses: [] },
    ];
    expect(evilTwinAddressSummary(interfaces, 'wlo1ap')).toEqual({
      found: true, up: true, addresses: ['10.0.0.1'], hasPortalAddress: true,
    });
    expect(evilTwinAddressSummary(interfaces, 'wlan1')).toEqual({
      found: true, up: false, addresses: [], hasPortalAddress: false,
    });
    expect(evilTwinAddressSummary(interfaces, 'missing').found).toBe(false);
    expect(formatHistoryDuration(420)).toBe('420 ms');
    expect(formatHistoryDuration(2550)).toBe('2.5 s');
  });

  it('scopes stop requests by operationId when present and calls history endpoints', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response('{}', {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    try {
      await opsApi.stop('11111111-1111-1111-1111-111111111111');
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/stop', expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ operationId: '11111111-1111-1111-1111-111111111111' }),
      }));
      await opsApi.stop(null);
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/stop', expect.objectContaining({
        method: 'POST',
        body: '{}',
      }));
      await opsApi.clearHistory();
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/history', expect.objectContaining({
        method: 'DELETE',
      }));
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it('identifies locally administered unicast MACs for default handshake rotation handling', () => {
    for (const randomMac of ['02:11:22:33:44:55', 'd6:aa:bb:cc:dd:ee', '0A:00:00:00:00:01', '1e:22:33:44:55:66']) {
      expect(isLocallyAdministeredMac(randomMac)).toBe(true);
    }
    for (const fixedOrInvalid of ['00:11:22:33:44:55', '50:c7:bf:11:22:33', '03:11:22:33:44:55', 'bad', null, undefined]) {
      expect(isLocallyAdministeredMac(fixedOrInvalid)).toBe(false);
    }
  });
});

describe('Ops lab workbench helpers (#9A–#9D)', () => {
  it('routes pmkid-verify requests and captureOnly payloads', () => {
    expect(statusPath('pmkid-verify')).toBe('/api/ops/pmkid/status');
    expect(startPath('pmkid-verify')).toBe('/api/ops/pmkid/verify');
    expect(operationTabForActive('pmkid-verify')).toBe('pmkid');
    expect(pmkidRequestBody({
      interfaceName: 'wlo1', wordlistPath: '  ', durationSeconds: 20, captureOnly: true,
    })).toEqual({ interface: 'wlo1', durationSeconds: 20, captureOnly: true });
  });

  it('detects DFS channels, PMF warnings, PSK suitability, and SSID lists', () => {
    expect(isDfsChannel(52, 5260)).toBe(true);
    expect(isDfsChannel(100, undefined)).toBe(true);
    expect(isDfsChannel(36, 5180)).toBe(false);
    expect(pmfDeauthWarning('Required')).toContain('802.11w PMF');
    expect(pmfDeauthWarning('Capable')).toBeNull();
    expect(pskSuitabilityWarning('WPA3', ['SAE'])).toContain('not applicable');
    expect(pskSuitabilityWarning('WPA2/WPA3', ['PSK', 'SAE'])).toBeNull();
    expect(pskSuitabilityWarning('Open', [])).toContain('Open network');
    expect(parseSsidList(' Lab-1 \n\n  Lab-2\r\n ')).toEqual(['Lab-1', 'Lab-2']);
  });

  it('sorts targets and APs strongest signal first while ignoring bogus sentinel RSSI and filters case-insensitively', () => {
    const aps = sortObservedAps([
      { bssid: 'weak', ssid: 'Neighbor', rssiDbm: -88, channel: 1 },
      { bssid: 'strong-hidden', ssid: null, ssidHidden: true, rssiDbm: -32, channel: 6 },
      { bssid: 'strong-named', ssid: 'EWAVE-LAB', rssiDbm: -34, channel: 11 },
      { bssid: 'unknown', ssid: 'NoRssi', rssiDbm: null, channel: 36 },
    ]);
    expect(aps.map(a => a.bssid)).toEqual(['strong-hidden', 'strong-named', 'weak', 'unknown']);

    const targets = sortOpsTargets([
      { id: 'sentinel', mac: '02:00:00:00:00:01', rssi: 127, apSsid: 'FarAp' },
      { id: 'close', mac: '02:00:00:00:00:02', rssi: -38, apSsid: 'EWAVE-LAB-5G' },
      { id: 'mid', mac: '02:00:00:00:00:03', rssi: -75, apSsid: 'MidAp' },
    ]);
    expect(targets.map(t => t.id)).toEqual(['close', 'mid', 'sentinel']);
    expect(matchesTargetFilter('ewave', ['EWAVE-LAB', 'aa:bb:cc'])).toBe(true);
    expect(matchesTargetFilter('ch 36', ['Other', 'CH 36'])).toBe(true);
    expect(matchesTargetFilter('ewave', ['Neighbor', 6])).toBe(false);
  });

  it('calls new LAN hosts, handshake/PMKID early finish, save-recording, and PMKID verify endpoints', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => new Response('{"available":true,"hosts":[]}', {
      status: 200, headers: { 'Content-Type': 'application/json' },
    }));
    vi.stubGlobal('fetch', fetchMock);
    try {
      await opsApi.lanHosts();
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/lan-hosts', expect.any(Object));
      await opsApi.finishHandshake();
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/handshake/finish', expect.objectContaining({ method: 'POST' }));
      await opsApi.saveHandshakeRecording({ capFilePath: '/tmp/hs.cap' });
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/handshake/save-recording', expect.objectContaining({
        method: 'POST', body: JSON.stringify({ capFilePath: '/tmp/hs.cap' }),
      }));
      await opsApi.finishPmkid();
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/pmkid/finish', expect.objectContaining({ method: 'POST' }));
      await opsApi.verifyPmkid({ wordlistPath: '/words.txt', hashPath: '/tmp/h.22000' });
      expect(fetchMock).toHaveBeenLastCalledWith('/api/ops/pmkid/verify', expect.objectContaining({
        method: 'POST', body: JSON.stringify({ wordlistPath: '/words.txt', hashPath: '/tmp/h.22000' }),
      }));
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
