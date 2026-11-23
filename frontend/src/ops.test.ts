import { describe, expect, it } from 'vitest';
import { accessPointLabel, errorMessage, operationReadiness, startPath, statusPath, targetLabel, toolSummary } from './ops';

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
