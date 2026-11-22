import { describe, expect, it } from 'vitest';
import { activeRoute, captureStateLabel, modulePath, rememberedTab, sessionSummary, sniperStartRequest } from './navigation';

describe('navigation and session state', () => {
  it('keeps nested module selection in the URL', () => {
    expect(activeRoute('/privacy/de-cloaker')).toBe('de-cloaker');
    expect(modulePath('privacy', 'de-cloaker')).toBe('/privacy/de-cloaker');
    expect(rememberedTab('privacy', 'privacy', ['whistleblower', 'de-cloaker'], 'de-cloaker')).toBe('de-cloaker');
  });
  it('uses the active backend capture snapshot and defaults to idle', () => {
    expect(sessionSummary({ wifi: { captureMode: 'replay', captureInterface: 'demo.pcap' } }, { mode: 'replay', running: false, observedChannel: 6, observedFrequencyMhz: 2437 })).toMatchObject({ mode: 'replay', source: 'demo.pcap', channel: 6, frequency: 2437, running: false });
    expect(sessionSummary(null, null).mode).toBe('idle');
  });
  it('keeps receiver readings separate from the channel of the last frame', () => {
    const readings = {
      radio: { channel: 1, frequencyMhz: 2412 },
      observedChannel: 6,
      observedFrequencyMhz: 2437,
    };
    expect(sessionSummary(null, { ...readings, mode: 'watch', running: true }))
      .toMatchObject({ channel: 1, frequency: 2412, channelLabel: 'Receiver' });
    expect(sessionSummary(null, { ...readings, mode: 'watch', running: false }))
      .toMatchObject({ channel: 6, frequency: 2437, channelLabel: 'Last frame' });
    expect(sessionSummary(null, { ...readings, mode: 'replay', running: true }))
      .toMatchObject({ channel: 6, frequency: 2437, channelLabel: 'Last frame' });
  });
  it('does not create a Sniper request without an explicit target and available capture', () => {
    expect(sniperStartRequest('', true)).toBeNull();
    expect(sniperStartRequest('Lab', false)).toBeNull();
    expect(sniperStartRequest(' Lab ', true)).toEqual({ ssid: ' Lab ' });
    expect(sniperStartRequest('é'.repeat(16), true)).toEqual({ ssid: 'é'.repeat(16) });
    expect(sniperStartRequest('é'.repeat(17), true)).toBeNull();
  });
  it('distinguishes completed, failed, and stopped recordings from an active replay', () => {
    expect(captureStateLabel({ mode: 'replay', running: false, replayState: 'COMPLETE' })).toBe('Replay complete');
    expect(captureStateLabel({ mode: 'replay', running: false, replayState: 'FAILED' })).toBe('Replay failed');
    expect(captureStateLabel({ mode: 'replay', running: false, replayState: 'STOPPED' })).toBe('Replay stopped');
    expect(captureStateLabel({ mode: 'replay', running: true, replayState: 'RUNNING' })).toBe('Replaying');
  });
});
