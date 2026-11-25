import type { CaptureHealth, CaptureStatus } from './api';

export function activeRoute(pathname: string): string {
  return pathname.split('/').filter(Boolean).at(-1) || 'overview';
}
export function modulePath(category: string, tab?: string): string {
  return `/${tab ? `${category}/${tab}` : category}`;
}
export function rememberedTab(category: string, requested: string, tabs: string[], stored: string | null): string {
  if (tabs.includes(requested)) return requested;
  if (stored && tabs.includes(stored)) return stored;
  return tabs[0];
}
export function sessionSummary(status?: Pick<CaptureStatus, 'wifi'> | null, health?: Partial<CaptureHealth> | null) {
  const wifi = status?.wifi ?? {};
  const mode = health?.mode || wifi.captureMode || 'idle';
  const running = health?.running ?? wifi.captureRunning ?? false;
  const radio = running && mode !== 'replay' ? health?.radio : null;
  const frame = { channel: health?.observedChannel, frequencyMhz: health?.observedFrequencyMhz };
  const receiverReading = radio?.channel || radio?.frequencyMhz ? radio : null;
  const frameReading = frame.channel || frame.frequencyMhz ? frame : null;
  const reading = receiverReading ?? frameReading ?? { channel: wifi.channel, frequencyMhz: null };
  return {
    mode,
    source: health?.source || wifi.captureSource || wifi.captureInterface || 'No active adapter or recording',
    channel: reading.channel || null,
    frequency: reading.frequencyMhz || null,
    channelLabel: receiverReading ? 'Receiver' : frameReading ? 'Last frame' : null,
    selectedAp: wifi.preferredApId || null,
    running,
    replayState: health?.replayState || wifi.replayState || null,
  };
}

export function channelReading(channel?: number | null, frequency?: number | null): string {
  const parts = [channel ? `CH ${channel}` : null, frequency ? `${frequency} MHz` : null];
  return parts.filter(Boolean).join(' · ');
}
export function captureStateLabel(session: { mode: string; running: boolean; replayState?: string | null }) {
  if (session.mode === 'replay') {
    switch (session.replayState?.toLowerCase()) {
      case 'complete':
      case 'completed': return 'Replay complete';
      case 'failed': return 'Replay failed';
      case 'stopped': return 'Replay stopped';
      default: return session.running ? 'Replaying' : 'Replay';
    }
  }
  if (session.mode === 'idle') return 'No active capture';
  return session.running ? 'Live capture' : 'Capture stopped';
}
export function sniperStartRequest(ssid: string, available: boolean): { ssid: string } | null {
  return available && ssid && new TextEncoder().encode(ssid).length <= 32 ? { ssid } : null;
}

export function readTab(category: string): string | null {
  try { return localStorage.getItem(`ewave.tab.${category}`); }
  catch { return null; }
}

export function rememberTab(category: string, tab: string): void {
  try { localStorage.setItem(`ewave.tab.${category}`, tab); }
  catch { /* Navigation still works when browser storage is unavailable. */ }
}
