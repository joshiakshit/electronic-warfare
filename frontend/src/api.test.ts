import { afterEach, describe, expect, it, vi } from 'vitest';
import { get, importRecording, send, subscribe } from './api';

afterEach(() => vi.unstubAllGlobals());
describe('local API client', () => {
  it('surfaces backend errors as readable messages', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'Wi-Fi capture unavailable' }), { status: 503 })));
    await expect(get('/api/spotter')).rejects.toThrow('Wi-Fi capture unavailable');
  });
  it('sends explicit JSON action requests', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ run: { state: 'SEARCHING' } }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    await send('/api/sniper', 'POST', { ssid: 'Lab' });
    expect(fetchMock).toHaveBeenCalledWith('/api/sniper', expect.objectContaining({ method: 'POST', body: '{"ssid":"Lab"}' }));
  });
  it('uploads a raw recording body with an encoded filename', async () => {
    const file = new File(['pcap'], 'My Recording & test.pcap');
    const entry = { id: 'recording-id', name: file.name, bytes: file.size, importedAt: 1 };
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(entry), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(importRecording(file)).resolves.toEqual(entry);
    expect(fetchMock).toHaveBeenCalledWith('/api/recordings?name=My+Recording+%26+test.pcap', {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/octet-stream' }, body: file,
    });
  });
});

it('sets the JSON media type for bodyless POST actions', async () => {
  const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
  await send('/api/capture/stop', 'POST');
  expect(fetchMock).toHaveBeenCalledWith('/api/capture/stop', expect.objectContaining({
    method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
  }));
});

it('refreshes on a sequence gap and accepts a new summary after reconnecting', () => {
  vi.useFakeTimers();
  const sockets: TestSocket[] = [];
  class TestSocket {
    onmessage?: (event: { data: string }) => void;
    onclose?: () => void;
    constructor() { sockets.push(this); }
    close() { this.onclose?.(); }
    emit(type: string, seq: number, sessionId: string | null) {
      this.onmessage?.({ data: JSON.stringify({
        type, seq, sessionId, timestamp: 1, payload: { modules: ['decloaker'] },
      }) });
    }
  }
  vi.stubGlobal('window', { setTimeout, clearTimeout });
  vi.stubGlobal('location', { protocol: 'http:', host: '127.0.0.1:7070' });
  vi.stubGlobal('WebSocket', TestSocket);
  const receive = vi.fn();
  const state = vi.fn();
  const stop = subscribe(receive, state);
  try {
    sockets[0].emit('summary', 1, null);
    sockets[0].emit('legacy', 2, null);
    sockets[0].emit('summary', 3, 'replay');
    sockets[0].emit('delta', 4, 'replay');
    sockets[0].emit('delta', 6, 'replay');
    sockets[0].emit('delta', 7, 'replay');

    expect(receive.mock.calls.map(([event]) => event.seq)).toEqual([1, 3, 4]);
    expect(state.mock.calls).toEqual([[true], [false]]);
    vi.advanceTimersByTime(2000);
    sockets[1].emit('summary', 1, 'replay');
    expect(state).toHaveBeenLastCalledWith(true);
    expect(receive).toHaveBeenLastCalledWith(expect.objectContaining({ type: 'summary', seq: 1 }));
    sockets[1].close();
    expect(state).toHaveBeenLastCalledWith(false);
  } finally {
    stop();
    vi.useRealTimers();
  }
});
