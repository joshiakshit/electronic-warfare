import { afterEach, describe, expect, it, vi } from 'vitest';
import { get, importRecording, send } from './api';

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
