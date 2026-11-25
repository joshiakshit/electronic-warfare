import { afterEach, describe, expect, it, vi } from 'vitest';
import { startSnapshotPolling } from './snapshotPolling';

afterEach(() => vi.useRealTimers());

describe('snapshot polling', () => {
  it('lets a slow request finish during a burst and fetches one follow-up', async () => {
    vi.useFakeTimers();
    let finish!: () => void;
    const firstResponse = new Promise<void>(resolve => { finish = resolve; });
    const load = vi.fn<(signal: AbortSignal) => Promise<void>>()
      .mockReturnValueOnce(firstResponse).mockResolvedValue(undefined);
    const poll = startSnapshotPolling(load, 4000);

    for (let event = 0; event < 5; event++) {
      await vi.advanceTimersByTimeAsync(1000);
      await poll.refresh();
    }
    expect(load).toHaveBeenCalledTimes(1);
    expect(load.mock.calls[0][0].aborted).toBe(false);

    finish();
    await vi.advanceTimersByTimeAsync(1);
    expect(load).toHaveBeenCalledTimes(2);
    poll.stop();
  });

  it('resumes polling after a rejected request and adjusts its repair interval', async () => {
    vi.useFakeTimers();
    let connected = true;
    const load = vi.fn<(signal: AbortSignal) => Promise<void>>().mockRejectedValueOnce(new Error('Offline'))
      .mockResolvedValue(undefined);
    const poll = startSnapshotPolling(load, () => connected ? 15000 : 4000);
    await vi.advanceTimersByTimeAsync(15000);
    expect(load).toHaveBeenCalledTimes(2);
    connected = false;
    await poll.refresh();
    await vi.advanceTimersByTimeAsync(4000);
    expect(load).toHaveBeenCalledTimes(4);
    poll.stop();
  });

  it('polls without events and cancels pending work when stopped', async () => {
    vi.useFakeTimers();
    let finish!: () => void;
    const secondResponse = new Promise<void>(resolve => { finish = resolve; });
    const load = vi.fn<(signal: AbortSignal) => Promise<void>>()
      .mockResolvedValueOnce(undefined).mockReturnValueOnce(secondResponse);
    const poll = startSnapshotPolling(load, 4000);

    await vi.advanceTimersByTimeAsync(4000);
    expect(load).toHaveBeenCalledTimes(2);
    await poll.refresh();
    poll.stop();
    expect(load.mock.calls[1][0].aborted).toBe(true);

    finish();
    await vi.advanceTimersByTimeAsync(8000);
    expect(load).toHaveBeenCalledTimes(2);
  });
});
