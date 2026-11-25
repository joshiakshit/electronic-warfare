export function startSnapshotPolling(load: (signal: AbortSignal) => Promise<void>, intervalMs: number | (() => number)) {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let running = false;
  let refreshQueued = false;

  async function refresh() {
    if (controller.signal.aborted) return;
    if (running) {
      refreshQueued = true;
      return;
    }

    clearTimeout(timer);
    running = true;
    try {
      await load(controller.signal);
    } catch {
      // The caller owns error presentation. Keep polling after a failed refresh.
    } finally {
      running = false;
      if (!controller.signal.aborted) {
        const interval = typeof intervalMs === 'number' ? intervalMs : intervalMs();
        timer = setTimeout(refresh, refreshQueued ? 0 : interval);
        refreshQueued = false;
      }
    }
  }

  void refresh();
  return {
    refresh,
    stop() {
      controller.abort();
      clearTimeout(timer);
    },
  };
}
