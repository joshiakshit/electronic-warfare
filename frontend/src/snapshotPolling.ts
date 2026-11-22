export function startSnapshotPolling(load: (signal: AbortSignal) => Promise<void>, intervalMs: number) {
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
    } finally {
      running = false;
      if (!controller.signal.aborted) {
        timer = setTimeout(refresh, refreshQueued ? 0 : intervalMs);
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
