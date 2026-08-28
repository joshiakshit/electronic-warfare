"""Period estimation from hit history via autocorrelation (Sprint 3, Task 5).

Recovers a periodic emitter's period per band by autocorrelating the observed
detection series. Feeds the next-transmission predictor.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.history import HitHistory


def estimate_period(
    slots: NDArray[np.intp],
    detections: NDArray[np.bool_],
    rho: float = 0.3,
    min_hits: int = 8,
) -> int | None:
    slots = np.asarray(slots, dtype=np.intp)
    detections = np.asarray(detections, dtype=np.bool_)

    if int(detections.sum()) < min_hits or len(slots) == 0:
        return None

    min_slot = int(slots.min())
    max_slot = int(slots.max())
    n = max_slot - min_slot + 1
    if n < 4:
        return None

    # Dense reindex: slots are only the scanned ones and are non-contiguous,
    # so the packed detections array cannot be autocorrelated directly.
    x = np.zeros(n, dtype=np.float64)
    x[slots[detections] - min_slot] = 1.0

    centered = x - x.mean()
    full = np.correlate(centered, centered, mode="full")
    r = full[n - 1 :]

    threshold = rho * r[0]
    max_lag = n // 2
    for lag in range(1, max_lag + 1):
        if r[lag] <= threshold:
            continue
        if lag - 1 >= 0 and r[lag] < r[lag - 1]:
            continue
        if lag + 1 < len(r) and r[lag] < r[lag + 1]:
            continue
        return lag

    return None


class PeriodEstimator:
    """Per-band period estimator wrapping a hit-history ring buffer."""

    def __init__(self, n_bands: int, capacity: int, rho: float = 0.3, min_hits: int = 8) -> None:
        self._history = HitHistory(n_bands, capacity)
        self._rho = rho
        self._min_hits = min_hits

    def observe(self, band: int, slot: int, detection: bool) -> None:
        self._history.append(band, slot, detection)

    def period(self, band: int) -> int | None:
        slots, detections = self._history.recent(band)
        return estimate_period(slots, detections, rho=self._rho, min_hits=self._min_hits)
