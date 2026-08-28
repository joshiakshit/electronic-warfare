"""Period estimation from hit history via autocorrelation (Sprint 3, Task 5).

Recovers a periodic emitter's period per band by autocorrelating the observed
detection series. Feeds the next-transmission predictor.
"""

from __future__ import annotations

import math

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.history import HitHistory


def estimate_period(
    slots: NDArray[np.intp],
    detections: NDArray[np.bool_],
    rho: float = 0.3,
    min_hits: int = 8,
    sparse: bool = False,
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

    if sparse:
        return _estimate_period_sparse(
            slots, detections, n, min_slot
        )

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


def _estimate_period_sparse(
    slots: NDArray[np.intp],
    detections: NDArray[np.bool_],
    n: int,
    min_slot: int,
) -> int | None:
    relative_slots = slots - min_slot
    hit_slots = relative_slots[detections]
    null_score = _phase_score(relative_slots, hit_slots, 1)
    best_period = None
    best_score = null_score

    for period in range(2, n // 2 + 1):
        score = _phase_score(relative_slots, hit_slots, period)
        if score > best_score:
            best_period = period
            best_score = score

    return best_period


def _phase_score(
    slots: NDArray[np.intp], hit_slots: NDArray[np.intp], period: int
) -> float:
    observations = np.bincount(slots % period, minlength=period)
    hits = np.bincount(hit_slots % period, minlength=period)
    alpha = 1.0
    beta = 10.0
    prior = math.lgamma(alpha) + math.lgamma(beta) - math.lgamma(alpha + beta)

    return float(
        sum(
            math.lgamma(alpha + hit)
            + math.lgamma(beta + observation - hit)
            - math.lgamma(alpha + beta + observation)
            - prior
            for observation, hit in zip(observations, hits)
        )
    )


class PeriodEstimator:
    """Per-band period estimator wrapping a hit-history ring buffer."""

    def __init__(
        self,
        n_bands: int,
        capacity: int,
        rho: float = 0.3,
        min_hits: int = 8,
        sparse: bool = False,
    ) -> None:
        self._history = HitHistory(n_bands, capacity)
        self._rho = rho
        self._min_hits = min_hits
        self._sparse = sparse
        self._cached_periods: list[int | None] = [None] * n_bands
        self._dirty = np.ones(n_bands, dtype=np.bool_)

    def observe(self, band: int, slot: int, detection: bool) -> None:
        self._history.append(band, slot, detection)
        self._dirty[band] = True

    def period(self, band: int) -> int | None:
        if not self._dirty[band]:
            return self._cached_periods[band]
        slots, detections = self._history.recent(band)
        period = estimate_period(
            slots, detections, rho=self._rho, min_hits=self._min_hits, sparse=self._sparse
        )
        self._cached_periods[band] = period
        self._dirty[band] = False
        return period
