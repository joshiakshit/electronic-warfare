"""Period estimation from detection history.

Two estimators:

- ``estimate_period``: dense autocorrelation (original).
- ``estimate_period_candidates``: bounded candidate set from hit-gap
  divisors with likelihood-ratio scoring, minimum-evidence gate, and
  holdout confirmation.  Near-linear runtime.

``PeriodEstimator`` wraps a hit-history ring buffer and dispatches to
the appropriate function.
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
        return estimate_period_candidates(slots, detections, min_hits=min_hits)

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


# ---- Candidate-based sparse period estimator (Objective 6) ----

def _hit_gap_candidates(hit_slots: NDArray[np.intp], max_period: int) -> set[int]:
    """Generate candidate periods from positive-hit gap divisors."""
    counts: dict[int, int] = {}

    def add(period: int) -> None:
        if 2 <= period <= max_period:
            counts[period] = counts.get(period, 0) + 1

    n = len(hit_slots)
    if n < 2:
        return set()

    # Use gaps between all pairs within a window to keep O(n * window)
    window = min(n, 30)
    for i in range(n):
        for j in range(i + 1, min(i + window, n)):
            gap = int(hit_slots[j] - hit_slots[i])
            if gap < 2:
                continue
            if gap <= max_period:
                add(gap)
            for divisor in range(2, math.isqrt(gap) + 1):
                if gap % divisor != 0:
                    continue
                quotient = gap // divisor
                add(divisor)
                add(quotient)

    ranked = sorted(counts, key=counts.__getitem__, reverse=True)[:48]
    candidates = set(ranked)
    for period in ranked[:12]:
        candidates.update(
            period + offset
            for offset in (-2, -1, 1, 2)
            if 2 <= period + offset <= max_period
        )
    return candidates


def _phase_likelihood(
    scan_slots: NDArray[np.intp],
    detections: NDArray[np.bool_],
    period: int,
) -> float:
    """Return the phase-folded Beta-Binomial log marginal likelihood."""
    phases = scan_slots % period
    obs_per_phase = np.bincount(phases, minlength=period)
    hit_per_phase = np.bincount(phases[detections], minlength=period)

    alpha = 1.0
    beta = 10.0
    prior = math.lgamma(alpha) + math.lgamma(beta) - math.lgamma(alpha + beta)
    score = 0.0
    for obs, hits in zip(obs_per_phase, hit_per_phase):
        if obs == 0:
            continue
        score += (
            math.lgamma(alpha + hits)
            + math.lgamma(beta + obs - hits)
            - math.lgamma(alpha + beta + obs)
            - prior
        )
    return score


def _aperiodic_likelihood(
    scan_slots: NDArray[np.intp],
    detections: NDArray[np.bool_],
) -> float:
    """Return the period-one aperiodic model likelihood."""
    return _phase_likelihood(scan_slots, detections, period=1)


def estimate_period_candidates(
    slots: NDArray[np.intp],
    detections: NDArray[np.bool_],
    min_hits: int = 6,
    min_margin: float = 3.0,
    min_concentration: float = 0.5,
    holdout_fraction: float = 0.3,
    max_period: int = 200,
) -> int | None:
    """Estimate period from sparse scans using bounded candidate set.

    1. Generate candidates from hit-gap divisors.
    2. Score each candidate with Beta-Binomial likelihood vs aperiodic.
    3. Gate on minimum evidence and likelihood margin.
    4. Confirm best candidate on holdout observations.
    """
    slots = np.asarray(slots, dtype=np.intp)
    detections = np.asarray(detections, dtype=np.bool_)

    n_hits = int(detections.sum())
    if n_hits < min_hits or len(slots) < 10:
        return None

    span = int(slots[-1] - slots[0]) + 1
    effective_max = min(max_period, span // 3)
    if effective_max < 2:
        return None

    # CW or nearly-always-on: no periodicity to find
    hit_rate = n_hits / len(slots)
    if hit_rate > 0.8:
        return None

    n_fit = max(1, int(len(slots) * (1.0 - holdout_fraction)))
    fit_slots = slots[:n_fit]
    fit_dets = detections[:n_fit]
    holdout_slots = slots[n_fit:]
    holdout_dets = detections[n_fit:]

    n_fit_hits = int(fit_dets.sum())
    if n_fit_hits < 3:
        return None

    candidates = _hit_gap_candidates(
        fit_slots[fit_dets] - int(fit_slots[0]), effective_max
    )
    if not candidates:
        return None

    null_score = _aperiodic_likelihood(fit_slots, fit_dets)

    best_period = None
    best_margin = float("-inf")
    second_margin = float("-inf")

    for period in sorted(candidates):
        if period < 2 or period > effective_max:
            continue
        score = _phase_likelihood(fit_slots, fit_dets, period)
        margin = score - null_score
        if margin > best_margin:
            second_margin = best_margin
            best_period = period
            best_margin = margin
        elif margin > second_margin:
            second_margin = margin

    if (
        best_period is None
        or best_margin < min_margin
        or best_margin - second_margin < min_concentration
    ):
        return None

    # A holdout with no hits cannot confirm or reject the candidate yet.
    if len(holdout_slots) >= 5:
        holdout_hits = int(holdout_dets.sum())
        if holdout_hits and (
            _phase_likelihood(holdout_slots, holdout_dets, best_period)
            - _aperiodic_likelihood(holdout_slots, holdout_dets)
            < 0.0
        ):
            return None

    return best_period


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
        self._observations = np.zeros(n_bands, dtype=np.int64)
        self._last_evidence = np.zeros(n_bands, dtype=np.int64)
        self._evidence_milestone = 16

    def observe(self, band: int, slot: int, detection: bool) -> None:
        self._history.append(band, slot, detection)
        self._observations[band] += 1
        if not self._sparse or detection or (
            self._observations[band] - self._last_evidence[band]
            >= self._evidence_milestone
        ):
            self._dirty[band] = True

    def period(self, band: int) -> int | None:
        if not self._dirty[band]:
            return self._cached_periods[band]
        slots, detections = self._history.recent(band)
        if int(detections.sum()) < self._min_hits:
            self._cached_periods[band] = None
            self._dirty[band] = False
            self._last_evidence[band] = self._observations[band]
            return None
        if self._sparse:
            period = estimate_period_candidates(
                slots, detections, min_hits=self._min_hits,
            )
        else:
            period = estimate_period(
                slots, detections, rho=self._rho, min_hits=self._min_hits,
            )
        self._cached_periods[band] = period
        self._dirty[band] = False
        self._last_evidence[band] = self._observations[band]
        return period
