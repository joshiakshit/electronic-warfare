"""Tests for period estimation via hit-history autocorrelation (Sprint 3, Task 5)."""

from __future__ import annotations

import numpy as np

from ewscan.agents.period import PeriodEstimator, estimate_period
from ewscan.env.emitters import PeriodicEmitter


def test_clean_period_returns_exact_value():
    slots = np.arange(0, 71)
    detections = slots % 10 == 0

    assert estimate_period(slots, detections) == 10


def test_jitter_within_one_slot_still_recovers_period():
    rng = np.random.default_rng(12345)
    emitter = PeriodicEmitter(band=0, period=10, dwell=3, jitter=1, phase=0)
    emitter.reset(rng)

    n_slots = 150
    slots = np.arange(n_slots)
    detections = np.array([emitter.step() for _ in range(n_slots)], dtype=bool)

    assert estimate_period(slots, detections) == 10


def test_dropout_still_recovers_period():
    rng = np.random.default_rng(12345)
    slots = np.arange(0, 161)
    hit_slots = np.arange(0, 161, 10)
    kept = rng.random(len(hit_slots)) >= 0.3
    detections = np.zeros(len(slots), dtype=bool)
    detections[hit_slots[kept]] = True

    assert estimate_period(slots, detections) == 10


def test_aperiodic_series_returns_none():
    rng = np.random.default_rng(12345)
    slots = np.arange(60)
    detections = rng.random(60) < 0.3

    assert estimate_period(slots, detections) is None


def test_insufficient_hits_returns_none():
    slots = np.arange(40)
    detections = np.zeros(40, dtype=bool)
    detections[[0, 10, 20]] = True

    assert estimate_period(slots, detections) is None


def test_period_estimator_observe_end_to_end_on_periodic_emitter():
    rng = np.random.default_rng(12345)
    emitter = PeriodicEmitter(band=0, period=10, dwell=1, jitter=0, phase=0)
    emitter.reset(rng)

    estimator = PeriodEstimator(n_bands=1, capacity=100)
    for slot in range(100):
        is_on = emitter.step()
        estimator.observe(0, slot, is_on)

    assert estimator.period(0) == 10


def test_first_qualifying_peak_wins_over_stronger_harmonic():
    # Global-max autocorrelation sits at lag 20 (2P); the first qualifying
    # local max is at lag 10 (P). Taking argmax instead of the first peak
    # would wrongly report 20.
    rng = np.random.default_rng(0)
    period = 10
    n_pulses = 20
    n_slots = n_pulses * period + 21
    pulse_slots = np.arange(0, n_pulses * period, period)
    kept = rng.random(len(pulse_slots)) < 0.6

    slots = np.arange(n_slots)
    detections = np.zeros(n_slots, dtype=bool)
    detections[pulse_slots[kept]] = True

    assert estimate_period(slots, detections) == 10


def test_irregular_scan_gaps_still_recover_true_period():
    # history.recent returns only scanned slots, which are non-contiguous.
    # Autocorrelating the packed array (skipping the dense reindex) loses
    # the lag axis and fails to recover the period.
    rng = np.random.default_rng(0)
    period = 10
    scanned_slots = []
    detections = []
    for slot in range(201):
        if rng.random() < 0.5:
            scanned_slots.append(slot)
            detections.append(slot % period == 0)

    slots = np.array(scanned_slots, dtype=np.intp)
    detections = np.array(detections, dtype=bool)

    assert estimate_period(slots, detections) == 10


def _sparse_observations(
    period: int, dwell: int, scan_rate: float, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    slots = np.flatnonzero(rng.random(2000) < scan_rate)
    return slots, (slots % period) < dwell


def test_sparse_period_20_recovers_at_twelve_percent_scan_rate():
    slots, detections = _sparse_observations(20, 1, 0.12, seed=5)

    assert estimate_period(slots, detections, sparse=True) == 20


def test_sparse_periods_recover_across_radar_scan_rates():
    recovered = 0
    for scan_rate in (0.10, 0.15, 0.20):
        for period, dwell in ((20, 3), (35, 4), (50, 5)):
            slots, detections = _sparse_observations(period, dwell, scan_rate, seed=period)
            recovered += estimate_period(slots, detections, sparse=True) == period

    assert recovered >= 7


def test_sparse_period_prefers_fundamental_over_harmonic():
    slots, detections = _sparse_observations(20, 3, 0.10, seed=20)

    assert estimate_period(slots, detections, sparse=True) == 20


def test_sparse_aperiodic_series_returns_none():
    rng = np.random.default_rng(99)
    slots = np.flatnonzero(rng.random(2000) < 0.12)
    detections = rng.random(len(slots)) < 0.15

    assert estimate_period(slots, detections, sparse=True) is None
