"""Tests for the candidate-based sparse period estimator (Objective 6)."""

from __future__ import annotations

import time

import numpy as np
import pytest

from ewscan.agents.period import estimate_period_candidates


# --- Test 1: exact periodic hits with sparse scans ---

class TestExactPeriodicHits:
    @pytest.mark.parametrize("period", [10, 20])
    def test_recovers_exact_period_at_sparse_scan_rate(self, period: int):
        rng = np.random.default_rng(period)
        n_slots = 2000
        scan_rate = 0.12
        scanned = rng.random(n_slots) < scan_rate
        slots = np.flatnonzero(scanned)
        detections = (slots % period) == 0
        result = estimate_period_candidates(slots, detections)
        assert result == period

    def test_period_8_dwell_1(self):
        rng = np.random.default_rng(0)
        n_slots = 1500
        slots = np.flatnonzero(rng.random(n_slots) < 0.15)
        detections = (slots % 8) == 0
        assert estimate_period_candidates(slots, detections) == 8

    @pytest.mark.parametrize("period", [35, 50])
    def test_low_evidence_returns_none(self, period: int):
        rng = np.random.default_rng(period)
        slots = np.flatnonzero(rng.random(2000) < 0.12)
        detections = (slots % period) == 0

        assert estimate_period_candidates(slots, detections) is None


# --- Test 2: jittered periodic hits ---

class TestJitteredHits:
    def test_jitter_1_still_recovers(self):
        rng = np.random.default_rng(42)
        period = 20
        n_slots = 2000
        slots = np.flatnonzero(rng.random(n_slots) < 0.15)

        truth_phase = np.zeros(n_slots, dtype=bool)
        for cycle_start in range(0, n_slots, period):
            on_slot = cycle_start + rng.integers(-1, 2)
            if 0 <= on_slot < n_slots:
                truth_phase[on_slot] = True

        detections = truth_phase[slots]
        result = estimate_period_candidates(slots, detections)
        assert result == period

    def test_dwell_3_with_jitter(self):
        rng = np.random.default_rng(10)
        period = 35
        dwell = 3
        n_slots = 2000
        slots = np.flatnonzero(rng.random(n_slots) < 0.15)

        truth = np.zeros(n_slots, dtype=bool)
        for cycle_start in range(0, n_slots, period):
            jitter = rng.integers(-1, 2)
            for d in range(dwell):
                s = cycle_start + jitter + d
                if 0 <= s < n_slots:
                    truth[s] = True

        detections = truth[slots]
        result = estimate_period_candidates(slots, detections)
        assert result == period


# --- Test 3: missing detections and false alarms ---

class TestNoisyDetections:
    def test_pd_80_percent_with_sparse_false_alarms_returns_none(self):
        rng = np.random.default_rng(77)
        period = 20
        n_slots = 2000
        pd, pfa = 0.80, 0.02
        slots = np.flatnonzero(rng.random(n_slots) < 0.15)
        truth_at_scan = (slots % period) == 0
        detections = np.where(
            truth_at_scan,
            rng.random(len(slots)) < pd,
            rng.random(len(slots)) < pfa,
        )
        result = estimate_period_candidates(slots, detections)
        assert result is None

    def test_high_pfa_still_recovers_with_enough_data(self):
        rng = np.random.default_rng(33)
        period = 20
        n_slots = 3000
        pd, pfa = 0.95, 0.05
        slots = np.flatnonzero(rng.random(n_slots) < 0.15)
        truth_at_scan = (slots % period) == 0
        detections = np.where(
            truth_at_scan,
            rng.random(len(slots)) < pd,
            rng.random(len(slots)) < pfa,
        )
        result = estimate_period_candidates(slots, detections)
        assert result == period


# --- Test 4: empty, CW, Markov, and random bands ---

class TestAperiodicBands:
    def test_empty_band_returns_none(self):
        slots = np.arange(0, 200, 5)
        detections = np.zeros(len(slots), dtype=bool)
        assert estimate_period_candidates(slots, detections) is None

    def test_always_on_cw_returns_none(self):
        slots = np.arange(0, 200, 5)
        detections = np.ones(len(slots), dtype=bool)
        assert estimate_period_candidates(slots, detections) is None

    def test_random_markov_returns_none(self):
        rng = np.random.default_rng(11)
        slots = np.flatnonzero(rng.random(2000) < 0.12)
        detections = rng.random(len(slots)) < 0.3
        assert estimate_period_candidates(slots, detections) is None

    def test_very_few_hits_returns_none(self):
        slots = np.arange(0, 100, 3)
        detections = np.zeros(len(slots), dtype=bool)
        detections[0] = True
        detections[5] = True
        assert estimate_period_candidates(slots, detections) is None


# --- Test 5: bounded runtime ---

class TestRuntime:
    @pytest.mark.parametrize("n_slots", [1000, 2000, 10000])
    def test_runtime_scales_near_linearly(self, n_slots: int):
        rng = np.random.default_rng(42)
        period = 50
        slots = np.flatnonzero(rng.random(n_slots) < 0.12)
        detections = (slots % period) == 0

        start = time.perf_counter()
        for _ in range(10):
            estimate_period_candidates(slots, detections)
        elapsed = time.perf_counter() - start

        per_call = elapsed / 10
        assert per_call < 0.05, f"Too slow at n_slots={n_slots}: {per_call:.4f}s"


# --- Test: prefers fundamental over harmonic ---

class TestHarmonics:
    def test_fundamental_preferred_over_double(self):
        rng = np.random.default_rng(20)
        period = 20
        dwell = 3
        n_slots = 2000
        slots = np.flatnonzero(rng.random(n_slots) < 0.10)
        detections = (slots % period) < dwell
        result = estimate_period_candidates(slots, detections)
        assert result == period


# --- Integration: replaces PeriodEstimator sparse path ---

class TestPeriodEstimatorIntegration:
    def test_period_estimator_uses_candidate_path(self):
        from ewscan.agents.period import PeriodEstimator

        rng = np.random.default_rng(5)
        period = 20
        n_slots = 2000
        estimator = PeriodEstimator(n_bands=1, capacity=n_slots, sparse=True)

        for slot in range(n_slots):
            if rng.random() < 0.12:
                det = (slot % period) == 0
                estimator.observe(0, slot, det)

        assert estimator.period(0) == period
