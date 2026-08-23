"""Tests for average intercept time error estimators -- Phase 1E.6.

Verification Criterion (PLAN.md 1E.6):
    Zero for the oracle, positive and finite otherwise.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.agents.baselines import OracleScheduler, RoundRobinScheduler, UniformRandomScheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.time_error import (
    BurstTimeError,
    EmitterTimeError,
    TimeErrorMetrics,
    estimate_average_time_error,
    estimate_per_emitter_time_error,
    estimate_time_error_metrics,
    extract_bursts,
)
from ewscan.testing.fixtures import ScriptedEnv, make_test_config, synthetic_log


# =========================================================================
# Helpers
# =========================================================================

def _make_log(
    n_bands: int,
    n_slots: int,
    truth: np.ndarray,
    actions: np.ndarray,
    detections: np.ndarray,
    emitters: tuple[EmitterInfo, ...] = (),
    pfa: float = 1e-3,
    detection_threshold: float = 3.0,
) -> EpisodeLog:
    """Convenience builder for custom test logs."""
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=emitters,
        detection_threshold=detection_threshold,
        pfa=pfa,
        seed=0,
    )
    return EpisodeLog(
        config=config,
        truth=truth.astype(np.bool_),
        actions=actions.astype(np.intp),
        detections=detections.astype(np.bool_),
    )


# =========================================================================
# 1. Burst Extraction Helper Tests
# =========================================================================

class TestExtractBursts:
    """Tests for the 1D burst interval extraction."""

    def test_empty_array(self):
        assert extract_bursts(np.array([], dtype=np.bool_)) == []

    def test_all_false(self):
        arr = np.zeros(10, dtype=np.bool_)
        assert extract_bursts(arr) == []

    def test_all_true(self):
        arr = np.ones(5, dtype=np.bool_)
        assert extract_bursts(arr) == [(0, 4)]

    def test_multiple_bursts(self):
        # Indices: 0 1 2 3 4 5 6 7 8 9
        # Values:  F T T F T F F T T T
        arr = np.array([False, True, True, False, True, False, False, True, True, True])
        assert extract_bursts(arr) == [(1, 2), (4, 4), (7, 9)]

    def test_single_slot_bursts(self):
        arr = np.array([True, False, True, False, True])
        assert extract_bursts(arr) == [(0, 0), (2, 2), (4, 4)]


# =========================================================================
# 2. Verification Criterion: Oracle vs Baselines
# =========================================================================

class TestVerificationCriterion:
    """Primary verification: Zero for the oracle, positive and finite otherwise."""

    def test_oracle_achieves_zero_time_error_on_nonoverlapping_bursts(self):
        """When bursts across bands do not collide, Oracle intercepts every burst
        at its exact start slot (time error = 0.0)."""
        n_bands = 3
        n_slots = 30
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)

        # Staggered bursts
        truth[0, 0:5] = True    # Band 0 burst at [0, 4]
        truth[1, 10:15] = True  # Band 1 burst at [10, 14]
        truth[2, 20:25] = True  # Band 2 burst at [20, 24]

        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
            EmitterInfo(band=1, snr=20.0, threat_level=1.0, emitter_type="burst"),
            EmitterInfo(band=2, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, emitters=emitters)

        oracle = OracleScheduler(truth=truth)
        env = ScriptedEnv(config, truth)
        log_oracle = env.run(oracle)

        metrics = estimate_time_error_metrics(log_oracle)
        assert metrics.n_bursts == 3
        assert metrics.n_intercepted_bursts == 3
        assert metrics.mean_time_error == 0.0
        assert metrics.burst_interception_ratio == 1.0

        for em in metrics.per_emitter:
            assert em.mean_time_error == 0.0
            assert em.burst_interception_ratio == 1.0
            for b in em.bursts:
                assert b.time_error == 0.0
                assert b.intercepted is True

    def test_round_robin_has_positive_finite_time_error(self):
        """Round-robin sweep incurs positive and finite time error on the same scenario."""
        n_bands = 3
        n_slots = 30
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)

        # Staggered bursts where RR will hit inside the window but not at slot 0
        truth[0, 1:5] = True    # Band 0 burst at [1, 4] -> RR scans band 0 at slot 0 (OFF), slot 3 (ON) -> error = 3-1 = 2
        truth[1, 9:15] = True   # Band 1 burst at [9, 14] -> RR scans band 1 at slot 10 -> error = 10-9 = 1
        truth[2, 21:26] = True  # Band 2 burst at [21, 25] -> RR scans band 2 at slot 23 -> error = 23-21 = 2

        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
            EmitterInfo(band=1, snr=20.0, threat_level=1.0, emitter_type="burst"),
            EmitterInfo(band=2, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, emitters=emitters)

        rr = RoundRobinScheduler()
        env = ScriptedEnv(config, truth)
        log_rr = env.run(rr)

        metrics = estimate_time_error_metrics(log_rr)
        assert metrics.n_bursts == 3
        assert metrics.n_intercepted_bursts == 3
        assert metrics.mean_time_error > 0.0
        assert math.isfinite(metrics.mean_time_error)
        assert metrics.mean_time_error == pytest.approx((2 + 1 + 2) / 3)

    def test_uniform_random_has_positive_finite_time_error(self):
        """Uniform random scanner has positive and finite time error."""
        n_bands = 4
        n_slots = 100
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, 0:20] = True
        truth[1, 25:45] = True
        truth[2, 50:70] = True

        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
            EmitterInfo(band=1, snr=20.0, threat_level=1.0, emitter_type="burst"),
            EmitterInfo(band=2, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, emitters=emitters, seed=42)

        rand_sched = UniformRandomScheduler(seed=42)
        env = ScriptedEnv(config, truth)
        log_rand = env.run(rand_sched)

        metrics = estimate_time_error_metrics(log_rand)
        assert metrics.n_bursts == 3
        assert metrics.n_intercepted_bursts > 0
        assert metrics.mean_time_error > 0.0
        assert math.isfinite(metrics.mean_time_error)


# =========================================================================
# 3. Hand-Computed Scenarios & Synthetic Log
# =========================================================================

class TestSyntheticLogTimeError:
    """Validate against known hand-computable properties from synthetic_log fixture.

    synthetic_log defaults (4 bands, 20 slots, RR actions):
      Band 0: CW (ON [0, 19]), scanned at {0, 4, 8, 12, 16} -> first hit at 0 -> error = 0 - 0 = 0.
      Band 1: bursty (ON [5, 9]), scanned at {1, 5, 9, 13, 17} -> first hit at 5 -> error = 5 - 5 = 0.
      Band 2: periodic (ON at {0, 3, 6, 9, 12, 15, 18}).
              7 single-slot bursts: [0,0], [3,3], [6,6], [9,9], [12,12], [15,15], [18,18].
              RR scans Band 2 at slots {2, 6, 10, 14, 18}.
              - Burst [0,0]: not scanned -> missed
              - Burst [3,3]: not scanned -> missed
              - Burst [6,6]: scanned at 6 -> hit at 6 -> error = 0
              - Burst [9,9]: not scanned -> missed
              - Burst [12,12]: not scanned -> missed
              - Burst [15,15]: not scanned -> missed
              - Burst [18,18]: scanned at 18 -> hit at 18 -> error = 0
    """

    def test_synthetic_log_time_error_values(self):
        log = synthetic_log(n_bands=4, n_slots=20)
        metrics = estimate_time_error_metrics(log)

        assert isinstance(metrics, TimeErrorMetrics)
        # Total bursts: 1 (band 0) + 1 (band 1) + 7 (band 2) = 9 bursts
        assert metrics.n_bursts == 9
        # Intercepted: band 0 (1), band 1 (1), band 2 (2) = 4 intercepted bursts
        assert metrics.n_intercepted_bursts == 4
        # All intercepted bursts happen to be intercepted at their start slot: (0+0+0+0)/4 = 0.0
        assert metrics.mean_time_error == 0.0
        assert metrics.burst_interception_ratio == pytest.approx(4 / 9)

        # Per emitter checks
        assert len(metrics.per_emitter) == 3
        # Emitter 0 (CW)
        assert metrics.per_emitter[0].n_bursts == 1
        assert metrics.per_emitter[0].n_intercepted_bursts == 1
        assert metrics.per_emitter[0].mean_time_error == 0.0

        # Emitter 1 (Bursty)
        assert metrics.per_emitter[1].n_bursts == 1
        assert metrics.per_emitter[1].n_intercepted_bursts == 1
        assert metrics.per_emitter[1].mean_time_error == 0.0

        # Emitter 2 (Periodic)
        assert metrics.per_emitter[2].n_bursts == 7
        assert metrics.per_emitter[2].n_intercepted_bursts == 2
        assert metrics.per_emitter[2].mean_time_error == 0.0
        assert metrics.per_emitter[2].burst_interception_ratio == pytest.approx(2 / 7)


class TestHandCraftedBurstError:
    """Hand-crafted test with nonzero errors on distinct bursts."""

    def test_known_burst_errors_and_penalties(self):
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        # 1 band, 10 slots.
        # Burst 1: [1, 3] (duration 3). Scanned at slot 2 -> error = 2 - 1 = 1.
        # Burst 2: [6, 8] (duration 3). Missed -> duration penalty = 3.
        truth = np.zeros((1, 10), dtype=np.bool_)
        truth[0, 1:4] = True
        truth[0, 6:9] = True

        actions = np.zeros(10, dtype=np.intp)
        # Hits only at slot 2
        detections = np.zeros(10, dtype=np.bool_)
        detections[2] = True

        log = _make_log(n_bands=1, n_slots=10, truth=truth, actions=actions,
                        detections=detections, emitters=emitters)

        metrics = estimate_time_error_metrics(log)
        assert metrics.n_bursts == 2
        assert metrics.n_intercepted_bursts == 1
        assert metrics.burst_interception_ratio == 0.5
        # Intercepted burst error
        assert metrics.mean_time_error == 1.0
        # Penalized mean error: (1 + 3) / 2 = 2.0
        assert metrics.mean_time_error_penalized == 2.0

        # Custom penalty
        metrics_custom_pen = estimate_time_error_metrics(log, miss_penalty=10.0)
        assert metrics_custom_pen.mean_time_error_penalized == pytest.approx((1 + 10.0) / 2)


# =========================================================================
# 4. False Alarms and Edge Cases
# =========================================================================

class TestFalseAlarmsAndEdgeCases:
    """Ensure false alarms on silent slots or bands do not count as burst intercepts."""

    def test_false_alarm_before_burst_does_not_count(self):
        """A false alarm at slot 0 when burst is [2, 4] must not register as an intercept."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        truth = np.zeros((1, 6), dtype=np.bool_)
        truth[0, 2:5] = True  # Burst at [2, 4]

        actions = np.zeros(6, dtype=np.intp)
        # False alarm at slot 0, true hit at slot 3
        detections = np.array([True, False, False, True, False, False])

        log = _make_log(n_bands=1, n_slots=6, truth=truth, actions=actions,
                        detections=detections, emitters=emitters)

        metrics = estimate_time_error_metrics(log)
        assert metrics.n_bursts == 1
        assert metrics.n_intercepted_bursts == 1
        # Intercept at slot 3 -> error = 3 - 2 = 1
        assert metrics.mean_time_error == 1.0
        assert metrics.bursts[0].intercept_slot == 3

    def test_zero_emitters_configured(self):
        truth = np.ones((2, 5), dtype=np.bool_)
        actions = np.zeros(5, dtype=np.intp)
        detections = np.ones(5, dtype=np.bool_)

        log = _make_log(n_bands=2, n_slots=5, truth=truth, actions=actions,
                        detections=detections, emitters=())

        metrics = estimate_time_error_metrics(log)
        assert metrics.n_bursts == 0
        assert metrics.n_intercepted_bursts == 0
        assert math.isnan(metrics.mean_time_error)
        assert math.isnan(metrics.mean_time_error_penalized)
        assert math.isnan(metrics.burst_interception_ratio)
        assert metrics.per_emitter == ()

    def test_no_bursts_in_episode(self):
        """All-silent episode returns NaNs."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        truth = np.zeros((1, 5), dtype=np.bool_)
        actions = np.zeros(5, dtype=np.intp)
        detections = np.zeros(5, dtype=np.bool_)

        log = _make_log(n_bands=1, n_slots=5, truth=truth, actions=actions,
                        detections=detections, emitters=emitters)

        metrics = estimate_time_error_metrics(log)
        assert metrics.n_bursts == 0
        assert math.isnan(metrics.mean_time_error)
        assert math.isnan(estimate_average_time_error(log))

    def test_zero_intercepted_bursts(self):
        """When bursts occur but none are intercepted, mean_time_error is NaN while penalized is finite."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="burst"),
        )
        truth = np.ones((1, 5), dtype=np.bool_)  # 1 burst [0, 4] (duration 5)
        actions = np.zeros(5, dtype=np.intp)
        detections = np.zeros(5, dtype=np.bool_)  # Sensor dead

        log = _make_log(n_bands=1, n_slots=5, truth=truth, actions=actions,
                        detections=detections, emitters=emitters)

        metrics = estimate_time_error_metrics(log)
        assert metrics.n_bursts == 1
        assert metrics.n_intercepted_bursts == 0
        assert math.isnan(metrics.mean_time_error)
        assert metrics.mean_time_error_penalized == 5.0
        assert metrics.burst_interception_ratio == 0.0
