"""Tests for interception ratio and average intercept rate estimators -- Phase 1E.2.

Verify criterion (PLAN.md 1E.2):
    Oracle near ceiling, random near 1/N.
    Matches hand-computed values on scripted logs.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.agents.baselines import OracleScheduler, UniformRandomScheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.interception import (
    EmitterInterceptionEstimate,
    InterceptRateEstimate,
    InterceptionMetrics,
    InterceptionRatioEstimate,
    estimate_intercept_rate,
    estimate_interception_metrics,
    estimate_interception_ratio,
    estimate_per_emitter_interception,
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
# 1. Verification on Synthetic Log (Hand-computed Ground Truth)
# =========================================================================

class TestSyntheticLogInterception:
    """Validate against known hand-computed numbers from synthetic_log fixture."""

    def test_interception_ratio_on_synthetic_log(self):
        """synthetic_log has 32 active band-slots and 9 hits -> ratio = 9/32."""
        log = synthetic_log(n_bands=4, n_slots=20)
        res = estimate_interception_ratio(log)

        assert isinstance(res, InterceptionRatioEstimate)
        assert res.n_hits == 9
        assert res.n_transmissions == 32
        assert res.ratio == pytest.approx(9 / 32)

    def test_intercept_rate_on_synthetic_log(self):
        """synthetic_log has 20 slots and 9 hits -> rate = 9/20."""
        log = synthetic_log(n_bands=4, n_slots=20)
        res = estimate_intercept_rate(log)

        assert isinstance(res, InterceptRateEstimate)
        assert res.n_hits == 9
        assert res.n_slots == 20
        assert res.rate == pytest.approx(9 / 20)

    def test_per_emitter_on_synthetic_log(self):
        """Per-emitter hits and transmissions match known synthetic_log properties."""
        log = synthetic_log(n_bands=4, n_slots=20)
        per_emitter = estimate_per_emitter_interception(log)

        assert len(per_emitter) == 3

        # Emitter 0 (band 0, CW): 20 active slots, 5 hits (scanned at 0,4,8,12,16)
        assert per_emitter[0].emitter_index == 0
        assert per_emitter[0].band == 0
        assert per_emitter[0].n_transmissions == 20
        assert per_emitter[0].n_hits == 5
        assert per_emitter[0].interception_ratio == pytest.approx(5 / 20)

        # Emitter 1 (band 1, bursty slots 5..9): 5 active slots, 2 hits (scanned at 5,9)
        assert per_emitter[1].emitter_index == 1
        assert per_emitter[1].band == 1
        assert per_emitter[1].n_transmissions == 5
        assert per_emitter[1].n_hits == 2
        assert per_emitter[1].interception_ratio == pytest.approx(2 / 5)

        # Emitter 2 (band 2, periodic t%3==0): 7 active slots (0,3,6,9,12,15,18), 2 hits (6,18)
        assert per_emitter[2].emitter_index == 2
        assert per_emitter[2].band == 2
        assert per_emitter[2].n_transmissions == 7
        assert per_emitter[2].n_hits == 2
        assert per_emitter[2].interception_ratio == pytest.approx(2 / 7)

    def test_convenience_function(self):
        """estimate_interception_metrics bundles all estimators consistently."""
        log = synthetic_log(n_bands=4, n_slots=20)
        metrics = estimate_interception_metrics(log)

        assert isinstance(metrics, InterceptionMetrics)
        assert metrics.interception_ratio == estimate_interception_ratio(log)
        assert metrics.intercept_rate == estimate_intercept_rate(log)
        assert metrics.per_emitter == estimate_per_emitter_interception(log)


# =========================================================================
# 2. Plan Criterion: Oracle near ceiling, Random near 1/N
# =========================================================================

class TestOracleVsRandom:
    """Primary verification criterion from PLAN.md:
    Oracle near ceiling (~1.0), Random near 1/N.
    """

    def test_oracle_ceiling_and_random_one_over_n(self):
        """In a scenario where exactly 1 band is active in each slot across N bands:
        - Oracle achieves interception ratio = 1.0 (ceiling) and rate = 1.0.
        - UniformRandom achieves interception ratio ≈ 1/N and rate ≈ 1/N.
        """
        n_bands = 8
        n_slots = 10_000
        seed = 42

        # Create a single active emitter that switches bands or remains active
        # Let band 0 be ON for the first half, band 3 for the second half
        # (Exactly 1 active band per slot -> total transmissions = n_slots)
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        for t in range(n_slots):
            active_band = (t // 500) % n_bands
            truth[active_band, t] = True

        emitters = tuple(
            EmitterInfo(
                band=b, snr=20.0, threat_level=1.0, emitter_type="dynamic"
            )
            for b in range(n_bands)
        )
        cfg = EpisodeConfig(
            n_bands=n_bands,
            n_slots=n_slots,
            k=1,
            emitters=emitters,
            detection_threshold=3.0,
            pfa=1e-3,
            seed=seed,
        )

        env = ScriptedEnv(cfg, truth)

        # 1. Test Oracle Scheduler
        oracle = OracleScheduler(truth=truth)
        oracle_log = env.run(oracle)

        oracle_ratio = estimate_interception_ratio(oracle_log)
        oracle_rate = estimate_intercept_rate(oracle_log)

        # Oracle tracks the active band in every slot with perfect detection
        assert oracle_ratio.ratio == 1.0
        assert oracle_ratio.n_hits == n_slots
        assert oracle_rate.rate == 1.0

        # 2. Test Uniform Random Scheduler
        random_sched = UniformRandomScheduler(seed=seed)
        random_log = env.run(random_sched)

        random_ratio = estimate_interception_ratio(random_log)
        random_rate = estimate_intercept_rate(random_log)

        # Theoretical expectation is 1/N = 1/8 = 0.125
        expected_ratio = 1.0 / n_bands
        assert random_ratio.ratio == pytest.approx(expected_ratio, abs=0.015)
        assert random_rate.rate == pytest.approx(expected_ratio, abs=0.015)

        # Oracle decisively beats random
        assert oracle_ratio.ratio > random_ratio.ratio * 5


# =========================================================================
# 3. Robustness: False Alarms & Sensor Noise
# =========================================================================

class TestSensorNoiseAndFalseAlarms:
    """Ensure false alarms do not count as hits and sensor misses are handled."""

    def test_false_alarms_do_not_count_as_hits(self):
        """Detections on silent bands (false alarms) must NOT be counted as intercepts."""
        truth = np.zeros((2, 6), dtype=np.bool_)
        truth[0, 0:3] = True  # Band 0 ON for first 3 slots, OFF for last 3

        # Scanner scans band 1 (always silent)
        actions = np.array([1, 1, 1, 1, 1, 1])
        # Sensor fires false alarms on slots 1 and 4
        detections = np.array([False, True, False, False, True, False])

        log = _make_log(n_bands=2, n_slots=6, truth=truth,
                        actions=actions, detections=detections)

        ratio = estimate_interception_ratio(log)
        rate = estimate_intercept_rate(log)

        assert ratio.n_hits == 0
        assert ratio.ratio == 0.0
        assert ratio.n_transmissions == 3
        assert rate.n_hits == 0
        assert rate.rate == 0.0

    def test_missed_detections_reduce_hits(self):
        """Scanned ON band without detection is a missed opportunity, not a hit."""
        truth = np.array([[True, True, True, True]])
        actions = np.array([0, 0, 0, 0])
        # Only 1 detection out of 4 scans of active band
        detections = np.array([True, False, False, False])

        log = _make_log(n_bands=1, n_slots=4, truth=truth,
                        actions=actions, detections=detections)

        ratio = estimate_interception_ratio(log)
        assert ratio.n_hits == 1
        assert ratio.n_transmissions == 4
        assert ratio.ratio == 0.25


# =========================================================================
# 4. Edge Cases & Boundary Conditions
# =========================================================================

class TestEdgeCases:
    """Boundary conditions and corner cases."""

    def test_all_silent_environment(self):
        """When no transmissions occur in truth, ratio is NaN and rate is 0.0."""
        truth = np.zeros((3, 10), dtype=np.bool_)
        actions = np.array([t % 3 for t in range(10)])
        detections = np.zeros(10, dtype=np.bool_)

        log = _make_log(n_bands=3, n_slots=10, truth=truth,
                        actions=actions, detections=detections)

        ratio = estimate_interception_ratio(log)
        rate = estimate_intercept_rate(log)

        assert math.isnan(ratio.ratio)
        assert ratio.n_hits == 0
        assert ratio.n_transmissions == 0
        assert rate.rate == 0.0
        assert rate.n_hits == 0
        assert rate.n_slots == 10

    def test_empty_log_zero_slots(self):
        """Log with n_slots=0 returns NaNs cleanly."""
        truth = np.zeros((2, 0), dtype=np.bool_)
        actions = np.array([], dtype=np.intp)
        detections = np.array([], dtype=np.bool_)

        log = _make_log(n_bands=2, n_slots=0, truth=truth,
                        actions=actions, detections=detections)

        ratio = estimate_interception_ratio(log)
        rate = estimate_intercept_rate(log)
        per_emitter = estimate_per_emitter_interception(log)

        assert math.isnan(ratio.ratio)
        assert math.isnan(rate.rate)
        assert ratio.n_hits == 0
        assert rate.n_slots == 0
        assert per_emitter == ()

    def test_emitter_never_transmits(self):
        """Emitter configured on a band that stays silent has NaN interception ratio."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=10.0, threat_level=0.5, emitter_type="silent"),
        )
        truth = np.array([
            [True, True, True],
            [False, False, False],
        ])
        actions = np.array([0, 1, 0])
        detections = np.array([True, False, True])

        log = _make_log(n_bands=2, n_slots=3, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        per_emitter = estimate_per_emitter_interception(log)
        assert len(per_emitter) == 2

        assert per_emitter[0].n_hits == 2
        assert per_emitter[0].n_transmissions == 3
        assert per_emitter[0].interception_ratio == pytest.approx(2 / 3)

        assert math.isnan(per_emitter[1].interception_ratio)
        assert per_emitter[1].n_hits == 0
        assert per_emitter[1].n_transmissions == 0
