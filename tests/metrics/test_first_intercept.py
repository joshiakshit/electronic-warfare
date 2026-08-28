"""Tests for time to first intercept estimators -- Phase 1E.3.

Verify criterion (PLAN.md 1E.3):
    Matches a hand-computed value on a scripted log.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.first_intercept import (
    EmitterFirstIntercept,
    FirstInterceptMetrics,
    estimate_first_intercept_metrics,
    estimate_per_emitter_first_intercept,
)
from ewscan.testing.fixtures import synthetic_log


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
    detection_threshold: float | None = None,
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
# 1. Verification on Synthetic Log
# =========================================================================

class TestSyntheticLogFirstIntercept:
    """Validate against known hand-computed numbers from synthetic_log fixture.

    synthetic_log defaults:
      Band 0 (CW): scanned at 0 -> detected at slot 0 (first intercept = 0)
      Band 1 (bursty 5..9): scanned at 1 (OFF), 5 (ON) -> detected at slot 5 (first intercept = 5)
      Band 2 (periodic t%3==0): scanned at 2 (OFF), 6 (ON) -> detected at slot 6 (first intercept = 6)
      Mean TTFI = (0 + 5 + 6) / 3 = 11/3 ≈ 3.6667
    """

    def test_per_emitter_first_intercept_on_synthetic_log(self):
        log = synthetic_log(n_bands=4, n_slots=20)
        per_emitter = estimate_per_emitter_first_intercept(log)

        assert len(per_emitter) == 3

        # Emitter 0: band 0, first intercepted at slot 0
        assert per_emitter[0].emitter_index == 0
        assert per_emitter[0].band == 0
        assert per_emitter[0].first_intercept_slot == 0
        assert per_emitter[0].intercepted is True

        # Emitter 1: band 1, first intercepted at slot 5
        assert per_emitter[1].emitter_index == 1
        assert per_emitter[1].band == 1
        assert per_emitter[1].first_intercept_slot == 5
        assert per_emitter[1].intercepted is True

        # Emitter 2: band 2, first intercepted at slot 6
        assert per_emitter[2].emitter_index == 2
        assert per_emitter[2].band == 2
        assert per_emitter[2].first_intercept_slot == 6
        assert per_emitter[2].intercepted is True

    def test_first_intercept_metrics_on_synthetic_log(self):
        log = synthetic_log(n_bands=4, n_slots=20)
        metrics = estimate_first_intercept_metrics(log)

        assert isinstance(metrics, FirstInterceptMetrics)
        assert metrics.n_emitters == 3
        assert metrics.n_intercepted == 3
        assert metrics.mean_time_to_first_intercept == pytest.approx(11 / 3)
        assert metrics.per_emitter == estimate_per_emitter_first_intercept(log)


# =========================================================================
# 2. Hand-Crafted Timing Scenarios
# =========================================================================

class TestHandCraftedTimings:
    """Explicitly test multi-emitter scenarios with known first-intercept slots."""

    def test_unintercepted_emitter_handled(self):
        """Unintercepted emitters have first_intercept_slot=None and do not corrupt mean TTFI."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=15.0, threat_level=0.8, emitter_type="cw"),
            EmitterInfo(band=2, snr=10.0, threat_level=0.5, emitter_type="cw"),
        )
        # 3 bands, 6 slots
        # Band 0: ON slots 0..5
        # Band 1: ON slots 3..5
        # Band 2: always OFF
        truth = np.zeros((3, 6), dtype=np.bool_)
        truth[0, :] = True
        truth[1, 3:] = True

        # Scanner sequence: 0, 2, 0, 1, 2, 1
        # Slot 0: scan 0 (ON) -> detection True => Band 0 intercepted at t=0
        # Slot 1: scan 2 (OFF) -> detection False
        # Slot 2: scan 0 (ON) -> detection True
        # Slot 3: scan 1 (ON) -> detection True => Band 1 intercepted at t=3
        # Slot 4: scan 2 (OFF) -> detection False
        # Slot 5: scan 1 (ON) -> detection True
        actions = np.array([0, 2, 0, 1, 2, 1])
        detections = np.array([True, False, True, True, False, True])

        log = _make_log(n_bands=3, n_slots=6, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        metrics = estimate_first_intercept_metrics(log)

        assert metrics.n_emitters == 3
        assert metrics.n_intercepted == 2
        assert metrics.per_emitter[0].first_intercept_slot == 0
        assert metrics.per_emitter[0].intercepted is True
        assert metrics.per_emitter[1].first_intercept_slot == 3
        assert metrics.per_emitter[1].intercepted is True
        assert metrics.per_emitter[2].first_intercept_slot is None
        assert metrics.per_emitter[2].intercepted is False

        # Mean TTFI over the 2 intercepted emitters: (0 + 3) / 2 = 1.5
        assert metrics.mean_time_to_first_intercept == pytest.approx(1.5)

    def test_false_alarm_does_not_trigger_first_intercept(self):
        """A false alarm on an emitter's band when it is silent must NOT register as first intercept."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
        )
        # Band 0 is OFF for slots 0..3, ON for slots 4..7
        truth = np.zeros((1, 8), dtype=np.bool_)
        truth[0, 4:] = True

        # Scanner always scans band 0
        actions = np.zeros(8, dtype=np.intp)

        # Sensor has a false alarm at slot 1 (band is OFF)
        # Sensor detects at slot 4 (band is ON)
        detections = np.array([False, True, False, False, True, True, False, False])

        log = _make_log(n_bands=1, n_slots=8, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        res = estimate_per_emitter_first_intercept(log)
        assert len(res) == 1
        # Slot 1 was a false alarm -> first genuine intercept is slot 4
        assert res[0].first_intercept_slot == 4
        assert res[0].intercepted is True

    def test_miss_before_hit_delays_first_intercept(self):
        """A missed detection when scanning an active emitter delays the recorded first intercept."""
        emitters = (
            EmitterInfo(band=0, snr=10.0, threat_level=1.0, emitter_type="cw"),
        )
        truth = np.ones((1, 5), dtype=np.bool_)
        actions = np.zeros(5, dtype=np.intp)

        # Slot 0: Missed (False)
        # Slot 1: Missed (False)
        # Slot 2: Hit (True)
        detections = np.array([False, False, True, True, False])

        log = _make_log(n_bands=1, n_slots=5, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        res = estimate_per_emitter_first_intercept(log)
        assert res[0].first_intercept_slot == 2
        assert res[0].intercepted is True


# =========================================================================
# 3. Edge Cases & Boundary Conditions
# =========================================================================

class TestEdgeCases:
    """Boundary conditions for first intercept metrics."""

    def test_no_emitters_configured(self):
        """Empty emitter list returns empty per_emitter and NaN mean TTFI."""
        truth = np.ones((2, 5), dtype=np.bool_)
        actions = np.zeros(5, dtype=np.intp)
        detections = np.ones(5, dtype=np.bool_)

        log = _make_log(n_bands=2, n_slots=5, truth=truth,
                        actions=actions, detections=detections, emitters=())

        metrics = estimate_first_intercept_metrics(log)
        assert metrics.n_emitters == 0
        assert metrics.n_intercepted == 0
        assert math.isnan(metrics.mean_time_to_first_intercept)
        assert metrics.per_emitter == ()

    def test_zero_emitters_intercepted(self):
        """When no emitter is intercepted, mean TTFI is NaN."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=1.0, emitter_type="cw"),
        )
        truth = np.ones((2, 5), dtype=np.bool_)
        actions = np.array([0, 0, 0, 0, 0])
        # Sensor completely dead (no detections)
        detections = np.zeros(5, dtype=np.bool_)

        log = _make_log(n_bands=2, n_slots=5, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        metrics = estimate_first_intercept_metrics(log)
        assert metrics.n_emitters == 2
        assert metrics.n_intercepted == 0
        assert math.isnan(metrics.mean_time_to_first_intercept)
        assert metrics.per_emitter[0].first_intercept_slot is None
        assert metrics.per_emitter[1].first_intercept_slot is None

    def test_zero_slots_episode_is_rejected(self):
        """Episode configuration requires a positive slot count."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
        )
        truth = np.zeros((1, 0), dtype=np.bool_)
        actions = np.array([], dtype=np.intp)
        detections = np.array([], dtype=np.bool_)

        with pytest.raises(ValueError, match="n_slots"):
            _make_log(n_bands=1, n_slots=0, truth=truth,
                      actions=actions, detections=detections, emitters=emitters)
