"""Tests for Pd, Pfa, and sensitivity estimators -- Phase 1E.1.

Verify criterion: estimated Pd matches the ROC parameter that generated the run.

Test strategy:
  1. Hand-built logs with perfect sensor (Pd=1, Pfa=0) → exact counts.
  2. Hand-built logs with known false alarms → exact Pfa.
  3. Monte Carlo convergence: run a long episode through the real detection
     model and verify that estimated Pd and Pfa approach the analytic values
     from the ROC equations within statistical tolerance.
  4. Edge cases: all-silent, all-transmitting, no scans of a given type.
  5. Sensitivity: multi-emitter scenario where weak emitters fall below the
     Pd threshold.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.env.detection import pd_from_snr, threshold_from_pfa
from ewscan.metrics.detection import (
    DetectionMetrics,
    PdEstimate,
    PfaEstimate,
    SensitivityEstimate,
    estimate_detection_metrics,
    estimate_pd,
    estimate_per_emitter_pd,
    estimate_pfa,
    estimate_sensitivity,
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
    """Convenience builder for hand-crafted episode logs."""
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
# 1. Hand-built: perfect sensor (Pd=1, Pfa=0)
# =========================================================================

class TestPerfectSensor:
    """Tests with a perfect sensor: detection iff transmitting AND scanned."""

    def test_pd_on_synthetic_log(self):
        """Pd=1.0 when the sensor is perfect and some transmitting bands are scanned."""
        log = synthetic_log()  # perfect sensor, round-robin
        pd_est = estimate_pd(log)
        # Every time the scanner looked at a transmitting band, it detected it
        assert pd_est.pd == 1.0
        assert pd_est.n_hits == pd_est.n_scans_on
        assert pd_est.n_scans_on > 0

    def test_pfa_on_synthetic_log(self):
        """Pfa=0 when the sensor is perfect."""
        log = synthetic_log()
        pfa_est = estimate_pfa(log)
        assert pfa_est.pfa == 0.0
        assert pfa_est.n_false_alarms == 0
        assert pfa_est.n_scans_off > 0

    def test_counts_match_hand_computed(self):
        """Verify hit and scan counts against the known synthetic_log properties."""
        log = synthetic_log(n_bands=4, n_slots=20)
        pd_est = estimate_pd(log)
        # From synthetic_log docstring: 9 hits, 32 active band-slots
        # But n_scans_on counts only the *scanned* transmitting slots,
        # not total transmitting band-slots.
        # Round-robin visits each band 5 times (20/4=5).
        # Band 0 is ON all 20 slots, scanned at {0,4,8,12,16} → 5 hits
        # Band 1 is ON at slots 5..9, scanned at {5,9} → 2 hits
        # Band 2 is ON at {0,3,6,9,12,15,18}, scanned at {6,18} → 2 hits
        # Band 3 always OFF, scanned at {3,7,11,15,19} → 0 hits
        assert pd_est.n_hits == 9
        assert pd_est.n_scans_on == 9  # perfect sensor: every scan of ON band detects
        assert pd_est.pd == 1.0

    def test_pfa_counts_hand_computed(self):
        """All scans of silent bands produce no detection with a perfect sensor."""
        log = synthetic_log(n_bands=4, n_slots=20)
        pfa_est = estimate_pfa(log)
        # 20 total scans - 9 scans on transmitting bands = 11 scans of silent bands
        assert pfa_est.n_scans_off == 11
        assert pfa_est.n_false_alarms == 0


class TestPerEmitterPd:
    """Per-emitter Pd on perfect-sensor logs."""

    def test_per_emitter_matches_aggregate(self):
        """Sum of per-emitter hits equals aggregate hits."""
        log = synthetic_log()
        pd_est = estimate_pd(log)
        per_emitter = estimate_per_emitter_pd(log)
        total_hits = sum(ep.n_hits for ep in per_emitter)
        # Per-emitter hits can exceed aggregate if emitters share a band,
        # but in the default scenario they don't.
        assert total_hits == pd_est.n_hits

    def test_per_emitter_pd_all_one(self):
        """With a perfect sensor, every emitter that was scanned has Pd=1."""
        log = synthetic_log()
        per_emitter = estimate_per_emitter_pd(log)
        for ep in per_emitter:
            if ep.n_scans_on > 0:
                assert ep.pd == 1.0, f"Emitter {ep.emitter_index} has Pd={ep.pd}"

    def test_emitter_band_and_snr_match_config(self):
        """Per-emitter results carry the correct band and SNR from config."""
        log = synthetic_log()
        per_emitter = estimate_per_emitter_pd(log)
        for idx, ep in enumerate(per_emitter):
            info = log.config.emitters[idx]
            assert ep.band == info.band
            assert ep.snr == info.snr
            assert ep.emitter_index == idx


# =========================================================================
# 2. Hand-built: known false alarms
# =========================================================================

class TestFalseAlarms:
    """Tests where we inject false alarms explicitly."""

    def test_pfa_with_injected_false_alarms(self):
        """Two false alarms on 5 scans of silent bands → Pfa = 0.4."""
        # 2 bands, 5 slots. Band 0 always ON, band 1 always OFF.
        truth = np.array([
            [True, True, True, True, True],
            [False, False, False, False, False],
        ])
        # Scanner always looks at band 1 (silent)
        actions = np.array([1, 1, 1, 1, 1])
        # Two false alarms at slots 1 and 3
        detections = np.array([False, True, False, True, False])
        log = _make_log(n_bands=2, n_slots=5, truth=truth,
                        actions=actions, detections=detections)

        pfa_est = estimate_pfa(log)
        assert pfa_est.n_scans_off == 5
        assert pfa_est.n_false_alarms == 2
        assert pfa_est.pfa == pytest.approx(0.4)

    def test_pd_zero_when_scanner_misses_all(self):
        """Pd=0 when the scanner looks at transmitting bands but never detects."""
        truth = np.array([[True, True, True, True]])
        actions = np.array([0, 0, 0, 0])
        detections = np.array([False, False, False, False])
        log = _make_log(n_bands=1, n_slots=4, truth=truth,
                        actions=actions, detections=detections)
        pd_est = estimate_pd(log)
        assert pd_est.pd == 0.0
        assert pd_est.n_scans_on == 4
        assert pd_est.n_hits == 0


# =========================================================================
# 3. Edge cases
# =========================================================================

class TestEdgeCases:
    """Boundary and degenerate scenarios."""

    def test_pd_nan_when_no_transmitting_scans(self):
        """Pd is NaN when the scanner never hits a transmitting band."""
        truth = np.array([
            [True, True],
            [False, False],
        ])
        # Scanner always on band 1 (silent)
        actions = np.array([1, 1])
        detections = np.array([False, False])
        log = _make_log(n_bands=2, n_slots=2, truth=truth,
                        actions=actions, detections=detections)
        pd_est = estimate_pd(log)
        assert math.isnan(pd_est.pd)
        assert pd_est.n_scans_on == 0

    def test_pfa_nan_when_all_scans_on_transmitting(self):
        """Pfa is NaN when the scanner always sees a transmitting band."""
        truth = np.array([[True, True, True]])
        actions = np.array([0, 0, 0])
        detections = np.array([True, True, True])
        log = _make_log(n_bands=1, n_slots=3, truth=truth,
                        actions=actions, detections=detections)
        pfa_est = estimate_pfa(log)
        assert math.isnan(pfa_est.pfa)
        assert pfa_est.n_scans_off == 0

    def test_per_emitter_pd_nan_when_never_scanned(self):
        """Per-emitter Pd is NaN for an emitter whose band is never scanned."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=10.0, threat_level=0.5, emitter_type="cw"),
        )
        truth = np.array([
            [True, True, True],
            [True, True, True],
        ])
        actions = np.array([0, 0, 0])  # never scan band 1
        detections = np.array([True, True, True])
        log = _make_log(n_bands=2, n_slots=3, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        per_emitter = estimate_per_emitter_pd(log)
        assert len(per_emitter) == 2
        assert per_emitter[0].pd == 1.0  # band 0, always scanned and detected
        assert math.isnan(per_emitter[1].pd)  # band 1, never scanned
        assert per_emitter[1].n_scans_on == 0

    def test_no_emitters_gives_empty_per_emitter(self):
        """Per-emitter Pd returns empty tuple when config has no emitters."""
        truth = np.array([[False, False, False]])
        actions = np.array([0, 0, 0])
        detections = np.array([False, False, False])
        log = _make_log(n_bands=1, n_slots=3, truth=truth,
                        actions=actions, detections=detections, emitters=())
        per_emitter = estimate_per_emitter_pd(log)
        assert per_emitter == ()


# =========================================================================
# 4. Sensitivity
# =========================================================================

class TestSensitivity:
    """Sensitivity estimator tests."""

    def test_sensitivity_picks_weakest_detectable(self):
        """Sensitivity is the lowest SNR where estimated Pd ≥ threshold."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=10.0, threat_level=0.5, emitter_type="cw"),
            EmitterInfo(band=2, snr=5.0, threat_level=0.3, emitter_type="cw"),
        )
        # All bands ON, scanner cycles 0→1→2, perfect sensor
        truth = np.ones((3, 9), dtype=np.bool_)
        actions = np.array([0, 1, 2, 0, 1, 2, 0, 1, 2])
        detections = np.ones(9, dtype=np.bool_)  # perfect sensor
        log = _make_log(n_bands=3, n_slots=9, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        sens = estimate_sensitivity(log, pd_threshold=0.5)
        # All emitters have Pd=1 ≥ 0.5, so min detectable SNR = 5.0
        assert sens.min_detectable_snr == 5.0

    def test_sensitivity_inf_when_no_emitter_meets_threshold(self):
        """Sensitivity is +inf when no emitter's Pd reaches the threshold."""
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
        )
        truth = np.ones((1, 4), dtype=np.bool_)
        actions = np.array([0, 0, 0, 0])
        detections = np.array([False, False, False, False])  # sensor dead
        log = _make_log(n_bands=1, n_slots=4, truth=truth,
                        actions=actions, detections=detections, emitters=emitters)

        sens = estimate_sensitivity(log, pd_threshold=0.5)
        assert sens.min_detectable_snr == float("inf")

    def test_sensitivity_nan_when_no_emitters(self):
        """Sensitivity is NaN when no emitters exist."""
        truth = np.zeros((2, 4), dtype=np.bool_)
        actions = np.array([0, 1, 0, 1])
        detections = np.array([False, False, False, False])
        log = _make_log(n_bands=2, n_slots=4, truth=truth,
                        actions=actions, detections=detections, emitters=())
        sens = estimate_sensitivity(log, pd_threshold=0.5)
        assert math.isnan(sens.min_detectable_snr)

    def test_sensitivity_invalid_threshold(self):
        """pd_threshold outside (0, 1] raises ValueError."""
        log = synthetic_log()
        with pytest.raises(ValueError, match="pd_threshold"):
            estimate_sensitivity(log, pd_threshold=0.0)
        with pytest.raises(ValueError, match="pd_threshold"):
            estimate_sensitivity(log, pd_threshold=1.5)


# =========================================================================
# 5. Combined convenience function
# =========================================================================

class TestDetectionMetrics:
    """Test the all-in-one estimate_detection_metrics."""

    def test_returns_all_fields(self):
        log = synthetic_log()
        dm = estimate_detection_metrics(log)
        assert isinstance(dm, DetectionMetrics)
        assert isinstance(dm.pd, PdEstimate)
        assert isinstance(dm.pfa, PfaEstimate)
        assert isinstance(dm.per_emitter_pd, tuple)
        assert isinstance(dm.sensitivity, SensitivityEstimate)

    def test_consistent_with_individual_calls(self):
        log = synthetic_log()
        dm = estimate_detection_metrics(log, pd_threshold=0.3)
        assert dm.pd == estimate_pd(log)
        assert dm.pfa == estimate_pfa(log)
        assert dm.per_emitter_pd == estimate_per_emitter_pd(log)
        assert dm.sensitivity == estimate_sensitivity(log, pd_threshold=0.3)


# =========================================================================
# 6. Monte Carlo convergence: estimated Pd ≈ analytic Pd
# =========================================================================

class TestMonteCarloConvergence:
    """Run a long episode through the real detection model and verify that
    estimated Pd and Pfa converge to the ROC-predicted values.

    This is the primary verification criterion from the plan:
    'Estimated Pd matches the ROC parameter that generated the run.'
    """

    @pytest.fixture
    def long_episode_params(self):
        """Parameters for the Monte Carlo test."""
        return {
            "n_bands": 4,
            "n_slots": 50_000,
            "pfa": 0.05,
            "snr_db": 10.0,
            "seed": 42,
        }

    def test_estimated_pd_matches_analytic(self, long_episode_params):
        """Estimated Pd converges to the analytic Pd from the ROC equation.

        We create a scenario with one CW emitter (always ON) and have the
        scanner always look at that band.  Over 50k slots, the estimated Pd
        should be very close to pd_from_snr(snr_db, threshold).
        """
        p = long_episode_params
        threshold = threshold_from_pfa(p["pfa"])
        analytic_pd = pd_from_snr(p["snr_db"], threshold)

        # Build the truth: band 0 always ON, others always OFF
        truth = np.zeros((p["n_bands"], p["n_slots"]), dtype=np.bool_)
        truth[0, :] = True

        # Scanner always on band 0
        actions = np.zeros(p["n_slots"], dtype=np.intp)

        # Generate detections using the ROC model
        rng = np.random.default_rng(p["seed"])
        snr_lin = 10.0 ** (p["snr_db"] / 10.0)
        pd_true = np.exp(-threshold / (1.0 + snr_lin))
        detections = rng.random(p["n_slots"]) < pd_true

        emitters = (
            EmitterInfo(
                band=0, snr=p["snr_db"], threat_level=1.0, emitter_type="cw"
            ),
        )
        log = _make_log(
            n_bands=p["n_bands"],
            n_slots=p["n_slots"],
            truth=truth,
            actions=actions,
            detections=detections,
            emitters=emitters,
            pfa=p["pfa"],
            detection_threshold=threshold,
        )

        pd_est = estimate_pd(log)
        # At 50k samples, 4σ of a Bernoulli with p≈0.96 is about 0.004
        assert pd_est.pd == pytest.approx(analytic_pd, abs=0.01), (
            f"Estimated Pd={pd_est.pd:.4f} vs analytic Pd={analytic_pd:.4f}"
        )

    def test_estimated_pfa_matches_analytic(self, long_episode_params):
        """Estimated Pfa converges to the analytic Pfa.

        Scanner always on band 1 (silent).  Detections drawn from the
        false-alarm probability.
        """
        p = long_episode_params
        threshold = threshold_from_pfa(p["pfa"])
        analytic_pfa = np.exp(-threshold)  # should equal p["pfa"]

        truth = np.zeros((p["n_bands"], p["n_slots"]), dtype=np.bool_)
        # Band 0 is ON but never scanned; band 1 is OFF and always scanned
        truth[0, :] = True

        actions = np.ones(p["n_slots"], dtype=np.intp)  # always band 1

        rng = np.random.default_rng(p["seed"])
        detections = rng.random(p["n_slots"]) < analytic_pfa

        log = _make_log(
            n_bands=p["n_bands"],
            n_slots=p["n_slots"],
            truth=truth,
            actions=actions,
            detections=detections,
            pfa=p["pfa"],
            detection_threshold=threshold,
        )

        pfa_est = estimate_pfa(log)
        # At 50k samples, 4σ of Bernoulli p=0.05 ≈ 0.004
        assert pfa_est.pfa == pytest.approx(analytic_pfa, abs=0.01), (
            f"Estimated Pfa={pfa_est.pfa:.4f} vs analytic Pfa={analytic_pfa:.4f}"
        )

    def test_per_emitter_pd_matches_roc_per_snr(self):
        """Each emitter's estimated Pd converges to its own ROC Pd.

        Two emitters at different SNRs.  Scanner alternates between them.
        Each emitter's Pd should match its own pd_from_snr.
        """
        n_slots = 60_000
        pfa = 0.01
        threshold = threshold_from_pfa(pfa)
        snrs = [15.0, 6.0]
        analytic_pds = [pd_from_snr(snr, threshold) for snr in snrs]

        truth = np.zeros((2, n_slots), dtype=np.bool_)
        truth[0, :] = True  # both bands always ON
        truth[1, :] = True

        # Alternate scanning: even slots → band 0, odd → band 1
        actions = np.array([t % 2 for t in range(n_slots)], dtype=np.intp)

        rng = np.random.default_rng(99)
        detections = np.zeros(n_slots, dtype=np.bool_)
        for t in range(n_slots):
            band = actions[t]
            pd_true = analytic_pds[band]
            detections[t] = rng.random() < pd_true

        emitters = tuple(
            EmitterInfo(band=b, snr=snrs[b], threat_level=1.0, emitter_type="cw")
            for b in range(2)
        )
        log = _make_log(
            n_bands=2, n_slots=n_slots, truth=truth, actions=actions,
            detections=detections, emitters=emitters, pfa=pfa,
            detection_threshold=threshold,
        )

        per_emitter = estimate_per_emitter_pd(log)
        for idx, ep in enumerate(per_emitter):
            assert ep.pd == pytest.approx(analytic_pds[idx], abs=0.015), (
                f"Emitter {idx} (SNR={snrs[idx]} dB): "
                f"estimated Pd={ep.pd:.4f} vs analytic={analytic_pds[idx]:.4f}"
            )

    def test_sensitivity_distinguishes_weak_from_strong(self):
        """Sensitivity correctly identifies the weakest detectable emitter
        in a multi-SNR scenario with Monte Carlo detections."""
        n_slots = 30_000
        pfa = 0.01
        threshold = threshold_from_pfa(pfa)
        # Three emitters: strong (20 dB), medium (8 dB), weak (2 dB)
        snrs = [20.0, 8.0, 2.0]
        analytic_pds = [pd_from_snr(snr, threshold) for snr in snrs]

        truth = np.ones((3, n_slots), dtype=np.bool_)
        actions = np.array([t % 3 for t in range(n_slots)], dtype=np.intp)

        rng = np.random.default_rng(77)
        detections = np.zeros(n_slots, dtype=np.bool_)
        for t in range(n_slots):
            band = actions[t]
            detections[t] = rng.random() < analytic_pds[band]

        emitters = tuple(
            EmitterInfo(band=b, snr=snrs[b], threat_level=1.0, emitter_type="cw")
            for b in range(3)
        )
        log = _make_log(
            n_bands=3, n_slots=n_slots, truth=truth, actions=actions,
            detections=detections, emitters=emitters, pfa=pfa,
            detection_threshold=threshold,
        )

        # With pd_threshold=0.5:
        # SNR 20 dB → Pd ≈ 0.999 ✓
        # SNR  8 dB → Pd ≈ 0.64  ✓
        # SNR  2 dB → Pd ≈ 0.22  ✗ (below 0.5)
        sens = estimate_sensitivity(log, pd_threshold=0.5)
        # Minimum detectable is 8.0 dB (weak emitter doesn't pass)
        assert sens.min_detectable_snr == 8.0, (
            f"Expected min_detectable_snr=8.0, got {sens.min_detectable_snr}"
        )
