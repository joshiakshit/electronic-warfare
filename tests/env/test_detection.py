"""Unit tests for the square-law detection model -- Phase 1B.4.

Verify criterion from PLAN.md:
  "Pd curve matches the analytic ROC within Monte Carlo error."

Tests cover:
  1. Analytic ROC equations: threshold ↔ Pfa round-trip, Pd monotonicity.
  2. Monte Carlo Pd matches analytic Pd within statistical tolerance.
  3. Monte Carlo Pfa matches analytic Pfa within statistical tolerance.
  4. DetectionModel class: reset/detect lifecycle, determinism, batch mode.
  5. Edge cases: very high SNR → Pd ≈ 1, very low SNR → Pd ≈ Pfa, SNR=0.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.env.detection import (
    DetectionModel,
    pd_from_snr,
    pfa_from_threshold,
    roc_curve,
    snr_for_target_pd,
    threshold_from_pfa,
)


# -----------------------------------------------------------------------
# Pure ROC equation tests
# -----------------------------------------------------------------------

class TestThresholdPfaRoundTrip:
    """threshold_from_pfa and pfa_from_threshold are exact inverses."""

    @pytest.mark.parametrize("pfa", [1e-1, 1e-3, 1e-6, 0.5, 0.99])
    def test_round_trip(self, pfa: float) -> None:
        threshold = threshold_from_pfa(pfa)
        recovered = pfa_from_threshold(threshold)
        assert abs(recovered - pfa) < 1e-12

    def test_threshold_positive(self) -> None:
        for pfa in [0.01, 0.001, 1e-6]:
            assert threshold_from_pfa(pfa) > 0.0

    def test_invalid_pfa_raises(self) -> None:
        with pytest.raises(ValueError, match="pfa"):
            threshold_from_pfa(0.0)
        with pytest.raises(ValueError, match="pfa"):
            threshold_from_pfa(1.0)
        with pytest.raises(ValueError, match="pfa"):
            threshold_from_pfa(-0.1)


class TestPdFromSnr:
    """Pd equation: exp(-λ / (1 + SNR_lin))."""

    def test_pd_at_zero_snr_equals_pfa(self) -> None:
        """SNR = 0 (linear 1) → Pd = exp(-λ/2), strictly between Pfa and 1."""
        pfa = 1e-3
        threshold = threshold_from_pfa(pfa)
        pd = pd_from_snr(0.0, threshold)
        # Pd at 0 dB should be higher than Pfa but less than 1
        assert pd > pfa
        assert pd < 1.0
        # Check exact: exp(-threshold / 2)
        expected = float(np.exp(-threshold / 2.0))
        assert abs(pd - expected) < 1e-12

    def test_pd_increases_with_snr(self) -> None:
        """Higher SNR → higher Pd at fixed threshold."""
        threshold = threshold_from_pfa(1e-3)
        snrs = [-10, -5, 0, 5, 10, 15, 20, 30]
        pds = [pd_from_snr(s, threshold) for s in snrs]
        for i in range(len(pds) - 1):
            assert pds[i] < pds[i + 1], f"Pd not monotonic at {snrs[i]}→{snrs[i+1]} dB"

    def test_pd_decreases_with_threshold(self) -> None:
        """Higher threshold → lower Pd at fixed SNR."""
        snr = 10.0
        thresholds = [0.5, 1.0, 3.0, 5.0, 10.0]
        pds = [pd_from_snr(snr, t) for t in thresholds]
        for i in range(len(pds) - 1):
            assert pds[i] > pds[i + 1], f"Pd not decreasing with threshold"

    def test_high_snr_pd_near_one(self) -> None:
        """At very high SNR, Pd → 1."""
        threshold = threshold_from_pfa(1e-3)
        pd = pd_from_snr(40.0, threshold)  # 40 dB
        assert pd > 0.999

    def test_very_low_snr_pd_near_pfa(self) -> None:
        """At very low SNR, Pd → Pfa."""
        pfa = 1e-3
        threshold = threshold_from_pfa(pfa)
        pd = pd_from_snr(-30.0, threshold)  # -30 dB
        assert abs(pd - pfa) < 0.01  # close to Pfa

    def test_known_value(self) -> None:
        """Check a specific hand-computed value.

        Pfa = 1e-3 → λ = -ln(1e-3) ≈ 6.9078
        SNR = 10 dB → SNR_lin = 10
        Pd = exp(-6.9078 / 11) ≈ exp(-0.6280) ≈ 0.5337
        """
        pfa = 1e-3
        threshold = threshold_from_pfa(pfa)
        pd = pd_from_snr(10.0, threshold)
        expected = float(np.exp(-threshold / 11.0))
        assert abs(pd - expected) < 1e-10


class TestSnrForTargetPd:
    """Inversion: given target Pd and threshold, what SNR is needed?"""

    @pytest.mark.parametrize("target_pd", [0.5, 0.9, 0.99])
    def test_round_trip(self, target_pd: float) -> None:
        threshold = threshold_from_pfa(1e-3)
        snr_db = snr_for_target_pd(target_pd, threshold)
        recovered_pd = pd_from_snr(snr_db, threshold)
        assert abs(recovered_pd - target_pd) < 1e-6

    def test_invalid_inputs(self) -> None:
        with pytest.raises(ValueError, match="target_pd"):
            snr_for_target_pd(0.0, 5.0)
        with pytest.raises(ValueError, match="target_pd"):
            snr_for_target_pd(1.0, 5.0)
        with pytest.raises(ValueError, match="threshold"):
            snr_for_target_pd(0.9, 0.0)


class TestRocCurve:
    """roc_curve produces a valid ROC with correct monotonicity."""

    def test_shape(self) -> None:
        pfa_arr, pd_arr = roc_curve(10.0, n_points=100)
        assert pfa_arr.shape == (100,)
        assert pd_arr.shape == (100,)

    def test_pd_ge_pfa(self) -> None:
        """For any non-negative SNR, Pd >= Pfa at every operating point."""
        pfa_arr, pd_arr = roc_curve(5.0)
        assert np.all(pd_arr >= pfa_arr - 1e-15)  # small tolerance for float

    def test_negative_snr_pd_still_above_random(self) -> None:
        """Even at negative SNR, Pd > Pfa (the signal always helps)."""
        pfa_arr, pd_arr = roc_curve(-3.0)
        assert np.all(pd_arr >= pfa_arr - 1e-15)

    def test_zero_snr_curve(self) -> None:
        """At 0 dB (SNR_lin = 1), Pd = Pfa^(1/2)."""
        pfa_arr, pd_arr = roc_curve(0.0, n_points=50)
        expected_pd = np.sqrt(pfa_arr)
        np.testing.assert_allclose(pd_arr, expected_pd, atol=1e-10)


# -----------------------------------------------------------------------
# Monte Carlo verification — the core PLAN.md verify criterion
# -----------------------------------------------------------------------

class TestMonteCarloMatchesAnalytic:
    """Pd curve matches the analytic ROC within Monte Carlo error."""

    N_TRIALS = 100_000

    @pytest.mark.parametrize("snr_db", [5.0, 10.0, 15.0, 20.0])
    def test_pd_monte_carlo(self, snr_db: float) -> None:
        """Draw N_TRIALS detections and compare empirical Pd to analytic."""
        pfa = 1e-3
        threshold = threshold_from_pfa(pfa)
        analytic_pd = pd_from_snr(snr_db, threshold)

        dm = DetectionModel(pfa=pfa)
        rng = np.random.default_rng(42)
        dm.reset(rng)

        hits = sum(dm.detect(snr_db, transmitting=True) for _ in range(self.N_TRIALS))
        empirical_pd = hits / self.N_TRIALS

        # 4-sigma tolerance for binomial: σ = sqrt(p*(1-p)/N)
        sigma = np.sqrt(analytic_pd * (1 - analytic_pd) / self.N_TRIALS)
        tol = max(4 * sigma, 0.005)  # floor at 0.5%
        assert abs(empirical_pd - analytic_pd) < tol, (
            f"SNR={snr_db} dB: empirical Pd={empirical_pd:.4f} vs "
            f"analytic Pd={analytic_pd:.4f}, tol={tol:.4f}"
        )

    def test_pfa_monte_carlo(self) -> None:
        """False alarm rate matches Pfa when no signal is present."""
        pfa = 1e-2  # use a higher Pfa so we get enough events in 100k trials
        threshold = threshold_from_pfa(pfa)

        dm = DetectionModel(pfa=pfa)
        rng = np.random.default_rng(99)
        dm.reset(rng)

        false_alarms = sum(
            dm.detect(0.0, transmitting=False) for _ in range(self.N_TRIALS)
        )
        empirical_pfa = false_alarms / self.N_TRIALS

        sigma = np.sqrt(pfa * (1 - pfa) / self.N_TRIALS)
        tol = max(4 * sigma, 0.002)
        assert abs(empirical_pfa - pfa) < tol, (
            f"Empirical Pfa={empirical_pfa:.4f} vs analytic Pfa={pfa:.4f}"
        )

    def test_pfa_low_rate_monte_carlo(self) -> None:
        """Even at the default low Pfa=1e-3, the rate is correct."""
        pfa = 1e-3
        n_trials = 500_000  # need more samples for rare events
        dm = DetectionModel(pfa=pfa)
        rng = np.random.default_rng(77)
        dm.reset(rng)

        false_alarms = sum(
            dm.detect(0.0, transmitting=False) for _ in range(n_trials)
        )
        empirical_pfa = false_alarms / n_trials

        sigma = np.sqrt(pfa * (1 - pfa) / n_trials)
        tol = max(4 * sigma, 0.0005)
        assert abs(empirical_pfa - pfa) < tol, (
            f"Low Pfa: empirical={empirical_pfa:.6f} vs analytic={pfa:.6f}"
        )

    def test_full_roc_curve_monte_carlo(self) -> None:
        """Sweep SNR values and verify the full Pd curve shape.

        This is the primary PLAN.md 1B.4 verify: the Pd curve matches
        the analytic ROC within Monte Carlo error.
        """
        pfa = 1e-3
        threshold = threshold_from_pfa(pfa)
        n_per_point = 50_000

        snr_values = [-5.0, 0.0, 5.0, 10.0, 15.0, 20.0]
        rng = np.random.default_rng(2024)

        for snr_db in snr_values:
            analytic_pd = pd_from_snr(snr_db, threshold)
            dm = DetectionModel(pfa=pfa)
            dm.reset(rng)

            hits = sum(
                dm.detect(snr_db, transmitting=True) for _ in range(n_per_point)
            )
            empirical_pd = hits / n_per_point

            sigma = np.sqrt(analytic_pd * (1 - analytic_pd) / n_per_point)
            tol = max(4 * sigma, 0.005)
            assert abs(empirical_pd - analytic_pd) < tol, (
                f"ROC curve mismatch at SNR={snr_db} dB: "
                f"empirical Pd={empirical_pd:.4f} vs analytic={analytic_pd:.4f}"
            )


# -----------------------------------------------------------------------
# DetectionModel lifecycle and semantics
# -----------------------------------------------------------------------

class TestDetectionModel:
    def test_unreset_raises(self) -> None:
        dm = DetectionModel(pfa=1e-3)
        with pytest.raises(RuntimeError, match="must be reset"):
            dm.detect(10.0, transmitting=True)

    def test_unreset_batch_raises(self) -> None:
        dm = DetectionModel(pfa=1e-3)
        with pytest.raises(RuntimeError, match="must be reset"):
            dm.detect_batch(np.array([10.0]), np.array([True]))

    def test_invalid_pfa_raises(self) -> None:
        with pytest.raises(ValueError, match="pfa"):
            DetectionModel(pfa=0.0)
        with pytest.raises(ValueError, match="pfa"):
            DetectionModel(pfa=1.0)

    def test_get_pd(self) -> None:
        pfa = 1e-3
        dm = DetectionModel(pfa=pfa)
        threshold = threshold_from_pfa(pfa)
        assert dm.get_pd(10.0) == pd_from_snr(10.0, threshold)

    def test_get_pfa(self) -> None:
        pfa = 1e-3
        dm = DetectionModel(pfa=pfa)
        assert abs(dm.get_pfa() - pfa) < 1e-12

    def test_determinism(self) -> None:
        """Same seed produces the same detection sequence."""
        dm = DetectionModel(pfa=1e-3)

        dm.reset(np.random.default_rng(42))
        seq1 = [dm.detect(10.0, True) for _ in range(200)]

        dm.reset(np.random.default_rng(42))
        seq2 = [dm.detect(10.0, True) for _ in range(200)]

        assert seq1 == seq2

    def test_mismatched_custom_threshold_raises(self) -> None:
        """An explicit threshold cannot override the configured Pfa."""
        pfa = 1e-3
        with pytest.raises(ValueError, match="does not match pfa"):
            DetectionModel(pfa=pfa, threshold=2.0)


class TestDetectBatch:
    """Vectorised detection matches scalar detect."""

    def test_batch_matches_scalar(self) -> None:
        """detect_batch gives the same results as calling detect in a loop."""
        pfa = 1e-3
        snr_db_arr = np.array([5.0, 10.0, 15.0, 20.0, 10.0, 5.0])
        transmitting = np.array([True, True, False, True, False, True])

        # Scalar path
        dm = DetectionModel(pfa=pfa)
        dm.reset(np.random.default_rng(123))
        scalar_results = np.array([
            dm.detect(float(snr_db_arr[i]), bool(transmitting[i]))
            for i in range(len(snr_db_arr))
        ])

        # Batch path — same seed
        dm2 = DetectionModel(pfa=pfa)
        dm2.reset(np.random.default_rng(123))
        batch_results = dm2.detect_batch(snr_db_arr, transmitting)

        np.testing.assert_array_equal(scalar_results, batch_results)

    def test_batch_scalar_snr_broadcast(self) -> None:
        """A single SNR value broadcasts across all bands."""
        dm = DetectionModel(pfa=1e-2)
        rng = np.random.default_rng(0)
        dm.reset(rng)
        transmitting = np.array([True, False, True, True, False])
        result = dm.detect_batch(10.0, transmitting)
        assert result.shape == transmitting.shape
        assert result.dtype == np.bool_

    def test_batch_all_transmitting_high_snr(self) -> None:
        """With very high SNR and all transmitting, nearly all detections."""
        dm = DetectionModel(pfa=1e-6)
        rng = np.random.default_rng(7)
        dm.reset(rng)
        n = 1000
        transmitting = np.ones(n, dtype=bool)
        result = dm.detect_batch(40.0, transmitting)
        # At 40 dB, Pd ≈ 1, so almost all should detect
        assert result.sum() > 0.99 * n

    def test_batch_none_transmitting(self) -> None:
        """With no signal, detections should be rare (near Pfa)."""
        pfa = 1e-3
        dm = DetectionModel(pfa=pfa)
        rng = np.random.default_rng(55)
        dm.reset(rng)
        n = 100_000
        transmitting = np.zeros(n, dtype=bool)
        result = dm.detect_batch(0.0, transmitting)
        empirical_pfa = result.sum() / n
        assert abs(empirical_pfa - pfa) < 0.002
