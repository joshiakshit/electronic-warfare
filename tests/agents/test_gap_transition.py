"""Tests for the gap-aware two-state transition estimator (Objective 5)."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.transition import GapAwareTransitionEstimator


# --- Test 1: exact T^d propagation for several gaps ---

class TestTdPropagation:
    """Belief propagated through gap d must match T^d applied to the posterior."""

    @pytest.mark.parametrize("gap", [1, 2, 5, 10, 50])
    def test_belief_propagation_matches_matrix_power(self, gap: int):
        p01, p10 = 0.1, 0.3
        est = GapAwareTransitionEstimator(n_bands=1, p01_init=p01, p10_init=p10)

        b_start = 0.7
        est._belief[0] = b_start

        # Manual T^d via eigenvalue decomposition
        lam = 1.0 - p01 - p10
        pi_on = p01 / (p01 + p10)
        expected = pi_on + (b_start - pi_on) * lam ** gap

        result = est._propagate_belief(0, gap)
        assert result == pytest.approx(expected, abs=1e-12)

    def test_gap_1_equals_standard_predict(self):
        p01, p10 = 0.2, 0.4
        est = GapAwareTransitionEstimator(n_bands=1, p01_init=p01, p10_init=p10)
        b = 0.6
        est._belief[0] = b

        standard = b * (1.0 - p10) + (1.0 - b) * p01
        gap1 = est._propagate_belief(0, 1)
        assert gap1 == pytest.approx(standard, abs=1e-12)

    def test_large_gap_converges_to_stationary(self):
        p01, p10 = 0.05, 0.15
        est = GapAwareTransitionEstimator(n_bands=1, p01_init=p01, p10_init=p10)
        est._belief[0] = 0.9

        pi_on = p01 / (p01 + p10)
        result = est._propagate_belief(0, 10000)
        assert result == pytest.approx(pi_on, abs=1e-6)


# --- Test 2: posterior update against analytic examples ---

class TestPosteriorUpdate:
    """Bayes correction with detector likelihood must match analytic formula."""

    def test_detection_raises_belief(self):
        pd, pfa = 0.9, 0.01
        est = GapAwareTransitionEstimator(n_bands=1, pd=pd, pfa=pfa)
        est._belief[0] = 0.3

        b = 0.3
        l_on, l_off = pd, pfa
        expected = (l_on * b) / (l_on * b + l_off * (1 - b))

        est._correct(0, True)
        assert est._belief[0] == pytest.approx(expected, abs=1e-12)

    def test_no_detection_lowers_belief(self):
        pd, pfa = 0.9, 0.01
        est = GapAwareTransitionEstimator(n_bands=1, pd=pd, pfa=pfa)
        est._belief[0] = 0.7

        b = 0.7
        l_on, l_off = 1.0 - pd, 1.0 - pfa
        expected = (l_on * b) / (l_on * b + l_off * (1 - b))

        est._correct(0, False)
        assert est._belief[0] == pytest.approx(expected, abs=1e-12)

    def test_prior_half_with_detection(self):
        pd, pfa = 0.9, 0.01
        est = GapAwareTransitionEstimator(n_bands=1, pd=pd, pfa=pfa)
        est._belief[0] = 0.5

        expected = (pd * 0.5) / (pd * 0.5 + pfa * 0.5)
        est._correct(0, True)
        assert est._belief[0] == pytest.approx(expected, abs=1e-12)


# --- Test 3: recovery of known Markov rates from irregular samples ---

class TestRateRecovery:
    """Estimator must recover ground-truth p01/p10 from irregular scans.

    A learning scheduler concentrates scans on promising bands with occasional
    exploration. This gives small gaps on focused bands (good for rate
    estimation) and large gaps on others (near-stationary, rates uncertain).
    """

    def test_recovers_rates_with_concentrated_scans(self):
        """Irregular scans with mean gap ~4 should recover both rates."""
        rng = np.random.default_rng(42)
        p01_true, p10_true = 0.1, 0.3
        n_bands = 4
        n_slots = 4000

        truth = np.empty((n_bands, n_slots), dtype=bool)
        pi_on = p01_true / (p01_true + p10_true)
        for b in range(n_bands):
            truth[b, 0] = rng.random() < pi_on
            for t in range(1, n_slots):
                if truth[b, t - 1]:
                    truth[b, t] = rng.random() >= p10_true
                else:
                    truth[b, t] = rng.random() < p01_true

        pd, pfa = 0.95, 0.01
        est = GapAwareTransitionEstimator(
            n_bands=n_bands, p01_init=0.5, p10_init=0.5, pd=pd, pfa=pfa,
        )

        # k=1 round-robin over 4 bands → gap=4, within mixing time
        for t in range(n_slots):
            band = t % n_bands
            true_state = truth[band, t]
            det = rng.random() < (pd if true_state else pfa)
            est.observe(band, t, det)

        p01_est = est.p01()
        p10_est = est.p10()
        for b in range(n_bands):
            assert abs(p01_est[b] - p01_true) < 0.06, (
                f"band {b}: p01={p01_est[b]:.3f} vs true={p01_true}"
            )
            assert abs(p10_est[b] - p10_true) < 0.12, (
                f"band {b}: p10={p10_est[b]:.3f} vs true={p10_true}"
            )

    def test_recovers_asymmetric_rates(self):
        """Rare ON emitter with frequent scans (gap=3) should recover rates."""
        rng = np.random.default_rng(99)
        p01_true, p10_true = 0.02, 0.5
        n_slots = 6000

        truth = np.empty(n_slots, dtype=bool)
        truth[0] = False
        for t in range(1, n_slots):
            if truth[t - 1]:
                truth[t] = rng.random() >= p10_true
            else:
                truth[t] = rng.random() < p01_true

        est = GapAwareTransitionEstimator(n_bands=1, pd=0.95, pfa=0.01)
        gap = 3
        for t in range(n_slots):
            if t % gap != 0:
                continue
            true_state = truth[t]
            det = rng.random() < (0.95 if true_state else 0.01)
            est.observe(0, t, det)

        assert abs(est.p01()[0] - p01_true) < 0.03
        assert abs(est.p10()[0] - p10_true) < 0.20

    def test_large_gap_gives_uncertain_but_reasonable_pi_on(self):
        """With gap >> mixing time, rates are uncertain but pi_on is correct."""
        rng = np.random.default_rng(55)
        p01_true, p10_true = 0.1, 0.3
        pi_on_true = p01_true / (p01_true + p10_true)
        n_slots = 3000

        truth = np.empty(n_slots, dtype=bool)
        truth[0] = rng.random() < pi_on_true
        for t in range(1, n_slots):
            if truth[t - 1]:
                truth[t] = rng.random() >= p10_true
            else:
                truth[t] = rng.random() < p01_true

        est = GapAwareTransitionEstimator(n_bands=1, pd=0.95, pfa=0.01)
        gap = 20
        for t in range(n_slots):
            if t % gap != 0:
                continue
            true_state = truth[t]
            det = rng.random() < (0.95 if true_state else 0.01)
            est.observe(0, t, det)

        # Can't recover exact rates, but pi_on estimate should be close
        p01_est = est.p01()[0]
        p10_est = est.p10()[0]
        if p01_est + p10_est > 1e-6:
            pi_on_est = p01_est / (p01_est + p10_est)
            assert abs(pi_on_est - pi_on_true) < 0.10


# --- Test 4: uncertainty remains high on unobserved bands ---

class TestUncertainty:
    """Bands without observations must report high uncertainty."""

    def test_unobserved_band_high_uncertainty(self):
        est = GapAwareTransitionEstimator(n_bands=4, pd=0.9, pfa=0.01)
        # Observe only band 0
        for t in range(100):
            est.observe(0, t, t % 3 == 0)

        # Band 0 has data: low uncertainty
        assert est.uncertainty(0) < est.uncertainty(1)
        assert est.uncertainty(0) < est.uncertainty(2)
        assert est.uncertainty(0) < est.uncertainty(3)

    def test_uncertainty_decreases_with_observations(self):
        est = GapAwareTransitionEstimator(n_bands=1, pd=0.9, pfa=0.01)
        u_before = est.uncertainty(0)
        for t in range(50):
            est.observe(0, t * 5, t % 3 == 0)
        u_after = est.uncertainty(0)
        assert u_after < u_before


# --- Test 5: small exact control problems match policy choices ---

class TestWhittleAlignment:
    """Whittle using gap-aware estimates should prefer the active band
    in a small scenario where one band is clearly ON and others are OFF."""

    def test_active_band_gets_higher_index(self):
        est = GapAwareTransitionEstimator(n_bands=2, pd=0.9, pfa=0.01)

        # Feed band 0 mostly-ON detections with sparse scans
        for t in range(0, 200, 10):
            est.observe(0, t, True)

        # Feed band 1 mostly-OFF detections
        for t in range(5, 200, 10):
            est.observe(1, t, False)

        # Band 0 should have higher belief and higher ON-rate estimate
        assert est.belief[0] > est.belief[1]
        assert est.p01()[0] > est.p01()[1] or est.p10()[0] < est.p10()[1]


# --- Backward compatibility: old TransitionEstimator still works ---

class TestLegacyInterface:
    """The gap-aware estimator must expose the same p01/p10/reset interface."""

    def test_reset_clears_state(self):
        est = GapAwareTransitionEstimator(n_bands=2, pd=0.9, pfa=0.01)
        est.observe(0, 0, True)
        est.observe(0, 1, False)
        est.reset()
        assert est.p01()[0] == pytest.approx(0.5, abs=0.01)
        assert est.p10()[0] == pytest.approx(0.5, abs=0.01)
        assert est.uncertainty(0) > 0.9

    def test_prior_at_zero_data(self):
        est = GapAwareTransitionEstimator(n_bands=3, pd=0.9, pfa=0.01)
        np.testing.assert_allclose(est.p01(), np.full(3, 0.5), atol=0.01)
        np.testing.assert_allclose(est.p10(), np.full(3, 0.5), atol=0.01)

    def test_multi_band_isolation(self):
        est = GapAwareTransitionEstimator(n_bands=2, pd=0.9, pfa=0.01)
        # Band 0: mostly ON
        for t in range(0, 100, 5):
            est.observe(0, t, True)
        # Band 1: mostly OFF
        for t in range(2, 100, 5):
            est.observe(1, t, False)
        assert est.p01()[0] != pytest.approx(est.p01()[1], abs=0.05)
