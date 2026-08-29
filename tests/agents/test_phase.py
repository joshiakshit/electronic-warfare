"""Tests for the phase-conditioned occupancy posterior."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.phase import PhaseOccupancy


def _feed_periodic(model, band, period, active, scan_rate, n_slots, seed=0):
    """Observe a dwell emitter on a randomly sampled fraction of slots."""
    rng = np.random.default_rng(seed)
    for slot in range(n_slots):
        if rng.random() >= scan_rate:
            continue
        model.observe(band, slot, slot % period in active)


class TestSparsePhaseRecovery:
    def test_recovers_sharp_phase_posterior_at_12_percent_scan_rate(self):
        model = PhaseOccupancy(n_bands=1, capacity=2000)
        _feed_periodic(model, 0, 20, {5, 6, 7}, scan_rate=0.12, n_slots=2000)

        assert model.period(0) == 20
        on_mean, _ = model.posterior(0, 2006)  # phase 6
        off_mean, _ = model.posterior(0, 2015)  # phase 15
        assert on_mean > 0.7
        assert off_mean < 0.2
        assert on_mean - off_mean > 0.5

    def test_posterior_does_not_decay_with_revisit_gap(self):
        """The property the Markov belief lacks: phase indexing is gap-free."""
        model = PhaseOccupancy(n_bands=1, capacity=2000)
        _feed_periodic(model, 0, 20, {5, 6, 7}, scan_rate=0.12, n_slots=2000)

        near = model.posterior(0, 2006)[0]
        far = model.posterior(0, 2006 + 20 * 500)[0]
        assert far == pytest.approx(near)


class TestWrongPeriodIsHarmless:
    def test_aperiodic_band_posterior_stays_at_the_marginal_rate(self):
        """A period that does not concentrate hits must change no decision."""
        rng = np.random.default_rng(3)
        model = PhaseOccupancy(n_bands=1, capacity=2000)
        for slot in range(2000):
            if rng.random() >= 0.15:
                continue
            model.observe(0, slot, bool(rng.random() < 0.3))

        means = np.array([model.posterior(0, slot)[0] for slot in range(400)])
        assert means.max() - means.min() < 0.35
        assert means.mean() == pytest.approx(0.3, abs=0.12)

    def test_empty_phase_bucket_falls_back_to_the_marginal(self):
        model = PhaseOccupancy(n_bands=2, capacity=200, smoothing=0)
        for slot in range(0, 200, 10):
            model.observe(0, slot, slot % 20 == 0)

        unseen_phase_mean = model.posterior(0, 3)[0]
        assert 0.0 < unseen_phase_mean < 1.0


class TestMarginalFallback:
    def test_band_without_a_period_uses_its_unconditional_rate(self):
        model = PhaseOccupancy(n_bands=1, capacity=200)
        for slot in range(40):
            model.observe(0, slot, slot < 20)

        assert model.period(0) is None
        mean, _ = model.posterior(0, 999)
        assert mean == pytest.approx(0.5, abs=0.1)

    def test_never_scanned_band_is_optimistic(self):
        model = PhaseOccupancy(n_bands=2, capacity=100)
        model.observe(0, 0, False)

        assert model.upper_bound(1)[1] > model.upper_bound(1)[0]

    def test_silent_band_collapses_toward_zero(self):
        model = PhaseOccupancy(n_bands=1, capacity=300)
        for slot in range(200):
            model.observe(0, slot, False)

        assert model.upper_bound(0)[0] < 0.1


class TestBookkeeping:
    def test_reset_clears_period_and_counts(self):
        model = PhaseOccupancy(n_bands=1, capacity=2000)
        _feed_periodic(model, 0, 20, {5, 6, 7}, scan_rate=0.5, n_slots=1000)
        assert model.period(0) is not None

        model.reset()
        assert model.period(0) is None
        assert model.counts()[0] == 0

    def test_lower_bound_is_below_the_posterior_mean(self):
        model = PhaseOccupancy(n_bands=1, capacity=2000)
        _feed_periodic(model, 0, 20, {5, 6, 7}, scan_rate=0.12, n_slots=2000)

        mean = model.posterior(0, 2006)[0]
        assert 0.0 <= model.lower_bound(0, 2006) <= mean
