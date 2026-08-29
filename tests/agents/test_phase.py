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


class TestRecencyTerm:
    """The half of the Markov belief that survives at k=1: gap == 1."""

    def _sticky(self, seed=0, p01=0.05, p10=0.05, n_slots=600):
        rng = np.random.default_rng(seed)
        model = PhaseOccupancy(n_bands=1, capacity=n_slots, pd=0.9, pfa=1e-4)
        state = True
        for slot in range(n_slots):
            state = (
                (rng.random() > p10) if state else (rng.random() < p01)
            )
            model.observe(0, slot, state)
        return model

    def test_state_just_seen_on_beats_the_marginal(self):
        model = self._sticky()
        model.observe(0, 600, True)
        assert model.posterior(0, 601)[0] > model.posterior(0, 900)[0]

    def test_state_just_seen_off_falls_below_the_marginal(self):
        model = self._sticky()
        model.observe(0, 600, False)
        assert model.posterior(0, 601)[0] < model.posterior(0, 900)[0]

    def test_recency_decays_back_to_the_marginal_with_gap(self):
        model = self._sticky()
        model.observe(0, 600, True)
        near = model.posterior(0, 601)[0]
        far = model.posterior(0, 700)[0]
        distant = model.posterior(0, 1200)[0]
        assert near > far > distant
        assert far - distant < near - far

    def test_a_single_miss_does_not_abandon_an_always_on_band(self):
        """Pd < 1 means a miss is usually the detector, not a state change."""
        model = PhaseOccupancy(n_bands=1, capacity=400, pd=0.9, pfa=1e-4)
        for slot in range(300):
            model.observe(0, slot, slot % 30 != 7)  # ~3% detector misses
        model.observe(0, 300, False)
        assert model.posterior(0, 301)[0] > 0.5

    def test_periodic_band_ignores_recency(self):
        model = PhaseOccupancy(n_bands=1, capacity=2000)
        _feed_periodic(model, 0, 20, {5, 6, 7}, scan_rate=0.5, n_slots=2000)
        assert model.period(0) is not None

        model.observe(0, 2007, True)
        off_phase = model.posterior(0, 2015)[0]
        assert off_phase < 0.3


class TestOptimismDoesNotCollapseAtZero:
    def test_few_misses_stay_more_optimistic_than_many(self):
        few = PhaseOccupancy(n_bands=1, capacity=500)
        many = PhaseOccupancy(n_bands=1, capacity=500)
        for slot in range(10):
            few.observe(0, slot * 7, False)
        for slot in range(100):
            many.observe(0, slot * 7, False)

        assert few.upper_bound(999)[0] > many.upper_bound(999)[0]

    def test_a_ten_look_miss_run_is_not_treated_as_proof_of_silence(self):
        """P(0 hits in 10 looks | 10% duty) = 0.35, so 10 looks prove little."""
        model = PhaseOccupancy(n_bands=1, capacity=500)
        for slot in range(10):
            model.observe(0, slot * 7, False)
        assert model.upper_bound(999)[0] > 0.15

    def test_never_observed_band_is_fully_optimistic(self):
        model = PhaseOccupancy(n_bands=2, capacity=100)
        model.observe(0, 0, True)
        assert model.upper_bound(1)[1] == pytest.approx(1.0)


class TestSurveyTerm:
    def test_bonus_vanishes_once_the_band_has_been_ruled_out(self):
        model = PhaseOccupancy(n_bands=1, capacity=500, survey_weight=0.3)
        early = model._survey_bonus(0)
        for slot in range(200):
            model.observe(0, slot, False)
        assert early == pytest.approx(0.3)
        assert model._survey_bonus(0) < 0.01

    def test_bonus_is_zero_once_the_band_has_ever_been_caught(self):
        model = PhaseOccupancy(n_bands=1, capacity=500, survey_weight=0.3)
        model.observe(0, 0, True)
        assert model._survey_bonus(0) == 0.0

    def test_bonus_cannot_outbid_an_always_on_incumbent(self):
        """Self-disabling: no survey scan is affordable against a carrier."""
        model = PhaseOccupancy(n_bands=2, capacity=2000, survey_weight=0.3)
        for slot in range(0, 400, 2):
            model.observe(0, slot, True)
            model.observe(1, slot + 1, False)
        values = model.upper_bound(401)
        assert values[0] > values[1]


class TestLongPeriodRecovery:
    def test_recovers_a_period_beyond_the_gap_window(self):
        """A 255-slot hop cycle is never proposed by hit-gap divisors."""
        rng = np.random.default_rng(0)
        active = set(rng.choice(255, size=64, replace=False).tolist())
        model = PhaseOccupancy(n_bands=1, capacity=4000, max_period=300)
        for slot in range(4000):
            if rng.random() < 0.5:
                model.observe(0, slot, slot % 255 in active)
        assert model.period(0) == 255
