"""Tests for Discounted Thompson Sampling scheduler (Phase 1D.6).

Verification criterion (PLAN.md 1D.6):
    Recovers from an abrupt change within a bounded slot count.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.thompson import (
    DiscountedThompsonScheduler,
    ThompsonSamplingScheduler,
)
from ewscan.contracts import Observation, Scheduler
from ewscan.testing.fixtures import ScriptedEnv, make_test_config


class TestDiscountedThompsonInterface:
    def test_is_scheduler(self):
        assert issubclass(DiscountedThompsonScheduler, Scheduler)

    def test_name(self):
        scheduler = DiscountedThompsonScheduler()
        assert scheduler.name == "discounted_thompson_sampling"

    def test_invalid_gamma_raises(self):
        with pytest.raises(ValueError, match="gamma"):
            DiscountedThompsonScheduler(gamma=0.0)
        with pytest.raises(ValueError, match="gamma"):
            DiscountedThompsonScheduler(gamma=-0.5)
        with pytest.raises(ValueError, match="gamma"):
            DiscountedThompsonScheduler(gamma=1.5)

    def test_gamma_one_is_allowed(self):
        s = DiscountedThompsonScheduler(gamma=1.0)
        assert s.gamma == 1.0

    def test_default_gamma(self):
        s = DiscountedThompsonScheduler()
        assert s.gamma == 0.95

    def test_reset_initializes_state(self):
        config = make_test_config(n_bands=3, n_slots=50)
        s = DiscountedThompsonScheduler(gamma=0.9)
        s.reset(config)
        np.testing.assert_array_equal(s.alpha, np.ones(3))
        np.testing.assert_array_equal(s.beta, np.ones(3))


class TestDecayMechanics:
    def test_decay_toward_prior(self):
        """After one decay step with no observation, alpha/beta move toward the prior."""
        config = make_test_config(n_bands=2, n_slots=10)
        s = DiscountedThompsonScheduler(gamma=0.5, seed=0)
        s.reset(config)

        # Manually set alpha to something away from the prior
        s._alpha[:] = [5.0, 3.0]
        s._beta[:] = [2.0, 4.0]

        # One act(None) triggers decay but no observation update
        s.act(None)

        # Expected after decay: prior + gamma * (old - prior)
        # alpha[0]: 1 + 0.5*(5-1) = 3.0
        # alpha[1]: 1 + 0.5*(3-1) = 2.0
        # beta[0]: 1 + 0.5*(2-1) = 1.5
        # beta[1]: 1 + 0.5*(4-1) = 2.5
        np.testing.assert_allclose(s.alpha, [3.0, 2.0], atol=1e-12)
        np.testing.assert_allclose(s.beta, [1.5, 2.5], atol=1e-12)

    def test_decay_with_custom_prior(self):
        """Decay targets the configured prior, not hardcoded 1.0."""
        config = make_test_config(n_bands=1, n_slots=10)
        s = DiscountedThompsonScheduler(
            alpha_prior=2.0, beta_prior=3.0, gamma=0.5, seed=0
        )
        s.reset(config)

        # After reset: alpha=2.0, beta=3.0
        # Manually push alpha away from prior
        s._alpha[:] = [6.0]
        s._beta[:] = [7.0]

        s.act(None)

        # alpha: 2.0 + 0.5*(6.0 - 2.0) = 4.0
        # beta: 3.0 + 0.5*(7.0 - 3.0) = 5.0
        np.testing.assert_allclose(s.alpha, [4.0], atol=1e-12)
        np.testing.assert_allclose(s.beta, [5.0], atol=1e-12)

    def test_unvisited_bands_revert_to_prior(self):
        """Bands that are never pulled should decay back to the prior."""
        config = make_test_config(n_bands=2, n_slots=50)
        s = DiscountedThompsonScheduler(gamma=0.9, seed=0)
        s.reset(config)

        # Manually inflate band 1 then never pull it
        s._alpha[1] = 10.0
        s._beta[1] = 1.0

        for t in range(50):
            obs = Observation(slot=t, band=0, detection=True) if t > 0 else None
            s.act(obs)

        # Band 1 was never updated, only decayed 50 times
        # alpha[1] should be close to 1.0 (the prior)
        assert abs(s.alpha[1] - 1.0) < 0.1

    def test_gamma_one_equals_standard_ts(self):
        """With gamma=1.0 (no decay), behavior matches standard Thompson Sampling."""
        config = make_test_config(n_bands=3, n_slots=100, seed=42)
        rng = np.random.default_rng(42)
        truth = rng.random((3, 100)) < 0.5

        env1 = ScriptedEnv(config, truth)
        s1 = DiscountedThompsonScheduler(gamma=1.0, seed=99)
        log1 = env1.run(s1)

        env2 = ScriptedEnv(config, truth)
        s2 = ThompsonSamplingScheduler(seed=99)
        log2 = env2.run(s2)

        np.testing.assert_array_equal(log1.actions, log2.actions)


class TestAbruptRecovery:
    """PLAN.md verification: recovers from an abrupt change within a bounded slot count."""

    def test_recovers_from_abrupt_switch(self):
        """Two-band scenario: band 0 ON then OFF, band 1 OFF then ON.

        The discounted scheduler must switch preference to band 1
        within a bounded number of slots after the change.
        """
        n_bands = 2
        phase1_len = 100
        phase2_len = 200
        n_slots = phase1_len + phase2_len
        gamma = 0.9

        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, :phase1_len] = True
        truth[1, phase1_len:] = True

        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=42)
        env = ScriptedEnv(config, truth)
        s = DiscountedThompsonScheduler(gamma=gamma, seed=42)
        log = env.run(s)

        # Phase 1: agent should converge on band 0
        phase1_band0 = np.sum(log.actions[:phase1_len] == 0)
        assert phase1_band0 > 80, f"Phase 1: expected mostly band 0, got {phase1_band0}/100"

        # Recovery window: slots 100..149 (first 50 slots of phase 2)
        # By slot 150, agent should have switched to band 1
        late_phase2 = log.actions[150:]
        band1_late = np.sum(late_phase2 == 1)
        frac = band1_late / len(late_phase2)
        assert frac > 0.85, (
            f"After recovery window, expected >85% band 1, got {frac:.2%}"
        )

    def test_recovers_faster_than_standard_ts(self):
        """Discounted TS recovers faster than standard TS in the early window after a switch."""
        n_bands = 2
        phase1_len = 100
        phase2_len = 200
        n_slots = phase1_len + phase2_len

        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, :phase1_len] = True
        truth[1, phase1_len:] = True

        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=42)

        # Standard TS
        env_std = ScriptedEnv(config, truth)
        s_std = ThompsonSamplingScheduler(seed=42)
        log_std = env_std.run(s_std)

        # Discounted TS
        env_disc = ScriptedEnv(config, truth)
        s_disc = DiscountedThompsonScheduler(gamma=0.9, seed=42)
        log_disc = env_disc.run(s_disc)

        # In the recovery window (first 80 slots after switch), discounted TS
        # should pick band 1 significantly more often
        window = slice(phase1_len, phase1_len + 80)
        band1_std = np.sum(log_std.actions[window] == 1)
        band1_disc = np.sum(log_disc.actions[window] == 1)

        assert band1_disc > band1_std + 10, (
            f"Discounted TS ({band1_disc}) should recover much faster than "
            f"standard TS ({band1_std}) in the first 80 slots after the switch"
        )

    def test_determinism(self):
        """Same seed produces identical runs."""
        n_bands = 2
        n_slots = 200
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, :100] = True
        truth[1, 100:] = True
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=7)

        env1 = ScriptedEnv(config, truth)
        log1 = env1.run(DiscountedThompsonScheduler(gamma=0.9, seed=7))

        env2 = ScriptedEnv(config, truth)
        log2 = env2.run(DiscountedThompsonScheduler(gamma=0.9, seed=7))

        np.testing.assert_array_equal(log1.actions, log2.actions)
        np.testing.assert_array_equal(log1.detections, log2.detections)

    def test_multiple_switches(self):
        """Agent tracks multiple abrupt changes across an episode."""
        n_bands = 2
        n_slots = 600

        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        # Switch every 200 slots
        truth[0, :200] = True
        truth[1, 200:400] = True
        truth[0, 400:] = True

        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=55)
        env = ScriptedEnv(config, truth)
        s = DiscountedThompsonScheduler(gamma=0.9, seed=55)
        log = env.run(s)

        # Check the tail of each phase (last 50 slots) to confirm tracking
        assert np.sum(log.actions[150:200] == 0) > 40
        assert np.sum(log.actions[350:400] == 1) > 40
        assert np.sum(log.actions[550:600] == 0) > 40
