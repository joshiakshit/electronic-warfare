"""Unit tests for Thompson Sampling scan scheduler (Phase 1D.5).

Verification criterion (PLAN.md 1D.5):
    Posterior mean converges to the true ON probability.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.baselines import RoundRobinScheduler, UniformRandomScheduler
from ewscan.agents.reward import RewardFunction
from ewscan.agents.stats import BandStatistics
from ewscan.agents.thompson import (
    BetaThompsonSamplingScheduler,
    ThompsonSamplingScheduler,
)
from ewscan.contracts import EmitterInfo, Observation, ScanAction, Scheduler, ThreatPrior
from ewscan.env.environment import RFEnvironment
from ewscan.experiments.runner import _build_scheduler_by_name, run_episode
from ewscan.testing.fixtures import ScriptedEnv, make_test_config


class TestThompsonSamplingInterface:
    def test_is_scheduler(self):
        assert issubclass(ThompsonSamplingScheduler, Scheduler)
        assert issubclass(BetaThompsonSamplingScheduler, Scheduler)
        assert BetaThompsonSamplingScheduler is ThompsonSamplingScheduler

    def test_name(self):
        scheduler = ThompsonSamplingScheduler()
        assert scheduler.name == "thompson_sampling"

    def test_unreset_act_raises(self):
        scheduler = ThompsonSamplingScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)

    def test_unreset_properties_raise(self):
        scheduler = ThompsonSamplingScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = scheduler.stats
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = scheduler.alpha
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = scheduler.beta
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = scheduler.posterior_means

    def test_invalid_priors_raise(self):
        with pytest.raises(ValueError, match="strictly positive"):
            ThompsonSamplingScheduler(alpha_prior=0.0)
        with pytest.raises(ValueError, match="strictly positive"):
            ThompsonSamplingScheduler(alpha_prior=-1.0)
        with pytest.raises(ValueError, match="strictly positive"):
            ThompsonSamplingScheduler(beta_prior=0.0)
        with pytest.raises(ValueError, match="strictly positive"):
            ThompsonSamplingScheduler(beta_prior=-0.5)

    def test_reset_initializes_state(self):
        config = make_test_config(n_bands=4, n_slots=20)
        scheduler = ThompsonSamplingScheduler(alpha_prior=2.0, beta_prior=3.0)
        scheduler.reset(config)

        assert scheduler.alpha_prior == 2.0
        assert scheduler.beta_prior == 3.0
        assert isinstance(scheduler.stats, BandStatistics)
        assert scheduler.stats.n_bands == 4
        assert scheduler.stats.total_pulls == 0

        assert np.array_equal(scheduler.alpha, np.array([2.0, 2.0, 2.0, 2.0]))
        assert np.array_equal(scheduler.beta, np.array([3.0, 3.0, 3.0, 3.0]))
        assert np.allclose(scheduler.posterior_means, np.full(4, 2.0 / 5.0))


class TestThompsonSamplingPosteriorUpdates:
    def test_conjugate_beta_bernoulli_updates(self):
        """Exact test of alpha/beta updates on scripted observations."""
        config = make_test_config(n_bands=3, n_slots=10)
        scheduler = ThompsonSamplingScheduler(alpha_prior=1.0, beta_prior=1.0, seed=42)
        scheduler.reset(config)

        # Slot 0: act(None)
        a0 = scheduler.act(None)
        assert 0 <= a0.bands[0] < 3

        # Feed detection on Band 0
        scheduler.act(Observation(slot=0, bands=(0,), detections=(True,)))
        assert scheduler.alpha[0] == 2.0
        assert scheduler.beta[0] == 1.0
        assert scheduler.posterior_means[0] == 2.0 / 3.0

        # Feed miss on Band 0
        scheduler.act(Observation(slot=1, bands=(0,), detections=(False,)))
        assert scheduler.alpha[0] == 2.0
        assert scheduler.beta[0] == 2.0
        assert scheduler.posterior_means[0] == 2.0 / 4.0

        # Feed detection on Band 1
        scheduler.act(Observation(slot=2, bands=(1,), detections=(True,)))
        assert scheduler.alpha[1] == 2.0
        assert scheduler.beta[1] == 1.0
        assert scheduler.posterior_means[1] == 2.0 / 3.0

        # Band 2 untouched
        assert scheduler.alpha[2] == 1.0
        assert scheduler.beta[2] == 1.0
        assert scheduler.posterior_means[2] == 0.5


class TestThompsonSamplingConvergence:
    """PLAN.md Verification Criterion:

    'Posterior mean converges to the true ON probability'
    """

    def test_posterior_mean_converges_to_true_probability(self):
        """Verify empirical convergence of Beta posterior mean to true Bernoulli p."""
        true_probs = np.array([0.80, 0.45, 0.20, 0.05])
        n_bands = len(true_probs)
        n_samples_per_band = 3000

        rng = np.random.default_rng(42)
        scheduler = ThompsonSamplingScheduler(alpha_prior=1.0, beta_prior=1.0, seed=42)
        config = make_test_config(n_bands=n_bands, n_slots=n_samples_per_band * n_bands)
        scheduler.reset(config)

        # Feed i.i.d. observations from the true Bernoulli distributions
        slot = 0
        for band in range(n_bands):
            p = true_probs[band]
            detections = rng.random(n_samples_per_band) < p
            for det in detections:
                scheduler.act(Observation(slot=slot, bands=(band,), detections=(bool(det),)))
                slot += 1

        # Check posterior means against true probabilities
        post_means = scheduler.posterior_means
        for band in range(n_bands):
            p_true = true_probs[band]
            p_est = post_means[band]
            assert abs(p_est - p_true) < 0.02, (
                f"Band {band}: posterior mean {p_est:.4f} did not converge to {p_true:.4f}"
            )

    def test_active_scheduling_posterior_convergence_on_optimal_arm(self):
        """In an active loop, the heavily sampled optimal arm's posterior converges to true p."""
        true_probs = np.array([0.75, 0.30, 0.15])
        n_bands = len(true_probs)
        n_slots = 2000

        rng = np.random.default_rng(123)
        truth = rng.random((n_bands, n_slots)) < true_probs[:, None]

        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=123)
        env = ScriptedEnv(config, truth)
        scheduler = ThompsonSamplingScheduler(alpha_prior=1.0, beta_prior=1.0, seed=123)

        log = env.run(scheduler)

        # Band 0 should be pulled the vast majority of the time
        band0_pulls = np.sum(log.actions == 0)
        assert band0_pulls > 1400

        # Band 0 posterior mean must match true p within small margin
        post_mean_0 = scheduler.posterior_means[0]
        assert abs(post_mean_0 - 0.75) < 0.03


class TestThompsonSamplingStationaryBenchmark:
    """Benchmark performance against baselines and theoretical regret properties."""

    def test_sublinear_regret_growth(self):
        """Cumulative regret should grow sublinearly and average regret should decrease."""
        probs = np.array([0.85, 0.50, 0.25, 0.10])
        n_bands = len(probs)
        opt_p = probs[0]

        horizons = [200, 500, 1000, 2000]
        n_trials = 15
        regrets = {H: [] for H in horizons}
        opt_fractions = {H: [] for H in horizons}

        for trial in range(n_trials):
            for H in horizons:
                rng = np.random.default_rng(trial * 1000 + H)
                truth = rng.random((n_bands, H)) < probs[:, None]

                config = make_test_config(n_bands=n_bands, n_slots=H, seed=trial)
                env = ScriptedEnv(config, truth)
                scheduler = ThompsonSamplingScheduler(seed=trial)

                log = env.run(scheduler)

                sampled_probs = probs[log.actions]
                cum_regret = np.sum(opt_p - sampled_probs)
                regrets[H].append(cum_regret)

                opt_pulls = np.sum(log.actions == 0)
                opt_fractions[H].append(opt_pulls / H)

        mean_regrets = [float(np.mean(regrets[H])) for H in horizons]
        mean_opt_fracs = [float(np.mean(opt_fractions[H])) for H in horizons]

        # 1. Average regret R(H)/H decreases toward 0
        avg_regret = np.array(mean_regrets) / np.array(horizons)
        assert avg_regret[-1] < avg_regret[0]
        assert avg_regret[-1] < 0.05

        # 2. Optimal arm is selected for majority of slots (>80% at H=2000)
        assert mean_opt_fracs[-1] > 0.80

    def test_thompson_beats_baselines_on_stationary_bench(self):
        """Thompson Sampling must strictly beat RoundRobin and UniformRandom."""
        probs = np.array([0.9, 0.3, 0.2, 0.1])
        n_bands = len(probs)
        n_slots = 1000

        rng = np.random.default_rng(42)
        truth = rng.random((n_bands, n_slots)) < probs[:, None]

        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=42)

        env_ts = ScriptedEnv(config, truth)
        log_ts = env_ts.run(ThompsonSamplingScheduler(seed=42))

        env_rr = ScriptedEnv(config, truth)
        log_rr = env_rr.run(RoundRobinScheduler())

        env_rnd = ScriptedEnv(config, truth)
        log_rnd = env_rnd.run(UniformRandomScheduler(seed=42))

        hits_ts = np.sum(log_ts.detections)
        hits_rr = np.sum(log_rr.detections)
        hits_rnd = np.sum(log_rnd.detections)

        assert hits_ts > hits_rr + 250
        assert hits_ts > hits_rnd + 250


class TestThompsonSamplingThreatWeightingAndReward:
    def test_threat_weighted_selection(self):
        """When threat weighting is enabled, scheduler favors high-threat arm over frequent low-threat arm."""
        # Band 0: frequent (p=0.8) but low threat (0.1) -> Expected threat = 0.08
        # Band 1: infrequent (p=0.3) but high threat (1.0) -> Expected threat = 0.30
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=0.1, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=1.0, emitter_type="cw"),
        )
        config = make_test_config(n_bands=2, n_slots=1000, emitters=emitters, seed=42)

        rng = np.random.default_rng(42)
        truth = np.vstack([
            rng.random(1000) < 0.8,
            rng.random(1000) < 0.3,
        ])

        prior = ThreatPrior(weights=(0.1, 1.0), provenance="test-intel")
        env = ScriptedEnv(config, truth, threat_prior=prior)
        scheduler = ThompsonSamplingScheduler(use_threat_weighting=True, seed=42)
        log = env.run(scheduler)

        # High-threat Band 1 should receive more pulls than Band 0
        band1_pulls = np.sum(log.actions == 1)
        assert band1_pulls > 600, f"Expected Band 1 to dominate, got {band1_pulls} pulls"

    def test_custom_reward_function_integration(self):
        rf = RewardFunction(w_threat=2.0, c_miss=0.5, w_novelty=0.1, w_decay=0.0)
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=0.2, emitter_type="cw"),
        )
        config = make_test_config(n_bands=2, n_slots=500, emitters=emitters, seed=42)

        rng = np.random.default_rng(42)
        truth = np.vstack([
            rng.random(500) < 0.7,
            rng.random(500) < 0.7,
        ])

        prior = ThreatPrior(weights=(1.0, 0.2), provenance="test-intel")
        env = ScriptedEnv(config, truth, threat_prior=prior)
        scheduler = ThompsonSamplingScheduler(reward_fn=rf, seed=42)
        log = env.run(scheduler)

        # Since detection rates are identical, Band 0 (threat=1.0) yields higher reward
        band0_pulls = np.sum(log.actions == 0)
        assert band0_pulls > 350


class TestThompsonSamplingIntegration:
    def test_determinism_with_same_seed(self):
        config = make_test_config(n_bands=4, n_slots=100, seed=99)
        rng = np.random.default_rng(99)
        truth = rng.random((4, 100)) < 0.4

        env1 = ScriptedEnv(config, truth)
        log1 = env1.run(ThompsonSamplingScheduler(seed=99))

        env2 = ScriptedEnv(config, truth)
        log2 = env2.run(ThompsonSamplingScheduler(seed=99))

        assert np.array_equal(log1.actions, log2.actions)
        assert np.array_equal(log1.detections, log2.detections)

    def test_rf_environment_and_runner_execution(self):
        emitters = (
            EmitterInfo(
                band=0,
                snr=25.0,
                threat_level=1.0,
                emitter_type="gilbert_elliott",
                params={"p01": 0.4, "p10": 0.1},
            ),
            EmitterInfo(
                band=2,
                snr=20.0,
                threat_level=0.5,
                emitter_type="cw",
            ),
        )
        config = make_test_config(
            n_bands=4,
            n_slots=300,
            emitters=emitters,
            seed=42,
        )

        scheduler = ThompsonSamplingScheduler(seed=42)
        result = run_episode(config, scheduler, seed=42)

        assert result.scheduler_name == "thompson_sampling"
        assert result.interception.interception_ratio.ratio > 0.0
        assert result.reward.average_reward is not None

    def test_runner_scheduler_builder_aliases(self):
        s1 = _build_scheduler_by_name("thompson")
        s2 = _build_scheduler_by_name("thompson_sampling")
        s3 = _build_scheduler_by_name("ts")

        assert isinstance(s1, ThompsonSamplingScheduler)
        assert isinstance(s2, ThompsonSamplingScheduler)
        assert isinstance(s3, ThompsonSamplingScheduler)
