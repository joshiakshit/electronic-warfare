"""Unit tests for UCB1 scan scheduler (Phase 1D.3).

Verification criterion (PLAN.md 1D.3):
    Regret grows logarithmically on a stationary bench.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.baselines import RoundRobinScheduler, UniformRandomScheduler
from ewscan.agents.reward import RewardFunction
from ewscan.agents.stats import BandStatistics
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import EmitterInfo, Observation, ScanAction, Scheduler
from ewscan.env.environment import RFEnvironment
from ewscan.testing.fixtures import ScriptedEnv, make_test_config


class TestUCB1SchedulerInterface:
    def test_is_scheduler(self):
        assert issubclass(UCB1Scheduler, Scheduler)

    def test_name(self):
        scheduler = UCB1Scheduler()
        assert scheduler.name == "ucb1"

    def test_unreset_act_raises(self):
        scheduler = UCB1Scheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)

    def test_unreset_stats_raises(self):
        scheduler = UCB1Scheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = scheduler.stats

    def test_invalid_c_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            UCB1Scheduler(c=-0.5)

    def test_reset_initializes_stats(self):
        config = make_test_config(n_bands=4, n_slots=10)
        scheduler = UCB1Scheduler(c=1.5)
        scheduler.reset(config)

        assert scheduler.c == 1.5
        assert isinstance(scheduler.stats, BandStatistics)
        assert scheduler.stats.n_bands == 4
        assert scheduler.stats.total_pulls == 0


class TestUCB1InitialExploration:
    def test_scans_all_unvisited_bands_first(self):
        """First n_bands slots must visit every band once in order."""
        n_bands = 5
        config = make_test_config(n_bands=n_bands, n_slots=20)
        scheduler = UCB1Scheduler()
        scheduler.reset(config)

        # Slot 0
        a0 = scheduler.act(None)
        assert a0.bands[0] == 0

        # Slot 1: provide obs for band 0
        a1 = scheduler.act(Observation(slot=0, bands=(0,), detections=(True,)))
        assert a1.bands[0] == 1

        # Slot 2: provide obs for band 1
        a2 = scheduler.act(Observation(slot=1, bands=(1,), detections=(True,)))
        assert a2.bands[0] == 2

        # Slot 3: provide obs for band 2
        a3 = scheduler.act(Observation(slot=2, bands=(2,), detections=(True,)))
        assert a3.bands[0] == 3

        # Slot 4: provide obs for band 3
        a4 = scheduler.act(Observation(slot=3, bands=(3,), detections=(True,)))
        assert a4.bands[0] == 4


class TestUCB1DecisionLogic:
    def test_selects_highest_ucb_arm(self):
        """Hand-crafted test: after initial sweep, chooses arm with highest UCB index."""
        config = make_test_config(n_bands=3, n_slots=10)
        scheduler = UCB1Scheduler(c=1.0)
        scheduler.reset(config)

        # Initial sweep:
        # slot 0 -> scans band 0
        assert scheduler.act(None).bands[0] == 0
        # slot 1 -> obs for band 0 (detection=True), scans band 1
        assert scheduler.act(Observation(slot=0, bands=(0,), detections=(True,))).bands[0] == 1
        # slot 2 -> obs for band 1 (detection=False), scans band 2
        assert scheduler.act(Observation(slot=1, bands=(1,), detections=(False,))).bands[0] == 2

        # Now all 3 bands visited once (t=3):
        # Band 0: mu = 1.0, bonus = sqrt(2 * ln(3) / 1)
        # Band 1: mu = 0.0, bonus = sqrt(2 * ln(3) / 1)
        # Band 2: mu = 0.0, bonus = sqrt(2 * ln(3) / 1)
        # Band 0 clearly has the maximum UCB -> next action must be band 0!
        a3 = scheduler.act(Observation(slot=2, bands=(2,), detections=(False,)))
        assert a3.bands[0] == 0

    def test_ucb_exploration_bonus_triggers_switch(self):
        """Verify that an arm with zero reward is eventually revisited due to the ln(t) bonus."""
        config = make_test_config(n_bands=2, n_slots=100)
        scheduler = UCB1Scheduler(c=1.0)
        scheduler.reset(config)

        # Initial sweep
        scheduler.act(None)  # chooses 0
        scheduler.act(Observation(slot=0, bands=(0,), detections=(True,)))  # chooses 1
        # Feed band 1 no detection
        action = scheduler.act(Observation(slot=1, bands=(1,), detections=(False,)))
        assert action.bands[0] == 0  # chooses 0

        # Continue pulling band 0 with detections. Band 0: mu=1.0, N_0 growing.
        # Band 1: mu=0.0, N_1=1. UCB_1 = 0 + sqrt(2 * ln(t) / 1)
        # When sqrt(2 * ln(t)) > 1.0 + sqrt(2 * ln(t) / N_0), band 1 will be chosen.
        # For t ~ 8, 2 * ln(8) = 4.158, sqrt(4.158) = 2.039 > 1 + sqrt(4.158 / 7) = 1.77.
        band1_selected = False
        for slot in range(2, 50):
            obs = Observation(slot=slot, bands=(action.bands[0],), detections=((action.bands[0] == 0,)))
            action = scheduler.act(obs)
            if action.bands[0] == 1:
                band1_selected = True
                break

        assert band1_selected, "Arm 1 should have been explored as t increased"


class TestUCB1WithRewardFunction:
    def test_custom_reward_function_integration(self):
        rf = RewardFunction(w_threat=1.0, c_miss=0.5, w_novelty=0.0, w_decay=0.0)
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=0.1, emitter_type="cw"),
        )
        config = make_test_config(n_bands=2, n_slots=10, emitters=emitters)
        scheduler = UCB1Scheduler(reward_fn=rf)
        scheduler.reset(config)

        # Initial sweep
        scheduler.act(None)  # 0
        scheduler.act(Observation(slot=0, bands=(0,), detections=(True,)))  # 1
        action = scheduler.act(Observation(slot=1, bands=(1,), detections=(True,)))  # slot 2

        # Both had detection=True, but band 0 has threat=1.0 (reward=1.0) while band 1 has threat=0.1 (reward=0.1)
        assert action.bands[0] == 0


class TestUCB1StationaryBenchmark:
    """Verification criterion: Regret grows logarithmically on a stationary bench.

    Theoretical guarantee (Auer et al. 2002):
        Expected pulls of suboptimal arm i: E[N_i(T)] <= (8 / Delta_i^2) * ln(T) + O(1)
        Expected cumulative regret: R(T) = sum_i Delta_i * E[N_i(T)] = O(ln T)
        Average regret: R(T) / T -> 0 as T -> infinity.
    """

    def test_logarithmic_regret_growth(self):
        # 4 stationary Bernoulli arms:
        # Band 0: p = 0.85 (optimal)
        # Band 1: p = 0.50
        # Band 2: p = 0.25
        # Band 3: p = 0.10
        probs = np.array([0.85, 0.50, 0.25, 0.10])
        n_bands = len(probs)
        opt_p = probs[0]

        horizons = [200, 500, 1000, 2000]
        n_trials = 20
        regrets = {H: [] for H in horizons}
        opt_pull_fractions = {H: [] for H in horizons}

        for trial in range(n_trials):
            for H in horizons:
                # Generate stationary truth table
                rng = np.random.default_rng(trial * 1000 + H)
                truth = rng.random((n_bands, H)) < probs[:, None]

                config = make_test_config(n_bands=n_bands, n_slots=H, seed=trial)
                env = ScriptedEnv(config, truth)
                scheduler = UCB1Scheduler(c=1.0, seed=trial)

                log = env.run(scheduler)

                # Regret: sum of (opt_p - probs[action_t])
                sampled_probs = probs[log.actions]
                cum_regret = np.sum(opt_p - sampled_probs)
                regrets[H].append(cum_regret)

                opt_pulls = np.sum(log.actions == 0)
                opt_pull_fractions[H].append(opt_pulls / H)

        mean_regrets = [float(np.mean(regrets[H])) for H in horizons]
        mean_opt_fracs = [float(np.mean(opt_pull_fractions[H])) for H in horizons]

        # 1. Regret / ln(H) should remain bounded as H grows (logarithmic scaling)
        log_H = np.log(horizons)
        regret_ratios = np.array(mean_regrets) / log_H

        # Log ratio remains stable and bounded
        assert regret_ratios[-1] < 15.0

        # 2. Average regret R(H)/H decreases toward 0
        avg_regret = np.array(mean_regrets) / np.array(horizons)
        assert avg_regret[-1] < avg_regret[0]
        assert avg_regret[-1] < 0.05

        # 3. Optimal arm is chosen for majority of slots (>80% at H=2000)
        assert mean_opt_fracs[-1] > 0.80

    def test_ucb1_beats_baselines_on_stationary_bench(self):
        """UCB1 must strictly beat RoundRobin and UniformRandom on cumulative hits."""
        probs = np.array([0.9, 0.3, 0.2, 0.1])
        n_bands = len(probs)
        n_slots = 1000

        rng = np.random.default_rng(42)
        truth = rng.random((n_bands, n_slots)) < probs[:, None]

        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=42)

        env_ucb = ScriptedEnv(config, truth)
        log_ucb = env_ucb.run(UCB1Scheduler(c=1.0, seed=42))

        env_rr = ScriptedEnv(config, truth)
        log_rr = env_rr.run(RoundRobinScheduler())

        env_rnd = ScriptedEnv(config, truth)
        log_rnd = env_rnd.run(UniformRandomScheduler(seed=42))

        hits_ucb = np.sum(log_ucb.detections)
        hits_rr = np.sum(log_rr.detections)
        hits_rnd = np.sum(log_rnd.detections)

        # UCB1 should focus on band 0 (p=0.9) and achieve vastly higher detections
        # Theoretical expectation: UCB1 ~ 750-850 hits, RR ~ (0.9+0.3+0.2+0.1)/4 * 1000 = 375 hits
        assert hits_ucb > hits_rr + 250
        assert hits_ucb > hits_rnd + 250


class TestUCB1WithRFEnvironment:
    def test_e2e_rf_environment(self):
        emitters = (
            EmitterInfo(
                band=0,
                snr=25.0,
                threat_level=1.0,
                emitter_type="gilbert_elliott",
                params={"p01": 0.5, "p10": 0.1},  # 83.3% duty cycle
            ),
            EmitterInfo(
                band=1,
                snr=25.0,
                threat_level=0.5,
                emitter_type="gilbert_elliott",
                params={"p01": 0.1, "p10": 0.5},  # 16.7% duty cycle
            ),
        )
        config = make_test_config(
            n_bands=4,
            n_slots=500,
            emitters=emitters,
            pfa=1e-5,
            detection_threshold=None,
            seed=42,
        )

        env = RFEnvironment(config)
        env.reset()

        scheduler = UCB1Scheduler(c=1.0, seed=42)
        scheduler.reset(config)

        actions = []
        detections = []
        for _ in range(config.n_slots):
            if not actions:
                action = scheduler.act(None)
            else:
                obs = Observation(
                    slot=len(actions) - 1,
                    bands=(actions[-1],),
                    detections=(detections[-1],),
                )
                action = scheduler.act(obs)

            actions.append(action.bands[0])
            obs = env.step(action)
            detections.append(obs.detections[0])

        # Band 0 has high duty cycle and high threat, UCB1 must spend majority of pulls on Band 0
        band0_pulls = actions.count(0)
        assert band0_pulls > 300, f"Band 0 pulls was only {band0_pulls}/500"
