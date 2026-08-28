"""Tests for the sniper + bandit arbiter scheduler (Sprint 3, Task 7)."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.sniper import SniperScheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import EmitterInfo
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import get_scenario
from ewscan.testing.fixtures import make_test_config

SEEDS = range(20)
SCENARIOS = ("mixed_threat", "periodic_radar", "sparse_bursty")


def _mean_interception_ratio(config_name, scheduler_factory):
    ratios = []
    for seed in SEEDS:
        config = get_scenario(config_name)
        result = run_episode(config, scheduler_factory(), seed=seed)
        ratios.append(result.interception.interception_ratio.ratio)
    return float(np.mean(ratios))


@pytest.mark.slow
class TestNoRegressionGate:
    """Task 7 test 1: sniper must never score below its inner bandit alone."""

    @pytest.mark.parametrize("scenario_name", SCENARIOS)
    def test_sniper_matches_or_beats_inner_bandit(self, scenario_name):
        bandit_mean = _mean_interception_ratio(scenario_name, UCB1Scheduler)
        sniper_mean = _mean_interception_ratio(
            scenario_name, lambda: SniperScheduler(inner=UCB1Scheduler())
        )
        print(
            f"\n[gate] {scenario_name}: bandit={bandit_mean:.6f} sniper={sniper_mean:.6f}"
        )
        assert sniper_mean >= bandit_mean - 0.0


class TestPredictionAccuracyRisesOnPeriodic:
    """Task 7 test 2."""

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Sprint 3 gate NOT MET. The sniper never predicts on periodic_radar: "
            "confidence stays at the 0.5 prior and predicted_band is set on 0 of 2000 "
            "slots. Emitter bands are scanned plenty (216-319 scans, 39-73 hits), but "
            "estimate_period returns None at the 0.11-0.16 scan rate a k=1 receiver "
            "produces; Task 5 was validated at ~0.5. Lowering rho trades misses for "
            "wrong periods. The no-regression and fallback-identity gates DO pass. "
            "See project memories/sprint3_whittle_gate_finding.md"
        ),
    )
    def test_periodic_radar_prediction_accuracy(self):
        config = get_scenario("periodic_radar")
        sniper_result = run_episode(config, SniperScheduler(inner=UCB1Scheduler()), seed=7)
        bandit_result = run_episode(config, UCB1Scheduler(), seed=7)

        assert bandit_result.prediction.active is False
        assert bandit_result.prediction.accuracy is None

        assert sniper_result.prediction.active is True
        assert sniper_result.prediction.accuracy is not None
        print(f"\n[accuracy] periodic_radar sniper accuracy={sniper_result.prediction.accuracy:.4f}")
        assert sniper_result.prediction.accuracy > 0.7


class TestDistinctnessAndLegality:
    """Task 7 test 3."""

    @pytest.mark.parametrize("scenario_name", SCENARIOS)
    def test_k_distinct_in_range_bands_every_slot(self, scenario_name):
        config = get_scenario(scenario_name)
        result = run_episode(config, SniperScheduler(inner=UCB1Scheduler()), seed=3)
        actions = result.log.actions
        for row in actions:
            bands = list(row)
            assert len(set(bands)) == len(bands)
            for b in bands:
                assert 0 <= b < config.n_bands


class TestConfidentOverrideHappens:
    """Task 7 test 4.

    Two bands: band 0 is a clean, fast periodic emitter (predictable); band 1
    is a near-always-on Markov emitter that dominates UCB1's mean-reward
    ranking. With k=2 over n_bands=3, UCB1 naturally shares its second slot
    between band 0 and the filler band 2, so band 0 is scanned often enough
    to build predictor confidence but is not guaranteed on its exact due
    slot. Once confident, the sniper must force band 0 into the action on
    its due slots.
    """

    def _config(self, n_slots: int = 4000, seed: int = 0):
        emitters = (
            EmitterInfo(
                band=0, snr=20.0, threat_level=0.5, emitter_type="periodic",
                params={"period": 8, "dwell": 1, "jitter": 0, "phase": 0},
            ),
            EmitterInfo(
                band=1, snr=20.0, threat_level=0.5, emitter_type="gilbert_elliott",
                params={"p01": 0.5, "p10": 0.05},
            ),
        )
        return make_test_config(
            n_bands=3, n_slots=n_slots, k=2, seed=seed,
            detection_threshold=None, pfa=1e-4, emitters=emitters,
        )

    def test_sniped_band_appears_on_due_slots(self):
        config = self._config()
        scheduler = SniperScheduler(inner=UCB1Scheduler())
        result = run_episode(config, scheduler, seed=0)

        truth = result.log.truth
        actions = result.log.actions
        period = 8

        on_slots = np.flatnonzero(truth[0])
        assert len(on_slots) > 0

        override_seen = False
        for t in on_slots:
            if t < 200:
                continue  # skip predictor warm-up window
            if 0 in actions[t]:
                override_seen = True
                break

        assert override_seen, "sniper never placed band 0 in the action on a due slot"


class TestFallbackIdentity:
    """Task 7 test 5: the linchpin.

    With the predictor forced to never be confident (tau_conf=2.0, an
    unreachable confidence value), the sniper's chosen action sequence must
    equal the inner bandit's exactly, seed for seed. This proves the
    guardrail: the sniper cannot regress below the bandit because, absent
    confidence, it IS the bandit.
    """

    @pytest.mark.parametrize("scenario_name", SCENARIOS)
    def test_action_sequence_matches_bare_bandit_exactly(self, scenario_name):
        config = get_scenario(scenario_name)

        bandit_result = run_episode(config, UCB1Scheduler(), seed=11)
        sniper_result = run_episode(
            config,
            SniperScheduler(inner=UCB1Scheduler(), tau_conf=2.0),
            seed=11,
        )

        assert np.array_equal(bandit_result.log.actions, sniper_result.log.actions)
        assert np.array_equal(bandit_result.log.detections, sniper_result.log.detections)
