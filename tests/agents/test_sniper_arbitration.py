"""Objective 7 tests for Sniper arbitration telemetry and safety."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.sniper import SniperScheduler
from ewscan.agents.reward import RewardFunction
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import Observation
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import get_scenario
from ewscan.testing.fixtures import make_test_config


class _DuePredictor:
    def __init__(self, band: int, confidence: float = 0.9) -> None:
        self.band = band
        self.confidence = confidence

    def observe(self, band: int, slot: int, detection: bool) -> None:
        pass

    def record_outcome(self, band: int, slot: int, was_on: bool) -> None:
        pass

    def due_bands(self, slot: int) -> list[tuple[int, float]]:
        return [(self.band, self.confidence)]

    def lower_confidence(self, band: int) -> float:
        return self.confidence


def _scheduler(k: int) -> SniperScheduler:
    config = make_test_config(n_bands=3, n_slots=100, k=k)
    scheduler = SniperScheduler(inner=UCB1Scheduler())
    scheduler.reset(config)
    scheduler._predictor = _DuePredictor(band=0)
    return scheduler


def test_prediction_is_logged_when_inner_action_already_contains_band():
    scheduler = _scheduler(k=2)

    action = scheduler.act(None)

    assert action.bands == (0, 1)
    assert scheduler.prediction_band == 0
    assert scheduler.prediction_confidence == pytest.approx(0.9)
    assert scheduler.inner_action == (0, 1)
    assert scheduler.executed_action == (0, 1)
    assert scheduler.did_override is False


def test_confident_prediction_replaces_one_inner_channel():
    scheduler = _scheduler(k=2)

    for slot in range(32):
        bands = (0, 1) if slot % 2 == 0 else (0, 2)
        scheduler.act(
            Observation(slot=slot, bands=bands, detections=(False, False))
        )

    action = scheduler.act(
        Observation(slot=32, bands=(0, 1), detections=(False, False))
    )

    assert 0 not in scheduler.inner_action
    assert 0 in action.bands
    assert len(set(action.bands) & set(scheduler.inner_action)) == 1
    assert scheduler.did_override is True
    assert scheduler.prediction_band == 0


@pytest.mark.parametrize("k", [1, 2, 3])
def test_arbitration_keeps_actions_distinct_for_every_k(k: int):
    scheduler = _scheduler(k)

    action = scheduler.act(None)

    assert len(action.bands) == k
    assert len(set(action.bands)) == k
    assert all(0 <= band < 3 for band in action.bands)


def test_telemetry_pairs_inner_and_sniper_actions_on_same_observations():
    config = get_scenario("periodic_radar")

    inner = run_episode(config, UCB1Scheduler(), seed=11)
    sniper = run_episode(
        config,
        SniperScheduler(inner=UCB1Scheduler(), tau_conf=2.0),
        seed=11,
    )

    assert sniper.arbitration is not None
    assert np.array_equal(sniper.arbitration.inner_action, inner.log.actions)
    assert np.array_equal(sniper.arbitration.executed_action, sniper.log.actions)
    assert not np.any(sniper.arbitration.did_override)


def test_arbitration_abstains_when_inner_uses_a_different_reward_scale():
    config = make_test_config(n_bands=3, n_slots=100, k=1)
    inner = UCB1Scheduler(c=0.0, reward_fn=RewardFunction())
    scheduler = SniperScheduler(inner=inner)
    scheduler.reset(config)
    scheduler._predictor = _DuePredictor(band=2, confidence=1.0)

    inner.stats.update(
        Observation(slot=0, bands=(0,), detections=(False,)), rewards=(0.0,)
    )
    inner.stats.update(
        Observation(slot=1, bands=(1,), detections=(True,)), rewards=(1.0,)
    )
    inner.stats.update(
        Observation(slot=2, bands=(2,), detections=(False,)), rewards=(0.0,)
    )

    action = scheduler.act(None)

    assert scheduler.inner_action == (1,)
    assert action.bands == (1,)
    assert scheduler.did_override is False
