"""Tests for average reward accumulator and cost readout estimators -- Phase 1E.4.

Verify criteria (PLAN.md 1E.4):
    Sums agree with the reward-design unit tests.
    Component breakdowns (hit reward, miss cost, novelty bonus, revisit decay) add up to total reward.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.reward import (
    RewardMetrics,
    estimate_average_reward,
    estimate_reward_metrics,
)


def _make_test_log(
    n_bands: int = 4,
    n_slots: int = 8,
    truth: np.ndarray | None = None,
    actions: np.ndarray | None = None,
    detections: np.ndarray | None = None,
    threat_level: float = 1.0,
) -> EpisodeLog:
    if truth is None:
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, :] = True
    if actions is None:
        actions = np.array([0, 0, 1, 2, 3, 0, 0, 1], dtype=np.intp)
    if detections is None:
        detections = np.array([truth[actions[t], t] for t in range(n_slots)], dtype=np.bool_)

    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=(EmitterInfo(band=0, snr=20.0, threat_level=threat_level, emitter_type="cw"),),
        detection_threshold=3.0,
        pfa=1e-3,
        seed=0,
    )
    return EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)


class TestEmptyLog:
    def test_zero_slots_returns_nans_and_zeros(self):
        log = _make_test_log(n_slots=0, truth=np.zeros((4, 0), dtype=bool), actions=np.array([], dtype=np.intp), detections=np.array([], dtype=bool))
        metrics = estimate_reward_metrics(log)

        assert metrics.n_slots == 0
        assert metrics.total_reward == 0.0
        assert math.isnan(metrics.average_reward)
        assert metrics.total_hit_reward == 0.0
        assert metrics.total_miss_cost == 0.0
        assert metrics.total_novelty_bonus == 0.0
        assert metrics.total_revisit_decay == 0.0
        assert math.isnan(metrics.average_hit_reward)
        assert math.isnan(metrics.average_miss_cost)
        assert math.isnan(metrics.average_novelty_bonus)
        assert math.isnan(metrics.average_revisit_decay)
        assert len(metrics.per_slot_rewards) == 0

        avg_reward = estimate_average_reward(log)
        assert math.isnan(avg_reward)


class TestRewardAccumulatorAgreement:
    """Verify that metrics agree with RewardFunction unit tests."""

    def test_per_slot_rewards_match_reward_function(self):
        log = _make_test_log()
        rf = RewardFunction()
        metrics = estimate_reward_metrics(log, rf=rf)
        expected_per_slot = rf.compute_episode(log)

        np.testing.assert_allclose(metrics.per_slot_rewards, expected_per_slot)

    def test_sum_of_components_equals_total_reward(self):
        log = _make_test_log()
        metrics = estimate_reward_metrics(log)

        component_sum = (
            metrics.total_hit_reward
            + metrics.total_miss_cost
            + metrics.total_novelty_bonus
            + metrics.total_revisit_decay
        )
        assert metrics.total_reward == pytest.approx(component_sum)
        assert metrics.total_reward == pytest.approx(float(np.sum(metrics.per_slot_rewards)))

    def test_averages_equal_totals_divided_by_n_slots(self):
        log = _make_test_log()
        metrics = estimate_reward_metrics(log)
        n = log.n_slots

        assert metrics.average_reward == pytest.approx(metrics.total_reward / n)
        assert metrics.average_hit_reward == pytest.approx(metrics.total_hit_reward / n)
        assert metrics.average_miss_cost == pytest.approx(metrics.total_miss_cost / n)
        assert metrics.average_novelty_bonus == pytest.approx(metrics.total_novelty_bonus / n)
        assert metrics.average_revisit_decay == pytest.approx(metrics.total_revisit_decay / n)

    def test_single_slot_scenario_1_stale_max_threat(self):
        # 16 bands, 1 slot, visit band 0, detect threat=1.0, staleness=16
        log = _make_test_log(
            n_bands=16,
            n_slots=1,
            truth=np.ones((16, 1), dtype=bool),
            actions=np.array([0], dtype=np.intp),
            detections=np.array([True], dtype=bool),
            threat_level=1.0,
        )
        metrics = estimate_reward_metrics(log)
        # Expected components: hit=1.0, miss=0.0, novelty=0.2, decay=0.0 -> total 1.2
        assert metrics.total_hit_reward == pytest.approx(1.0)
        assert metrics.total_miss_cost == pytest.approx(0.0)
        assert metrics.total_novelty_bonus == pytest.approx(0.2)
        assert metrics.total_revisit_decay == pytest.approx(0.0)
        assert metrics.total_reward == pytest.approx(1.2)
        assert metrics.average_reward == pytest.approx(1.2)

    def test_custom_reward_function_parameters(self):
        log = _make_test_log()
        custom_rf = RewardFunction(w_threat=2.0, c_miss=0.5, w_novelty=0.4, w_decay=0.6)
        metrics = estimate_reward_metrics(log, rf=custom_rf)

        expected_per_slot = custom_rf.compute_episode(log)
        np.testing.assert_allclose(metrics.per_slot_rewards, expected_per_slot)
        assert metrics.total_reward == pytest.approx(float(np.sum(expected_per_slot)))

    def test_estimate_average_reward_helper(self):
        log = _make_test_log()
        metrics = estimate_reward_metrics(log)
        avg = estimate_average_reward(log)
        assert avg == pytest.approx(metrics.average_reward)
