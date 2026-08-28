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
    retune_cost_slots: int = 0,
    retune_events: np.ndarray | None = None,
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
        detection_threshold=None,
        pfa=1e-3,
        seed=0,
        retune_cost_slots=retune_cost_slots,
    )
    return EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=detections,
        retune_events=retune_events,
    )


class TestEmptyLog:
    def test_zero_slots_is_rejected(self):
        with pytest.raises(ValueError, match="n_slots"):
            _make_test_log(
                n_slots=0,
                truth=np.zeros((4, 0), dtype=bool),
                actions=np.array([], dtype=np.intp),
                detections=np.array([], dtype=bool),
            )


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
            + metrics.total_retune_penalty
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
        assert metrics.average_retune_penalty == pytest.approx(metrics.total_retune_penalty / n)

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

    def test_band_thrashing_pays_more_retune_penalty(self):
        common = dict(
            n_bands=2,
            n_slots=4,
            truth=np.ones((2, 4), dtype=bool),
            detections=np.ones(4, dtype=bool),
            retune_cost_slots=1,
        )
        sticky = _make_test_log(
            **common,
            actions=np.array([0, 0, 0, 0], dtype=np.intp),
            retune_events=np.array([False, False, False, False]),
        )
        thrashing = _make_test_log(
            **common,
            actions=np.array([0, 1, 0, 1], dtype=np.intp),
            retune_events=np.array([False, True, True, True]),
        )

        sticky_metrics = estimate_reward_metrics(sticky)
        thrashing_metrics = estimate_reward_metrics(thrashing)

        assert thrashing_metrics.total_retune_penalty < sticky_metrics.total_retune_penalty
        assert thrashing_metrics.total_reward < sticky_metrics.total_reward
