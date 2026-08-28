"""Objective 4: learner reward vs truth-based evaluation utility."""

from __future__ import annotations

import numpy as np

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.reward import (
    estimate_evaluation_utility,
    estimate_reward_metrics,
)


def _quiet_log(detections, valid=None) -> EpisodeLog:
    n_bands, n_slots = 2, len(detections)
    truth = np.zeros((n_bands, n_slots), dtype=bool)  # all bands quiet
    actions = np.zeros((n_slots, 1), dtype=np.intp)
    dets = np.array(detections, dtype=bool).reshape(n_slots, 1)
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
        pfa=1e-3,
        seed=0,
    )
    return EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=dets,
        valid_slots=None if valid is None else np.array(valid, dtype=bool),
    )


def test_learner_reward_can_reward_false_alarm_but_utility_does_not():
    # Band 0 is quiet; a detection there is a false alarm.
    log = _quiet_log([True])
    learner = estimate_reward_metrics(log)
    evaluation = estimate_evaluation_utility(log)

    assert learner.total_hit_reward > 0.0  # observation-based reward is fooled
    assert evaluation.n_true_positive == 0
    assert evaluation.total_utility <= 0.0  # truth-based utility never credits it


def test_evaluation_utility_scores_true_positive():
    n_bands, n_slots = 2, 2
    truth = np.zeros((n_bands, n_slots), dtype=bool)
    truth[0, :] = True  # band 0 transmitting
    actions = np.zeros((n_slots, 1), dtype=np.intp)
    detections = np.array([[True], [False]], dtype=bool)
    config = EpisodeConfig(
        n_bands=n_bands, n_slots=n_slots, k=1,
        emitters=(EmitterInfo(band=0, snr=20.0, threat_level=2.0, emitter_type="cw"),),
        pfa=1e-3, seed=0,
    )
    log = EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)
    evaluation = estimate_evaluation_utility(log)
    assert evaluation.n_true_positive == 1  # slot 0 hit
    assert evaluation.n_false_negative == 1  # slot 1 missed real signal
    assert evaluation.total_utility == 2.0 - evaluation.miss_cost_used  # threat 2.0 hit minus one miss


def test_evaluation_utility_skips_invalid_slots():
    n_bands, n_slots = 2, 2
    truth = np.zeros((n_bands, n_slots), dtype=bool)
    truth[0, :] = True
    actions = np.zeros((n_slots, 1), dtype=np.intp)
    detections = np.array([[True], [True]], dtype=bool)
    config = EpisodeConfig(
        n_bands=n_bands, n_slots=n_slots, k=1,
        emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
        pfa=1e-3, seed=0,
    )
    log = EpisodeLog(
        config=config, truth=truth, actions=actions, detections=detections,
        valid_slots=np.array([True, False], dtype=bool),
    )
    evaluation = estimate_evaluation_utility(log)
    assert evaluation.n_true_positive == 1  # slot 1 skipped
