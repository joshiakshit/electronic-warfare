"""Objective 4: hand-built edge-case scenarios exercised through the runner."""

from __future__ import annotations

import math

import numpy as np

from ewscan.agents.baselines import RoundRobinScheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig
from ewscan.experiments.runner import run_episode
from ewscan.testing.fixtures import StubScheduler


def _cfg(emitters, n_bands=4, n_slots=16, k=1) -> EpisodeConfig:
    return EpisodeConfig(
        n_bands=n_bands, n_slots=n_slots, k=k, emitters=tuple(emitters), pfa=1e-4, seed=0
    )


def test_no_emitters():
    res = run_episode(_cfg(()), RoundRobinScheduler(), seed=1)
    assert res.log.emitter_truth.shape == (0, 16)
    assert math.isnan(res.interception.interception_ratio.ratio)
    assert res.first_intercept.n_emitters == 0
    assert res.evaluation.n_true_positive == 0


def test_no_transmissions():
    # Markov emitter frozen OFF: p01=0, p10=0, initial_state=0.
    em = EmitterInfo(
        band=0, snr=20.0, threat_level=1.0, emitter_type="gilbert_elliott",
        params={"p01": 0.0, "p10": 0.0, "initial_state": 0},
    )
    res = run_episode(_cfg((em,)), RoundRobinScheduler(), seed=1)
    assert res.log.truth.sum() == 0
    assert math.isnan(res.interception.interception_ratio.ratio)
    assert res.first_intercept.n_intercepted == 0


def test_no_interceptions():
    # Emitter on band 0; stub always scans band 1, so it is never intercepted.
    em = EmitterInfo(band=0, snr=30.0, threat_level=1.0, emitter_type="cw")
    res = run_episode(_cfg((em,)), StubScheduler(bands=1), seed=1)
    assert res.interception.interception_ratio.n_transmissions == 16
    assert res.interception.interception_ratio.ratio == 0.0
    assert res.first_intercept.n_intercepted == 0
    assert res.first_intercept.intercept_fraction == 0.0
    # Missed emitter charged the full horizon.
    assert res.first_intercept.mean_time_to_first_intercept_penalized == 16.0


def test_all_bands_active():
    emitters = [
        EmitterInfo(band=b, snr=30.0, threat_level=1.0, emitter_type="cw")
        for b in range(4)
    ]
    res = run_episode(_cfg(emitters), RoundRobinScheduler(), seed=1)
    # Every band-slot is a transmission; round robin visits 1 of 4 each slot.
    assert res.interception.interception_ratio.n_transmissions == 4 * 16
    assert res.first_intercept.n_intercepted == 4


def test_k_equal_to_n():
    emitters = [
        EmitterInfo(band=b, snr=30.0, threat_level=1.0, emitter_type="cw")
        for b in range(4)
    ]
    res = run_episode(_cfg(emitters, k=4), RoundRobinScheduler(), seed=1)
    # With k == n_bands the receiver scans every band every slot: full intercept.
    assert res.interception.interception_ratio.ratio == 1.0
    assert res.first_intercept.n_intercepted == 4


def test_k_greater_than_one():
    emitters = [
        EmitterInfo(band=0, snr=30.0, threat_level=1.0, emitter_type="cw"),
        EmitterInfo(band=2, snr=30.0, threat_level=1.0, emitter_type="cw"),
    ]
    res = run_episode(_cfg(emitters, k=2), RoundRobinScheduler(), seed=1)
    assert res.log.actions.shape == (16, 2)
    assert res.first_intercept.n_intercepted == 2
