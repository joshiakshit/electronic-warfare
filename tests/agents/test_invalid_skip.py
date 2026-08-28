"""Objective 4: every learning scheduler skips invalid observations."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.nonstationary_ucb import DUCB1Scheduler, SWUCB1Scheduler
from ewscan.agents.pomdp import BeliefScheduler
from ewscan.agents.sniper import SniperScheduler
from ewscan.agents.thompson import (
    DiscountedThompsonScheduler,
    ThompsonSamplingScheduler,
)
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import Observation, SchedulerConfig
from ewscan.detector import make_detector_capability


def _config(n_bands=3) -> SchedulerConfig:
    return SchedulerConfig(
        n_bands=n_bands,
        n_slots=20,
        k=1,
        detector_capability=make_detector_capability(pfa=1e-3, threshold=None, dwell=1),
        seed=0,
    )


STATS_LEARNERS = [
    lambda: UCB1Scheduler(seed=0),
    lambda: DUCB1Scheduler(seed=0),
    lambda: SWUCB1Scheduler(seed=0),
    lambda: ThompsonSamplingScheduler(seed=0),
    lambda: DiscountedThompsonScheduler(seed=0),
]


@pytest.mark.parametrize("factory", STATS_LEARNERS)
def test_invalid_obs_does_not_update_stats(factory):
    s = factory()
    s.reset(_config())
    s.act(None)
    invalid = Observation(slot=0, bands=(0,), detections=(True,), settling=True, valid=False)
    s.act(invalid)
    assert s.stats.total_pulls == 0

    valid = Observation(slot=1, bands=(0,), detections=(True,), valid=True)
    s.act(valid)
    assert s.stats.total_pulls == 1


def test_belief_ignores_invalid_obs():
    s = BeliefScheduler(seed=0)
    s.reset(_config())
    s.act(None)
    before = s.belief.copy()
    invalid = Observation(slot=0, bands=(0,), detections=(True,), settling=True, valid=False)
    s.act(invalid)
    # Predict still advances belief, but the invalid measurement must not
    # correct band 0 differently than an unobserved band.
    s2 = BeliefScheduler(seed=0)
    s2.reset(_config())
    s2.act(None)
    s2.act(Observation(slot=0, bands=(0,), detections=(True,), settling=True, valid=False))
    np.testing.assert_allclose(s.belief, s2.belief)


def test_sniper_inner_skips_invalid_obs():
    s = SniperScheduler(inner=UCB1Scheduler())
    s.reset(_config())
    s.act(None)
    invalid = Observation(slot=0, bands=(0,), detections=(True,), settling=True, valid=False)
    s.act(invalid)
    assert s._inner.stats.total_pulls == 0
