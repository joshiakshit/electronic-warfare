"""Tests for staleness bonus (Phase 1D.7).

Verification criterion (PLAN.md 1D.7):
    No band starved past a bounded interval in any scenario.
"""

from __future__ import annotations

import numpy as np

from ewscan.agents.nonstationary_ucb import DUCB1Scheduler, SWUCB1Scheduler
from ewscan.agents.thompson import (
    DiscountedThompsonScheduler,
    ThompsonSamplingScheduler,
)
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.testing.fixtures import ScriptedEnv, make_test_config


def _max_gap(actions: np.ndarray, band: int) -> int:
    """Return the longest consecutive run of slots where `band` was not selected."""
    max_g = 0
    current = 0
    for a in actions:
        if a == band:
            current = 0
        else:
            current += 1
            max_g = max(max_g, current)
    return max_g


def _make_starvation_env(n_slots: int = 300, seed: int = 42):
    """2 bands: Band 0 always ON (high reward), Band 1 always OFF (low reward)."""
    n_bands = 2
    truth = np.zeros((n_bands, n_slots), dtype=bool)
    truth[0, :] = True
    config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=seed)
    return config, truth


class TestThompsonStaleness:
    def test_starvation_without_bonus(self):
        config, truth = _make_starvation_env()
        env = ScriptedEnv(config, truth)
        sched = ThompsonSamplingScheduler(staleness_weight=0.0, seed=42)
        log = env.run(sched)

        band1_last100 = int(np.sum(log.actions[-100:] == 1))
        assert band1_last100 == 0

    def test_staleness_bonus_prevents_starvation(self):
        config, truth = _make_starvation_env()
        env = ScriptedEnv(config, truth)
        sched = ThompsonSamplingScheduler(staleness_weight=0.05, seed=42)
        log = env.run(sched)

        gap = _max_gap(log.actions, band=1)
        assert gap <= 30, f"Max starvation gap was {gap}, expected <= 30"


class TestDiscountedThompsonStaleness:
    def test_staleness_bonus_prevents_starvation(self):
        config, truth = _make_starvation_env()
        env = ScriptedEnv(config, truth)
        sched = DiscountedThompsonScheduler(staleness_weight=0.05, seed=42)
        log = env.run(sched)

        gap = _max_gap(log.actions, band=1)
        assert gap <= 30, f"Max starvation gap was {gap}, expected <= 30"


class TestUCB1Staleness:
    def test_staleness_bonus_prevents_starvation(self):
        config, truth = _make_starvation_env()
        env = ScriptedEnv(config, truth)
        sched = UCB1Scheduler(staleness_weight=0.05, seed=42)
        log = env.run(sched)

        gap = _max_gap(log.actions, band=1)
        assert gap <= 30, f"Max starvation gap was {gap}, expected <= 30"


class TestDUCB1Staleness:
    def test_staleness_bonus_prevents_starvation(self):
        config, truth = _make_starvation_env()
        env = ScriptedEnv(config, truth)
        sched = DUCB1Scheduler(staleness_weight=0.05, seed=42)
        log = env.run(sched)

        gap = _max_gap(log.actions, band=1)
        assert gap <= 30, f"Max starvation gap was {gap}, expected <= 30"


class TestSWUCB1Staleness:
    def test_staleness_bonus_prevents_starvation(self):
        config, truth = _make_starvation_env()
        env = ScriptedEnv(config, truth)
        sched = SWUCB1Scheduler(staleness_weight=0.05, seed=42)
        log = env.run(sched)

        gap = _max_gap(log.actions, band=1)
        assert gap <= 30, f"Max starvation gap was {gap}, expected <= 30"
