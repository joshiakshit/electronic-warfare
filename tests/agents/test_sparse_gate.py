"""Sparse-observation performance gates at the operational k=1 setting.

The blind track only. Each gate runs paired seeds: every scheduler sees the
same scenario and the same seed, so the truth matrix is identical and the
per-seed difference removes scenario variance. A gate passes only when the
95% confidence interval of the paired difference lies entirely above zero
against BOTH stationary bandit baselines.
"""

from __future__ import annotations

import time

import numpy as np
import pytest

from ewscan.agents.pomdp import BeliefScheduler
from ewscan.agents.sniper import SniperScheduler
from ewscan.agents.thompson import ThompsonSamplingScheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import get_scenario
from ewscan.metrics.aggregation import student_t_critical

N_SEEDS = 30
SEEDS = range(N_SEEDS)


def _interception_by_seed(scenario_name, factory):
    scores = []
    for seed in SEEDS:
        config = get_scenario(scenario_name)
        result = run_episode(config, factory(), seed=seed)
        scores.append(result.interception.interception_ratio.ratio)
    return np.asarray(scores, dtype=np.float64)


def _paired_ci(candidate, baseline, confidence=0.95):
    """Return (mean_difference, ci_lower, ci_upper) for candidate - baseline."""
    diff = candidate - baseline
    mean = float(diff.mean())
    n = len(diff)
    sem = float(diff.std(ddof=1) / np.sqrt(n))
    if sem == 0.0:
        return mean, mean, mean
    half = student_t_critical(confidence, df=n - 1) * sem
    return mean, mean - half, mean + half


def _assert_beats_baselines(scenario_name, factory, label):
    candidate = _interception_by_seed(scenario_name, factory)
    ucb1 = _interception_by_seed(scenario_name, UCB1Scheduler)
    thompson = _interception_by_seed(scenario_name, ThompsonSamplingScheduler)

    report = [
        f"\n[gate] {scenario_name} / {label}, {N_SEEDS} paired seeds",
        f"  {label:18s} mean={candidate.mean():.4f}",
        f"  {'ucb1':18s} mean={ucb1.mean():.4f}",
        f"  {'thompson_sampling':18s} mean={thompson.mean():.4f}",
    ]
    failures = []
    for name, baseline in (("ucb1", ucb1), ("thompson_sampling", thompson)):
        mean, low, high = _paired_ci(candidate, baseline)
        report.append(
            f"  paired diff vs {name:18s} {mean:+.4f}  95% CI [{low:+.4f}, {high:+.4f}]"
        )
        if low <= 0.0:
            failures.append(f"{label} does not clear {name}: CI lower bound {low:+.4f}")
    print("\n".join(report))
    assert not failures, "; ".join(failures)


@pytest.mark.slow
class TestSparseInterceptionGates:
    """The operational gate: beat both stationary bandits at k=1 over 16 bands."""

    def test_belief_beats_baselines_on_mixed_threat(self):
        _assert_beats_baselines("mixed_threat", BeliefScheduler, "belief")

    def test_sniper_beats_baselines_on_periodic_radar(self):
        _assert_beats_baselines("periodic_radar", SniperScheduler, "sniper")


@pytest.mark.slow
class TestRuntimeCeiling:
    """No scheduler may exceed 5x the UCB1 per-episode runtime."""

    @pytest.mark.parametrize("scenario_name", ("mixed_threat", "periodic_radar"))
    @pytest.mark.parametrize(
        "factory,label", ((BeliefScheduler, "belief"), (SniperScheduler, "sniper"))
    )
    def test_per_episode_runtime_within_5x_ucb1(self, scenario_name, factory, label):
        def elapsed(build):
            start = time.perf_counter()
            for seed in range(5):
                run_episode(get_scenario(scenario_name), build(), seed=seed)
            return time.perf_counter() - start

        baseline = elapsed(UCB1Scheduler)
        candidate = elapsed(factory)
        ratio = candidate / baseline
        print(f"\n[runtime] {scenario_name} / {label}: {ratio:.2f}x ucb1")
        assert ratio <= 5.0, f"{label} runs at {ratio:.2f}x ucb1 on {scenario_name}"
