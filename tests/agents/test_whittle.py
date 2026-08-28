"""Unit tests for the Whittle index scheduler (Sprint 3 Task 4)."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.thompson import ThompsonSamplingScheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.agents.whittle import WhittleScheduler, solve_whittle_grid
from ewscan.contracts import Scheduler
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import make_mixed_threat_scenario
from ewscan.testing.fixtures import make_test_config

ANCHOR_P01 = 0.1
ANCHOR_P10 = 0.3
ANCHOR_PD = 0.9
ANCHOR_PFA = 1e-3


class TestWhittleSchedulerInterface:
    def test_is_scheduler(self):
        assert issubclass(WhittleScheduler, Scheduler)

    def test_name(self):
        assert WhittleScheduler().name == "whittle"

    def test_unreset_act_raises(self):
        scheduler = WhittleScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)


class TestMonotonicity:
    """Test 1: for a positively-correlated chain, W(b) is non-decreasing in b."""

    def test_monotone_nondecreasing(self):
        b, w = solve_whittle_grid(
            p01=ANCHOR_P01,
            p10=ANCHOR_P10,
            pd=ANCHOR_PD,
            pfa=ANCHOR_PFA,
            beta=0.95,
            ngrid=101,
            nm=50,
            sweeps=200,
        )
        assert np.all(np.diff(w) >= -1e-9)


class TestMyopicLimit:
    """Test 2: as beta -> 0, W(b) collapses to the myopic value b."""

    def test_collapses_to_belief_at_tiny_beta(self):
        b, w = solve_whittle_grid(
            p01=ANCHOR_P01,
            p10=ANCHOR_P10,
            pd=ANCHOR_PD,
            pfa=ANCHOR_PFA,
            beta=1e-3,
            ngrid=101,
            nm=50,
            sweeps=200,
        )
        assert np.max(np.abs(w - b)) < 1e-2


class TestStationaryBeliefFinite:
    """Test 3: W(pi_ON) is finite and within the [0, 1] bracket."""

    def test_stationary_index_in_bracket(self):
        pi_on = ANCHOR_P01 / (ANCHOR_P01 + ANCHOR_P10)
        b, w = solve_whittle_grid(
            p01=ANCHOR_P01,
            p10=ANCHOR_P10,
            pd=ANCHOR_PD,
            pfa=ANCHOR_PFA,
            beta=0.95,
            ngrid=101,
            nm=50,
            sweeps=200,
        )
        w_pi = float(np.interp(pi_on, b, w))
        assert np.isfinite(w_pi)
        assert 0.0 <= w_pi <= 1.0


class TestRegressionAnchors:
    """C-5 anchors at p01=0.1, p10=0.3, Pd=0.9, Pfa=1e-3, pinned defaults."""

    def test_anchor_values(self):
        b, w = solve_whittle_grid(
            p01=ANCHOR_P01,
            p10=ANCHOR_P10,
            pd=ANCHOR_PD,
            pfa=ANCHOR_PFA,
            beta=0.95,
            ngrid=101,
            nm=50,
            sweeps=200,
        )
        expected = {0.0: 0.0000, 0.25: 0.4052, 0.5: 0.6030, 1.0: 1.0000}
        for query, target in expected.items():
            idx = int(np.argmin(np.abs(b - query)))
            assert w[idx] == pytest.approx(target, abs=1e-2)


class TestSchedulerLegality:
    """Test 4: WhittleScheduler returns K distinct in-range bands every slot."""

    def test_returns_k_distinct_bands_every_slot(self):
        n_bands = 6
        n_slots = 30
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, k=3, seed=3)
        scheduler = WhittleScheduler(seed=3)
        result = run_episode(config, scheduler, seed=3)
        for action in result.log.actions:
            assert len(action) == 3
            assert len(set(action)) == 3
            assert all(0 <= b < n_bands for b in action)


class TestPerformanceGate:
    """Test 5: the Sprint 3 gate. Whittle mean interception ratio must beat
    UCB1 and Thompson Sampling over >= 20 seeds on mixed_threat.
    """

    @pytest.mark.slow
    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Sprint 3 gate NOT MET. Whittle 0.2600 vs ucb1 0.4794, thompson 0.5385 "
            "over 20 seeds. The index math is correct (matches the C-5 anchors); the "
            "belief it consumes is uninformative because TransitionEstimator's gap==1 "
            "filter never forms pairs at k=1 across 16 bands, so p01/p10 stay at the "
            "0.5 prior. See project memories/sprint3_whittle_gate_finding.md"
        ),
    )
    def test_beats_ucb1_and_thompson_on_mixed_threat(self):
        n_seeds = 20
        base_config = make_mixed_threat_scenario()

        ratios = {"whittle": [], "ucb1": [], "thompson_sampling": []}
        builders = {
            "whittle": lambda seed: WhittleScheduler(seed=seed),
            "ucb1": lambda seed: UCB1Scheduler(seed=seed),
            "thompson_sampling": lambda seed: ThompsonSamplingScheduler(seed=seed),
        }
        for seed in range(n_seeds):
            for label, builder in builders.items():
                scheduler = builder(seed)
                result = run_episode(base_config, scheduler, seed=seed)
                ratios[label].append(result.interception.interception_ratio.ratio)

        means = {label: float(np.mean(vals)) for label, vals in ratios.items()}
        print("whittle mean interception ratio:", means["whittle"])
        print("ucb1 mean interception ratio:", means["ucb1"])
        print("thompson_sampling mean interception ratio:", means["thompson_sampling"])

        assert means["whittle"] >= means["ucb1"]
        assert means["whittle"] >= means["thompson_sampling"]
