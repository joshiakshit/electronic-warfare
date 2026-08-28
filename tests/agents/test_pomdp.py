"""Unit tests for the POMDP belief tracker and scheduler (Sprint 3 Task 3)."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.pomdp import BeliefScheduler, BeliefTracker
from ewscan.agents.transition import TransitionEstimator
from ewscan.contracts import EmitterInfo, Observation, Scheduler
from ewscan.env.environment import RFEnvironment
from ewscan.testing.fixtures import make_test_config


class TestBeliefSchedulerInterface:
    def test_is_scheduler(self):
        assert issubclass(BeliefScheduler, Scheduler)

    def test_name(self):
        assert BeliefScheduler().name == "belief"

    def test_unreset_act_raises(self):
        scheduler = BeliefScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)


class TestStationaryConvergence:
    """Test 1: predict-only iteration converges to pi_ON = p01/(p01+p10)."""

    @pytest.mark.parametrize("b0", [0.0, 1.0, 0.5])
    def test_converges_to_stationary_pi_on(self, b0):
        tracker = BeliefTracker(1, pd_nominal=0.9, pfa=1e-3)
        tracker._belief = np.array([b0], dtype=np.float64)
        p01 = np.array([0.1])
        p10 = np.array([0.3])
        for _ in range(200):
            tracker.predict(p01, p10)
        assert tracker.belief[0] == pytest.approx(0.25, abs=1e-6)


class TestPerfectSensorCollapse:
    """Test 2: Pd=1, Pfa=0 collapses belief to 1 (detection) or 0 (no detection)."""

    def test_detection_sets_belief_to_one(self):
        tracker = BeliefTracker(1, pd_nominal=1.0, pfa=0.0)
        tracker.reset(np.array([0.3]), np.array([0.7]))  # pi_on = 0.3
        tracker.correct(0, True)
        assert tracker.belief[0] == pytest.approx(1.0, abs=1e-12)

    def test_nondetection_sets_belief_to_zero(self):
        tracker = BeliefTracker(1, pd_nominal=1.0, pfa=0.0)
        tracker.reset(np.array([0.3]), np.array([0.7]))  # pi_on = 0.3
        tracker.correct(0, False)
        assert tracker.belief[0] == pytest.approx(0.0, abs=1e-12)


class TestBayesArithmetic:
    """Test 3: b_pred=0.5, Pd=0.9, Pfa=0.1 -> 0.9 on detect, 0.1 on non-detect."""

    def test_detection_updates_to_point_nine(self):
        tracker = BeliefTracker(1, pd_nominal=0.9, pfa=0.1)
        tracker.reset(np.array([0.5]), np.array([0.5]))  # pi_on = 0.5
        tracker.correct(0, True)
        assert tracker.belief[0] == pytest.approx(0.9, abs=1e-9)

    def test_nondetection_updates_to_point_one(self):
        tracker = BeliefTracker(1, pd_nominal=0.9, pfa=0.1)
        tracker.reset(np.array([0.5]), np.array([0.5]))  # pi_on = 0.5
        tracker.correct(0, False)
        assert tracker.belief[0] == pytest.approx(0.1, abs=1e-9)


class TestSettlingSkipsCorrection:
    """Test 4: a settling observation carries the predict-only result."""

    def test_settling_observation_uses_predict_only(self):
        config = make_test_config(n_bands=1, n_slots=5, k=1)
        scheduler = BeliefScheduler(pd_nominal=0.9, seed=0)
        scheduler.reset(config)

        scheduler.act(None)
        belief_before_settling = scheduler.belief.copy()

        settling_obs = Observation(slot=0, bands=(0,), detections=(True,), settling=True)
        scheduler.act(settling_obs)
        actual = scheduler.belief.copy()

        # transition.observe must also be skipped on settling, so p01/p10 stay
        # at the untouched Laplace prior (0.5/0.5) here.
        expected_tracker = BeliefTracker(1, pd_nominal=0.9, pfa=config.pfa)
        expected_tracker._belief = belief_before_settling.copy()
        fresh_transition = TransitionEstimator(1)
        expected_tracker.predict(fresh_transition.p01(), fresh_transition.p10())

        assert actual[0] == pytest.approx(expected_tracker.belief[0], abs=1e-12)


class TestDegenerateLikelihoodGuard:
    """Divide-by-zero trap: Pd=Pfa=0 with d=1 makes the Bayes denominator 0."""

    def test_zero_denominator_leaves_belief_unchanged(self):
        tracker = BeliefTracker(1, pd_nominal=0.0, pfa=0.0)
        tracker.reset(np.array([0.4]), np.array([0.6]))  # pi_on = 0.4
        before = tracker.belief.copy()
        tracker.correct(0, True)
        assert tracker.belief[0] == pytest.approx(before[0])


class TestBeliefClipping:
    """Belief must be clipped to [0, 1] after every predict/correct call."""

    def test_predict_clips_overshoot(self):
        tracker = BeliefTracker(1, pd_nominal=0.9, pfa=0.1)
        tracker._belief = np.array([1.5], dtype=np.float64)
        tracker.predict(np.array([0.1]), np.array([0.1]))
        assert 0.0 <= tracker.belief[0] <= 1.0

    def test_correct_clips_overshoot(self):
        tracker = BeliefTracker(1, pd_nominal=0.9, pfa=0.1)
        tracker._belief = np.array([1.5], dtype=np.float64)
        tracker.correct(0, True)
        assert 0.0 <= tracker.belief[0] <= 1.0


class TestBeliefTrajectoryOrderGuard:
    """The real predict/correct ordering guard (Addendum D).

    Test 5's aggregate accuracy does NOT distinguish correct order from
    reversed order (verified: identical to 4 decimals across a wide sweep).
    This test pins the literal belief trajectory instead, with p01=p10=0.5
    (no transition data) so predict() always maps belief to exactly 0.5 and
    any surviving signal must come from correction happening before predict.
    """

    def test_belief_trajectory_pins_correct_then_predict_order(self):
        emitters = (
            EmitterInfo(
                band=0,
                snr=20.0,
                threat_level=1.0,
                emitter_type="gilbert_elliott",
                params={"p01": 0.2, "p10": 0.2},
            ),
        )
        config = make_test_config(
            n_bands=1, n_slots=20, k=1, pfa=0.1, emitters=emitters, seed=0
        )
        scheduler = BeliefScheduler(pd_nominal=0.9, seed=0)
        scheduler.reset(config)

        detections = [True, True, False, False, True, False, True, True]
        expected = [
            0.5,
            0.5,
            0.65,
            0.5,
            0.35,
            0.5,
            0.49,
            0.4207317073,
            0.5132681564,
        ]

        scheduler.act(None)
        trajectory = [scheduler.belief[0]]
        for slot, det in enumerate(detections):
            scheduler.act(Observation(slot=slot, bands=(0,), detections=(det,)))
            trajectory.append(scheduler.belief[0])

        for i in range(6):
            assert trajectory[i] == pytest.approx(expected[i], abs=1e-9)


class TestTracksTruth:
    """Test 5: integration, tracking accuracy on a strong Markov emitter.

    This threshold is deliberately tight: reversing the predict/correct order
    in BeliefScheduler.act lags the belief by one slot and drops accuracy well
    below 85% on this scenario.
    """

    def test_tracks_markov_emitter_after_warmup(self):
        n_slots = 400
        emitters = (
            EmitterInfo(
                band=0,
                snr=20.0,
                threat_level=1.0,
                emitter_type="gilbert_elliott",
                params={"p01": 0.1, "p10": 0.1},
            ),
        )
        config = make_test_config(
            n_bands=1, n_slots=n_slots, k=1, pfa=1e-3, emitters=emitters, seed=7
        )
        env = RFEnvironment(config=config)
        env.reset()
        scheduler = BeliefScheduler(pd_nominal=0.9, seed=7)
        scheduler.reset(config)

        truth = env.truth[0]
        predicted_on = np.zeros(n_slots, dtype=bool)

        obs = None
        for t in range(n_slots):
            action = scheduler.act(obs)
            obs = env.step(action)
            predicted_on[t] = scheduler.belief[0] > 0.5

        warmup = 50
        accuracy = (predicted_on[warmup:] == truth[warmup:]).mean()
        assert accuracy > 0.85


class TestSchedulerLegality:
    """Test 6: BeliefScheduler returns K distinct in-range bands every slot."""

    def test_returns_k_distinct_bands_every_slot(self):
        n_bands = 6
        n_slots = 30
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, k=3, seed=3)
        env = RFEnvironment(config=config)
        env.reset()
        scheduler = BeliefScheduler(seed=3)
        scheduler.reset(config)

        obs = None
        for _ in range(n_slots):
            action = scheduler.act(obs)
            assert len(action.bands) == 3
            assert len(set(action.bands)) == 3
            assert all(0 <= b < n_bands for b in action.bands)
            obs = env.step(action)
