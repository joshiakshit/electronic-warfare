"""Tests for ewscan.testing.fixtures -- 1A.5 verification.

Verify criterion (PLAN.md 1A.5):
    Track A can test metrics and Track B can test agents, neither needing
    the other.

These tests prove the fixtures produce valid, consistent data that both
tracks can build on independently.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import (
    EpisodeConfig,
    EpisodeLog,
    Observation,
    ScanAction,
    Scheduler,
)
from ewscan.testing import (
    ScriptedEnv,
    StubScheduler,
    make_test_config,
    scripted_observations,
    synthetic_log,
)


# -----------------------------------------------------------------------
# make_test_config
# -----------------------------------------------------------------------

class TestMakeTestConfig:
    def test_defaults(self):
        cfg = make_test_config()
        assert cfg.n_bands == 4
        assert cfg.n_slots == 20
        assert cfg.k == 1
        assert cfg.seed == 0

    def test_custom_values(self):
        cfg = make_test_config(n_bands=16, n_slots=2000, k=2, seed=42)
        assert cfg.n_bands == 16
        assert cfg.n_slots == 2000
        assert cfg.k == 2
        assert cfg.seed == 42


# -----------------------------------------------------------------------
# scripted_observations
# -----------------------------------------------------------------------

class TestScriptedObservations:
    def test_builds_correct_observations(self):
        specs = [(0, 2, True), (1, 3, False), (2, 0, True)]
        obs = scripted_observations(specs)
        assert len(obs) == 3
        assert obs[0] == Observation(slot=0, band=2, detection=True)
        assert obs[1] == Observation(slot=1, band=3, detection=False)
        assert obs[2] == Observation(slot=2, band=0, detection=True)

    def test_empty_sequence(self):
        assert scripted_observations([]) == []

    def test_scheduler_can_consume(self):
        """Track B use case: feed observations to a scheduler."""
        specs = [(0, 0, True), (1, 1, False), (2, 0, True)]
        obs_list = scripted_observations(specs)

        sched = StubScheduler(bands=0)
        sched.reset(make_test_config())
        sched.act(None)
        for obs in obs_list:
            action = sched.act(obs)
            assert isinstance(action, ScanAction)


# -----------------------------------------------------------------------
# synthetic_log -- Track A metric testing
# -----------------------------------------------------------------------

class TestSyntheticLog:
    def test_shapes_and_types(self):
        log = synthetic_log()
        assert isinstance(log, EpisodeLog)
        assert log.truth.shape == (4, 20)
        assert log.truth.dtype == np.bool_
        assert log.actions.shape == (20,)
        assert log.actions.dtype == np.intp
        assert log.detections.shape == (20,)
        assert log.detections.dtype == np.bool_

    def test_config_matches(self):
        log = synthetic_log()
        assert log.n_bands == 4
        assert log.n_slots == 20
        assert log.config.k == 1

    def test_deterministic(self):
        a = synthetic_log(seed=7)
        b = synthetic_log(seed=7)
        np.testing.assert_array_equal(a.truth, b.truth)
        np.testing.assert_array_equal(a.actions, b.actions)
        np.testing.assert_array_equal(a.detections, b.detections)

    def test_truth_band0_always_on(self):
        log = synthetic_log()
        assert log.truth[0].all()

    def test_truth_band1_bursty(self):
        log = synthetic_log()
        assert log.truth[1, 5:10].all()
        assert not log.truth[1, :5].any()
        assert not log.truth[1, 10:].any()

    def test_truth_band2_periodic(self):
        log = synthetic_log()
        for t in range(20):
            expected = t % 3 == 0
            assert log.truth[2, t] == expected, f"slot {t}"

    def test_truth_band3_off(self):
        log = synthetic_log()
        assert not log.truth[3].any()

    def test_actions_are_round_robin(self):
        log = synthetic_log()
        for t in range(20):
            assert log.actions[t] == t % 4, f"slot {t}"

    def test_detections_match_truth_at_scanned_bands(self):
        log = synthetic_log()
        for t in range(20):
            band = log.actions[t]
            assert log.detections[t] == log.truth[band, t], f"slot {t}"

    def test_known_total_active_band_slots(self):
        log = synthetic_log()
        assert log.truth.sum() == 32

    def test_known_hit_count(self):
        log = synthetic_log()
        assert log.detections.sum() == 9

    def test_known_hits_per_band(self):
        log = synthetic_log()
        hits = [0, 0, 0, 0]
        for t in range(20):
            if log.detections[t]:
                hits[log.actions[t]] += 1
        assert hits == [5, 2, 2, 0]

    def test_known_first_intercept(self):
        log = synthetic_log()
        first = {}
        for t in range(20):
            band = log.actions[t]
            if log.detections[t] and band not in first:
                first[band] = t
        assert first[0] == 0
        assert first[1] == 5
        assert first[2] == 6
        assert 3 not in first

    def test_custom_size(self):
        log = synthetic_log(n_bands=16, n_slots=200)
        assert log.truth.shape == (16, 200)
        assert log.actions.shape == (200,)

    def test_emitters_match_bands(self):
        log = synthetic_log()
        bands_in_emitters = {e.band for e in log.config.emitters}
        assert bands_in_emitters == {0, 1, 2}


# -----------------------------------------------------------------------
# StubScheduler
# -----------------------------------------------------------------------

class TestStubScheduler:
    def test_is_a_scheduler(self):
        assert issubclass(StubScheduler, Scheduler)

    def test_default_always_band_0(self):
        s = StubScheduler()
        s.reset(make_test_config())
        for _ in range(10):
            assert s.act(None).band == 0

    def test_custom_single_band(self):
        s = StubScheduler(bands=3)
        s.reset(make_test_config())
        for _ in range(10):
            assert s.act(None).band == 3

    def test_cycling_sequence(self):
        s = StubScheduler(bands=[0, 2, 1])
        s.reset(make_test_config())
        assert s.act(None).band == 0
        assert s.act(None).band == 2
        assert s.act(None).band == 1
        assert s.act(None).band == 0

    def test_reset_restarts_sequence(self):
        s = StubScheduler(bands=[0, 1])
        cfg = make_test_config()
        s.reset(cfg)
        assert s.act(None).band == 0
        assert s.act(None).band == 1
        s.reset(cfg)
        assert s.act(None).band == 0

    def test_name(self):
        assert StubScheduler().name == "stub"


# -----------------------------------------------------------------------
# ScriptedEnv
# -----------------------------------------------------------------------

class TestScriptedEnv:
    def _make_env(self):
        cfg = make_test_config(n_bands=3, n_slots=5)
        truth = np.zeros((3, 5), dtype=np.bool_)
        truth[0, :] = True
        truth[1, 2] = True
        return ScriptedEnv(cfg, truth), cfg, truth

    def test_step_returns_correct_observation(self):
        env, _, _ = self._make_env()
        obs = env.step(ScanAction(band=0))
        assert obs == Observation(slot=0, band=0, detection=True)
        obs = env.step(ScanAction(band=1))
        assert obs == Observation(slot=1, band=1, detection=False)

    def test_step_advances_slot(self):
        env, _, _ = self._make_env()
        assert env.slot == 0
        env.step(ScanAction(band=0))
        assert env.slot == 1

    def test_done_flag(self):
        env, cfg, _ = self._make_env()
        assert not env.done
        for _ in range(cfg.n_slots):
            env.step(ScanAction(band=0))
        assert env.done

    def test_step_past_end_raises(self):
        env, cfg, _ = self._make_env()
        for _ in range(cfg.n_slots):
            env.step(ScanAction(band=0))
        with pytest.raises(IndexError):
            env.step(ScanAction(band=0))

    def test_reset(self):
        env, _, _ = self._make_env()
        env.step(ScanAction(band=0))
        env.reset()
        assert env.slot == 0
        assert not env.done

    def test_shape_mismatch_raises(self):
        cfg = make_test_config(n_bands=4, n_slots=10)
        bad_truth = np.zeros((3, 10), dtype=np.bool_)
        with pytest.raises(ValueError, match="does not match config"):
            ScriptedEnv(cfg, bad_truth)

    def test_run_produces_valid_log(self):
        log = synthetic_log()
        env = ScriptedEnv(log.config, log.truth)
        sched = StubScheduler(bands=list(range(log.n_bands)))
        result = env.run(sched)
        assert isinstance(result, EpisodeLog)
        assert result.truth.shape == (log.n_bands, log.n_slots)
        assert result.actions.shape == (log.n_slots,)
        assert result.detections.shape == (log.n_slots,)

    def test_run_deterministic(self):
        log = synthetic_log()
        env = ScriptedEnv(log.config, log.truth)
        sched = StubScheduler(bands=list(range(log.n_bands)))

        a = env.run(sched)
        b = env.run(sched)
        np.testing.assert_array_equal(a.actions, b.actions)
        np.testing.assert_array_equal(a.detections, b.detections)

    def test_run_with_round_robin_matches_synthetic_log(self):
        """ScriptedEnv.run with a round-robin stub must produce the same
        log as synthetic_log, since both use the same truth and scan pattern."""
        expected = synthetic_log()
        env = ScriptedEnv(expected.config, expected.truth.copy())
        sched = StubScheduler(bands=list(range(expected.n_bands)))
        result = env.run(sched)
        np.testing.assert_array_equal(result.actions, expected.actions)
        np.testing.assert_array_equal(result.detections, expected.detections)
        np.testing.assert_array_equal(result.truth, expected.truth)
