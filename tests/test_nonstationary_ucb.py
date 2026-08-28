"""Tests for non-stationary UCB schedulers (Phase 1D.4).

Verification criterion (PLAN.md 1D.4):
    Tracks a mid-episode band switch that UCB1 fails to follow.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.nonstationary_ucb import DUCB1Scheduler, SWUCB1Scheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import (
    EmitterInfo,
    Observation,
    ScanAction,
    Scheduler,
    ThreatPrior,
    scheduler_config_from_episode,
)
from ewscan.testing.fixtures import ScriptedEnv, make_test_config


class TestDUCB1Interface:
    def test_is_scheduler(self):
        assert issubclass(DUCB1Scheduler, Scheduler)

    def test_name(self):
        s = DUCB1Scheduler()
        assert s.name == "ducb1"

    def test_unreset_act_raises(self):
        s = DUCB1Scheduler()
        with pytest.raises(RuntimeError):
            s.act(None)

    def test_returns_scan_action(self):
        config = make_test_config(n_bands=3, n_slots=10)
        s = DUCB1Scheduler()
        s.reset(config)
        a = s.act(None)
        assert isinstance(a, ScanAction)


class TestSWUCB1Interface:
    def test_is_scheduler(self):
        assert issubclass(SWUCB1Scheduler, Scheduler)

    def test_name(self):
        s = SWUCB1Scheduler()
        assert s.name == "swucb1"

    def test_unreset_act_raises(self):
        s = SWUCB1Scheduler()
        with pytest.raises(RuntimeError):
            s.act(None)

    def test_returns_scan_action(self):
        config = make_test_config(n_bands=3, n_slots=10)
        s = SWUCB1Scheduler()
        s.reset(config)
        a = s.act(None)
        assert isinstance(a, ScanAction)


class TestMidEpisodeSwitch:
    """Core verification: non-stationary UCB variants track a mid-episode
    band switch that stationary UCB1 fails to follow.

    Scenario: 4 bands, 2000 slots, low exploration (c=0.1).
    Phase 1 (0-999):    Band 0 p=0.9, others p=0.05.
    Phase 2 (1000-1999): Band 2 p=0.9, others p=0.05.

    With low c, UCB1 converges hard on band 0 during Phase 1 and never
    explores band 2 in Phase 2. The non-stationary variants forget Phase 1
    evidence and discover band 2.
    """

    N_BANDS = 4
    N_SLOTS = 2000
    SWITCH = 1000
    C = 0.1

    def _build_truth(self, seed: int = 42) -> np.ndarray:
        rng = np.random.default_rng(seed)
        truth = np.zeros((self.N_BANDS, self.N_SLOTS), dtype=np.bool_)
        truth[0, : self.SWITCH] = rng.random(self.SWITCH) < 0.9
        for b in range(1, self.N_BANDS):
            truth[b, : self.SWITCH] = rng.random(self.SWITCH) < 0.05
        for b in range(self.N_BANDS):
            truth[b, self.SWITCH :] = rng.random(self.N_SLOTS - self.SWITCH) < 0.05
        truth[2, self.SWITCH :] = rng.random(self.N_SLOTS - self.SWITCH) < 0.9
        return truth

    def test_ducb1_adapts_to_switch(self):
        truth = self._build_truth(seed=42)
        config = make_test_config(n_bands=self.N_BANDS, n_slots=self.N_SLOTS, seed=42)

        env_ucb = ScriptedEnv(config, truth)
        log_ucb = env_ucb.run(UCB1Scheduler(c=self.C, seed=42))

        env_ducb = ScriptedEnv(config, truth)
        log_ducb = env_ducb.run(DUCB1Scheduler(c=self.C, gamma=0.99, seed=42))

        ucb_band2 = np.sum(log_ucb.actions[self.SWITCH :] == 2)
        ducb_band2 = np.sum(log_ducb.actions[self.SWITCH :] == 2)

        assert ducb_band2 > 600, (
            f"DUCB1 pulled band 2 only {ducb_band2} times in Phase 2"
        )
        assert ducb_band2 > ucb_band2 + 400, (
            f"DUCB1 ({ducb_band2}) did not sufficiently outperform UCB1 ({ucb_band2})"
        )

    def test_swucb1_adapts_to_switch(self):
        truth = self._build_truth(seed=42)
        config = make_test_config(n_bands=self.N_BANDS, n_slots=self.N_SLOTS, seed=42)

        env_ucb = ScriptedEnv(config, truth)
        log_ucb = env_ucb.run(UCB1Scheduler(c=self.C, seed=42))

        env_sw = ScriptedEnv(config, truth)
        log_sw = env_sw.run(SWUCB1Scheduler(c=self.C, window_size=100, seed=42))

        ucb_band2 = np.sum(log_ucb.actions[self.SWITCH :] == 2)
        sw_band2 = np.sum(log_sw.actions[self.SWITCH :] == 2)

        assert sw_band2 > 600, (
            f"SWUCB1 pulled band 2 only {sw_band2} times in Phase 2"
        )
        assert sw_band2 > ucb_band2 + 400, (
            f"SWUCB1 ({sw_band2}) did not sufficiently outperform UCB1 ({ucb_band2})"
        )


class TestSWUCB1CircularBuffer:
    def test_buffer_wraps_correctly(self):
        """After window_size steps, evictions must happen without error."""
        config = make_test_config(n_bands=3, n_slots=200)
        s = SWUCB1Scheduler(window_size=10, seed=0)
        s.reset(config)

        obs = None
        for t in range(200):
            a = s.act(obs)
            obs = Observation(slot=t, bands=(a.bands[0],), detections=((t % 3 == 0,)))

    def test_window_forgets_old_data(self):
        """A band visited only at the start should become unvisited-in-window
        after window_size steps on other bands."""
        config = make_test_config(n_bands=2, n_slots=60)
        s = SWUCB1Scheduler(window_size=5, c=0.0, seed=0)
        s.reset(config)

        # Initial sweep: visit bands 0 and 1
        a0 = s.act(None)
        assert a0.bands[0] == 0
        a1 = s.act(Observation(slot=0, bands=(0,), detections=(True,)))
        assert a1.bands[0] == 1

        # Now feed 5 observations for band 1 to push band 0 out of the window
        obs = Observation(slot=1, bands=(1,), detections=(True,))
        for t in range(2, 7):
            s.act(obs)
            obs = Observation(slot=t, bands=(1,), detections=(True,))
        
        # Process the final observation
        s.act(obs)

        # After 5 steps of only band 1, band 0's statistics in the window should be zero
        assert s._w_counts[0] == 0
        assert s._w_vals[0] == 0.0


class TestAllZeroRewards:
    def test_ducb1_zero_rewards(self):
        config = make_test_config(n_bands=3, n_slots=20)
        s = DUCB1Scheduler(seed=0)
        s.reset(config)
        obs = None
        counts = {0: 0, 1: 0, 2: 0}
        for t in range(20):
            a = s.act(obs)
            counts[a.bands[0]] += 1
            obs = Observation(slot=t, bands=(a.bands[0],), detections=(False,))
        
        # Should explore all bands due to zero rewards resulting in UCB tie-breaking
        assert all(c > 0 for c in counts.values())
        assert sum(counts.values()) == 20

    def test_swucb1_zero_rewards(self):
        config = make_test_config(n_bands=3, n_slots=20)
        s = SWUCB1Scheduler(seed=0)
        s.reset(config)
        obs = None
        counts = {0: 0, 1: 0, 2: 0}
        for t in range(20):
            a = s.act(obs)
            counts[a.bands[0]] += 1
            obs = Observation(slot=t, bands=(a.bands[0],), detections=(False,))
        
        # Should explore all bands due to zero rewards resulting in UCB tie-breaking
        assert all(c > 0 for c in counts.values())
        assert sum(counts.values()) == 20


class TestThreatWeighting:
    def test_ducb1_uses_threat_map(self):
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=0.1, emitter_type="cw"),
        )
        config = make_test_config(n_bands=2, n_slots=10, emitters=emitters)
        prior = ThreatPrior(weights=(1.0, 0.1), provenance="test-intel")
        s = DUCB1Scheduler(use_threat_weighting=True, seed=0)
        s.reset(scheduler_config_from_episode(config, threat_prior=prior))

        s.act(None)
        s.act(Observation(slot=0, bands=(0,), detections=(True,)))
        a = s.act(Observation(slot=1, bands=(1,), detections=(True,)))
        # Band 0 has higher threat weight, should be preferred
        assert a.bands[0] == 0

    def test_swucb1_uses_threat_map(self):
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=0.1, emitter_type="cw"),
        )
        config = make_test_config(n_bands=2, n_slots=10, emitters=emitters)
        prior = ThreatPrior(weights=(1.0, 0.1), provenance="test-intel")
        s = SWUCB1Scheduler(use_threat_weighting=True, seed=0)
        s.reset(scheduler_config_from_episode(config, threat_prior=prior))

        s.act(None)
        s.act(Observation(slot=0, bands=(0,), detections=(True,)))
        a = s.act(Observation(slot=1, bands=(1,), detections=(True,)))
        assert a.bands[0] == 0
