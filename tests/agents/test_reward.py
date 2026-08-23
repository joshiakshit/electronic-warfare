"""Tests for the reward function (Phase 1D.1).

Pins reward values on hand-built cases matching REWARD_SPEC.md.
"""

import numpy as np
import pytest

from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog


@pytest.fixture
def rf() -> RewardFunction:
    return RewardFunction()


class TestComputeSingleSlot:
    """Pin the five scenarios from REWARD_SPEC.md."""

    def test_stale_band_detection_max_threat(self, rf: RewardFunction):
        # First visit to stale band (staleness=n_bands), detect threat=1.0
        # Expected: 1.0 + 0.0 + 0.2 + 0.0 = 1.2
        r = rf.compute(detection=True, threat_level=1.0, staleness=16, n_bands=16)
        assert r == pytest.approx(1.2)

    def test_immediate_revisit_detection_max_threat(self, rf: RewardFunction):
        # Immediate revisit (staleness=0), detect threat=1.0
        # Expected: 1.0 + 0.0 + 0.0 - 0.3 = 0.7
        r = rf.compute(detection=True, threat_level=1.0, staleness=0, n_bands=16)
        assert r == pytest.approx(0.7)

    def test_stale_band_no_detection(self, rf: RewardFunction):
        # First visit to stale band (staleness=n_bands), no detection
        # Expected: 0.0 - 0.1 + 0.2 + 0.0 = 0.1
        r = rf.compute(detection=False, threat_level=1.0, staleness=16, n_bands=16)
        assert r == pytest.approx(0.1)

    def test_immediate_revisit_no_detection(self, rf: RewardFunction):
        # Immediate revisit (staleness=0), no detection
        # Expected: 0.0 - 0.1 + 0.0 - 0.3 = -0.4
        r = rf.compute(detection=False, threat_level=1.0, staleness=0, n_bands=16)
        assert r == pytest.approx(-0.4)

    def test_half_stale_detection_mid_threat(self, rf: RewardFunction):
        # staleness = n_bands/2, detect threat=0.5
        # R_hit = 1.0 * 0.5 * 1 = 0.5
        # R_miss = 0
        # R_novelty = 0.2 * min(8/16, 1.0) = 0.1
        # R_decay = -0.3 * max(0, 1 - 8/16) = -0.15
        # Total = 0.45
        r = rf.compute(detection=True, threat_level=0.5, staleness=8, n_bands=16)
        assert r == pytest.approx(0.45)


class TestThreatWeighting:
    """Threat level scales the hit reward linearly."""

    def test_zero_threat_detection(self, rf: RewardFunction):
        # Detection on a zero-threat band, fully stale
        # R_hit = 0, R_miss = 0, R_novelty = 0.2, R_decay = 0
        r = rf.compute(detection=True, threat_level=0.0, staleness=16, n_bands=16)
        assert r == pytest.approx(0.2)

    def test_threat_scales_linearly(self, rf: RewardFunction):
        r1 = rf.compute(detection=True, threat_level=0.5, staleness=16, n_bands=16)
        r2 = rf.compute(detection=True, threat_level=1.0, staleness=16, n_bands=16)
        # Difference should be exactly w_threat * 0.5
        assert (r2 - r1) == pytest.approx(0.5)

    def test_high_threat_beats_low_threat_same_staleness(self, rf: RewardFunction):
        r_low = rf.compute(detection=True, threat_level=0.2, staleness=8, n_bands=16)
        r_high = rf.compute(detection=True, threat_level=0.9, staleness=8, n_bands=16)
        assert r_high > r_low


class TestNoveltyBonus:
    """Novelty grows linearly with staleness and caps at n_bands."""

    def test_novelty_zero_at_staleness_zero(self, rf: RewardFunction):
        # With detection to isolate novelty from miss cost
        r_stale0 = rf.compute(detection=True, threat_level=1.0, staleness=0, n_bands=16)
        r_stale1 = rf.compute(detection=True, threat_level=1.0, staleness=1, n_bands=16)
        # Novelty difference: 0.2 * (1/16 - 0) = 0.0125
        # Decay difference: -0.3 * (1 - 1/16) vs -0.3 * (1 - 0) = +0.01875
        # Total diff should be positive (stale=1 better than stale=0)
        assert r_stale1 > r_stale0

    def test_novelty_caps_at_n_bands(self, rf: RewardFunction):
        # staleness beyond n_bands gives same novelty as staleness=n_bands
        r_at = rf.compute(detection=True, threat_level=1.0, staleness=16, n_bands=16)
        r_beyond = rf.compute(detection=True, threat_level=1.0, staleness=100, n_bands=16)
        assert r_at == pytest.approx(r_beyond)

    def test_novelty_linear(self, rf: RewardFunction):
        # Novelty at staleness=4 and staleness=8 with n_bands=16
        # Isolate by using same detection/threat and noting decay also changes
        # Just verify novelty component: 0.2 * 4/16 = 0.05, 0.2 * 8/16 = 0.1
        rf_no_decay = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=0.2, w_decay=0.0)
        r4 = rf_no_decay.compute(detection=False, threat_level=0.0, staleness=4, n_bands=16)
        r8 = rf_no_decay.compute(detection=False, threat_level=0.0, staleness=8, n_bands=16)
        assert r4 == pytest.approx(0.05)
        assert r8 == pytest.approx(0.1)


class TestRevisitDecay:
    """Revisit penalty is strongest at staleness=0 and vanishes at cooldown."""

    def test_decay_max_at_zero_staleness(self, rf: RewardFunction):
        # Isolate decay: detection with no threat, no novelty
        rf_decay_only = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=0.0, w_decay=0.3)
        r = rf_decay_only.compute(detection=True, threat_level=0.0, staleness=0, n_bands=16)
        assert r == pytest.approx(-0.3)

    def test_decay_zero_at_cooldown(self, rf: RewardFunction):
        rf_decay_only = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=0.0, w_decay=0.3)
        r = rf_decay_only.compute(detection=True, threat_level=0.0, staleness=16, n_bands=16)
        assert r == pytest.approx(0.0)

    def test_decay_linear_between(self, rf: RewardFunction):
        rf_decay_only = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=0.0, w_decay=0.3)
        # At staleness=8, cooldown=16: decay = -0.3 * (1 - 8/16) = -0.15
        r = rf_decay_only.compute(detection=True, threat_level=0.0, staleness=8, n_bands=16)
        assert r == pytest.approx(-0.15)

    def test_custom_cooldown(self):
        rf = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=0.0, w_decay=0.3, cooldown=4)
        # At staleness=2, cooldown=4: decay = -0.3 * (1 - 2/4) = -0.15
        r = rf.compute(detection=True, threat_level=0.0, staleness=2, n_bands=16)
        assert r == pytest.approx(-0.15)
        # At staleness=4, cooldown=4: decay = 0
        r = rf.compute(detection=True, threat_level=0.0, staleness=4, n_bands=16)
        assert r == pytest.approx(0.0)


class TestMissCost:
    """Miss cost applies only when detection is False."""

    def test_miss_cost_on_no_detection(self, rf: RewardFunction):
        rf_miss_only = RewardFunction(w_threat=0.0, c_miss=0.1, w_novelty=0.0, w_decay=0.0)
        r = rf_miss_only.compute(detection=False, threat_level=0.0, staleness=16, n_bands=16)
        assert r == pytest.approx(-0.1)

    def test_no_miss_cost_on_detection(self, rf: RewardFunction):
        rf_miss_only = RewardFunction(w_threat=0.0, c_miss=0.1, w_novelty=0.0, w_decay=0.0)
        r = rf_miss_only.compute(detection=True, threat_level=0.0, staleness=16, n_bands=16)
        assert r == pytest.approx(0.0)


class TestComputeEpisode:
    """Batch reward computation over a full episode log."""

    def _make_log(self) -> EpisodeLog:
        """4 bands, 8 slots. Band 0 always ON (threat=1.0), others OFF."""
        n_bands, n_slots = 4, 8
        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, :] = True

        # Actions: visit band 0 twice, then sweep 1,2,3, then back to 0
        actions = np.array([0, 0, 1, 2, 3, 0, 0, 1], dtype=np.intp)
        detections = np.array(
            [truth[actions[t], t] for t in range(n_slots)], dtype=np.bool_
        )

        config = EpisodeConfig(
            n_bands=n_bands,
            n_slots=n_slots,
            k=1,
            emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
            detection_threshold=3.0,
            pfa=1e-3,
            seed=0,
        )
        return EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)

    def test_length_matches_episode(self):
        log = self._make_log()
        rf = RewardFunction()
        rewards = rf.compute_episode(log)
        assert rewards.shape == (8,)

    def test_first_slot_uses_initial_staleness(self):
        log = self._make_log()
        rf = RewardFunction()
        rewards = rf.compute_episode(log)
        # Slot 0: band=0, detection=True, threat=1.0, staleness=4 (initial=n_bands)
        # R_hit = 1.0, R_miss = 0, R_novelty = 0.2*min(4/4,1) = 0.2, R_decay = -0.3*max(0,1-4/4) = 0
        assert rewards[0] == pytest.approx(1.2)

    def test_immediate_revisit_slot(self):
        log = self._make_log()
        rf = RewardFunction()
        rewards = rf.compute_episode(log)
        # Slot 1: band=0, detection=True, threat=1.0, staleness=0 (just visited at slot 0)
        # R_hit = 1.0, R_miss = 0, R_novelty = 0, R_decay = -0.3
        assert rewards[1] == pytest.approx(0.7)

    def test_miss_on_empty_band(self):
        log = self._make_log()
        rf = RewardFunction()
        rewards = rf.compute_episode(log)
        # Slot 2: band=1, detection=False, threat=baseline(0.1), staleness=5 (init=4, +1 from slot 0-1)
        # Wait, let me re-trace staleness:
        # Init: staleness = [4, 4, 4, 4]
        # After slot 0 (band=0): staleness becomes [0, 5, 5, 5] (all +1, then band 0 = 0)
        # After slot 1 (band=0): staleness becomes [0, 6, 6, 6]
        # At slot 2 (band=1): staleness[1] = 6
        # R_hit = 0, R_miss = -0.1, R_novelty = 0.2*min(6/4, 1) = 0.2, R_decay = -0.3*max(0,1-6/4) = 0
        # Total = 0.1
        assert rewards[2] == pytest.approx(0.1)

    def test_return_after_sweep(self):
        log = self._make_log()
        rf = RewardFunction()
        rewards = rf.compute_episode(log)
        # Slot 5: band=0, detection=True, threat=1.0
        # Trace staleness for band 0:
        #   After slot 0: 0
        #   After slot 1: 0
        #   After slot 2: 1 (band 1 visited, all others +1, band 1 -> 0)
        #     Wait, staleness tracking: after each slot, ALL bands get +1, then visited band = 0
        #   Let me retrace carefully:
        #   Init: [4, 4, 4, 4]
        #   Slot 0, band=0: read staleness[0]=4, then all+=1 -> [5,5,5,5], then band0=0 -> [0,5,5,5]
        #   Slot 1, band=0: read staleness[0]=0, then all+=1 -> [1,6,6,6], then band0=0 -> [0,6,6,6]
        #   Slot 2, band=1: read staleness[1]=6, then all+=1 -> [1,7,7,7], then band1=0 -> [1,0,7,7]
        #   Slot 3, band=2: read staleness[2]=7, then all+=1 -> [2,1,8,8], then band2=0 -> [2,1,0,8]
        #   Slot 4, band=3: read staleness[3]=8, then all+=1 -> [3,2,1,9], then band3=0 -> [3,2,1,0]
        #   Slot 5, band=0: read staleness[0]=3
        # R_hit = 1.0, R_miss = 0, R_novelty = 0.2*min(3/4, 1) = 0.15
        # R_decay = -0.3*max(0, 1-3/4) = -0.3*0.25 = -0.075
        # Total = 1.0 + 0.15 - 0.075 = 1.075
        assert rewards[5] == pytest.approx(1.075)

    def test_baseline_threat_for_unknown_bands(self):
        log = self._make_log()
        rf = RewardFunction(baseline_threat=0.05)
        rewards = rf.compute_episode(log)
        # Slot 2: band=1 (no emitter), detection=False, staleness=6
        # R_hit = 0, R_miss = -0.1, R_novelty = 0.2*min(6/4,1) = 0.2, R_decay = 0
        # Total = 0.1 (same regardless of baseline_threat since no detection)
        assert rewards[2] == pytest.approx(0.1)


class TestCustomWeights:
    """Verify that custom weight parameters override defaults."""

    def test_zero_all_weights(self):
        rf = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=0.0, w_decay=0.0)
        r = rf.compute(detection=True, threat_level=1.0, staleness=0, n_bands=16)
        assert r == pytest.approx(0.0)

    def test_heavy_miss_cost(self):
        rf = RewardFunction(w_threat=1.0, c_miss=1.0, w_novelty=0.0, w_decay=0.0)
        r = rf.compute(detection=False, threat_level=1.0, staleness=16, n_bands=16)
        assert r == pytest.approx(-1.0)

    def test_heavy_novelty(self):
        rf = RewardFunction(w_threat=0.0, c_miss=0.0, w_novelty=1.0, w_decay=0.0)
        r = rf.compute(detection=False, threat_level=0.0, staleness=16, n_bands=16)
        assert r == pytest.approx(1.0)
