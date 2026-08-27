"""Unit tests for BandStatistics sufficient statistics store (Phase 1D.2).

Verification criterion (PLAN.md 1D.2):
    Counts and ages correct after a scripted action sequence.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.stats import BandStatistics
from ewscan.contracts import Observation
from ewscan.testing.fixtures import scripted_observations


class TestBandStatisticsInit:
    def test_uninitialized_access_raises(self):
        stats = BandStatistics()
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = stats.counts
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = stats.staleness
        with pytest.raises(RuntimeError, match="must be reset"):
            stats.update(Observation(slot=0, bands=(0,), detections=(True,)))

    def test_init_with_n_bands(self):
        stats = BandStatistics(n_bands=4)
        assert stats.n_bands == 4
        assert stats.total_pulls == 0
        np.testing.assert_array_equal(stats.counts, [0, 0, 0, 0])
        np.testing.assert_array_equal(stats.hits, [0, 0, 0, 0])
        np.testing.assert_array_equal(stats.staleness, [4, 4, 4, 4])
        np.testing.assert_array_equal(stats.last_scanned, [-1, -1, -1, -1])
        np.testing.assert_array_equal(stats.mean_detections, [0.0, 0.0, 0.0, 0.0])
        np.testing.assert_array_equal(stats.mean_rewards, [0.0, 0.0, 0.0, 0.0])
        np.testing.assert_array_equal(stats.unvisited_bands, [0, 1, 2, 3])

    def test_invalid_n_bands_raises(self):
        with pytest.raises(ValueError, match="positive"):
            BandStatistics(n_bands=0)
        with pytest.raises(ValueError, match="positive"):
            BandStatistics(n_bands=-2)


class TestBandStatisticsUpdates:
    def test_single_update_hit(self):
        stats = BandStatistics(n_bands=4)
        obs = Observation(slot=0, bands=(1,), detections=(True,))
        stats.update(obs, rewards=[1.0])

        assert stats.total_pulls == 1
        np.testing.assert_array_equal(stats.counts, [0, 1, 0, 0])
        np.testing.assert_array_equal(stats.hits, [0, 1, 0, 0])
        np.testing.assert_array_equal(stats.total_rewards, [0.0, 1.0, 0.0, 0.0])
        # Visited band 1 resets to 0, other bands increment from 4 to 5
        np.testing.assert_array_equal(stats.staleness, [5, 0, 5, 5])
        np.testing.assert_array_equal(stats.last_scanned, [-1, 0, -1, -1])
        np.testing.assert_array_equal(stats.mean_detections, [0.0, 1.0, 0.0, 0.0])
        np.testing.assert_array_equal(stats.mean_rewards, [0.0, 1.0, 0.0, 0.0])
        np.testing.assert_array_equal(stats.unvisited_bands, [0, 2, 3])

    def test_single_update_miss(self):
        stats = BandStatistics(n_bands=4)
        obs = Observation(slot=0, bands=(2,), detections=(False,))
        stats.update(obs, rewards=[-0.1])

        assert stats.total_pulls == 1
        np.testing.assert_array_equal(stats.counts, [0, 0, 1, 0])
        np.testing.assert_array_equal(stats.hits, [0, 0, 0, 0])
        np.testing.assert_array_equal(stats.total_rewards, [0.0, 0.0, -0.1, 0.0])
        np.testing.assert_array_equal(stats.staleness, [5, 5, 0, 5])
        np.testing.assert_array_equal(stats.last_scanned, [-1, -1, 0, -1])
        np.testing.assert_array_equal(stats.mean_detections, [0.0, 0.0, 0.0, 0.0])
        np.testing.assert_array_equal(stats.mean_rewards, [0.0, 0.0, -0.1, 0.0])

    def test_scripted_action_sequence(self):
        """Verify counts, hits, staleness, and last_scanned over a 6-slot sequence."""
        stats = BandStatistics(n_bands=4)
        specs = [
            (0, 0, True),   # slot 0: band 0 hit
            (1, 0, False),  # slot 1: band 0 miss
            (2, 1, True),   # slot 2: band 1 hit
            (3, 2, True),   # slot 3: band 2 hit
            (4, 3, False),  # slot 4: band 3 miss
            (5, 0, True),   # slot 5: band 0 hit
        ]
        obs_list = scripted_observations(specs)

        # Slot 0: band 0
        stats.update(obs_list[0])
        # Init staleness: [4, 4, 4, 4] -> after slot 0: [0, 5, 5, 5]
        np.testing.assert_array_equal(stats.counts, [1, 0, 0, 0])
        np.testing.assert_array_equal(stats.hits, [1, 0, 0, 0])
        np.testing.assert_array_equal(stats.staleness, [0, 5, 5, 5])
        np.testing.assert_array_equal(stats.last_scanned, [0, -1, -1, -1])

        # Slot 1: band 0
        stats.update(obs_list[1])
        # Previous staleness: [0, 5, 5, 5] -> all +1 -> [1, 6, 6, 6] -> band 0=0 -> [0, 6, 6, 6]
        np.testing.assert_array_equal(stats.counts, [2, 0, 0, 0])
        np.testing.assert_array_equal(stats.hits, [1, 0, 0, 0])
        np.testing.assert_array_equal(stats.staleness, [0, 6, 6, 6])
        np.testing.assert_array_equal(stats.last_scanned, [1, -1, -1, -1])

        # Slot 2: band 1
        stats.update(obs_list[2])
        # Previous: [0, 6, 6, 6] -> all +1 -> [1, 7, 7, 7] -> band 1=0 -> [1, 0, 7, 7]
        np.testing.assert_array_equal(stats.counts, [2, 1, 0, 0])
        np.testing.assert_array_equal(stats.hits, [1, 1, 0, 0])
        np.testing.assert_array_equal(stats.staleness, [1, 0, 7, 7])
        np.testing.assert_array_equal(stats.last_scanned, [1, 2, -1, -1])

        # Slot 3: band 2
        stats.update(obs_list[3])
        # Previous: [1, 0, 7, 7] -> all +1 -> [2, 1, 8, 8] -> band 2=0 -> [2, 1, 0, 8]
        np.testing.assert_array_equal(stats.counts, [2, 1, 1, 0])
        np.testing.assert_array_equal(stats.hits, [1, 1, 1, 0])
        np.testing.assert_array_equal(stats.staleness, [2, 1, 0, 8])
        np.testing.assert_array_equal(stats.last_scanned, [1, 2, 3, -1])

        # Slot 4: band 3
        stats.update(obs_list[4])
        # Previous: [2, 1, 0, 8] -> all +1 -> [3, 2, 1, 9] -> band 3=0 -> [3, 2, 1, 0]
        np.testing.assert_array_equal(stats.counts, [2, 1, 1, 1])
        np.testing.assert_array_equal(stats.hits, [1, 1, 1, 0])
        np.testing.assert_array_equal(stats.staleness, [3, 2, 1, 0])
        np.testing.assert_array_equal(stats.last_scanned, [1, 2, 3, 4])
        assert len(stats.unvisited_bands) == 0

        # Slot 5: band 0
        stats.update(obs_list[5])
        # Previous: [3, 2, 1, 0] -> all +1 -> [4, 3, 2, 1] -> band 0=0 -> [0, 3, 2, 1]
        np.testing.assert_array_equal(stats.counts, [3, 1, 1, 1])
        np.testing.assert_array_equal(stats.hits, [2, 1, 1, 0])
        np.testing.assert_array_equal(stats.staleness, [0, 3, 2, 1])
        np.testing.assert_array_equal(stats.last_scanned, [5, 2, 3, 4])

        # Mean detection rates: [2/3, 1/1, 1/1, 0/1]
        np.testing.assert_allclose(
            stats.mean_detections, [2.0 / 3.0, 1.0, 1.0, 0.0]
        )

    def test_out_of_bounds_band_raises(self):
        stats = BandStatistics(n_bands=3)
        with pytest.raises(IndexError, match="out of range"):
            stats.update(Observation(slot=0, bands=(3,), detections=(True,)))
        with pytest.raises(IndexError, match="out of range"):
            stats.update(Observation(slot=0, bands=(-1,), detections=(True,)))

    def test_helper_getters(self):
        stats = BandStatistics(n_bands=3)
        stats.update(Observation(slot=0, bands=(1,), detections=(True,)), rewards=[0.8])

        assert stats.get_count(1) == 1
        assert stats.get_count(0) == 0
        assert stats.get_hits(1) == 1
        assert stats.get_hits(0) == 0
        assert stats.get_staleness(1) == 0
        assert stats.get_staleness(0) == 4
        assert stats.get_mean_detection(1) == 1.0
        assert stats.get_mean_detection(0) == 0.0
        assert stats.get_mean_reward(1) == 0.8
        assert stats.get_mean_reward(0) == 0.0

        with pytest.raises(IndexError):
            stats.get_count(5)
        with pytest.raises(IndexError):
            stats.get_staleness(-1)

    def test_reset_clears_state(self):
        stats = BandStatistics(n_bands=4)
        for t in range(4):
            stats.update(Observation(slot=t, bands=(t,), detections=(True,)), rewards=[1.0])
        assert stats.total_pulls == 4

        stats.reset(n_bands=2)
        assert stats.n_bands == 2
        assert stats.total_pulls == 0
        np.testing.assert_array_equal(stats.counts, [0, 0])
        np.testing.assert_array_equal(stats.hits, [0, 0])
        np.testing.assert_array_equal(stats.staleness, [2, 2])
        np.testing.assert_array_equal(stats.last_scanned, [-1, -1])
        np.testing.assert_array_equal(stats.total_rewards, [0.0, 0.0])

    def test_encapsulation_copy_protection(self):
        """Mutating returned arrays must not affect internal statistics."""
        stats = BandStatistics(n_bands=3)
        counts = stats.counts
        counts[0] = 999
        assert stats.counts[0] == 0

        staleness = stats.staleness
        staleness[0] = 999
        assert stats.staleness[0] == 3
