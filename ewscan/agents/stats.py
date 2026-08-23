"""Per-band sufficient statistics store with slot-age tracking (Phase 1D.2).

Maintains visit counts, detection counts, reward accumulators, empirical means,
and per-band staleness / slot-age tracking for learning schedulers.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import Observation


class BandStatistics:
    """Per-band sufficient statistics store with slot-age tracking.

    Tracks:
    - `counts`: number of times each band has been scanned.
    - `hits`: number of positive detections on each band.
    - `total_rewards`: accumulated reward on each band.
    - `staleness`: slots elapsed since the band was last scanned. Initialized
      to `n_bands` at reset, reset to 0 upon scan, and incremented on unvisited
      slots conforming to REWARD_SPEC.md.
    - `last_scanned`: the slot index when each band was last scanned (-1 if never).
    - `total_pulls`: total number of observations / scans recorded across all bands.

    Parameters
    ----------
    n_bands : int | None, optional
        Number of frequency bands. If provided, initializes the statistics store
        immediately. Otherwise, call `reset(n_bands)` before updating.
    """

    def __init__(self, n_bands: int | None = None) -> None:
        self._n_bands: int | None = None
        self._counts: NDArray[np.int64] | None = None
        self._hits: NDArray[np.int64] | None = None
        self._total_rewards: NDArray[np.float64] | None = None
        self._staleness: NDArray[np.int64] | None = None
        self._last_scanned: NDArray[np.int64] | None = None
        self._total_pulls: int = 0

        if n_bands is not None:
            self.reset(n_bands)

    def reset(self, n_bands: int) -> None:
        """Reset all statistics for a new episode.

        Parameters
        ----------
        n_bands : int
            Number of frequency bands. Must be positive.
        """
        if n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {n_bands}")

        self._n_bands = n_bands
        self._counts = np.zeros(n_bands, dtype=np.int64)
        self._hits = np.zeros(n_bands, dtype=np.int64)
        self._total_rewards = np.zeros(n_bands, dtype=np.float64)
        # Initial staleness is n_bands per REWARD_SPEC.md
        self._staleness = np.full(n_bands, n_bands, dtype=np.int64)
        self._last_scanned = np.full(n_bands, -1, dtype=np.int64)
        self._total_pulls = 0

    def _check_initialized(self) -> None:
        if self._n_bands is None or self._counts is None or self._staleness is None:
            raise RuntimeError("BandStatistics must be reset before use")

    def update(self, obs: Observation, reward: float | None = None) -> None:
        """Update statistics with a new scan observation.

        Parameters
        ----------
        obs : Observation
            The observation returned by the environment.
        reward : float | None, optional
            Optional reward signal obtained from this scan slot.
        """
        self._check_initialized()
        assert self._counts is not None
        assert self._hits is not None
        assert self._total_rewards is not None
        assert self._staleness is not None
        assert self._last_scanned is not None
        assert self._n_bands is not None

        band = obs.band
        if not (0 <= band < self._n_bands):
            raise IndexError(
                f"Band index {band} out of range for n_bands={self._n_bands}"
            )

        # Update visit count and hit count
        self._counts[band] += 1
        if obs.detection:
            self._hits[band] += 1

        # Update total rewards if reward is provided
        if reward is not None:
            self._total_rewards[band] += float(reward)

        # Update slot age / staleness:
        # All bands age by 1 slot, and the scanned band resets to 0
        self._staleness += 1
        self._staleness[band] = 0

        # Update last scanned slot
        self._last_scanned[band] = obs.slot
        self._total_pulls += 1

    @property
    def n_bands(self) -> int:
        """Number of frequency bands."""
        self._check_initialized()
        assert self._n_bands is not None
        return self._n_bands

    @property
    def total_pulls(self) -> int:
        """Total number of pulls/scans recorded."""
        return self._total_pulls

    @property
    def counts(self) -> NDArray[np.int64]:
        """Per-band scan counts."""
        self._check_initialized()
        assert self._counts is not None
        return self._counts.copy()

    @property
    def hits(self) -> NDArray[np.int64]:
        """Per-band detection counts."""
        self._check_initialized()
        assert self._hits is not None
        return self._hits.copy()

    @property
    def total_rewards(self) -> NDArray[np.float64]:
        """Per-band accumulated rewards."""
        self._check_initialized()
        assert self._total_rewards is not None
        return self._total_rewards.copy()

    @property
    def staleness(self) -> NDArray[np.int64]:
        """Per-band staleness (slots elapsed since last scan)."""
        self._check_initialized()
        assert self._staleness is not None
        return self._staleness.copy()

    @property
    def last_scanned(self) -> NDArray[np.int64]:
        """Per-band slot index of last scan (-1 if never scanned)."""
        self._check_initialized()
        assert self._last_scanned is not None
        return self._last_scanned.copy()

    @property
    def mean_detections(self) -> NDArray[np.float64]:
        """Empirical detection rate per band (hits / counts), 0.0 if unvisited."""
        self._check_initialized()
        assert self._counts is not None
        assert self._hits is not None
        means = np.zeros(self._n_bands, dtype=np.float64)
        visited = self._counts > 0
        means[visited] = self._hits[visited] / self._counts[visited]
        return means

    @property
    def mean_rewards(self) -> NDArray[np.float64]:
        """Empirical mean reward per band (total_rewards / counts), 0.0 if unvisited."""
        self._check_initialized()
        assert self._counts is not None
        assert self._total_rewards is not None
        means = np.zeros(self._n_bands, dtype=np.float64)
        visited = self._counts > 0
        means[visited] = self._total_rewards[visited] / self._counts[visited]
        return means

    @property
    def unvisited_bands(self) -> NDArray[np.int64]:
        """Array of band indices that have not been visited yet (counts == 0)."""
        self._check_initialized()
        assert self._counts is not None
        return np.flatnonzero(self._counts == 0)

    def get_staleness(self, band: int) -> int:
        """Get the current staleness for a specific band."""
        self._check_initialized()
        assert self._staleness is not None
        assert self._n_bands is not None
        if not (0 <= band < self._n_bands):
            raise IndexError(f"Band index {band} out of range for n_bands={self._n_bands}")
        return int(self._staleness[band])

    def get_count(self, band: int) -> int:
        """Get the scan count for a specific band."""
        self._check_initialized()
        assert self._counts is not None
        assert self._n_bands is not None
        if not (0 <= band < self._n_bands):
            raise IndexError(f"Band index {band} out of range for n_bands={self._n_bands}")
        return int(self._counts[band])

    def get_hits(self, band: int) -> int:
        """Get the hit count for a specific band."""
        self._check_initialized()
        assert self._hits is not None
        assert self._n_bands is not None
        if not (0 <= band < self._n_bands):
            raise IndexError(f"Band index {band} out of range for n_bands={self._n_bands}")
        return int(self._hits[band])

    def get_mean_detection(self, band: int) -> float:
        """Get the empirical detection rate for a specific band."""
        self._check_initialized()
        assert self._counts is not None
        assert self._hits is not None
        assert self._n_bands is not None
        if not (0 <= band < self._n_bands):
            raise IndexError(f"Band index {band} out of range for n_bands={self._n_bands}")
        cnt = self._counts[band]
        return float(self._hits[band] / cnt) if cnt > 0 else 0.0

    def get_mean_reward(self, band: int) -> float:
        """Get the empirical mean reward for a specific band."""
        self._check_initialized()
        assert self._counts is not None
        assert self._total_rewards is not None
        assert self._n_bands is not None
        if not (0 <= band < self._n_bands):
            raise IndexError(f"Band index {band} out of range for n_bands={self._n_bands}")
        cnt = self._counts[band]
        return float(self._total_rewards[band] / cnt) if cnt > 0 else 0.0
