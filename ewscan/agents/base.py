"""Base class for learning schedulers."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.reward import RewardFunction
from ewscan.agents.stats import BandStatistics
from ewscan.contracts import EpisodeConfig, Observation, Scheduler
from ewscan.rng import make_generators


class BaseLearningScheduler(Scheduler):
    """Base class for learning schedulers providing common boilerplate.
    
    Handles stats initialization, threat map generation, RNG setup,
    and reward computation.
    """

    def __init__(
        self,
        reward_fn: RewardFunction | None = None,
        use_threat_weighting: bool = False,
        staleness_weight: float = 0.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        self._reward_fn = reward_fn
        self._use_threat_weighting = use_threat_weighting
        self._staleness_weight = float(staleness_weight)
        self._seed = seed

        self._stats: BandStatistics | None = None
        self._n_bands: int | None = None
        self._threat_map: NDArray[np.float64] | None = None
        self._rng: np.random.Generator | None = None

    @property
    def stats(self) -> BandStatistics:
        """Underlying sufficient statistics store."""
        if self._stats is None:
            raise RuntimeError("Scheduler must be reset before accessing stats")
        return self._stats

    def reset(self, config: EpisodeConfig) -> None:
        """Reset scheduler state for a new episode."""
        if config.n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {config.n_bands}")

        self._n_bands = config.n_bands
        self._stats = BandStatistics(config.n_bands)

        # Build threat map
        baseline = (
            self._reward_fn.baseline_threat if self._reward_fn is not None else 0.1
        )
        threat_map = np.full(config.n_bands, baseline, dtype=np.float64)
        for em in config.emitters:
            if 0 <= em.band < config.n_bands:
                threat_map[em.band] = max(threat_map[em.band], float(em.threat_level))
        self._threat_map = threat_map

        # Initialize RNG for tie-breaking and sampling
        if isinstance(self._seed, np.random.Generator):
            self._rng = self._seed
        elif self._seed is not None:
            self._rng = np.random.default_rng(self._seed)
        else:
            self._rng = make_generators(config.seed)["scheduler"]

    def _compute_reward(self, obs: Observation) -> float:
        """Compute reward for an observation based on configuration."""
        assert self._threat_map is not None
        assert self._stats is not None
        assert self._n_bands is not None

        if self._reward_fn is not None:
            staleness = self._stats.get_staleness(obs.band)
            threat = float(self._threat_map[obs.band])
            return self._reward_fn.compute(
                detection=obs.detection,
                threat_level=threat,
                staleness=staleness,
                n_bands=self._n_bands,
            )
        elif self._use_threat_weighting:
            return float(obs.detection) * float(self._threat_map[obs.band])
        else:
            return float(obs.detection)
