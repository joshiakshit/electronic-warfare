"""Base class for learning schedulers."""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.reward import RewardFunction
from ewscan.agents.stats import BandStatistics
from ewscan.contracts import (
    EpisodeConfig,
    Observation,
    SchedulerConfig,
    Scheduler,
    as_scheduler_config,
)
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
        self._k: int | None = None
        self._retune_cost_slots: int = 0
        self._threat_map: NDArray[np.float64] | None = None
        self._rng: np.random.Generator | None = None

    @property
    def stats(self) -> BandStatistics:
        """Underlying sufficient statistics store."""
        if self._stats is None:
            raise RuntimeError("Scheduler must be reset before accessing stats")
        return self._stats

    def reset(self, config: SchedulerConfig | EpisodeConfig) -> None:
        """Reset scheduler state for a new episode.

        Any EpisodeConfig is reduced to the blind scheduler view first, so a
        learning scheduler can never read emitter bands, types, SNRs, threat
        levels, or transition parameters. Threat weighting is available only
        through an explicit ThreatPrior.
        """
        config = as_scheduler_config(config)
        if config.n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {config.n_bands}")

        self._n_bands = config.n_bands
        self._k = config.k
        self._retune_cost_slots = config.retune_cost_slots
        self._stats = BandStatistics(config.n_bands)

        # Build threat map from the explicit prior only. Without a prior every
        # band shares the baseline weight, so hidden emitter data cannot leak.
        baseline = (
            self._reward_fn.baseline_threat if self._reward_fn is not None else 0.1
        )
        threat_map = np.full(config.n_bands, baseline, dtype=np.float64)
        if config.threat_prior is not None:
            weights = np.asarray(config.threat_prior.weights, dtype=np.float64)
            threat_map = np.maximum(threat_map, weights)
        self._threat_map = threat_map

        # Initialize RNG for tie-breaking and sampling
        if isinstance(self._seed, np.random.Generator):
            self._rng = self._seed
        elif self._seed is not None:
            self._rng = np.random.default_rng(self._seed)
        else:
            self._rng = make_generators(config.seed)["scheduler"]

    def _compute_rewards(self, obs: Observation) -> list[float]:
        """Compute per-band rewards for a parallel observation.

        Returns one reward per band in ``obs.bands``, in order. Staleness is
        read before any statistics update, so all k bands see the same slot age.
        """
        assert self._threat_map is not None
        assert self._stats is not None
        assert self._n_bands is not None

        rewards: list[float] = []
        for band, detection in zip(obs.bands, obs.detections):
            if self._reward_fn is not None:
                staleness = self._stats.get_staleness(band)
                threat = float(self._threat_map[band])
                rewards.append(
                    self._reward_fn.compute(
                        detection=detection,
                        threat_level=threat,
                        staleness=staleness,
                        n_bands=self._n_bands,
                    )
                )
            elif self._use_threat_weighting:
                rewards.append(float(detection) * float(self._threat_map[band]))
            else:
                rewards.append(float(detection))
        if obs.retune_event and self._retune_cost_slots > 0:
            penalty = (self._reward_fn or RewardFunction()).c_retune / len(rewards)
            rewards = [reward - penalty for reward in rewards]
        return rewards

    def _select_top_k(
        self,
        values: NDArray[np.float64],
        k: int,
        unvisited: NDArray[np.int64] | None = None,
    ) -> tuple[int, ...]:
        """Pick k distinct band indices.

        Fills from ``unvisited`` (ascending index) first, then by descending
        value with uniform random tie-breaking. For k=1 with no unvisited this
        reproduces the single-arm argmax-with-random-tie-break behaviour.
        """
        assert self._rng is not None
        chosen: list[int] = []
        if unvisited is not None:
            for b in unvisited:
                if len(chosen) >= k:
                    break
                chosen.append(int(b))
        if len(chosen) >= k:
            return tuple(chosen)

        vals = np.array(values, dtype=np.float64, copy=True)
        for b in chosen:
            vals[b] = -np.inf
        while len(chosen) < k:
            max_val = np.max(vals)
            best = np.flatnonzero(np.isclose(vals, max_val, rtol=1e-12, atol=1e-12))
            pick = int(best[0]) if len(best) == 1 else int(self._rng.choice(best))
            chosen.append(pick)
            vals[pick] = -np.inf
        return tuple(chosen)
