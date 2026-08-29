"""Non-stationary UCB scan schedulers (Phase 1D.4).

Two variants that handle restless emitters by forgetting old observations:
- DUCB1Scheduler: discounted UCB1, multiplies past counts/rewards by gamma.
- SWUCB1Scheduler: sliding window UCB1, considers only the last W observations.
"""

from __future__ import annotations

import numpy as np

from ewscan.agents.base import BaseLearningScheduler
from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EpisodeConfig, Observation, ScanAction


class DUCB1Scheduler(BaseLearningScheduler):
    def __init__(
        self,
        c: float = 1.0,
        gamma: float = 0.99,
        reward_fn: RewardFunction | None = None,
        use_threat_weighting: bool = False,
        staleness_weight: float = 0.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        super().__init__(
            reward_fn=reward_fn,
            use_threat_weighting=use_threat_weighting,
            staleness_weight=staleness_weight,
            seed=seed,
        )
        self._c = float(c)
        self._gamma = float(gamma)

        self._d_counts: np.ndarray | None = None
        self._d_vals: np.ndarray | None = None
        self._d_total_pulls: float = 0.0

    @property
    def name(self) -> str:
        return "ducb1"

    @property
    def learning_metric(self) -> str:
        return "discounted_detection_rate"

    @property
    def learning_values(self) -> np.ndarray:
        if self._d_counts is None or self._d_vals is None:
            raise RuntimeError("Scheduler must be reset before accessing learning values")
        return self._d_vals / np.maximum(self._d_counts, 1e-12)

    def reset(self, config: EpisodeConfig) -> None:
        super().reset(config)
        self._d_counts = np.zeros(config.n_bands, dtype=np.float64)
        self._d_vals = np.zeros(config.n_bands, dtype=np.float64)
        self._d_total_pulls = 0.0

    def act(self, obs: Observation | None) -> ScanAction:
        if (
            self._stats is None
            or self._n_bands is None
            or self._threat_map is None
            or self._rng is None
            or self._d_counts is None
            or self._d_vals is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        if obs is not None and obs.valid:
            rewards = self._compute_rewards(obs)
            self._stats.update(obs, rewards=rewards)

            self._d_counts *= self._gamma
            self._d_vals *= self._gamma
            self._d_total_pulls *= self._gamma

            for band, r in zip(obs.bands, rewards):
                self._d_counts[band] += 1.0
                self._d_vals[band] += r
                self._d_total_pulls += 1.0

        means = self._d_vals / np.maximum(self._d_counts, 1e-12)
        with np.errstate(divide="ignore", invalid="ignore"):
            bonus = self._c * np.sqrt(
                2.0 * np.log(self._d_total_pulls) / np.maximum(self._d_counts, 1e-12)
            )
        ucb_values = means + bonus
        if self._staleness_weight > 0.0:
            ucb_values += self._staleness_weight * self._stats.staleness

        unvisited = self._stats.unvisited_bands
        bands = self._select_top_k(ucb_values, self._k, unvisited=unvisited)
        return ScanAction(bands=bands)


class SWUCB1Scheduler(BaseLearningScheduler):
    def __init__(
        self,
        c: float = 1.0,
        window_size: int = 100,
        reward_fn: RewardFunction | None = None,
        use_threat_weighting: bool = False,
        staleness_weight: float = 0.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        super().__init__(
            reward_fn=reward_fn,
            use_threat_weighting=use_threat_weighting,
            staleness_weight=staleness_weight,
            seed=seed,
        )
        self._c = float(c)
        self._window_size = window_size

        self._history_band: np.ndarray | None = None
        self._history_val: np.ndarray | None = None
        self._ptr: int = 0
        self._steps_recorded: int = 0

        self._w_counts: np.ndarray | None = None
        self._w_vals: np.ndarray | None = None

    @property
    def name(self) -> str:
        return "swucb1"

    @property
    def learning_metric(self) -> str:
        return "window_detection_rate"

    @property
    def learning_values(self) -> np.ndarray:
        if self._w_counts is None or self._w_vals is None:
            raise RuntimeError("Scheduler must be reset before accessing learning values")
        return self._w_vals / np.maximum(self._w_counts, 1)

    def reset(self, config: EpisodeConfig) -> None:
        super().reset(config)
        self._history_band = np.zeros(self._window_size, dtype=np.int64)
        self._history_val = np.zeros(self._window_size, dtype=np.float64)
        self._ptr = 0
        self._steps_recorded = 0

        self._w_counts = np.zeros(config.n_bands, dtype=np.int64)
        self._w_vals = np.zeros(config.n_bands, dtype=np.float64)

    def act(self, obs: Observation | None) -> ScanAction:
        if (
            self._stats is None
            or self._n_bands is None
            or self._threat_map is None
            or self._rng is None
            or self._history_band is None
            or self._history_val is None
            or self._w_counts is None
            or self._w_vals is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        if obs is not None and obs.valid:
            rewards = self._compute_rewards(obs)
            self._stats.update(obs, rewards=rewards)

            for band, r in zip(obs.bands, rewards):
                if self._steps_recorded >= self._window_size:
                    old_band = int(self._history_band[self._ptr])
                    old_val = float(self._history_val[self._ptr])
                    self._w_counts[old_band] -= 1
                    self._w_vals[old_band] -= old_val

                self._history_band[self._ptr] = band
                self._history_val[self._ptr] = r
                self._w_counts[band] += 1
                self._w_vals[band] += r
                self._ptr = (self._ptr + 1) % self._window_size
                self._steps_recorded += 1

        # Use global stats for initial exploration (not window counts) to avoid
        # deadlocking into round-robin when window_size < n_bands
        unvisited = self._stats.unvisited_bands

        t = min(self._steps_recorded, self._window_size)
        # Clip counts to avoid negative drift from floating-point subtraction
        safe_counts = np.maximum(self._w_counts, 1)
        means = self._w_vals / safe_counts
        with np.errstate(divide="ignore", invalid="ignore"):
            bonus = self._c * np.sqrt(2.0 * np.log(t) / safe_counts)
        ucb_values = means + bonus
        if self._staleness_weight > 0.0:
            ucb_values += self._staleness_weight * self._stats.staleness

        bands = self._select_top_k(ucb_values, self._k, unvisited=unvisited)
        return ScanAction(bands=bands)
