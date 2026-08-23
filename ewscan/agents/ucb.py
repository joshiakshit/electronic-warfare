"""UCB1 scan scheduler for ewscan (Phase 1D.3).

Textbook stationary upper confidence bound (UCB1) multi-armed bandit algorithm.
Selects bands according to:
    Q_i(t) = hat{mu}_i + c * sqrt(2 * ln(t) / N_i)
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.base import BaseLearningScheduler
from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EpisodeConfig, Observation, ScanAction


class UCB1Scheduler(BaseLearningScheduler):
    """Textbook stationary UCB1 scan scheduler (Phase 1D.3).

    Initializes by scanning every band once, then selects bands that maximize
    the upper confidence bound:
        Q_i(t) = hat{mu}_i + c * sqrt(2 * ln(t) / N_i)

    Parameters
    ----------
    c : float, default 1.0
        Exploration bonus coefficient.
    reward_fn : RewardFunction | None, optional
        Optional custom RewardFunction instance. If provided, reward is computed
        via `reward_fn.compute()` and the empirical mean reward is used as hat{mu}_i.
        If None, empirical detection rate (or threat-weighted detection) is used.
    use_threat_weighting : bool, default False
        When `reward_fn` is None, if True, weights binary detections by the band's
        threat level (`threat * detection`). If False, uses raw binary detection.
    seed : int | np.random.Generator | None, optional
        Optional random seed or Generator override for tie-breaking. If None,
        derived from `EpisodeConfig.seed`.
    """

    def __init__(
        self,
        c: float = 1.0,
        reward_fn: RewardFunction | None = None,
        use_threat_weighting: bool = False,
        staleness_weight: float = 0.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        if c < 0:
            raise ValueError(f"Exploration coefficient c must be non-negative, got {c}")
        super().__init__(
            reward_fn=reward_fn,
            use_threat_weighting=use_threat_weighting,
            staleness_weight=staleness_weight,
            seed=seed,
        )
        self._c = float(c)

    @property
    def name(self) -> str:
        return "ucb1"

    @property
    def c(self) -> float:
        """Exploration bonus multiplier."""
        return self._c

    def act(self, obs: Observation | None) -> ScanAction:
        """Update statistics with incoming observation and select next band."""
        if (
            self._stats is None
            or self._n_bands is None
            or self._threat_map is None
            or self._rng is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        # Step 1: Update statistics with incoming observation
        if obs is not None:
            r = self._compute_reward(obs)
            self._stats.update(obs, reward=r)

        # Step 2: Band selection
        # Phase 1: Unvisited arms exploration (pull each arm once)
        unvisited = self._stats.unvisited_bands
        if len(unvisited) > 0:
            chosen_band = int(unvisited[0])
            return ScanAction(band=chosen_band)

        # Phase 2: UCB1 score computation
        counts = self._stats.counts
        t = self._stats.total_pulls

        if self._reward_fn is not None or self._use_threat_weighting:
            means = self._stats.mean_rewards
        else:
            means = self._stats.mean_detections

        # UCB1 formula: hat{mu}_i + c * sqrt(2 * ln(t) / N_i)
        bonus = self._c * np.sqrt(2.0 * np.log(t) / counts)
        ucb_values = means + bonus
        if self._staleness_weight > 0.0:
            ucb_values += self._staleness_weight * self._stats.staleness

        # Select arm with maximum UCB value (break ties uniformly at random or deterministically)
        max_val = np.max(ucb_values)
        best_candidates = np.flatnonzero(np.isclose(ucb_values, max_val, rtol=1e-12, atol=1e-12))
        if len(best_candidates) == 1:
            chosen_band = int(best_candidates[0])
        else:
            chosen_band = int(self._rng.choice(best_candidates))

        return ScanAction(band=chosen_band)
