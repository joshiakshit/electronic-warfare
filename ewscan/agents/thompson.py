"""Thompson Sampling scan scheduler with Beta posterior (Phase 1D.5).

Bayesian posterior sampling for multi-armed bandit ES receiver scheduling:
- For each band i, maintains a conjugate Beta(alpha_i, beta_i) posterior over
  the true transmission probability theta_i in [0, 1].
- In each slot, samples theta_hat_i ~ Beta(alpha_i, beta_i) for all bands.
- Selects the band maximizing the sampled score (with optional threat weighting
  or reward function shaping).
- Upon receiving sensor feedback (hit/miss), performs the exact Bayesian update:
  alpha_i <- alpha_i + 1 (on detection), beta_i <- beta_i + 1 (on miss).
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.base import BaseLearningScheduler
from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EpisodeConfig, Observation, ScanAction


class ThompsonSamplingScheduler(BaseLearningScheduler):
    """Thompson Sampling scan scheduler with Beta posterior (Phase 1D.5).

    Maintains independent Beta posteriors for each band:
        theta_i ~ Beta(alpha_i, beta_i)
    and samples candidate values theta_hat_i to make scan decisions,
    guaranteeing Bayesian probability matching and convergence of the posterior
    mean to the true transmission probability.

    Parameters
    ----------
    alpha_prior : float, default 1.0
        Prior pseudo-count for positive detections (alpha_0 > 0). Default is 1.0 (uniform prior).
    beta_prior : float, default 1.0
        Prior pseudo-count for misses (beta_0 > 0). Default is 1.0 (uniform prior).
    reward_fn : RewardFunction | None, optional
        Optional custom RewardFunction instance. If provided, expected reward is computed
        from the sampled activation probabilities, staleness, and threat levels.
    use_threat_weighting : bool, default False
        When `reward_fn` is None, if True, weights sampled activation probabilities by the
        band's threat level (`threat * theta_hat`). If False, uses raw sampled probability.
    seed : int | np.random.Generator | None, optional
        Optional random seed or Generator override for sampling and tie-breaking.
        If None, derived from `EpisodeConfig.seed`.
    """

    def __init__(
        self,
        alpha_prior: float = 1.0,
        beta_prior: float = 1.0,
        reward_fn: RewardFunction | None = None,
        use_threat_weighting: bool = False,
        staleness_weight: float = 0.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        if alpha_prior <= 0.0:
            raise ValueError(
                f"alpha_prior must be strictly positive, got {alpha_prior}"
            )
        if beta_prior <= 0.0:
            raise ValueError(
                f"beta_prior must be strictly positive, got {beta_prior}"
            )
        super().__init__(
            reward_fn=reward_fn,
            use_threat_weighting=use_threat_weighting,
            staleness_weight=staleness_weight,
            seed=seed,
        )

        self._alpha_prior = float(alpha_prior)
        self._beta_prior = float(beta_prior)
        self._alpha: NDArray[np.float64] | None = None
        self._beta: NDArray[np.float64] | None = None

    @property
    def name(self) -> str:
        return "thompson_sampling"

    @property
    def alpha_prior(self) -> float:
        """Configured prior pseudo-count for detections."""
        return self._alpha_prior

    @property
    def beta_prior(self) -> float:
        """Configured prior pseudo-count for misses."""
        return self._beta_prior

    @property
    def alpha(self) -> NDArray[np.float64]:
        """Current posterior alpha parameters across all bands."""
        if self._alpha is None:
            raise RuntimeError("Scheduler must be reset before accessing alpha")
        return self._alpha.copy()

    @property
    def beta(self) -> NDArray[np.float64]:
        """Current posterior beta parameters across all bands."""
        if self._beta is None:
            raise RuntimeError("Scheduler must be reset before accessing beta")
        return self._beta.copy()

    @property
    def posterior_means(self) -> NDArray[np.float64]:
        """Current posterior means (alpha / (alpha + beta)) across all bands."""
        if self._alpha is None or self._beta is None:
            raise RuntimeError("Scheduler must be reset before accessing posterior_means")
        return self._alpha / (self._alpha + self._beta)

    def reset(self, config: EpisodeConfig) -> None:
        """Reset scheduler state for a new episode."""
        super().reset(config)
        # Initialize Beta posterior parameters
        self._alpha = np.full(config.n_bands, self._alpha_prior, dtype=np.float64)
        self._beta = np.full(config.n_bands, self._beta_prior, dtype=np.float64)

    def act(self, obs: Observation | None) -> ScanAction:
        """Update posterior statistics with incoming observation and sample next band."""
        if (
            self._stats is None
            or self._n_bands is None
            or self._threat_map is None
            or self._rng is None
            or self._alpha is None
            or self._beta is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        # Step 1: Update statistics and Bayesian Beta posterior with incoming observation
        if obs is not None:
            rewards = self._compute_rewards(obs)
            self._stats.update(obs, rewards=rewards)

            # Exact Beta-Bernoulli conjugate update per channel
            for band, det in zip(obs.bands, obs.detections):
                if det:
                    self._alpha[band] += 1.0
                else:
                    self._beta[band] += 1.0

        # Step 2: Draw samples from posterior distributions
        # theta_hat_i ~ Beta(alpha_i, beta_i)
        sampled_thetas = self._rng.beta(self._alpha, self._beta)

        # Step 3: Compute decision scores
        if self._reward_fn is not None:
            # Expected reward computed from sampled activation probability
            scores = np.empty(self._n_bands, dtype=np.float64)
            cd = (
                self._reward_fn.cooldown
                if self._reward_fn.cooldown is not None
                else self._n_bands
            )
            for b in range(self._n_bands):
                s = self._stats.get_staleness(b)
                threat = float(self._threat_map[b])
                theta = float(sampled_thetas[b])

                r_hit = self._reward_fn.w_threat * threat
                r_miss = -self._reward_fn.c_miss
                r_novelty = self._reward_fn.w_novelty * min(s / self._n_bands, 1.0)
                r_decay = (
                    -self._reward_fn.w_decay * max(0.0, 1.0 - s / cd)
                    if cd > 0
                    else 0.0
                )
                scores[b] = theta * r_hit + (1.0 - theta) * r_miss + r_novelty + r_decay
        elif self._use_threat_weighting:
            scores = sampled_thetas * self._threat_map
        else:
            scores = sampled_thetas

        if self._staleness_weight > 0.0:
            scores = scores + self._staleness_weight * self._stats.staleness

        # Select the k highest-scoring distinct arms
        bands = self._select_top_k(scores, self._k)
        return ScanAction(bands=bands)


# Convenient alias
BetaThompsonSamplingScheduler = ThompsonSamplingScheduler


class DiscountedThompsonScheduler(ThompsonSamplingScheduler):
    """Thompson Sampling with posterior decay for restless arms (Phase 1D.6).

    At every step, all bands' Beta parameters decay toward the prior before the
    observation update. This keeps the effective sample size bounded, so the
    agent can recover from abrupt emitter state changes.
    """

    def __init__(
        self,
        gamma: float = 0.95,
        alpha_prior: float = 1.0,
        beta_prior: float = 1.0,
        reward_fn: RewardFunction | None = None,
        use_threat_weighting: bool = False,
        staleness_weight: float = 0.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        if not (0.0 < gamma <= 1.0):
            raise ValueError(f"gamma must be in (0, 1], got {gamma}")
        super().__init__(
            alpha_prior=alpha_prior,
            beta_prior=beta_prior,
            reward_fn=reward_fn,
            use_threat_weighting=use_threat_weighting,
            staleness_weight=staleness_weight,
            seed=seed,
        )
        self._gamma = gamma

    @property
    def name(self) -> str:
        return "discounted_thompson_sampling"

    @property
    def gamma(self) -> float:
        return self._gamma

    def act(self, obs: Observation | None) -> ScanAction:
        if (
            self._alpha is None
            or self._beta is None
            or self._stats is None
            or self._n_bands is None
            or self._threat_map is None
            or self._rng is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        # Decay all bands toward the prior
        self._alpha[:] = self._alpha_prior + self._gamma * (self._alpha - self._alpha_prior)
        self._beta[:] = self._beta_prior + self._gamma * (self._beta - self._beta_prior)

        # Update stats and posterior with the observation
        if obs is not None:
            rewards = self._compute_rewards(obs)
            self._stats.update(obs, rewards=rewards)

            for band, det in zip(obs.bands, obs.detections):
                if det:
                    self._alpha[band] += 1.0
                else:
                    self._beta[band] += 1.0

        # Sample and select (same logic as parent)
        sampled_thetas = self._rng.beta(self._alpha, self._beta)

        if self._reward_fn is not None:
            scores = np.empty(self._n_bands, dtype=np.float64)
            cd = (
                self._reward_fn.cooldown
                if self._reward_fn.cooldown is not None
                else self._n_bands
            )
            for b in range(self._n_bands):
                s = self._stats.get_staleness(b)
                threat = float(self._threat_map[b])
                theta = float(sampled_thetas[b])
                r_hit = self._reward_fn.w_threat * threat
                r_miss = -self._reward_fn.c_miss
                r_novelty = self._reward_fn.w_novelty * min(s / self._n_bands, 1.0)
                r_decay = (
                    -self._reward_fn.w_decay * max(0.0, 1.0 - s / cd)
                    if cd > 0
                    else 0.0
                )
                scores[b] = theta * r_hit + (1.0 - theta) * r_miss + r_novelty + r_decay
        elif self._use_threat_weighting:
            scores = sampled_thetas * self._threat_map
        else:
            scores = sampled_thetas

        if self._staleness_weight > 0.0:
            scores = scores + self._staleness_weight * self._stats.staleness

        bands = self._select_top_k(scores, self._k)
        return ScanAction(bands=bands)
