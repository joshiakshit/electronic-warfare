"""Baseline scan schedulers for ewscan (Track B -- Phase 1C.1 - 1C.4).

Contains:
- RoundRobinScheduler: Sequential scan across all available bands.
- UniformRandomScheduler: Open-loop uniform random scanning across bands.
- PriorWeightedScheduler: Open-loop stochastic scanning sampled from a prior vector.
- OracleScheduler: Omniscient scan scheduler reading truth via side channel.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import (
    EpisodeConfig,
    Observation,
    ScanAction,
    Scheduler,
    SchedulerConfig,
    as_scheduler_config,
)
from ewscan.rng import make_generators


class RoundRobinScheduler(Scheduler):
    """Sequential sweep across all frequency bands in order (Phase 1C.1).

    Parameters
    ----------
    start_band : int, default 0
        Initial band index to begin the sweep from.
    """

    def __init__(self, start_band: int = 0) -> None:
        self._start_band = start_band
        self._current_band = start_band
        self._n_bands: int | None = None
        self._k: int | None = None

    def reset(self, config: EpisodeConfig) -> None:
        """Reset scheduler state for a new episode."""
        if config.n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {config.n_bands}")
        self._n_bands = config.n_bands
        self._k = config.k
        self._current_band = self._start_band % self._n_bands

    def act(self, obs: Observation | None) -> ScanAction:
        """Select the next k bands sequentially (wrapping)."""
        if self._n_bands is None or self._k is None:
            raise RuntimeError("Scheduler must be reset before calling act()")

        bands = tuple(
            (self._current_band + i) % self._n_bands for i in range(self._k)
        )
        self._current_band = (self._current_band + self._k) % self._n_bands
        return ScanAction(bands=bands)

    @property
    def name(self) -> str:
        return "round_robin"


class UniformRandomScheduler(Scheduler):
    """Uniform random open-loop scheduler (Phase 1C.2).

    Selects bands uniformly at random in each slot.

    Parameters
    ----------
    seed : int | np.random.Generator | None, optional
        Optional seed or Generator override. If None, derives generator from
        EpisodeConfig.seed via make_generators.
    """

    def __init__(self, seed: int | np.random.Generator | None = None) -> None:
        self._seed = seed
        self._rng: np.random.Generator | None = None
        self._n_bands: int | None = None
        self._k: int | None = None

    def reset(self, config: EpisodeConfig) -> None:
        """Reset scheduler state and derive random generator."""
        if config.n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {config.n_bands}")
        self._n_bands = config.n_bands
        self._k = config.k

        if isinstance(self._seed, np.random.Generator):
            self._rng = self._seed
        elif self._seed is not None:
            self._rng = np.random.default_rng(self._seed)
        else:
            self._rng = make_generators(config.seed)["scheduler"]

    def act(self, obs: Observation | None) -> ScanAction:
        """Select k distinct bands uniformly at random."""
        if self._n_bands is None or self._rng is None or self._k is None:
            raise RuntimeError("Scheduler must be reset before calling act()")

        if self._k == 1:
            bands = (int(self._rng.integers(0, self._n_bands)),)
        else:
            bands = tuple(
                int(b)
                for b in self._rng.choice(self._n_bands, size=self._k, replace=False)
            )
        return ScanAction(bands=bands)

    @property
    def name(self) -> str:
        return "uniform_random"


class PriorWeightedScheduler(Scheduler):
    """Prior-weighted open-loop scheduler (Phase 1C.3).

    Selects bands according to a user-supplied prior probability vector.

    Parameters
    ----------
    priors : Sequence[float] | None, optional
        Vector of prior non-negative weights for each band. Normalization is
        handled automatically. If None, defaults to uniform priors over config.n_bands.
    seed : int | np.random.Generator | None, optional
        Optional seed or Generator override. If None, derives generator from
        EpisodeConfig.seed via make_generators.
    """

    def __init__(
        self,
        priors: Sequence[float] | None = None,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        self._raw_priors = tuple(priors) if priors is not None else None
        self._seed = seed
        self._rng: np.random.Generator | None = None
        self._n_bands: int | None = None
        self._k: int | None = None
        self._probs: NDArray[np.float64] | None = None

    def reset(self, config: SchedulerConfig | EpisodeConfig) -> None:
        """Reset scheduler state, set normalized priors, and derive generator."""
        config = as_scheduler_config(config)
        if config.n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {config.n_bands}")
        self._n_bands = config.n_bands
        self._k = config.k

        if self._raw_priors is None:
            if config.threat_prior is None:
                arr = np.ones(config.n_bands, dtype=np.float64)
            else:
                arr = np.asarray(config.threat_prior.weights, dtype=np.float64)
                if float(arr.sum()) == 0.0:
                    arr = np.ones(config.n_bands, dtype=np.float64)
            self._probs = arr / float(arr.sum())
        else:
            if len(self._raw_priors) != config.n_bands:
                raise ValueError(
                    f"Priors length ({len(self._raw_priors)}) does not match "
                    f"n_bands ({config.n_bands})"
                )
            arr = np.array(self._raw_priors, dtype=np.float64)
            if np.any(arr < 0) or np.any(np.isnan(arr)) or np.any(np.isinf(arr)):
                raise ValueError("Prior probabilities must be non-negative finite numbers")
            total = float(np.sum(arr))
            if total <= 0:
                raise ValueError("Sum of prior probabilities must be positive")
            self._probs = arr / total

        if isinstance(self._seed, np.random.Generator):
            self._rng = self._seed
        elif self._seed is not None:
            self._rng = np.random.default_rng(self._seed)
        else:
            self._rng = make_generators(config.seed)["scheduler"]

    def act(self, obs: Observation | None) -> ScanAction:
        """Select k distinct bands according to the prior distribution."""
        if (
            self._n_bands is None
            or self._rng is None
            or self._probs is None
            or self._k is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        if self._k == 1:
            bands = (int(self._rng.choice(self._n_bands, p=self._probs)),)
        else:
            positive = np.flatnonzero(self._probs > 0.0)
            if len(positive) >= self._k:
                selected = self._rng.choice(
                    self._n_bands, size=self._k, replace=False, p=self._probs
                )
            else:
                zero_weight = np.flatnonzero(self._probs == 0.0)
                filler = self._rng.choice(
                    zero_weight,
                    size=self._k - len(positive),
                    replace=False,
                )
                selected = np.concatenate((positive, filler))
            bands = tuple(int(band) for band in selected)
        return ScanAction(bands=bands)

    @property
    def name(self) -> str:
        return "prior_weighted"


class OracleScheduler(Scheduler):
    """Omniscient scan scheduler with ground-truth side-channel access (Phase 1C.4).

    The oracle acts as the theoretical upper bound / scoreboard ceiling for
    scan scheduling performance. At each slot, it inspects the true RF activity
    across all bands and selects an active band (prioritizing higher-threat emitters
    if multiple bands are active simultaneously). If no band is transmitting,
    it falls back to a deterministic round-robin sweep.

    Truth access is strictly provided via explicit constructor/setter injection
    and is never exposed through Observation objects.

    Parameters
    ----------
    truth : NDArray[np.bool_] | Sequence[Sequence[bool]] | None, optional
        Ground-truth transmission matrix of shape (n_bands, n_slots). Can also
        be set or updated via `set_truth()`.
    """

    def __init__(
        self,
        truth: NDArray[np.bool_] | Sequence[Sequence[bool]] | None = None,
    ) -> None:
        self._truth: NDArray[np.bool_] | None = None
        self._n_bands: int | None = None
        self._n_slots: int | None = None
        self._k: int | None = None
        self._slot: int = 0
        self._threat_weights: NDArray[np.float64] | None = None

        if truth is not None:
            self.set_truth(truth)

    def set_truth(
        self,
        truth: NDArray[np.bool_] | Sequence[Sequence[bool]],
    ) -> None:
        """Set or update the ground-truth transmission matrix.

        Parameters
        ----------
        truth : NDArray[np.bool_] | Sequence[Sequence[bool]]
            2-dimensional boolean array of shape (n_bands, n_slots).
        """
        arr = np.asarray(truth, dtype=np.bool_)
        if arr.ndim != 2:
            raise ValueError(
                f"Truth matrix must be 2-dimensional (n_bands, n_slots), got shape {arr.shape}"
            )
        self._truth = arr.copy()

    @property
    def truth(self) -> NDArray[np.bool_] | None:
        """Copy of current ground-truth transmission matrix if set."""
        return self._truth.copy() if self._truth is not None else None

    def reset(self, config: EpisodeConfig) -> None:
        """Reset scheduler state for a new episode."""
        if config.n_bands <= 0:
            raise ValueError(f"n_bands must be positive, got {config.n_bands}")
        if config.n_slots <= 0:
            raise ValueError(f"n_slots must be positive, got {config.n_slots}")

        if self._truth is None:
            raise RuntimeError(
                "Truth matrix must be set before resetting or running OracleScheduler"
            )

        if self._truth.shape != (config.n_bands, config.n_slots):
            raise ValueError(
                f"Truth matrix shape {self._truth.shape} does not match config "
                f"({config.n_bands}, {config.n_slots})"
            )

        self._n_bands = config.n_bands
        self._n_slots = config.n_slots
        self._k = config.k
        self._slot = 0

        self._threat_weights = np.zeros(config.n_bands, dtype=np.float64)
        for em in config.emitters:
            if 0 <= em.band < config.n_bands:
                self._threat_weights[em.band] = max(
                    self._threat_weights[em.band], float(em.threat_level)
                )

    def act(self, obs: Observation | None) -> ScanAction:
        """Select active band using ground truth knowledge."""
        if (
            self._n_bands is None
            or self._n_slots is None
            or self._truth is None
            or self._threat_weights is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        t = self._slot
        chosen: list[int] = []
        if t < self._n_slots:
            active = np.flatnonzero(self._truth[:, t])
            if len(active) > 0:
                order = active[np.argsort(-self._threat_weights[active], kind="stable")]
                chosen = [int(b) for b in order[: self._k]]

        # Fill any spare channels with distinct round-robin bands
        i = 0
        while len(chosen) < self._k:
            b = (t + i) % self._n_bands
            if b not in chosen:
                chosen.append(b)
            i += 1

        self._slot += 1
        return ScanAction(bands=tuple(chosen))

    @property
    def name(self) -> str:
        return "oracle"
