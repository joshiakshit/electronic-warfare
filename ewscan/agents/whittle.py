"""Whittle index scan scheduler (Sprint 3 Task 4).

Numeric Whittle index for a Gilbert-Elliott restless bandit: for each band,
W(b) is the passive subsidy m that makes the one-arm problem indifferent
between activating and staying passive at belief b. Solved by sweeping m over
a grid and value-iterating once per m across the whole belief grid (Addendum
C-3), never by bisecting m per belief point.
"""

from __future__ import annotations

from dataclasses import replace

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.base import BaseLearningScheduler
from ewscan.agents.pomdp import BeliefTracker
from ewscan.agents.transition import TransitionEstimator
from ewscan.contracts import DetectorCapability, EpisodeConfig, Observation, ScanAction

_GRID_CACHE: dict[tuple[float, float, float, float, float, int, int, int], tuple[NDArray[np.float64], NDArray[np.float64]]] = {}


def solve_whittle_grid(
    p01: float,
    p10: float,
    pd: float,
    pfa: float,
    beta: float,
    ngrid: int,
    nm: int,
    sweeps: int,
) -> tuple[NDArray[np.float64], NDArray[np.float64]]:
    """Numeric Whittle index W(b) for one band, cached on a belief grid.

    Returns (b_grid, w_grid). Correct-then-predict order per Addendum C-2:
    b is the post-predict belief, so tau_active(b, d) = predict(correct(b, d)).

    Memoized by (p01, p10) rounded to 3 decimals: online transition estimates
    repeat often across recomputes, and selection only needs W's ranking, so
    the rounding is well within the already-accepted grid deviation.
    """
    key = (round(p01, 3), round(p10, 3), pd, pfa, beta, ngrid, nm, sweeps)
    cached = _GRID_CACHE.get(key)
    if cached is not None:
        return cached

    b = np.linspace(0.0, 1.0, ngrid)

    def predict(x: NDArray[np.float64]) -> NDArray[np.float64]:
        return x * (1.0 - p10) + (1.0 - x) * p01

    def correct(x: NDArray[np.float64], detected: bool) -> NDArray[np.float64]:
        l_on = pd if detected else (1.0 - pd)
        l_off = pfa if detected else (1.0 - pfa)
        denom = l_on * x + l_off * (1.0 - x)
        safe_denom = np.where(denom < 1e-12, 1.0, denom)
        updated = np.where(denom < 1e-12, x, (l_on * x) / safe_denom)
        return np.clip(updated, 0.0, 1.0)

    tau_active_1 = predict(correct(b, True))
    tau_active_0 = predict(correct(b, False))
    tau_passive = predict(b)
    p_detect = b * pd + (1.0 - b) * pfa

    m_grid = np.linspace(0.0, 1.0, nm)
    f = np.empty((nm, ngrid), dtype=np.float64)
    for i, m in enumerate(m_grid):
        v = b.copy()
        for _ in range(sweeps):
            active = b + beta * (
                p_detect * np.interp(tau_active_1, b, v)
                + (1.0 - p_detect) * np.interp(tau_active_0, b, v)
            )
            passive = m + beta * np.interp(tau_passive, b, v)
            v_next = np.maximum(active, passive)
            if np.max(np.abs(v_next - v)) < 1e-9:
                v = v_next
                break
            v = v_next
        active = b + beta * (
            p_detect * np.interp(tau_active_1, b, v)
            + (1.0 - p_detect) * np.interp(tau_active_0, b, v)
        )
        passive = m + beta * np.interp(tau_passive, b, v)
        f[i] = active - passive

    w = np.empty(ngrid, dtype=np.float64)
    for j in range(ngrid):
        column = f[:, j]
        if column[0] <= 0.0:
            w[j] = m_grid[0]
        elif column[-1] > 0.0:
            w[j] = m_grid[-1]
        else:
            idx = int(np.argmax(column <= 0.0))
            f0, f1 = column[idx - 1], column[idx]
            m0, m1 = m_grid[idx - 1], m_grid[idx]
            w[j] = m0 + (0.0 - f0) * (m1 - m0) / (f1 - f0)
    _GRID_CACHE[key] = (b, w)
    return b, w


class WhittleScheduler(BaseLearningScheduler):
    """Scan scheduler that selects bands by threat-weighted Whittle index.

    Parameters
    ----------
    pd_nominal : float, default 0.9
        Nominal detection probability, same hyperparameter as Task 3.
    beta : float, default 0.95
        Discount factor for the single-arm value iteration.
    ngrid : int, default 101
        Number of belief grid points the index is cached on.
    nm : int, default 50
        Number of subsidy values swept to find the active/passive crossing.
    sweeps : int, default 200
        Value iteration sweeps per subsidy value.
    recompute_interval : int, default 50
        Recompute the index grid every this many `act` calls, since p01/p10
        estimates drift slowly and a fresh grid is not needed every slot.
    seed : int | np.random.Generator | None, optional
        Optional random seed or Generator override for tie-breaking.
    """

    def __init__(
        self,
        pd_nominal: float = 0.9,
        beta: float = 0.95,
        ngrid: int = 101,
        nm: int = 50,
        sweeps: int = 200,
        recompute_interval: int = 50,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        super().__init__(seed=seed)
        self._pd_nominal = float(pd_nominal)
        self._beta = float(beta)
        self._ngrid = int(ngrid)
        self._nm = int(nm)
        self._sweeps = int(sweeps)
        self._recompute_interval = int(recompute_interval)
        self._pfa: float | None = None
        self._detector_capability: DetectorCapability | None = None
        self._transition: TransitionEstimator | None = None
        self._belief_tracker: BeliefTracker | None = None
        self._belief_grid: NDArray[np.float64] | None = None
        self._index_grid: NDArray[np.float64] | None = None
        self._slots_since_recompute: int = 0

    @property
    def name(self) -> str:
        return "whittle"

    @property
    def detector_capability(self) -> DetectorCapability:
        if self._detector_capability is None:
            raise RuntimeError("Scheduler must be reset before accessing detector capability")
        return self._detector_capability

    def reset(self, config: EpisodeConfig) -> None:
        super().reset(config)
        self._detector_capability = replace(
            config.detector_capability,
            nominal_pd=self._pd_nominal,
        )
        self._pfa = self._detector_capability.effective_pfa
        self._transition = TransitionEstimator(config.n_bands)
        self._belief_tracker = BeliefTracker(
            config.n_bands,
            self._detector_capability.nominal_pd,
            self._detector_capability.effective_pfa,
        )
        self._belief_tracker.reset(self._transition.p01(), self._transition.p10())
        self._slots_since_recompute = 0
        self._recompute_index()

    def _recompute_index(self) -> None:
        assert self._transition is not None and self._n_bands is not None
        assert self._pfa is not None
        p01 = self._transition.p01()
        p10 = self._transition.p10()
        index_grid = np.empty((self._n_bands, self._ngrid), dtype=np.float64)
        for band in range(self._n_bands):
            grid, w = solve_whittle_grid(
                p01=float(p01[band]),
                p10=float(p10[band]),
                pd=self._pd_nominal,
                pfa=self._pfa,
                beta=self._beta,
                ngrid=self._ngrid,
                nm=self._nm,
                sweeps=self._sweeps,
            )
            self._belief_grid = grid
            index_grid[band] = w
        self._index_grid = index_grid
        self._slots_since_recompute = 0

    def act(self, obs: Observation | None) -> ScanAction:
        if (
            self._transition is None
            or self._belief_tracker is None
            or self._belief_grid is None
            or self._index_grid is None
            or self._threat_map is None
            or self._n_bands is None
            or self._k is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        if obs is not None and not obs.settling:
            for band, det in zip(obs.bands, obs.detections):
                self._transition.observe(band, obs.slot, det)
                self._belief_tracker.correct(band, det)

        self._belief_tracker.predict(self._transition.p01(), self._transition.p10())

        self._slots_since_recompute += 1
        if self._slots_since_recompute >= self._recompute_interval:
            self._recompute_index()

        belief = np.clip(self._belief_tracker.belief, 0.0, 1.0)
        whittle_index = np.array(
            [
                np.interp(belief[band], self._belief_grid, self._index_grid[band])
                for band in range(self._n_bands)
            ]
        )
        value = self._threat_map * whittle_index
        bands = self._select_top_k(value, self._k)
        return ScanAction(bands=bands)
