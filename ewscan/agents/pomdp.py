"""POMDP belief tracker and belief-driven scan scheduler (Sprint 3 Task 3).

Maintains a per-band belief b_t = P(band is ON at slot t | history) via a
Bayesian filter over the online p01/p10 transition estimates from
`TransitionEstimator`. Never reads emitter truth or emitter parameters.
"""

from __future__ import annotations

from dataclasses import replace

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.base import BaseLearningScheduler
from ewscan.agents.phase import PhaseOccupancy
from ewscan.agents.transition import TransitionEstimator
from ewscan.contracts import DetectorCapability, EpisodeConfig, Observation, ScanAction


class BeliefTracker:
    """Per-band Bayesian ON/OFF belief filter (predict/correct)."""

    def __init__(self, n_bands: int, pd_nominal: float, pfa: float) -> None:
        self._pd_nominal = float(pd_nominal)
        self._pfa = float(pfa)
        self._belief = np.full(n_bands, 0.5, dtype=np.float64)

    def reset(self, p01: NDArray[np.float64], p10: NDArray[np.float64]) -> None:
        """Set belief to the stationary pi_ON = p01 / (p01 + p10)."""
        pi_on = p01 / (p01 + p10)
        self._belief = np.clip(pi_on, 0.0, 1.0)

    def predict(self, p01: NDArray[np.float64], p10: NDArray[np.float64]) -> None:
        """Time update, all bands: b_pred = b*(1-p10) + (1-b)*p01."""
        b = self._belief
        b_pred = b * (1.0 - p10) + (1.0 - b) * p01
        self._belief = np.clip(b_pred, 0.0, 1.0)

    def correct(self, band: int, detection: bool) -> None:
        """Measurement update for one scanned band, given a detection bit."""
        b_pred = self._belief[band]
        pd = self._pd_nominal
        pfa = self._pfa
        l_on = pd if detection else (1.0 - pd)
        l_off = pfa if detection else (1.0 - pfa)
        denom = l_on * b_pred + l_off * (1.0 - b_pred)
        if denom < 1e-12:
            return
        b_t = (l_on * b_pred) / denom
        self._belief[band] = np.clip(b_t, 0.0, 1.0)

    @property
    def belief(self) -> NDArray[np.float64]:
        return self._belief


class BeliefScheduler(BaseLearningScheduler):
    """Scan scheduler that selects bands by threat-weighted ON belief.

    Parameters
    ----------
    pd_nominal : float, default 0.9
        Nominal detection probability used for the Bayes correction. The
        scheduler cannot know a band's true SNR, so this is a fixed
        hyperparameter rather than a per-band estimate.
    optimism : float, default 1.0
        Standard deviations of posterior optimism added when ranking bands.
        Exploration stops on its own once one band's occupancy is certain
        enough that no other band's optimistic value can reach it.
    seed : int | np.random.Generator | None, optional
        Optional random seed or Generator override for tie-breaking.
    """

    def __init__(
        self,
        pd_nominal: float = 0.9,
        optimism: float = 1.0,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        super().__init__(seed=seed)
        self._pd_nominal = float(pd_nominal)
        self._optimism = float(optimism)
        self._detector_capability: DetectorCapability | None = None
        self._transition: TransitionEstimator | None = None
        self._belief_tracker: BeliefTracker | None = None
        self._occupancy: PhaseOccupancy | None = None
        self._slot: int = 0

    @property
    def name(self) -> str:
        return "belief"

    @property
    def belief(self) -> NDArray[np.float64]:
        """Current per-band belief P(ON), the value used for selection."""
        if self._belief_tracker is None:
            raise RuntimeError("Scheduler must be reset before accessing belief")
        return self._belief_tracker.belief.copy()

    @property
    def learning_metric(self) -> str:
        return "on_probability"

    @property
    def learning_values(self) -> NDArray[np.float64]:
        return self.belief

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
        self._transition = TransitionEstimator(config.n_bands)
        self._occupancy = PhaseOccupancy(config.n_bands, config.n_slots)
        self._slot = 0
        self._belief_tracker = BeliefTracker(
            config.n_bands,
            self._detector_capability.nominal_pd,
            self._detector_capability.effective_pfa,
        )
        self._belief_tracker.reset(self._transition.p01(), self._transition.p10())

    def act(self, obs: Observation | None) -> ScanAction:
        if (
            self._transition is None
            or self._belief_tracker is None
            or self._occupancy is None
            or self._threat_map is None
            or self._n_bands is None
            or self._k is None
        ):
            raise RuntimeError("Scheduler must be reset before calling act()")

        # Correct with the PREVIOUS action's observation before predicting
        # forward, or the belief lags the true state by one slot.
        if obs is not None and obs.valid:
            for band, det in zip(obs.bands, obs.detections):
                self._transition.observe(band, obs.slot, det)
                self._belief_tracker.correct(band, det)
                self._occupancy.observe(band, obs.slot, det)

        self._belief_tracker.predict(self._transition.p01(), self._transition.p10())

        self._slot = 0 if obs is None else obs.slot + 1
        value = self._threat_map * self._occupancy.upper_bound(
            self._slot, z=self._optimism
        )
        bands = self._select_top_k(value, self._k)
        return ScanAction(bands=bands)
