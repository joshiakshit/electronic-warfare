"""Sniper + bandit arbiter (Sprint 3, Task 7).

Wraps an inner bandit scheduler with a NextTxPredictor. When the predictor is
confident a band is due now, the sniper reserves one channel for it; every
other slot the inner bandit's own choice stands unchanged. Never reads truth,
emitter SNR, or emitter params.
"""

from __future__ import annotations

import numpy as np

from ewscan.agents.base import BaseLearningScheduler
from ewscan.agents.predictor import NextTxPredictor
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import EpisodeConfig, Observation, ScanAction, Scheduler


class SniperScheduler(BaseLearningScheduler):
    """Reserves one scan channel for a confident, due next-transmission prediction.

    Parameters
    ----------
    inner : Scheduler | None, optional
        Bandit scheduler that supplies the baseline K-band choice and learns
        from the executed observation. Defaults to a fresh ``UCB1Scheduler``.
        Constructed and seeded independently of the sniper; the sniper never
        passes it a seed or RNG, so its action sequence is unaffected by
        whether the sniper is confident or not (Task 7 test 5).
    tau_conf : float, default 0.6
        Confidence threshold passed to the internal ``NextTxPredictor``.
    predictor_capacity : int | None, optional
        Ring-buffer capacity for the internal ``PeriodEstimator``. Defaults to
        ``config.n_slots`` at reset time.
    predictor_window : int, default 20
        Outcome window passed to the internal ``NextTxPredictor``.
    seed : int | np.random.Generator | None, optional
        Seed for the sniper's own RNG (currently unused for selection, since
        all band choice is either delegated to `inner` or resolved by threat
        tie-break). Kept for base-class compatibility.
    """

    def __init__(
        self,
        inner: Scheduler | None = None,
        tau_conf: float = 0.6,
        predictor_capacity: int | None = None,
        predictor_window: int = 20,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        super().__init__(seed=seed)
        self._inner = inner if inner is not None else UCB1Scheduler()
        self._tau_conf = float(tau_conf)
        self._predictor_capacity = predictor_capacity
        self._predictor_window = predictor_window
        self._predictor: NextTxPredictor | None = None
        self.predicted_band = -1

    @property
    def name(self) -> str:
        return "sniper"

    def reset(self, config: EpisodeConfig) -> None:
        super().reset(config)
        self._inner.reset(config)
        capacity = (
            self._predictor_capacity
            if self._predictor_capacity is not None
            else config.n_slots
        )
        self._predictor = NextTxPredictor(
            config.n_bands,
            capacity,
            tau_conf=self._tau_conf,
            window=self._predictor_window,
        )
        self.predicted_band = -1

    def act(self, obs: Observation | None) -> ScanAction:
        if self._predictor is None or self._k is None or self._threat_map is None:
            raise RuntimeError("Scheduler must be reset before calling act()")

        # Score and fold in the previous action's outcomes before choosing
        # the next slot. Addendum E: record_outcome must run before observe,
        # or observe's _last_hit advance makes the due-slot check look wrong.
        if obs is not None and obs.valid:
            for band, det in zip(obs.bands, obs.detections):
                self._predictor.record_outcome(band, obs.slot, det)
                self._predictor.observe(band, obs.slot, det)

        # Inner bandit always learns from the real, executed observation and
        # always supplies the baseline choice, whether or not it gets overridden.
        inner_bands = list(self._inner.act(obs).bands)

        current_slot = 0 if obs is None else obs.slot + 1
        due = self._predictor.due_bands(current_slot)
        sniped_band = None
        if due:
            sniped_band = max(due, key=lambda item: self._threat_map[item[0]])[0]

        if sniped_band is not None and sniped_band not in inner_bands:
            # inner_bands are distinct and sniped_band is confirmed absent, so
            # replacing exactly one entry keeps the list distinct by construction.
            bands = inner_bands
            bands[-1] = sniped_band
            self.predicted_band = sniped_band
        else:
            bands = inner_bands
            self.predicted_band = -1

        return ScanAction(bands=tuple(bands))
