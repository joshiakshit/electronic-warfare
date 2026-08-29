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
    min_incremental_value : float, default 0.0
        Required lower-bound advantage over the replaced inner band.
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
        min_incremental_value: float = 0.0,
        predictor_capacity: int | None = None,
        predictor_window: int = 20,
        seed: int | np.random.Generator | None = None,
    ) -> None:
        super().__init__(seed=seed)
        self._inner = inner if inner is not None else UCB1Scheduler()
        self._tau_conf = float(tau_conf)
        self._min_incremental_value = float(min_incremental_value)
        self._predictor_capacity = predictor_capacity
        self._predictor_window = predictor_window
        self._predictor: NextTxPredictor | None = None
        self.predicted_band = -1
        self.prediction_band = -1
        self.prediction_confidence = 0.0
        self.inner_action: tuple[int, ...] = ()
        self.executed_action: tuple[int, ...] = ()
        self.did_override = False

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
        self.prediction_band = -1
        self.prediction_confidence = 0.0
        self.inner_action = ()
        self.executed_action = ()
        self.did_override = False

    def _inner_upper_value(self, band: int) -> float:
        if not isinstance(self._inner, BaseLearningScheduler):
            return float("inf")
        if (
            self._inner._reward_fn is not None
            or self._inner._use_threat_weighting
        ):
            return float("inf")
        count = self._inner.stats.get_count(band)
        if count == 0:
            return float("inf")
        hits = self._inner.stats.get_hits(band)
        mean = (hits + 1.0) / (count + 2.0)
        uncertainty = np.sqrt(mean * (1.0 - mean) / (count + 3.0))
        return float(mean + uncertainty)

    def _incremental_value(self, predicted_band: int, inner_bands: list[int]) -> float:
        assert self._predictor is not None
        predicted_lower = self._predictor.lower_confidence(predicted_band)
        replaced_upper = min(self._inner_upper_value(band) for band in inner_bands)
        return predicted_lower - replaced_upper

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
        self.inner_action = tuple(inner_bands)

        current_slot = 0 if obs is None else obs.slot + 1
        due = self._predictor.due_bands(current_slot)
        sniped_band = None
        confidence = 0.0
        if due:
            sniped_band, confidence = max(
                due, key=lambda item: (item[1], self._threat_map[item[0]])
            )

        self.prediction_band = -1 if sniped_band is None else sniped_band
        self.predicted_band = self.prediction_band
        self.prediction_confidence = confidence
        self.did_override = False

        if (
            sniped_band is not None
            and sniped_band not in inner_bands
            and self._incremental_value(sniped_band, inner_bands)
            >= self._min_incremental_value
        ):
            bands = inner_bands
            replaced = min(range(len(bands)), key=lambda index: self._inner_upper_value(bands[index]))
            bands[replaced] = sniped_band
            self.did_override = True
        else:
            bands = inner_bands

        self.executed_action = tuple(bands)
        return ScanAction(bands=self.executed_action)
