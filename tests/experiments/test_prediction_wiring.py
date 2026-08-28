"""Tests for prediction wiring in run_episode (Sprint 3 Task 0).

Verifies the runner collects per-slot band predictions from an opt-in
scheduler attribute (`predicted_band`) and feeds them to
estimate_prediction_metrics, without changing behavior for schedulers
that never set the attribute.
"""

from __future__ import annotations

import numpy as np

from ewscan.agents.baselines import RoundRobinScheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig, Observation, ScanAction, Scheduler
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import get_scenario


def _alternating_truth_config(n_slots: int = 20) -> EpisodeConfig:
    """Two bands whose periodic emitters alternate: band 0 ON on even slots,
    band 1 ON on odd slots. Deterministic (no jitter), so exposes any
    off-by-one shift between predicted_band and the slot it's scored against.
    """
    emitters = (
        EmitterInfo(
            band=0, snr=20.0, threat_level=1.0, emitter_type="periodic",
            params={"period": 2, "dwell": 1, "jitter": 0, "phase": 0},
        ),
        EmitterInfo(
            band=1, snr=20.0, threat_level=1.0, emitter_type="periodic",
            params={"period": 2, "dwell": 1, "jitter": 0, "phase": 1},
        ),
    )
    return EpisodeConfig(
        n_bands=2,
        n_slots=n_slots,
        k=1,
        emitters=emitters,
        detection_threshold=3.0,
        pfa=1e-3,
        seed=0,
    )


class _AlternatingPredictor(Scheduler):
    """Predicts band 0 on even acting slots, band 1 on odd acting slots.

    Matches the truth built by _alternating_truth_config exactly.
    """

    def __init__(self) -> None:
        self._t = 0

    def reset(self, config: EpisodeConfig) -> None:
        self._t = 0

    def act(self, obs: Observation | None) -> ScanAction:
        self.predicted_band = 0 if self._t % 2 == 0 else 1
        self._t += 1
        return ScanAction(bands=(0,))

    @property
    def name(self) -> str:
        return "alternating_predictor"


class _AlwaysNegativePredictor(Scheduler):
    """Explicitly sets predicted_band = -1 every slot (never predicts)."""

    def reset(self, config: EpisodeConfig) -> None:
        pass

    def act(self, obs: Observation | None) -> ScanAction:
        self.predicted_band = -1
        return ScanAction(bands=(0,))

    @property
    def name(self) -> str:
        return "always_negative"


class _OddSlotPredictor(Scheduler):
    """Sets predicted_band on odd acting slots only; unset (default -1) on even."""

    def __init__(self) -> None:
        self._t = 0

    def reset(self, config: EpisodeConfig) -> None:
        self._t = 0

    def act(self, obs: Observation | None) -> ScanAction:
        if self._t % 2 == 1:
            self.predicted_band = 0
        else:
            self.predicted_band = -1
        self._t += 1
        return ScanAction(bands=(0,))

    @property
    def name(self) -> str:
        return "odd_slot_predictor"


def test_backward_compatibility_round_robin_mixed_threat():
    config = get_scenario("mixed_threat")
    result = run_episode(config, RoundRobinScheduler(), seed=42)

    assert result.prediction.active is False
    assert result.prediction.accuracy is None
    assert result.prediction.n_predictions == 0


def test_alternating_predictor_scores_perfect_accuracy():
    config = _alternating_truth_config(n_slots=20)
    result = run_episode(config, _AlternatingPredictor(), seed=0)

    assert result.prediction.active is True
    assert result.prediction.accuracy == 1.0
    assert result.prediction.n_predictions == config.n_slots


def test_always_negative_predictor_gives_no_active_predictions():
    config = _alternating_truth_config(n_slots=20)
    result = run_episode(config, _AlwaysNegativePredictor(), seed=0)

    assert result.prediction.n_predictions == 0
    assert result.prediction.accuracy is None


def test_odd_slot_predictor_counts_half_the_slots():
    config = _alternating_truth_config(n_slots=20)
    result = run_episode(config, _OddSlotPredictor(), seed=0)

    assert result.prediction.n_predictions == config.n_slots // 2
