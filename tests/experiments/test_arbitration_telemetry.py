"""Objective 7 runner telemetry tests."""

from __future__ import annotations

from ewscan.contracts import Observation, ScanAction, Scheduler
from ewscan.experiments.runner import run_episode

from tests.experiments.test_prediction_wiring import _alternating_truth_config


class _TelemetryScheduler(Scheduler):
    def reset(self, config) -> None:
        pass

    def act(self, obs: Observation | None) -> ScanAction:
        self.predicted_band = 1
        self.prediction_band = 1
        self.prediction_confidence = 0.8
        self.inner_action = (0,)
        self.executed_action = (1,)
        self.did_override = True
        return ScanAction(bands=(1,))

    @property
    def name(self) -> str:
        return "telemetry"


def test_runner_records_prediction_and_override_telemetry_separately():
    config = _alternating_truth_config(n_slots=4)

    result = run_episode(config, _TelemetryScheduler())

    assert result.arbitration is not None
    assert result.arbitration.prediction_band.tolist() == [1, 1, 1, 1]
    assert result.arbitration.prediction_confidence.tolist() == [0.8] * 4
    assert result.arbitration.inner_action.tolist() == [[0]] * 4
    assert result.arbitration.executed_action.tolist() == [[1]] * 4
    assert result.arbitration.did_override.tolist() == [True] * 4
