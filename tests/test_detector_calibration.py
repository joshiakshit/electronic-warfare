"""Detector capability and scenario calibration regression tests."""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.agents.baselines import RoundRobinScheduler
from ewscan.agents.pomdp import BeliefScheduler
from ewscan.agents.whittle import WhittleScheduler
from ewscan.contracts import DetectorCapability, EpisodeConfig, EpisodeLog
from ewscan.env.detection import DetectionModel, pfa_from_threshold_dlook
from ewscan.env.environment import RFEnvironment
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import get_scenario, list_scenarios
from ewscan.metrics.detection import estimate_detection_metrics


def _config(
    *,
    pfa: float = 0.05,
    dwell: int = 1,
    detection_threshold: float | None = None,
    n_slots: int = 20,
) -> EpisodeConfig:
    return EpisodeConfig(
        n_bands=4,
        n_slots=n_slots,
        k=1,
        emitters=(),
        detection_threshold=detection_threshold,
        pfa=pfa,
        dwell=dwell,
        seed=0,
    )


def test_requested_pfa_derives_one_look_threshold() -> None:
    config = _config(pfa=1e-4)
    assert config.detection_threshold == pytest.approx(-math.log(1e-4))
    assert config.detector_capability == DetectorCapability(
        requested_pfa=1e-4,
        threshold=-math.log(1e-4),
        effective_pfa=1e-4,
        dwell=1,
        nominal_pd=0.9,
    )


def test_dwell_aware_effective_pfa_is_exposed() -> None:
    config = _config(pfa=0.05, dwell=4)
    expected = pfa_from_threshold_dlook(config.detection_threshold, 4)
    assert config.detector_capability.requested_pfa == 0.05
    assert config.detector_capability.effective_pfa == pytest.approx(expected)
    assert config.detector_capability.effective_pfa != pytest.approx(0.05)


def test_matching_explicit_threshold_is_accepted() -> None:
    pfa = 0.01
    config = _config(pfa=pfa, detection_threshold=-math.log(pfa))
    assert config.detection_threshold == pytest.approx(-math.log(pfa))


def test_mismatched_explicit_threshold_is_rejected() -> None:
    with pytest.raises(ValueError, match="does not match pfa"):
        _config(pfa=0.01, detection_threshold=3.0)


def test_detection_model_exposes_the_same_capability() -> None:
    config = _config(pfa=0.02, dwell=3)
    model = DetectionModel(
        pfa=config.pfa,
        threshold=config.detection_threshold,
        dwell=config.dwell,
    )
    assert model.capability == config.detector_capability
    assert model.get_pfa() == pytest.approx(config.detector_capability.effective_pfa)


@pytest.mark.parametrize("scheduler", [BeliefScheduler(), WhittleScheduler(ngrid=11, nm=5, sweeps=5)])
def test_bayesian_schedulers_receive_effective_capability(scheduler: object) -> None:
    config = _config(pfa=0.05, dwell=4)
    scheduler.reset(config)
    assert scheduler.detector_capability == config.detector_capability
    assert scheduler.detector_capability.effective_pfa != config.pfa


def test_detection_metrics_expose_effective_capability() -> None:
    config = _config(pfa=0.05, dwell=4, n_slots=4)
    log = EpisodeLog(
        config=config,
        truth=np.zeros((4, 4), dtype=np.bool_),
        actions=np.zeros((4, 1), dtype=np.intp),
        detections=np.zeros((4, 1), dtype=np.bool_),
    )
    metrics = estimate_detection_metrics(log)
    assert metrics.capability == config.detector_capability


def test_serialized_episode_exposes_requested_and_effective_pfa() -> None:
    config = _config(pfa=0.05, dwell=4)
    result = run_episode(config, RoundRobinScheduler())
    serialized = result.to_dict()
    assert serialized["detector_requested_pfa"] == 0.05
    assert serialized["detector_effective_pfa"] == pytest.approx(
        config.detector_capability.effective_pfa
    )
    assert serialized["detector_threshold"] == pytest.approx(config.detection_threshold)
    assert serialized["detector_dwell"] == 4


@pytest.mark.parametrize("scenario_name", list_scenarios())
def test_standard_scenario_detector_calibration(scenario_name: str) -> None:
    config = get_scenario(scenario_name, n_slots=20)
    environment = RFEnvironment(config)
    environment.reset()

    capability = environment.detection_model.capability
    assert capability == config.detector_capability
    assert capability.threshold == pytest.approx(-math.log(capability.requested_pfa))

    n_trials = 500_000
    environment.detection_model.reset(np.random.default_rng(100))
    false_alarms = environment.detection_model.detect_batch(
        0.0,
        np.zeros(n_trials, dtype=np.bool_),
    )
    empirical = float(false_alarms.mean())
    sigma = math.sqrt(
        capability.effective_pfa * (1.0 - capability.effective_pfa) / n_trials
    )
    assert empirical == pytest.approx(capability.effective_pfa, abs=5.0 * sigma)


def test_dwell_aware_quiet_band_monte_carlo_matches_capability() -> None:
    model = DetectionModel(pfa=0.05, dwell=4)
    model.reset(np.random.default_rng(22))
    n_trials = 300_000
    false_alarms = model.detect_batch(0.0, np.zeros(n_trials, dtype=np.bool_))
    empirical = float(false_alarms.mean())
    expected = model.capability.effective_pfa
    sigma = math.sqrt(expected * (1.0 - expected) / n_trials)
    assert empirical == pytest.approx(expected, abs=5.0 * sigma)
