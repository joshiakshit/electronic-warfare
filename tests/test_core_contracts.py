"""Core configuration and artifact contract regression tests."""

from __future__ import annotations

import subprocess
import sys

import numpy as np
import pytest
from fastapi import HTTPException

from ewscan.api.server import SimulationRequest, simulate
from ewscan.config import ConfigError, config_from_dict
from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog, Observation
from ewscan.experiments.scenarios import make_sparse_bursty_scenario


def _config(**overrides: object) -> EpisodeConfig:
    values = {
        "n_bands": 4,
        "n_slots": 8,
        "k": 1,
        "emitters": (),
        "detection_threshold": 3.0,
        "pfa": 1e-3,
        "seed": 0,
        "retune_cost_slots": 0,
        "dwell": 1,
    }
    values.update(overrides)
    return EpisodeConfig(**values)


@pytest.mark.parametrize("field", ["n_bands", "n_slots"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_direct_config_requires_positive_integer_dimensions(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        _config(**{field: value})


@pytest.mark.parametrize("value", [0, -1, 5, True, 1.5])
def test_direct_config_enforces_k_range_and_type(value: object) -> None:
    with pytest.raises(ValueError, match="k"):
        _config(k=value)


@pytest.mark.parametrize("value", [0.0, 1.0, -0.1, 1.1, True])
def test_direct_config_requires_open_pfa_interval(value: object) -> None:
    with pytest.raises(ValueError, match="pfa"):
        _config(pfa=value)


@pytest.mark.parametrize("value", [0.0, -1.0, True, "high"])
def test_direct_config_requires_positive_threshold(value: object) -> None:
    with pytest.raises(ValueError, match="detection_threshold"):
        _config(detection_threshold=value)


@pytest.mark.parametrize("field,value", [("dwell", 1.5), ("dwell", True), ("retune_cost_slots", 1.5), ("retune_cost_slots", True)])
def test_direct_config_requires_integer_timing_values(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        _config(**{field: value})


def test_direct_config_rejects_out_of_range_emitter_band() -> None:
    emitter = EmitterInfo(4, 10.0, 1.0, "cw")
    with pytest.raises(ValueError, match="band"):
        _config(emitters=(emitter,))


@pytest.mark.parametrize(
    "emitter",
    [
        EmitterInfo(0, 10.0, 1.0, "gilbert_elliott", {"p01": -0.1, "p10": 0.2}),
        EmitterInfo(0, 10.0, 1.0, "periodic", {"period": 0}),
        EmitterInfo(0, 10.0, 1.0, "frequency_hop", {"hop_bands": []}),
        EmitterInfo(0, 10.0, 1.0, "beam", {"omega": 0.0, "beamwidth": 0.1, "snr_peak": 10.0}),
    ],
)
def test_emitter_specific_parameters_fail_during_config_construction(emitter: EmitterInfo) -> None:
    with pytest.raises(ValueError):
        _config(emitters=(emitter,))


def test_frequency_hop_bands_must_fit_episode() -> None:
    emitter = EmitterInfo(
        0,
        10.0,
        1.0,
        "frequency_hop",
        {"hop_bands": [0, 4]},
    )
    with pytest.raises(ValueError, match="hop_bands"):
        _config(emitters=(emitter,))


def test_yaml_uses_the_same_pfa_validation() -> None:
    data = {
        "n_bands": 4,
        "n_slots": 8,
        "k": 1,
        "detection_threshold": 3.0,
        "pfa": 0.0,
    }
    with pytest.raises(ConfigError, match="pfa"):
        config_from_dict(data)


def test_scenario_builder_uses_the_same_dimension_validation() -> None:
    with pytest.raises(ValueError, match="n_slots"):
        make_sparse_bursty_scenario(n_slots=0)


def test_api_rejects_invalid_k_as_client_input() -> None:
    request = SimulationRequest.model_validate(
        {
            "scenario_name": "sparse_bursty",
            "scheduler_name": "round_robin",
            "seed": 0,
            "k": 17,
        }
    )
    with pytest.raises(HTTPException, match="k") as exc_info:
        simulate(request)
    assert exc_info.value.status_code == 422


def test_observation_requires_aligned_parallel_tuples() -> None:
    with pytest.raises(ValueError, match="same length"):
        Observation(slot=0, bands=(0, 1), detections=(True,))


@pytest.mark.parametrize(
    "actions,match",
    [
        (np.array([[0], [1], [2], [3], [4], [0], [1], [2]]), "out of range"),
        (np.array([[0, 0]] * 8), "duplicate"),
    ],
)
def test_episode_log_rejects_invalid_action_values(actions: np.ndarray, match: str) -> None:
    k = actions.shape[1]
    config = _config(k=k)
    with pytest.raises(ValueError, match=match):
        EpisodeLog(
            config=config,
            truth=np.zeros((config.n_bands, config.n_slots), dtype=np.bool_),
            actions=actions,
            detections=np.zeros((config.n_slots, k), dtype=np.bool_),
        )


def test_environment_does_not_require_generator_spawn() -> None:
    source = ("ewscan/env/environment.py")
    with open(source, encoding="utf-8") as handle:
        assert ".spawn(" not in handle.read()


@pytest.mark.slow
def test_clean_wheel_install_imports_runtime_and_runs_round_robin(tmp_path) -> None:
    wheel_dir = tmp_path / "wheel"
    wheel_dir.mkdir()
    subprocess.run(
        [sys.executable, "-m", "pip", "wheel", ".", "--no-deps", "--wheel-dir", str(wheel_dir)],
        check=True,
    )
    wheel = next(wheel_dir.glob("ewscan-*.whl"))

    venv_dir = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    python = venv_dir / "bin" / "python"
    subprocess.run([str(python), "-m", "pip", "install", str(wheel)], check=True)

    smoke = """
import ewscan.agents
import ewscan.api
import ewscan.env
import ewscan.experiments
import ewscan.metrics
from ewscan.agents.baselines import RoundRobinScheduler
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import make_sparse_bursty_scenario

config = make_sparse_bursty_scenario(n_slots=8, seed=7)
result = run_episode(config, RoundRobinScheduler(), seed=7)
assert result.log.actions.shape == (8, 1)
"""
    subprocess.run([str(python), "-c", smoke], cwd=tmp_path, check=True)
