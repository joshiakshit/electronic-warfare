"""Objective 8 API contract tests."""

from __future__ import annotations

import math

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from ewscan.api.server import (
    SimulationRequest,
    _finite_float,
    _result_from_log,
    _serialize_result,
    _synthetic_log,
    get_scenarios,
    get_schedulers,
    simulate,
)
from ewscan.experiments.registry import scheduler_names


def test_scheduler_endpoint_uses_shared_registry():
    assert get_schedulers() == {"schedulers": list(scheduler_names())}


def test_simulation_hides_truth_and_emitter_snr_by_default():
    result = _serialize_result(
        _result_from_log(_synthetic_log(1), "round_robin", 1), debug=False
    )

    assert "truth" not in result["log"]
    assert "emitters" not in result["log"]


def test_debug_simulation_exposes_demo_truth_only_when_requested():
    result = _serialize_result(
        _result_from_log(_synthetic_log(1), "round_robin", 1), debug=True
    )

    assert "truth" in result["log"]
    assert "snr" in result["log"]["emitters"][0]


def test_serialized_result_exposes_analysis_payload():
    result = _serialize_result(
        _result_from_log(_synthetic_log(1), "round_robin", 1), debug=True
    )

    assert result["config"]["n_bands"] == 4
    assert result["config"]["n_slots"] == 20
    assert result["metrics"]["intercept_rate"] is not None
    assert result["metrics"]["total_reward"] is not None
    assert result["detection_counts"]["hits"] >= 0
    assert len(result["per_emitter"]) == 3
    assert len(result["log"]["valid_slots"]) == 20
    assert len(result["log"]["per_slot_rewards"]) == 20


def test_public_scenarios_do_not_include_scheduler_ignoring_replay():
    assert "synthetic_log" not in get_scenarios()["scenarios"]


def test_unknown_scheduler_is_a_client_error():
    with pytest.raises(HTTPException) as error:
        simulate(SimulationRequest(scenario_name="periodic_radar", scheduler_name="bad"))

    assert error.value.status_code == 422


def test_request_bounds_reject_invalid_seed_and_k():
    with pytest.raises(ValidationError):
        SimulationRequest(scenario_name="synthetic_log", scheduler_name="ucb1", seed=-1)
    with pytest.raises(ValidationError):
        SimulationRequest(scenario_name="synthetic_log", scheduler_name="ucb1", k=65)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_finite_serialization_replaces_non_finite_values(value: float):
    assert _finite_float(value) is None


def test_simulation_passes_one_hard_deadline_to_all_runs(monkeypatch):
    result = _result_from_log(_synthetic_log(1), "round_robin", 1)
    deadlines = []

    def fake_run(config, scheduler, seed, deadline=None):
        deadlines.append(deadline)
        return result

    monkeypatch.setattr("ewscan.api.server.run_episode", fake_run)
    response = simulate(
        SimulationRequest(
            scenario_name="periodic_radar", scheduler_name="round_robin"
        )
    )

    assert response["active"]["scheduler_name"] == "round_robin"
    assert len(deadlines) == 3
    assert deadlines[0] is not None
    assert deadlines == [deadlines[0]] * 3


def test_episode_deadline_is_a_service_unavailable_error(monkeypatch):
    def timed_out(*args, **kwargs):
        raise TimeoutError("episode deadline exceeded")

    monkeypatch.setattr("ewscan.api.server.run_episode", timed_out)

    with pytest.raises(HTTPException) as error:
        simulate(
            SimulationRequest(
                scenario_name="periodic_radar", scheduler_name="round_robin"
            )
        )

    assert error.value.status_code == 503
    assert "time budget" in error.value.detail
