"""Objective 8 API contract tests."""

from __future__ import annotations

import math

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from ewscan.api.server import SimulationRequest, _finite_float, get_schedulers, simulate
from ewscan.experiments.registry import scheduler_names


def test_scheduler_endpoint_uses_shared_registry():
    assert get_schedulers() == {"schedulers": list(scheduler_names())}


def test_simulation_hides_truth_and_emitter_snr_by_default():
    result = simulate(SimulationRequest(scenario_name="synthetic_log", scheduler_name="ucb1"))

    assert "truth" not in result["active"]["log"]
    assert "emitters" not in result["active"]["log"]


def test_debug_simulation_exposes_demo_truth_only_when_requested():
    result = simulate(
        SimulationRequest(
            scenario_name="synthetic_log", scheduler_name="ucb1", debug=True
        )
    )

    assert "truth" in result["active"]["log"]
    assert "snr" in result["active"]["log"]["emitters"][0]


def test_unknown_scheduler_is_a_client_error():
    with pytest.raises(HTTPException) as error:
        simulate(SimulationRequest(scenario_name="synthetic_log", scheduler_name="bad"))

    assert error.value.status_code == 422


def test_request_bounds_reject_invalid_seed_and_k():
    with pytest.raises(ValidationError):
        SimulationRequest(scenario_name="synthetic_log", scheduler_name="ucb1", seed=-1)
    with pytest.raises(ValidationError):
        SimulationRequest(scenario_name="synthetic_log", scheduler_name="ucb1", k=65)


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_finite_serialization_replaces_non_finite_values(value: float):
    assert _finite_float(value) is None
