"""Bounded local API for running EW scan simulations."""

from __future__ import annotations

import os
import threading
import time
from typing import Any

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.experiments.registry import build_scheduler, scheduler_names
from ewscan.experiments.runner import EpisodeResult, run_episode
from ewscan.experiments.scenarios import get_scenario, list_scenarios
from ewscan.metrics.detection import estimate_detection_metrics
from ewscan.metrics.first_intercept import estimate_first_intercept_metrics
from ewscan.metrics.interception import estimate_interception_metrics
from ewscan.metrics.prediction import estimate_prediction_metrics
from ewscan.metrics.reward import estimate_evaluation_utility, estimate_reward_metrics
from ewscan.metrics.time_error import estimate_time_error_metrics


MAX_K = 64
MAX_RUN_SECONDS = 15.0
_run_lock = threading.BoundedSemaphore(value=1)
_cors_origins = tuple(
    origin.strip()
    for origin in os.getenv("EWSCAN_CORS_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
)

app = FastAPI(title="EW Scan API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(_cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class SimulationRequest(BaseModel):
    scenario_name: str = Field(min_length=1, max_length=64)
    scheduler_name: str = Field(min_length=1, max_length=64)
    seed: int = Field(default=42, ge=0, le=2_147_483_647)
    k: int = Field(default=1, ge=1, le=MAX_K)
    debug: bool = False


def _synthetic_log(seed: int) -> EpisodeLog:
    n_bands = 4
    n_slots = 20
    truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
    truth[0, :] = True
    truth[1, 5:10] = True
    truth[2, ::3] = True
    actions = np.array([[slot % n_bands] for slot in range(n_slots)], dtype=np.intp)
    detections = np.array(
        [[truth[actions[slot, 0], slot]] for slot in range(n_slots)], dtype=np.bool_
    )
    emitters = (
        EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
        EmitterInfo(
            band=1,
            snr=15.0,
            threat_level=0.8,
            emitter_type="gilbert_elliott",
            params={"p01": 0.2, "p10": 0.2},
        ),
        EmitterInfo(
            band=2,
            snr=12.0,
            threat_level=0.5,
            emitter_type="periodic",
            params={"period": 3},
        ),
    )
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=emitters,
        pfa=1e-3,
        seed=seed,
    )
    return EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)


def _result_from_log(log: EpisodeLog, scheduler_name: str, seed: int) -> EpisodeResult:
    return EpisodeResult(
        config=log.config,
        scheduler_name=scheduler_name,
        seed=seed,
        log=log,
        track="oracle" if scheduler_name == "oracle" else "blind",
        detection=estimate_detection_metrics(log),
        interception=estimate_interception_metrics(log),
        first_intercept=estimate_first_intercept_metrics(log),
        reward=estimate_reward_metrics(log),
        evaluation=estimate_evaluation_utility(log),
        prediction=estimate_prediction_metrics(log),
        time_error=estimate_time_error_metrics(log),
    )


def _finite_float(value: float) -> float | None:
    number = float(value)
    return number if np.isfinite(number) else None


def _serialize_result(res: EpisodeResult, *, debug: bool) -> dict[str, Any]:
    log = res.log
    payload: dict[str, Any] = {
        "scheduler_name": res.scheduler_name,
        "detector": {
            "requested_pfa": _finite_float(res.detection.capability.requested_pfa),
            "effective_pfa": _finite_float(res.detection.capability.effective_pfa),
            "threshold": _finite_float(res.detection.capability.threshold),
            "dwell": res.detection.capability.dwell,
            "nominal_pd": _finite_float(res.detection.capability.nominal_pd),
        },
        "metrics": {
            "interception_ratio": _finite_float(res.interception.interception_ratio.ratio),
            "average_reward": _finite_float(res.reward.average_reward),
            "retune_penalty": _finite_float(res.reward.total_retune_penalty),
            "mean_ttfi": _finite_float(res.first_intercept.mean_time_to_first_intercept),
            "pd": _finite_float(res.detection.pd.pd),
            "pfa": _finite_float(res.detection.pfa.pfa),
        },
        "log": {
            "n_slots": log.n_slots,
            "n_bands": log.n_bands,
            "actions": log.actions.tolist(),
            "detections": log.detections.tolist(),
            "retune_events": log.retune_events.tolist(),
            "settling_slots": log.settling_slots.tolist(),
        },
    }
    if debug:
        payload["log"]["truth"] = log.truth.tolist()
        payload["log"]["emitters"] = [
            {
                "band": emitter.band,
                "type": emitter.emitter_type,
                "threat": _finite_float(emitter.threat_level),
                "snr": _finite_float(emitter.snr),
            }
            for emitter in log.config.emitters
        ]
    return payload


@app.get("/api/scenarios")
def get_scenarios() -> dict[str, list[str]]:
    return {"scenarios": ["synthetic_log", *list_scenarios()]}


@app.get("/api/schedulers")
def get_schedulers() -> dict[str, list[str]]:
    return {"schedulers": list(scheduler_names())}


@app.post("/api/simulate")
def simulate(req: SimulationRequest) -> dict[str, Any]:
    if not _run_lock.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="A simulation is already running")
    try:
        started = time.perf_counter()
        scheduler = build_scheduler(req.scheduler_name)
        if req.scenario_name == "synthetic_log":
            if req.k != 1:
                raise HTTPException(status_code=422, detail="synthetic_log requires k=1")
            log = _synthetic_log(req.seed)
            active = _result_from_log(log, "round_robin", req.seed)
            baseline = active
            oracle = active
        else:
            config = get_scenario(req.scenario_name, seed=req.seed, k=req.k)
            active = run_episode(config, scheduler, seed=req.seed)
            baseline = run_episode(config, build_scheduler("round_robin"), seed=req.seed)
            oracle = run_episode(config, build_scheduler("oracle"), seed=req.seed)
        if time.perf_counter() - started > MAX_RUN_SECONDS:
            raise HTTPException(status_code=503, detail="Simulation exceeded the time budget")
        return {
            "active": _serialize_result(active, debug=req.debug),
            "baseline": _serialize_result(baseline, debug=req.debug),
            "oracle": _serialize_result(oracle, debug=req.debug),
        }
    except HTTPException:
        raise
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Simulation failed") from exc
    finally:
        _run_lock.release()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
