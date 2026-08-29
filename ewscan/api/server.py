"""Bounded local API for running EW scan simulations."""

from __future__ import annotations

import os
import logging
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
logger = logging.getLogger(__name__)
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


def _finite_float(value: float | None) -> float | None:
    if value is None:
        return None
    number = float(value)
    return number if np.isfinite(number) else None


def _serialize_result(res: EpisodeResult, *, debug: bool) -> dict[str, Any]:
    log = res.log
    detection = res.detection
    interception = res.interception
    first_intercept = res.first_intercept
    reward = res.reward
    evaluation = res.evaluation
    prediction = res.prediction
    time_error = res.time_error

    per_emitter = []
    for index, emitter in enumerate(log.config.emitters):
        emitter_pd = detection.per_emitter_pd[index]
        emitter_interception = interception.per_emitter[index]
        emitter_first_intercept = first_intercept.per_emitter[index]
        emitter_time_error = time_error.per_emitter[index]
        per_emitter.append(
            {
                "index": index,
                "band": emitter.band,
                "type": emitter.emitter_type,
                "threat": _finite_float(emitter.threat_level),
                "snr": _finite_float(emitter.snr),
                "pd": _finite_float(emitter_pd.pd),
                "pd_hits": emitter_pd.n_hits,
                "pd_scans_on": emitter_pd.n_scans_on,
                "interception_ratio": _finite_float(
                    emitter_interception.interception_ratio
                ),
                "interception_hits": emitter_interception.n_hits,
                "transmissions": emitter_interception.n_transmissions,
                "first_intercept_slot": emitter_first_intercept.first_intercept_slot,
                "intercepted": emitter_first_intercept.intercepted,
                "mean_time_error": _finite_float(emitter_time_error.mean_time_error),
                "mean_time_error_penalized": _finite_float(
                    emitter_time_error.mean_time_error_penalized
                ),
                "burst_interception_ratio": _finite_float(
                    emitter_time_error.burst_interception_ratio
                ),
                "n_bursts": emitter_time_error.n_bursts,
                "n_intercepted_bursts": emitter_time_error.n_intercepted_bursts,
            }
        )

    payload: dict[str, Any] = {
        "scheduler_name": res.scheduler_name,
        "track": res.track,
        "seed": res.seed,
        "duration_seconds": _finite_float(res.duration_seconds),
        "config": {
            "n_bands": log.config.n_bands,
            "n_slots": log.config.n_slots,
            "k": log.config.k,
            "pfa": _finite_float(log.config.pfa),
            "detection_threshold": _finite_float(log.config.detection_threshold),
            "dwell": log.config.dwell,
            "retune_cost_slots": log.config.retune_cost_slots,
            "n_emitters": len(log.config.emitters),
        },
        "detector": {
            "requested_pfa": _finite_float(detection.capability.requested_pfa),
            "effective_pfa": _finite_float(detection.capability.effective_pfa),
            "threshold": _finite_float(detection.capability.threshold),
            "dwell": detection.capability.dwell,
            "nominal_pd": _finite_float(detection.capability.nominal_pd),
        },
        "metrics": {
            "interception_ratio": _finite_float(interception.interception_ratio.ratio),
            "intercept_rate": _finite_float(interception.intercept_rate.rate),
            "interception_hits": interception.interception_ratio.n_hits,
            "transmissions": interception.interception_ratio.n_transmissions,
            "average_reward": _finite_float(reward.average_reward),
            "total_reward": _finite_float(reward.total_reward),
            "hit_reward": _finite_float(reward.total_hit_reward),
            "miss_cost": _finite_float(reward.total_miss_cost),
            "novelty_bonus": _finite_float(reward.total_novelty_bonus),
            "revisit_decay": _finite_float(reward.total_revisit_decay),
            "retune_penalty": _finite_float(reward.total_retune_penalty),
            "mean_ttfi": _finite_float(first_intercept.mean_time_to_first_intercept),
            "ttfi_penalized": _finite_float(
                first_intercept.mean_time_to_first_intercept_penalized
            ),
            "intercept_fraction": _finite_float(first_intercept.intercept_fraction),
            "pd": _finite_float(detection.pd.pd),
            "pfa": _finite_float(detection.pfa.pfa),
            "sensitivity": _finite_float(detection.sensitivity.min_detectable_snr),
            "evaluation_utility": _finite_float(evaluation.average_utility),
            "total_utility": _finite_float(evaluation.total_utility),
            "time_error": _finite_float(time_error.mean_time_error),
            "time_error_penalized": _finite_float(time_error.mean_time_error_penalized),
            "burst_interception_ratio": _finite_float(time_error.burst_interception_ratio),
            "n_bursts": time_error.n_bursts,
            "n_intercepted_bursts": time_error.n_intercepted_bursts,
        },
        "detection_counts": {
            "hits": detection.pd.n_hits,
            "scans_on": detection.pd.n_scans_on,
            "false_alarms": detection.pfa.n_false_alarms,
            "scans_off": detection.pfa.n_scans_off,
        },
        "evaluation_counts": {
            "true_positives": evaluation.n_true_positive,
            "false_negatives": evaluation.n_false_negative,
            "false_alarms": evaluation.n_false_alarm,
        },
        "prediction": {
            "accuracy": _finite_float(prediction.accuracy),
            "percentage_correct": _finite_float(prediction.percentage_correct),
            "predictor_present": prediction.predictor_present,
            "n_predictions": prediction.n_predictions,
            "n_correct": prediction.n_correct,
            "coverage": _finite_float(prediction.coverage),
            "mean_confidence": _finite_float(prediction.mean_confidence),
            "n_overrides": prediction.n_overrides,
        },
        "per_emitter": per_emitter,
        "log": {
            "n_slots": log.n_slots,
            "n_bands": log.n_bands,
            "actions": log.actions.tolist(),
            "detections": log.detections.tolist(),
            "retune_events": log.retune_events.tolist(),
            "settling_slots": log.settling_slots.tolist(),
            "valid_slots": log.valid_slots.tolist(),
            "per_slot_rewards": reward.per_slot_rewards.tolist(),
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
        payload["log"]["emitter_truth"] = (
            log.emitter_truth.tolist() if log.emitter_truth is not None else None
        )
        payload["log"]["emitter_bands"] = (
            log.emitter_bands.tolist() if log.emitter_bands is not None else None
        )
    if res.arbitration is not None:
        payload["arbitration"] = {
            "prediction_band": res.arbitration.prediction_band.tolist(),
            "prediction_confidence": res.arbitration.prediction_confidence.tolist(),
            "inner_action": res.arbitration.inner_action.tolist(),
            "executed_action": res.arbitration.executed_action.tolist(),
            "did_override": res.arbitration.did_override.tolist(),
        }
    return payload


@app.get("/api/scenarios")
def get_scenarios() -> dict[str, list[str]]:
    return {"scenarios": list(list_scenarios())}


@app.get("/api/schedulers")
def get_schedulers() -> dict[str, list[str]]:
    return {"schedulers": list(scheduler_names())}


@app.post("/api/simulate")
def simulate(req: SimulationRequest) -> dict[str, Any]:
    if not _run_lock.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="A simulation is already running")
    try:
        started = time.perf_counter()
        deadline = started + MAX_RUN_SECONDS
        scheduler = build_scheduler(req.scheduler_name)
        config = get_scenario(req.scenario_name, seed=req.seed, k=req.k)
        active = run_episode(config, scheduler, seed=req.seed, deadline=deadline)
        baseline = run_episode(
            config,
            build_scheduler("round_robin"),
            seed=req.seed,
            deadline=deadline,
        )
        oracle = run_episode(
            config,
            build_scheduler("oracle"),
            seed=req.seed,
            deadline=deadline,
        )
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
    except TimeoutError as exc:
        raise HTTPException(status_code=503, detail="Simulation exceeded the time budget") from exc
    except Exception as exc:
        logger.exception("Simulation failed")
        raise HTTPException(status_code=500, detail="Simulation failed") from exc
    finally:
        _run_lock.release()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
