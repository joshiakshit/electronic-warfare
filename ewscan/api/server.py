from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np

from ewscan.contracts import EpisodeLog
from ewscan.experiments.runner import EpisodeResult, _build_scheduler_by_name, run_episode
from ewscan.experiments.scenarios import list_scenarios, get_scenario
from ewscan.metrics.detection import estimate_detection_metrics
from ewscan.metrics.first_intercept import estimate_first_intercept_metrics
from ewscan.metrics.interception import estimate_interception_metrics
from ewscan.metrics.prediction import estimate_prediction_metrics
from ewscan.metrics.reward import estimate_reward_metrics
from ewscan.metrics.time_error import estimate_time_error_metrics
from ewscan.testing.fixtures import synthetic_log

app = FastAPI(title="EW Scan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SimulationRequest(BaseModel):
    scenario_name: str
    scheduler_name: str
    seed: int = 42
    k: int = 1

def _result_from_log(log: EpisodeLog, scheduler_name: str, seed: int) -> EpisodeResult:
    detection = estimate_detection_metrics(log)
    interception = estimate_interception_metrics(log)
    first_intercept = estimate_first_intercept_metrics(log)
    reward = estimate_reward_metrics(log)
    prediction = estimate_prediction_metrics(log)
    time_error = estimate_time_error_metrics(log)
    return EpisodeResult(
        config=log.config,
        scheduler_name=scheduler_name,
        seed=seed,
        log=log,
        detection=detection,
        interception=interception,
        first_intercept=first_intercept,
        reward=reward,
        prediction=prediction,
        time_error=time_error,
        duration_seconds=0.0,
    )

def _serialize_result(res: EpisodeResult) -> Dict[str, Any]:
    log = res.log
    return {
        "scheduler_name": res.scheduler_name,
        "metrics": {
            "interception_ratio": float(res.interception.interception_ratio.ratio) if np.isfinite(res.interception.interception_ratio.ratio) else 0.0,
            "average_reward": float(res.reward.average_reward) if np.isfinite(res.reward.average_reward) else 0.0,
            "retune_penalty": float(res.reward.total_retune_penalty),
            "mean_ttfi": float(res.first_intercept.mean_time_to_first_intercept),
            "pd": float(res.detection.pd.pd) if np.isfinite(res.detection.pd.pd) else 0.0,
            "pfa": float(res.detection.pfa.pfa) if np.isfinite(res.detection.pfa.pfa) else 0.0,
        },
        "log": {
            "n_slots": log.n_slots,
            "n_bands": log.n_bands,
            "truth": log.truth.tolist(),
            "actions": log.actions.tolist(),
            "detections": log.detections.tolist(),
            "retune_events": log.retune_events.tolist(),
            "settling_slots": log.settling_slots.tolist(),
            "emitters": [
                {"band": em.band, "type": em.emitter_type, "threat": float(em.threat_level), "snr": float(em.snr)}
                for em in log.config.emitters
            ]
        }
    }

@app.get("/api/scenarios")
def get_scenarios():
    return {"scenarios": ["synthetic_log"] + list_scenarios()}

@app.get("/api/schedulers")
def get_schedulers():
    return {"schedulers": [
        "ucb1",
        "sliding_window_ucb",
        "discounted_ucb",
        "thompson_sampling",
        "discounted_thompson",
        "round_robin",
        "uniform_random",
        "prior_weighted",
        "oracle"
    ]}

@app.post("/api/simulate")
def simulate(req: SimulationRequest):
    try:
        if req.scenario_name == "synthetic_log":
            log = synthetic_log(n_bands=4, n_slots=20, seed=req.seed)
            active_res = _result_from_log(log, "Round-Robin (Synthetic)", req.seed)
            rr_res = active_res
            oracle_res = active_res
        else:
            config = get_scenario(req.scenario_name, seed=req.seed, k=req.k)
            active_sched = _build_scheduler_by_name(req.scheduler_name, config)
            active_res = run_episode(config, active_sched, seed=req.seed)
            
            rr_sched = _build_scheduler_by_name("round_robin", config)
            rr_res = run_episode(config, rr_sched, seed=req.seed)
            
            oracle_sched = _build_scheduler_by_name("oracle", config)
            oracle_res = run_episode(config, oracle_sched, seed=req.seed)

        return {
            "active": _serialize_result(active_res),
            "baseline": _serialize_result(rr_res),
            "oracle": _serialize_result(oracle_res) if oracle_res else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
