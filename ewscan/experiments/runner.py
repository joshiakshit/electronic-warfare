"""Single-episode runner for ewscan -- Experiment harness Task 1 (Phase 1E.8).

Provides:
- EpisodeResult: Dataclass containing the EpisodeLog and all computed figures of merit.
- EpisodeRunner: Configurable runner class.
- run_episode: Core single-episode execution function.
- CLI entrypoint for running an episode from configuration and printing/saving results.
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from ewscan.agents.reward import RewardFunction
from ewscan.config import load_config
from ewscan.contracts import EpisodeConfig, EpisodeLog, Observation, ScanAction, Scheduler
from ewscan.env.environment import RFEnvironment
from ewscan.env.recorder import EpisodeRecorder, save_episode_log
from ewscan.metrics.detection import DetectionMetrics, estimate_detection_metrics
from ewscan.metrics.first_intercept import FirstInterceptMetrics, estimate_first_intercept_metrics
from ewscan.metrics.interception import InterceptionMetrics, estimate_interception_metrics
from ewscan.metrics.prediction import PredictionMetrics, estimate_prediction_metrics
from ewscan.metrics.reward import RewardMetrics, estimate_reward_metrics
from ewscan.metrics.time_error import TimeErrorMetrics, estimate_time_error_metrics


@dataclass(frozen=True)
class EpisodeResult:
    """Complete result of executing a single episode.

    Attributes
    ----------
    config : EpisodeConfig
        Episode scenario configuration.
    scheduler_name : str
        Name of the scheduler evaluated.
    seed : int
        Seed used for RNG initialization.
    log : EpisodeLog
        Full episode execution log (truth, actions, detections).
    detection : DetectionMetrics
        Figure of Merit 1: Detection probabilities, Pfa, and sensitivity.
    interception : InterceptionMetrics
        Figure of Merit 2: Interception ratio and intercept rate.
    first_intercept : FirstInterceptMetrics
        Figure of Merit 3: Time to first intercept per emitter and average.
    reward : RewardMetrics
        Figure of Merit 4: Average reward accumulator and cost breakdown.
    prediction : PredictionMetrics
        Figure of Merit 5: Prediction accuracy / percentage correct.
    time_error : TimeErrorMetrics
        Figure of Merit 6: Intercept time error on transmission bursts.
    duration_seconds : float
        Elapsed wall-clock execution time for the episode.
    """

    config: EpisodeConfig
    scheduler_name: str
    seed: int
    log: EpisodeLog
    detection: DetectionMetrics
    interception: InterceptionMetrics
    first_intercept: FirstInterceptMetrics
    reward: RewardMetrics
    prediction: PredictionMetrics
    time_error: TimeErrorMetrics
    duration_seconds: float = 0.0

    def to_dict(self, prefix: str = "") -> dict[str, Any]:
        """Flatten scalar metrics and metadata into a key-value dictionary.

        Parameters
        ----------
        prefix : str, default ""
            Optional prefix for dictionary keys.

        Returns
        -------
        dict[str, Any]
            Flat dictionary suitable for tabular displays, CSV exports, or DataFrames.
        """
        intercept_fraction = (
            (self.first_intercept.n_intercepted / self.first_intercept.n_emitters)
            if self.first_intercept.n_emitters > 0
            else float("nan")
        )

        return {
            f"{prefix}scheduler": self.scheduler_name,
            f"{prefix}seed": self.seed,
            f"{prefix}n_bands": self.config.n_bands,
            f"{prefix}n_slots": self.config.n_slots,
            f"{prefix}k": self.config.k,
            f"{prefix}duration_seconds": self.duration_seconds,
            # Figure of Merit 1: Detection
            f"{prefix}pd": self.detection.pd.pd,
            f"{prefix}pfa": self.detection.pfa.pfa,
            f"{prefix}sensitivity": self.detection.sensitivity.min_detectable_snr,
            # Figure of Merit 2: Interception
            f"{prefix}interception_ratio": self.interception.interception_ratio.ratio,
            f"{prefix}intercept_rate": self.interception.intercept_rate.rate,
            # Figure of Merit 3: Time to first intercept
            f"{prefix}ttfi": self.first_intercept.mean_time_to_first_intercept,
            f"{prefix}intercept_fraction": intercept_fraction,
            # Figure of Merit 4: Reward & cost
            f"{prefix}average_reward": self.reward.average_reward,
            f"{prefix}total_reward": self.reward.total_reward,
            f"{prefix}hit_reward": self.reward.total_hit_reward,
            f"{prefix}miss_cost": self.reward.total_miss_cost,
            f"{prefix}novelty_bonus": self.reward.total_novelty_bonus,
            f"{prefix}revisit_decay": self.reward.total_revisit_decay,
            f"{prefix}retune_penalty": self.reward.total_retune_penalty,
            # Figure of Merit 5: Prediction
            f"{prefix}prediction_accuracy": self.prediction.accuracy,
            f"{prefix}prediction_pct_correct": self.prediction.percentage_correct,
            # Figure of Merit 6: Time error
            f"{prefix}time_error": self.time_error.mean_time_error,
            f"{prefix}time_error_penalized": self.time_error.mean_time_error_penalized,
            f"{prefix}burst_interception_ratio": self.time_error.burst_interception_ratio,
        }

    def summary(self) -> str:
        """Return a formatted human-readable summary of the episode results."""
        pred_str = (
            f"{self.prediction.accuracy:.4f}"
            if self.prediction.accuracy is not None
            else "None (Stub)"
        )
        lines = [
            f"=== Episode Result: {self.scheduler_name} (seed={self.seed}) ===",
            f"Bands: {self.config.n_bands}, Slots: {self.config.n_slots}, Duration: {self.duration_seconds * 1000:.2f}ms",
            f"Interception Ratio : {self.interception.interception_ratio.ratio:.4f} ({self.interception.interception_ratio.n_hits}/{self.interception.interception_ratio.n_transmissions} hits)",
            f"Intercept Rate     : {self.interception.intercept_rate.rate:.4f}",
            f"Mean TTFI          : {self.first_intercept.mean_time_to_first_intercept:.2f} slots ({self.first_intercept.n_intercepted}/{self.first_intercept.n_emitters} emitters)",
            f"Average Reward     : {self.reward.average_reward:.4f} (Total: {self.reward.total_reward:.2f})",
            f"Estimated Pd       : {self.detection.pd.pd:.4f}, Pfa: {self.detection.pfa.pfa:.4e}",
            f"Mean Time Error    : {self.time_error.mean_time_error:.2f} slots (Penalized: {self.time_error.mean_time_error_penalized:.2f})",
            f"Prediction Accuracy: {pred_str}",
        ]
        return "\n".join(lines)


def run_episode(
    config: EpisodeConfig,
    scheduler: Scheduler,
    seed: int | None = None,
    rf: RewardFunction | None = None,
    miss_penalty: float | None = None,
    pd_threshold: float = 0.5,
    env: RFEnvironment | None = None,
) -> EpisodeResult:
    """Execute a single episode with a scheduler and compute all 7 figures of merit.

    Parameters
    ----------
    config : EpisodeConfig
        Scenario configuration defining bands, slots, emitters, and detection parameters.
    scheduler : Scheduler
        Scheduler instance implementing the Scheduler ABC.
    seed : int | None, optional
        Seed override for reproducibility. If None, uses config.seed.
    rf : RewardFunction | None, optional
        Custom reward function for evaluating reward metrics. If None, uses default.
    miss_penalty : float | None, optional
        Penalty for missed bursts in time error calculation.
    pd_threshold : float, default 0.5
        Threshold for sensitivity estimation.
    env : RFEnvironment | None, optional
        Pre-instantiated RFEnvironment. If None, constructs one from config.

    Returns
    -------
    EpisodeResult
        Dataclass containing the completed EpisodeLog and all computed metrics.
    """
    effective_seed = int(seed) if seed is not None else int(config.seed)

    if effective_seed != config.seed:
        ep_config = EpisodeConfig(
            n_bands=config.n_bands,
            n_slots=config.n_slots,
            k=config.k,
            emitters=config.emitters,
            detection_threshold=config.detection_threshold,
            pfa=config.pfa,
            seed=effective_seed,
            retune_cost_slots=config.retune_cost_slots,
        )
    else:
        ep_config = config

    # Initialize environment
    if env is None:
        environment = RFEnvironment(ep_config)
        environment.reset(seed=effective_seed)
    else:
        environment = env
        environment.reset(seed=effective_seed)

    truth = environment.truth

    # Inject truth to oracle schedulers (must happen before reset, since
    # OracleScheduler.reset() validates that truth is already set)
    if hasattr(scheduler, "set_truth"):
        scheduler.set_truth(truth)

    # Reset scheduler (OracleScheduler.reset validates truth shape here)
    scheduler.reset(ep_config)

    # Initialize recorder and record ground truth
    recorder = EpisodeRecorder(ep_config)
    recorder.record_truth(truth)

    # Execute episode time-stepping loop
    start_time = time.perf_counter()
    obs: Observation | None = None
    for _ in range(ep_config.n_slots):
        action = scheduler.act(obs)
        obs = environment.step(action)
        recorder.record_observation(obs)
    duration = time.perf_counter() - start_time

    # Compile episode log
    log = recorder.to_log()

    # Compute all 7 figures of merit
    detection = estimate_detection_metrics(log, pd_threshold=pd_threshold)
    interception = estimate_interception_metrics(log)
    first_intercept = estimate_first_intercept_metrics(log)
    reward = estimate_reward_metrics(log, rf=rf)
    prediction = estimate_prediction_metrics(log)
    time_error = estimate_time_error_metrics(log, miss_penalty=miss_penalty)

    return EpisodeResult(
        config=ep_config,
        scheduler_name=scheduler.name,
        seed=effective_seed,
        log=log,
        detection=detection,
        interception=interception,
        first_intercept=first_intercept,
        reward=reward,
        prediction=prediction,
        time_error=time_error,
        duration_seconds=duration,
    )


class EpisodeRunner:
    """Configurable runner for executing single episodes.

    Parameters
    ----------
    rf : RewardFunction | None, optional
        Custom reward function for evaluating reward metrics.
    miss_penalty : float | None, optional
        Penalty for missed bursts in time error calculation.
    pd_threshold : float, default 0.5
        Threshold for sensitivity estimation.
    """

    def __init__(
        self,
        rf: RewardFunction | None = None,
        miss_penalty: float | None = None,
        pd_threshold: float = 0.5,
    ) -> None:
        self.rf = rf
        self.miss_penalty = miss_penalty
        self.pd_threshold = pd_threshold

    def run(
        self,
        config: EpisodeConfig,
        scheduler: Scheduler,
        seed: int | None = None,
        env: RFEnvironment | None = None,
    ) -> EpisodeResult:
        """Execute a single episode with the configured evaluation parameters.

        Parameters
        ----------
        config : EpisodeConfig
            Scenario configuration.
        scheduler : Scheduler
            Scheduler instance.
        seed : int | None, optional
            Seed override.
        env : RFEnvironment | None, optional
            Optional environment instance.

        Returns
        -------
        EpisodeResult
            Result of the episode execution.
        """
        return run_episode(
            config=config,
            scheduler=scheduler,
            seed=seed,
            rf=self.rf,
            miss_penalty=self.miss_penalty,
            pd_threshold=self.pd_threshold,
            env=env,
        )


def _build_scheduler_by_name(name: str, config: EpisodeConfig | None = None) -> Scheduler:
    """Instantiate a scheduler by name."""
    name_clean = name.strip().lower().replace("-", "_")

    if name_clean == "round_robin":
        from ewscan.agents.baselines import RoundRobinScheduler

        return RoundRobinScheduler()
    elif name_clean in ("uniform_random", "random"):
        from ewscan.agents.baselines import UniformRandomScheduler

        return UniformRandomScheduler()
    elif name_clean in ("prior_weighted", "prior"):
        from ewscan.agents.baselines import PriorWeightedScheduler

        return PriorWeightedScheduler()
    elif name_clean == "oracle":
        from ewscan.agents.baselines import OracleScheduler

        return OracleScheduler()
    elif name_clean == "ucb1":
        from ewscan.agents.ucb import UCB1Scheduler

        return UCB1Scheduler()
    elif name_clean in ("sliding_window_ucb", "sw_ucb", "swucb1"):
        from ewscan.agents.nonstationary_ucb import SWUCB1Scheduler

        return SWUCB1Scheduler()
    elif name_clean in ("discounted_ucb", "d_ucb", "ducb1"):
        from ewscan.agents.nonstationary_ucb import DUCB1Scheduler

        return DUCB1Scheduler()
    elif name_clean in ("thompson", "thompson_sampling", "ts"):
        from ewscan.agents.thompson import ThompsonSamplingScheduler

        return ThompsonSamplingScheduler()
    elif name_clean in ("discounted_thompson", "discounted_thompson_sampling", "d_ts", "dts"):
        from ewscan.agents.thompson import DiscountedThompsonScheduler

        return DiscountedThompsonScheduler()
    elif name_clean == "stub":
        from ewscan.testing.fixtures import StubScheduler

        return StubScheduler()
    else:
        raise ValueError(
            f"Unknown scheduler name '{name}'. Available: round_robin, uniform_random, "
            f"prior_weighted, oracle, ucb1, sliding_window_ucb, discounted_ucb, "
            f"thompson_sampling, discounted_thompson, stub"
        )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for running a single episode."""
    parser = argparse.ArgumentParser(
        description="Run a single EW scan scheduling episode and compute metrics."
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="configs/mvp.yaml",
        help="Path to YAML episode configuration file (default: configs/mvp.yaml).",
    )
    parser.add_argument(
        "--scheduler",
        "-s",
        type=str,
        default="round_robin",
        help="Scheduler name: round_robin, uniform_random, prior_weighted, oracle, ucb1, sliding_window_ucb, discounted_ucb, thompson_sampling, stub (default: round_robin).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional seed override.",
    )
    parser.add_argument(
        "--save-log",
        type=str,
        default=None,
        help="Optional filepath (.json or .npz) to save the resulting EpisodeLog.",
    )

    args = parser.parse_args(argv)

    try:
        from ewscan.experiments.scenarios import get_scenario

        config_path = Path(args.config)
        if config_path.is_file():
            config = load_config(config_path)
        else:
            try:
                config = get_scenario(args.config)
            except Exception:
                config = load_config(args.config)

        scheduler = _build_scheduler_by_name(args.scheduler, config)
        result = run_episode(config, scheduler, seed=args.seed)

        print(result.summary())

        if args.save_log:
            save_episode_log(result.log, args.save_log)
            print(f"Log saved to {args.save_log}")

        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
