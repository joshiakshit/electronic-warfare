"""Multi-seed sweep runner for ewscan -- Experiment harness Task 2 (Phase 1E.8).

Provides:
- SweepResult: Dataclass containing all episode results, flat tabular records,
  and multi-seed aggregates with confidence intervals.
- SweepRunner: Configurable runner class for executing sweeps across scenarios,
  schedulers, and seeds.
- run_sweep: Top-level sweep execution function.
- save_sweep_csv / save_aggregate_csv: CSV export utilities.
- CLI entrypoint (`python -m ewscan.experiments.sweep`) for running sweeps from configuration.

Verification Criterion (PLAN.md 1E.8 Task 2):
  Output rows equal schedulers times seeds.
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

import numpy as np

from ewscan.agents.baselines import (
    OracleScheduler,
    PriorWeightedScheduler,
    RoundRobinScheduler,
    UniformRandomScheduler,
)
from ewscan.agents.nonstationary_ucb import DUCB1Scheduler, SWUCB1Scheduler
from ewscan.agents.reward import RewardFunction
from ewscan.agents.thompson import ThompsonSamplingScheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.config import load_config
from ewscan.contracts import EpisodeConfig, Scheduler
from ewscan.experiments.runner import EpisodeResult, run_episode
from ewscan.metrics.aggregation import (
    AggregateMetrics,
    aggregate_metric_records,
)
from ewscan.testing.fixtures import StubScheduler


# Default scheduler names included in standard sweeps
DEFAULT_SCHEDULER_NAMES: list[str] = [
    "oracle",
    "thompson_sampling",
    "discounted_thompson",
    "ucb1",
    "sliding_window_ucb",
    "discounted_ucb",
    "prior_weighted",
    "round_robin",
    "uniform_random",
]

# Standard column ordering for CSV export
SWEEP_CSV_COLUMNS: list[str] = [
    "scenario",
    "scheduler",
    "seed",
    "n_bands",
    "n_slots",
    "k",
    "duration_seconds",
    # Figure of Merit 1: Detection
    "pd",
    "pfa",
    "sensitivity",
    # Figure of Merit 2: Interception
    "interception_ratio",
    "intercept_rate",
    # Figure of Merit 3: Time to first intercept
    "ttfi",
    "intercept_fraction",
    # Figure of Merit 4: Reward & cost
    "average_reward",
    "total_reward",
    "hit_reward",
    "miss_cost",
    "novelty_bonus",
    "revisit_decay",
    # Figure of Merit 5: Prediction
    "prediction_accuracy",
    "prediction_pct_correct",
    # Figure of Merit 6: Time error
    "time_error",
    "time_error_penalized",
    "burst_interception_ratio",
]


def _build_scheduler_by_name(name: str, config: EpisodeConfig | None = None) -> Scheduler:
    """Instantiate a fresh scheduler by canonical name string.

    Parameters
    ----------
    name : str
        Scheduler name identifier.
    config : EpisodeConfig | None, optional
        Optional scenario config (e.g. for prior derivation or validation).

    Returns
    -------
    Scheduler
        New instance of the requested scheduler.
    """
    name_clean = name.strip().lower().replace("-", "_")

    if name_clean == "round_robin":
        return RoundRobinScheduler()
    elif name_clean in ("uniform_random", "random"):
        return UniformRandomScheduler()
    elif name_clean in ("prior_weighted", "prior"):
        priors = None
        if config is not None and len(config.emitters) > 0:
            # Derive normalized threat-weighted prior from emitters if available
            p = np.full(config.n_bands, 0.1, dtype=np.float64)
            for em in config.emitters:
                if 0 <= em.band < config.n_bands:
                    p[em.band] = max(p[em.band], float(em.threat_level))
            priors = (p / p.sum()).tolist()
        return PriorWeightedScheduler(priors=priors)
    elif name_clean == "oracle":
        return OracleScheduler()
    elif name_clean == "ucb1":
        return UCB1Scheduler()
    elif name_clean in ("sliding_window_ucb", "sw_ucb", "swucb1"):
        return SWUCB1Scheduler()
    elif name_clean in ("discounted_ucb", "d_ucb", "ducb1"):
        return DUCB1Scheduler()
    elif name_clean in ("thompson", "thompson_sampling", "ts"):
        return ThompsonSamplingScheduler()
    elif name_clean in ("discounted_thompson", "discounted_thompson_sampling", "d_ts", "dts"):
        from ewscan.agents.thompson import DiscountedThompsonScheduler
        return DiscountedThompsonScheduler()
    elif name_clean == "stub":
        return StubScheduler()
    else:
        raise ValueError(
            f"Unknown scheduler name '{name}'. Available: {', '.join(DEFAULT_SCHEDULER_NAMES)}, stub"
        )


def _clone_scheduler(sched: Scheduler) -> Scheduler:
    """Create a fresh instance of a scheduler with matching hyperparameters.

    Uses deepcopy as the primary mechanism to preserve custom subclass
    overrides. Falls back to manual reconstruction if deepcopy fails.
    """
    import copy

    try:
        return copy.deepcopy(sched)
    except Exception:
        # Fallback: manual reconstruction for known types
        if isinstance(sched, RoundRobinScheduler):
            return RoundRobinScheduler()
        elif isinstance(sched, UniformRandomScheduler):
            return UniformRandomScheduler(seed=sched._seed)
        elif isinstance(sched, PriorWeightedScheduler):
            return PriorWeightedScheduler(priors=sched.priors, seed=sched._seed)
        elif isinstance(sched, OracleScheduler):
            return OracleScheduler()
        elif isinstance(sched, UCB1Scheduler):
            return UCB1Scheduler(
                c=sched.c,
                reward_fn=sched._reward_fn,
                use_threat_weighting=sched._use_threat_weighting,
                seed=sched._seed,
            )
        elif isinstance(sched, SWUCB1Scheduler):
            return SWUCB1Scheduler(
                window_size=sched.window_size,
                c=sched.c,
                reward_fn=sched._reward_fn,
                use_threat_weighting=sched._use_threat_weighting,
                seed=sched._seed,
            )
        elif isinstance(sched, DUCB1Scheduler):
            return DUCB1Scheduler(
                gamma=sched.gamma,
                c=sched.c,
                reward_fn=sched._reward_fn,
                use_threat_weighting=sched._use_threat_weighting,
                seed=sched._seed,
            )
        elif isinstance(sched, ThompsonSamplingScheduler):
            if hasattr(sched, "name") and sched.name == "discounted_thompson":
                from ewscan.agents.thompson import DiscountedThompsonScheduler
                return DiscountedThompsonScheduler(
                    gamma=getattr(sched, "gamma", 0.95),
                    alpha_prior=sched.alpha_prior,
                    beta_prior=sched.beta_prior,
                    use_threat_weighting=sched._use_threat_weighting,
                    seed=sched._seed,
                )
            return ThompsonSamplingScheduler(
                alpha_prior=sched.alpha_prior,
                beta_prior=sched.beta_prior,
                use_threat_weighting=sched._use_threat_weighting,
                seed=sched._seed,
            )
        elif isinstance(sched, StubScheduler):
            return StubScheduler(bands=sched.bands)
        else:
            return sched


def _resolve_scheduler(
    item: Scheduler | str | type[Scheduler] | tuple[str, Any],
    config: EpisodeConfig | None = None,
) -> tuple[str, Callable[[], Scheduler]]:
    """Resolve a scheduler specification into (name, factory_fn)."""
    if isinstance(item, str):
        sched_name = item.strip().lower().replace("-", "_")
        return sched_name, lambda: _build_scheduler_by_name(sched_name, config)

    if isinstance(item, tuple) and len(item) == 2:
        name, target = item
        if callable(target) and not isinstance(target, Scheduler):
            return str(name), target
        elif isinstance(target, Scheduler):
            return str(name), lambda: _clone_scheduler(target)
        else:
            raise TypeError(f"Invalid scheduler tuple target: {type(target)}")

    if isinstance(item, type) and issubclass(item, Scheduler):
        dummy = item()
        return dummy.name, lambda: item()

    if isinstance(item, Scheduler):
        return item.name, lambda: _clone_scheduler(item)

    if callable(item):
        dummy = item()
        if isinstance(dummy, Scheduler):
            return dummy.name, item

    raise TypeError(
        f"Expected Scheduler instance, name string, class, or factory callable; got {type(item)}"
    )


def save_sweep_csv(records: list[dict[str, Any]], filepath: str | Path) -> None:
    """Save episode sweep records to a CSV file.

    Parameters
    ----------
    records : list[dict[str, Any]]
        List of flat record dictionaries.
    filepath : str | Path
        Target CSV file path.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    if not records:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(SWEEP_CSV_COLUMNS)
        return

    # Determine headers: ordered preferred columns followed by any extra columns
    all_keys = set()
    for r in records:
        all_keys.update(r.keys())

    header = [c for c in SWEEP_CSV_COLUMNS if c in all_keys]
    for k in sorted(all_keys):
        if k not in header:
            header.append(k)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(records)


def save_aggregate_csv(
    aggregates: dict[tuple[str, str], AggregateMetrics],
    filepath: str | Path,
) -> None:
    """Save aggregated multi-seed benchmark metrics to a CSV file.

    Parameters
    ----------
    aggregates : dict[tuple[str, str], AggregateMetrics]
        Aggregated metrics dictionary keyed by (scenario_name, scheduler_name).
    filepath : str | Path
        Target CSV file path.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, Any]] = []
    for (scenario, scheduler), agg in aggregates.items():
        row: dict[str, Any] = {
            "scenario": scenario,
            "scheduler": scheduler,
            **agg.to_dict(),
        }
        rows.append(row)

    if not rows:
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("scenario,scheduler,n_episodes,confidence_level\n")
        return

    # Collect headers
    all_keys = set()
    for r in rows:
        all_keys.update(r.keys())

    header = ["scenario", "scheduler", "n_episodes", "confidence_level"]
    for k in sorted(all_keys):
        if k not in header:
            header.append(k)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)


@dataclass(frozen=True)
class SweepResult:
    """Container holding full results from a multi-seed benchmark sweep.

    Attributes
    ----------
    episode_results : list[EpisodeResult]
        Collection of all executed single-episode results.
    records : list[dict[str, Any]]
        Flat row dictionaries for every (scenario, scheduler, seed) episode.
    aggregates : dict[tuple[str, str], AggregateMetrics]
        Aggregated summary metrics keyed by (scenario_name, scheduler_name).
    duration_seconds : float
        Elapsed wall-clock execution time for the entire sweep.
    """

    episode_results: list[EpisodeResult] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)
    aggregates: dict[tuple[str, str], AggregateMetrics] = field(default_factory=dict)
    duration_seconds: float = 0.0

    @property
    def n_rows(self) -> int:
        """Total number of episode result rows (schedulers * scenarios * seeds)."""
        return len(self.records)

    def to_csv(self, filepath: str | Path) -> None:
        """Export all episode records to CSV.

        Parameters
        ----------
        filepath : str | Path
            Destination CSV path.
        """
        save_sweep_csv(self.records, filepath)

    def to_aggregate_csv(self, filepath: str | Path) -> None:
        """Export multi-seed aggregated metrics across scenarios/schedulers to CSV.

        Parameters
        ----------
        filepath : str | Path
            Destination CSV path.
        """
        save_aggregate_csv(self.aggregates, filepath)

    def to_records(self) -> list[dict[str, Any]]:
        """Return a copy of the list of flat row dictionaries."""
        return [dict(r) for r in self.records]

    def to_dataframe(self) -> Any:
        """Convert episode records into a pandas DataFrame if pandas is installed.

        Returns
        -------
        pandas.DataFrame
            DataFrame of all episode results.

        Raises
        ------
        ImportError
            If pandas is not installed in the environment.
        """
        try:
            import pandas as pd

            return pd.DataFrame(self.records)
        except ImportError as exc:
            raise ImportError(
                "pandas is required for to_dataframe(). Install pandas or use to_records() / to_csv()."
            ) from exc

    def summary(self) -> str:
        """Generate a formatted human-readable summary table of the sweep."""
        lines = [
            f"=== Multi-Seed Sweep Summary ({self.n_rows} runs, {self.duration_seconds:.2f}s) ===",
            f"{'Scenario':<16} {'Scheduler':<20} {'Runs':<6} {'Int Ratio (mean ± CI)':<24} {'Avg Reward (mean ± CI)':<24} {'Est Pd':<10}",
            "-" * 105,
        ]

        for (scenario, scheduler), agg in self.aggregates.items():
            ir = agg.interception.interception_ratio
            ir_ci = f"{ir.mean:.3f} ± {ir.ci_width / 2.0:.3f}" if ir.n_samples > 1 else f"{ir.mean:.3f}"

            rew = agg.reward.average_reward
            rew_ci = f"{rew.mean:.3f} ± {rew.ci_width / 2.0:.3f}" if rew.n_samples > 1 else f"{rew.mean:.3f}"

            pd_mean = f"{agg.detection.pd.mean:.3f}"

            lines.append(
                f"{scenario:<16} {scheduler:<20} {agg.n_episodes:<6} {ir_ci:<24} {rew_ci:<24} {pd_mean:<10}"
            )

        return "\n".join(lines)


class SweepRunner:
    """Configurable runner for executing multi-seed sweeps across scenarios and schedulers.

    Parameters
    ----------
    rf : RewardFunction | None, optional
        Custom reward function for evaluating reward metrics.
    miss_penalty : float | None, optional
        Penalty for missed bursts in time error calculation.
    pd_threshold : float, default 0.5
        Threshold for sensitivity estimation.
    confidence_level : float, default 0.95
        Confidence level for multi-seed interval estimates (0 < c < 1).
    """

    def __init__(
        self,
        rf: RewardFunction | None = None,
        miss_penalty: float | None = None,
        pd_threshold: float = 0.5,
        confidence_level: float = 0.95,
    ) -> None:
        self.rf = rf
        self.miss_penalty = miss_penalty
        self.pd_threshold = pd_threshold
        self.confidence_level = confidence_level

    def run(
        self,
        scenarios: EpisodeConfig | Sequence[EpisodeConfig] | dict[str, EpisodeConfig],
        schedulers: Sequence[Scheduler | str | type[Scheduler] | tuple[str, Any]],
        seeds: Sequence[int] | int,
        progress_callback: Callable[[int, int, str, str, int], None] | None = None,
    ) -> SweepResult:
        """Execute the multi-seed sweep.

        Parameters
        ----------
        scenarios : EpisodeConfig | Sequence[EpisodeConfig] | dict[str, EpisodeConfig]
            One or more episode configurations.
        schedulers : Sequence[Scheduler | str | type[Scheduler] | tuple[str, Any]]
            Collection of schedulers (instances, string names, or factory functions).
        seeds : Sequence[int] | int
            List of RNG seeds, or an integer count N (which generates seeds 0..N-1).
        progress_callback : Callable[[int, int, str, str, int], None] | None, optional
            Callback called on each completed episode with:
            (completed_count, total_count, scenario_name, scheduler_name, seed).

        Returns
        -------
        SweepResult
            Aggregated and per-episode sweep results.
        """
        # 1. Normalize scenarios into dict[str, EpisodeConfig]
        scenarios_dict: dict[str, EpisodeConfig] = {}
        if isinstance(scenarios, EpisodeConfig):
            scenarios_dict["default"] = scenarios
        elif isinstance(scenarios, str):
            if scenarios.strip().lower() == "all":
                from ewscan.experiments.scenarios import get_all_scenarios

                scenarios_dict = get_all_scenarios()
            elif Path(scenarios).is_file():
                scenarios_dict[Path(scenarios).stem] = load_config(scenarios)
            else:
                from ewscan.experiments.scenarios import (
                    canonical_scenario_name,
                    get_scenario,
                )

                name = canonical_scenario_name(scenarios)
                scenarios_dict[name] = get_scenario(name)
        elif isinstance(scenarios, dict):
            for k, v in scenarios.items():
                if isinstance(v, EpisodeConfig):
                    scenarios_dict[k] = v
                elif isinstance(v, str):
                    if Path(v).is_file():
                        scenarios_dict[k] = load_config(v)
                    else:
                        from ewscan.experiments.scenarios import get_scenario

                        scenarios_dict[k] = get_scenario(v)
                else:
                    raise TypeError(
                        f"Invalid scenario type in dict for key '{k}': {type(v)}"
                    )
        elif isinstance(scenarios, Sequence):
            for idx, sc in enumerate(scenarios):
                if isinstance(sc, EpisodeConfig):
                    scenarios_dict[f"scenario_{idx}"] = sc
                elif isinstance(sc, str):
                    if Path(sc).is_file():
                        key = Path(sc).stem
                        # Deduplicate: append suffix if key already exists
                        if key in scenarios_dict:
                            suffix = 1
                            while f"{key}_{suffix}" in scenarios_dict:
                                suffix += 1
                            key = f"{key}_{suffix}"
                        scenarios_dict[key] = load_config(sc)
                    else:
                        from ewscan.experiments.scenarios import (
                            canonical_scenario_name,
                            get_scenario,
                        )

                        name = canonical_scenario_name(sc)
                        scenarios_dict[name] = get_scenario(name)
                else:
                    raise TypeError(
                        f"Invalid scenario element type at index {idx}: {type(sc)}"
                    )
        else:
            raise TypeError(f"Invalid scenarios type: {type(scenarios)}")

        # 2. Normalize seeds into list[int]
        if isinstance(seeds, int):
            if seeds <= 0:
                raise ValueError(f"seeds count must be positive, got {seeds}")
            seeds_list = list(range(seeds))
        elif isinstance(seeds, Sequence):
            seeds_list = [int(s) for s in seeds]
            if len(seeds_list) == 0:
                raise ValueError("seeds sequence cannot be empty")
        else:
            raise TypeError(f"Invalid seeds type: {type(seeds)}")

        # 3. Calculate total episodes
        total_episodes = len(scenarios_dict) * len(schedulers) * len(seeds_list)

        episode_results: list[EpisodeResult] = []
        records: list[dict[str, Any]] = []
        aggregates: dict[tuple[str, str], AggregateMetrics] = {}

        start_time = time.perf_counter()
        completed = 0

        # 4. Sweep execution loop
        for scenario_name, config in scenarios_dict.items():
            # Resolve schedulers for this scenario
            resolved_schedulers: list[tuple[str, Callable[[], Scheduler]]] = [
                _resolve_scheduler(s, config) for s in schedulers
            ]

            for sched_name, sched_factory in resolved_schedulers:
                scenario_sched_results: list[EpisodeResult] = []

                for seed in seeds_list:
                    scheduler_instance = sched_factory()
                    ep_res = run_episode(
                        config=config,
                        scheduler=scheduler_instance,
                        seed=seed,
                        rf=self.rf,
                        miss_penalty=self.miss_penalty,
                        pd_threshold=self.pd_threshold,
                    )

                    episode_results.append(ep_res)
                    scenario_sched_results.append(ep_res)

                    record = {
                        "scenario": scenario_name,
                        **ep_res.to_dict(),
                        "scheduler": sched_name,
                    }
                    records.append(record)


                    completed += 1
                    if progress_callback is not None:
                        progress_callback(
                            completed,
                            total_episodes,
                            scenario_name,
                            sched_name,
                            seed,
                        )

                # Aggregate across seeds for (scenario, scheduler)
                agg = aggregate_metric_records(
                    detection_list=[r.detection for r in scenario_sched_results],
                    interception_list=[r.interception for r in scenario_sched_results],
                    first_intercept_list=[r.first_intercept for r in scenario_sched_results],
                    reward_list=[r.reward for r in scenario_sched_results],
                    prediction_list=[r.prediction for r in scenario_sched_results],
                    time_error_list=[r.time_error for r in scenario_sched_results],
                    confidence_level=self.confidence_level,
                )
                aggregates[(scenario_name, sched_name)] = agg

        total_duration = time.perf_counter() - start_time

        return SweepResult(
            episode_results=episode_results,
            records=records,
            aggregates=aggregates,
            duration_seconds=total_duration,
        )


def run_sweep(
    scenarios: EpisodeConfig | Sequence[EpisodeConfig] | dict[str, EpisodeConfig],
    schedulers: Sequence[Scheduler | str | type[Scheduler] | tuple[str, Any]],
    seeds: Sequence[int] | int,
    rf: RewardFunction | None = None,
    miss_penalty: float | None = None,
    pd_threshold: float = 0.5,
    confidence_level: float = 0.95,
    progress_callback: Callable[[int, int, str, str, int], None] | None = None,
) -> SweepResult:
    """Execute a multi-seed sweep across scenarios and schedulers.

    Parameters
    ----------
    scenarios : EpisodeConfig | Sequence[EpisodeConfig] | dict[str, EpisodeConfig]
        Scenario configurations.
    schedulers : Sequence[Scheduler | str | type[Scheduler] | tuple[str, Any]]
        List of schedulers.
    seeds : Sequence[int] | int
        List of seeds or count of seeds.
    rf : RewardFunction | None, optional
        Custom RewardFunction instance.
    miss_penalty : float | None, optional
        Penalty for missed bursts in time error calculation.
    pd_threshold : float, default 0.5
        Threshold for sensitivity estimation.
    confidence_level : float, default 0.95
        Confidence level for interval estimates.
    progress_callback : Callable[[int, int, str, str, int], None] | None, optional
        Progress reporting callback.

    Returns
    -------
    SweepResult
        Completed sweep results container.
    """
    runner = SweepRunner(
        rf=rf,
        miss_penalty=miss_penalty,
        pd_threshold=pd_threshold,
        confidence_level=confidence_level,
    )
    return runner.run(
        scenarios=scenarios,
        schedulers=schedulers,
        seeds=seeds,
        progress_callback=progress_callback,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for executing multi-seed sweeps."""
    parser = argparse.ArgumentParser(
        description="Run multi-seed sweeps across EW scan schedulers and export CSV results."
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        action="append",
        default=None,
        help="Path(s) to YAML scenario config files (default: configs/mvp.yaml).",
    )
    parser.add_argument(
        "--schedulers",
        "-s",
        type=str,
        default=None,
        help=(
            "Comma-separated list of schedulers to run (e.g. 'oracle,ucb1,round_robin'). "
            f"Defaults to all: {','.join(DEFAULT_SCHEDULER_NAMES)}"
        ),
    )
    parser.add_argument(
        "--seeds",
        type=str,
        default=None,
        help="Comma-separated list of explicit seed integers (e.g. '0,1,2,3,4').",
    )
    parser.add_argument(
        "--num-seeds",
        "-n",
        type=int,
        default=30,
        help="Number of seeds to run if --seeds is not given (default: 30).",
    )
    parser.add_argument(
        "--seed-start",
        type=int,
        default=0,
        help="Starting seed integer when using --num-seeds (default: 0).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="sweep_results.csv",
        help="Target CSV file path for episode-level results (default: sweep_results.csv).",
    )
    parser.add_argument(
        "--aggregate-output",
        type=str,
        default=None,
        help="Optional CSV file path for multi-seed aggregated metrics.",
    )
    parser.add_argument(
        "--confidence-level",
        type=float,
        default=0.95,
        help="Confidence level for interval estimates (default: 0.95).",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress console progress output.",
    )

    args = parser.parse_args(argv)

    try:
        # 1. Parse scenario configs
        config_paths = args.config if args.config else ["configs/mvp.yaml"]
        scenarios: dict[str, EpisodeConfig] = {}
        for cp in config_paths:
            if cp.strip().lower() == "all":
                from ewscan.experiments.scenarios import get_all_scenarios

                scenarios.update(get_all_scenarios())
            else:
                path = Path(cp)
                if path.is_file():
                    scenario_name = path.stem
                    scenarios[scenario_name] = load_config(path)
                else:
                    from ewscan.experiments.scenarios import (
                        canonical_scenario_name,
                        get_scenario,
                    )

                    name = canonical_scenario_name(cp)
                    scenarios[name] = get_scenario(name)

        # 2. Parse schedulers
        if args.schedulers:
            scheduler_names = [s.strip() for s in args.schedulers.split(",") if s.strip()]
        else:
            scheduler_names = list(DEFAULT_SCHEDULER_NAMES)

        # 3. Parse seeds
        if args.seeds:
            seeds = [int(s.strip()) for s in args.seeds.split(",") if s.strip()]
        else:
            seeds = list(range(args.seed_start, args.seed_start + args.num_seeds))

        if not args.quiet:
            print(
                f"Starting sweep: {len(scenarios)} scenario(s), {len(scheduler_names)} scheduler(s), {len(seeds)} seed(s) "
                f"({len(scenarios) * len(scheduler_names) * len(seeds)} total runs)..."
            )

        def _cli_progress(done: int, total: int, sc: str, sch: str, sd: int) -> None:
            if not args.quiet and (done % max(1, total // 20) == 0 or done == total):
                pct = 100.0 * done / total
                print(f"[{done:>4}/{total}] ({pct:>5.1f}%) {sc} | {sch:<18} (seed={sd})")

        result = run_sweep(
            scenarios=scenarios,
            schedulers=scheduler_names,
            seeds=seeds,
            confidence_level=args.confidence_level,
            progress_callback=_cli_progress if not args.quiet else None,
        )

        # 4. Save results
        if args.output:
            result.to_csv(args.output)
            if not args.quiet:
                print(f"Saved {result.n_rows} episode records to {args.output}")

        if args.aggregate_output:
            result.to_aggregate_csv(args.aggregate_output)
            if not args.quiet:
                print(f"Saved aggregated metrics to {args.aggregate_output}")

        if not args.quiet:
            print("\n" + result.summary() + "\n")

        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
