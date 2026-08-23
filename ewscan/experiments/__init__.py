"""Experiment harness modules for ewscan."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ewscan.experiments.runner import EpisodeResult, EpisodeRunner, run_episode
    from ewscan.experiments.scenarios import (
        SCENARIO_BUILDERS,
        SCENARIO_METADATA,
        ScenarioMetadata,
        canonical_scenario_name,
        get_all_scenarios,
        get_scenario,
        get_scenario_metadata,
        list_scenarios,
        make_mixed_threat_scenario,
        make_periodic_radar_scenario,
        make_sparse_bursty_scenario,
    )
    from ewscan.experiments.sweep import (
        DEFAULT_SCHEDULER_NAMES,
        SweepResult,
        SweepRunner,
        run_sweep,
        save_aggregate_csv,
        save_sweep_csv,
    )

__all__ = [
    "DEFAULT_SCHEDULER_NAMES",
    "EpisodeResult",
    "EpisodeRunner",
    "SCENARIO_BUILDERS",
    "SCENARIO_METADATA",
    "ScenarioMetadata",
    "SweepResult",
    "SweepRunner",
    "canonical_scenario_name",
    "get_all_scenarios",
    "get_scenario",
    "get_scenario_metadata",
    "list_scenarios",
    "make_mixed_threat_scenario",
    "make_periodic_radar_scenario",
    "make_sparse_bursty_scenario",
    "run_episode",
    "run_sweep",
    "save_aggregate_csv",
    "save_sweep_csv",
]


def __getattr__(name: str):
    if name in ("EpisodeResult", "EpisodeRunner", "run_episode"):
        import ewscan.experiments.runner as _r

        return getattr(_r, name)
    elif name in (
        "DEFAULT_SCHEDULER_NAMES",
        "SweepResult",
        "SweepRunner",
        "run_sweep",
        "save_aggregate_csv",
        "save_sweep_csv",
    ):
        import ewscan.experiments.sweep as _s

        return getattr(_s, name)
    elif name in (
        "SCENARIO_BUILDERS",
        "SCENARIO_METADATA",
        "ScenarioMetadata",
        "canonical_scenario_name",
        "get_all_scenarios",
        "get_scenario",
        "get_scenario_metadata",
        "list_scenarios",
        "make_mixed_threat_scenario",
        "make_periodic_radar_scenario",
        "make_sparse_bursty_scenario",
    ):
        import ewscan.experiments.scenarios as _sc

        return getattr(_sc, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


