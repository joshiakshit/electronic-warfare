"""Scheduler registry shared by runner, sweeps, and the API."""

from __future__ import annotations

from collections.abc import Callable

from ewscan.contracts import Scheduler


SchedulerFactory = Callable[[], Scheduler]


def _factories() -> dict[str, SchedulerFactory]:
    from ewscan.agents.baselines import (
        OracleScheduler,
        PriorWeightedScheduler,
        RoundRobinScheduler,
        UniformRandomScheduler,
    )
    from ewscan.agents.nonstationary_ucb import DUCB1Scheduler, SWUCB1Scheduler
    from ewscan.agents.pomdp import BeliefScheduler
    from ewscan.agents.sniper import SniperScheduler
    from ewscan.agents.thompson import DiscountedThompsonScheduler, ThompsonSamplingScheduler
    from ewscan.agents.ucb import UCB1Scheduler
    from ewscan.agents.whittle import WhittleScheduler

    return {
        "round_robin": RoundRobinScheduler,
        "uniform_random": UniformRandomScheduler,
        "prior_weighted": PriorWeightedScheduler,
        "oracle": OracleScheduler,
        "ucb1": UCB1Scheduler,
        "sliding_window_ucb": SWUCB1Scheduler,
        "discounted_ucb": DUCB1Scheduler,
        "thompson_sampling": ThompsonSamplingScheduler,
        "discounted_thompson": DiscountedThompsonScheduler,
        "belief": BeliefScheduler,
        "whittle": WhittleScheduler,
        "sniper": SniperScheduler,
    }


_ALIASES = {
    "random": "uniform_random",
    "prior": "prior_weighted",
    "sw_ucb": "sliding_window_ucb",
    "swucb1": "sliding_window_ucb",
    "d_ucb": "discounted_ucb",
    "ducb1": "discounted_ucb",
    "thompson": "thompson_sampling",
    "ts": "thompson_sampling",
    "discounted_thompson_sampling": "discounted_thompson",
    "d_ts": "discounted_thompson",
    "dts": "discounted_thompson",
}


def scheduler_names() -> tuple[str, ...]:
    """Return the canonical scheduler names safe for user selection."""
    return tuple(_factories())


def build_scheduler(name: str) -> Scheduler:
    """Create a scheduler from a canonical name or documented alias."""
    cleaned = name.strip().lower().replace("-", "_")
    canonical = _ALIASES.get(cleaned, cleaned)
    factories = _factories()
    try:
        return factories[canonical]()
    except KeyError as exc:
        available = ", ".join(scheduler_names())
        raise ValueError(f"Unknown scheduler name '{name}'. Available: {available}") from exc
