import pytest
from ewscan.contracts import EmitterInfo, EpisodeConfig
from ewscan.agents.baselines import UniformRandomScheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.agents.nonstationary_ucb import SWUCB1Scheduler, DUCB1Scheduler
from ewscan.agents.thompson import ThompsonSamplingScheduler, DiscountedThompsonScheduler
from ewscan.experiments.runner import run_episode

def test_learners_beat_random_stationary_bench():
    """Convergence tests on a stationary bench (Phase 1 Integration Task 3).
    Defines the pass bar; learners beat random by a stated margin."""
    config = EpisodeConfig(
        n_bands=5,
        n_slots=2000,
        k=1,
        emitters=(
            EmitterInfo(
                band=2,
                snr=15.0,
                threat_level=1.0,
                emitter_type="gilbert_elliott",
                params={"p01": 0.5, "p10": 0.5},
            ),
        ),
        detection_threshold=3.0,
        pfa=1e-4,
        seed=42,
    )
    
    random_sched = UniformRandomScheduler(seed=42)
    random_res = run_episode(config, random_sched, seed=42)
    
    # Margin of interception ratio. Random should be ~ 1/5 = 0.2. 
    # Learners should easily hit > 0.4 on this stationary target.
    pass_margin = 0.20
    
    learners = [
        UCB1Scheduler(seed=42),
        SWUCB1Scheduler(seed=42),
        DUCB1Scheduler(seed=42),
        ThompsonSamplingScheduler(seed=42),
        DiscountedThompsonScheduler(seed=42)
    ]
    
    for learner in learners:
        learner_res = run_episode(config, learner, seed=42)
        diff = learner_res.interception.interception_ratio.ratio - random_res.interception.interception_ratio.ratio
        assert diff >= pass_margin, (
            f"{learner.name} failed to beat random by margin {pass_margin}. "
            f"Random: {random_res.interception.interception_ratio.ratio}, "
            f"{learner.name}: {learner_res.interception.interception_ratio.ratio}"
        )


def test_end_to_end_smoke():
    """End-to-end smoke test (Phase 1 Integration Task 4).
    Verify that all scenarios and all schedulers run with no exception."""
    from ewscan.experiments.scenarios import get_all_scenarios
    from ewscan.experiments.sweep import DEFAULT_SCHEDULER_NAMES
    from ewscan.experiments.runner import _build_scheduler_by_name
    
    # We will use a reduced number of slots (e.g. 50) to keep the smoke test fast
    # but still enough to step through the environment loop.
    scenarios = get_all_scenarios(n_slots=50)
    
    for scenario_name, config in scenarios.items():
        for sched_name in DEFAULT_SCHEDULER_NAMES:
            scheduler = _build_scheduler_by_name(sched_name, config)
            # The act of running it without raising an exception is the test itself
            res = run_episode(config, scheduler, seed=42)
            
            # Basic sanity checks to ensure it actually produced output
            assert res.scheduler_name == scheduler.name
            assert res.log.truth.shape[1] == 50
            assert len(res.log.actions) == 50

