"""Tests for single-episode runner (Experiment harness Task 1 -- Phase 1E.8).

Verifications:
- Same seed and stub scheduler give identical metrics twice (PLAN.md criterion).
- Deterministic behavior across all baseline and learning schedulers.
- Correct handling of OracleScheduler with truth injection.
- Verification of all 7 figures of merit in EpisodeResult.
- Flat dict serialization and CLI operation.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from ewscan.agents.baselines import (
    OracleScheduler,
    PriorWeightedScheduler,
    RoundRobinScheduler,
    UniformRandomScheduler,
)
from ewscan.agents.nonstationary_ucb import (
    DUCB1Scheduler,
    SWUCB1Scheduler,
)
from ewscan.agents.thompson import (
    DiscountedThompsonScheduler,
    ThompsonSamplingScheduler,
)
from ewscan.agents.reward import RewardFunction
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig
from ewscan.env.environment import RFEnvironment
from ewscan.env.recorder import load_episode_log
from ewscan.experiments.runner import (
    EpisodeRunner,
    _build_scheduler_by_name,
    main,
    run_episode,
)
from ewscan.testing.fixtures import StubScheduler, make_test_config


def _build_scenario_config(seed: int = 42) -> EpisodeConfig:
    """Build a multi-emitter scenario config for runner tests."""
    emitters = (
        EmitterInfo(
            band=0,
            snr=15.0,
            threat_level=0.8,
            emitter_type="gilbert_elliott",
            params={"p01": 0.1, "p10": 0.3},
        ),
        EmitterInfo(
            band=2,
            snr=20.0,
            threat_level=1.0,
            emitter_type="periodic",
            params={"period": 10, "dwell": 2, "jitter": 0},
        ),
        EmitterInfo(
            band=3,
            snr=12.0,
            threat_level=0.5,
            emitter_type="cw",
        ),
    )
    return make_test_config(
        n_bands=4,
        n_slots=100,
        emitters=emitters,
        pfa=1e-3,
        detection_threshold=None,
        seed=seed,
    )


class TestEpisodeRunner:
    """Unit and verification tests for EpisodeRunner and run_episode."""

    def test_verify_same_seed_stub_scheduler_identical_metrics(self):
        """PLAN.md 1E.8 Verify: Same seed and stub scheduler give identical metrics twice."""
        config = _build_scenario_config(seed=12345)
        stub1 = StubScheduler(bands=[0, 2])
        stub2 = StubScheduler(bands=[0, 2])

        result1 = run_episode(config, stub1, seed=12345)
        result2 = run_episode(config, stub2, seed=12345)

        # 1. Logs must be strictly identical
        assert np.array_equal(result1.log.truth, result2.log.truth)
        assert np.array_equal(result1.log.actions, result2.log.actions)
        assert np.array_equal(result1.log.detections, result2.log.detections)

        # 2. All 7 figures of merit must match exactly
        # FoM 1: Detection
        assert result1.detection.pd.pd == result2.detection.pd.pd
        assert result1.detection.pfa.pfa == result2.detection.pfa.pfa
        assert result1.detection.sensitivity.min_detectable_snr == result2.detection.sensitivity.min_detectable_snr

        # FoM 2: Interception
        assert result1.interception.interception_ratio.ratio == result2.interception.interception_ratio.ratio
        assert result1.interception.interception_ratio.n_hits == result2.interception.interception_ratio.n_hits
        assert result1.interception.intercept_rate.rate == result2.interception.intercept_rate.rate

        # FoM 3: First intercept
        assert result1.first_intercept.mean_time_to_first_intercept == result2.first_intercept.mean_time_to_first_intercept
        assert result1.first_intercept.n_intercepted == result2.first_intercept.n_intercepted

        # FoM 4: Reward
        assert result1.reward.total_reward == result2.reward.total_reward
        assert result1.reward.average_reward == result2.reward.average_reward
        assert result1.reward.total_hit_reward == result2.reward.total_hit_reward
        assert result1.reward.total_miss_cost == result2.reward.total_miss_cost

        # FoM 5: Prediction
        assert result1.prediction.accuracy == result2.prediction.accuracy
        assert result1.prediction.percentage_correct == result2.prediction.percentage_correct

        # FoM 6: Time error
        assert result1.time_error.mean_time_error == result2.time_error.mean_time_error
        assert result1.time_error.mean_time_error_penalized == result2.time_error.mean_time_error_penalized
        assert result1.time_error.burst_interception_ratio == result2.time_error.burst_interception_ratio

        # Metadata
        assert result1.scheduler_name == "stub"
        assert result1.seed == 12345
        assert result1.duration_seconds >= 0.0

    def test_determinism_across_schedulers(self):
        """Verify determinism across all baseline and learning schedulers."""
        config = _build_scenario_config(seed=42)
        schedulers = [
            RoundRobinScheduler(),
            UniformRandomScheduler(seed=42),
            PriorWeightedScheduler(priors=[0.4, 0.1, 0.3, 0.2], seed=42),
            UCB1Scheduler(seed=42),
            SWUCB1Scheduler(window_size=20, seed=42),
            DUCB1Scheduler(gamma=0.9, seed=42),
            ThompsonSamplingScheduler(seed=42),
            DiscountedThompsonScheduler(gamma=0.9, seed=42),
        ]

        for sched in schedulers:
            r1 = run_episode(config, sched, seed=42)
            # Fresh instance for second run
            sched_fresh: Any
            if isinstance(sched, PriorWeightedScheduler):
                sched_fresh = PriorWeightedScheduler(priors=[0.4, 0.1, 0.3, 0.2], seed=42)
            elif isinstance(sched, SWUCB1Scheduler):
                sched_fresh = SWUCB1Scheduler(window_size=20, seed=42)
            elif isinstance(sched, DUCB1Scheduler):
                sched_fresh = DUCB1Scheduler(gamma=0.9, seed=42)
            elif isinstance(sched, DiscountedThompsonScheduler):
                sched_fresh = DiscountedThompsonScheduler(gamma=0.9, seed=42)
            elif hasattr(sched, "_seed"):
                sched_fresh = type(sched)(seed=42)
            else:
                sched_fresh = type(sched)()

            r2 = run_episode(config, sched_fresh, seed=42)

            assert np.array_equal(r1.log.actions, r2.log.actions), f"Failed actions determinism for {sched.name}"
            assert np.array_equal(r1.log.detections, r2.log.detections), f"Failed detections determinism for {sched.name}"
            assert r1.interception.interception_ratio.ratio == r2.interception.interception_ratio.ratio
            assert r1.reward.total_reward == r2.reward.total_reward

    def test_learning_scheduler_records_per_slot_learning_values(self):
        config = _build_scenario_config(seed=42)

        result = run_episode(config, UCB1Scheduler(), seed=42)

        assert result.learning is not None
        assert result.learning.metric == "empirical_detection_rate"
        assert result.learning.values.shape == (config.n_slots, config.n_bands)
        assert np.all(np.isfinite(result.learning.values))
        assert np.all((0.0 <= result.learning.values) & (result.learning.values <= 1.0))

    def test_fixed_scheduler_has_no_learning_telemetry(self):
        config = _build_scenario_config(seed=42)

        result = run_episode(config, RoundRobinScheduler(), seed=42)

        assert result.learning is None

    def test_different_seeds_produce_different_runs(self):
        """Verify that different seeds alter RF environment generation and outcomes."""
        config = _build_scenario_config(seed=42)
        sched1 = RoundRobinScheduler()
        sched2 = RoundRobinScheduler()

        r1 = run_episode(config, sched1, seed=42)
        r2 = run_episode(config, sched2, seed=999)

        assert not np.array_equal(r1.log.truth, r2.log.truth)
        assert r1.seed == 42
        assert r2.seed == 999

    def test_oracle_scheduler_execution(self):
        """Verify OracleScheduler executes seamlessly with truth injection."""
        # Single isolated emitter: oracle achieves 0.0 intercept time error
        single_emitter_config = make_test_config(
            n_bands=4,
            n_slots=50,
            emitters=(
                EmitterInfo(
                    band=2,
                    snr=25.0,
                    threat_level=1.0,
                    emitter_type="periodic",
                    params={"period": 10, "dwell": 3, "jitter": 0},
                ),
            ),
            seed=42,
        )
        oracle = OracleScheduler()
        single_res = run_episode(single_emitter_config, oracle, seed=42)
        assert single_res.scheduler_name == "oracle"
        assert single_res.time_error.mean_time_error == 0.0

        # Multi-emitter scenario: oracle achieves higher hits than round robin
        config = _build_scenario_config(seed=42)
        multi_res = run_episode(config, oracle, seed=42)
        assert multi_res.scheduler_name == "oracle"
        assert multi_res.log.truth.shape == (4, 100)

        rr_result = run_episode(config, RoundRobinScheduler(), seed=42)
        assert multi_res.interception.interception_ratio.n_hits >= rr_result.interception.interception_ratio.n_hits

    def test_episode_runner_class_with_custom_parameters(self):
        """Verify EpisodeRunner class with custom RewardFunction and miss_penalty."""
        config = _build_scenario_config(seed=42)
        rf = RewardFunction(w_threat=2.0, c_miss=1.0, w_novelty=0.5, w_decay=0.2)
        runner = EpisodeRunner(rf=rf, miss_penalty=10.0, pd_threshold=0.6)

        result = runner.run(config, RoundRobinScheduler(), seed=42)
        assert result.reward.total_reward != 0.0
        assert result.time_error.mean_time_error_penalized >= result.time_error.mean_time_error

    def test_with_preinstantiated_env(self):
        """Verify passing pre-instantiated RFEnvironment."""
        config = _build_scenario_config(seed=42)
        env = RFEnvironment(config)
        sched = RoundRobinScheduler()

        result = run_episode(config, sched, seed=42, env=env)
        assert result.log.truth.shape == (4, 100)
        assert len(result.log.actions) == 100

    def test_to_dict_flattening(self):
        """Verify to_dict flattens all key metrics into serializable types."""
        config = _build_scenario_config(seed=42)
        result = run_episode(config, RoundRobinScheduler(), seed=42)

        flat = result.to_dict(prefix="exp_")
        assert flat["exp_scheduler"] == "round_robin"
        assert flat["exp_seed"] == 42
        assert flat["exp_n_bands"] == 4
        assert flat["exp_n_slots"] == 100
        assert "exp_interception_ratio" in flat
        assert "exp_intercept_rate" in flat
        assert "exp_pd" in flat
        assert "exp_pfa" in flat
        assert "exp_sensitivity" in flat
        assert "exp_ttfi" in flat
        assert "exp_intercept_fraction" in flat
        assert "exp_average_reward" in flat
        assert "exp_total_reward" in flat
        assert "exp_time_error" in flat
        assert "exp_prediction_accuracy" in flat

        # Ensure all values are numeric/string or None
        for k, v in flat.items():
            assert v is None or isinstance(v, (int, float, str, np.number)), f"Key {k} has unexpected type {type(v)}"

    def test_summary_string_format(self):
        """Verify summary returns a descriptive non-empty string."""
        config = _build_scenario_config(seed=42)
        result = run_episode(config, RoundRobinScheduler(), seed=42)
        summary = result.summary()

        assert "=== Episode Result: round_robin" in summary
        assert "Interception Ratio" in summary
        assert "Average Reward" in summary
        assert "Estimated Pd" in summary

    def test_build_scheduler_by_name(self):
        """Verify scheduler resolution by string name."""
        assert isinstance(_build_scheduler_by_name("round_robin"), RoundRobinScheduler)
        assert isinstance(_build_scheduler_by_name("uniform_random"), UniformRandomScheduler)
        assert isinstance(_build_scheduler_by_name("prior_weighted"), PriorWeightedScheduler)
        assert isinstance(_build_scheduler_by_name("oracle"), OracleScheduler)
        assert isinstance(_build_scheduler_by_name("ucb1"), UCB1Scheduler)
        assert isinstance(_build_scheduler_by_name("sliding_window_ucb"), SWUCB1Scheduler)
        assert isinstance(_build_scheduler_by_name("swucb1"), SWUCB1Scheduler)
        assert isinstance(_build_scheduler_by_name("discounted_ucb"), DUCB1Scheduler)
        assert isinstance(_build_scheduler_by_name("ducb1"), DUCB1Scheduler)
        with pytest.raises(ValueError, match="Unknown scheduler name"):
            _build_scheduler_by_name("non_existent_sched")

    def test_cli_execution(self, tmp_path: Path):
        """Verify CLI main entrypoint with --config, --scheduler, and --save-log."""
        log_file = tmp_path / "test_run.json"
        exit_code = main([
            "--config", "configs/mvp.yaml",
            "--scheduler", "round_robin",
            "--seed", "42",
            "--save-log", str(log_file),
        ])
        assert exit_code == 0
        assert log_file.is_file()

        # Load back the saved log
        loaded_log = load_episode_log(log_file)
        assert loaded_log.config.n_bands == 16
        assert loaded_log.config.n_slots == 2000
        assert len(loaded_log.actions) == 2000

    def test_cli_invalid_config_or_scheduler(self):
        """Verify CLI handles errors gracefully."""
        exit_code = main(["--config", "non_existent.yaml"])
        assert exit_code == 1

        exit_code_sched = main(["--config", "configs/mvp.yaml", "--scheduler", "unknown_sched"])
        assert exit_code_sched == 1


def test_run_episode_stops_at_hard_deadline():
    config = make_test_config(n_bands=2, n_slots=10, k=1)

    with pytest.raises(TimeoutError, match="deadline"):
        run_episode(config, RoundRobinScheduler(), deadline=0.0)
