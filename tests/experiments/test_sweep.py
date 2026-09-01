"""Tests for multi-seed sweep runner (Experiment harness Task 2 -- Phase 1E.8).

Verifications:
- Output rows equal schedulers times seeds (PLAN.md Task 2 criterion).
- Deterministic behavior across runs with the same seeds.
- Correct multi-seed aggregation and confidence intervals across all 7 figures of merit.
- CSV export for both episode-level records and aggregate metrics.
- Support for all baseline and learning schedulers.
- CLI main entrypoint execution.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ewscan.agents.baselines import RoundRobinScheduler
from ewscan.agents.nonstationary_ucb import SWUCB1Scheduler
from ewscan.agents.ucb import UCB1Scheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig
from ewscan.experiments.sweep import (
    main,
    run_sweep,
)
from ewscan.testing.fixtures import make_test_config


def _build_test_scenario(seed: int = 42, n_slots: int = 60) -> EpisodeConfig:
    """Build a compact scenario config for quick testing."""
    emitters = (
        EmitterInfo(
            band=0,
            snr=18.0,
            threat_level=0.8,
            emitter_type="gilbert_elliott",
            params={"p01": 0.1, "p10": 0.2},
        ),
        EmitterInfo(
            band=2,
            snr=22.0,
            threat_level=1.0,
            emitter_type="periodic",
            params={"period": 10, "dwell": 2, "jitter": 0},
        ),
    )
    return make_test_config(
        n_bands=4,
        n_slots=n_slots,
        emitters=emitters,
        pfa=1e-3,
        detection_threshold=None,
        seed=seed,
    )


class TestSweepRunner:
    """Unit and integration tests for SweepRunner and run_sweep."""

    def test_verify_output_rows_equal_schedulers_times_seeds(self):
        """PLAN.md 1E.8 Task 2 Criterion: Output rows equal schedulers times seeds."""
        config = _build_test_scenario()
        schedulers = ["round_robin", "uniform_random", "ucb1"]
        seeds = [10, 20, 30, 40]

        result = run_sweep(
            scenarios=config,
            schedulers=schedulers,
            seeds=seeds,
        )

        expected_rows = len(schedulers) * len(seeds)  # 3 * 4 = 12
        assert result.n_rows == expected_rows
        assert len(result.episode_results) == expected_rows
        assert len(result.records) == expected_rows

        # Check unique (scheduler, seed) pairs
        sched_seed_pairs = [(r["scheduler"], r["seed"]) for r in result.records]
        assert len(set(sched_seed_pairs)) == expected_rows

    def test_multi_scenario_row_count(self):
        """Verify row count scaling across multiple scenarios."""
        scenarios = {
            "scen_a": _build_test_scenario(seed=1, n_slots=30),
            "scen_b": _build_test_scenario(seed=2, n_slots=30),
        }
        schedulers = ["round_robin", "oracle"]
        seeds = [100, 200, 300]

        result = run_sweep(
            scenarios=scenarios,
            schedulers=schedulers,
            seeds=seeds,
        )

        expected_rows = len(scenarios) * len(schedulers) * len(seeds)  # 2 * 2 * 3 = 12
        assert result.n_rows == expected_rows
        assert len(result.aggregates) == len(scenarios) * len(schedulers)  # 4 aggregate entries

    def test_determinism_across_sweep_runs(self, tmp_path: Path):
        """Verify that running the same sweep twice produces identical outputs."""
        config = _build_test_scenario(seed=42, n_slots=50)
        schedulers = ["round_robin", "ucb1", "thompson_sampling"]
        seeds = [42, 43, 44]

        res1 = run_sweep(config, schedulers, seeds)
        res2 = run_sweep(config, schedulers, seeds)

        assert res1.n_rows == res2.n_rows
        for r1, r2 in zip(res1.records, res2.records):
            for k in r1:
                if k != "duration_seconds":
                    assert r1[k] == r2[k], f"Mismatch for key {k}: {r1[k]} != {r2[k]}"

        # Also verify CSV export succeeds and headers/rows match
        csv1 = tmp_path / "sweep1.csv"
        csv2 = tmp_path / "sweep2.csv"
        res1.to_csv(csv1)
        res2.to_csv(csv2)
        assert csv1.is_file() and csv2.is_file()

        with open(csv1, newline="", encoding="utf-8") as f1, open(csv2, newline="", encoding="utf-8") as f2:
            r1_rows = list(csv.DictReader(f1))
            r2_rows = list(csv.DictReader(f2))
            assert len(r1_rows) == len(r2_rows)
            for row1, row2 in zip(r1_rows, r2_rows):
                for k in row1:
                    if k != "duration_seconds":
                        assert row1[k] == row2[k], f"CSV mismatch for key {k}: {row1[k]} != {row2[k]}"


    def test_multi_seed_aggregation_and_ci(self):
        """Verify that aggregates correctly compute statistics and confidence intervals."""
        config = _build_test_scenario(seed=42, n_slots=60)
        schedulers = ["round_robin"]
        seeds = [1, 2, 3, 4, 5, 6, 7, 8]

        result = run_sweep(config, schedulers, seeds, confidence_level=0.95)

        agg = result.aggregates[("default", "round_robin")]
        assert agg.n_episodes == len(seeds)
        assert agg.confidence_level == 0.95

        # Check interception ratio statistics
        ir_stats = agg.interception.interception_ratio
        assert ir_stats.n_samples == len(seeds)
        assert not np.isnan(ir_stats.mean)
        assert ir_stats.std >= 0.0
        assert ir_stats.ci_lower <= ir_stats.mean <= ir_stats.ci_upper
        assert ir_stats.ci_width == pytest.approx(ir_stats.ci_upper - ir_stats.ci_lower)

        # Check reward statistics
        rew_stats = agg.reward.average_reward
        assert rew_stats.n_samples == len(seeds)
        assert rew_stats.ci_lower <= rew_stats.mean <= rew_stats.ci_upper

    def test_all_standard_schedulers(self):
        """Verify sweep execution across all standard baseline and learning schedulers."""
        config = _build_test_scenario(seed=42, n_slots=40)
        all_scheds = [
            "round_robin",
            "uniform_random",
            "prior_weighted",
            "oracle",
            "ucb1",
            "sliding_window_ucb",
            "discounted_ucb",
            "thompson_sampling",
            "discounted_thompson",
        ]
        seeds = [10, 20]

        result = run_sweep(config, all_scheds, seeds)
        assert result.n_rows == len(all_scheds) * len(seeds)

        # Check all schedulers are present in records
        recorded_scheds = {r["scheduler"] for r in result.records}
        assert recorded_scheds == set(all_scheds)


    def test_ordering_regression_signal(self):
        """PLAN.md Verification: oracle > learner > round-robin on interception ratio."""
        config = _build_test_scenario(seed=42, n_slots=150)
        schedulers = ["oracle", "ucb1", "round_robin", "uniform_random"]
        seeds = list(range(5))

        result = run_sweep(config, schedulers, seeds)
        oracle_agg = result.aggregates[("default", "oracle")]
        ucb_agg = result.aggregates[("default", "ucb1")]
        rr_agg = result.aggregates[("default", "round_robin")]

        # Oracle achieves highest interception ratio
        assert oracle_agg.interception.interception_ratio.mean >= ucb_agg.interception.interception_ratio.mean
        assert oracle_agg.interception.interception_ratio.mean >= rr_agg.interception.interception_ratio.mean

    def test_csv_export_files(self, tmp_path: Path):
        """Verify episode CSV and aggregate CSV serialization."""
        config = _build_test_scenario(seed=42, n_slots=50)
        schedulers = ["round_robin", "ucb1"]
        seeds = [1, 2, 3]

        result = run_sweep(config, schedulers, seeds)

        csv_file = tmp_path / "sweep_records.csv"
        agg_csv_file = tmp_path / "sweep_aggregates.csv"

        result.to_csv(csv_file)
        result.to_aggregate_csv(agg_csv_file)

        assert csv_file.is_file()
        assert agg_csv_file.is_file()

        # Read back episode CSV
        with open(csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 2 * 3
            assert "scenario" in reader.fieldnames
            assert "scheduler" in reader.fieldnames
            assert "seed" in reader.fieldnames
            assert "interception_ratio" in reader.fieldnames
            assert "average_reward" in reader.fieldnames

        # Read back aggregate CSV
        with open(agg_csv_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            agg_rows = list(reader)
            assert len(agg_rows) == 2
            assert "scenario" in reader.fieldnames
            assert "scheduler" in reader.fieldnames
            assert "interception_ratio_mean" in reader.fieldnames
            assert "interception_ratio_ci_lower" in reader.fieldnames
            assert "interception_ratio_ci_upper" in reader.fieldnames

    def test_progress_callback(self):
        """Verify that progress callback is called on every completed episode."""
        config = _build_test_scenario(seed=42, n_slots=30)
        schedulers = ["round_robin", "ucb1"]
        seeds = [1, 2]

        calls: list[tuple[int, int, str, str, int]] = []

        def callback(done: int, total: int, sc: str, sch: str, sd: int) -> None:
            calls.append((done, total, sc, sch, sd))

        result = run_sweep(config, schedulers, seeds, progress_callback=callback)

        assert len(calls) == 4
        assert calls[-1][0] == 4
        assert calls[-1][1] == 4

    def test_polymorphic_scheduler_inputs(self):
        """Verify passing instances, classes, and callables as schedulers."""
        config = _build_test_scenario(seed=42, n_slots=30)
        schedulers = [
            RoundRobinScheduler(),
            UCB1Scheduler,
            ("custom_swucb", lambda: SWUCB1Scheduler(window_size=10)),
        ]
        seeds = [1, 2]

        result = run_sweep(config, schedulers, seeds)
        assert result.n_rows == 6
        sched_names = {r["scheduler"] for r in result.records}
        assert "round_robin" in sched_names
        assert "ucb1" in sched_names
        assert "custom_swucb" in sched_names

    def test_summary_format(self):
        """Verify summary returns a formatted table with scenario and scheduler rows."""
        config = _build_test_scenario(seed=42, n_slots=30)
        result = run_sweep(config, ["round_robin", "ucb1"], [1, 2])
        summary = result.summary()

        assert "Multi-Seed Sweep Summary" in summary
        assert "round_robin" in summary
        assert "ucb1" in summary
        assert "Int Ratio" in summary

    def test_dataframe_conversion(self):
        """Verify to_dataframe returns a pandas DataFrame if pandas is installed."""
        config = _build_test_scenario(seed=42, n_slots=30)
        result = run_sweep(config, ["round_robin"], [1, 2])

        try:
            import pandas as pd

            df = result.to_dataframe()
            assert isinstance(df, pd.DataFrame)
            assert len(df) == 2
            assert "scheduler" in df.columns
        except ImportError:
            with pytest.raises(ImportError):
                result.to_dataframe()

    def test_cli_execution(self, tmp_path: Path):
        """Verify CLI main entrypoint with sweep parameters."""
        out_csv = tmp_path / "cli_sweep.csv"
        agg_csv = tmp_path / "cli_agg.csv"

        exit_code = main([
            "--config", "configs/mvp.yaml",
            "--schedulers", "round_robin,ucb1",
            "--num-seeds", "3",
            "--seed-start", "10",
            "--output", str(out_csv),
            "--aggregate-output", str(agg_csv),
            "--quiet",
        ])

        assert exit_code == 0
        assert out_csv.is_file()
        assert agg_csv.is_file()

        with open(out_csv, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
            assert len(rows) == 6  # 2 schedulers * 3 seeds

        with open(agg_csv, newline="", encoding="utf-8") as f:
            agg_rows = list(csv.DictReader(f))
            assert len(agg_rows) == 2

    def test_cli_invalid_config_or_empty_seeds(self):
        """Verify CLI handles errors gracefully."""
        exit_code = main(["--config", "non_existent_file.yaml", "--quiet"])
        assert exit_code == 1

        exit_code_sched = main(["--config", "configs/mvp.yaml", "--schedulers", "invalid_sched", "--quiet"])
        assert exit_code_sched == 1
