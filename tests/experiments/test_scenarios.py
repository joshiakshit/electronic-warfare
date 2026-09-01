"""Tests for Scenario Library (Experiment harness Task 3 -- Phase 1E.8).

Verifications:
- Three canned demo scenarios: sparse_bursty, mixed_threat, periodic_radar.
- Registry discovery, alias resolution, and metadata lookup.
- Parity between Python scenario builders and YAML files in configs/.
- Verification Criterion (PLAN.md Task 3): Each separates a learner from round-robin by a visible margin.
- Determinism across seeds and scenario executions.
- Integration with EpisodeRunner, SweepRunner, and CLI entrypoints.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from ewscan.agents.ucb import UCB1Scheduler
from ewscan.config import load_config
from ewscan.contracts import EpisodeConfig
from ewscan.experiments.runner import main as runner_main, run_episode
from ewscan.experiments.scenarios import (
    canonical_scenario_name,
    get_all_scenarios,
    get_scenario,
    get_scenario_metadata,
    list_scenarios,
    make_contested_spectrum_scenario,
    make_mixed_threat_scenario,
    make_periodic_radar_scenario,
    make_sparse_bursty_scenario,
)
from ewscan.experiments.sweep import main as sweep_main, run_sweep


class TestScenarioBuilders:
    """Unit tests for individual scenario factory functions."""

    def test_make_sparse_bursty_scenario(self):
        """Verify sparse_bursty scenario structure and emitter definitions."""
        config = make_sparse_bursty_scenario(seed=42)
        assert isinstance(config, EpisodeConfig)
        assert config.n_bands == 16
        assert config.n_slots == 2000
        assert config.k == 1
        assert config.seed == 42
        assert len(config.emitters) == 3

        bands = [em.band for em in config.emitters]
        assert bands == [3, 7, 12]
        for em in config.emitters:
            assert em.emitter_type == "gilbert_elliott"
            assert "p01" in em.params and "p10" in em.params
            assert 0.0 < em.threat_level <= 1.0
            assert em.snr > 0.0

    def test_make_mixed_threat_scenario(self):
        """Verify mixed_threat scenario structure and emitter types."""
        config = make_mixed_threat_scenario(seed=42)
        assert isinstance(config, EpisodeConfig)
        assert config.n_bands == 16
        assert config.n_slots == 2000
        assert config.k == 1
        assert len(config.emitters) == 4

        bands = [em.band for em in config.emitters]
        assert bands == [1, 4, 9, 14]

        # Check CW emitter
        cw_em = next(em for em in config.emitters if em.band == 1)
        assert cw_em.emitter_type == "cw"
        assert cw_em.threat_level == 0.2

        # Check Periodic emitter
        per_em = next(em for em in config.emitters if em.band == 4)
        assert per_em.emitter_type == "periodic"
        assert per_em.params["period"] == 40
        assert per_em.threat_level == 0.8

        # Check High Threat Rare emitter
        rare_em = next(em for em in config.emitters if em.band == 14)
        assert rare_em.emitter_type == "gilbert_elliott"
        assert rare_em.threat_level == 1.0

    def test_make_periodic_radar_scenario(self):
        """Verify periodic_radar scenario structure and radar pulse parameters."""
        config = make_periodic_radar_scenario(seed=42)
        assert isinstance(config, EpisodeConfig)
        assert config.n_bands == 16
        assert config.n_slots == 2000
        assert config.k == 1
        assert len(config.emitters) == 3

        bands = [em.band for em in config.emitters]
        assert bands == [2, 8, 13]
        for em in config.emitters:
            assert em.emitter_type == "periodic"
            assert "period" in em.params
            assert "dwell" in em.params
            assert "jitter" in em.params
            assert "phase" in em.params

    def test_make_contested_spectrum_scenario(self):
        config = make_contested_spectrum_scenario(seed=42)

        assert config.n_bands == 16
        assert config.n_slots == 2000
        assert config.k == 1
        assert {em.emitter_type for em in config.emitters} == {
            "beam",
            "frequency_hop",
            "periodic",
            "gilbert_elliott",
        }

        hopper = next(em for em in config.emitters if em.emitter_type == "frequency_hop")
        assert len(hopper.params["hop_bands"]) >= 4

        beam = next(em for em in config.emitters if em.emitter_type == "beam")
        assert beam.params["omega"] > 0
        assert beam.params["beamwidth"] > 0

    def test_parameter_overrides(self):
        """Verify keyword argument overrides in scenario builders."""
        config = make_sparse_bursty_scenario(n_bands=16, n_slots=500, seed=123)
        assert config.n_slots == 500
        assert config.seed == 123


class TestScenarioRegistry:
    """Unit tests for registry discovery, lookup, and alias resolution."""

    def test_list_scenarios(self):
        """Verify all three canonical scenario names are returned."""
        names = list_scenarios()
        assert set(names) == {
            "sparse_bursty",
            "mixed_threat",
            "periodic_radar",
            "contested_spectrum",
        }

    def test_canonical_name_resolution(self):
        """Verify resolution of aliases and case-insensitive strings."""
        assert canonical_scenario_name("sparse_bursty") == "sparse_bursty"
        assert canonical_scenario_name("Sparse_Bursty") == "sparse_bursty"
        assert canonical_scenario_name("sparse-bursty") == "sparse_bursty"
        assert canonical_scenario_name("sparse") == "sparse_bursty"
        assert canonical_scenario_name("sparse_and_bursty") == "sparse_bursty"
        assert canonical_scenario_name("bursty") == "sparse_bursty"

        assert canonical_scenario_name("mixed_threat") == "mixed_threat"
        assert canonical_scenario_name("mixed") == "mixed_threat"
        assert canonical_scenario_name("mixed-high-threat") == "mixed_threat"

        assert canonical_scenario_name("periodic_radar") == "periodic_radar"
        assert canonical_scenario_name("radar") == "periodic_radar"
        assert canonical_scenario_name("periodic") == "periodic_radar"
        assert canonical_scenario_name("contested") == "contested_spectrum"

    def test_canonical_name_invalid_raises(self):
        """Verify unknown scenario names raise ValueError."""
        with pytest.raises(ValueError, match="Unknown scenario 'invalid_name'"):
            canonical_scenario_name("invalid_name")

    def test_get_scenario_lookup(self):
        """Verify get_scenario returns expected EpisodeConfig."""
        for name in list_scenarios():
            config = get_scenario(name, seed=99)
            assert isinstance(config, EpisodeConfig)
            assert config.seed == 99

    def test_get_all_scenarios(self):
        """Verify get_all_scenarios returns all three configured scenarios."""
        all_scens = get_all_scenarios(n_slots=100)
        assert set(all_scens.keys()) == {
            "sparse_bursty",
            "mixed_threat",
            "periodic_radar",
            "contested_spectrum",
        }
        for cfg in all_scens.values():
            assert cfg.n_slots == 100

    def test_scenario_metadata(self):
        """Verify metadata fields for each scenario."""
        for name in list_scenarios():
            meta = get_scenario_metadata(name)
            assert meta.name == name
            assert len(meta.title) > 0
            assert len(meta.description) > 0
            assert len(meta.tactical_rationale) > 0
            assert len(meta.active_bands) > 0
            assert len(meta.emitter_types) == len(meta.active_bands)


class TestYAMLConfigurationParity:
    """Verify that YAML config files in configs/ exactly match the Python scenario builders."""

    @pytest.mark.parametrize(
        ("scenario_name", "yaml_filename", "factory_fn"),
        [
            ("sparse_bursty", "sparse_bursty.yaml", make_sparse_bursty_scenario),
            ("mixed_threat", "mixed_threat.yaml", make_mixed_threat_scenario),
            ("periodic_radar", "periodic_radar.yaml", make_periodic_radar_scenario),
            (
                "contested_spectrum",
                "contested_spectrum.yaml",
                make_contested_spectrum_scenario,
            ),
        ],
    )
    def test_yaml_matches_python_factory(self, scenario_name, yaml_filename, factory_fn):
        """Verify YAML content deserializes identically to Python factory output."""
        yaml_path = Path("configs") / yaml_filename
        assert yaml_path.is_file(), f"Missing YAML file: {yaml_path}"

        yaml_config = load_config(yaml_path)
        py_config = factory_fn()

        assert yaml_config.n_bands == py_config.n_bands
        assert yaml_config.n_slots == py_config.n_slots
        assert yaml_config.k == py_config.k
        assert yaml_config.detection_threshold == py_config.detection_threshold
        assert yaml_config.pfa == py_config.pfa
        assert yaml_config.seed == py_config.seed
        assert len(yaml_config.emitters) == len(py_config.emitters)

        for y_em, p_em in zip(yaml_config.emitters, py_config.emitters):
            assert y_em.band == p_em.band
            assert y_em.snr == pytest.approx(p_em.snr)
            assert y_em.threat_level == pytest.approx(p_em.threat_level)
            assert y_em.emitter_type == p_em.emitter_type
            assert y_em.params == p_em.params


class TestLearnerSeparationCriterion:
    """Verify PLAN.md Task 3 Criterion:

    Each scenario separates a learner from round-robin by a visible margin.
    """

    def test_sparse_bursty_separation(self):
        """Verify learners achieve significant interception ratio gain on sparse_bursty."""
        config = make_sparse_bursty_scenario(seed=42, n_slots=2000)
        schedulers = ["oracle", "ucb1", "thompson_sampling", "round_robin", "uniform_random"]
        seeds = list(range(5))

        sweep_res = run_sweep(config, schedulers, seeds)
        oracle_ir = sweep_res.aggregates[("default", "oracle")].interception.interception_ratio.mean
        ucb1_ir = sweep_res.aggregates[("default", "ucb1")].interception.interception_ratio.mean
        ts_ir = sweep_res.aggregates[("default", "thompson_sampling")].interception.interception_ratio.mean
        rr_ir = sweep_res.aggregates[("default", "round_robin")].interception.interception_ratio.mean
        rand_ir = sweep_res.aggregates[("default", "uniform_random")].interception.interception_ratio.mean

        # Verification checks:
        # 1. Round-robin and uniform random dwell at ~ 1/16 (0.05-0.07)
        assert rr_ir < 0.08
        assert rand_ir < 0.08

        # 2. Both learners achieve at least 3x higher interception ratio than round-robin
        assert ucb1_ir >= 3.0 * rr_ir
        assert ts_ir >= 3.0 * rr_ir

        # 3. Oracle achieves highest interception
        assert oracle_ir > ucb1_ir
        assert oracle_ir > ts_ir

    def test_mixed_threat_separation(self):
        """Verify learners achieve substantial interception gain on mixed_threat."""
        config = make_mixed_threat_scenario(seed=42, n_slots=2000)
        schedulers = ["oracle", "thompson_sampling", "ucb1", "round_robin", "uniform_random"]
        seeds = list(range(5))

        sweep_res = run_sweep(config, schedulers, seeds)
        oracle_ir = sweep_res.aggregates[("default", "oracle")].interception.interception_ratio.mean
        ts_ir = sweep_res.aggregates[("default", "thompson_sampling")].interception.interception_ratio.mean
        ucb1_ir = sweep_res.aggregates[("default", "ucb1")].interception.interception_ratio.mean
        rr_ir = sweep_res.aggregates[("default", "round_robin")].interception.interception_ratio.mean

        assert rr_ir < 0.08
        # Learners achieve > 5x higher interception ratio
        assert ts_ir >= 5.0 * rr_ir
        assert ucb1_ir >= 5.0 * rr_ir
        assert oracle_ir >= 5.0 * rr_ir

    def test_periodic_radar_separation(self):
        """Verify learners achieve visible interception gain on periodic_radar."""
        config = make_periodic_radar_scenario(seed=42, n_slots=2000)
        schedulers = ["oracle", "thompson_sampling", "ucb1", "round_robin"]
        seeds = list(range(5))

        sweep_res = run_sweep(config, schedulers, seeds)
        oracle_ir = sweep_res.aggregates[("default", "oracle")].interception.interception_ratio.mean
        ts_ir = sweep_res.aggregates[("default", "thompson_sampling")].interception.interception_ratio.mean
        ucb1_ir = sweep_res.aggregates[("default", "ucb1")].interception.interception_ratio.mean
        rr_ir = sweep_res.aggregates[("default", "round_robin")].interception.interception_ratio.mean

        assert rr_ir < 0.08
        # Learners achieve at least 2x higher interception ratio
        assert ts_ir >= 2.0 * rr_ir
        assert ucb1_ir >= 2.0 * rr_ir
        assert oracle_ir >= 5.0 * rr_ir

    def test_determinism_across_scenarios(self):
        """Verify exact determinism when running episodes with identical seeds."""
        for name in list_scenarios():
            config = get_scenario(name, seed=42, n_slots=100)
            res1 = run_episode(config, UCB1Scheduler(seed=42), seed=42)
            res2 = run_episode(config, UCB1Scheduler(seed=42), seed=42)

            assert np.array_equal(res1.log.truth, res2.log.truth)
            assert np.array_equal(res1.log.actions, res2.log.actions)
            assert np.array_equal(res1.log.detections, res2.log.detections)
            assert res1.interception.interception_ratio.ratio == res2.interception.interception_ratio.ratio


class TestSweepAndRunnerIntegration:
    """Verify integration of scenarios with runner, sweep, and CLI entrypoints."""

    def test_sweep_with_scenario_names(self):
        """Verify SweepRunner accepts scenario name strings directly."""
        result = run_sweep(
            scenarios=["sparse_bursty", "mixed_threat", "periodic_radar"],
            schedulers=["round_robin", "ucb1"],
            seeds=[1, 2],
        )
        assert result.n_rows == 3 * 2 * 2  # 3 scenarios * 2 schedulers * 2 seeds = 12
        assert len(result.aggregates) == 6

    def test_sweep_with_all_keyword(self):
        """Verify SweepRunner accepts scenarios='all'."""
        result = run_sweep(
            scenarios="all",
            schedulers=["round_robin"],
            seeds=[1],
        )
        assert result.n_rows == 4

    def test_runner_cli_with_scenario_name(self):
        """Verify runner CLI accepts scenario name string."""
        exit_code = runner_main(["--config", "sparse_bursty", "--scheduler", "round_robin"])
        assert exit_code == 0

    def test_sweep_cli_with_scenario_names(self, tmp_path: Path):
        """Verify sweep CLI accepts multiple scenario names and exports CSV."""
        out_csv = tmp_path / "canned_sweep.csv"
        exit_code = sweep_main([
            "--config", "sparse_bursty",
            "--config", "mixed_threat",
            "--config", "periodic_radar",
            "--schedulers", "round_robin,ucb1",
            "--num-seeds", "2",
            "--output", str(out_csv),
            "--quiet",
        ])
        assert exit_code == 0
        assert out_csv.is_file()
