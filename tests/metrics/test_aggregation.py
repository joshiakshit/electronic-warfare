"""Tests for multi-seed aggregation with confidence intervals -- Phase 1E.7.

Verification Criterion (PLAN.md 1E.7):
    CI narrows as seed count rises.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from ewscan.agents.baselines import RoundRobinScheduler, UniformRandomScheduler
from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.aggregation import (
    AggregateMetrics,
    MetricStats,
    aggregate_episodes,
    aggregate_metric_records,
    compute_metric_stats,
    student_t_critical,
)
from ewscan.testing.fixtures import ScriptedEnv, make_test_config, synthetic_log


# =========================================================================
# 1. Student's t and Quantile Verification
# =========================================================================

class TestStudentTCritical:
    """Verify accuracy of critical value calculation."""

    def test_known_critical_values_95pct(self):
        """Check known Student-t two-tailed critical values for 95% CI (alpha=0.05)."""
        # Exact values from standard statistical tables:
        # df=1: 12.7062
        # df=2: 4.3027
        # df=10: 2.2281
        # df=30: 2.0423
        # df=100: 1.9840
        # df=inf (normal): 1.95996
        assert student_t_critical(0.95, df=1) == pytest.approx(12.7062, rel=1e-3)
        assert student_t_critical(0.95, df=2) == pytest.approx(4.3027, rel=1e-3)
        assert student_t_critical(0.95, df=10) == pytest.approx(2.2281, rel=1e-3)
        assert student_t_critical(0.95, df=30) == pytest.approx(2.0423, rel=1e-3)
        assert student_t_critical(0.95, df=100) == pytest.approx(1.9840, rel=1e-3)

    def test_different_confidence_levels(self):
        """Check critical values for 90% and 99% confidence levels."""
        # df=10, 90% (alpha=0.10): t ≈ 1.8125
        # df=10, 99% (alpha=0.01): t ≈ 3.1693
        assert student_t_critical(0.90, df=10) == pytest.approx(1.8125, rel=1e-3)
        assert student_t_critical(0.99, df=10) == pytest.approx(3.1693, rel=1e-3)

    def test_invalid_arguments(self):
        with pytest.raises(ValueError):
            student_t_critical(0.0, df=5)
        with pytest.raises(ValueError):
            student_t_critical(1.0, df=5)
        assert math.isnan(student_t_critical(0.95, df=0))


# =========================================================================
# 2. Verification Criterion: CI Narrows As Seed Count Rises
# =========================================================================

class TestCINarrowsAsSeedCountRises:
    """Primary verification requirement from PLAN.md 1E.7:
    'CI narrows as seed count rises'
    """

    def test_ci_width_decreases_with_sample_size(self):
        """As sample count rises from N=5 to N=30 to N=100 from an i.i.d. source,
        the confidence interval width strictly narrows."""
        rng = np.random.default_rng(12345)
        # Fixed underlying distribution N(mu=10, sigma=2)
        population = rng.normal(loc=10.0, scale=2.0, size=200)

        samples_5 = population[:5]
        samples_15 = population[:15]
        samples_30 = population[:30]
        samples_100 = population[:100]

        stats_5 = compute_metric_stats(samples_5, confidence_level=0.95)
        stats_15 = compute_metric_stats(samples_15, confidence_level=0.95)
        stats_30 = compute_metric_stats(samples_30, confidence_level=0.95)
        stats_100 = compute_metric_stats(samples_100, confidence_level=0.95)

        # Standard errors must decrease
        assert stats_5.sem > stats_15.sem > stats_30.sem > stats_100.sem

        # Confidence interval widths must strictly narrow
        assert stats_5.ci_width > stats_15.ci_width > stats_30.ci_width > stats_100.ci_width

        # Theoretical rate check: CI width for N=100 should be roughly 1/sqrt(20) ~ 0.22 of N=5
        assert stats_100.ci_width < 0.4 * stats_5.ci_width


# =========================================================================
# 3. Scalar Stats Calculation & Edge Cases
# =========================================================================

class TestMetricStatsComputation:
    """Detailed validation of compute_metric_stats."""

    def test_known_hand_computed_sample(self):
        # Sample: [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] (N=8)
        # Mean = 40 / 8 = 5.0
        # Variance (ddof=1) = 4.5714 -> std = 2.1381
        # SEM = 2.1381 / sqrt(8) = 0.7559
        # df=7, 95% t_crit ≈ 2.3646
        # Margin = 2.3646 * 0.7559 ≈ 1.7875
        # CI = [5.0 - 1.7875, 5.0 + 1.7875] = [3.2125, 6.7875]
        data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
        stats = compute_metric_stats(data, confidence_level=0.95)

        assert stats.n_samples == 8
        assert stats.mean == pytest.approx(5.0)
        assert stats.std == pytest.approx(np.std(data, ddof=1))
        assert stats.sem == pytest.approx(stats.std / math.sqrt(8))
        assert stats.median == pytest.approx(4.5)
        assert stats.min == 2.0
        assert stats.max == 9.0
        assert stats.ci_lower == pytest.approx(5.0 - stats.ci_width / 2)
        assert stats.ci_upper == pytest.approx(5.0 + stats.ci_width / 2)

    def test_empty_and_nan_handling(self):
        """Empty input or all-NaN input returns NaN stats."""
        stats_empty = compute_metric_stats([])
        assert stats_empty.n_samples == 0
        assert math.isnan(stats_empty.mean)
        assert math.isnan(stats_empty.std)
        assert math.isnan(stats_empty.ci_lower)

        stats_nans = compute_metric_stats([float("nan"), None, float("nan")])
        assert stats_nans.n_samples == 0
        assert math.isnan(stats_nans.mean)

    def test_single_sample_n1(self):
        """Sample size N=1 returns mean with std=0, sem=0, and CI=[val, val]."""
        stats = compute_metric_stats([42.0])
        assert stats.n_samples == 1
        assert stats.mean == 42.0
        assert stats.std == 0.0
        assert stats.sem == 0.0
        assert stats.ci_lower == 42.0
        assert stats.ci_upper == 42.0
        assert stats.ci_width == 0.0

    def test_zero_variance_identical_samples(self):
        """Multiple identical samples (std=0) give CI width 0."""
        stats = compute_metric_stats([5.0, 5.0, 5.0, 5.0, 5.0])
        assert stats.n_samples == 5
        assert stats.mean == 5.0
        assert stats.std == 0.0
        assert stats.sem == 0.0
        assert stats.ci_lower == 5.0
        assert stats.ci_upper == 5.0
        assert stats.ci_width == 0.0

    def test_filters_embedded_nans(self):
        """NaN values inside a sequence are filtered out without corrupting valid stats."""
        data = [10.0, float("nan"), 20.0, None, 30.0]
        stats = compute_metric_stats(data)
        assert stats.n_samples == 3
        assert stats.mean == pytest.approx(20.0)


# =========================================================================
# 4. Multi-Seed Episode Aggregation & All 7 Figures of Merit
# =========================================================================

class TestMultiSeedEpisodeAggregation:
    """Test full multi-seed aggregation over all 7 figures of merit."""

    @pytest.fixture
    def multi_seed_logs(self) -> list[EpisodeLog]:
        """Generate 5 episode logs across different seeds with UniformRandomScheduler."""
        logs = []
        n_bands = 4
        n_slots = 50

        truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
        truth[0, :] = True       # CW
        truth[1, 10:30] = True   # Bursty
        truth[2, ::4] = True     # Periodic

        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=15.0, threat_level=0.8, emitter_type="bursty"),
            EmitterInfo(band=2, snr=10.0, threat_level=0.5, emitter_type="periodic"),
        )

        for s in range(5):
            config = make_test_config(n_bands=n_bands, n_slots=n_slots, emitters=emitters, seed=s)
            sched = UniformRandomScheduler(seed=s)
            env = ScriptedEnv(config, truth)
            log = env.run(sched)
            logs.append(log)

        return logs

    def test_aggregate_episodes_all_seven_metrics(self, multi_seed_logs):
        agg = aggregate_episodes(multi_seed_logs, confidence_level=0.95)

        assert isinstance(agg, AggregateMetrics)
        assert agg.n_episodes == 5
        assert agg.confidence_level == 0.95

        # 1. Detection metrics
        assert agg.detection.pd.n_samples == 5
        assert 0.0 <= agg.detection.pd.mean <= 1.0
        assert agg.detection.pfa.n_samples == 5
        assert math.isfinite(agg.detection.sensitivity.mean)

        # 2. Interception metrics
        assert agg.interception.interception_ratio.n_samples == 5
        assert 0.0 <= agg.interception.interception_ratio.mean <= 1.0
        assert agg.interception.intercept_rate.n_samples == 5

        # 3. First intercept metrics
        assert agg.first_intercept.mean_time_to_first_intercept.n_samples == 5
        assert agg.first_intercept.intercept_fraction.mean == 1.0  # all emitters intercepted

        # 4. Reward metrics
        assert agg.reward.average_reward.n_samples == 5
        assert agg.reward.total_reward.n_samples == 5

        # 5. Prediction metrics (stub in MVP)
        assert agg.prediction.accuracy.n_samples == 0  # no predictor active

        # 6. Time error metrics
        assert agg.time_error.mean_time_error.n_samples == 5
        assert agg.time_error.mean_time_error.mean > 0.0
        assert agg.time_error.burst_interception_ratio.n_samples == 5

    def test_to_dict_export(self, multi_seed_logs):
        """to_dict produces flat key-value pairs suitable for CSV and DataFrame."""
        agg = aggregate_episodes(multi_seed_logs, confidence_level=0.95)
        d = agg.to_dict(prefix="exp_")

        assert d["exp_n_episodes"] == 5
        assert d["exp_confidence_level"] == 0.95
        assert "exp_pd_mean" in d
        assert "exp_pd_ci_lower" in d
        assert "exp_pd_ci_upper" in d
        assert "exp_interception_ratio_mean" in d
        assert "exp_ttfi_mean" in d
        assert "exp_average_reward_mean" in d
        assert "exp_time_error_mean" in d
        assert "exp_burst_interception_ratio_mean" in d
