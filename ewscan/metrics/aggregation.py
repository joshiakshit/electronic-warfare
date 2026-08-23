"""Multi-seed aggregation with confidence intervals -- Phase 1E.7.

Provides statistical aggregation, summary statistics (mean, std, SEM, median, min, max),
and Student's t-distribution confidence intervals across multi-seed runs and benchmark sweeps
for all seven figures of merit.

Verification Criterion (PLAN.md 1E.7):
  CI narrows as seed count rises.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np

from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EpisodeLog
from ewscan.metrics.detection import DetectionMetrics, estimate_detection_metrics
from ewscan.metrics.first_intercept import FirstInterceptMetrics, estimate_first_intercept_metrics
from ewscan.metrics.interception import InterceptionMetrics, estimate_interception_metrics
from ewscan.metrics.prediction import PredictionMetrics, estimate_prediction_metrics
from ewscan.metrics.reward import RewardMetrics, estimate_reward_metrics
from ewscan.metrics.time_error import TimeErrorMetrics, estimate_time_error_metrics


# ---------------------------------------------------------------------------
# High-precision Student's t and Normal Quantiles (pure Python/NumPy)
# ---------------------------------------------------------------------------

def _norm_ppf(p: float) -> float:
    """Standard normal percent point function (quantile / probit).

    Accurate to ~1e-15 using Acklam's rational approximation.
    """
    if p <= 0.0:
        return float("-inf")
    if p >= 1.0:
        return float("inf")
    if p == 0.5:
        return 0.0

    # Coefficients in rational approximations
    a = (
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    )
    b = (
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    )
    c = (
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    )
    d = (
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e00,
        3.754408661907416e00,
    )

    p_low = 0.02425
    p_high = 1.0 - p_low

    if p < p_low:
        q = math.sqrt(-2.0 * math.log(p))
        return (
            ((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]
        ) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)
    elif p <= p_high:
        q = p - 0.5
        r = q * q
        return (
            (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
        ) / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1.0)
    else:
        q = math.sqrt(-2.0 * math.log(1.0 - p))
        return -(
            ((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]
        ) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1.0)


def student_t_critical(confidence_level: float, df: int) -> float:
    """Compute the two-tailed Student's t critical value for a given confidence level.

    Parameters
    ----------
    confidence_level : float
        Confidence level, e.g. 0.95 for a 95% confidence interval.
    df : int
        Degrees of freedom (n - 1).

    Returns
    -------
    float
        Critical value t_{alpha/2, df}.
    """
    if df < 1:
        return float("nan")
    if not (0.0 < confidence_level < 1.0):
        raise ValueError(f"confidence_level must be in (0, 1), got {confidence_level}")

    p = 0.5 * (1.0 + confidence_level)

    # Exact closed forms for small df
    if df == 1:
        return float(math.tan(math.pi * (p - 0.5)))
    if df == 2:
        return float((2.0 * p - 1.0) / math.sqrt(2.0 * p * (1.0 - p)))

    # Try scipy if available for exact lookup
    try:
        from scipy.stats import t as sp_t

        return float(sp_t.ppf(p, df))
    except ImportError:
        pass

    # Cornish-Fisher asymptotic expansion from normal quantile
    z = _norm_ppf(p)
    z2 = z * z
    z3 = z2 * z
    z5 = z3 * z2
    z7 = z5 * z2

    t_val = (
        z
        + (z3 + z) / (4.0 * df)
        + (5.0 * z5 + 16.0 * z3 + 3.0 * z) / (96.0 * df * df)
        + (3.0 * z7 + 19.0 * z5 + 17.0 * z3 - 15.0 * z) / (384.0 * df * df * df)
    )
    return float(t_val)


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MetricStats:
    """Summary statistics and confidence interval for a scalar metric across seeds.

    Attributes
    ----------
    mean : float
        Sample mean of the metric, NaN if no valid samples.
    std : float
        Sample standard deviation (ddof=1), 0.0 if n_samples <= 1, NaN if n_samples == 0.
    sem : float
        Standard error of the mean (std / sqrt(n)), NaN if n_samples == 0.
    ci_lower : float
        Lower bound of the two-sided Student-t confidence interval.
    ci_upper : float
        Upper bound of the two-sided Student-t confidence interval.
    ci_width : float
        Total width of the confidence interval (ci_upper - ci_lower).
    confidence_level : float
        Confidence level used (e.g. 0.95).
    n_samples : int
        Number of valid (finite, non-NaN) samples aggregated.
    median : float
        Sample median, NaN if no valid samples.
    min : float
        Minimum observed value, NaN if no valid samples.
    max : float
        Maximum observed value, NaN if no valid samples.
    """

    mean: float
    std: float
    sem: float
    ci_lower: float
    ci_upper: float
    ci_width: float
    confidence_level: float
    n_samples: int
    median: float
    min: float
    max: float


@dataclass(frozen=True)
class AggregateDetectionMetrics:
    """Multi-seed summary for detection performance (Figure of Merit 1)."""

    pd: MetricStats
    pfa: MetricStats
    sensitivity: MetricStats


@dataclass(frozen=True)
class AggregateInterceptionMetrics:
    """Multi-seed summary for interception performance (Figure of Merit 2)."""

    interception_ratio: MetricStats
    intercept_rate: MetricStats


@dataclass(frozen=True)
class AggregateFirstInterceptMetrics:
    """Multi-seed summary for time to first intercept (Figure of Merit 3)."""

    mean_time_to_first_intercept: MetricStats
    intercept_fraction: MetricStats


@dataclass(frozen=True)
class AggregateRewardMetrics:
    """Multi-seed summary for reward accumulator & cost readout (Figure of Merit 4)."""

    total_reward: MetricStats
    average_reward: MetricStats
    total_hit_reward: MetricStats
    total_miss_cost: MetricStats
    total_novelty_bonus: MetricStats
    total_revisit_decay: MetricStats


@dataclass(frozen=True)
class AggregatePredictionMetrics:
    """Multi-seed summary for prediction accuracy (Figure of Merit 5)."""

    accuracy: MetricStats
    percentage_correct: MetricStats


@dataclass(frozen=True)
class AggregateTimeErrorMetrics:
    """Multi-seed summary for intercept time error (Figure of Merit 6)."""

    mean_time_error: MetricStats
    mean_time_error_penalized: MetricStats
    burst_interception_ratio: MetricStats


@dataclass(frozen=True)
class AggregateMetrics:
    """Top-level multi-seed benchmark summary covering all 7 figures of merit (1E.7).

    Attributes
    ----------
    n_episodes : int
        Total number of episode logs supplied.
    confidence_level : float
        Confidence level for interval estimates (e.g. 0.95).
    detection : AggregateDetectionMetrics
        Figure of Merit 1: Pd, Pfa, and Sensitivity.
    interception : AggregateInterceptionMetrics
        Figure of Merit 2: Interception Ratio and Intercept Rate.
    first_intercept : AggregateFirstInterceptMetrics
        Figure of Merit 3: Time to First Intercept.
    reward : AggregateRewardMetrics
        Figure of Merit 4: Average Reward and Cost components.
    prediction : AggregatePredictionMetrics
        Figure of Merit 5: Prediction Accuracy / % Correct.
    time_error : AggregateTimeErrorMetrics
        Figure of Merit 6: Average Intercept Time Error.
    """

    n_episodes: int
    confidence_level: float
    detection: AggregateDetectionMetrics
    interception: AggregateInterceptionMetrics
    first_intercept: AggregateFirstInterceptMetrics
    reward: AggregateRewardMetrics
    prediction: AggregatePredictionMetrics
    time_error: AggregateTimeErrorMetrics

    def to_dict(self, prefix: str = "") -> dict[str, Any]:
        """Flatten into a key-value dictionary suitable for CSV export and dataframes."""
        out: dict[str, Any] = {
            f"{prefix}n_episodes": self.n_episodes,
            f"{prefix}confidence_level": self.confidence_level,
        }

        def _add_stat(stat_name: str, s: MetricStats) -> None:
            out[f"{prefix}{stat_name}_mean"] = s.mean
            out[f"{prefix}{stat_name}_std"] = s.std
            out[f"{prefix}{stat_name}_sem"] = s.sem
            out[f"{prefix}{stat_name}_ci_lower"] = s.ci_lower
            out[f"{prefix}{stat_name}_ci_upper"] = s.ci_upper
            out[f"{prefix}{stat_name}_ci_width"] = s.ci_width
            out[f"{prefix}{stat_name}_median"] = s.median
            out[f"{prefix}{stat_name}_min"] = s.min
            out[f"{prefix}{stat_name}_max"] = s.max
            out[f"{prefix}{stat_name}_n"] = s.n_samples

        _add_stat("pd", self.detection.pd)
        _add_stat("pfa", self.detection.pfa)
        _add_stat("sensitivity", self.detection.sensitivity)
        _add_stat("interception_ratio", self.interception.interception_ratio)
        _add_stat("intercept_rate", self.interception.intercept_rate)
        _add_stat("ttfi", self.first_intercept.mean_time_to_first_intercept)
        _add_stat("intercept_fraction", self.first_intercept.intercept_fraction)
        _add_stat("average_reward", self.reward.average_reward)
        _add_stat("total_reward", self.reward.total_reward)
        _add_stat("hit_reward", self.reward.total_hit_reward)
        _add_stat("miss_cost", self.reward.total_miss_cost)
        _add_stat("novelty_bonus", self.reward.total_novelty_bonus)
        _add_stat("revisit_decay", self.reward.total_revisit_decay)
        _add_stat("prediction_accuracy", self.prediction.accuracy)
        _add_stat("prediction_pct_correct", self.prediction.percentage_correct)
        _add_stat("time_error", self.time_error.mean_time_error)
        _add_stat("time_error_penalized", self.time_error.mean_time_error_penalized)
        _add_stat("burst_interception_ratio", self.time_error.burst_interception_ratio)

        return out


# ---------------------------------------------------------------------------
# Core computation functions
# ---------------------------------------------------------------------------

def compute_metric_stats(
    values: Sequence[float | None],
    confidence_level: float = 0.95,
) -> MetricStats:
    """Compute summary statistics and Student's t confidence interval for a sequence of values.

    Parameters
    ----------
    values : Sequence[float | None]
        Collection of scalar samples (e.g. from multi-seed runs). NaNs and Nones are filtered out.
    confidence_level : float, default 0.95
        Confidence level for the two-sided interval in (0, 1).

    Returns
    -------
    MetricStats
        Calculated statistics and CI.
    """
    if not (0.0 < confidence_level < 1.0):
        raise ValueError(f"confidence_level must be in (0, 1), got {confidence_level}")

    valid: list[float] = [
        float(v) for v in values if v is not None and not math.isnan(float(v))
    ]
    n = len(valid)

    if n == 0:
        return MetricStats(
            mean=float("nan"),
            std=float("nan"),
            sem=float("nan"),
            ci_lower=float("nan"),
            ci_upper=float("nan"),
            ci_width=float("nan"),
            confidence_level=confidence_level,
            n_samples=0,
            median=float("nan"),
            min=float("nan"),
            max=float("nan"),
        )

    arr = np.array(valid, dtype=np.float64)
    mean_val = float(np.mean(arr))
    median_val = float(np.median(arr))
    min_val = float(np.min(arr))
    max_val = float(np.max(arr))

    if n == 1:
        return MetricStats(
            mean=mean_val,
            std=0.0,
            sem=0.0,
            ci_lower=mean_val,
            ci_upper=mean_val,
            ci_width=0.0,
            confidence_level=confidence_level,
            n_samples=1,
            median=median_val,
            min=min_val,
            max=max_val,
        )

    std_val = float(np.std(arr, ddof=1))
    sem_val = float(std_val / math.sqrt(n))

    if std_val == 0.0 or sem_val == 0.0:
        ci_lower = mean_val
        ci_upper = mean_val
        ci_width = 0.0
    else:
        t_crit = student_t_critical(confidence_level, df=n - 1)
        margin = t_crit * sem_val
        ci_lower = mean_val - margin
        ci_upper = mean_val + margin
        ci_width = ci_upper - ci_lower

    return MetricStats(
        mean=mean_val,
        std=std_val,
        sem=sem_val,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        ci_width=ci_width,
        confidence_level=confidence_level,
        n_samples=n,
        median=median_val,
        min=min_val,
        max=max_val,
    )


def aggregate_metric_records(
    detection_list: Sequence[DetectionMetrics] = (),
    interception_list: Sequence[InterceptionMetrics] = (),
    first_intercept_list: Sequence[FirstInterceptMetrics] = (),
    reward_list: Sequence[RewardMetrics] = (),
    prediction_list: Sequence[PredictionMetrics] = (),
    time_error_list: Sequence[TimeErrorMetrics] = (),
    confidence_level: float = 0.95,
) -> AggregateMetrics:
    """Aggregate pre-computed metric record objects across episodes.

    Parameters
    ----------
    detection_list : Sequence[DetectionMetrics]
    interception_list : Sequence[InterceptionMetrics]
    first_intercept_list : Sequence[FirstInterceptMetrics]
    reward_list : Sequence[RewardMetrics]
    prediction_list : Sequence[PredictionMetrics]
    time_error_list : Sequence[TimeErrorMetrics]
    confidence_level : float, default 0.95

    Returns
    -------
    AggregateMetrics
    """
    n_episodes = max(
        len(detection_list),
        len(interception_list),
        len(first_intercept_list),
        len(reward_list),
        len(prediction_list),
        len(time_error_list),
        0,
    )

    # Detection metrics
    pds = [d.pd.pd for d in detection_list]
    pfas = [d.pfa.pfa for d in detection_list]
    sensitivities = [d.sensitivity.min_detectable_snr for d in detection_list]

    agg_det = AggregateDetectionMetrics(
        pd=compute_metric_stats(pds, confidence_level),
        pfa=compute_metric_stats(pfas, confidence_level),
        sensitivity=compute_metric_stats(sensitivities, confidence_level),
    )

    # Interception metrics
    ratios = [i.interception_ratio.ratio for i in interception_list]
    rates = [i.intercept_rate.rate for i in interception_list]

    agg_int = AggregateInterceptionMetrics(
        interception_ratio=compute_metric_stats(ratios, confidence_level),
        intercept_rate=compute_metric_stats(rates, confidence_level),
    )

    # First intercept metrics
    ttfis = [f.mean_time_to_first_intercept for f in first_intercept_list]
    intercept_fractions = [
        (f.n_intercepted / f.n_emitters) if f.n_emitters > 0 else float("nan")
        for f in first_intercept_list
    ]

    agg_fi = AggregateFirstInterceptMetrics(
        mean_time_to_first_intercept=compute_metric_stats(ttfis, confidence_level),
        intercept_fraction=compute_metric_stats(intercept_fractions, confidence_level),
    )

    # Reward metrics
    tot_rewards = [r.total_reward for r in reward_list]
    avg_rewards = [r.average_reward for r in reward_list]
    hit_rewards = [r.total_hit_reward for r in reward_list]
    miss_costs = [r.total_miss_cost for r in reward_list]
    novelty_bonuses = [r.total_novelty_bonus for r in reward_list]
    revisit_decays = [r.total_revisit_decay for r in reward_list]

    agg_rew = AggregateRewardMetrics(
        total_reward=compute_metric_stats(tot_rewards, confidence_level),
        average_reward=compute_metric_stats(avg_rewards, confidence_level),
        total_hit_reward=compute_metric_stats(hit_rewards, confidence_level),
        total_miss_cost=compute_metric_stats(miss_costs, confidence_level),
        total_novelty_bonus=compute_metric_stats(novelty_bonuses, confidence_level),
        total_revisit_decay=compute_metric_stats(revisit_decays, confidence_level),
    )

    # Prediction metrics
    accuracies = [p.accuracy for p in prediction_list]
    pct_corrects = [p.percentage_correct for p in prediction_list]

    agg_pred = AggregatePredictionMetrics(
        accuracy=compute_metric_stats(accuracies, confidence_level),
        percentage_correct=compute_metric_stats(pct_corrects, confidence_level),
    )

    # Time error metrics
    time_errors = [t.mean_time_error for t in time_error_list]
    penalized_time_errors = [t.mean_time_error_penalized for t in time_error_list]
    burst_ratios = [t.burst_interception_ratio for t in time_error_list]

    agg_te = AggregateTimeErrorMetrics(
        mean_time_error=compute_metric_stats(time_errors, confidence_level),
        mean_time_error_penalized=compute_metric_stats(penalized_time_errors, confidence_level),
        burst_interception_ratio=compute_metric_stats(burst_ratios, confidence_level),
    )

    return AggregateMetrics(
        n_episodes=n_episodes,
        confidence_level=confidence_level,
        detection=agg_det,
        interception=agg_int,
        first_intercept=agg_fi,
        reward=agg_rew,
        prediction=agg_pred,
        time_error=agg_te,
    )


def aggregate_episodes(
    logs: Sequence[EpisodeLog],
    confidence_level: float = 0.95,
    pd_threshold: float = 0.5,
    rf: RewardFunction | None = None,
    miss_penalty: float | None = None,
) -> AggregateMetrics:
    """Compute and aggregate all seven figures of merit from a collection of EpisodeLogs.

    Parameters
    ----------
    logs : Sequence[EpisodeLog]
        Collection of episode logs from multi-seed runs.
    confidence_level : float, default 0.95
        Confidence level for interval estimates (0 < c < 1).
    pd_threshold : float, default 0.5
        Threshold for sensitivity estimation.
    rf : RewardFunction | None, optional
        Reward function instance for reward metrics.
    miss_penalty : float | None, optional
        Penalty for missed bursts in time error calculation.

    Returns
    -------
    AggregateMetrics
        Aggregated results across all episodes with means, stds, and confidence intervals.
    """
    detection_list: list[DetectionMetrics] = []
    interception_list: list[InterceptionMetrics] = []
    first_intercept_list: list[FirstInterceptMetrics] = []
    reward_list: list[RewardMetrics] = []
    prediction_list: list[PredictionMetrics] = []
    time_error_list: list[TimeErrorMetrics] = []

    for log in logs:
        detection_list.append(estimate_detection_metrics(log, pd_threshold=pd_threshold))
        interception_list.append(estimate_interception_metrics(log))
        first_intercept_list.append(estimate_first_intercept_metrics(log))
        reward_list.append(estimate_reward_metrics(log, rf=rf))
        prediction_list.append(estimate_prediction_metrics(log))
        time_error_list.append(estimate_time_error_metrics(log, miss_penalty=miss_penalty))

    return aggregate_metric_records(
        detection_list=detection_list,
        interception_list=interception_list,
        first_intercept_list=first_intercept_list,
        reward_list=reward_list,
        prediction_list=prediction_list,
        time_error_list=time_error_list,
        confidence_level=confidence_level,
    )
