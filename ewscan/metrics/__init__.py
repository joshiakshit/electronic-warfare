"""Metrics modules for ewscan -- the seven figures of merit."""

from ewscan.metrics.aggregation import (
    AggregateDetectionMetrics,
    AggregateFirstInterceptMetrics,
    AggregateInterceptionMetrics,
    AggregateMetrics,
    AggregatePredictionMetrics,
    AggregateRewardMetrics,
    AggregateTimeErrorMetrics,
    MetricStats,
    aggregate_episodes,
    aggregate_metric_records,
    compute_metric_stats,
    student_t_critical,
)
from ewscan.metrics.detection import (
    DetectionMetrics,
    EmitterPdEstimate,
    PdEstimate,
    PfaEstimate,
    SensitivityEstimate,
    estimate_detection_metrics,
    estimate_pd,
    estimate_per_emitter_pd,
    estimate_pfa,
    estimate_sensitivity,
)
from ewscan.metrics.first_intercept import (
    EmitterFirstIntercept,
    FirstInterceptMetrics,
    estimate_first_intercept_metrics,
    estimate_per_emitter_first_intercept,
)
from ewscan.metrics.interception import (
    EmitterInterceptionEstimate,
    InterceptRateEstimate,
    InterceptionMetrics,
    InterceptionRatioEstimate,
    estimate_intercept_rate,
    estimate_interception_metrics,
    estimate_interception_ratio,
    estimate_per_emitter_interception,
)
from ewscan.metrics.prediction import (
    PredictionMetrics,
    estimate_percentage_correct,
    estimate_prediction_metrics,
)
from ewscan.metrics.reward import (
    RewardMetrics,
    estimate_average_reward,
    estimate_reward_metrics,
)
from ewscan.metrics.time_error import (
    BurstTimeError,
    EmitterTimeError,
    TimeErrorMetrics,
    estimate_average_time_error,
    estimate_per_emitter_time_error,
    estimate_time_error_metrics,
    extract_bursts,
)

__all__ = [
    # 1E.1 Detection metrics
    "DetectionMetrics",
    "EmitterPdEstimate",
    "PdEstimate",
    "PfaEstimate",
    "SensitivityEstimate",
    "estimate_detection_metrics",
    "estimate_pd",
    "estimate_per_emitter_pd",
    "estimate_pfa",
    "estimate_sensitivity",
    # 1E.2 Interception ratio & rate
    "EmitterInterceptionEstimate",
    "InterceptRateEstimate",
    "InterceptionMetrics",
    "InterceptionRatioEstimate",
    "estimate_intercept_rate",
    "estimate_interception_metrics",
    "estimate_interception_ratio",
    "estimate_per_emitter_interception",
    # 1E.3 Time to first intercept
    "EmitterFirstIntercept",
    "FirstInterceptMetrics",
    "estimate_first_intercept_metrics",
    "estimate_per_emitter_first_intercept",
    # 1E.4 Average reward accumulator and cost readout
    "RewardMetrics",
    "estimate_average_reward",
    "estimate_reward_metrics",
    # 1E.5 Percentage of correct predictions (stub in MVP)
    "PredictionMetrics",
    "estimate_percentage_correct",
    "estimate_prediction_metrics",
    # 1E.6 Average intercept time error
    "BurstTimeError",
    "EmitterTimeError",
    "TimeErrorMetrics",
    "estimate_average_time_error",
    "estimate_per_emitter_time_error",
    "estimate_time_error_metrics",
    "extract_bursts",
    # 1E.7 Multi-seed aggregation with confidence intervals
    "AggregateDetectionMetrics",
    "AggregateFirstInterceptMetrics",
    "AggregateInterceptionMetrics",
    "AggregateMetrics",
    "AggregatePredictionMetrics",
    "AggregateRewardMetrics",
    "AggregateTimeErrorMetrics",
    "MetricStats",
    "aggregate_episodes",
    "aggregate_metric_records",
    "compute_metric_stats",
    "student_t_critical",
]
