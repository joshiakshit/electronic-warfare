"""Metrics modules for ewscan -- the seven figures of merit."""

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

__all__ = [
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
]
