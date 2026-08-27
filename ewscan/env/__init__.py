"""Environment simulation modules for ewscan."""

from ewscan.env.detection import (
    DetectionModel,
    pd_from_snr,
    pfa_from_threshold,
    roc_curve,
    snr_for_target_pd,
    threshold_from_pfa,
)
from ewscan.env.emitters import (
    FrequencyHopEmitter,
    GilbertElliottEmitter,
    PeriodicEmitter,
    StaticCWEmitter,
    emitter_from_info,
)
from ewscan.env.environment import (
    Environment,
    RFEnvironment,
    generate_truth_matrix,
)
from ewscan.env.recorder import (
    EpisodeRecorder,
    save_episode_log,
    load_episode_log,
)

__all__ = [
    "DetectionModel",
    "Environment",
    "FrequencyHopEmitter",
    "GilbertElliottEmitter",
    "PeriodicEmitter",
    "RFEnvironment",
    "StaticCWEmitter",
    "emitter_from_info",
    "generate_truth_matrix",
    "pd_from_snr",
    "pfa_from_threshold",
    "roc_curve",
    "snr_for_target_pd",
    "threshold_from_pfa",
    "EpisodeRecorder",
    "save_episode_log",
    "load_episode_log",
]


