"""Objective 4: horizon-penalized TTFI alongside intercept fraction."""

from __future__ import annotations

import numpy as np

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.first_intercept import estimate_first_intercept_metrics


def test_penalized_ttfi_assigns_horizon_to_missed_emitter():
    n_bands, n_slots = 2, 10
    truth = np.ones((n_bands, n_slots), dtype=bool)
    actions = np.ones((n_slots, 1), dtype=np.intp)  # scan band 1 by default
    actions[3, 0] = 0  # scan band 0 at slot 3
    detections = np.zeros((n_slots, 1), dtype=bool)
    detections[3, 0] = True  # only emitter 0 is ever intercepted
    config = EpisodeConfig(
        n_bands=n_bands, n_slots=n_slots, k=1,
        emitters=(
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=1.0, emitter_type="cw"),
        ),
        pfa=1e-3, seed=0,
    )
    log = EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)

    m = estimate_first_intercept_metrics(log)
    assert m.n_emitters == 2
    assert m.n_intercepted == 1
    assert m.mean_time_to_first_intercept == 3.0  # intercepted-only mean
    assert m.intercept_fraction == 0.5
    # Missed emitter charged the full horizon (n_slots): (3 + 10) / 2 = 6.5
    assert m.mean_time_to_first_intercept_penalized == 6.5
