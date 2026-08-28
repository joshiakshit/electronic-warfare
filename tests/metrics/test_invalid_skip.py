"""Objective 4: every metric skips invalid (settling) slots.

Hand-built log, k=1, 4 slots, band 0 always ON, band 1 always OFF.

  slot 0: scan band0, det=T, valid   -> true hit
  slot 1: scan band0, det=T, INVALID -> skipped everywhere
  slot 2: scan band1, det=T, valid   -> false alarm
  slot 3: scan band0, det=T, valid   -> true hit
"""

from __future__ import annotations

import numpy as np

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.metrics.detection import estimate_pd, estimate_pfa
from ewscan.metrics.interception import (
    estimate_intercept_rate,
    estimate_interception_ratio,
)


def _log() -> EpisodeLog:
    n_bands, n_slots = 2, 4
    truth = np.zeros((n_bands, n_slots), dtype=bool)
    truth[0, :] = True
    actions = np.array([[0], [0], [1], [0]], dtype=np.intp)
    detections = np.array([[True], [True], [True], [True]], dtype=bool)
    valid_slots = np.array([True, False, True, True], dtype=bool)
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
        pfa=1e-3,
        seed=0,
    )
    return EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=detections,
        valid_slots=valid_slots,
    )


def test_pd_skips_invalid_slot():
    est = estimate_pd(_log())
    assert est.n_scans_on == 2  # slots 0 and 3, slot 1 excluded
    assert est.n_hits == 2
    assert est.pd == 1.0


def test_pfa_skips_invalid_slot():
    est = estimate_pfa(_log())
    assert est.n_scans_off == 1  # only slot 2 (valid off-scan)
    assert est.n_false_alarms == 1
    assert est.pfa == 1.0


def test_interception_ratio_skips_invalid_hit():
    est = estimate_interception_ratio(_log())
    # slot 1 would be a hit without the skip; total truth stays 4.
    assert est.n_hits == 2
    assert est.n_transmissions == 4
    assert est.ratio == 0.5


def test_intercept_rate_skips_invalid_hit():
    est = estimate_intercept_rate(_log())
    assert est.n_hits == 2
    assert est.rate == 0.5
