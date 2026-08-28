"""Objective 4: per-emitter truth drives hopping and co-resident attribution."""

from __future__ import annotations

import numpy as np

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog
from ewscan.env.environment import RFEnvironment
from ewscan.metrics.interception import estimate_per_emitter_interception
from ewscan.metrics.first_intercept import estimate_per_emitter_first_intercept
from ewscan.metrics.time_error import estimate_per_emitter_time_error


def test_frequency_hopper_attributes_every_transmission():
    # One hopper that alternates band 0 / band 1 each slot, always ON. The
    # receiver follows it perfectly. All four transmissions must be intercepted.
    n_bands, n_slots = 2, 4
    truth = np.array([[True, False, True, False], [False, True, False, True]], dtype=bool)
    emitter_truth = np.array([[True, True, True, True]], dtype=bool)
    emitter_bands = np.array([[0, 1, 0, 1]], dtype=np.intp)
    actions = np.array([[0], [1], [0], [1]], dtype=np.intp)
    detections = np.array([[True], [True], [True], [True]], dtype=bool)
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=(
            EmitterInfo(
                band=0, snr=20.0, threat_level=1.0, emitter_type="frequency_hop",
                params={"hop_bands": [0, 1]},
            ),
        ),
        pfa=1e-3,
        seed=0,
    )
    log = EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=detections,
        emitter_truth=emitter_truth,
        emitter_bands=emitter_bands,
    )

    per = estimate_per_emitter_interception(log)
    assert per[0].n_transmissions == 4
    assert per[0].n_hits == 4
    assert per[0].interception_ratio == 1.0

    fi = estimate_per_emitter_first_intercept(log)
    assert fi[0].intercepted is True
    assert fi[0].first_intercept_slot == 0


def test_co_resident_emitters_attributed_separately():
    # Two emitters share band 0. Emitter 0 transmits slots 0,1; emitter 1 slots
    # 2,3. Each must be credited only its own transmissions.
    n_bands, n_slots = 2, 4
    truth = np.array([[True, True, True, True], [False, False, False, False]], dtype=bool)
    emitter_truth = np.array(
        [[True, True, False, False], [False, False, True, True]], dtype=bool
    )
    emitter_bands = np.zeros((2, n_slots), dtype=np.intp)
    actions = np.array([[0], [0], [0], [0]], dtype=np.intp)
    detections = np.array([[True], [True], [True], [True]], dtype=bool)
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=(
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
        ),
        pfa=1e-3,
        seed=0,
    )
    log = EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=detections,
        emitter_truth=emitter_truth,
        emitter_bands=emitter_bands,
    )

    per = estimate_per_emitter_interception(log)
    assert per[0].n_transmissions == 2 and per[0].n_hits == 2
    assert per[1].n_transmissions == 2 and per[1].n_hits == 2

    te = estimate_per_emitter_time_error(log)
    assert te[0].n_bursts == 1 and te[0].n_intercepted_bursts == 1
    assert te[1].n_bursts == 1 and te[1].n_intercepted_bursts == 1


def test_environment_records_hopper_activity():
    config = EpisodeConfig(
        n_bands=3,
        n_slots=12,
        k=1,
        emitters=(
            EmitterInfo(
                band=0, snr=20.0, threat_level=1.0, emitter_type="frequency_hop",
                params={"hop_bands": [0, 1, 2]},
            ),
        ),
        pfa=1e-3,
        seed=0,
    )
    env = RFEnvironment(config)
    env.reset(seed=0)
    assert env.emitter_truth.shape == (1, 12)
    assert env.emitter_bands.shape == (1, 12)
    assert bool(env.emitter_truth.all())  # hopper is always ON
    assert len(np.unique(env.emitter_bands[0])) > 1  # it actually hops
