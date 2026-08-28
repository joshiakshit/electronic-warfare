"""Objective 4: settling slots are invalid and take no detector draw."""

from __future__ import annotations

import numpy as np

from ewscan.contracts import EmitterInfo, EpisodeConfig, ScanAction
from ewscan.env.environment import RFEnvironment


def _config() -> EpisodeConfig:
    return EpisodeConfig(
        n_bands=2,
        n_slots=6,
        k=1,
        emitters=(EmitterInfo(band=0, snr=30.0, threat_level=1.0, emitter_type="cw"),),
        pfa=1e-3,
        seed=0,
        retune_cost_slots=3,
    )


def test_settling_is_invalid_with_no_detection():
    env = RFEnvironment(_config())
    env.reset(seed=0)

    # Slot 0: scan band 0, no previous band, so no settling.
    obs0 = env.step(ScanAction(bands=(0,)))
    assert obs0.valid is True
    assert obs0.settling is False
    assert obs0.detections == (True,)  # CW at 30 dB always detects

    # Slot 1: retune to band 1 triggers settling for 3 slots.
    obs1 = env.step(ScanAction(bands=(1,)))
    assert obs1.settling is True
    assert obs1.valid is False
    assert obs1.detections == (False,)

    # Slots 2 and 3 remain settling and invalid.
    obs2 = env.step(ScanAction(bands=(1,)))
    obs3 = env.step(ScanAction(bands=(1,)))
    assert obs2.settling and not obs2.valid
    assert obs3.settling and not obs3.valid

    # Slot 4: settling has cleared.
    obs4 = env.step(ScanAction(bands=(1,)))
    assert obs4.settling is False
    assert obs4.valid is True


def test_settling_takes_no_detector_draw_on_active_band():
    # Return to the CW band during settling. A real draw would detect the 30 dB
    # signal, but a settling slot must not draw at all.
    env = RFEnvironment(_config())
    env.reset(seed=0)
    env.step(ScanAction(bands=(0,)))
    env.step(ScanAction(bands=(1,)))  # retune -> settling starts
    obs = env.step(ScanAction(bands=(0,)))  # back on active band, still settling
    assert obs.settling is True
    assert obs.valid is False
    assert obs.detections == (False,)
