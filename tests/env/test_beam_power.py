"""Objective 4: BeamEmitter passes varying effective power in linear units."""

from __future__ import annotations

import numpy as np

from ewscan.contracts import EmitterInfo, EpisodeConfig
from ewscan.env.emitters import BeamEmitter
from ewscan.env.environment import RFEnvironment


def test_power_linear_follows_beam_shape():
    e = BeamEmitter(band=0, omega=2 * np.pi / 20, beamwidth=0.3, snr_peak=20.0, theta0=0.0)
    e.reset(np.random.default_rng(0))
    power = e.power_linear(20)
    peak = 10.0 ** (20.0 / 10.0)
    # Slot 0 sits on boresight: full linear peak power.
    assert np.isclose(power[0], peak)
    # Away from boresight the linear power drops below the peak.
    assert power[5] < peak


def test_environment_sees_varying_beam_snr():
    config = EpisodeConfig(
        n_bands=2,
        n_slots=40,
        k=1,
        emitters=(
            EmitterInfo(
                band=0, snr=20.0, threat_level=1.0, emitter_type="beam",
                params={"omega": 2 * np.pi / 20, "beamwidth": 0.5, "snr_peak": 20.0},
            ),
        ),
        pfa=1e-3,
        seed=0,
    )
    env = RFEnvironment(config)
    env.reset(seed=0)
    on = env.emitter_truth[0]
    snr_on = env._snr_matrix[0, on]
    # The beam shape must reach the detector: on-slot SNRs are not a single value.
    assert np.unique(np.round(snr_on, 6)).size > 1
    # And they never exceed the peak of 20 dB.
    assert np.max(snr_on) <= 20.0 + 1e-9
