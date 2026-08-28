"""Tests for the vectorized truth-build fast path in RFEnvironment.reset().

Verifies activity()-based vectorization is bit-identical to the per-slot
step() loop for every emitter type and seed, and that RNG-sequential
emitters (Markov, jittered periodic, hopper) are untouched.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import EmitterInfo
from ewscan.env import (
    BeamEmitter,
    GilbertElliottEmitter,
    PeriodicEmitter,
    RFEnvironment,
    StaticCWEmitter,
)


def _force_loop_env(env: RFEnvironment) -> None:
    """Monkeypatch every emitter's activity() to return None, forcing the
    original per-slot loop path."""
    for em in env.emitters:
        em.activity = lambda n_slots: None  # noqa: ARG005


class TestExactEqualityPerEmitterType:
    def test_cw_emitter(self):
        info = EmitterInfo(band=3, snr=20.0, threat_level=0.5, emitter_type="cw", params={})
        env_a = RFEnvironment(n_bands=8, n_slots=500, emitters=[info], seed=7)
        env_b = RFEnvironment(n_bands=8, n_slots=500, emitters=[info], seed=7)

        assert env_a.emitters[0].activity(500) is not None
        _force_loop_env(env_b)

        env_a.reset()
        env_b.reset()

        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )

    def test_periodic_emitter_no_jitter(self):
        info = EmitterInfo(
            band=2,
            snr=15.0,
            threat_level=0.7,
            emitter_type="periodic",
            params={"period": 17, "dwell": 3, "jitter": 0, "phase": 5},
        )
        env_a = RFEnvironment(n_bands=8, n_slots=500, emitters=[info], seed=11)
        env_b = RFEnvironment(n_bands=8, n_slots=500, emitters=[info], seed=11)

        assert env_a.emitters[0].activity(500) is not None
        _force_loop_env(env_b)

        env_a.reset()
        env_b.reset()

        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )

    def test_beam_emitter(self):
        em = BeamEmitter(band=4, omega=0.3, beamwidth=0.5, snr_peak=18.0)
        env_a = RFEnvironment(n_bands=8, n_slots=500, emitters=[em], seed=3)
        em2 = BeamEmitter(band=4, omega=0.3, beamwidth=0.5, snr_peak=18.0)
        env_b = RFEnvironment(n_bands=8, n_slots=500, emitters=[em2], seed=3)

        assert env_a.emitters[0].activity(500) is not None
        _force_loop_env(env_b)

        env_a.reset()
        env_b.reset()

        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )


class TestMixedScenarioGolden:
    def test_mixed_threat_matches_forced_loop(self):
        from ewscan.experiments.scenarios import make_mixed_threat_scenario

        cfg = make_mixed_threat_scenario(n_slots=2000)
        env_a = RFEnvironment(config=cfg)
        env_b = RFEnvironment(config=cfg)
        _force_loop_env(env_b)

        env_a.reset()
        env_b.reset()

        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )

    def test_periodic_radar_matches_forced_loop(self):
        from ewscan.experiments.scenarios import make_periodic_radar_scenario

        cfg = make_periodic_radar_scenario(n_slots=2000)
        env_a = RFEnvironment(config=cfg)
        env_b = RFEnvironment(config=cfg)
        _force_loop_env(env_b)

        env_a.reset()
        env_b.reset()

        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )


class TestMarkovUntouched:
    def test_gilbert_elliott_only_env_identical_with_and_without_vectorization(self):
        em = GilbertElliottEmitter(band=1, p01=0.1, p10=0.2, snr=12.0)
        env_a = RFEnvironment(n_bands=6, n_slots=800, emitters=[em], seed=9)
        em2 = GilbertElliottEmitter(band=1, p01=0.1, p10=0.2, snr=12.0)
        env_b = RFEnvironment(n_bands=6, n_slots=800, emitters=[em2], seed=9)
        _force_loop_env(env_b)

        env_a.reset()
        env_b.reset()

        assert em.activity(800) is None
        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )


class TestJitterFallback:
    def test_periodic_with_jitter_returns_none_and_matches_loop(self):
        info = EmitterInfo(
            band=5,
            snr=16.0,
            threat_level=0.6,
            emitter_type="periodic",
            params={"period": 20, "dwell": 3, "jitter": 2, "phase": 1},
        )
        env_a = RFEnvironment(n_bands=8, n_slots=500, emitters=[info], seed=13)
        env_b = RFEnvironment(n_bands=8, n_slots=500, emitters=[info], seed=13)
        _force_loop_env(env_b)

        em_a = env_a.emitters[0]
        assert em_a.activity(500) is None

        env_a.reset()
        env_b.reset()

        assert np.array_equal(env_a.truth, env_b.truth)
        np.testing.assert_allclose(
            env_a._snr_matrix, env_b._snr_matrix, rtol=0, atol=0
        )


class TestCoResidentAccumulation:
    def test_two_emitters_same_band_or_and_power_sum(self):
        cw = StaticCWEmitter(band=2, snr=10.0)
        periodic = PeriodicEmitter(band=2, period=5, dwell=2, jitter=0, phase=0, snr=13.0)
        env = RFEnvironment(n_bands=6, n_slots=100, emitters=[cw, periodic], seed=1)
        env.reset()

        cw_power = 10.0 ** (10.0 / 10.0)
        combined_power = cw_power + 10.0 ** (13.0 / 10.0)
        t = np.arange(100)
        periodic_on = (t % 5) < 2

        assert np.all(env.truth[2, :])
        expected_snr = np.where(
            periodic_on, 10.0 * np.log10(combined_power), 10.0 * np.log10(cw_power)
        )
        np.testing.assert_allclose(env._snr_matrix[2, :], expected_snr, rtol=0, atol=0)
