"""Unit tests for RFEnvironment and truth matrix generation -- Phase 1B.5.

Verifies:
- Shape and dtype of truth matrix [bands x slots], dtype bool.
- Co-resident emitters in the same band OR together.
- Step and reset lifecycle, slot tracking, done flag, and error handling.
- Determinism and reproducibility across seeds.
- Subsystem RNG independence.
- Emitter factory (emitter_from_info) instantiations.
- Detection integration with DetectionModel.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import (
    EmitterInfo,
    EpisodeConfig,
    Observation,
    ScanAction,
)
from ewscan.env import (
    DetectionModel,
    Environment,
    GilbertElliottEmitter,
    PeriodicEmitter,
    RFEnvironment,
    StaticCWEmitter,
    emitter_from_info,
    generate_truth_matrix,
)
from ewscan.rng import make_generators


# ---------------------------------------------------------------------------
# Emitter Factory Tests
# ---------------------------------------------------------------------------

class TestEmitterFactory:
    """Test emitter_from_info factory function."""

    def test_gilbert_elliott_creation(self):
        info = EmitterInfo(
            band=2,
            snr=12.0,
            threat_level=0.7,
            emitter_type="gilbert_elliott",
            params={"p01": 0.1, "p10": 0.3},
        )
        em = emitter_from_info(info)
        assert isinstance(em, GilbertElliottEmitter)
        assert em.band == 2
        assert em.snr == 12.0
        assert em.threat_level == 0.7
        assert em.p01 == 0.1
        assert em.p10 == 0.3

    def test_periodic_creation(self):
        info = EmitterInfo(
            band=1,
            snr=18.0,
            threat_level=0.9,
            emitter_type="periodic",
            params={"period": 20, "dwell": 3, "jitter": 1, "phase": 5},
        )
        em = emitter_from_info(info)
        assert isinstance(em, PeriodicEmitter)
        assert em.band == 1
        assert em.snr == 18.0
        assert em.period == 20
        assert em.dwell == 3
        assert em.jitter == 1
        assert em.phase == 5

    def test_cw_creation(self):
        info = EmitterInfo(
            band=0,
            snr=25.0,
            threat_level=1.0,
            emitter_type="cw",
            params={},
        )
        em = emitter_from_info(info)
        assert isinstance(em, StaticCWEmitter)
        assert em.band == 0
        assert em.snr == 25.0
        assert em.threat_level == 1.0

    def test_alias_emitter_types(self):
        info_markov = EmitterInfo(
            band=0, snr=10.0, threat_level=1.0, emitter_type="markov", params={"p01": 0.1, "p10": 0.1}
        )
        assert isinstance(emitter_from_info(info_markov), GilbertElliottEmitter)

        info_radar = EmitterInfo(
            band=0, snr=10.0, threat_level=1.0, emitter_type="radar", params={"period": 10}
        )
        assert isinstance(emitter_from_info(info_radar), PeriodicEmitter)

        info_static = EmitterInfo(
            band=0, snr=10.0, threat_level=1.0, emitter_type="static_cw"
        )
        assert isinstance(emitter_from_info(info_static), StaticCWEmitter)

    def test_unknown_emitter_type_raises(self):
        info = EmitterInfo(
            band=0, snr=10.0, threat_level=1.0, emitter_type="unknown_future_type"
        )
        with pytest.raises(ValueError, match="Unknown emitter type"):
            emitter_from_info(info)


# ---------------------------------------------------------------------------
# Truth Matrix Shape, Dtype, and Co-resident Emitter ORing (Core 1B.5 Verify)
# ---------------------------------------------------------------------------

class TestTruthMatrix:
    """PLAN.md 1B.5 verify check:
    Shape and dtype correct; co-resident emitters OR together.
    """

    def test_truth_matrix_shape_and_dtype(self):
        config = EpisodeConfig(
            n_bands=8,
            n_slots=100,
            k=1,
            emitters=(
                EmitterInfo(band=0, snr=10.0, threat_level=1.0, emitter_type="cw"),
                EmitterInfo(
                    band=3,
                    snr=15.0,
                    threat_level=0.8,
                    emitter_type="periodic",
                    params={"period": 10, "dwell": 2},
                ),
            ),
            detection_threshold=3.0,
            pfa=1e-3,
            seed=42,
        )
        env = RFEnvironment(config)
        env.reset()

        truth = env.truth
        assert truth.shape == (8, 100)
        assert truth.dtype == np.bool_

    def test_co_resident_emitters_or_together(self):
        """Two periodic emitters on the same band OR together."""
        # Emitter 1 on band 1: period 4, dwell 1, phase 0 -> ON at 0, 4, 8, 12, ...
        # Emitter 2 on band 1: period 6, dwell 1, phase 0 -> ON at 0, 6, 12, ...
        e1 = PeriodicEmitter(band=1, period=4, dwell=1, jitter=0, phase=0)
        e2 = PeriodicEmitter(band=1, period=6, dwell=1, jitter=0, phase=0)

        env = RFEnvironment(
            n_bands=4,
            n_slots=20,
            emitters=[e1, e2],
            pfa=1e-3,
            seed=0,
        )
        env.reset()
        truth = env.truth

        # Band 1 truth should be ON at slots {0, 4, 6, 8, 12, 16, 18}
        expected_on_slots = {0, 4, 6, 8, 12, 16, 18}
        actual_on_slots = set(np.where(truth[1, :])[0])
        assert actual_on_slots == expected_on_slots

        # Other bands (0, 2, 3) must be completely OFF
        assert not np.any(truth[0, :])
        assert not np.any(truth[2, :])
        assert not np.any(truth[3, :])

    def test_co_resident_cw_and_periodic(self):
        """CW + Periodic on band 0 -> band 0 is always ON."""
        e_cw = StaticCWEmitter(band=0)
        e_per = PeriodicEmitter(band=0, period=5, dwell=1)

        env = RFEnvironment(
            n_bands=2,
            n_slots=50,
            emitters=[e_cw, e_per],
            seed=1,
        )
        env.reset()
        assert np.all(env.truth[0, :])
        assert not np.any(env.truth[1, :])

    def test_co_resident_markov_emitters(self):
        """Two Gilbert-Elliott emitters on the same band OR together."""
        ge1 = GilbertElliottEmitter(band=2, p01=0.2, p10=0.3, initial_state=0)
        ge2 = GilbertElliottEmitter(band=2, p01=0.4, p10=0.1, initial_state=1)

        env = RFEnvironment(
            n_bands=4,
            n_slots=200,
            emitters=[ge1, ge2],
            seed=99,
        )
        env.reset()
        truth = env.truth

        # Reset emitters with the same child RNGs and step individually to verify OR
        gens = make_generators(99)
        child_rngs = gens["emitter"].spawn(2)
        ge1_test = GilbertElliottEmitter(band=2, p01=0.2, p10=0.3, initial_state=0)
        ge2_test = GilbertElliottEmitter(band=2, p01=0.4, p10=0.1, initial_state=1)
        ge1_test.reset(child_rngs[0])
        ge2_test.reset(child_rngs[1])

        for t in range(200):
            s1 = ge1_test.step()
            s2 = ge2_test.step()
            expected = s1 or s2
            assert truth[2, t] == expected

    def test_generate_truth_matrix_helper(self):
        config = EpisodeConfig(
            n_bands=4,
            n_slots=30,
            k=1,
            emitters=(
                EmitterInfo(band=0, snr=10.0, threat_level=1.0, emitter_type="cw"),
                EmitterInfo(
                    band=2,
                    snr=15.0,
                    threat_level=0.5,
                    emitter_type="periodic",
                    params={"period": 3, "dwell": 1, "jitter": 0, "phase": 0},
                ),
            ),
            detection_threshold=3.0,
            pfa=1e-3,
            seed=7,
        )
        t_matrix = generate_truth_matrix(config)
        assert t_matrix.shape == (4, 30)
        assert t_matrix.dtype == np.bool_
        assert np.all(t_matrix[0, :])
        assert np.array_equal(t_matrix[2, :], [t % 3 == 0 for t in range(30)])
        assert not np.any(t_matrix[1, :])
        assert not np.any(t_matrix[3, :])


# ---------------------------------------------------------------------------
# Stepping and Environment Lifecycle
# ---------------------------------------------------------------------------

class TestEnvironmentLifecycle:
    """Test reset, step, properties, and error guards."""

    def test_unreset_access_truth_raises(self):
        env = RFEnvironment(n_bands=4, n_slots=20)
        with pytest.raises(RuntimeError, match="must be reset"):
            _ = env.truth

    def test_unreset_step_raises(self):
        env = RFEnvironment(n_bands=4, n_slots=20)
        with pytest.raises(RuntimeError, match="must be reset"):
            env.step(ScanAction(bands=(0,)))

    def test_step_progresses_slots_and_completes(self):
        n_slots = 15
        env = RFEnvironment(
            n_bands=4,
            n_slots=n_slots,
            emitters=[StaticCWEmitter(band=0)],
            seed=0,
        )
        env.reset()

        assert env.slot == 0
        assert not env.done

        for t in range(n_slots):
            assert env.slot == t
            assert not env.done
            action = ScanAction(bands=(t % 4,))
            obs = env.step(action)
            assert isinstance(obs, Observation)
            assert obs.slot == t
            assert obs.bands[0] == action.bands[0]
            assert isinstance(obs.detections[0], bool)

        assert env.slot == n_slots
        assert env.done

        # Stepping past done raises IndexError
        with pytest.raises(IndexError, match="already completed"):
            env.step(ScanAction(bands=(0,)))

    def test_invalid_action_band_raises(self):
        env = RFEnvironment(n_bands=4, n_slots=10)
        env.reset()

        with pytest.raises(ValueError, match="out of valid range"):
            env.step(ScanAction(bands=(-1,)))

        with pytest.raises(ValueError, match="out of valid range"):
            env.step(ScanAction(bands=(4,)))

    def test_invalid_construction_parameters(self):
        with pytest.raises(ValueError, match="n_bands"):
            RFEnvironment(n_bands=0, n_slots=10)
        with pytest.raises(ValueError, match="n_slots"):
            RFEnvironment(n_bands=4, n_slots=0)
        with pytest.raises(ValueError, match="k"):
            RFEnvironment(n_bands=4, n_slots=10, k=0)
        with pytest.raises(ValueError, match="cannot exceed"):
            RFEnvironment(n_bands=4, n_slots=10, k=5)
        with pytest.raises(ValueError, match="out of range"):
            RFEnvironment(
                n_bands=4,
                n_slots=10,
                emitters=[StaticCWEmitter(band=4)],
            )

    def test_environment_alias(self):
        assert Environment is RFEnvironment

    def test_environment_properties_and_custom_detection(self):
        dm = DetectionModel(pfa=1e-2, threshold=4.5)
        info = EmitterInfo(band=1, snr=12.0, threat_level=0.5, emitter_type="cw")
        env = RFEnvironment(
            n_bands=5,
            n_slots=25,
            k=1,
            emitters=[info],
            detection_model=dm,
            seed=10,
        )
        assert env.n_bands == 5
        assert env.n_slots == 25
        assert env.k == 1
        assert len(env.emitters) == 1
        assert isinstance(env.emitters[0], StaticCWEmitter)
        assert env.detection_model is dm
        assert isinstance(env.config, EpisodeConfig)
        assert env.config.n_bands == 5
        assert env.config.detection_threshold == 4.5
        assert env.config.pfa == 1e-2

    def test_invalid_emitter_type_in_sequence_raises(self):
        with pytest.raises(TypeError, match="Expected Emitter or EmitterInfo"):
            RFEnvironment(
                n_bands=4,
                n_slots=10,
                emitters=["invalid_emitter_type"],  # type: ignore
            )



# ---------------------------------------------------------------------------
# Detection Integration and Physical Realism
# ---------------------------------------------------------------------------

class TestDetectionIntegration:
    """Test interaction between ground truth and DetectionModel."""

    def test_high_snr_cw_gives_near_perfect_detection(self):
        """A 40 dB CW emitter should produce nearly 100% detections when scanned."""
        n_slots = 1000
        env = RFEnvironment(
            n_bands=2,
            n_slots=n_slots,
            emitters=[StaticCWEmitter(band=0, snr=40.0)],
            pfa=1e-3,
            seed=42,
        )
        env.reset()

        detections = []
        for _ in range(n_slots):
            obs = env.step(ScanAction(bands=(0,)))
            detections.append(obs.detections[0])

        hit_rate = sum(detections) / n_slots
        assert hit_rate > 0.99

    def test_quiet_band_detection_matches_pfa(self):
        """Scanning an empty band draws false alarms at approximately Pfa rate."""
        n_slots = 50_000
        pfa = 0.01
        env = RFEnvironment(
            n_bands=2,
            n_slots=n_slots,
            emitters=[StaticCWEmitter(band=0)],  # band 1 is completely quiet
            pfa=pfa,
            seed=123,
        )
        env.reset()

        detections = []
        for _ in range(n_slots):
            obs = env.step(ScanAction(bands=(1,)))
            detections.append(obs.detections[0])

        empirical_pfa = sum(detections) / n_slots
        sigma = np.sqrt(pfa * (1 - pfa) / n_slots)
        assert abs(empirical_pfa - pfa) < 4 * sigma


# ---------------------------------------------------------------------------
# Determinism and RNG Subsystem Independence
# ---------------------------------------------------------------------------

class TestDeterminismAndIndependence:
    """Test that seed guarantees reproducibility and subsystem isolation."""

    def test_determinism_same_seed(self):
        config = EpisodeConfig(
            n_bands=4,
            n_slots=100,
            k=1,
            emitters=(
                EmitterInfo(
                    band=1,
                    snr=15.0,
                    threat_level=0.8,
                    emitter_type="gilbert_elliott",
                    params={"p01": 0.2, "p10": 0.3},
                ),
                EmitterInfo(
                    band=2,
                    snr=10.0,
                    threat_level=0.5,
                    emitter_type="periodic",
                    params={"period": 6, "dwell": 2, "jitter": 1},
                ),
            ),
            detection_threshold=3.0,
            pfa=1e-3,
            seed=777,
        )

        env1 = RFEnvironment(config)
        env1.reset()
        obs1 = [env1.step(ScanAction(bands=(t % 4,))) for t in range(100)]

        env2 = RFEnvironment(config)
        env2.reset()
        obs2 = [env2.step(ScanAction(bands=(t % 4,))) for t in range(100)]

        np.testing.assert_array_equal(env1.truth, env2.truth)
        assert obs1 == obs2

    def test_subsystem_rng_independence(self):
        """Drawing from scheduler RNG should not alter environment truth or detections."""
        config = EpisodeConfig(
            n_bands=4,
            n_slots=100,
            k=1,
            emitters=(
                EmitterInfo(
                    band=1,
                    snr=15.0,
                    threat_level=0.8,
                    emitter_type="gilbert_elliott",
                    params={"p01": 0.2, "p10": 0.3},
                ),
            ),
            detection_threshold=3.0,
            pfa=1e-3,
            seed=42,
        )

        # Run 1: normal
        env1 = RFEnvironment(config)
        env1.reset()
        obs1 = [env1.step(ScanAction(bands=(1,))) for _ in range(100)]

        # Run 2: advance scheduler RNG externally
        generators = make_generators(42)
        _ = generators["scheduler"].random(10_000)

        env2 = RFEnvironment(config)
        env2.reset()
        obs2 = [env2.step(ScanAction(bands=(1,))) for _ in range(100)]

        np.testing.assert_array_equal(env1.truth, env2.truth)
        assert obs1 == obs2
