"""Unit tests for baseline scan schedulers (Phase 1C.1 - 1C.3)."""

import numpy as np
import pytest

from ewscan.agents import (
    OracleScheduler,
    PriorWeightedScheduler,
    RoundRobinScheduler,
    UniformRandomScheduler,
)
from ewscan.contracts import EmitterInfo, ThreatPrior, scheduler_config_from_episode
from ewscan.env.environment import RFEnvironment
from ewscan.testing.fixtures import ScriptedEnv, make_test_config


class TestRoundRobinScheduler:
    def test_name(self):
        scheduler = RoundRobinScheduler()
        assert scheduler.name == "round_robin"

    def test_unreset_act_raises(self):
        scheduler = RoundRobinScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)

    def test_sequential_sweep(self):
        config = make_test_config(n_bands=4, n_slots=10)
        scheduler = RoundRobinScheduler()
        scheduler.reset(config)

        actions = [scheduler.act(None).bands[0] for _ in range(10)]
        assert actions == [0, 1, 2, 3, 0, 1, 2, 3, 0, 1]

    def test_custom_start_band(self):
        config = make_test_config(n_bands=3, n_slots=5)
        scheduler = RoundRobinScheduler(start_band=1)
        scheduler.reset(config)

        actions = [scheduler.act(None).bands[0] for _ in range(5)]
        assert actions == [1, 2, 0, 1, 2]

    def test_reset_restarts_sequence(self):
        config = make_test_config(n_bands=4, n_slots=5)
        scheduler = RoundRobinScheduler()
        scheduler.reset(config)
        first_run = [scheduler.act(None).bands[0] for _ in range(5)]

        scheduler.reset(config)
        second_run = [scheduler.act(None).bands[0] for _ in range(5)]

        assert first_run == second_run == [0, 1, 2, 3, 0]


class TestUniformRandomScheduler:
    def test_name(self):
        scheduler = UniformRandomScheduler()
        assert scheduler.name == "uniform_random"

    def test_unreset_act_raises(self):
        scheduler = UniformRandomScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)

    def test_reproducibility_via_config_seed(self):
        config = make_test_config(n_bands=8, n_slots=20, seed=42)

        sched1 = UniformRandomScheduler()
        sched1.reset(config)
        seq1 = [sched1.act(None).bands[0] for _ in range(20)]

        sched2 = UniformRandomScheduler()
        sched2.reset(config)
        seq2 = [sched2.act(None).bands[0] for _ in range(20)]

        assert seq1 == seq2

    def test_uniform_distribution_convergence(self):
        n_bands = 4
        n_slots = 100_000
        config = make_test_config(n_bands=n_bands, n_slots=n_slots, seed=123)

        scheduler = UniformRandomScheduler()
        scheduler.reset(config)

        counts = np.zeros(n_bands, dtype=int)
        for _ in range(n_slots):
            action = scheduler.act(None)
            counts[action.bands[0]] += 1

        expected = n_slots / n_bands
        chi2 = np.sum((counts - expected) ** 2 / expected)
        # For df=3, critical value at alpha=0.01 is 11.345
        assert chi2 < 11.345

        proportions = counts / n_slots
        np.testing.assert_allclose(proportions, 0.25, atol=0.01)


class TestPriorWeightedScheduler:
    def test_name(self):
        scheduler = PriorWeightedScheduler()
        assert scheduler.name == "prior_weighted"

    def test_unreset_act_raises(self):
        scheduler = PriorWeightedScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)

    def test_default_uniform_priors(self):
        config = make_test_config(n_bands=4, n_slots=100_000, seed=42)
        scheduler = PriorWeightedScheduler()
        scheduler.reset(config)

        counts = np.zeros(4, dtype=int)
        for _ in range(100_000):
            action = scheduler.act(None)
            counts[action.bands[0]] += 1

        proportions = counts / 100_000
        np.testing.assert_allclose(proportions, 0.25, atol=0.01)

    def test_custom_priors_distribution(self):
        priors = [0.5, 0.3, 0.2, 0.0]
        config = make_test_config(n_bands=4, n_slots=100_000, seed=42)
        scheduler = PriorWeightedScheduler(priors=priors)
        scheduler.reset(config)

        counts = np.zeros(4, dtype=int)
        for _ in range(100_000):
            action = scheduler.act(None)
            counts[action.bands[0]] += 1

        proportions = counts / 100_000
        np.testing.assert_allclose(proportions, priors, atol=0.015)
        assert counts[3] == 0  # Zero probability band should never be scanned

    def test_unnormalized_priors(self):
        priors = [10.0, 30.0]
        config = make_test_config(n_bands=2, n_slots=100_000, seed=42)
        scheduler = PriorWeightedScheduler(priors=priors)
        scheduler.reset(config)

        counts = np.zeros(2, dtype=int)
        for _ in range(100_000):
            action = scheduler.act(None)
            counts[action.bands[0]] += 1

        proportions = counts / 100_000
        np.testing.assert_allclose(proportions, [0.25, 0.75], atol=0.01)

    def test_invalid_priors_mismatched_length(self):
        config = make_test_config(n_bands=4)
        scheduler = PriorWeightedScheduler(priors=[0.5, 0.5])
        with pytest.raises(ValueError, match="Priors length"):
            scheduler.reset(config)

    def test_invalid_priors_negative(self):
        config = make_test_config(n_bands=2)
        scheduler = PriorWeightedScheduler(priors=[-0.5, 1.5])
        with pytest.raises(ValueError, match="non-negative"):
            scheduler.reset(config)

    def test_invalid_priors_zero_sum(self):
        config = make_test_config(n_bands=2)
        scheduler = PriorWeightedScheduler(priors=[0.0, 0.0])
        with pytest.raises(ValueError, match="positive"):
            scheduler.reset(config)

    def test_uses_explicit_scheduler_threat_prior(self):
        config = make_test_config(n_bands=3, seed=42)
        scheduler_config = scheduler_config_from_episode(
            config,
            threat_prior=ThreatPrior(
                weights=(0.0, 0.0, 1.0),
                provenance="test",
            ),
        )
        scheduler = PriorWeightedScheduler()

        scheduler.reset(scheduler_config)

        assert scheduler.act(None).bands == (2,)

    def test_k_larger_than_positive_prior_count_fills_zero_weight_bands(self):
        config = make_test_config(n_bands=3, n_slots=20, k=2, seed=42)
        scheduler = PriorWeightedScheduler(priors=(1.0, 0.0, 0.0))
        scheduler.reset(config)

        for _ in range(20):
            action = scheduler.act(None)
            assert 0 in action.bands
            assert len(action.bands) == 2
            assert len(set(action.bands)) == 2


class TestOracleScheduler:
    def test_name(self):
        scheduler = OracleScheduler()
        assert scheduler.name == "oracle"

    def test_unreset_act_raises(self):
        scheduler = OracleScheduler()
        with pytest.raises(RuntimeError, match="must be reset"):
            scheduler.act(None)

    def test_unset_truth_raises(self):
        config = make_test_config(n_bands=4, n_slots=10)
        scheduler = OracleScheduler()
        with pytest.raises(RuntimeError, match="Truth matrix must be set"):
            scheduler.reset(config)

    def test_set_truth_and_truth_property(self):
        truth = np.array([[True, False], [False, True]], dtype=bool)
        scheduler = OracleScheduler(truth=truth)
        retrieved = scheduler.truth
        assert retrieved is not None
        assert np.array_equal(retrieved, truth)

        # Mutating copy must not modify internal truth
        retrieved[0, 0] = False
        assert scheduler.truth[0, 0] == True

    def test_set_truth_invalid_dimension(self):
        scheduler = OracleScheduler()
        with pytest.raises(ValueError, match="2-dimensional"):
            scheduler.set_truth([True, False, True])

    def test_mismatched_truth_shape_raises(self):
        truth = np.zeros((3, 10), dtype=bool)
        config = make_test_config(n_bands=4, n_slots=10)
        scheduler = OracleScheduler(truth=truth)
        with pytest.raises(ValueError, match="Truth matrix shape"):
            scheduler.reset(config)

    def test_single_active_emitter_perfect_tracking(self):
        # 4 bands, 10 slots. Exactly one band active per slot in varying order
        truth = np.zeros((4, 10), dtype=bool)
        active_sequence = [2, 0, 3, 1, 1, 2, 0, 3, 2, 1]
        for t, b in enumerate(active_sequence):
            truth[b, t] = True

        config = make_test_config(n_bands=4, n_slots=10)
        scheduler = OracleScheduler(truth=truth)
        scheduler.reset(config)

        env = ScriptedEnv(config, truth)
        log = env.run(scheduler)

        assert log.actions[:, 0].tolist() == active_sequence
        assert np.all(log.detections)
        assert np.sum(log.detections) == 10

    def test_threat_level_prioritization(self):
        # Multiple bands active at the same time:
        # Band 0: threat 0.4
        # Band 1: threat 0.9
        # Band 2: threat 0.2
        emitters = (
            EmitterInfo(band=0, snr=20.0, threat_level=0.4, emitter_type="cw"),
            EmitterInfo(band=1, snr=20.0, threat_level=0.9, emitter_type="cw"),
            EmitterInfo(band=2, snr=20.0, threat_level=0.2, emitter_type="cw"),
        )
        config = make_test_config(n_bands=4, n_slots=5, emitters=emitters)

        truth = np.zeros((4, 5), dtype=bool)
        # Slot 0: bands 0 and 2 active -> pick 0 (threat 0.4 > 0.2)
        truth[0, 0] = True
        truth[2, 0] = True
        # Slot 1: bands 0, 1, 2 active -> pick 1 (threat 0.9)
        truth[0, 1] = True
        truth[1, 1] = True
        truth[2, 1] = True
        # Slot 2: band 2 active -> pick 2
        truth[2, 2] = True
        # Slot 3: band 0 active -> pick 0
        truth[0, 3] = True
        # Slot 4: bands 0 and 1 active -> pick 1 (threat 0.9 > 0.4)
        truth[0, 4] = True
        truth[1, 4] = True

        scheduler = OracleScheduler(truth=truth)
        scheduler.reset(config)

        actions = [scheduler.act(None).bands[0] for _ in range(5)]
        assert actions == [0, 1, 2, 0, 1]

    def test_idle_slots_fallback(self):
        # No bands active at any slot -> fallback to round-robin sweep
        truth = np.zeros((3, 6), dtype=bool)
        config = make_test_config(n_bands=3, n_slots=6)

        scheduler = OracleScheduler(truth=truth)
        scheduler.reset(config)

        actions = [scheduler.act(None).bands[0] for _ in range(6)]
        assert actions == [0, 1, 2, 0, 1, 2]

    def test_reset_restarts_sequence(self):
        truth = np.zeros((2, 4), dtype=bool)
        truth[1, :] = True  # Band 1 always active
        config = make_test_config(n_bands=2, n_slots=4)

        scheduler = OracleScheduler(truth=truth)
        scheduler.reset(config)
        first_run = [scheduler.act(None).bands[0] for _ in range(4)]

        scheduler.reset(config)
        second_run = [scheduler.act(None).bands[0] for _ in range(4)]

        assert first_run == second_run == [1, 1, 1, 1]

    def test_oracle_interception_ceiling_with_rf_environment(self):
        # Multi-emitter RFEnvironment scenario
        emitters = (
            EmitterInfo(
                band=0,
                snr=25.0,
                threat_level=1.0,
                emitter_type="gilbert_elliott",
                params={"p01": 0.3, "p10": 0.3},
            ),
            EmitterInfo(
                band=2,
                snr=25.0,
                threat_level=0.8,
                emitter_type="periodic",
                params={"period": 4, "dwell": 1},
            ),
            EmitterInfo(
                band=3,
                snr=25.0,
                threat_level=0.5,
                emitter_type="cw",
            ),
        )
        config = make_test_config(
            n_bands=5,
            n_slots=200,
            emitters=emitters,
            pfa=1e-6,
            detection_threshold=None,
            seed=42,
        )

        # Run environment with Oracle
        env = RFEnvironment(config)
        env.reset()
        truth = env.truth

        oracle = OracleScheduler(truth=truth)
        oracle.reset(config)

        rr = RoundRobinScheduler()
        rr.reset(config)

        rnd = UniformRandomScheduler(seed=123)
        rnd.reset(config)

        # Calculate max theoretical hits (slots with at least 1 transmitting emitter)
        slots_with_transmission = np.sum(np.any(truth, axis=0))

        # Check Oracle action selection against truth
        oracle_active_intercepts = 0
        for t in range(config.n_slots):
            action = oracle.act(None)
            if truth[action.bands[0], t]:
                oracle_active_intercepts += 1

        # Oracle must intercept an active transmission in 100% of slots with transmission
        assert oracle_active_intercepts == slots_with_transmission

        # Evaluate RoundRobin and Random on the exact same truth
        rr_intercepts = sum(1 for t in range(config.n_slots) if truth[rr.act(None).bands[0], t])
        rnd_intercepts = sum(1 for t in range(config.n_slots) if truth[rnd.act(None).bands[0], t])

        # Oracle strictly beats round-robin and uniform random
        assert oracle_active_intercepts > rr_intercepts
        assert oracle_active_intercepts > rnd_intercepts
