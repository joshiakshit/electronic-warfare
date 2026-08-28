"""Objective 3: scheduler information boundary.

Blind schedulers must not receive emitter tuples or hidden truth. Only the
Oracle receives the generated truth matrix. A prior-aided run supplies an
explicit ThreatPrior with provenance.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.ucb import UCB1Scheduler
from ewscan.agents.thompson import ThompsonSamplingScheduler
from ewscan.contracts import (
    EmitterInfo,
    EpisodeConfig,
    Observation,
    SchedulerConfig,
    ThreatPrior,
    as_scheduler_config,
    scheduler_config_from_episode,
)


def _config(emitters=(), n_bands=4, k=1, n_slots=20, seed=0) -> EpisodeConfig:
    return EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=tuple(emitters),
        pfa=1e-3,
        seed=seed,
    )


class TestThreatPriorContract:
    def test_requires_provenance(self):
        with pytest.raises(ValueError, match="provenance"):
            ThreatPrior(weights=(0.1, 0.2), provenance="   ")

    def test_rejects_negative_weight(self):
        with pytest.raises(ValueError, match="non-negative"):
            ThreatPrior(weights=(0.1, -0.2), provenance="intel")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="non-empty"):
            ThreatPrior(weights=(), provenance="intel")

    def test_keeps_provenance_and_weights(self):
        p = ThreatPrior(weights=(0.1, 0.9), provenance="external-sigint")
        assert p.provenance == "external-sigint"
        assert p.weights == (0.1, 0.9)


class TestSchedulerConfigBlind:
    def test_has_no_emitter_tuple(self):
        sc = scheduler_config_from_episode(_config())
        assert not hasattr(sc, "emitters")

    def test_exposes_only_operator_visible_fields(self):
        cfg = _config(
            emitters=(EmitterInfo(band=1, snr=20.0, threat_level=0.9, emitter_type="cw"),)
        )
        sc = scheduler_config_from_episode(cfg)
        assert sc.n_bands == cfg.n_bands
        assert sc.n_slots == cfg.n_slots
        assert sc.k == cfg.k
        assert sc.seed == cfg.seed
        assert sc.dwell == cfg.dwell
        assert sc.retune_cost_slots == cfg.retune_cost_slots
        assert sc.detector_capability == cfg.detector_capability
        assert sc.threat_prior is None

    def test_prior_weight_length_must_match_bands(self):
        with pytest.raises(ValueError, match="n_bands"):
            SchedulerConfig(
                n_bands=4,
                n_slots=10,
                k=1,
                detector_capability=_config().detector_capability,
                threat_prior=ThreatPrior(weights=(0.1, 0.2), provenance="x"),
            )

    def test_as_scheduler_config_from_episode_is_blind(self):
        sc = as_scheduler_config(_config())
        assert isinstance(sc, SchedulerConfig)
        assert not hasattr(sc, "emitters")

    def test_as_scheduler_config_passthrough(self):
        sc = scheduler_config_from_episode(_config())
        assert as_scheduler_config(sc) is sc


class TestBlindInformationIsolation:
    def test_hidden_metadata_does_not_change_blind_decisions(self):
        # Two configs differ only in hidden emitter metadata. The blind
        # scheduler-visible config must be identical, so with identical
        # observation streams the actions are identical.
        cfg_a = _config(
            emitters=(EmitterInfo(band=0, snr=20.0, threat_level=0.1, emitter_type="cw"),)
        )
        cfg_b = _config(
            emitters=(
                EmitterInfo(band=0, snr=5.0, threat_level=0.9, emitter_type="cw"),
                EmitterInfo(band=2, snr=30.0, threat_level=0.5, emitter_type="cw"),
            )
        )
        assert scheduler_config_from_episode(cfg_a) == scheduler_config_from_episode(cfg_b)

        obs_stream = [
            None,
            Observation(slot=0, bands=(0,), detections=(True,)),
            Observation(slot=1, bands=(1,), detections=(False,)),
            Observation(slot=2, bands=(2,), detections=(True,)),
        ]

        def run(cfg):
            s = UCB1Scheduler(use_threat_weighting=True, seed=7)
            s.reset(cfg)
            return [tuple(s.act(o).bands) for o in obs_stream]

        assert run(cfg_a) == run(cfg_b)

    def test_threat_weighting_uniform_without_prior(self):
        # Without a prior the threat map is uniform, so emitter threat levels
        # cannot bias a blind scheduler.
        cfg = _config(
            emitters=(EmitterInfo(band=3, snr=20.0, threat_level=5.0, emitter_type="cw"),)
        )
        s = UCB1Scheduler(use_threat_weighting=True, seed=0)
        s.reset(cfg)
        assert np.all(s._threat_map == s._threat_map[0])


class TestPriorAidedInput:
    def test_prior_shapes_threat_map(self):
        cfg = _config()
        prior = ThreatPrior(weights=(0.1, 0.1, 0.1, 0.9), provenance="intel")
        sc = scheduler_config_from_episode(cfg, threat_prior=prior)
        s = ThompsonSamplingScheduler(use_threat_weighting=True, seed=0)
        s.reset(sc)
        assert s._threat_map[3] == pytest.approx(0.9)
        assert s._threat_map[0] == pytest.approx(0.1)


class TestRunnerTrackLabels:
    def _scenario(self):
        return _config(
            emitters=(
                EmitterInfo(
                    band=1, snr=20.0, threat_level=0.9,
                    emitter_type="gilbert_elliott", params={"p01": 0.2, "p10": 0.2},
                ),
            ),
            n_slots=40,
        )

    def test_blind_run_is_labelled_blind(self):
        from ewscan.experiments.runner import run_episode

        res = run_episode(self._scenario(), UCB1Scheduler(seed=0), seed=1)
        assert res.track == "blind"
        assert res.to_dict()["track"] == "blind"

    def test_prior_aided_run_is_labelled(self):
        from ewscan.experiments.runner import run_episode

        prior = ThreatPrior(weights=(0.1, 0.9, 0.1, 0.1), provenance="intel")
        res = run_episode(
            self._scenario(), UCB1Scheduler(seed=0), seed=1, threat_prior=prior
        )
        assert res.track == "prior_aided"

    def test_oracle_run_is_labelled_oracle(self):
        from ewscan.agents.baselines import OracleScheduler
        from ewscan.experiments.runner import run_episode

        res = run_episode(self._scenario(), OracleScheduler(), seed=1)
        assert res.track == "oracle"


class TestOracleOnlyTruth:
    def test_only_oracle_receives_truth(self):
        # A blind scheduler receives a SchedulerConfig with no truth and no
        # emitter data; the environment truth reaches only the Oracle.
        from ewscan.agents.baselines import OracleScheduler

        captured = {}

        class SpyUCB(UCB1Scheduler):
            def reset(self, config):
                captured["type"] = type(config).__name__
                captured["has_emitters"] = hasattr(config, "emitters")
                captured["has_truth"] = hasattr(config, "truth")
                super().reset(config)

        from ewscan.experiments.runner import run_episode

        cfg = _config(
            emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
            n_slots=30,
        )
        run_episode(cfg, SpyUCB(seed=0), seed=1)
        assert captured["type"] == "SchedulerConfig"
        assert captured["has_emitters"] is False
        assert captured["has_truth"] is False

        oracle = OracleScheduler()
        run_episode(cfg, oracle, seed=1)
        assert oracle.truth is not None

    def test_non_oracle_set_truth_method_does_not_receive_truth(self):
        from ewscan.experiments.runner import run_episode

        class TruthProbe(UCB1Scheduler):
            truth_received = False

            def set_truth(self, truth):
                self.truth_received = True

        cfg = _config(
            emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
            n_slots=10,
        )
        scheduler = TruthProbe(seed=0)

        result = run_episode(cfg, scheduler, seed=1)

        assert scheduler.truth_received is False
        assert result.track == "blind"
