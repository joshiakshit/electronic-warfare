"""K>1 parallel action space: contracts, environment, and metric redefinition."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog, Observation, ScanAction
from ewscan.env.environment import RFEnvironment
from ewscan.env.recorder import load_episode_log, save_episode_log
from ewscan.metrics.detection import estimate_detection_metrics
from ewscan.metrics.first_intercept import estimate_first_intercept_metrics
from ewscan.metrics.interception import estimate_interception_metrics
from ewscan.metrics.time_error import estimate_time_error_metrics
from ewscan.testing.fixtures import synthetic_log


def _golden_k2_log() -> EpisodeLog:
    """A hand-computable k=2 episode with a perfect detector.

    Bands: 0 ON every slot, 1 ON at slots 1-2, 2 always OFF.
    Actions per slot (channel 0, channel 1):
      s0 (0,1)  s1 (0,2)  s2 (1,2)  s3 (0,1)
    Detections equal truth at the scanned cells (Pd=1, Pfa=0).
    """
    n_bands, n_slots, k = 3, 4, 2
    truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
    truth[0, :] = True
    truth[1, 1:3] = True

    actions = np.array([[0, 1], [0, 2], [1, 2], [0, 1]], dtype=np.intp)
    detections = np.array(
        [[bool(truth[actions[t, j], t]) for j in range(k)] for t in range(n_slots)],
        dtype=np.bool_,
    )
    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=(
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),
            EmitterInfo(
                band=1,
                snr=15.0,
                threat_level=0.8,
                emitter_type="periodic",
                params={"period": 4, "dwell": 2, "phase": 1},
            ),
        ),
        detection_threshold=None,
        pfa=1e-3,
        seed=0,
    )
    return EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)


class TestContracts:
    def test_scanaction_rejects_duplicate_bands(self):
        with pytest.raises(ValueError, match="Duplicate"):
            ScanAction(bands=(1, 1))

    def test_scanaction_coerces_list(self):
        a = ScanAction(bands=[2, 0])
        assert a.bands == (2, 0)

    def test_observation_orders_align(self):
        obs = Observation(slot=3, bands=(2, 0), detections=(True, False))
        assert obs.bands == (2, 0)
        assert obs.detections == (True, False)

    def test_config_rejects_k_out_of_range(self):
        with pytest.raises(ValueError, match="1 <= k <= n_bands"):
            EpisodeConfig(4, 10, 5, (), None, 1e-3)
        with pytest.raises(ValueError, match="1 <= k <= n_bands"):
            EpisodeConfig(4, 10, 0, (), None, 1e-3)

    def test_config_allows_k_equal_n_bands(self):
        cfg = EpisodeConfig(4, 10, 4, (), None, 1e-3)
        assert cfg.k == 4

    def test_log_exposes_k_and_enforces_2d(self):
        log = _golden_k2_log()
        assert log.k == 2
        assert log.actions.shape == (4, 2)
        assert log.detections.shape == (4, 2)

    def test_log_rejects_wrong_action_shape(self):
        cfg = EpisodeConfig(3, 4, 2, (), None, 1e-3)
        truth = np.zeros((3, 4), dtype=np.bool_)
        bad = np.zeros(4, dtype=np.intp)  # 1D, should be (4, 2)
        with pytest.raises(ValueError, match="actions shape"):
            EpisodeLog(config=cfg, truth=truth, actions=bad, detections=np.zeros((4, 2), dtype=np.bool_))


class TestEnvironment:
    def _env(self, k: int) -> RFEnvironment:
        cfg = EpisodeConfig(
            n_bands=3,
            n_slots=5,
            k=k,
            emitters=(EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw"),),
            detection_threshold=None,
            pfa=1e-3,
            seed=0,
        )
        env = RFEnvironment(cfg)
        env.reset(seed=0)
        return env

    def test_step_returns_k_aligned_observation_and_advances_once(self):
        env = self._env(k=2)
        obs = env.step(ScanAction(bands=(0, 1)))
        assert obs.slot == 0
        assert len(obs.bands) == 2
        assert len(obs.detections) == 2
        assert env.slot == 1  # one advance per step

    def test_step_rejects_wrong_length(self):
        env = self._env(k=2)
        with pytest.raises(ValueError, match="expected k=2"):
            env.step(ScanAction(bands=(0,)))

    def test_step_rejects_out_of_range_band(self):
        env = self._env(k=2)
        with pytest.raises(ValueError, match="out of valid range"):
            env.step(ScanAction(bands=(0, 9)))


class TestGoldenK2Metrics:
    def test_detection(self):
        m = estimate_detection_metrics(_golden_k2_log())
        assert m.pd.pd == pytest.approx(1.0)
        assert m.pd.n_hits == 4
        assert m.pd.n_scans_on == 4
        assert m.pfa.pfa == pytest.approx(0.0)
        assert m.pfa.n_scans_off == 4

    def test_interception(self):
        m = estimate_interception_metrics(_golden_k2_log())
        assert m.interception_ratio.n_transmissions == 6
        assert m.interception_ratio.n_hits == 4
        assert m.interception_ratio.ratio == pytest.approx(4 / 6)
        assert m.intercept_rate.rate == pytest.approx(1.0)
        by_band = {e.band: e for e in m.per_emitter}
        assert by_band[0].interception_ratio == pytest.approx(3 / 4)
        assert by_band[1].interception_ratio == pytest.approx(1 / 2)

    def test_first_intercept(self):
        m = estimate_first_intercept_metrics(_golden_k2_log())
        slots = {e.band: e.first_intercept_slot for e in m.per_emitter}
        assert slots[0] == 0
        assert slots[1] == 2
        assert m.mean_time_to_first_intercept == pytest.approx(1.0)

    def test_time_error(self):
        m = estimate_time_error_metrics(_golden_k2_log())
        assert m.mean_time_error == pytest.approx(0.5)
        assert m.n_intercepted_bursts == 2


class TestRoundTrip:
    @pytest.mark.parametrize("suffix", [".json", ".npz"])
    def test_2d_save_load(self, tmp_path, suffix):
        log = _golden_k2_log()
        path = tmp_path / f"log{suffix}"
        save_episode_log(log, path)
        loaded = load_episode_log(path)
        assert loaded.actions.shape == (4, 2)
        assert loaded.detections.shape == (4, 2)
        np.testing.assert_array_equal(loaded.actions, log.actions)
        np.testing.assert_array_equal(loaded.detections, log.detections)


class TestK1Parity:
    """The k=1 synthetic log must still yield its known hand-computed results."""

    def test_known_interception_ratio(self):
        log = synthetic_log(n_bands=4, n_slots=20)
        assert log.actions.shape == (20, 1)
        m = estimate_interception_metrics(log)
        assert m.interception_ratio.n_hits == 9
        assert m.interception_ratio.n_transmissions == 32

    def test_known_first_intercepts(self):
        log = synthetic_log(n_bands=4, n_slots=20)
        slots = {e.band: e.first_intercept_slot for e in estimate_first_intercept_metrics(log).per_emitter}
        assert slots[0] == 0
        assert slots[1] == 5
        assert slots[2] == 6
