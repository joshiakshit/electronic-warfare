"""Tests for variable dwell time (d-look non-coherent integration).

Verifies the d-look ROC in ewscan/env/detection.py, EpisodeConfig/config
plumbing for the dwell field, RNG-stream parity (detect draws exactly one
uniform at any dwell), and the resulting episode-level Pd effect.
"""

from __future__ import annotations

from dataclasses import replace

import numpy as np
import pytest

from ewscan.agents.baselines import RoundRobinScheduler
from ewscan.config import config_from_dict, config_to_dict, dump_config, load_config_from_yaml
from ewscan.contracts import EpisodeConfig
from ewscan.env.detection import (
    DetectionModel,
    pd_from_snr,
    pd_from_snr_dlook,
    pfa_from_threshold,
    pfa_from_threshold_dlook,
    threshold_from_pfa,
)
from ewscan.experiments.runner import run_episode
from ewscan.experiments.scenarios import make_mixed_threat_scenario


# ---------------------------------------------------------------------------
# 1. Parity at dwell = 1
# ---------------------------------------------------------------------------

class TestDlookParityAtDwellOne:
    @pytest.mark.parametrize("snr_db", [-3, 0, 6, 12])
    @pytest.mark.parametrize("pfa", [1e-2, 1e-4])
    def test_pd_parity(self, snr_db, pfa):
        threshold = threshold_from_pfa(pfa)
        assert pd_from_snr_dlook(snr_db, threshold, 1) == pd_from_snr(snr_db, threshold)

    @pytest.mark.parametrize("pfa", [1e-2, 1e-4])
    def test_pfa_parity(self, pfa):
        threshold = threshold_from_pfa(pfa)
        assert pfa_from_threshold_dlook(threshold, 1) == pfa_from_threshold(threshold)


# ---------------------------------------------------------------------------
# 2. Monotone gain and the non-CFAR Pfa direction
# ---------------------------------------------------------------------------

class TestDlookMonotonicity:
    """Integration gain at the operating points this simulator actually uses.

    Non-CFAR (decision D-A1): the same per-look threshold is summed to
    d*lambda. Whether Pfa_d rises or falls with d depends on lambda against
    the noise-only mean (scale=1). Every realistic pfa gives lambda > 1, so
    Pfa_d falls with d. It only rises when pfa > 1/e.
    """

    @pytest.mark.parametrize("pfa", [1e-2, 1e-4])
    def test_pd_increases_with_dwell_above_threshold_snr(self, pfa):
        threshold = threshold_from_pfa(pfa)
        snr_db = 15.0

        pd_vals = [pd_from_snr_dlook(snr_db, threshold, d) for d in range(1, 9)]

        for i in range(len(pd_vals) - 1):
            assert pd_vals[i + 1] > pd_vals[i]
        assert pd_vals[3] > pd_vals[0]  # d=4 vs d=1

    @pytest.mark.parametrize("pfa", [1e-2, 1e-4])
    def test_pfa_falls_with_dwell_at_realistic_thresholds(self, pfa):
        threshold = threshold_from_pfa(pfa)
        assert threshold > 1.0

        pfa_vals = [pfa_from_threshold_dlook(threshold, d) for d in range(1, 9)]

        for i in range(len(pfa_vals) - 1):
            assert pfa_vals[i + 1] < pfa_vals[i]

    def test_pfa_rises_with_dwell_only_below_unit_threshold(self):
        threshold = threshold_from_pfa(0.5)
        assert threshold < 1.0

        pfa_vals = [pfa_from_threshold_dlook(threshold, d) for d in range(1, 9)]

        for i in range(len(pfa_vals) - 1):
            assert pfa_vals[i + 1] > pfa_vals[i]

    def test_weak_signal_loses_pd_with_dwell(self):
        """Below the per-look threshold, integration hurts. Not a free lunch."""
        threshold = threshold_from_pfa(1e-4)
        snr_db = 0.0

        pd_vals = [pd_from_snr_dlook(snr_db, threshold, d) for d in range(1, 5)]

        for i in range(len(pd_vals) - 1):
            assert pd_vals[i + 1] < pd_vals[i]


# ---------------------------------------------------------------------------
# 3. Closed form vs Monte Carlo (draw sum-of-d-exponentials directly)
# ---------------------------------------------------------------------------

class TestDlookMonteCarlo:
    N = 200_000

    @pytest.mark.parametrize("dwell", [2, 4])
    def test_closed_form_matches_monte_carlo(self, dwell):
        pfa = 0.1
        threshold = threshold_from_pfa(pfa)
        snr_db = 6.0
        snr_lin = 10.0 ** (snr_db / 10.0)
        lam = dwell * threshold
        rng = np.random.default_rng(2024)

        samples_h0 = rng.gamma(shape=dwell, scale=1.0, size=self.N)
        empirical_pfa = float(np.mean(samples_h0 > lam))
        analytic_pfa = pfa_from_threshold_dlook(threshold, dwell)
        se_pfa = np.sqrt(analytic_pfa * (1 - analytic_pfa) / self.N)
        assert abs(empirical_pfa - analytic_pfa) < 3 * se_pfa

        samples_h1 = rng.gamma(shape=dwell, scale=1.0 + snr_lin, size=self.N)
        empirical_pd = float(np.mean(samples_h1 > lam))
        analytic_pd = pd_from_snr_dlook(snr_db, threshold, dwell)
        se_pd = np.sqrt(analytic_pd * (1 - analytic_pd) / self.N)
        assert abs(empirical_pd - analytic_pd) < 3 * se_pd


# ---------------------------------------------------------------------------
# 4. Config round-trip
# ---------------------------------------------------------------------------

class TestDwellConfigRoundTrip:
    def _base_data(self):
        return {
            "n_bands": 8,
            "n_slots": 100,
            "k": 1,
            "pfa": 1e-3,
        }

    def test_dwell_missing_defaults_to_one(self):
        config = config_from_dict(self._base_data())
        assert config.dwell == 1

    def test_dwell_roundtrips_through_dict(self):
        data = self._base_data()
        data["dwell"] = 4
        config = config_from_dict(data)
        assert config.dwell == 4
        assert config_to_dict(config)["dwell"] == 4

    def test_dwell_roundtrips_through_yaml(self):
        data = self._base_data()
        data["dwell"] = 4
        config = config_from_dict(data)
        yaml_str = dump_config(config)
        loaded = load_config_from_yaml(yaml_str)
        assert loaded.dwell == 4


# ---------------------------------------------------------------------------
# 5. EpisodeConfig validation
# ---------------------------------------------------------------------------

class TestEpisodeConfigDwellValidation:
    @pytest.mark.parametrize("bad_dwell", [0, -1, True, 1.5])
    def test_invalid_dwell_raises(self, bad_dwell):
        with pytest.raises(ValueError, match="dwell"):
            EpisodeConfig(
                n_bands=4,
                n_slots=10,
                k=1,
                emitters=(),
                detection_threshold=None,
                pfa=1e-3,
                dwell=bad_dwell,
            )


class TestDetectionModelDwellValidation:
    @pytest.mark.parametrize("bad_dwell", [0, -1, True, 1.5])
    def test_invalid_dwell_raises(self, bad_dwell):
        with pytest.raises(ValueError, match="dwell"):
            DetectionModel(pfa=1e-3, dwell=bad_dwell)


# ---------------------------------------------------------------------------
# 6. Episode-level effect
# ---------------------------------------------------------------------------

class TestEpisodeLevelDwellEffect:
    def test_measured_pd_higher_at_dwell_four(self):
        base_config = make_mixed_threat_scenario()
        config_d1 = replace(base_config, dwell=1)
        config_d4 = replace(base_config, dwell=4)

        result_d1 = run_episode(config_d1, RoundRobinScheduler())
        result_d4 = run_episode(config_d4, RoundRobinScheduler())

        assert result_d4.detection.pd.pd > result_d1.detection.pd.pd


# ---------------------------------------------------------------------------
# RNG-stream parity (bug analysis: detect must draw exactly one uniform)
# ---------------------------------------------------------------------------

class TestRngStreamParity:
    @pytest.mark.parametrize("dwell", [1, 2, 4, 8, 16])
    def test_detect_consumes_exactly_one_draw(self, dwell):
        rng_a = np.random.default_rng(123)
        rng_b = np.random.default_rng(123)

        dm = DetectionModel(pfa=1e-3, dwell=dwell)
        dm.reset(rng_a)
        dm.detect(10.0, transmitting=True)

        rng_b.random()  # the reference: exactly one draw

        assert rng_a.bit_generator.state == rng_b.bit_generator.state

    @pytest.mark.parametrize("dwell", [1, 3, 8])
    def test_detect_batch_consumes_exactly_one_draw_per_element(self, dwell):
        n = 50
        transmitting = np.zeros(n, dtype=bool)
        transmitting[::2] = True

        rng_a = np.random.default_rng(7)
        rng_b = np.random.default_rng(7)

        dm = DetectionModel(pfa=1e-3, dwell=dwell)
        dm.reset(rng_a)
        dm.detect_batch(np.full(n, 10.0), transmitting)

        rng_b.random(n)  # the reference: exactly one draw per element

        assert rng_a.bit_generator.state == rng_b.bit_generator.state


# ---------------------------------------------------------------------------
# d=1 bit-for-bit parity of DetectionModel.detect against the legacy formulas
# ---------------------------------------------------------------------------

class TestDetectDwellOneBitForBitParity:
    def test_detect_sequence_matches_legacy_formulas(self):
        pfa = 1e-3
        threshold = threshold_from_pfa(pfa)
        snr_db = 10.0

        dm = DetectionModel(pfa=pfa, dwell=1)
        rng = np.random.default_rng(555)
        dm.reset(rng)
        actual = [dm.detect(snr_db, transmitting=(i % 2 == 0)) for i in range(500)]

        ref_rng = np.random.default_rng(555)
        expected = []
        for i in range(500):
            u = ref_rng.random()
            p = pd_from_snr(snr_db, threshold) if i % 2 == 0 else pfa_from_threshold(threshold)
            expected.append(bool(u < p))

        assert actual == expected
