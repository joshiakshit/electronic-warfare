"""Tests for the online p01/p10 transition estimator (Task 2)."""

import numpy as np

from ewscan.agents.transition import TransitionEstimator


def test_deterministic_sequence_matches_counts_and_formula():
    est = TransitionEstimator(n_bands=1)
    # ON/OFF sequence at consecutive slots 0..6 for band 0.
    sequence = [False, True, True, False, False, False, True]
    for slot in range(1, len(sequence)):
        est.update(
            band=0,
            prev_slot=slot - 1,
            prev_det=sequence[slot - 1],
            cur_slot=slot,
            cur_det=sequence[slot],
        )

    # Hand count transitions between consecutive pairs:
    # (F,T) (T,T) (T,F) (F,F) (F,F) (F,T)
    # n_00 = 2 (F,F)+(F,F), n_01 = 2 ((F,T),(F,T)), n_10 = 1 ((T,F)), n_11 = 1 ((T,T))
    counts = est.counts(0)
    assert counts == {"n_00": 2, "n_01": 2, "n_10": 1, "n_11": 1}

    expected_p01 = (2 + 1) / (2 + 2 + 2)
    expected_p10 = (1 + 1) / (1 + 1 + 2)
    assert est.p01()[0] == expected_p01
    assert est.p10()[0] == expected_p10


def test_gap_skipping_does_not_count():
    est = TransitionEstimator(n_bands=1)
    before = est.counts(0)
    est.update(band=0, prev_slot=0, prev_det=False, cur_slot=2, cur_det=True)
    after = est.counts(0)
    assert after == before == {"n_00": 0, "n_01": 0, "n_10": 0, "n_11": 0}
    assert est.p01()[0] == 0.5
    assert est.p10()[0] == 0.5


def test_convergence_high_snr():
    rng = np.random.default_rng(12345)
    p01_true = 0.1
    p10_true = 0.3

    n_slots = 5000
    truth = np.empty(n_slots, dtype=bool)
    truth[0] = rng.random() < (p01_true / (p01_true + p10_true))
    for t in range(1, n_slots):
        if truth[t - 1]:
            truth[t] = rng.random() >= p10_true
        else:
            truth[t] = rng.random() < p01_true

    est = TransitionEstimator(n_bands=1)
    for t in range(n_slots):
        est.observe(band=0, slot=t, det=bool(truth[t]))

    assert abs(est.p01()[0] - p01_true) < 0.03
    assert abs(est.p10()[0] - p10_true) < 0.03


def test_prior_at_zero_data():
    est = TransitionEstimator(n_bands=3)
    np.testing.assert_array_equal(est.p01(), np.full(3, 0.5))
    np.testing.assert_array_equal(est.p10(), np.full(3, 0.5))


def test_multi_band_isolation():
    est = TransitionEstimator(n_bands=2)
    est.observe(band=0, slot=0, det=False)
    est.observe(band=0, slot=1, det=True)
    est.observe(band=1, slot=0, det=True)
    est.observe(band=1, slot=1, det=True)

    band0_counts = est.counts(0)
    band1_counts = est.counts(1)

    assert band0_counts == {"n_00": 0, "n_01": 1, "n_10": 0, "n_11": 0}
    assert band1_counts == {"n_00": 0, "n_01": 0, "n_10": 0, "n_11": 1}

    assert est.p01()[0] != est.p01()[1]
    assert est.p10()[0] != est.p10()[1]
