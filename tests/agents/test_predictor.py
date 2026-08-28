"""Tests for the next-transmission predictor (Sprint 3, Task 6)."""

from __future__ import annotations

import numpy as np

from ewscan.agents.predictor import NextTxPredictor


def _feed(predictor: NextTxPredictor, band: int, slot: int, is_on: bool) -> None:
    # Score the standing prediction for this slot against the model state as
    # it was BEFORE this slot's own detection is folded in, then update.
    predictor.record_outcome(band, slot, is_on)
    predictor.observe(band, slot, is_on)


def test_catch_up_loop_recovers_prediction_after_scan_gap():
    period = 10
    predictor = NextTxPredictor(n_bands=1, capacity=200, tau_conf=0.6, window=20)

    # Warm up: dense scan builds the period estimate and pushes confidence
    # above tau_conf via real due-slot outcomes (slots 80, 90, 100, 110).
    for slot in range(120):
        _feed(predictor, 0, slot, slot % period == 0)

    assert predictor.confidence(0) >= 0.6

    # Deliberate scan gap: band goes unobserved for three full periods
    # (120..149), leaving s_last=110 behind the current slot.
    resume_slot = 150
    due = predictor.due_bands(resume_slot)
    assert any(band == 0 for band, _ in due), (
        "predictor failed to catch s_next up across the scan gap"
    )

    # Long-run accuracy after the gap: keep scanning cleanly and confirm the
    # predictor's due calls line up with truth almost every time.
    n_checks = 0
    n_correct = 0
    for slot in range(resume_slot, resume_slot + 300):
        due = predictor.due_bands(slot)
        is_on = slot % period == 0
        if any(band == 0 for band, _ in due):
            n_checks += 1
            if is_on:
                n_correct += 1
        _feed(predictor, 0, slot, is_on)

    assert n_checks > 0
    assert n_correct / n_checks > 0.9


def test_confidence_tracks_empirical_hit_rate():
    rng = np.random.default_rng(12345)
    period = 10
    predictor = NextTxPredictor(n_bands=2, capacity=400, tau_conf=0.6, window=200)
    hit_rates = {0: 0.9, 1: 0.65}

    n_slots = 4000
    for slot in range(n_slots):
        for band, p_hit in hit_rates.items():
            scheduled = slot % period == 0
            is_on = bool(scheduled and rng.random() < p_hit)
            _feed(predictor, band, slot, is_on)

    for band, p_hit in hit_rates.items():
        assert abs(predictor.confidence(band) - p_hit) < 0.1


def test_no_period_gives_no_prediction_and_prior_confidence():
    rng = np.random.default_rng(12345)
    predictor = NextTxPredictor(n_bands=1, capacity=200, tau_conf=0.6, window=20)

    for slot in range(200):
        is_on = bool(rng.random() < 0.3)
        _feed(predictor, 0, slot, is_on)

    assert predictor.confidence(0) == 0.5
    for slot in range(200, 260):
        assert predictor.due_bands(slot) == []


def test_due_bands_lists_all_due_candidates_for_caller_tie_break():
    predictor = NextTxPredictor(n_bands=2, capacity=200, tau_conf=0.6, window=20)
    period = 10

    for slot in range(120):
        is_on = slot % period == 0
        _feed(predictor, 0, slot, is_on)
        _feed(predictor, 1, slot, is_on)

    due = predictor.due_bands(120)
    due_bands_set = {band for band, _ in due}
    assert due_bands_set == {0, 1}

    # Tie-break itself is a caller (Task 7) concern; due_bands only needs to
    # expose every qualifying candidate so the caller can pick by threat.
    threat = {0: 1.0, 1: 5.0}
    chosen = max(due, key=lambda item: threat[item[0]])[0]
    assert chosen == 1


def test_unscanned_due_slot_does_not_update_confidence():
    predictor = NextTxPredictor(n_bands=1, capacity=200, tau_conf=0.6, window=20)
    period = 10

    for slot in range(100):
        is_on = slot % period == 0
        _feed(predictor, 0, slot, is_on)

    confidence_before = predictor.confidence(0)
    due = predictor.due_bands(100)
    assert any(band == 0 for band, _ in due)

    # Band is due at slot 100 but was NOT scanned: no observe()/record_outcome()
    # call is made for it. Confidence must not move.
    assert predictor.confidence(0) == confidence_before


def test_due_slot_matches_truth_exactly_no_off_by_one():
    # Addendum A guard: the slot the predictor names as due must equal the
    # slot truth is actually ON, not +-1 off it. Truth used in the test only.
    period = 10
    predictor = NextTxPredictor(n_bands=1, capacity=200, tau_conf=0.6, window=20)
    truth = {slot: (slot % period == 0) for slot in range(200)}

    for slot in range(100):
        _feed(predictor, 0, slot, truth[slot])

    for slot in range(100, 140):
        due = predictor.due_bands(slot)
        is_due = any(band == 0 for band, _ in due)
        assert is_due == truth[slot], f"slot {slot}: due={is_due}, truth={truth[slot]}"
        _feed(predictor, 0, slot, truth[slot])
