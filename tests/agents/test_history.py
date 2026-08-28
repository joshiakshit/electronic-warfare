"""Tests for the hit-history ring buffer (Sprint 3, Task 1)."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.agents.history import HitHistory


def test_append_below_capacity_returns_in_order():
    history = HitHistory(n_bands=2, capacity=5)
    history.append(0, 10, True)
    history.append(0, 11, False)
    history.append(0, 12, True)

    slots, detections = history.recent(0)

    assert list(slots) == [10, 11, 12]
    assert list(detections) == [True, False, True]


def test_wrap_returns_last_n_in_chronological_order():
    history = HitHistory(n_bands=1, capacity=3)
    for slot, detection in [(0, True), (1, False), (2, True), (3, False), (4, True)]:
        history.append(0, slot, detection)

    slots, detections = history.recent(0)

    # Oldest two writes (slot 0, slot 1) were overwritten; the remaining three
    # must read out oldest-to-newest, not in raw ring-physical order.
    assert list(slots) == [2, 3, 4]
    assert list(detections) == [True, False, True]


def test_count_caps_at_capacity_and_slots_outcomes_align_with_recent():
    history = HitHistory(n_bands=1, capacity=3)
    for slot, detection in [(0, True), (1, False), (2, True), (3, False), (4, True)]:
        history.append(0, slot, detection)

    assert history.count(0) == 3

    recent_slots, recent_detections = history.recent(0)
    assert list(history.slots(0)) == list(recent_slots)
    assert list(history.outcomes(0)) == list(recent_detections)


def test_multi_band_isolation():
    history = HitHistory(n_bands=2, capacity=5)
    history.append(0, 0, True)
    history.append(0, 1, True)

    assert history.count(1) == 0
    slots, detections = history.recent(1)
    assert len(slots) == 0
    assert len(detections) == 0

    assert history.count(0) == 2


def test_reset_clears_all_counts_and_cursors():
    history = HitHistory(n_bands=2, capacity=3)
    history.append(0, 0, True)
    history.append(1, 0, False)
    history.append(1, 1, True)

    history.reset()

    assert history.count(0) == 0
    assert history.count(1) == 0
    slots, detections = history.recent(0)
    assert len(slots) == 0
    assert len(detections) == 0

    # Buffer must be reusable after reset, starting fresh from the beginning.
    history.append(0, 5, True)
    slots, detections = history.recent(0)
    assert list(slots) == [5]
    assert list(detections) == [True]


def test_out_of_range_band_raises_index_error():
    history = HitHistory(n_bands=2, capacity=3)

    with pytest.raises(IndexError):
        history.append(2, 0, True)

    with pytest.raises(IndexError):
        history.append(-1, 0, True)

    with pytest.raises(IndexError):
        history.recent(2)

    with pytest.raises(IndexError):
        history.count(5)


def test_dtypes_are_intp_and_bool():
    history = HitHistory(n_bands=1, capacity=3)
    history.append(0, 7, True)

    slots, detections = history.recent(0)
    assert slots.dtype == np.intp
    assert detections.dtype == np.bool_
