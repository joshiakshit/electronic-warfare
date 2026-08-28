"""Objective 4: EpisodeLog validates its arrays and action contracts."""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog


def _config(n_bands=2, n_slots=3, k=1, n_emitters=1) -> EpisodeConfig:
    emitters = tuple(
        EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw")
        for _ in range(n_emitters)
    )
    return EpisodeConfig(
        n_bands=n_bands, n_slots=n_slots, k=k, emitters=emitters, pfa=1e-3, seed=0
    )


def _ok_arrays(cfg):
    truth = np.zeros((cfg.n_bands, cfg.n_slots), dtype=bool)
    actions = np.zeros((cfg.n_slots, cfg.k), dtype=np.intp)
    detections = np.zeros((cfg.n_slots, cfg.k), dtype=bool)
    return truth, actions, detections


def test_action_out_of_range_rejected():
    cfg = _config()
    truth, actions, detections = _ok_arrays(cfg)
    actions[0, 0] = 5  # n_bands is 2
    with pytest.raises(ValueError, match="out of range"):
        EpisodeLog(config=cfg, truth=truth, actions=actions, detections=detections)


def test_duplicate_bands_within_slot_rejected():
    cfg = _config(n_bands=3, k=2)
    truth, actions, detections = _ok_arrays(cfg)
    actions[0] = [1, 1]  # duplicate within a slot
    with pytest.raises(ValueError, match="duplicate"):
        EpisodeLog(config=cfg, truth=truth, actions=actions, detections=detections)


def test_valid_slots_wrong_shape_rejected():
    cfg = _config()
    truth, actions, detections = _ok_arrays(cfg)
    with pytest.raises(ValueError, match="valid_slots"):
        EpisodeLog(
            config=cfg, truth=truth, actions=actions, detections=detections,
            valid_slots=np.ones(cfg.n_slots + 1, dtype=bool),
        )


def test_emitter_truth_requires_emitter_bands():
    cfg = _config()
    truth, actions, detections = _ok_arrays(cfg)
    with pytest.raises(ValueError, match="both"):
        EpisodeLog(
            config=cfg, truth=truth, actions=actions, detections=detections,
            emitter_truth=np.zeros((1, cfg.n_slots), dtype=bool),
        )


def test_emitter_truth_wrong_shape_rejected():
    cfg = _config(n_emitters=2)
    truth, actions, detections = _ok_arrays(cfg)
    with pytest.raises(ValueError, match="emitter_truth"):
        EpisodeLog(
            config=cfg, truth=truth, actions=actions, detections=detections,
            emitter_truth=np.zeros((1, cfg.n_slots), dtype=bool),  # expected 2 rows
            emitter_bands=np.zeros((1, cfg.n_slots), dtype=np.intp),
        )


def test_emitter_bands_out_of_range_rejected():
    cfg = _config()
    truth, actions, detections = _ok_arrays(cfg)
    bands = np.zeros((1, cfg.n_slots), dtype=np.intp)
    bands[0, 0] = 9  # out of range
    with pytest.raises(ValueError, match="emitter_bands"):
        EpisodeLog(
            config=cfg, truth=truth, actions=actions, detections=detections,
            emitter_truth=np.ones((1, cfg.n_slots), dtype=bool),
            emitter_bands=bands,
        )


def test_detections_shape_mismatch_rejected():
    cfg = _config(k=2, n_bands=3)
    truth, actions, _ = _ok_arrays(cfg)
    bad_detections = np.zeros((cfg.n_slots, 1), dtype=bool)  # k should be 2
    with pytest.raises(ValueError, match="detections shape"):
        EpisodeLog(config=cfg, truth=truth, actions=actions, detections=bad_detections)
