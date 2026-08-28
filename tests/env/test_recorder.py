"""Unit tests for EpisodeRecorder and EpisodeLog saving/loading -- Phase 1B.6.

Verifies:
- Action and slot index bounds checking during recording.
- Multi-step sequence recording and Observation object recording.
- Truth matrix validation.
- Output conversion to EpisodeLog with data integrity (non-mutating copies).
- Round-trip serialization equivalence for both JSON and NPZ formats.
- Error pathways for missing files and malformed payloads.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import numpy as np
import pytest

from ewscan.contracts import EmitterInfo, EpisodeConfig, EpisodeLog, Observation
from ewscan.env import (
    EpisodeRecorder,
    load_episode_log,
    save_episode_log,
)


@pytest.fixture
def sample_config() -> EpisodeConfig:
    """A standard EpisodeConfig for recorder testing."""
    return EpisodeConfig(
        n_bands=4,
        n_slots=10,
        k=1,
        emitters=(
            EmitterInfo(band=0, snr=10.0, threat_level=0.5, emitter_type="cw"),
            EmitterInfo(band=2, snr=15.0, threat_level=0.8, emitter_type="periodic", params={"period": 5}),
        ),
        detection_threshold=None,
        pfa=1e-3,
        seed=42,
    )


@pytest.fixture
def sample_truth(sample_config) -> np.ndarray:
    """A matching truth matrix of shape (n_bands, n_slots)."""
    # Band 0 always ON, others OFF
    truth = np.zeros((sample_config.n_bands, sample_config.n_slots), dtype=np.bool_)
    truth[0, :] = True
    return truth


class TestEpisodeRecorder:
    """Tests for the EpisodeRecorder class."""

    def test_recorder_initialization(self, sample_config):
        recorder = EpisodeRecorder(sample_config)
        assert recorder.config == sample_config
        assert recorder.current_slot == 0

    def test_record_step_by_step(self, sample_config, sample_truth):
        recorder = EpisodeRecorder(sample_config)
        
        # Record slot-by-slot
        for t in range(sample_config.n_slots):
            assert recorder.current_slot == t
            # Record scanning band t % 4, with detection if it was transmitting in truth
            band = t % sample_config.n_bands
            det = bool(sample_truth[band, t])
            recorder.record((band,), (det,))

        assert recorder.current_slot == sample_config.n_slots
        
        # Try recording past n_slots -> should raise IndexError
        with pytest.raises(IndexError, match="Attempted to record at slot"):
            recorder.record((0,), (False,))

    def test_record_invalid_actions(self, sample_config):
        recorder = EpisodeRecorder(sample_config)
        
        # Invalid band index (too low)
        with pytest.raises(ValueError, match="out of valid range"):
            recorder.record((-1,), (False,))

        # Invalid band index (too high)
        with pytest.raises(ValueError, match="out of valid range"):
            recorder.record((sample_config.n_bands,), (False,))

    def test_record_observation(self, sample_config, sample_truth):
        recorder = EpisodeRecorder(sample_config)
        
        obs_seq = [
            Observation(slot=0, bands=(1,), detections=(False,)),
            Observation(slot=2, bands=(0,), detections=(True,)),
            Observation(slot=1, bands=(2,), detections=(False,)),
        ]
        
        for obs in obs_seq:
            recorder.record_observation(obs)

        # The current slot should track the maximum slot recorded + 1
        assert recorder.current_slot == 3

    def test_record_observation_bounds(self, sample_config):
        recorder = EpisodeRecorder(sample_config)
        
        # Slot out of bounds
        with pytest.raises(IndexError, match="Observation slot"):
            recorder.record_observation(Observation(slot=-1, bands=(0,), detections=(False,)))
            
        with pytest.raises(IndexError, match="Observation slot"):
            recorder.record_observation(Observation(slot=sample_config.n_slots, bands=(0,), detections=(False,)))

        # Band out of bounds
        with pytest.raises(ValueError, match="Observation band"):
            recorder.record_observation(Observation(slot=0, bands=(-1,), detections=(False,)))
            
        with pytest.raises(ValueError, match="Observation band"):
            recorder.record_observation(Observation(slot=0, bands=(sample_config.n_bands,), detections=(False,)))

    def test_record_truth_matrix_validation(self, sample_config, sample_truth):
        recorder = EpisodeRecorder(sample_config)
        
        # Valid truth matrix recording
        recorder.record_truth(sample_truth)
        
        # Invalid dimensions
        bad_truth_bands = np.zeros((sample_config.n_bands + 1, sample_config.n_slots), dtype=np.bool_)
        with pytest.raises(ValueError, match="Truth matrix shape"):
            recorder.record_truth(bad_truth_bands)
            
        bad_truth_slots = np.zeros((sample_config.n_bands, sample_config.n_slots - 1), dtype=np.bool_)
        with pytest.raises(ValueError, match="Truth matrix shape"):
            recorder.record_truth(bad_truth_slots)

    def test_to_log_errors(self, sample_config, sample_truth):
        recorder = EpisodeRecorder(sample_config)
        
        # 1. No truth matrix recorded yet
        for t in range(sample_config.n_slots):
            recorder.record((t % sample_config.n_bands,), (False,))
        with pytest.raises(RuntimeError, match="ground truth matrix was not recorded"):
            recorder.to_log()

        # 2. Incomplete episode steps recorded
        recorder_incomplete = EpisodeRecorder(sample_config)
        recorder_incomplete.record_truth(sample_truth)
        recorder_incomplete.record((0,), (False,))
        with pytest.raises(ValueError, match="Expected.*steps, but only recorded"):
            recorder_incomplete.to_log()

    def test_to_log_success(self, sample_config, sample_truth):
        recorder = EpisodeRecorder(sample_config)
        recorder.record_truth(sample_truth)
        
        actions = []
        detections = []
        for t in range(sample_config.n_slots):
            band = t % sample_config.n_bands
            det = bool(sample_truth[band, t])
            actions.append(band)
            detections.append(det)
            recorder.record((band,), (det,))
            
        log = recorder.to_log()
        assert isinstance(log, EpisodeLog)
        assert log.config == sample_config
        np.testing.assert_array_equal(log.truth, sample_truth)
        np.testing.assert_array_equal(log.actions[:, 0], np.array(actions, dtype=np.intp))
        np.testing.assert_array_equal(log.detections[:, 0], np.array(detections, dtype=np.bool_))
        assert not np.any(log.retune_events)
        assert not np.any(log.settling_slots)

        # Check that we copy arrays so mutate operations on original don't affect log
        sample_truth[0, 0] = not sample_truth[0, 0]
        assert log.truth[0, 0] != sample_truth[0, 0]


class TestSerialization:
    """Tests for saving and loading EpisodeLog instances."""

    @pytest.fixture
    def full_log(self, sample_config, sample_truth) -> EpisodeLog:
        recorder = EpisodeRecorder(sample_config)
        recorder.record_truth(sample_truth)
        for t in range(sample_config.n_slots):
            recorder.record(
                (t % sample_config.n_bands,),
                (bool(sample_truth[t % sample_config.n_bands, t]),),
                retune_event=t == 1,
                settling=t in (1, 2),
            )
        return recorder.to_log()

    def test_json_roundtrip(self, full_log):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "episode.json"
            save_episode_log(full_log, filepath)
            
            assert filepath.is_file()
            
            # Read back
            loaded = load_episode_log(filepath)
            
            # Verify equivalent
            assert loaded.config == full_log.config
            np.testing.assert_array_equal(loaded.truth, full_log.truth)
            np.testing.assert_array_equal(loaded.actions, full_log.actions)
            np.testing.assert_array_equal(loaded.detections, full_log.detections)
            np.testing.assert_array_equal(loaded.retune_events, full_log.retune_events)
            np.testing.assert_array_equal(loaded.settling_slots, full_log.settling_slots)
            assert loaded.truth.dtype == np.bool_
            assert loaded.actions.dtype == np.intp
            assert loaded.detections.dtype == np.bool_

    def test_npz_roundtrip(self, full_log):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "episode.npz"
            save_episode_log(full_log, filepath)
            
            assert filepath.is_file()
            
            # Read back
            loaded = load_episode_log(filepath)
            
            # Verify equivalent
            assert loaded.config == full_log.config
            np.testing.assert_array_equal(loaded.truth, full_log.truth)
            np.testing.assert_array_equal(loaded.actions, full_log.actions)
            np.testing.assert_array_equal(loaded.detections, full_log.detections)
            np.testing.assert_array_equal(loaded.retune_events, full_log.retune_events)
            np.testing.assert_array_equal(loaded.settling_slots, full_log.settling_slots)
            assert loaded.truth.dtype == np.bool_
            assert loaded.actions.dtype == np.intp
            assert loaded.detections.dtype == np.bool_

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError, match="Log file not found"):
            load_episode_log("non_existent_file_path_123.json")

    def test_malformed_json_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "malformed.json"
            filepath.write_text("invalid json content {", encoding="utf-8")
            
            with pytest.raises(ValueError, match="Failed to parse JSON file"):
                load_episode_log(filepath)

    def test_missing_keys_json_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "missing_keys.json"
            # Missing "truth"
            data = {
                "config": {},
                "actions": [],
                "detections": []
            }
            filepath.write_text(json.dumps(data), encoding="utf-8")
            
            with pytest.raises(ValueError, match="JSON log file missing required keys"):
                load_episode_log(filepath)

    def test_missing_arrays_npz_raises(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "missing.npz"
            # Save only some arrays
            np.savez(filepath, actions=np.array([1, 2]))
            
            with pytest.raises(ValueError, match="NPZ log file missing required arrays"):
                load_episode_log(filepath)
