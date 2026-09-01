"""Episode recorder for RF environment simulations -- Phase 1B.6.

Provides the EpisodeRecorder class to log actions, detections, and ground truth,
and helper functions to save and load EpisodeLog instances.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence
import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeConfig, EpisodeLog, Observation
from ewscan.config import config_to_dict, config_from_dict


class EpisodeRecorder:
    """Records actions, detections, and ground truth during an episode.
    
    This is used by the runner to build an EpisodeLog representing the complete
    execution of an episode.
    
    Lifecycle:
      1. Initialize with an EpisodeConfig.
      2. Record actions and detections slot-by-slot using record() or record_observation().
      3. Set the ground truth matrix using record_truth().
      4. Call to_log() to construct the finalized EpisodeLog.
    """

    def __init__(self, config: EpisodeConfig) -> None:
        """Initialize the recorder for a given episode configuration.
        
        Parameters
        ----------
        config : EpisodeConfig
            The configuration for the episode to be recorded.
        """
        self._config = config
        self._actions = np.zeros((config.n_slots, config.k), dtype=np.intp)
        self._detections = np.zeros((config.n_slots, config.k), dtype=np.bool_)
        self._retune_events = np.zeros(config.n_slots, dtype=np.bool_)
        self._settling_slots = np.zeros(config.n_slots, dtype=np.bool_)
        self._valid_slots = np.ones(config.n_slots, dtype=np.bool_)
        self._truth: NDArray[np.bool_] | None = None
        self._emitter_truth: NDArray[np.bool_] | None = None
        self._emitter_bands: NDArray[np.intp] | None = None
        self._current_slot = 0

    @property
    def config(self) -> EpisodeConfig:
        """The episode configuration."""
        return self._config

    @property
    def current_slot(self) -> int:
        """The next slot to be recorded."""
        return self._current_slot

    def record(
        self,
        bands: "Sequence[int]",
        detections: "Sequence[bool]",
        retune_event: bool = False,
        settling: bool = False,
        valid: bool | None = None,
    ) -> None:
        """Record the k bands and detections at the current slot and advance.

        Parameters
        ----------
        bands : Sequence[int]
            The k band indices scanned in this step.
        detections : Sequence[bool]
            The k detection results, aligned with bands.

        Raises
        ------
        IndexError
            If attempting to record past the configured number of slots.
        ValueError
            If the number of bands is not k, or a band is out of range.
        """
        if self._current_slot >= self._config.n_slots:
            raise IndexError(
                f"Attempted to record at slot {self._current_slot}, but episode config n_slots is {self._config.n_slots}"
            )
        if len(bands) != self._config.k or len(detections) != self._config.k:
            raise ValueError(
                f"Expected {self._config.k} bands and detections, got {len(bands)} and {len(detections)}"
            )
        for band in bands:
            if not (0 <= band < self._config.n_bands):
                raise ValueError(
                    f"Action band {band} out of valid range [0, {self._config.n_bands - 1}]"
                )

        sample_valid = not settling if valid is None else bool(valid)
        if settling and sample_valid:
            raise ValueError("settling observations must be invalid")

        self._actions[self._current_slot, :] = bands
        self._detections[self._current_slot, :] = detections
        self._retune_events[self._current_slot] = retune_event
        self._settling_slots[self._current_slot] = settling
        self._valid_slots[self._current_slot] = sample_valid
        self._current_slot += 1

    def record_observation(self, obs: Observation) -> None:
        """Record action and detection from an Observation.
        
        This uses the Observation's slot index directly.
        
        Parameters
        ----------
        obs : Observation
            The observation to record.
            
        Raises
        ------
        IndexError
            If the observation's slot is out of the range [0, n_slots - 1].
        ValueError
            If the observation's band is out of the range [0, n_bands - 1].
        """
        slot = obs.slot
        bands = obs.bands
        detections = obs.detections

        if not (0 <= slot < self._config.n_slots):
            raise IndexError(
                f"Observation slot {slot} out of range [0, {self._config.n_slots - 1}]"
            )
        if len(bands) != self._config.k:
            raise ValueError(
                f"Observation has {len(bands)} bands, expected k={self._config.k}"
            )
        for band in bands:
            if not (0 <= band < self._config.n_bands):
                raise ValueError(
                    f"Observation band {band} out of valid range [0, {self._config.n_bands - 1}]"
                )

        self._actions[slot, :] = bands
        self._detections[slot, :] = detections
        self._retune_events[slot] = obs.retune_event
        self._settling_slots[slot] = obs.settling
        self._valid_slots[slot] = obs.valid
        # Update current slot pointer to match or exceed recorded slot
        self._current_slot = max(self._current_slot, slot + 1)

    def record_truth(self, truth: NDArray[np.bool_]) -> None:
        """Record the ground truth transmission matrix.
        
        Parameters
        ----------
        truth : NDArray[np.bool_]
            The binary transmission matrix of shape (n_bands, n_slots).
            
        Raises
        ------
        ValueError
            If the shape of the truth matrix does not match the configured (n_bands, n_slots).
        """
        if truth.shape != (self._config.n_bands, self._config.n_slots):
            raise ValueError(
                f"Truth matrix shape {truth.shape} does not match config "
                f"({self._config.n_bands}, {self._config.n_slots})"
            )
        self._truth = truth.copy()

    def record_emitter_truth(
        self,
        emitter_truth: NDArray[np.bool_],
        emitter_bands: NDArray[np.intp],
    ) -> None:
        """Record per-emitter ON state and occupied band for every slot."""
        n_em = len(self._config.emitters)
        expected = (n_em, self._config.n_slots)
        if emitter_truth.shape != expected or emitter_bands.shape != expected:
            raise ValueError(
                f"emitter activity shape must be {expected}, got "
                f"{emitter_truth.shape} and {emitter_bands.shape}"
            )
        self._emitter_truth = emitter_truth.copy()
        self._emitter_bands = emitter_bands.copy()

    def to_log(self) -> EpisodeLog:
        """Compile and return the finalized EpisodeLog.
        
        Returns
        -------
        EpisodeLog
            The finalized log of the episode.
            
        Raises
        ------
        RuntimeError
            If the ground truth matrix was not recorded.
        ValueError
            If the number of recorded slots is less than n_slots.
        """
        if self._truth is None:
            raise RuntimeError("Cannot compile log: ground truth matrix was not recorded")
        if self._current_slot < self._config.n_slots:
            raise ValueError(
                f"Expected {self._config.n_slots} steps, but only recorded {self._current_slot} slots"
            )
            
        return EpisodeLog(
            config=self._config,
            truth=self._truth.copy(),
            actions=self._actions.copy(),
            detections=self._detections.copy(),
            retune_events=self._retune_events.copy(),
            settling_slots=self._settling_slots.copy(),
            valid_slots=self._valid_slots.copy(),
            emitter_truth=(
                self._emitter_truth.copy() if self._emitter_truth is not None else None
            ),
            emitter_bands=(
                self._emitter_bands.copy() if self._emitter_bands is not None else None
            ),
        )


def save_episode_log(log: EpisodeLog, filepath: str | Path) -> None:
    """Save an EpisodeLog to a file.
    
    Supports .json (human-readable) and .npz (compressed binary numpy arrays).
    Determined by the file extension of filepath.
    
    Parameters
    ----------
    log : EpisodeLog
        The log instance to save.
    filepath : str | Path
        Target file path.
    """
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    config_dict = config_to_dict(log.config)
    
    if path.suffix.lower() == ".json":
        data = {
            "config": config_dict,
            "truth": log.truth.tolist(),
            "actions": log.actions.tolist(),
            "detections": log.detections.tolist(),
            "retune_events": log.retune_events.tolist(),
            "settling_slots": log.settling_slots.tolist(),
            "valid_slots": log.valid_slots.tolist(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        # Default or .npz format
        config_json = json.dumps(config_dict)
        np.savez_compressed(
            path,
            truth=log.truth,
            actions=log.actions,
            detections=log.detections,
            retune_events=log.retune_events,
            settling_slots=log.settling_slots,
            valid_slots=log.valid_slots,
            config_json=config_json,
        )


def load_episode_log(filepath: str | Path) -> EpisodeLog:
    """Load an EpisodeLog from a file.
    
    Supports .json and .npz formats.
    
    Parameters
    ----------
    filepath : str | Path
        Path to the saved log file.
        
    Returns
    -------
    EpisodeLog
        The loaded EpisodeLog instance.
        
    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    ValueError
        If the file content is malformed or invalid.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {path}")
        
    if path.suffix.lower() == ".json":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            raise ValueError(f"Failed to parse JSON file {path}: {exc}") from exc
            
        required = {"config", "truth", "actions", "detections"}
        missing = required - set(data.keys())
        if missing:
            raise ValueError(f"JSON log file missing required keys: {missing}")
            
        config = config_from_dict(data["config"])
        truth = np.array(data["truth"], dtype=np.bool_)
        actions = np.array(data["actions"], dtype=np.intp)
        detections = np.array(data["detections"], dtype=np.bool_)
        retune_events = np.array(data.get("retune_events", []), dtype=np.bool_)
        settling_slots = np.array(data.get("settling_slots", []), dtype=np.bool_)
        valid_slots = np.array(data.get("valid_slots", []), dtype=np.bool_)

    else:
        # Load from .npz
        try:
            with np.load(path) as data:
                required = {"truth", "actions", "detections", "config_json"}
                missing = required - set(data.files)
                if missing:
                    raise ValueError(f"NPZ log file missing required arrays: {missing}")
                
                truth = data["truth"]
                actions = data["actions"]
                detections = data["detections"]
                retune_events = data["retune_events"] if "retune_events" in data.files else None
                settling_slots = data["settling_slots"] if "settling_slots" in data.files else None
                valid_slots = data["valid_slots"] if "valid_slots" in data.files else None

                config_json_raw = data["config_json"]
                if isinstance(config_json_raw, np.ndarray):
                    if config_json_raw.ndim == 0:
                        config_json_str = config_json_raw.item()
                    else:
                        config_json_str = config_json_raw[0]
                else:
                    config_json_str = config_json_raw
                if isinstance(config_json_str, bytes):
                    config_json_str = config_json_str.decode("utf-8")
                    
                config_dict = json.loads(config_json_str)
                config = config_from_dict(config_dict)
        except Exception as exc:
            raise ValueError(f"Failed to load NPZ file {path}: {exc}") from exc

    # Validate shapes and dimensions
    if truth.shape != (config.n_bands, config.n_slots):
        raise ValueError(
            f"Loaded truth shape {truth.shape} does not match config "
            f"({config.n_bands}, {config.n_slots})"
        )
    if actions.shape != (config.n_slots, config.k):
        raise ValueError(
            f"Loaded actions shape {actions.shape} does not match (n_slots, k) ({config.n_slots}, {config.k})"
        )
    if detections.shape != (config.n_slots, config.k):
        raise ValueError(
            f"Loaded detections shape {detections.shape} does not match (n_slots, k) ({config.n_slots}, {config.k})"
        )
    if retune_events is None or retune_events.size == 0:
        retune_events = np.zeros(config.n_slots, dtype=np.bool_)
    if settling_slots is None or settling_slots.size == 0:
        settling_slots = np.zeros(config.n_slots, dtype=np.bool_)
    if valid_slots is None or valid_slots.size == 0:
        valid_slots = np.ones(config.n_slots, dtype=np.bool_)

    return EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=detections,
        retune_events=retune_events,
        settling_slots=settling_slots,
        valid_slots=valid_slots,
    )
