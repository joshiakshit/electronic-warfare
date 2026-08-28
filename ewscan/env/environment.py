"""Simulated RF environment and truth matrix generator -- Phase 1B.5.

Provides the concrete RFEnvironment stepper that simulates passive EW receiver
sensing across discrete frequency bands and time slots.
"""

from __future__ import annotations

from typing import Sequence

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import (
    Emitter,
    EmitterInfo,
    EpisodeConfig,
    Observation,
    ScanAction,
)
from ewscan.env.detection import DetectionModel
from ewscan.env.emitters import emitter_from_info
from ewscan.rng import make_emitter_generators, make_generators


class RFEnvironment:
    """Simulated RF environment for passive Electronic Support scan scheduling.

    Simulates an RF spectrum divided into discrete frequency bands and time slots.
    Multiple emitters (Markov, periodic radar, CW, etc.) can be active across bands.
    Co-resident emitters within the same band are OR-combined for ground truth
    activity, with incoherent power summation for combined SNR.

    Lifecycle:
      1. Initialize with an EpisodeConfig or explicit parameters.
      2. Call reset(seed=...) to initialize RNGs and compute the truth matrix.
      3. Call step(ScanAction(band=...)) sequentially to obtain Observations.
    """

    def __init__(
        self,
        config: EpisodeConfig | None = None,
        *,
        n_bands: int = 16,
        n_slots: int = 2000,
        k: int = 1,
        emitters: Sequence[Emitter | EmitterInfo] = (),
        detection_model: DetectionModel | None = None,
        pfa: float = 1e-4,
        detection_threshold: float | None = None,
        seed: int = 0,
        retune_cost_slots: int = 0,
        dwell: int = 1,
    ) -> None:
        if config is not None:
            self._n_bands = config.n_bands
            self._n_slots = config.n_slots
            self._k = config.k
            self._seed = config.seed
            self._emitters = tuple(
                em if isinstance(em, Emitter) else emitter_from_info(em)
                for em in config.emitters
            )
            self._detection_model = (
                detection_model
                if detection_model is not None
                else DetectionModel(
                    pfa=config.pfa,
                    threshold=config.detection_threshold,
                    dwell=config.dwell,
                )
            )
            if self._detection_model.capability != config.detector_capability:
                raise ValueError(
                    "detection_model capability must match the EpisodeConfig capability"
                )
            self._config = config
        else:
            if n_bands <= 0:
                raise ValueError(f"n_bands must be positive, got {n_bands}")
            if n_slots <= 0:
                raise ValueError(f"n_slots must be positive, got {n_slots}")
            if k <= 0:
                raise ValueError(f"k must be positive, got {k}")
            if k > n_bands:
                raise ValueError(f"k ({k}) cannot exceed n_bands ({n_bands})")
            if (
                not isinstance(retune_cost_slots, int)
                or isinstance(retune_cost_slots, bool)
                or retune_cost_slots < 0
            ):
                raise ValueError(
                    f"retune_cost_slots must be a non-negative integer, got {retune_cost_slots!r}"
                )
            if not isinstance(dwell, int) or isinstance(dwell, bool) or dwell < 1:
                raise ValueError(
                    f"dwell must be a positive integer, got {dwell!r}"
                )

            self._n_bands = int(n_bands)
            self._n_slots = int(n_slots)
            self._k = int(k)
            self._seed = int(seed)

            concrete_emitters: list[Emitter] = []
            emitter_infos: list[EmitterInfo] = []
            for em in emitters:
                if isinstance(em, Emitter):
                    concrete_emitters.append(em)
                    emitter_infos.append(em.info)
                elif isinstance(em, EmitterInfo):
                    concrete_emitters.append(emitter_from_info(em))
                    emitter_infos.append(em)
                else:
                    raise TypeError(
                        f"Expected Emitter or EmitterInfo, got {type(em).__name__}"
                    )

            self._emitters = tuple(concrete_emitters)

            if detection_model is not None:
                self._detection_model = detection_model
                pfa_val = detection_model.pfa
                det_thresh = detection_model.threshold
                dwell_val = detection_model.dwell
            else:
                self._detection_model = DetectionModel(
                    pfa=pfa, threshold=detection_threshold, dwell=dwell
                )
                pfa_val = pfa
                det_thresh = self._detection_model.threshold
                dwell_val = dwell

            self._config = EpisodeConfig(
                n_bands=self._n_bands,
                n_slots=self._n_slots,
                k=self._k,
                emitters=tuple(emitter_infos),
                detection_threshold=det_thresh,
                pfa=pfa_val,
                seed=self._seed,
                retune_cost_slots=retune_cost_slots,
                dwell=dwell_val,
            )

        # Validate emitter band assignments
        for em in self._emitters:
            if not (0 <= em.band < self._n_bands):
                raise ValueError(
                    f"Emitter assigned to band {em.band}, which is out of range [0, {self._n_bands - 1}]"
                )

        self._slot: int = 0
        self._is_reset: bool = False
        self._truth: NDArray[np.bool_] = np.zeros(
            (self._n_bands, self._n_slots), dtype=np.bool_
        )
        self._snr_matrix: NDArray[np.float64] = np.zeros(
            (self._n_bands, self._n_slots), dtype=np.float64
        )
        self._previous_bands: tuple[int, ...] | None = None
        self._settling_remaining = 0

    @property
    def config(self) -> EpisodeConfig:
        """Episode configuration."""
        return self._config

    @property
    def n_bands(self) -> int:
        """Total number of frequency bands."""
        return self._n_bands

    @property
    def n_slots(self) -> int:
        """Total number of time slots in the episode."""
        return self._n_slots

    @property
    def k(self) -> int:
        """Instantaneous scan bandwidth (number of bands scanned per slot)."""
        return self._k

    @property
    def emitters(self) -> tuple[Emitter, ...]:
        """Concrete emitter instances in the environment."""
        return self._emitters

    @property
    def detection_model(self) -> DetectionModel:
        """Detection model instance used for sensor observations."""
        return self._detection_model

    @property
    def slot(self) -> int:
        """Current time slot index (0-indexed)."""
        return self._slot

    @property
    def done(self) -> bool:
        """True if the episode has completed all slots."""
        return self._is_reset and self._slot >= self._n_slots

    @property
    def truth(self) -> NDArray[np.bool_]:
        """Ground-truth transmission matrix [n_bands x n_slots]."""
        if not self._is_reset:
            raise RuntimeError("Environment must be reset() before accessing truth")
        return self._truth.copy()

    def reset(self, seed: int | None = None) -> None:
        """Reset the environment state and generate truth for a new episode.

        Parameters
        ----------
        seed : int | None
            Optional seed override. If not provided, uses the seed from config.
        """
        if seed is not None:
            self._seed = int(seed)

        # Obtain independent subsystem generators
        generators = make_generators(self._seed)

        # Reset detection model
        self._detection_model.reset(generators["detection"])

        # Reset emitters with independent child RNGs spawned from emitter subsystem
        child_rngs = make_emitter_generators(self._seed, len(self._emitters))
        for em, rng_i in zip(self._emitters, child_rngs):
            em.reset(rng_i)

        # Reset slot counter and state matrices
        self._slot = 0
        self._previous_bands = None
        self._settling_remaining = 0
        self._truth = np.zeros((self._n_bands, self._n_slots), dtype=np.bool_)
        power_matrix = np.zeros((self._n_bands, self._n_slots), dtype=np.float64)

        # Read each emitter's band per slot so frequency-agile emitters place
        # activity across bands. Fixed emitters return a constant current_band.
        for em in self._emitters:
            em_power_lin = 10.0 ** (em.snr / 10.0)
            activity = em.activity(self._n_slots)
            if activity is None:
                for t in range(self._n_slots):
                    on = em.step()
                    b = em.current_band
                    if not (0 <= b < self._n_bands):
                        raise ValueError(
                            f"Emitter reported band {b} at slot {t}, out of range "
                            f"[0, {self._n_bands - 1}]"
                        )
                    if on:
                        self._truth[b, t] = True
                        power_matrix[b, t] += em_power_lin
                continue

            on_arr, band_arr = activity
            band_arr = np.asarray(band_arr, dtype=np.intp)
            out_of_range = (band_arr < 0) | (band_arr >= self._n_bands)
            if out_of_range.any():
                t = int(np.argmax(out_of_range))
                raise ValueError(
                    f"Emitter reported band {int(band_arr[t])} at slot {t}, out of range "
                    f"[0, {self._n_bands - 1}]"
                )
            on_idx = np.flatnonzero(on_arr)
            bands_on = band_arr[on_idx]
            self._truth[bands_on, on_idx] = True
            np.add.at(power_matrix, (bands_on, on_idx), em_power_lin)

        # Compute combined SNR matrix in dB
        with np.errstate(divide="ignore"):
            self._snr_matrix = np.where(
                self._truth,
                10.0 * np.log10(np.maximum(power_matrix, 1e-30)),
                0.0,
            )

        self._is_reset = True

    def step(self, action: ScanAction) -> Observation:
        """Execute one parallel scan action and return sensor observation.

        The k channels sample the same slot. Returns one Observation whose
        detections align with action.bands. Advances the slot once.

        Raises
        ------
        RuntimeError
            If called before reset().
        IndexError
            If called when the episode is already done.
        ValueError
            If len(action.bands) != k, or any band is out of range.
        """
        if not self._is_reset:
            raise RuntimeError("Environment must be reset() before calling step()")

        if self._slot >= self._n_slots:
            raise IndexError(
                f"Episode already completed all {self._n_slots} slots"
            )

        bands = action.bands
        if len(bands) != self._k:
            raise ValueError(
                f"ScanAction has {len(bands)} bands, expected k={self._k}"
            )
        for b in bands:
            if not (0 <= b < self._n_bands):
                raise ValueError(
                    f"Action band {b} out of valid range [0, {self._n_bands - 1}]"
                )

        t = self._slot
        retune_event = (
            self._previous_bands is not None
            and tuple(sorted(bands)) != tuple(sorted(self._previous_bands))
        )
        if retune_event:
            distance = np.mean(
                np.abs(
                    np.asarray(sorted(bands), dtype=np.intp)
                    - np.asarray(sorted(self._previous_bands), dtype=np.intp)
                )
            )
            self._settling_remaining = int(np.ceil(
                self._config.retune_cost_slots * distance
            ))
        settling = self._settling_remaining > 0
        detections = tuple(
            self._detection_model.detect(
                0.0 if settling else float(self._snr_matrix[b, t]),
                False if settling else bool(self._truth[b, t]),
            )
            for b in bands
        )
        obs = Observation(
            slot=t,
            bands=bands,
            detections=detections,
            retune_event=retune_event,
            settling=settling,
        )

        self._previous_bands = bands
        self._settling_remaining = max(0, self._settling_remaining - 1)
        self._slot += 1
        return obs


Environment = RFEnvironment


def generate_truth_matrix(
    config: EpisodeConfig,
    seed: int | None = None,
) -> NDArray[np.bool_]:
    """Generate ground-truth transmission matrix [n_bands x n_slots] for a scenario.

    Parameters
    ----------
    config : EpisodeConfig
        Configuration specifying bands, slots, emitters, and scenario parameters.
    seed : int | None
        Optional seed override (defaults to config.seed).

    Returns
    -------
    NDArray[np.bool_]
        Binary transmission matrix of shape (n_bands, n_slots) with dtype bool.
    """
    env = RFEnvironment(config)
    env.reset(seed=seed if seed is not None else config.seed)
    return env.truth
