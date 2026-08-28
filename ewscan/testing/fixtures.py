"""Test fixtures for parallel development -- 1A.5.

Four tools so Track A (metrics, runner) and Track B (schedulers, dashboard)
can develop and test independently:

- scripted_observations: hand-built Observation sequences for scheduler tests
- synthetic_log: a complete EpisodeLog with known properties
- StubScheduler: a trivial Scheduler for runner tests
- ScriptedEnv: a truth-matrix playback environment for runner tests
"""

from __future__ import annotations

from typing import Sequence

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import (
    EmitterInfo,
    EpisodeConfig,
    EpisodeLog,
    Observation,
    ScanAction,
    Scheduler,
    ThreatPrior,
    scheduler_config_from_episode,
)


def make_test_config(
    n_bands: int = 4,
    n_slots: int = 20,
    k: int = 1,
    seed: int = 0,
    detection_threshold: float | None = None,
    pfa: float = 1e-3,
    emitters: tuple[EmitterInfo, ...] = (),
) -> EpisodeConfig:
    """Build an EpisodeConfig for testing."""
    return EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=k,
        emitters=emitters,
        detection_threshold=detection_threshold,
        pfa=pfa,
        seed=seed,
    )


def scripted_observations(
    specs: Sequence[tuple[int, int, bool]],
) -> list[Observation]:
    """Build Observation objects from (slot, band, detection) tuples.

    For scheduler unit tests where you want full control over what the
    scheduler sees at each step.
    """
    return [Observation(slot=s, bands=(b,), detections=(d,)) for s, b, d in specs]


def _build_default_truth(n_bands: int, n_slots: int) -> NDArray[np.bool_]:
    """Build the standard test truth matrix.

    Band 0: ON every slot (CW).
    Band 1: ON for a burst in the second quarter of the episode.
    Band 2: ON at slots where slot % 3 == 0 (periodic, period 3).
    Remaining bands: OFF.
    """
    truth = np.zeros((n_bands, n_slots), dtype=np.bool_)
    if n_bands > 0:
        truth[0, :] = True
    if n_bands > 1:
        start = n_slots // 4
        end = start + max(n_slots // 4, 1)
        truth[1, start:end] = True
    if n_bands > 2:
        truth[2, ::3] = True
    return truth


def _build_default_emitters(n_bands: int) -> tuple[EmitterInfo, ...]:
    """Build EmitterInfo entries matching the default truth matrix."""
    emitters: list[EmitterInfo] = []
    if n_bands > 0:
        emitters.append(
            EmitterInfo(band=0, snr=20.0, threat_level=1.0, emitter_type="cw")
        )
    if n_bands > 1:
        emitters.append(
            EmitterInfo(
                band=1, snr=15.0, threat_level=0.8,
                emitter_type="gilbert_elliott",
                params={"p01": 0.2, "p10": 0.2},
            )
        )
    if n_bands > 2:
        emitters.append(
            EmitterInfo(
                band=2, snr=12.0, threat_level=0.5,
                emitter_type="periodic", params={"period": 3},
            )
        )
    return tuple(emitters)


def synthetic_log(
    n_bands: int = 4,
    n_slots: int = 20,
    seed: int = 0,
) -> EpisodeLog:
    """Build an EpisodeLog with known, hand-computable properties.

    Default scenario (4 bands, 20 slots):
      Band 0: ON every slot (CW emitter, threat=1.0)
      Band 1: ON at slots 5..9 inclusive (bursty, threat=0.8)
      Band 2: ON at slots where slot % 3 == 0 (periodic, threat=0.5)
      Band 3: always OFF

    Actions: round-robin, action[t] = t % n_bands.
    Detections: perfect sensor (Pd=1, Pfa=0).

    Known results for default parameters:
      Total active band-slots: 32
      Hits (detection on active band): 9
        Band 0: 5 (slots 0, 4, 8, 12, 16)
        Band 1: 2 (slots 5, 9)
        Band 2: 2 (slots 6, 18)
      Interception ratio: 9 / 32
      First intercept: band 0 at slot 0, band 1 at slot 5, band 2 at slot 6
    """
    truth = _build_default_truth(n_bands, n_slots)
    actions = np.array([[t % n_bands] for t in range(n_slots)], dtype=np.intp)
    detections = np.array(
        [[bool(truth[actions[t, 0], t])] for t in range(n_slots)], dtype=np.bool_
    )

    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=_build_default_emitters(n_bands),
        detection_threshold=None,
        pfa=1e-3,
        seed=seed,
    )
    return EpisodeLog(
        config=config,
        truth=truth,
        actions=actions,
        detections=detections,
    )


class StubScheduler(Scheduler):
    """Scheduler that follows a fixed band sequence. Defaults to always band 0.

    Accepts a single band index or a sequence to cycle through.
    """

    def __init__(self, bands: int | Sequence[int] = 0):
        if isinstance(bands, int):
            self._bands = (bands,)
        else:
            self._bands = tuple(bands)
        self._step = 0
        self._k = 1
        self._n_bands = 1

    def reset(self, config: EpisodeConfig) -> None:
        self._step = 0
        self._k = config.k
        self._n_bands = config.n_bands

    def act(self, obs: Observation | None) -> ScanAction:
        base = self._bands[self._step % len(self._bands)]
        self._step += 1
        chosen = [base]
        i = 0
        while len(chosen) < self._k:
            b = (base + 1 + i) % self._n_bands
            if b not in chosen:
                chosen.append(b)
            i += 1
        return ScanAction(bands=tuple(chosen))

    @property
    def name(self) -> str:
        return "stub"


class ScriptedEnv:
    """Plays back a pre-built truth matrix as an environment.

    Produces Observations from a fixed truth matrix with perfect detection
    (no noise). Used to test the runner and metrics without real emitters.
    """

    def __init__(
        self,
        config: EpisodeConfig,
        truth: NDArray[np.bool_],
        threat_prior: ThreatPrior | None = None,
    ):
        if truth.shape != (config.n_bands, config.n_slots):
            raise ValueError(
                f"Truth shape {truth.shape} does not match config "
                f"({config.n_bands}, {config.n_slots})"
            )
        self.config = config
        self.truth = truth
        self._threat_prior = threat_prior
        self._slot = 0

    def reset(self) -> None:
        self._slot = 0

    def step(self, action: ScanAction) -> Observation:
        if self._slot >= self.config.n_slots:
            raise IndexError(f"Episode ended at slot {self.config.n_slots}")
        bands = action.bands
        detections = tuple(bool(self.truth[b, self._slot]) for b in bands)
        obs = Observation(slot=self._slot, bands=bands, detections=detections)
        self._slot += 1
        return obs

    @property
    def slot(self) -> int:
        return self._slot

    @property
    def done(self) -> bool:
        return self._slot >= self.config.n_slots

    def run(self, scheduler: Scheduler) -> EpisodeLog:
        """Run a full episode with the given scheduler and return the log."""
        self.reset()
        if self._threat_prior is not None:
            scheduler.reset(
                scheduler_config_from_episode(self.config, threat_prior=self._threat_prior)
            )
        else:
            scheduler.reset(self.config)

        actions = np.zeros((self.config.n_slots, self.config.k), dtype=np.intp)
        detections = np.zeros((self.config.n_slots, self.config.k), dtype=np.bool_)

        obs: Observation | None = None
        for t in range(self.config.n_slots):
            action = scheduler.act(obs)
            obs = self.step(action)
            actions[t, :] = action.bands
            detections[t, :] = obs.detections

        return EpisodeLog(
            config=self.config,
            truth=self.truth.copy(),
            actions=actions,
            detections=detections,
        )
