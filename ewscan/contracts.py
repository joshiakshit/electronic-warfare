"""Shared contracts for ewscan. Frozen between sync gates."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from numpy.typing import NDArray


@dataclass(frozen=True)
class Band:
    """A frequency band in the receiver's tuning range."""

    index: int
    label: str = ""


@dataclass(frozen=True)
class Observation:
    """Sensor feedback from one scan step, delivered to the scheduler."""

    slot: int
    band: int
    detection: bool


@dataclass(frozen=True)
class ScanAction:
    """Scheduler's choice: which band to scan next."""

    band: int


@dataclass(frozen=True)
class EmitterInfo:
    """Static specification of one emitter, used to configure the environment."""

    band: int
    snr: float
    threat_level: float
    emitter_type: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EpisodeConfig:
    """Full specification of one episode scenario."""

    n_bands: int
    n_slots: int
    k: int
    emitters: tuple[EmitterInfo, ...]
    detection_threshold: float
    pfa: float
    seed: int = 0


@dataclass
class EpisodeLog:
    """Complete record of one episode. Filled by the runner, read by metrics
    and dashboard."""

    config: EpisodeConfig
    truth: NDArray[np.bool_]
    actions: NDArray[np.intp]
    detections: NDArray[np.bool_]

    @property
    def n_bands(self) -> int:
        return self.config.n_bands

    @property
    def n_slots(self) -> int:
        return self.config.n_slots


class Emitter(ABC):
    """Base class for signal emitters (Track A implements these)."""

    @abstractmethod
    def reset(self, rng: np.random.Generator) -> None: ...

    @abstractmethod
    def step(self) -> bool: ...

    @property
    @abstractmethod
    def info(self) -> EmitterInfo: ...


class Scheduler(ABC):
    """Base class for scan schedulers (Track B implements these).

    Lifecycle: reset(config) once, then act(None) for the first slot,
    then act(obs) for each subsequent slot.
    """

    @abstractmethod
    def reset(self, config: EpisodeConfig) -> None: ...

    @abstractmethod
    def act(self, obs: Observation | None) -> ScanAction: ...

    @property
    @abstractmethod
    def name(self) -> str: ...
