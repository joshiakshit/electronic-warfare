"""Shared contracts for ewscan. Frozen between sync gates."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import MappingProxyType
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
    """Sensor feedback from one scan step, delivered to the scheduler.

    Parallel receiver: ``bands[i]`` is the tuned sub-band and ``detections[i]``
    its detection result. The two tuples share the same order and length k.
    """

    slot: int
    bands: tuple[int, ...]
    detections: tuple[bool, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "bands", tuple(int(b) for b in self.bands))
        object.__setattr__(self, "detections", tuple(bool(d) for d in self.detections))


@dataclass(frozen=True)
class ScanAction:
    """Scheduler's choice: the k distinct bands to scan in parallel next slot."""

    bands: tuple[int, ...]

    def __post_init__(self) -> None:
        bands = tuple(int(b) for b in self.bands)
        object.__setattr__(self, "bands", bands)
        if len(set(bands)) != len(bands):
            raise ValueError(f"Duplicate bands in ScanAction: {bands}")


@dataclass(frozen=True)
class EmitterInfo:
    """Static specification of one emitter, used to configure the environment."""

    band: int
    snr: float
    threat_level: float
    emitter_type: str
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Wrap params in a read-only proxy to enforce immutability
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))


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

    def __post_init__(self) -> None:
        if not (1 <= self.k <= self.n_bands):
            raise ValueError(
                f"k must satisfy 1 <= k <= n_bands, got k={self.k}, n_bands={self.n_bands}"
            )


@dataclass
class EpisodeLog:
    """Complete record of one episode. Filled by the runner, read by metrics
    and dashboard."""

    config: EpisodeConfig
    truth: NDArray[np.bool_]
    actions: NDArray[np.intp]
    detections: NDArray[np.bool_]

    def __post_init__(self) -> None:
        ns, nb, k = self.config.n_slots, self.config.n_bands, self.config.k
        # For k=1, accept a 1D (n_slots,) array and store it as (n_slots, 1) so
        # downstream code always sees the 2D shape.
        if k == 1 and self.actions.ndim == 1:
            self.actions = self.actions.reshape(ns, 1)
        if k == 1 and self.detections.ndim == 1:
            self.detections = self.detections.reshape(ns, 1)
        if self.truth.shape != (nb, ns):
            raise ValueError(
                f"truth shape {self.truth.shape} does not match (n_bands, n_slots) ({nb}, {ns})"
            )
        if self.actions.shape != (ns, k):
            raise ValueError(
                f"actions shape {self.actions.shape} does not match (n_slots, k) ({ns}, {k})"
            )
        if self.detections.shape != (ns, k):
            raise ValueError(
                f"detections shape {self.detections.shape} does not match (n_slots, k) ({ns}, {k})"
            )

    @property
    def n_bands(self) -> int:
        return self.config.n_bands

    @property
    def n_slots(self) -> int:
        return self.config.n_slots

    @property
    def k(self) -> int:
        return self.config.k


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
