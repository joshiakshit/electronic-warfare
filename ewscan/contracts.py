"""Shared contracts for ewscan. Frozen between sync gates."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import math
from numbers import Integral, Real
from types import MappingProxyType
from typing import Any

import numpy as np
from numpy.typing import NDArray

from ewscan.detector import DetectorCapability, make_detector_capability


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
    retune_event: bool = False
    settling: bool = False
    valid: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "bands", tuple(int(b) for b in self.bands))
        object.__setattr__(self, "detections", tuple(bool(d) for d in self.detections))
        object.__setattr__(self, "retune_event", bool(self.retune_event))
        object.__setattr__(self, "settling", bool(self.settling))
        object.__setattr__(self, "valid", bool(self.valid))
        if len(self.bands) != len(self.detections):
            raise ValueError(
                "Observation bands and detections must have the same length, "
                f"got {len(self.bands)} and {len(self.detections)}"
            )


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
    detection_threshold: float | None = None
    pfa: float = 1e-4
    seed: int = 0
    retune_cost_slots: int = 0
    dwell: int = 1
    detector_capability: DetectorCapability = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "emitters", tuple(self.emitters))
        capability = validate_episode_config(self)
        object.__setattr__(self, "n_bands", int(self.n_bands))
        object.__setattr__(self, "n_slots", int(self.n_slots))
        object.__setattr__(self, "k", int(self.k))
        object.__setattr__(self, "detection_threshold", capability.threshold)
        object.__setattr__(self, "pfa", float(self.pfa))
        object.__setattr__(self, "seed", int(self.seed))
        object.__setattr__(self, "retune_cost_slots", int(self.retune_cost_slots))
        object.__setattr__(self, "dwell", int(self.dwell))
        object.__setattr__(self, "detector_capability", capability)


@dataclass(frozen=True)
class ThreatPrior:
    """External, possibly noisy band-threat prior for prior-aided runs.

    ``weights[b]`` is the prior threat weight for band b. ``provenance`` records
    where the prior came from so blind and prior-aided results stay separable.
    """

    weights: tuple[float, ...]
    provenance: str

    def __post_init__(self) -> None:
        weights = tuple(float(w) for w in self.weights)
        object.__setattr__(self, "weights", weights)
        if len(weights) == 0:
            raise ValueError("ThreatPrior weights must be non-empty")
        for w in weights:
            if not math.isfinite(w) or w < 0.0:
                raise ValueError(
                    f"ThreatPrior weights must be finite and non-negative, got {w}"
                )
        if not isinstance(self.provenance, str) or not self.provenance.strip():
            raise ValueError("ThreatPrior requires a non-empty provenance string")


@dataclass(frozen=True)
class SchedulerConfig:
    """Scheduler-visible configuration. Carries no emitter tuple or truth.

    This is the only configuration a blind scheduler receives. It exposes what
    a real operator would know: dimensions, detector capability, and an optional
    external ThreatPrior. Emitter bands, types, SNRs, threat levels, and
    transition parameters are absent by construction.
    """

    n_bands: int
    n_slots: int
    k: int
    detector_capability: DetectorCapability
    seed: int = 0
    dwell: int = 1
    retune_cost_slots: int = 0
    threat_prior: ThreatPrior | None = None

    def __post_init__(self) -> None:
        n_bands = _require_integer("n_bands", self.n_bands, 1)
        _require_integer("n_slots", self.n_slots, 1)
        if not isinstance(self.k, Integral) or isinstance(self.k, bool):
            raise ValueError(f"k must be a positive integer, got {self.k!r}")
        k = int(self.k)
        if not 1 <= k <= n_bands:
            raise ValueError(
                f"k must satisfy 1 <= k <= n_bands, got k={k}, n_bands={n_bands}"
            )
        if not isinstance(self.detector_capability, DetectorCapability):
            raise ValueError("detector_capability must be a DetectorCapability")
        if not isinstance(self.seed, Integral) or isinstance(self.seed, bool):
            raise ValueError(f"seed must be an integer, got {self.seed!r}")
        _require_integer("retune_cost_slots", self.retune_cost_slots, 0)
        _require_integer("dwell", self.dwell, 1)
        if self.threat_prior is not None:
            if not isinstance(self.threat_prior, ThreatPrior):
                raise ValueError("threat_prior must be a ThreatPrior or None")
            if len(self.threat_prior.weights) != n_bands:
                raise ValueError(
                    f"threat_prior has {len(self.threat_prior.weights)} weights, "
                    f"expected n_bands={n_bands}"
                )
        object.__setattr__(self, "n_bands", n_bands)
        object.__setattr__(self, "n_slots", int(self.n_slots))
        object.__setattr__(self, "k", k)
        object.__setattr__(self, "seed", int(self.seed))
        object.__setattr__(self, "dwell", int(self.dwell))
        object.__setattr__(self, "retune_cost_slots", int(self.retune_cost_slots))


def scheduler_config_from_episode(
    config: EpisodeConfig,
    threat_prior: ThreatPrior | None = None,
) -> SchedulerConfig:
    """Build a blind scheduler-visible config, dropping every emitter secret.

    Supply ``threat_prior`` only for an explicit prior-aided run.
    """
    return SchedulerConfig(
        n_bands=config.n_bands,
        n_slots=config.n_slots,
        k=config.k,
        detector_capability=config.detector_capability,
        seed=config.seed,
        dwell=config.dwell,
        retune_cost_slots=config.retune_cost_slots,
        threat_prior=threat_prior,
    )


def as_scheduler_config(
    config: "SchedulerConfig | EpisodeConfig",
) -> SchedulerConfig:
    """Return a SchedulerConfig, deriving a blind view from an EpisodeConfig.

    An EpisodeConfig is converted to the blind scheduler view so legacy callers
    that still pass one cannot leak emitter data into a scheduler.
    """
    if isinstance(config, SchedulerConfig):
        return config
    if isinstance(config, EpisodeConfig):
        return scheduler_config_from_episode(config)
    raise TypeError(
        f"Expected SchedulerConfig or EpisodeConfig, got {type(config).__name__}"
    )


def _require_integer(name: str, value: Any, minimum: int) -> int:
    if not isinstance(value, Integral) or isinstance(value, bool) or value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{name} must be a {qualifier} integer, got {value!r}")
    return int(value)


def _require_number(name: str, value: Any) -> float:
    if not isinstance(value, Real) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number, got {value!r}")
    return float(value)


def _require_probability(name: str, value: Any, *, open_interval: bool = False) -> float:
    number = _require_number(name, value)
    valid = 0.0 < number < 1.0 if open_interval else 0.0 <= number <= 1.0
    if not valid:
        interval = "(0, 1)" if open_interval else "[0, 1]"
        raise ValueError(f"{name} must be in {interval}, got {number}")
    return number


def _validate_emitter(emitter: EmitterInfo, n_bands: int, index: int) -> None:
    prefix = f"emitters[{index}]"
    if not isinstance(emitter, EmitterInfo):
        raise ValueError(f"{prefix} must be EmitterInfo, got {type(emitter).__name__}")
    band = _require_integer(f"{prefix}.band", emitter.band, 0)
    if band >= n_bands:
        raise ValueError(
            f"{prefix}.band={band} is out of range [0, {n_bands - 1}]"
        )
    _require_number(f"{prefix}.snr", emitter.snr)
    threat = _require_number(f"{prefix}.threat_level", emitter.threat_level)
    if threat < 0.0:
        raise ValueError(f"{prefix}.threat_level must be non-negative, got {threat}")

    emitter_type = emitter.emitter_type.strip().lower()
    params = emitter.params
    if emitter_type in {"gilbert_elliott", "markov", "ge"}:
        _validate_markov_params(params, prefix)
    elif emitter_type in {"periodic", "radar"}:
        _validate_periodic_params(params, prefix)
    elif emitter_type in {"cw", "static_cw", "static"}:
        if params:
            raise ValueError(f"{prefix}.params must be empty for a CW emitter")
    elif emitter_type in {"frequency_hop", "hopper", "agile"}:
        _validate_hop_params(params, prefix, n_bands)
    elif emitter_type in {"beam", "scanning_beam"}:
        _validate_beam_params(params, prefix)
    else:
        raise ValueError(f"{prefix}.emitter_type is unknown: {emitter.emitter_type!r}")


def _require_known_params(params: Any, prefix: str, allowed: set[str]) -> None:
    unknown = set(params) - allowed
    if unknown:
        names = ", ".join(sorted(unknown))
        raise ValueError(f"{prefix}.params contains unknown fields: {names}")


def _validate_markov_params(params: Any, prefix: str) -> None:
    allowed = {"p01", "p10", "initial_state"}
    _require_known_params(params, prefix, allowed)
    missing = {"p01", "p10"} - set(params)
    if missing:
        raise ValueError(f"{prefix}.params is missing: {', '.join(sorted(missing))}")
    p01 = _require_probability(f"{prefix}.params.p01", params["p01"])
    p10 = _require_probability(f"{prefix}.params.p10", params["p10"])
    initial_state = params.get("initial_state")
    if initial_state is not None and (
        not isinstance(initial_state, Integral)
        or isinstance(initial_state, bool)
        or initial_state not in (0, 1)
    ):
        raise ValueError(
            f"{prefix}.params.initial_state must be 0, 1, or null, got {initial_state!r}"
        )
    if p01 == 0.0 and p10 == 0.0 and initial_state is None:
        raise ValueError(
            f"{prefix}.params p01 and p10 cannot both be zero without initial_state"
        )


def _validate_periodic_params(params: Any, prefix: str) -> None:
    allowed = {"period", "dwell", "jitter", "phase"}
    _require_known_params(params, prefix, allowed)
    if "period" not in params:
        raise ValueError(f"{prefix}.params is missing: period")
    period = _require_integer(f"{prefix}.params.period", params["period"], 1)
    dwell = _require_integer(f"{prefix}.params.dwell", params.get("dwell", 1), 1)
    if dwell > period:
        raise ValueError(
            f"{prefix}.params.dwell must not exceed period {period}, got {dwell}"
        )
    _require_integer(f"{prefix}.params.jitter", params.get("jitter", 0), 0)
    _require_integer(f"{prefix}.params.phase", params.get("phase", 0), 0)


def _validate_hop_params(params: Any, prefix: str, n_bands: int) -> None:
    allowed = {"hop_bands", "sequence", "taps", "state", "n_bits", "r", "x0"}
    _require_known_params(params, prefix, allowed)
    hop_bands = params.get("hop_bands")
    if not isinstance(hop_bands, (list, tuple)) or not hop_bands:
        raise ValueError(f"{prefix}.params.hop_bands must be a non-empty list")
    for band in hop_bands:
        value = _require_integer(f"{prefix}.params.hop_bands", band, 0)
        if value >= n_bands:
            raise ValueError(
                f"{prefix}.params.hop_bands must be in [0, {n_bands - 1}], got {value}"
            )
    sequence = params.get("sequence", "lfsr")
    if sequence not in {"lfsr", "logistic"}:
        raise ValueError(
            f"{prefix}.params.sequence must be 'lfsr' or 'logistic', got {sequence!r}"
        )
    n_bits = _require_integer(f"{prefix}.params.n_bits", params.get("n_bits", 8), 1)
    state = _require_integer(f"{prefix}.params.state", params.get("state", 1), 1)
    if state >= 1 << n_bits:
        raise ValueError(f"{prefix}.params.state does not fit in n_bits={n_bits}")
    taps = params.get("taps", [n_bits - 1, n_bits - 2])
    if not isinstance(taps, (list, tuple)) or not taps:
        raise ValueError(f"{prefix}.params.taps must be a non-empty list")
    for tap in taps:
        value = _require_integer(f"{prefix}.params.taps", tap, 0)
        if value >= n_bits:
            raise ValueError(f"{prefix}.params.taps must be below n_bits={n_bits}")
    r = _require_number(f"{prefix}.params.r", params.get("r", 3.9))
    if not 0.0 < r <= 4.0:
        raise ValueError(f"{prefix}.params.r must be in (0, 4], got {r}")
    x0 = _require_number(f"{prefix}.params.x0", params.get("x0", 0.5))
    if not 0.0 < x0 < 1.0:
        raise ValueError(f"{prefix}.params.x0 must be in (0, 1), got {x0}")


def _validate_beam_params(params: Any, prefix: str) -> None:
    allowed = {"omega", "beamwidth", "snr_peak", "theta0", "floor"}
    _require_known_params(params, prefix, allowed)
    missing = {"omega", "beamwidth", "snr_peak"} - set(params)
    if missing:
        raise ValueError(f"{prefix}.params is missing: {', '.join(sorted(missing))}")
    for name in ("omega", "beamwidth"):
        value = _require_number(f"{prefix}.params.{name}", params[name])
        if value <= 0.0:
            raise ValueError(f"{prefix}.params.{name} must be positive, got {value}")
    _require_number(f"{prefix}.params.snr_peak", params["snr_peak"])
    _require_number(f"{prefix}.params.theta0", params.get("theta0", 0.0))
    if params.get("floor") is not None:
        _require_number(f"{prefix}.params.floor", params["floor"])


def validate_episode_config(config: EpisodeConfig) -> DetectorCapability:
    """Validate one episode at every public construction boundary."""
    n_bands = _require_integer("n_bands", config.n_bands, 1)
    _require_integer("n_slots", config.n_slots, 1)
    if not isinstance(config.k, Integral) or isinstance(config.k, bool):
        raise ValueError(f"k must be a positive integer, got {config.k!r}")
    k = int(config.k)
    if not 1 <= k <= n_bands:
        raise ValueError(
            f"k must satisfy 1 <= k <= n_bands, got k={k}, n_bands={n_bands}"
        )
    if config.detection_threshold is not None:
        threshold = _require_number("detection_threshold", config.detection_threshold)
        if threshold <= 0.0:
            raise ValueError(
                f"detection_threshold must be positive, got {threshold}"
            )
    _require_probability("pfa", config.pfa, open_interval=True)
    if not isinstance(config.seed, Integral) or isinstance(config.seed, bool):
        raise ValueError(f"seed must be an integer, got {config.seed!r}")
    _require_integer("retune_cost_slots", config.retune_cost_slots, 0)
    dwell = _require_integer("dwell", config.dwell, 1)
    for index, emitter in enumerate(config.emitters):
        _validate_emitter(emitter, n_bands, index)
    return make_detector_capability(
        pfa=config.pfa,
        threshold=config.detection_threshold,
        dwell=dwell,
    )


@dataclass
class EpisodeLog:
    """Complete record of one episode. Filled by the runner, read by metrics
    and dashboard."""

    config: EpisodeConfig
    truth: NDArray[np.bool_]
    actions: NDArray[np.intp]
    detections: NDArray[np.bool_]
    retune_events: NDArray[np.bool_] | None = None
    settling_slots: NDArray[np.bool_] | None = None
    valid_slots: NDArray[np.bool_] | None = None
    emitter_truth: NDArray[np.bool_] | None = None
    emitter_bands: NDArray[np.intp] | None = None

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
        if not np.issubdtype(self.actions.dtype, np.integer):
            raise ValueError(f"actions must contain integer band values, got {self.actions.dtype}")
        invalid_actions = (self.actions < 0) | (self.actions >= nb)
        if invalid_actions.any():
            slot, channel = np.argwhere(invalid_actions)[0]
            value = int(self.actions[slot, channel])
            raise ValueError(
                f"actions[{slot}, {channel}]={value} is out of range [0, {nb - 1}]"
            )
        if k > 1 and np.any(np.diff(np.sort(self.actions, axis=1), axis=1) == 0):
            raise ValueError("actions must not contain duplicate bands within a slot")
        if self.retune_events is None:
            self.retune_events = np.zeros(ns, dtype=np.bool_)
        elif self.retune_events.shape != (ns,):
            raise ValueError(
                f"retune_events shape {self.retune_events.shape} does not match (n_slots,) ({ns},)"
            )
        else:
            self.retune_events = self.retune_events.astype(np.bool_, copy=False)
        if self.settling_slots is None:
            self.settling_slots = np.zeros(ns, dtype=np.bool_)
        elif self.settling_slots.shape != (ns,):
            raise ValueError(
                f"settling_slots shape {self.settling_slots.shape} does not match (n_slots,) ({ns},)"
            )
        else:
            self.settling_slots = self.settling_slots.astype(np.bool_, copy=False)
        if self.valid_slots is None:
            self.valid_slots = np.ones(ns, dtype=np.bool_)
        elif self.valid_slots.shape != (ns,):
            raise ValueError(
                f"valid_slots shape {self.valid_slots.shape} does not match (n_slots,) ({ns},)"
            )
        else:
            self.valid_slots = self.valid_slots.astype(np.bool_, copy=False)

        n_em = len(self.config.emitters)
        if self.emitter_truth is not None or self.emitter_bands is not None:
            if self.emitter_truth is None or self.emitter_bands is None:
                raise ValueError(
                    "emitter_truth and emitter_bands must both be given or both omitted"
                )
            if self.emitter_truth.shape != (n_em, ns):
                raise ValueError(
                    f"emitter_truth shape {self.emitter_truth.shape} does not match "
                    f"(n_emitters, n_slots) ({n_em}, {ns})"
                )
            if self.emitter_bands.shape != (n_em, ns):
                raise ValueError(
                    f"emitter_bands shape {self.emitter_bands.shape} does not match "
                    f"(n_emitters, n_slots) ({n_em}, {ns})"
                )
            if not np.issubdtype(self.emitter_bands.dtype, np.integer):
                raise ValueError(
                    f"emitter_bands must contain integer band values, got {self.emitter_bands.dtype}"
                )
            if n_em > 0:
                bad = (self.emitter_bands < 0) | (self.emitter_bands >= nb)
                if bad.any():
                    em, slot = np.argwhere(bad)[0]
                    value = int(self.emitter_bands[em, slot])
                    raise ValueError(
                        f"emitter_bands[{em}, {slot}]={value} is out of range [0, {nb - 1}]"
                    )
            self.emitter_truth = self.emitter_truth.astype(np.bool_, copy=False)

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
    def current_band(self) -> int:
        """Band occupied on the most recent step. Fixed-band emitters return
        their static band; frequency-agile emitters override this."""
        return self.band

    def activity(
        self, n_slots: int
    ) -> tuple[NDArray[np.bool_], NDArray[np.intp]] | None:
        """Optional vectorized fast path: (on_per_slot, band_per_slot) for the
        whole episode, or None to fall back to the step() loop. Emitters whose
        state depends on RNG draws made in sequence must return None."""
        return None

    def power_linear(self, n_slots: int) -> NDArray[np.float64] | None:
        """Optional per-slot effective linear power. None means use the
        constant ``10 ** (snr / 10)``. Emitters with a varying effective power
        (e.g. a scanning beam) override this to pass the shape to the detector."""
        return None

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
