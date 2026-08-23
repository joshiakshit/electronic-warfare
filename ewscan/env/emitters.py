"""Signal emitters for RF environment simulation -- Phase 1B.1 to 1B.3.

Provides concrete implementations of the Emitter ABC:
- GilbertElliottEmitter: Two-state Markov model (OFF <-> ON).
- PeriodicEmitter: Pulsed periodic emitter with dwell and timing jitter.
- StaticCWEmitter: Continuous Wave emitter (ON every slot).
"""

from __future__ import annotations

import numpy as np

from ewscan.contracts import Emitter, EmitterInfo


class GilbertElliottEmitter(Emitter):
    """Gilbert-Elliott two-state Markov emitter -- 1B.1.

    State transition model:
      - State 0 (OFF) -> State 1 (ON) with probability p01
      - State 1 (ON)  -> State 0 (OFF) with probability p10

    If initial_state is None during reset(), the initial state is sampled from
    the stationary distribution: P(ON) = p01 / (p01 + p10).
    """

    def __init__(
        self,
        band: int,
        p01: float,
        p10: float,
        snr: float = 10.0,
        threat_level: float = 1.0,
        initial_state: int | None = None,
    ) -> None:
        if not (0.0 <= p01 <= 1.0):
            raise ValueError(f"p01 must be in [0, 1], got {p01}")
        if not (0.0 <= p10 <= 1.0):
            raise ValueError(f"p10 must be in [0, 1], got {p10}")
        if p01 == 0.0 and p10 == 0.0 and initial_state is None:
            raise ValueError("p01 and p10 cannot both be 0 unless initial_state is explicitly set")
        if initial_state is not None and initial_state not in (0, 1):
            raise ValueError(f"initial_state must be 0, 1, or None, got {initial_state}")

        self.band = int(band)
        self.p01 = float(p01)
        self.p10 = float(p10)
        self.snr = float(snr)
        self.threat_level = float(threat_level)
        self.initial_state = initial_state

        self._state: int = 0
        self._rng: np.random.Generator | None = None

    def reset(self, rng: np.random.Generator) -> None:
        self._rng = rng
        if self.initial_state is not None:
            self._state = self.initial_state
        else:
            p_on = self.p01 / (self.p01 + self.p10) if (self.p01 + self.p10) > 0 else 0.0
            self._state = 1 if rng.random() < p_on else 0

    def step(self) -> bool:
        if self._rng is None:
            raise RuntimeError("Emitter must be reset() before calling step()")

        current_on = bool(self._state)
        if self._state == 0:
            if self._rng.random() < self.p01:
                self._state = 1
        else:
            if self._rng.random() < self.p10:
                self._state = 0

        return current_on

    @property
    def info(self) -> EmitterInfo:
        return EmitterInfo(
            band=self.band,
            snr=self.snr,
            threat_level=self.threat_level,
            emitter_type="gilbert_elliott",
            params={"p01": self.p01, "p10": self.p10},
        )


class PeriodicEmitter(Emitter):
    """Periodic pulsed radar emitter -- 1B.2.

    Parameters:
      - period (P >= 1): Cycle length in slots.
      - dwell (1 <= D <= P): Active ON duration in slots per period.
      - jitter (J >= 0): Maximum slot timing offset per period, drawn from [-J, J].
      - phase (phase >= 0): Fixed initial slot offset.
    """

    def __init__(
        self,
        band: int,
        period: int,
        dwell: int = 1,
        jitter: int = 0,
        phase: int = 0,
        snr: float = 10.0,
        threat_level: float = 1.0,
    ) -> None:
        if period < 1:
            raise ValueError(f"period must be >= 1, got {period}")
        if not (1 <= dwell <= period):
            raise ValueError(f"dwell must be between 1 and period ({period}), got {dwell}")
        if jitter < 0:
            raise ValueError(f"jitter must be >= 0, got {jitter}")
        if phase < 0:
            raise ValueError(f"phase must be >= 0, got {phase}")

        self.band = int(band)
        self.period = int(period)
        self.dwell = int(dwell)
        self.jitter = int(jitter)
        self.phase = int(phase)
        self.snr = float(snr)
        self.threat_level = float(threat_level)

        self._slot: int = 0
        self._rng: np.random.Generator | None = None
        self._period_jitters: dict[int, int] = {}

    def reset(self, rng: np.random.Generator) -> None:
        self._rng = rng
        self._slot = 0
        self._period_jitters = {}

    def _get_jitter(self, period_idx: int) -> int:
        if self.jitter == 0:
            return 0
        if period_idx not in self._period_jitters:
            if self._rng is None:
                raise RuntimeError("Emitter must be reset() before calling step()")
            self._period_jitters[period_idx] = int(
                self._rng.integers(-self.jitter, self.jitter + 1)
            )
            # Prune old entries to cap memory (keep only recent window)
            max_offset = (self.jitter // self.period) + 1 if self.period > 0 else 1
            min_keep = max(0, period_idx - max_offset - 2)
            stale = [k for k in self._period_jitters if k < min_keep]
            for k in stale:
                del self._period_jitters[k]
        return self._period_jitters[period_idx]

    def step(self) -> bool:
        if self._rng is None:
            raise RuntimeError("Emitter must be reset() before calling step()")

        t = self._slot
        is_on = False

        if t >= self.phase:
            approx_k = (t - self.phase) // self.period
            # Widen search window based on jitter magnitude to avoid
            # missing pulses when jitter > period
            max_offset = (self.jitter // self.period) + 1 if self.period > 0 else 1
            for k in range(max(0, approx_k - max_offset), approx_k + max_offset + 1):
                j = self._get_jitter(k)
                start = k * self.period + self.phase + j
                end = start + self.dwell
                if start <= t < end:
                    is_on = True
                    break

        self._slot += 1
        return is_on

    @property
    def info(self) -> EmitterInfo:
        return EmitterInfo(
            band=self.band,
            snr=self.snr,
            threat_level=self.threat_level,
            emitter_type="periodic",
            params={
                "period": self.period,
                "dwell": self.dwell,
                "jitter": self.jitter,
                "phase": self.phase,
            },
        )


class StaticCWEmitter(Emitter):
    """Static Continuous Wave (CW) emitter -- 1B.3.

    Emits continuously (ON in every slot).
    """

    def __init__(
        self,
        band: int,
        snr: float = 10.0,
        threat_level: float = 1.0,
    ) -> None:
        self.band = int(band)
        self.snr = float(snr)
        self.threat_level = float(threat_level)
        self._rng: np.random.Generator | None = None

    def reset(self, rng: np.random.Generator) -> None:
        self._rng = rng

    def step(self) -> bool:
        if self._rng is None:
            raise RuntimeError("Emitter must be reset() before calling step()")
        return True

    @property
    def info(self) -> EmitterInfo:
        return EmitterInfo(
            band=self.band,
            snr=self.snr,
            threat_level=self.threat_level,
            emitter_type="cw",
            params={},
        )


def emitter_from_info(info: EmitterInfo) -> Emitter:
    """Instantiate a concrete Emitter from an EmitterInfo specification.

    Parameters
    ----------
    info : EmitterInfo
        The static specification of the emitter.

    Returns
    -------
    Emitter
        The instantiated concrete emitter.

    Raises
    ------
    ValueError
        If the emitter_type is not recognized.
    """
    emitter_type = info.emitter_type.lower().strip()
    if emitter_type in ("gilbert_elliott", "markov", "ge"):
        return GilbertElliottEmitter(
            band=info.band,
            snr=info.snr,
            threat_level=info.threat_level,
            **info.params,
        )
    elif emitter_type in ("periodic", "radar"):
        return PeriodicEmitter(
            band=info.band,
            snr=info.snr,
            threat_level=info.threat_level,
            **info.params,
        )
    elif emitter_type in ("cw", "static_cw", "static"):
        return StaticCWEmitter(
            band=info.band,
            snr=info.snr,
            threat_level=info.threat_level,
        )
    else:
        raise ValueError(f"Unknown emitter type: {info.emitter_type!r}")

