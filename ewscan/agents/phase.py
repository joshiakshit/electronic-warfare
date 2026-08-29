"""Phase-conditioned occupancy posterior for sparsely scanned bands.

At k=1 across 16 bands a band is revisited every 11-16 slots. A Markov belief
propagated over that gap decays to its stationary prior, so it carries no
information at selection time. Indexing occupancy by ``slot % period`` instead
of by elapsed time removes the decay entirely: the estimate is as sharp after a
100-slot gap as after one slot.

A wrong period needs no rejection gate. It spreads hits evenly over its phase
buckets, so the phase posterior collapses onto the band's marginal rate and the
model contributes nothing. Only a period that concentrates hits changes any
decision.

Reads (band, slot, detection) only. Never emitter truth or emitter parameters.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.history import HitHistory
from ewscan.agents.period import estimate_period_model_candidates


class PhaseOccupancy:
    """Per-band posterior over P(band is ON at slot t), indexed by slot phase.

    Parameters
    ----------
    n_bands : int
        Number of frequency bands.
    capacity : int
        Ring-buffer capacity for each band's observation history.
    refit_interval : int, default 48
        Observations on a band between period refits. Refitting on a cadence
        rather than on every detection is what keeps the runtime bounded.
    min_hits : int, default 6
        Hits required on a band before a period fit is attempted.
    smoothing : int, default 1
        Circular half-width pooled around the queried phase. Absorbs emitter
        jitter and lends support to phase buckets with few observations.
    prior_strength : float, default 4.0
        Pseudo-count shrinking each phase bucket toward the band's marginal
        rate. This is what makes a wrong period harmless.
    max_period : int, default 200
        Longest period the fitter will consider.
    """

    def __init__(
        self,
        n_bands: int,
        capacity: int,
        refit_interval: int = 48,
        min_hits: int = 6,
        smoothing: int = 1,
        prior_strength: float = 4.0,
        max_period: int = 200,
    ) -> None:
        self._n_bands = int(n_bands)
        self._history = HitHistory(n_bands, capacity)
        self._refit_interval = int(refit_interval)
        self._min_hits = int(min_hits)
        self._smoothing = int(smoothing)
        self._prior_strength = float(prior_strength)
        self._max_period = int(max_period)

        self._counts = np.zeros(n_bands, dtype=np.int64)
        self._hits = np.zeros(n_bands, dtype=np.int64)
        self._since_refit = np.zeros(n_bands, dtype=np.int64)
        self._period: list[int | None] = [None] * n_bands
        self._obs_phase: list[NDArray[np.float64] | None] = [None] * n_bands
        self._hit_phase: list[NDArray[np.float64] | None] = [None] * n_bands

    def observe(self, band: int, slot: int, detection: bool) -> None:
        """Fold one scan outcome into the marginal and phase statistics."""
        self._history.append(band, slot, detection)
        self._counts[band] += 1
        if detection:
            self._hits[band] += 1

        period = self._period[band]
        if period is not None:
            phase = slot % period
            obs_phase = self._obs_phase[band]
            hit_phase = self._hit_phase[band]
            assert obs_phase is not None and hit_phase is not None
            obs_phase[phase] += 1.0
            if detection:
                hit_phase[phase] += 1.0

        self._since_refit[band] += 1
        # A band short of min_hits must not burn its refit slot, or the first
        # fit lands a whole interval after the evidence for it arrived.
        if (
            self._since_refit[band] >= self._refit_interval
            and int(self._hits[band]) >= self._min_hits
        ):
            self._refit(band)

    def _refit(self, band: int) -> None:
        """Re-estimate the band's period and rebuild its phase histogram."""
        self._since_refit[band] = 0
        slots, detections = self._history.recent(band)
        model = estimate_period_model_candidates(
            slots,
            detections,
            min_hits=self._min_hits,
            holdout_fraction=0.0,
            max_period=self._max_period,
        )
        if model is None:
            self._period[band] = None
            self._obs_phase[band] = None
            self._hit_phase[band] = None
            return

        period = int(model.period)
        phases = np.asarray(slots, dtype=np.int64) % period
        self._period[band] = period
        self._obs_phase[band] = np.bincount(
            phases, minlength=period
        ).astype(np.float64)
        self._hit_phase[band] = np.bincount(
            phases[np.asarray(detections, dtype=bool)], minlength=period
        ).astype(np.float64)

    def _marginal(self, band: int) -> float:
        """Jeffreys posterior mean of the band's unconditional ON rate."""
        return float(
            (self._hits[band] + 0.5) / (self._counts[band] + 1.0)
        )

    def _phase_evidence(self, band: int, slot: int) -> tuple[float, float]:
        """Return (hits, observations) for this slot's phase.

        The exact bucket is used whenever it holds any observation. Emitter
        jitter is part of the phase distribution, so pooling neighbours would
        blur a real signal; it is only a fallback for a phase never scanned.
        """
        period = self._period[band]
        if period is None:
            return float(self._hits[band]), float(self._counts[band])

        obs_phase = self._obs_phase[band]
        hit_phase = self._hit_phase[band]
        assert obs_phase is not None and hit_phase is not None
        phase = slot % period
        if obs_phase[phase] > 0.0:
            return float(hit_phase[phase]), float(obs_phase[phase])

        width = min(self._smoothing, (period - 1) // 2)
        if width <= 0:
            return 0.0, 0.0

        window = (np.arange(-width, width + 1) + phase) % period
        return float(hit_phase[window].sum()), float(obs_phase[window].sum())

    def posterior(self, band: int, slot: int) -> tuple[float, float]:
        """Return (mean, standard deviation) of P(ON) for this band and slot.

        The prior pseudo-counts stabilise the mean but deliberately do not
        count toward the spread. A (band, phase) cell nobody has observed must
        stay maximally uncertain, or the scheduler stops exploring it.
        """
        marginal = self._marginal(band)
        hits, observations = self._phase_evidence(band, slot)
        kappa = self._prior_strength
        mean = (hits + kappa * marginal) / (observations + kappa)
        return mean, float(np.sqrt(mean * (1.0 - mean) / (observations + 1.0)))

    def occupancy(self, slot: int) -> NDArray[np.float64]:
        """Posterior mean P(ON at ``slot``) for every band."""
        return np.array(
            [self.posterior(band, slot)[0] for band in range(self._n_bands)],
            dtype=np.float64,
        )

    def upper_bound(self, slot: int, z: float = 1.0) -> NDArray[np.float64]:
        """Optimistic per-band occupancy, used to drive exploration."""
        values = np.empty(self._n_bands, dtype=np.float64)
        for band in range(self._n_bands):
            mean, sd = self.posterior(band, slot)
            values[band] = mean + z * sd
        return values

    def lower_bound(self, band: int, slot: int, z: float = 1.0) -> float:
        """Conservative occupancy for this band, used to gate an override."""
        mean, sd = self.posterior(band, slot)
        return max(0.0, mean - z * sd)

    def period(self, band: int) -> int | None:
        """Current period estimate for a band, or None if none is fitted."""
        return self._period[band]

    def counts(self) -> NDArray[np.int64]:
        """Per-band scan counts."""
        return self._counts.copy()

    def reset(self) -> None:
        """Clear all statistics for a new episode."""
        self._history.reset()
        self._counts[:] = 0
        self._hits[:] = 0
        self._since_refit[:] = 0
        self._period = [None] * self._n_bands
        self._obs_phase = [None] * self._n_bands
        self._hit_phase = [None] * self._n_bands
