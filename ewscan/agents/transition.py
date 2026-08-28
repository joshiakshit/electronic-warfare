"""Online Gilbert-Elliott transition estimators from noisy detections.

Two estimators:

- ``TransitionEstimator``: legacy gap==1 counter (used by BeliefScheduler).
- ``GapAwareTransitionEstimator``: T^d propagation with EM-style expected
  transition count learning. Works across arbitrary observation gaps.

Neither reads emitter parameters or the truth matrix.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray


class TransitionEstimator:
    """Per-band online estimator of P(OFF->ON) and P(ON->OFF).

    Uses Beta(1,1) (Laplace) smoothing so estimates start at 0.5/0.5 and move
    with data. Only adjacent-slot pairs (cur_slot - prev_slot == 1) count
    toward a transition; wider gaps span an unknown number of hidden
    transitions and are discarded.
    """

    def __init__(self, n_bands: int) -> None:
        self._n_bands = n_bands
        self._n_00 = np.zeros(n_bands, dtype=np.int64)
        self._n_01 = np.zeros(n_bands, dtype=np.int64)
        self._n_10 = np.zeros(n_bands, dtype=np.int64)
        self._n_11 = np.zeros(n_bands, dtype=np.int64)
        self._last_slot = np.full(n_bands, -1, dtype=np.int64)
        self._last_det = np.zeros(n_bands, dtype=bool)

    def observe(self, band: int, slot: int, det: bool) -> None:
        """Form a pair with this band's previous observation and update."""
        prev_slot = self._last_slot[band]
        if prev_slot != -1:
            self.update(band, int(prev_slot), bool(self._last_det[band]), slot, det)
        self._last_slot[band] = slot
        self._last_det[band] = det

    def update(
        self,
        band: int,
        prev_slot: int,
        prev_det: bool,
        cur_slot: int,
        cur_det: bool,
    ) -> None:
        if cur_slot - prev_slot != 1:
            return
        if not prev_det and not cur_det:
            self._n_00[band] += 1
        elif not prev_det and cur_det:
            self._n_01[band] += 1
        elif prev_det and not cur_det:
            self._n_10[band] += 1
        else:
            self._n_11[band] += 1

    def p01(self) -> NDArray[np.float64]:
        return (self._n_01 + 1) / (self._n_00 + self._n_01 + 2)

    def p10(self) -> NDArray[np.float64]:
        return (self._n_10 + 1) / (self._n_11 + self._n_10 + 2)

    def counts(self, band: int) -> dict[str, int]:
        return {
            "n_00": int(self._n_00[band]),
            "n_01": int(self._n_01[band]),
            "n_10": int(self._n_10[band]),
            "n_11": int(self._n_11[band]),
        }

    def reset(self) -> None:
        self._n_00[:] = 0
        self._n_01[:] = 0
        self._n_10[:] = 0
        self._n_11[:] = 0
        self._last_slot[:] = -1
        self._last_det[:] = False


class GapAwareTransitionEstimator:
    """Gap-aware two-state HMM estimator using T^d belief propagation.

    Propagates belief across arbitrary gaps using the closed-form T^d.
    Learns p01/p10 via method of moments: estimates pi_on from the mean
    corrected belief, measures the d-step transition frequency, then inverts
    the matrix power formula to recover one-step rates.
    """

    def __init__(
        self,
        n_bands: int,
        p01_init: float = 0.5,
        p10_init: float = 0.5,
        pd: float = 0.9,
        pfa: float = 0.01,
        rate_update_interval: int = 10,
    ) -> None:
        self._n_bands = n_bands
        self._pd = float(pd)
        self._pfa = float(pfa)
        self._rate_update_interval = int(rate_update_interval)

        self._p01 = np.full(n_bands, p01_init, dtype=np.float64)
        self._p10 = np.full(n_bands, p10_init, dtype=np.float64)
        self._belief = np.full(n_bands, 0.5, dtype=np.float64)

        self._last_slot = np.full(n_bands, -1, dtype=np.int64)
        self._obs_count = np.zeros(n_bands, dtype=np.int64)
        self._prev_belief = np.full(n_bands, 0.5, dtype=np.float64)

        # Moment accumulators for rate estimation
        self._sum_belief = np.zeros(n_bands, dtype=np.float64)
        self._sum_f01 = np.zeros(n_bands, dtype=np.float64)
        self._sum_from0 = np.zeros(n_bands, dtype=np.float64)
        self._sum_gap = np.zeros(n_bands, dtype=np.float64)
        self._n_pairs = np.zeros(n_bands, dtype=np.int64)
        self._since_update = np.zeros(n_bands, dtype=np.int64)

    def _propagate_belief(self, band: int, gap: int) -> float:
        """Propagate belief forward by gap steps using T^d closed form."""
        b = self._belief[band]
        p01 = self._p01[band]
        p10 = self._p10[band]
        s = p01 + p10
        if s < 1e-15:
            return b
        pi_on = p01 / s
        lam = 1.0 - s
        return pi_on + (b - pi_on) * lam ** gap

    def _correct(self, band: int, detection: bool) -> None:
        """Bayes update: incorporate a detection observation."""
        b = self._belief[band]
        l_on = self._pd if detection else (1.0 - self._pd)
        l_off = self._pfa if detection else (1.0 - self._pfa)
        denom = l_on * b + l_off * (1.0 - b)
        if denom < 1e-15:
            return
        self._belief[band] = np.clip((l_on * b) / denom, 0.0, 1.0)

    def _accumulate_pair(
        self, band: int, gap: int,
        b_prev_corrected: float, b_curr_corrected: float,
    ) -> None:
        """Accumulate d-step soft transition statistics from endpoint beliefs."""
        if gap < 1:
            return
        s_prev_off = 1.0 - b_prev_corrected
        s_curr_on = b_curr_corrected

        self._sum_f01[band] += s_prev_off * s_curr_on
        self._sum_from0[band] += s_prev_off
        self._sum_gap[band] += gap
        self._n_pairs[band] += 1

    def _maybe_update_rates(self, band: int) -> None:
        """Reestimate p01/p10 using matrix power inversion."""
        self._since_update[band] += 1
        if self._since_update[band] < self._rate_update_interval:
            return
        self._since_update[band] = 0

        n_obs = int(self._obs_count[band])
        n_pairs = int(self._n_pairs[band])
        if n_obs < 4 or n_pairs < 2:
            return

        pi_on = self._sum_belief[band] / n_obs
        pi_on = np.clip(pi_on, 0.02, 0.98)
        pi_off = 1.0 - pi_on

        # d-step OFF->ON transition frequency
        if self._sum_from0[band] < 0.5:
            return
        f01_d = self._sum_f01[band] / self._sum_from0[band]
        f01_d = np.clip(f01_d, 0.01, 0.99)

        mean_gap = self._sum_gap[band] / max(n_pairs, 1)
        mean_gap = max(mean_gap, 1.0)

        # Invert [T^d]_{01} = pi_on * (1 - lambda^d)
        # lambda^d = 1 - f01_d / pi_on
        ratio = f01_d / pi_on
        ratio = np.clip(ratio, 0.01, 0.99)
        lam_d = 1.0 - ratio
        lam_d = np.clip(lam_d, 1e-8, 1.0 - 1e-8)
        lam = lam_d ** (1.0 / mean_gap)
        lam = np.clip(lam, 0.0, 0.998)

        s = 1.0 - lam
        s = np.clip(s, 0.002, 0.998)
        self._p01[band] = np.clip(pi_on * s, 0.001, 0.999)
        self._p10[band] = np.clip(pi_off * s, 0.001, 0.999)

    def observe(self, band: int, slot: int, det: bool) -> None:
        """Process one (band, slot, detection) observation."""
        prev_slot = int(self._last_slot[band])
        b_prev_corrected = self._prev_belief[band]

        if prev_slot >= 0:
            gap = slot - prev_slot
            if gap > 0:
                self._belief[band] = self._propagate_belief(band, gap)

        self._correct(band, det)
        self._sum_belief[band] += self._belief[band]

        if prev_slot >= 0:
            gap = slot - prev_slot
            if gap > 0:
                self._accumulate_pair(
                    band, gap, b_prev_corrected, self._belief[band],
                )

        self._prev_belief[band] = self._belief[band]
        self._last_slot[band] = slot
        self._obs_count[band] += 1
        self._maybe_update_rates(band)

    def p01(self) -> NDArray[np.float64]:
        return self._p01.copy()

    def p10(self) -> NDArray[np.float64]:
        return self._p10.copy()

    @property
    def belief(self) -> NDArray[np.float64]:
        return self._belief.copy()

    def uncertainty(self, band: int) -> float:
        """Normalized uncertainty: 1.0 at zero data, decreasing with evidence."""
        count = int(self._obs_count[band])
        if count < 2:
            return 1.0
        return 1.0 / (1.0 + self._n_pairs[band] * 0.1)

    def reset(self) -> None:
        self._p01[:] = 0.5
        self._p10[:] = 0.5
        self._belief[:] = 0.5
        self._prev_belief[:] = 0.5
        self._last_slot[:] = -1
        self._obs_count[:] = 0
        self._sum_belief[:] = 0.0
        self._sum_f01[:] = 0.0
        self._sum_from0[:] = 0.0
        self._sum_gap[:] = 0.0
        self._n_pairs[:] = 0
        self._since_update[:] = 0
