"""Online Gilbert-Elliott transition estimators from noisy detections.

Two estimators:

- ``TransitionEstimator``: legacy gap==1 counter (used by BeliefScheduler).
- ``GapAwareTransitionEstimator``: T^d propagation with EM-style expected
  transition count learning. Works across arbitrary observation gaps.

Neither reads emitter parameters or the truth matrix.
"""

from __future__ import annotations

from collections import deque

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

    Propagates belief across arbitrary gaps. A forward-backward bridge adds
    expected one-step transition counts for every unobserved gap.
    """

    def __init__(
        self,
        n_bands: int,
        p01_init: float = 0.5,
        p10_init: float = 0.5,
        pd: float = 0.9,
        pfa: float = 0.01,
        rate_update_interval: int = 50,
        fit_window: int = 1024,
    ) -> None:
        self._n_bands = n_bands
        self._pd = float(pd)
        self._pfa = float(pfa)
        self._rate_update_interval = int(rate_update_interval)
        self._fit_window = int(fit_window)
        self._p01_init = float(p01_init)
        self._p10_init = float(p10_init)

        self._p01 = np.full(n_bands, p01_init, dtype=np.float64)
        self._p10 = np.full(n_bands, p10_init, dtype=np.float64)
        self._belief = np.full(n_bands, 0.5, dtype=np.float64)

        self._last_slot = np.full(n_bands, -1, dtype=np.int64)
        self._obs_count = np.zeros(n_bands, dtype=np.int64)
        self._prev_belief = np.full(n_bands, 0.5, dtype=np.float64)

        self._expected_counts = np.zeros((n_bands, 2, 2), dtype=np.float64)
        self._events: list[deque[tuple[int, bool]]] = [
            deque(maxlen=self._fit_window) for _ in range(n_bands)
        ]
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

    def _bridge_statistics(
        self,
        band: int,
        start_belief: float,
        gap: int,
        detection: bool,
    ) -> tuple[float, NDArray[np.float64]]:
        """Return the terminal posterior and expected transitions over one gap."""
        if gap < 1:
            raise ValueError(f"gap must be positive, got {gap}")

        transition = np.array(
            [
                [1.0 - self._p01[band], self._p01[band]],
                [self._p10[band], 1.0 - self._p10[band]],
            ],
            dtype=np.float64,
        )
        likelihood = np.array(
            [
                self._pfa if detection else 1.0 - self._pfa,
                self._pd if detection else 1.0 - self._pd,
            ],
            dtype=np.float64,
        )

        forward = np.empty((gap + 1, 2), dtype=np.float64)
        forward[0] = (1.0 - start_belief, start_belief)
        for step in range(1, gap + 1):
            forward[step] = forward[step - 1] @ transition

        evidence = float(forward[gap] @ likelihood)
        if evidence < 1e-15:
            return float(forward[gap, 1]), np.zeros((2, 2), dtype=np.float64)

        backward = np.empty((gap + 1, 2), dtype=np.float64)
        backward[gap] = likelihood
        for step in range(gap - 1, -1, -1):
            backward[step] = transition @ backward[step + 1]

        counts = np.zeros((2, 2), dtype=np.float64)
        for step in range(gap):
            counts += (
                forward[step, :, None]
                * transition
                * backward[step + 1, None, :]
                / evidence
            )

        posterior = forward[gap] * likelihood / evidence
        return float(posterior[1]), counts

    def _maybe_update_rates(self, band: int) -> None:
        """Reestimate p01/p10 from accumulated expected transition counts."""
        n_pairs = int(self._n_pairs[band])
        if n_pairs < 10 or (
            n_pairs != 10 and n_pairs % self._rate_update_interval != 0
        ):
            return

        events = tuple(self._events[band])
        if len(events) < 4:
            return

        if abs(1.0 - self._p01[band] - self._p10[band]) < 0.01:
            detection_rate = sum(detection for _, detection in events) / len(events)
            detector_span = self._pd - self._pfa
            stationary_on = (
                (detection_rate - self._pfa) / detector_span
                if abs(detector_span) > 1e-12
                else 0.5
            )
            stationary_on = float(np.clip(stationary_on, 0.02, 0.98))
            initial_rate = 0.4
            self._p01[band] = stationary_on * initial_rate
            self._p10[band] = (1.0 - stationary_on) * initial_rate

        for _ in range(4):
            total_counts = np.zeros((2, 2), dtype=np.float64)
            rate_sum = self._p01[band] + self._p10[band]
            belief = self._p01[band] / rate_sum if rate_sum > 1e-15 else 0.5
            self._belief[band] = belief
            self._correct(band, events[0][1])
            belief = float(self._belief[band])

            for (previous_slot, _), (slot, detection) in zip(events, events[1:]):
                gap = slot - previous_slot
                if gap < 1:
                    continue
                belief, counts = self._bridge_statistics(
                    band,
                    belief,
                    gap,
                    detection,
                )
                total_counts += counts

            prior_weight = 0.5
            off_total = float(total_counts[0].sum())
            on_total = float(total_counts[1].sum())
            self._p01[band] = np.clip(
                (total_counts[0, 1] + prior_weight * self._p01_init)
                / (off_total + prior_weight),
                0.001,
                0.999,
            )
            self._p10[band] = np.clip(
                (total_counts[1, 0] + prior_weight * self._p10_init)
                / (on_total + prior_weight),
                0.001,
                0.999,
            )

        self._expected_counts[band] = total_counts
        self._belief[band] = belief

    def observe(self, band: int, slot: int, det: bool) -> None:
        """Process one (band, slot, detection) observation."""
        prev_slot = int(self._last_slot[band])
        b_prev_corrected = self._prev_belief[band]

        if prev_slot >= 0:
            gap = slot - prev_slot
            if gap > 0:
                posterior, counts = self._bridge_statistics(
                    band,
                    b_prev_corrected,
                    gap,
                    det,
                )
                self._belief[band] = posterior
                self._expected_counts[band] += counts
                self._n_pairs[band] += 1
        else:
            self._correct(band, det)

        self._prev_belief[band] = self._belief[band]
        self._last_slot[band] = slot
        self._obs_count[band] += 1
        self._events[band].append((slot, bool(det)))
        self._maybe_update_rates(band)
        self._prev_belief[band] = self._belief[band]

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
        self._p01[:] = self._p01_init
        self._p10[:] = self._p10_init
        self._belief[:] = 0.5
        self._prev_belief[:] = 0.5
        self._last_slot[:] = -1
        self._obs_count[:] = 0
        self._expected_counts[:] = 0.0
        for events in self._events:
            events.clear()
        self._n_pairs[:] = 0
        self._since_update[:] = 0
