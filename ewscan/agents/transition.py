"""Online Gilbert-Elliott transition estimator (p01/p10) from noisy detections.

The estimator only ever sees (band, slot, detection) triples supplied by the
caller. It never reads emitter parameters or the truth matrix. Because the
input is a detection, not truth, the estimates are biased by the detector ROC
(Pd < 1 causes p10 to look too high, Pfa > 0 causes p01 to look too high). This
bias is accepted for the MVP and is not corrected here.
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
