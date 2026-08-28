"""Per-band hit-history ring buffer (Sprint 3, Task 1).

Fixed-size circular buffer of recent scan outcomes per band. Feeds period
estimation and next-transmission prediction with a clean chronological
detection time series. Stores raw detection outcomes only, never truth.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray


class HitHistory:
    """Per-band circular buffer of (slot, detection) scan outcomes.

    Parameters
    ----------
    n_bands : int
        Number of frequency bands.
    capacity : int
        Maximum number of entries retained per band.
    """

    def __init__(self, n_bands: int, capacity: int) -> None:
        self._n_bands = n_bands
        self._capacity = capacity
        self._slots: NDArray[np.intp] = np.zeros((n_bands, capacity), dtype=np.intp)
        self._detections: NDArray[np.bool_] = np.zeros(
            (n_bands, capacity), dtype=np.bool_
        )
        self._cursor: NDArray[np.intp] = np.zeros(n_bands, dtype=np.intp)
        self._count: NDArray[np.intp] = np.zeros(n_bands, dtype=np.intp)

    def _check_band(self, band: int) -> None:
        if not (0 <= band < self._n_bands):
            raise IndexError(f"Band index {band} out of range for n_bands={self._n_bands}")

    def append(self, band: int, slot: int, detection: bool) -> None:
        self._check_band(band)
        idx = self._cursor[band]
        self._slots[band, idx] = slot
        self._detections[band, idx] = detection
        self._cursor[band] = (idx + 1) % self._capacity
        self._count[band] = min(self._count[band] + 1, self._capacity)

    def recent(self, band: int) -> tuple[NDArray[np.intp], NDArray[np.bool_]]:
        self._check_band(band)
        n = int(self._count[band])
        if n < self._capacity:
            return self._slots[band, :n].copy(), self._detections[band, :n].copy()
        cursor = self._cursor[band]
        slots = np.concatenate([self._slots[band, cursor:], self._slots[band, :cursor]])
        detections = np.concatenate(
            [self._detections[band, cursor:], self._detections[band, :cursor]]
        )
        return slots, detections

    def slots(self, band: int) -> NDArray[np.intp]:
        return self.recent(band)[0]

    def outcomes(self, band: int) -> NDArray[np.bool_]:
        return self.recent(band)[1]

    def count(self, band: int) -> int:
        self._check_band(band)
        return int(self._count[band])

    def reset(self) -> None:
        self._cursor[:] = 0
        self._count[:] = 0
