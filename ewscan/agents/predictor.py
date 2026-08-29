"""Next-transmission prediction from period estimates (Sprint 3, Task 6).

Predicts, per band, the next slot a periodic emitter will be ON, with an
empirical confidence built purely from scanned outcomes. Feeds the
predicted_band wiring (Task 0); never reads truth.
"""

from __future__ import annotations

from collections import deque

from ewscan.agents.period import PeriodEstimator


class NextTxPredictor:
    """Per-band next-ON-slot predictor with an empirically calibrated confidence."""

    def __init__(self, n_bands: int, capacity: int, tau_conf: float = 0.6, window: int = 20) -> None:
        self._n_bands = n_bands
        self._tau_conf = tau_conf
        self._period_estimator = PeriodEstimator(n_bands, capacity, sparse=True)
        self._last_hit: list[int | None] = [None] * n_bands
        self._outcomes: list[deque[bool]] = [deque(maxlen=window) for _ in range(n_bands)]

    def observe(self, band: int, slot: int, detection: bool) -> None:
        self._period_estimator.observe(band, slot, detection)
        if detection:
            self._last_hit[band] = slot

    def _due_slot(self, band: int, slot: int) -> int | None:
        model = self._period_estimator.model(band)
        if model is None:
            return None
        return slot if model.is_due(slot) else None

    def due_bands(self, slot: int) -> list[tuple[int, float]]:
        due = []
        for band in range(self._n_bands):
            if self._due_slot(band, slot) != slot:
                continue
            conf = self.confidence(band)
            if conf >= self._tau_conf:
                due.append((band, conf))
        return due

    def confidence(self, band: int) -> float:
        outcomes = self._outcomes[band]
        correct = sum(outcomes)
        total = len(outcomes)
        return (correct + 1) / (total + 2)

    def lower_confidence(self, band: int) -> float:
        outcomes = self._outcomes[band]
        total = len(outcomes)
        confidence = self.confidence(band)
        return max(
            0.0,
            confidence - (confidence * (1.0 - confidence) / (total + 3)) ** 0.5,
        )

    def record_outcome(self, band: int, slot: int, was_on: bool) -> None:
        # Only score outcomes for slots the predictor itself believed were due;
        # this is what makes confidence an empirical hit rate, not a truth read.
        if self._due_slot(band, slot) != slot:
            return
        self._outcomes[band].append(bool(was_on))
