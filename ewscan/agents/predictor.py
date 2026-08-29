"""Next-transmission prediction from phase-conditioned occupancy (Sprint 3, Task 6).

Predicts, per band, whether a periodic emitter is transmitting in the current
slot, with an empirical confidence built purely from scanned outcomes. Feeds
the predicted_band wiring (Task 0); never reads truth.

The occupancy posterior is indexed by slot phase rather than by elapsed time,
so a prediction is as sharp after a 100-slot revisit gap as after one slot.
That is what lets the predictor fire at a k=1 scan rate.
"""

from __future__ import annotations

from collections import deque

from ewscan.agents.phase import PhaseOccupancy


class NextTxPredictor:
    """Per-band due-now predictor with an empirically calibrated confidence."""

    def __init__(
        self,
        n_bands: int,
        capacity: int,
        tau_conf: float = 0.6,
        window: int = 20,
        due_threshold: float = 0.5,
    ) -> None:
        self._n_bands = n_bands
        self._tau_conf = tau_conf
        self._due_threshold = float(due_threshold)
        self._occupancy = PhaseOccupancy(n_bands, capacity)
        self._outcomes: list[deque[bool]] = [deque(maxlen=window) for _ in range(n_bands)]
        # due_bands records the slot it was asked about so lower_confidence can
        # answer for that same slot without changing its one-argument signature.
        self._query_slot = 0

    def observe(self, band: int, slot: int, detection: bool) -> None:
        self._occupancy.observe(band, slot, detection)

    def _is_due(self, band: int, slot: int) -> bool:
        if self._occupancy.period(band) is None:
            return False
        return self._occupancy.posterior(band, slot)[0] >= self._due_threshold

    def due_bands(self, slot: int) -> list[tuple[int, float]]:
        self._query_slot = slot
        due = []
        for band in range(self._n_bands):
            if not self._is_due(band, slot):
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
        """Conservative P(ON now) for this band, on the last queried slot.

        This is measured occupancy at the band's current phase, not the
        outcome-window hit rate, so it carries real support from the first
        prediction onward instead of waiting on a scored-outcome bootstrap.
        """
        return self._occupancy.lower_bound(band, self._query_slot)

    def period(self, band: int) -> int | None:
        return self._occupancy.period(band)

    def record_outcome(self, band: int, slot: int, was_on: bool) -> None:
        # Only score outcomes for slots the predictor itself believed were due;
        # this is what makes confidence an empirical hit rate, not a truth read.
        if not self._is_due(band, slot):
            return
        self._outcomes[band].append(bool(was_on))
