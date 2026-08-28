"""Per-emitter activity lookup shared by attribution metrics.

Uses the per-emitter truth and occupied-band logs when present so hopping and
co-resident emitters attribute correctly. Falls back to the band-level truth
and the emitter's static configured band for hand-built logs that omit them.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeLog


def emitter_activity(
    log: EpisodeLog, idx: int
) -> tuple[NDArray[np.bool_], NDArray[np.intp]]:
    """Return ``(on_per_slot, band_per_slot)`` for emitter ``idx``."""
    n_slots = log.n_slots
    if log.emitter_truth is not None and log.emitter_bands is not None:
        return (
            np.asarray(log.emitter_truth[idx], dtype=np.bool_),
            np.asarray(log.emitter_bands[idx], dtype=np.intp),
        )

    band = log.config.emitters[idx].band
    if 0 <= band < log.n_bands:
        on = np.asarray(log.truth[band, :], dtype=np.bool_)
    else:
        on = np.zeros(n_slots, dtype=np.bool_)
    bands = np.full(n_slots, band, dtype=np.intp)
    return on, bands
