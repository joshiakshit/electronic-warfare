"""Time to first intercept estimators from the episode log -- Phase 1E.3.

Estimates the latency / speed with which the receiver achieves initial detection
of each active emitter.

Definitions
-----------
**Time to First Intercept (TTFI):**
  For a given emitter on band *b*, the earliest slot index *t* (0-indexed) at which:
  1. The receiver was tuned to band *b* (``actions[t] == b``).
  2. Band *b* was transmitting in ground truth (``truth[b, t] == True``).
  3. The detector reported a detection (``detections[t] == True``).

  If an emitter is never intercepted during the episode, its
  ``first_intercept_slot`` is ``None`` and ``intercepted`` is ``False``.

**Mean Time to First Intercept:**
  The arithmetic mean of ``first_intercept_slot`` across all intercepted emitters:

  Mean TTFI = (sum of first_intercept_slot for intercepted emitters) / (# intercepted emitters)

  Returns ``float('nan')`` if no emitters were intercepted (or if no emitters are configured).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeLog
from ewscan.metrics._emitter import emitter_activity


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmitterFirstIntercept:
    """Time-to-first-intercept result for a single emitter.

    Attributes
    ----------
    emitter_index : int
        Index into ``EpisodeConfig.emitters``.
    band : int
        The frequency band this emitter occupies.
    first_intercept_slot : int | None
        Slot index of the first successful intercept (0-indexed), or None if never intercepted.
    intercepted : bool
        True if the emitter was intercepted at least once during the episode.
    """

    emitter_index: int
    band: int
    first_intercept_slot: int | None
    intercepted: bool


@dataclass(frozen=True)
class FirstInterceptMetrics:
    """Complete summary of time-to-first-intercept across all configured emitters.

    Attributes
    ----------
    per_emitter : tuple[EmitterFirstIntercept, ...]
        Per-emitter first intercept records in config order.
    mean_time_to_first_intercept : float
        Mean slot index of first intercept over all intercepted emitters,
        or NaN if no emitters were intercepted.
    n_emitters : int
        Total number of emitters in the episode configuration.
    n_intercepted : int
        Total number of emitters successfully intercepted at least once.
    """

    per_emitter: tuple[EmitterFirstIntercept, ...]
    mean_time_to_first_intercept: float
    mean_time_to_first_intercept_penalized: float
    intercept_fraction: float
    n_emitters: int
    n_intercepted: int


# ---------------------------------------------------------------------------
# Core estimation functions
# ---------------------------------------------------------------------------

def estimate_per_emitter_first_intercept(
    log: EpisodeLog,
) -> tuple[EmitterFirstIntercept, ...]:
    """Estimate time to first intercept for each configured emitter.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log with config, truth, actions, and detections.

    Returns
    -------
    tuple[EmitterFirstIntercept, ...]
        One result per emitter declared in ``log.config.emitters``.
    """
    results: list[EmitterFirstIntercept] = []
    if log.n_slots == 0:
        for idx, emitter_info in enumerate(log.config.emitters):
            results.append(
                EmitterFirstIntercept(
                    emitter_index=idx,
                    band=emitter_info.band,
                    first_intercept_slot=None,
                    intercepted=False,
                )
            )
        return tuple(results)

    # Safe indexing: clamp invalid actions to avoid negative index wrap-around
    actions = log.actions
    valid_actions = (actions >= 0) & (actions < log.n_bands)
    safe_actions = np.where(valid_actions, actions, 0)
    slots = np.arange(log.n_slots)[:, None]
    scanned_truth = log.truth[safe_actions, slots]
    scanned_truth[~valid_actions] = False
    hits = log.detections & scanned_truth & log.valid_slots[:, None]

    for idx, emitter_info in enumerate(log.config.emitters):
        band = emitter_info.band
        on, em_bands = emitter_activity(log, idx)
        scanned_emitter = log.actions == em_bands[:, None]
        emitter_hits = (hits & scanned_emitter & on[:, None]).any(axis=1)

        hit_slots = np.flatnonzero(emitter_hits)
        if len(hit_slots) > 0:
            first_slot = int(hit_slots[0])
            results.append(
                EmitterFirstIntercept(
                    emitter_index=idx,
                    band=band,
                    first_intercept_slot=first_slot,
                    intercepted=True,
                )
            )
        else:
            results.append(
                EmitterFirstIntercept(
                    emitter_index=idx,
                    band=band,
                    first_intercept_slot=None,
                    intercepted=False,
                )
            )

    return tuple(results)


def estimate_first_intercept_metrics(log: EpisodeLog) -> FirstInterceptMetrics:
    """Compute overall first intercept metrics from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.

    Returns
    -------
    FirstInterceptMetrics
        Complete time-to-first-intercept summary.
    """
    per_emitter = estimate_per_emitter_first_intercept(log)
    n_emitters = len(per_emitter)

    intercepted_slots = [
        e.first_intercept_slot
        for e in per_emitter
        if e.first_intercept_slot is not None
    ]
    n_intercepted = len(intercepted_slots)

    if n_intercepted > 0:
        mean_ttfi = float(np.mean(intercepted_slots))
    else:
        mean_ttfi = float("nan")

    # Horizon-penalized TTFI charges every missed emitter the full episode
    # length, so a scheduler cannot look good by ignoring hard emitters.
    if n_emitters > 0:
        horizon = float(log.n_slots)
        penalized = [
            float(e.first_intercept_slot) if e.first_intercept_slot is not None else horizon
            for e in per_emitter
        ]
        mean_ttfi_penalized = float(np.mean(penalized))
        intercept_fraction = n_intercepted / n_emitters
    else:
        mean_ttfi_penalized = float("nan")
        intercept_fraction = float("nan")

    return FirstInterceptMetrics(
        per_emitter=per_emitter,
        mean_time_to_first_intercept=mean_ttfi,
        mean_time_to_first_intercept_penalized=mean_ttfi_penalized,
        intercept_fraction=intercept_fraction,
        n_emitters=n_emitters,
        n_intercepted=n_intercepted,
    )
