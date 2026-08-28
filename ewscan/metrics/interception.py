"""Interception ratio and average intercept rate estimators from the episode log -- Phase 1E.2.

Estimates how effectively the receiver intercepts RF emitter activity across
the operational spectrum and over time.

Definitions
-----------
**Hit / Intercept at slot t:**
  A scan is an intercept (hit) if the receiver tuned to a band that was
  actively transmitting in truth AND the sensor produced a detection.
  False alarms (detections on silent bands) are excluded.

**Interception ratio:**
  The fraction of total ground-truth transmission opportunities across all
  bands that were intercepted by the receiver.

  Interception Ratio = (# hits) / (total active band-slots in truth)

  For an omniscient Oracle scheduler on non-overlapping transmissions, this
  approaches 1.0 (the theoretical ceiling).  For a uniform random scanner
  across N bands with 1 active emitter, this is ~1/N.

**Average intercept rate:**
  The average number of successful intercepts per receiver time slot.

  Average Intercept Rate = (# hits) / (# total episode slots)

  Represents the operational scan efficiency (fraction of slots yielding a true intercept).

**Per-emitter interception ratio:**
  The fraction of an individual emitter's transmission slots that were
  intercepted by the receiver.
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
class InterceptionRatioEstimate:
    """Aggregate interception ratio estimate.

    Attributes
    ----------
    ratio : float
        Fraction of all active band-slots intercepted, NaN if no transmissions occurred.
    n_hits : int
        Total number of successful intercepts (true positive detections).
    n_transmissions : int
        Total number of active band-slots in ground truth across all bands.
    """

    ratio: float
    n_hits: int
    n_transmissions: int


@dataclass(frozen=True)
class InterceptRateEstimate:
    """Average intercept rate estimate per receiver scan slot.

    Attributes
    ----------
    rate : float
        Average number of intercepts per slot, NaN if n_slots == 0.
    n_hits : int
        Total number of successful intercepts.
    n_slots : int
        Total number of slots in the episode.
    """

    rate: float
    n_hits: int
    n_slots: int


@dataclass(frozen=True)
class EmitterInterceptionEstimate:
    """Per-emitter interception ratio estimate.

    Attributes
    ----------
    emitter_index : int
        Index into ``EpisodeConfig.emitters``.
    band : int
        The band this emitter occupies.
    interception_ratio : float
        Fraction of this emitter's transmissions intercepted, NaN if never transmitted.
    n_hits : int
        Number of successful intercepts of this emitter.
    n_transmissions : int
        Number of slots this emitter's band was active in truth.
    """

    emitter_index: int
    band: int
    interception_ratio: float
    n_hits: int
    n_transmissions: int


@dataclass(frozen=True)
class InterceptionMetrics:
    """Complete interception performance summary for one episode.

    Bundles aggregate interception ratio, average intercept rate, and
    per-emitter interception statistics.
    """

    interception_ratio: InterceptionRatioEstimate
    intercept_rate: InterceptRateEstimate
    per_emitter: tuple[EmitterInterceptionEstimate, ...]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _scanned_hits(log: EpisodeLog) -> NDArray[np.bool_]:
    """Compute a (n_slots, k) boolean array of per-channel hits.

    Entry (t, j) is a hit when:
    1. The scanned band was transmitting: ``truth[actions[t, j], t] == True``.
    2. The detector registered a detection: ``detections[t, j] == True``.
    """
    if log.n_slots == 0:
        return np.empty((0, log.k), dtype=np.bool_)
    actions = log.actions
    valid = (actions >= 0) & (actions < log.n_bands)
    safe = np.where(valid, actions, 0)
    slots = np.arange(log.n_slots)[:, None]
    scanned_truth = log.truth[safe, slots]
    scanned_truth[~valid] = False
    return log.detections & scanned_truth & log.valid_slots[:, None]


# ---------------------------------------------------------------------------
# Core estimation functions
# ---------------------------------------------------------------------------

def estimate_interception_ratio(log: EpisodeLog) -> InterceptionRatioEstimate:
    """Estimate the aggregate interception ratio from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log with truth, actions, and detections.

    Returns
    -------
    InterceptionRatioEstimate
        The aggregate interception ratio with supporting counts.
    """
    n_transmissions = int(np.count_nonzero(log.truth))
    if n_transmissions == 0:
        return InterceptionRatioEstimate(
            ratio=float("nan"),
            n_hits=0,
            n_transmissions=0,
        )

    hits = _scanned_hits(log)
    n_hits = int(np.count_nonzero(hits))
    return InterceptionRatioEstimate(
        ratio=n_hits / n_transmissions,
        n_hits=n_hits,
        n_transmissions=n_transmissions,
    )


def estimate_intercept_rate(log: EpisodeLog) -> InterceptRateEstimate:
    """Estimate the average intercept rate per time slot from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log with truth, actions, and detections.

    Returns
    -------
    InterceptRateEstimate
        The average intercept rate with supporting counts.
    """
    if log.n_slots == 0:
        return InterceptRateEstimate(
            rate=float("nan"),
            n_hits=0,
            n_slots=0,
        )

    hits = _scanned_hits(log)
    n_hits = int(np.count_nonzero(hits))
    return InterceptRateEstimate(
        rate=n_hits / log.n_slots,
        n_hits=n_hits,
        n_slots=log.n_slots,
    )


def estimate_per_emitter_interception(
    log: EpisodeLog,
) -> tuple[EmitterInterceptionEstimate, ...]:
    """Estimate per-emitter interception ratio from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.

    Returns
    -------
    tuple[EmitterInterceptionEstimate, ...]
        One estimate per emitter declared in ``log.config.emitters``.
    """
    results: list[EmitterInterceptionEstimate] = []
    hits = _scanned_hits(log)

    for idx, emitter_info in enumerate(log.config.emitters):
        band = emitter_info.band
        on, em_bands = emitter_activity(log, idx)

        n_transmissions = int(np.count_nonzero(on))

        if n_transmissions == 0:
            results.append(
                EmitterInterceptionEstimate(
                    emitter_index=idx,
                    band=band,
                    interception_ratio=float("nan"),
                    n_hits=0,
                    n_transmissions=0,
                )
            )
            continue

        # A hit needs the receiver tuned to this emitter's occupied band while
        # the emitter is transmitting.
        scanned_emitter = log.actions == em_bands[:, None]
        emitter_hits = (hits & scanned_emitter & on[:, None]).any(axis=1)
        n_hits = int(np.count_nonzero(emitter_hits))

        results.append(
            EmitterInterceptionEstimate(
                emitter_index=idx,
                band=band,
                interception_ratio=n_hits / n_transmissions,
                n_hits=n_hits,
                n_transmissions=n_transmissions,
            )
        )

    return tuple(results)


def estimate_interception_metrics(log: EpisodeLog) -> InterceptionMetrics:
    """Compute all interception performance metrics from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.

    Returns
    -------
    InterceptionMetrics
        Complete interception performance summary.
    """
    ratio_est = estimate_interception_ratio(log)
    rate_est = estimate_intercept_rate(log)
    per_emitter = estimate_per_emitter_interception(log)

    return InterceptionMetrics(
        interception_ratio=ratio_est,
        intercept_rate=rate_est,
        per_emitter=per_emitter,
    )
