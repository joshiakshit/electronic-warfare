"""Average intercept time error estimators from the episode log -- Phase 1E.6.

Estimates the timing latency / time error of intercepting active RF transmission
bursts across configured emitters.

Definitions
-----------
**Transmission Burst:**
  For a given emitter on band *b*, a transmission burst *k* is a maximal
  contiguous time slot interval :math:`[t_{\\text{start}}, t_{\\text{end}}]`
  such that:
  :math:`\\text{truth}[b, t] == \\text{True} \\quad \\forall t \\in [t_{\\text{start}}, t_{\\text{end}}]`
  with duration :math:`D_k = t_{\\text{end}} - t_{\\text{start}} + 1`.

**Burst Intercept & Intercept Time Error:**
  A burst is successfully intercepted if during its active window
  :math:`[t_{\\text{start}}, t_{\\text{end}}]`, the receiver scanned band *b*
  and registered a true detection (hit):
  :math:`\\text{actions}[t] == b \\land \\text{truth}[b, t] \\land \\text{detections}[t] == \\text{True}`

  Let :math:`t_{\\text{hit}}` be the earliest slot index within the burst where
  such a hit occurred.  The **intercept time error** for this burst is:
  :math:`\\Delta t_k = t_{\\text{hit}} - t_{\\text{start}} \\ge 0`

  - For an ideal / omniscient Oracle scheduler, :math:`t_{\\text{hit}} = t_{\\text{start}}`
    on every burst, yielding :math:`\\Delta t_k = 0.0`.
  - For non-oracle schedulers (e.g. round-robin or random), scanning is delayed,
    yielding a positive and finite time error :math:`\\Delta t_k > 0.0`.

**Mean Intercept Time Error:**
  The arithmetic mean of :math:`\\Delta t_k` across all successfully intercepted bursts:
  :math:`\\text{Mean Error} = \\frac{1}{M_{\\text{intercepted}}} \\sum_{k \\in \\text{intercepted}} \\Delta t_k`
  Returns ``float('nan')`` if no bursts were intercepted (or no bursts exist).

**Penalized Mean Time Error:**
  Computes the average across *all* :math:`M` bursts in the episode, where missed
  bursts are penalized by a specified duration (default: the burst's own duration :math:`D_k`).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeLog


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BurstTimeError:
    """Timing record for a single transmission burst.

    Attributes
    ----------
    emitter_index : int
        Index into ``EpisodeConfig.emitters``.
    band : int
        Frequency band this burst occurred on.
    start_slot : int
        Starting slot index of the burst (0-indexed, inclusive).
    end_slot : int
        Ending slot index of the burst (0-indexed, inclusive).
    duration : int
        Total duration of the burst in slots (end_slot - start_slot + 1).
    intercept_slot : int | None
        Slot index of the first hit within the burst, or None if missed.
    time_error : float | None
        Intercept time error (intercept_slot - start_slot), or None if missed.
    intercepted : bool
        True if the burst was intercepted at least once, False otherwise.
    """

    emitter_index: int
    band: int
    start_slot: int
    end_slot: int
    duration: int
    intercept_slot: int | None
    time_error: float | None
    intercepted: bool


@dataclass(frozen=True)
class EmitterTimeError:
    """Timing error summary for a single emitter across all its bursts.

    Attributes
    ----------
    emitter_index : int
        Index into ``EpisodeConfig.emitters``.
    band : int
        Frequency band this emitter occupies.
    mean_time_error : float
        Mean time error over intercepted bursts, or NaN if no bursts intercepted.
    mean_time_error_penalized : float
        Mean time error across all bursts with miss penalty applied, or NaN if 0 bursts.
    n_bursts : int
        Total number of transmission bursts for this emitter.
    n_intercepted_bursts : int
        Number of bursts successfully intercepted.
    burst_interception_ratio : float
        Fraction of bursts intercepted (n_intercepted_bursts / n_bursts), or NaN if 0 bursts.
    bursts : tuple[BurstTimeError, ...]
        Individual records for all bursts in chronological order.
    """

    emitter_index: int
    band: int
    mean_time_error: float
    mean_time_error_penalized: float
    n_bursts: int
    n_intercepted_bursts: int
    burst_interception_ratio: float
    bursts: tuple[BurstTimeError, ...]


@dataclass(frozen=True)
class TimeErrorMetrics:
    """Complete summary of intercept time error for an episode.

    Attributes
    ----------
    mean_time_error : float
        Mean time error across all intercepted bursts in the episode,
        or NaN if no bursts were intercepted.
    mean_time_error_penalized : float
        Mean time error across all bursts with miss penalty applied,
        or NaN if no bursts occurred.
    n_bursts : int
        Total number of transmission bursts across all configured emitters.
    n_intercepted_bursts : int
        Total number of successfully intercepted bursts.
    burst_interception_ratio : float
        Fraction of total bursts intercepted, or NaN if 0 bursts.
    per_emitter : tuple[EmitterTimeError, ...]
        Per-emitter time error summaries in config order.
    bursts : tuple[BurstTimeError, ...]
        All burst records across all emitters.
    """

    mean_time_error: float
    mean_time_error_penalized: float
    n_bursts: int
    n_intercepted_bursts: int
    burst_interception_ratio: float
    per_emitter: tuple[EmitterTimeError, ...]
    bursts: tuple[BurstTimeError, ...]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def extract_bursts(truth_row: NDArray[np.bool_]) -> list[tuple[int, int]]:
    """Extract contiguous active transmission intervals [start, end] from a 1D boolean array.

    Parameters
    ----------
    truth_row : NDArray[np.bool_]
        1D boolean array indicating truth for a single band over time.

    Returns
    -------
    list[tuple[int, int]]
        List of (start_slot, end_slot) pairs, inclusive.
    """
    if len(truth_row) == 0:
        return []

    # Pad with False on both ends to detect edges cleanly
    padded = np.pad(truth_row.astype(np.int8), (1, 1), mode="constant", constant_values=0)
    diff = np.diff(padded)

    starts = np.flatnonzero(diff == 1)
    ends = np.flatnonzero(diff == -1) - 1

    return list(zip(starts.tolist(), ends.tolist()))


def _compute_scanned_hits(log: EpisodeLog) -> NDArray[np.bool_]:
    """Compute a (n_slots, k) mask of per-channel hits."""
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

def estimate_per_emitter_time_error(
    log: EpisodeLog,
    miss_penalty: float | None = None,
) -> tuple[EmitterTimeError, ...]:
    """Estimate intercept time error for each configured emitter in the episode.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.
    miss_penalty : float | None, optional
        Penalty value assigned to missed bursts when computing penalized mean error.
        If None, defaults to the duration of the missed burst.

    Returns
    -------
    tuple[EmitterTimeError, ...]
        Per-emitter timing error summaries in config order.
    """
    hits = _compute_scanned_hits(log)
    results: list[EmitterTimeError] = []

    for idx, emitter_info in enumerate(log.config.emitters):
        band = emitter_info.band
        if band < 0 or band >= log.n_bands:
            results.append(
                EmitterTimeError(
                    emitter_index=idx,
                    band=band,
                    mean_time_error=float("nan"),
                    mean_time_error_penalized=float("nan"),
                    n_bursts=0,
                    n_intercepted_bursts=0,
                    burst_interception_ratio=float("nan"),
                    bursts=(),
                )
            )
            continue

        raw_bursts = extract_bursts(log.truth[band, :])
        burst_records: list[BurstTimeError] = []
        intercepted_errors: list[float] = []
        penalized_errors: list[float] = []

        scanned_this_band = log.actions == band
        band_hits = (hits & scanned_this_band).any(axis=1)

        for start, end in raw_bursts:
            duration = end - start + 1
            # Check if any hit occurred in [start, end]
            burst_hit_indices = np.flatnonzero(band_hits[start : end + 1])

            if len(burst_hit_indices) > 0:
                first_hit_slot = start + int(burst_hit_indices[0])
                t_error = float(first_hit_slot - start)
                record = BurstTimeError(
                    emitter_index=idx,
                    band=band,
                    start_slot=start,
                    end_slot=end,
                    duration=duration,
                    intercept_slot=first_hit_slot,
                    time_error=t_error,
                    intercepted=True,
                )
                intercepted_errors.append(t_error)
                penalized_errors.append(t_error)
            else:
                penalty = float(duration if miss_penalty is None else miss_penalty)
                record = BurstTimeError(
                    emitter_index=idx,
                    band=band,
                    start_slot=start,
                    end_slot=end,
                    duration=duration,
                    intercept_slot=None,
                    time_error=None,
                    intercepted=False,
                )
                penalized_errors.append(penalty)

            burst_records.append(record)

        n_bursts = len(burst_records)
        n_intercepted = len(intercepted_errors)

        if n_bursts == 0:
            mean_err = float("nan")
            mean_penalized = float("nan")
            ratio = float("nan")
        else:
            mean_err = float(np.mean(intercepted_errors)) if n_intercepted > 0 else float("nan")
            mean_penalized = float(np.mean(penalized_errors))
            ratio = float(n_intercepted) / float(n_bursts)

        results.append(
            EmitterTimeError(
                emitter_index=idx,
                band=band,
                mean_time_error=mean_err,
                mean_time_error_penalized=mean_penalized,
                n_bursts=n_bursts,
                n_intercepted_bursts=n_intercepted,
                burst_interception_ratio=ratio,
                bursts=tuple(burst_records),
            )
        )

    return tuple(results)


def estimate_time_error_metrics(
    log: EpisodeLog,
    miss_penalty: float | None = None,
) -> TimeErrorMetrics:
    """Compute overall intercept time error metrics from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.
    miss_penalty : float | None, optional
        Penalty value assigned to missed bursts when computing penalized mean error.
        If None, defaults to the duration of the missed burst.

    Returns
    -------
    TimeErrorMetrics
        Complete intercept time error summary for the episode.
    """
    per_emitter = estimate_per_emitter_time_error(log, miss_penalty=miss_penalty)

    all_bursts: list[BurstTimeError] = []
    intercepted_errors: list[float] = []
    penalized_errors: list[float] = []

    for em in per_emitter:
        for b in em.bursts:
            all_bursts.append(b)
            if b.intercepted and b.time_error is not None:
                intercepted_errors.append(b.time_error)
                penalized_errors.append(b.time_error)
            else:
                penalty = float(b.duration if miss_penalty is None else miss_penalty)
                penalized_errors.append(penalty)

    n_bursts = len(all_bursts)
    n_intercepted = len(intercepted_errors)

    if n_bursts == 0:
        mean_err = float("nan")
        mean_penalized = float("nan")
        ratio = float("nan")
    else:
        mean_err = float(np.mean(intercepted_errors)) if n_intercepted > 0 else float("nan")
        mean_penalized = float(np.mean(penalized_errors))
        ratio = float(n_intercepted) / float(n_bursts)

    return TimeErrorMetrics(
        mean_time_error=mean_err,
        mean_time_error_penalized=mean_penalized,
        n_bursts=n_bursts,
        n_intercepted_bursts=n_intercepted,
        burst_interception_ratio=ratio,
        per_emitter=per_emitter,
        bursts=tuple(all_bursts),
    )


def estimate_average_time_error(
    log: EpisodeLog,
    miss_penalty: float | None = None,
) -> float:
    """Compute average intercept time error for an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.
    miss_penalty : float | None, optional
        Penalty value for missed bursts.

    Returns
    -------
    float
        Mean intercept time error over intercepted bursts (or NaN if 0 intercepted).
    """
    return estimate_time_error_metrics(log, miss_penalty=miss_penalty).mean_time_error
