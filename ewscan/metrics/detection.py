"""Pd, Pfa, and sensitivity estimators from the episode log -- Phase 1E.1.

Estimates detection performance metrics by partitioning the scanner's
observations against ground-truth transmission state.

Definitions
-----------
**Probability of detection (Pd):**
  Of the slots where the scanner tuned to a band that was *actually
  transmitting*, what fraction produced a detection?

  Pd_hat = (# detections on transmitting bands) / (# scans of transmitting bands)

  This is a direct empirical estimate of the underlying sensor Pd.  For a
  long enough episode, it converges to the ROC-determined Pd for the
  emitter's SNR and the detector threshold.

**Probability of false alarm (Pfa):**
  Of the slots where the scanner tuned to a band that was *not* transmitting,
  what fraction produced a detection?

  Pfa_hat = (# detections on silent bands) / (# scans of silent bands)

  Converges to the detector's analytic Pfa = exp(-threshold).

**Per-emitter Pd:**
  Partitions the Pd estimate by emitter.  For each emitter, considers only
  the slots where (a) the scanner was tuned to the emitter's band AND
  (b) the emitter was transmitting, then computes the detection fraction.
  Bands hosting multiple emitters attribute the scan to every resident
  emitter that was ON.

**Sensitivity:**
  The minimum emitter SNR (in dB) at which the estimated Pd exceeds a
  specified threshold (default: 0.5).  Operationally, this answers the
  question "how weak can a signal be before we stop reliably detecting it?"

All estimators take an ``EpisodeLog`` and return dataclasses with both the
point estimates and the underlying counts, so that confidence intervals and
downstream aggregation (1E.7) can be computed without re-scanning the log.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeLog


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PdEstimate:
    """Aggregate probability-of-detection estimate.

    Attributes
    ----------
    pd : float
        Point estimate, NaN if no transmitting-band scans occurred.
    n_hits : int
        Number of detections on transmitting bands (true positives).
    n_scans_on : int
        Number of scans where the tuned band was transmitting.
    """

    pd: float
    n_hits: int
    n_scans_on: int


@dataclass(frozen=True)
class PfaEstimate:
    """Aggregate probability-of-false-alarm estimate.

    Attributes
    ----------
    pfa : float
        Point estimate, NaN if no silent-band scans occurred.
    n_false_alarms : int
        Number of detections on silent bands (false positives).
    n_scans_off : int
        Number of scans where the tuned band was not transmitting.
    """

    pfa: float
    n_false_alarms: int
    n_scans_off: int


@dataclass(frozen=True)
class EmitterPdEstimate:
    """Per-emitter probability-of-detection estimate.

    Attributes
    ----------
    emitter_index : int
        Index into ``EpisodeConfig.emitters``.
    band : int
        The band this emitter occupies.
    snr : float
        The emitter's configured SNR in dB.
    pd : float
        Point estimate, NaN if the emitter was never scanned while transmitting.
    n_hits : int
        Detections while scanning this emitter's band when it was ON.
    n_scans_on : int
        Scans of this emitter's band while it was ON.
    """

    emitter_index: int
    band: int
    snr: float
    pd: float
    n_hits: int
    n_scans_on: int


@dataclass(frozen=True)
class SensitivityEstimate:
    """Receiver sensitivity estimate.

    Attributes
    ----------
    min_detectable_snr : float
        Minimum emitter SNR (dB) whose estimated Pd ≥ *pd_threshold*.
        ``float('inf')`` if no emitter meets the threshold.
        ``float('nan')`` if no emitters were scanned while transmitting.
    pd_threshold : float
        The Pd threshold used for this estimate.
    emitter_pds : tuple[EmitterPdEstimate, ...]
        Per-emitter Pd estimates used to derive sensitivity.
    """

    min_detectable_snr: float
    pd_threshold: float
    emitter_pds: tuple[EmitterPdEstimate, ...]


@dataclass(frozen=True)
class DetectionMetrics:
    """Complete detection performance summary for one episode.

    Bundles the aggregate Pd, aggregate Pfa, per-emitter Pd, and
    sensitivity into a single result object.
    """

    pd: PdEstimate
    pfa: PfaEstimate
    per_emitter_pd: tuple[EmitterPdEstimate, ...]
    sensitivity: SensitivityEstimate


# ---------------------------------------------------------------------------
# Core estimation functions
# ---------------------------------------------------------------------------

def _scanned_truth(log: EpisodeLog) -> NDArray[np.bool_]:
    """Return the truth value at each scanned (band, slot) pair.

    Returns a 1-D boolean array of length ``n_slots`` where entry *t* is
    ``truth[actions[t], t]``.  Invalid action indices (out of band range)
    are treated as non-detections (False).
    """
    actions = log.actions
    valid = (actions >= 0) & (actions < log.n_bands)
    safe_actions = np.where(valid, actions, 0)
    result = log.truth[safe_actions, np.arange(log.n_slots)]
    result[~valid] = False
    return result


def estimate_pd(log: EpisodeLog) -> PdEstimate:
    """Estimate the aggregate probability of detection from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log with truth, actions, and detections.

    Returns
    -------
    PdEstimate
        The aggregate Pd estimate with supporting counts.
    """
    scanned_on = _scanned_truth(log)  # bool[n_slots]: was the scanned band ON?
    n_scans_on = int(np.count_nonzero(scanned_on))
    if n_scans_on == 0:
        return PdEstimate(pd=float("nan"), n_hits=0, n_scans_on=0)

    # A "hit" is a detection where the scanned band was actually transmitting
    hits = log.detections & scanned_on
    n_hits = int(np.count_nonzero(hits))
    return PdEstimate(
        pd=n_hits / n_scans_on,
        n_hits=n_hits,
        n_scans_on=n_scans_on,
    )


def estimate_pfa(log: EpisodeLog) -> PfaEstimate:
    """Estimate the aggregate probability of false alarm from an episode log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log with truth, actions, and detections.

    Returns
    -------
    PfaEstimate
        The aggregate Pfa estimate with supporting counts.
    """
    scanned_on = _scanned_truth(log)
    scanned_off = ~scanned_on
    n_scans_off = int(np.count_nonzero(scanned_off))
    if n_scans_off == 0:
        return PfaEstimate(pfa=float("nan"), n_false_alarms=0, n_scans_off=0)

    false_alarms = log.detections & scanned_off
    n_false_alarms = int(np.count_nonzero(false_alarms))
    return PfaEstimate(
        pfa=n_false_alarms / n_scans_off,
        n_false_alarms=n_false_alarms,
        n_scans_off=n_scans_off,
    )


def estimate_per_emitter_pd(log: EpisodeLog) -> tuple[EmitterPdEstimate, ...]:
    """Estimate per-emitter Pd from an episode log.

    For each emitter declared in ``log.config.emitters``, counts the slots
    where (a) the scanner was tuned to the emitter's band AND (b) the band
    was transmitting in truth, then computes the detection fraction.

    .. note::

       When multiple emitters share a band, we cannot attribute a detection
       to a *specific* emitter from the binary truth alone — both emitters
       are "detected" whenever the band reads ON while being scanned.  The
       per-emitter Pd is therefore computed over the *emitter's own*
       transmission schedule (from the config), but the detection outcome
       is the *band-level* detection from the log.

       For the MVP (no multi-emitter-per-band scenarios), this is exact.
       Phase 2A.5 may require per-emitter truth columns.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.

    Returns
    -------
    tuple[EmitterPdEstimate, ...]
        One estimate per emitter in config order.
    """
    results: list[EmitterPdEstimate] = []
    slots = np.arange(log.n_slots)

    for idx, emitter_info in enumerate(log.config.emitters):
        band = emitter_info.band

        # Skip emitters with out-of-range bands
        if band < 0 or band >= log.n_bands:
            results.append(EmitterPdEstimate(
                emitter_index=idx,
                band=band,
                snr=emitter_info.snr,
                pd=float("nan"),
                n_hits=0,
                n_scans_on=0,
            ))
            continue

        # Slots where the scanner was tuned to this emitter's band
        scanned_this_band = log.actions == band

        # Of those, which ones had the band actually ON?
        # (truth is band-level, not per-emitter — see docstring caveat)
        on_and_scanned = scanned_this_band & log.truth[band, :]
        n_scans_on = int(np.count_nonzero(on_and_scanned))

        if n_scans_on == 0:
            results.append(EmitterPdEstimate(
                emitter_index=idx,
                band=band,
                snr=emitter_info.snr,
                pd=float("nan"),
                n_hits=0,
                n_scans_on=0,
            ))
            continue

        # Detections at those slots
        n_hits = int(np.count_nonzero(log.detections & on_and_scanned))
        results.append(EmitterPdEstimate(
            emitter_index=idx,
            band=band,
            snr=emitter_info.snr,
            pd=n_hits / n_scans_on,
            n_hits=n_hits,
            n_scans_on=n_scans_on,
        ))

    return tuple(results)


def estimate_sensitivity(
    log: EpisodeLog,
    pd_threshold: float = 0.5,
) -> SensitivityEstimate:
    """Estimate receiver sensitivity from an episode log.

    Sensitivity is the *minimum emitter SNR* (dB) at which the estimated Pd
    meets or exceeds ``pd_threshold``.  This is computed from the per-emitter
    Pd estimates: we find the emitter with the lowest SNR whose Pd ≥ threshold.

    If no emitter meets the threshold, ``min_detectable_snr`` is ``+inf``.
    If no emitter was scanned while transmitting, it is ``nan``.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.
    pd_threshold : float
        Pd floor for "detectable" (default 0.5).

    Returns
    -------
    SensitivityEstimate
        Sensitivity result with per-emitter details.

    Raises
    ------
    ValueError
        If ``pd_threshold`` is not in (0, 1].
    """
    if not (0.0 < pd_threshold <= 1.0):
        raise ValueError(f"pd_threshold must be in (0, 1], got {pd_threshold}")

    emitter_pds = estimate_per_emitter_pd(log)

    if not emitter_pds:
        return SensitivityEstimate(
            min_detectable_snr=float("nan"),
            pd_threshold=pd_threshold,
            emitter_pds=emitter_pds,
        )

    # Filter emitters that have enough samples AND meet the threshold
    detectable_snrs: list[float] = []
    any_scanned = False
    for ep in emitter_pds:
        if ep.n_scans_on > 0:
            any_scanned = True
            if ep.pd >= pd_threshold:
                detectable_snrs.append(ep.snr)

    if not any_scanned:
        min_snr = float("nan")
    elif not detectable_snrs:
        min_snr = float("inf")
    else:
        min_snr = min(detectable_snrs)

    return SensitivityEstimate(
        min_detectable_snr=min_snr,
        pd_threshold=pd_threshold,
        emitter_pds=emitter_pds,
    )


# ---------------------------------------------------------------------------
# Convenience: compute everything at once
# ---------------------------------------------------------------------------

def estimate_detection_metrics(
    log: EpisodeLog,
    pd_threshold: float = 0.5,
) -> DetectionMetrics:
    """Compute all detection performance metrics from an episode log.

    This is the primary entry point for 1E.1.  Returns aggregate Pd and Pfa,
    per-emitter Pd, and the sensitivity estimate in a single pass over the log.

    Parameters
    ----------
    log : EpisodeLog
        A completed episode log.
    pd_threshold : float
        Pd floor used for the sensitivity estimate (default 0.5).

    Returns
    -------
    DetectionMetrics
        Complete detection performance summary.
    """
    pd_est = estimate_pd(log)
    pfa_est = estimate_pfa(log)
    per_emitter = estimate_per_emitter_pd(log)
    sens = estimate_sensitivity(log, pd_threshold=pd_threshold)

    return DetectionMetrics(
        pd=pd_est,
        pfa=pfa_est,
        per_emitter_pd=per_emitter,
        sensitivity=sens,
    )
