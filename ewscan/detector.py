"""Detector capability contract and calibration helpers."""

from __future__ import annotations

from dataclasses import dataclass
import math
from numbers import Integral, Real


@dataclass(frozen=True)
class DetectorCapability:
    """Effective detector values visible to schedulers and metrics."""

    requested_pfa: float
    threshold: float
    effective_pfa: float
    dwell: int
    nominal_pd: float = 0.9


def threshold_from_pfa(pfa: float) -> float:
    """Return the one-look threshold for a requested false-alarm rate."""
    if not isinstance(pfa, Real) or isinstance(pfa, bool) or not 0.0 < pfa < 1.0:
        raise ValueError(f"pfa must be in (0, 1), got {pfa!r}")
    return -math.log(float(pfa))


def pfa_from_threshold(threshold: float) -> float:
    """Return the one-look false-alarm rate for a positive threshold."""
    if (
        not isinstance(threshold, Real)
        or isinstance(threshold, bool)
        or not math.isfinite(threshold)
        or threshold <= 0.0
    ):
        raise ValueError(f"threshold must be positive, got {threshold!r}")
    return math.exp(-float(threshold))


def pfa_from_threshold_dlook(threshold: float, dwell: int) -> float:
    """Return the effective false-alarm rate for integrated looks."""
    pfa_from_threshold(threshold)
    if not isinstance(dwell, Integral) or isinstance(dwell, bool) or dwell < 1:
        raise ValueError(f"dwell must be a positive integer, got {dwell!r}")
    x = int(dwell) * float(threshold)
    term = 1.0
    total = term
    for n in range(1, int(dwell)):
        term = term * x / n
        total += term
    return math.exp(-x) * total


def make_detector_capability(
    pfa: float,
    threshold: float | None,
    dwell: int,
    nominal_pd: float = 0.9,
) -> DetectorCapability:
    """Derive and validate one consistent detector capability."""
    requested_pfa = float(pfa)
    derived_threshold = threshold_from_pfa(pfa)
    if threshold is not None:
        pfa_from_threshold(threshold)
        if not math.isclose(
            float(threshold),
            derived_threshold,
            rel_tol=1e-12,
            abs_tol=1e-12,
        ):
            raise ValueError(
                f"detection_threshold {threshold} does not match pfa-derived "
                f"threshold {derived_threshold} for pfa {requested_pfa}"
            )
    if not isinstance(dwell, Integral) or isinstance(dwell, bool) or dwell < 1:
        raise ValueError(f"dwell must be a positive integer, got {dwell!r}")
    if (
        not isinstance(nominal_pd, Real)
        or isinstance(nominal_pd, bool)
        or not 0.0 < nominal_pd <= 1.0
    ):
        raise ValueError(f"nominal_pd must be in (0, 1], got {nominal_pd!r}")
    effective_pfa = (
        requested_pfa
        if int(dwell) == 1
        else pfa_from_threshold_dlook(derived_threshold, int(dwell))
    )
    return DetectorCapability(
        requested_pfa=requested_pfa,
        threshold=derived_threshold,
        effective_pfa=effective_pfa,
        dwell=int(dwell),
        nominal_pd=float(nominal_pd),
    )
