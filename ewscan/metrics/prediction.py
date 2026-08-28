"""Prediction accuracy metrics from the episode log -- Phase 1E.5.

Evaluates percentage of correct predictions made by a scan predictor or sniper policy.
Returns a defined null when no predictor is active (Phase 1 MVP stub).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeLog


@dataclass(frozen=True)
class PredictionMetrics:
    """Prediction metrics summary for one episode.

    Attributes
    ----------
    accuracy : float | None
        Fraction of predictions that were correct (0.0-1.0), or None if no
        prediction was made.
    percentage_correct : float | None
        ``accuracy`` as a percentage, or None.
    predictor_present : bool
        True if a predictor was installed (an array was supplied), regardless
        of whether it ever predicted.
    active : bool
        Alias of ``predictor_present`` kept for compatibility.
    n_predictions : int
        Number of slots with a real prediction (band >= 0), on valid slots.
    n_correct : int
        Number of correct predictions.
    coverage : float
        ``n_predictions / n_slots``: how often the predictor committed.
    mean_confidence : float | None
        Mean predictor confidence over prediction slots, or None if no
        confidence stream was supplied.
    n_overrides : int
        Number of slots the predictor overrode the inner action, from the
        supplied override stream (0 if none supplied).
    """

    accuracy: float | None
    percentage_correct: float | None
    predictor_present: bool
    active: bool
    n_predictions: int
    n_correct: int
    coverage: float
    mean_confidence: float | None
    n_overrides: int


def _require_prediction_shape(name: str, arr: NDArray, n_slots: int) -> NDArray:
    a = np.asarray(arr)
    if a.shape != (n_slots,):
        raise ValueError(
            f"{name} must have shape (n_slots,) = ({n_slots},), got {a.shape}"
        )
    return a


def estimate_prediction_metrics(
    log: EpisodeLog,
    predictions: NDArray[np.intp] | None = None,
    confidences: NDArray[np.float64] | None = None,
    overrides: NDArray[np.bool_] | None = None,
) -> PredictionMetrics:
    """Compute prediction metrics for an episode log.

    ``predictions`` must be an integer array of exact shape ``(n_slots,)`` where
    each entry is a predicted band index or ``-1`` for no prediction. Boolean
    arrays, other numeric dtypes, and any other shape are rejected. Invalid
    (settling) slots are skipped. ``confidences`` and ``overrides`` are optional
    per-slot streams recorded separately from accuracy.
    """
    if predictions is None:
        return PredictionMetrics(
            accuracy=None,
            percentage_correct=None,
            predictor_present=False,
            active=False,
            n_predictions=0,
            n_correct=0,
            coverage=0.0,
            mean_confidence=None,
            n_overrides=0,
        )

    preds = np.asarray(predictions)
    if not np.issubdtype(preds.dtype, np.integer):
        raise ValueError(
            f"predictions must be an integer band-or-(-1) array, got dtype {preds.dtype}"
        )
    preds = _require_prediction_shape("predictions", preds, log.n_slots)

    valid = log.valid_slots
    mask = (preds >= 0) & (preds < log.n_bands) & valid
    n_predictions = int(np.sum(mask))
    coverage = n_predictions / log.n_slots if log.n_slots > 0 else 0.0

    if n_predictions > 0:
        slot_indices = np.where(mask)[0]
        predicted_bands = preds[mask]
        n_correct = int(np.sum(log.truth[predicted_bands, slot_indices]))
    else:
        n_correct = 0

    mean_confidence: float | None = None
    if confidences is not None:
        conf = _require_prediction_shape("confidences", confidences, log.n_slots)
        if n_predictions > 0:
            mean_confidence = float(np.mean(conf[mask]))

    n_overrides = 0
    if overrides is not None:
        ov = _require_prediction_shape("overrides", overrides, log.n_slots)
        n_overrides = int(np.sum(np.asarray(ov, dtype=bool) & mask))

    if n_predictions == 0:
        accuracy: float | None = None
        percentage_correct: float | None = None
    else:
        accuracy = float(n_correct) / float(n_predictions)
        percentage_correct = accuracy * 100.0

    return PredictionMetrics(
        accuracy=accuracy,
        percentage_correct=percentage_correct,
        predictor_present=True,
        active=True,
        n_predictions=n_predictions,
        n_correct=n_correct,
        coverage=coverage,
        mean_confidence=mean_confidence,
        n_overrides=n_overrides,
    )


def estimate_percentage_correct(
    log: EpisodeLog,
    predictions: NDArray[np.intp] | NDArray[np.bool_] | None = None,
) -> float | None:
    """Compute percentage of correct predictions for an episode log.

    Parameters
    ----------
    log : EpisodeLog
        The episode log to evaluate.
    predictions : NDArray[np.intp] | NDArray[np.bool_] | None
        Optional array of predictions. If None, returns None.

    Returns
    -------
    float | None
        Percentage of correct predictions (0.0 to 100.0), or None if no predictor active.
    """
    return estimate_prediction_metrics(log, predictions=predictions).percentage_correct
