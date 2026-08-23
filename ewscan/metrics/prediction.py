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
    """Prediction accuracy metrics summary for one episode.

    Attributes
    ----------
    accuracy : float | None
        Fraction of predictions that were correct (range 0.0 to 1.0),
        or None if no predictor is active or no predictions were made.
    percentage_correct : float | None
        Percentage of predictions that were correct (range 0.0 to 100.0),
        or None if no predictor is active or no predictions were made.
    active : bool
        True if a predictor was active during the episode, False otherwise.
    n_predictions : int
        Total number of predictions evaluated.
    n_correct : int
        Number of correct predictions.
    """

    accuracy: float | None
    percentage_correct: float | None
    active: bool
    n_predictions: int
    n_correct: int


def estimate_prediction_metrics(
    log: EpisodeLog,
    predictions: NDArray[np.intp] | NDArray[np.bool_] | None = None,
) -> PredictionMetrics:
    """Compute prediction accuracy metrics for an episode log.

    In Phase 1 MVP, no predictor is active by default (predictions=None),
    so this returns a defined null (active=False, accuracy=None, percentage_correct=None).

    In Phase 2, when predictions are provided:
    - If `predictions` is a 1D boolean array indicating correctness of evaluated predictions
      or per-slot predictions: counts True values as correct.
    - If `predictions` is a 1D integer array of predicted band indices per slot (shape: (n_slots,),
      with -1 indicating no prediction at slot t): a prediction at slot t for band b is correct
      if truth[b, t] == True.

    Parameters
    ----------
    log : EpisodeLog
        The episode log to evaluate.
    predictions : NDArray[np.intp] | NDArray[np.bool_] | None
        Optional array of predictions. If None, returns stub null metrics.

    Returns
    -------
    PredictionMetrics
        Dataclass containing accuracy, percentage_correct, active status,
        n_predictions, and n_correct.
    """
    if predictions is None:
        return PredictionMetrics(
            accuracy=None,
            percentage_correct=None,
            active=False,
            n_predictions=0,
            n_correct=0,
        )

    preds = np.asarray(predictions)
    if preds.size == 0:
        return PredictionMetrics(
            accuracy=None,
            percentage_correct=None,
            active=True,
            n_predictions=0,
            n_correct=0,
        )

    if np.issubdtype(preds.dtype, np.bool_):
        n_predictions = int(preds.size)
        n_correct = int(np.sum(preds))
    else:
        # Integer array of predicted band indices per slot
        if preds.shape[0] != log.n_slots:
            raise ValueError(
                f"Predictions length ({preds.shape[0]}) does not match episode slots ({log.n_slots})"
            )
        mask = (preds >= 0) & (preds < log.n_bands)
        n_predictions = int(np.sum(mask))
        if n_predictions > 0:
            slot_indices = np.where(mask)[0]
            predicted_bands = preds[mask]
            correct_mask = log.truth[predicted_bands, slot_indices]
            n_correct = int(np.sum(correct_mask))
        else:
            n_correct = 0

    if n_predictions == 0:
        return PredictionMetrics(
            accuracy=None,
            percentage_correct=None,
            active=True,
            n_predictions=0,
            n_correct=0,
        )

    accuracy = float(n_correct) / float(n_predictions)
    percentage_correct = accuracy * 100.0

    return PredictionMetrics(
        accuracy=accuracy,
        percentage_correct=percentage_correct,
        active=True,
        n_predictions=n_predictions,
        n_correct=n_correct,
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
