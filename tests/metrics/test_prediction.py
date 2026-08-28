"""Tests for prediction accuracy metrics -- Phase 1E.5.

Verify criteria (PLAN.md 1E.5):
    Returns a defined null when no predictor is active (Phase 1 MVP stub).
    Calculates correct percentage when predictions are provided (Phase 2 functionality).
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.contracts import EpisodeConfig, EpisodeLog
from ewscan.metrics.prediction import (
    PredictionMetrics,
    estimate_percentage_correct,
    estimate_prediction_metrics,
)


def _make_test_log(n_bands: int = 4, n_slots: int = 4) -> EpisodeLog:
    truth = np.zeros((n_bands, n_slots), dtype=bool)
    truth[0, 0] = True
    truth[0, 1] = True
    truth[0, 3] = True
    actions = np.array([0, 0, 1, 0], dtype=np.intp)
    detections = np.array([True, True, False, True], dtype=bool)

    config = EpisodeConfig(
        n_bands=n_bands,
        n_slots=n_slots,
        k=1,
        emitters=(),
        detection_threshold=None,
        pfa=1e-3,
        seed=0,
    )
    return EpisodeLog(config=config, truth=truth, actions=actions, detections=detections)


class TestMVPStubBehavior:
    """When no predictor is active (default in Phase 1), returns defined null."""

    def test_default_none_predictions_returns_stub_null(self):
        log = _make_test_log()
        metrics = estimate_prediction_metrics(log)

        assert isinstance(metrics, PredictionMetrics)
        assert metrics.predictor_present is False
        assert metrics.active is False
        assert metrics.accuracy is None
        assert metrics.percentage_correct is None
        assert metrics.n_predictions == 0
        assert metrics.n_correct == 0
        assert metrics.coverage == 0.0

    def test_estimate_percentage_correct_returns_none_when_inactive(self):
        log = _make_test_log()
        pct = estimate_percentage_correct(log)
        assert pct is None


class TestMalformedPredictionArrays:
    """Objective 4: predictions must be an integer array of shape (n_slots,)."""

    def test_boolean_array_rejected(self):
        log = _make_test_log()
        preds = np.array([True, True, False, True], dtype=bool)
        with pytest.raises(ValueError, match="integer"):
            estimate_prediction_metrics(log, predictions=preds)

    def test_two_dimensional_array_rejected(self):
        log = _make_test_log()
        preds = np.zeros((4, 1), dtype=np.intp)
        with pytest.raises(ValueError, match="shape"):
            estimate_prediction_metrics(log, predictions=preds)

    def test_float_array_rejected(self):
        log = _make_test_log()
        preds = np.zeros(4, dtype=np.float64)
        with pytest.raises(ValueError, match="integer"):
            estimate_prediction_metrics(log, predictions=preds)

    def test_empty_array_rejected(self):
        log = _make_test_log()
        preds = np.array([], dtype=np.intp)
        with pytest.raises(ValueError, match="shape"):
            estimate_prediction_metrics(log, predictions=preds)


class TestActivePredictorIntegerBandArray:
    """When predictions are supplied as predicted band indices per slot."""

    def test_integer_band_predictions(self):
        log = _make_test_log(n_bands=4, n_slots=4)
        # Truth: band 0 ON at slots 0, 1, 3. Band 1 always OFF.
        # Predictions per slot:
        # slot 0: band 0 -> truth[0,0]=True (correct)
        # slot 1: band 1 -> truth[1,1]=False (incorrect)
        # slot 2: -1     -> no prediction made (ignored)
        # slot 3: band 0 -> truth[0,3]=True (correct)
        preds = np.array([0, 1, -1, 0], dtype=np.intp)
        metrics = estimate_prediction_metrics(log, predictions=preds)

        assert metrics.predictor_present is True
        assert metrics.active is True
        assert metrics.n_predictions == 3
        assert metrics.n_correct == 2
        assert metrics.coverage == pytest.approx(0.75)
        assert metrics.accuracy == pytest.approx(2.0 / 3.0)
        assert metrics.percentage_correct == pytest.approx(200.0 / 3.0)

    def test_all_negative_one_predictions(self):
        log = _make_test_log()
        preds = np.array([-1, -1, -1, -1], dtype=np.intp)
        metrics = estimate_prediction_metrics(log, predictions=preds)

        assert metrics.predictor_present is True
        assert metrics.active is True
        assert metrics.n_predictions == 0
        assert metrics.n_correct == 0
        assert metrics.coverage == 0.0
        assert metrics.accuracy is None
        assert metrics.percentage_correct is None

    def test_confidence_and_overrides_recorded(self):
        log = _make_test_log()
        preds = np.array([0, 1, -1, 0], dtype=np.intp)
        confidences = np.array([0.8, 0.4, 0.0, 0.6], dtype=np.float64)
        overrides = np.array([True, False, False, True], dtype=bool)
        metrics = estimate_prediction_metrics(
            log, predictions=preds, confidences=confidences, overrides=overrides
        )
        assert metrics.mean_confidence == pytest.approx((0.8 + 0.4 + 0.6) / 3.0)
        assert metrics.n_overrides == 2

    def test_mismatched_predictions_length_raises(self):
        log = _make_test_log(n_slots=4)
        preds = np.array([0, 1], dtype=np.intp)
        with pytest.raises(ValueError, match="shape"):
            estimate_prediction_metrics(log, predictions=preds)
