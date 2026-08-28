"""Square-law detector ROC and detection model -- Phase 1B.4.

Implements a single-pulse square-law (energy) detector with closed-form
probability of detection (Pd) and probability of false alarm (Pfa).

Physics model
-------------
The receiver forms a test statistic T by squaring and summing the received
signal envelope (one pulse, one complex sample for the MVP).  Under the two
hypotheses:

  H0 (noise only):  T ~ Exponential(1)          (normalised noise power = 1)
  H1 (signal + noise): T ~ Exponential(1 + SNR)  (SNR in linear scale)

Given a detection threshold λ on the normalised statistic:

  Pfa = P(T > λ | H0)  = exp(-λ)
  Pd  = P(T > λ | H1)  = exp(-λ / (1 + SNR_lin))

These are the exact closed-form ROC equations for a single-look (dwell=1)
energy detector on complex Gaussian noise with a deterministic signal of
known power. For a dwell of d looks the chi-squared (Gamma) form applies;
see ``pd_from_snr_dlook`` / ``pfa_from_threshold_dlook`` below.

The ``detect`` function draws a uniform random number and compares it to the
appropriate probability (Pd if the emitter is transmitting, Pfa otherwise),
returning a boolean detection.

For a dwell of d integrated looks, the statistic is the sum of d i.i.d.
Exponential draws, i.e. Gamma(d, scale). Its survival function is the
regularized upper incomplete gamma, which for integer d has the closed form
exp(-x) * sum_{n=0}^{d-1} x^n / n!. See ``pd_from_snr_dlook`` /
``pfa_from_threshold_dlook``.

See also: Assumption 1 in PLAN.md (sensor model).
"""

from __future__ import annotations

import numpy as np


# ---------------------------------------------------------------------------
# ROC equations -- pure functions, no state
# ---------------------------------------------------------------------------

def threshold_from_pfa(pfa: float) -> float:
    """Compute the detection threshold λ from a desired false-alarm rate.

    Parameters
    ----------
    pfa:
        Probability of false alarm, must satisfy 0 < pfa < 1.

    Returns
    -------
    float
        Detection threshold λ = -ln(pfa).

    Raises
    ------
    ValueError
        If *pfa* is outside (0, 1).
    """
    if not (0.0 < pfa < 1.0):
        raise ValueError(f"pfa must be in (0, 1), got {pfa}")
    return -np.log(pfa)


def pd_from_snr(snr_db: float, threshold: float) -> float:
    """Probability of detection for a single-pulse square-law detector.

    Parameters
    ----------
    snr_db:
        Signal-to-noise ratio in dB.
    threshold:
        Detection threshold λ (on the normalised test statistic).
        Typically obtained from ``threshold_from_pfa``.

    Returns
    -------
    float
        Pd = exp(-λ / (1 + SNR_lin)).
    """
    snr_lin = 10.0 ** (snr_db / 10.0)
    return float(np.exp(-threshold / (1.0 + snr_lin)))


def pfa_from_threshold(threshold: float) -> float:
    """Recover the false-alarm probability from a threshold.

    Inverse of ``threshold_from_pfa``.

    Parameters
    ----------
    threshold:
        Detection threshold λ ≥ 0.

    Returns
    -------
    float
        Pfa = exp(-λ).
    """
    return float(np.exp(-threshold))


def _dlook_survival(x: float, dwell: int) -> float:
    """exp(-x) * sum_{n=0}^{dwell-1} x^n / n!, the Gamma(dwell, 1) survival function.

    Accumulates terms iteratively (term_n = term_{n-1} * x / n) for numerical
    stability. Exact for integer dwell; realistic dwell is capped at 16.
    """
    term = 1.0
    total = term
    for n in range(1, dwell):
        term = term * x / n
        total += term
    return float(np.exp(-x) * total)


def pd_from_snr_dlook(snr_db: float, threshold: float, dwell: int) -> float:
    """Probability of detection for a d-look non-coherent (square-law) integrator.

    Sums ``dwell`` i.i.d. exponential looks; the test statistic is
    Gamma(dwell, 1 + SNR_lin) under H1. Keeps the same per-look threshold λ
    and sums it to Λ = dwell * λ (decision D-A1: non-CFAR, Pfa is not
    re-solved per dwell).

    Parameters
    ----------
    snr_db:
        Signal-to-noise ratio in dB.
    threshold:
        Per-look detection threshold λ.
    dwell:
        Number of integrated looks, dwell >= 1.

    Returns
    -------
    float
        Pd_d = exp(-Λ / (1 + SNR_lin)) * sum_{n=0}^{dwell-1} (Λ / (1 + SNR_lin))^n / n!,
        with Λ = dwell * λ. At dwell=1 this equals ``pd_from_snr`` exactly.
    """
    snr_lin = 10.0 ** (snr_db / 10.0)
    x = dwell * threshold / (1.0 + snr_lin)
    return _dlook_survival(x, dwell)


def pfa_from_threshold_dlook(threshold: float, dwell: int) -> float:
    """False-alarm probability for a d-look non-coherent (square-law) integrator.

    Non-CFAR (decision D-A1): summing ``dwell`` looks against Λ = dwell * λ
    means Pfa is not held constant across dwell values.

    Parameters
    ----------
    threshold:
        Per-look detection threshold λ.
    dwell:
        Number of integrated looks, dwell >= 1.

    Returns
    -------
    float
        Pfa_d = exp(-Λ) * sum_{n=0}^{dwell-1} Λ^n / n!, with Λ = dwell * λ.
        At dwell=1 this equals ``pfa_from_threshold`` exactly.
    """
    x = dwell * threshold
    return _dlook_survival(x, dwell)


def snr_for_target_pd(target_pd: float, threshold: float) -> float:
    """SNR (dB) required to achieve a target Pd at a given threshold.

    Inverts the Pd equation: SNR_lin = λ / (-ln Pd) - 1.

    Parameters
    ----------
    target_pd:
        Desired probability of detection, 0 < target_pd < 1.
    threshold:
        Detection threshold λ > 0.

    Returns
    -------
    float
        Required SNR in dB.

    Raises
    ------
    ValueError
        If *target_pd* is outside (0, 1) or *threshold* ≤ 0.
    """
    if not (0.0 < target_pd < 1.0):
        raise ValueError(f"target_pd must be in (0, 1), got {target_pd}")
    if threshold <= 0.0:
        raise ValueError(f"threshold must be > 0, got {threshold}")
    snr_lin = threshold / (-np.log(target_pd)) - 1.0
    return float(10.0 * np.log10(max(snr_lin, 1e-30)))


# ---------------------------------------------------------------------------
# ROC curve generation (useful for plotting and verification)
# ---------------------------------------------------------------------------

def roc_curve(
    snr_db: float,
    n_points: int = 200,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate the analytic ROC curve for a given SNR.

    Parameters
    ----------
    snr_db:
        Signal-to-noise ratio in dB.
    n_points:
        Number of points on the curve.

    Returns
    -------
    pfa_arr, pd_arr:
        Arrays of length *n_points* with Pfa values (decreasing from
        near-1 to near-0) and the corresponding Pd values.
    """
    # Sweep threshold from near-zero (high Pfa) to large (low Pfa)
    thresholds = np.linspace(1e-6, 20.0, n_points)
    pfa_arr = np.exp(-thresholds)
    snr_lin = 10.0 ** (snr_db / 10.0)
    pd_arr = np.exp(-thresholds / (1.0 + snr_lin))
    return pfa_arr, pd_arr


# ---------------------------------------------------------------------------
# Detection model -- stateful (uses RNG)
# ---------------------------------------------------------------------------

class DetectionModel:
    """Square-law energy detector with configurable threshold and Pfa.

    This is the detection layer that sits between the truth matrix and the
    observation delivered to the scheduler.  Each call to ``detect`` draws
    a single detection event:

    - If the emitter **is** transmitting on the scanned band, the detection
      probability is ``pd_from_snr(snr_db, threshold)``.
    - If the emitter is **not** transmitting, the false-alarm probability is
      ``pfa_from_threshold(threshold)``.

    The threshold is derived from the desired Pfa at construction time, so
    the two are kept consistent.

    Parameters
    ----------
    pfa:
        Desired false-alarm probability (0 < pfa < 1).
    threshold:
        If given, overrides the threshold derived from *pfa*.  The caller
        is responsible for consistency; ``self.pfa`` will still reflect the
        constructor argument for logging, but the actual false-alarm rate
        will be ``exp(-threshold)``.
    dwell:
        Number of integrated looks per scan, dwell >= 1 (default 1). Each
        call to ``detect``/``detect_batch`` still draws exactly one uniform
        per element; only the probability compared against changes.
    """

    def __init__(self, pfa: float, threshold: float | None = None, dwell: int = 1) -> None:
        if not (0.0 < pfa < 1.0):
            raise ValueError(f"pfa must be in (0, 1), got {pfa}")
        if not isinstance(dwell, int) or isinstance(dwell, bool) or dwell < 1:
            raise ValueError(f"dwell must be a positive integer, got {dwell!r}")
        self.pfa = pfa
        self.threshold = threshold if threshold is not None else threshold_from_pfa(pfa)
        self.dwell = dwell
        self._rng: np.random.Generator | None = None

    def reset(self, rng: np.random.Generator) -> None:
        """Bind a fresh RNG for a new episode."""
        self._rng = rng

    def get_pd(self, snr_db: float) -> float:
        """Return the detection probability for a given emitter SNR.

        This is a pure query (no random draw).
        """
        return pd_from_snr_dlook(snr_db, self.threshold, self.dwell)

    def get_pfa(self) -> float:
        """Return the actual false-alarm probability implied by the threshold."""
        return pfa_from_threshold_dlook(self.threshold, self.dwell)

    def detect(self, snr_db: float, transmitting: bool) -> bool:
        """Draw a single detection event.

        Parameters
        ----------
        snr_db:
            SNR of the emitter on this band (only used when *transmitting*
            is True).
        transmitting:
            Whether the emitter is actually transmitting in this slot.

        Returns
        -------
        bool
            True if the detector fires (detection or false alarm).
        """
        if self._rng is None:
            raise RuntimeError("DetectionModel must be reset() before calling detect()")
        u = self._rng.random()
        if transmitting:
            p = pd_from_snr_dlook(snr_db, self.threshold, self.dwell)
        else:
            p = pfa_from_threshold_dlook(self.threshold, self.dwell)
        return bool(u < p)

    def detect_batch(
        self,
        snr_db: np.ndarray | float,
        transmitting: np.ndarray,
    ) -> np.ndarray:
        """Vectorised detection for an entire slot or episode chunk.

        Parameters
        ----------
        snr_db:
            Per-band SNR in dB.  Scalar or 1-D array broadcastable with
            *transmitting*.
        transmitting:
            Boolean array indicating which bands are transmitting.

        Returns
        -------
        np.ndarray[bool]
            Detection outcomes, same shape as *transmitting*.
        """
        if self._rng is None:
            raise RuntimeError("DetectionModel must be reset() before calling detect_batch()")
        transmitting = np.asarray(transmitting, dtype=np.bool_)
        snr_db = np.broadcast_to(np.asarray(snr_db, dtype=np.float64), transmitting.shape)

        snr_lin = 10.0 ** (snr_db / 10.0)
        x_pd = self.dwell * self.threshold / (1.0 + snr_lin)
        term = np.ones_like(x_pd)
        pd_total = term.copy()
        for n in range(1, self.dwell):
            term = term * x_pd / n
            pd_total = pd_total + term
        pd_vals = np.exp(-x_pd) * pd_total
        pfa_val = pfa_from_threshold_dlook(self.threshold, self.dwell)

        probs = np.where(transmitting, pd_vals, pfa_val)
        u = self._rng.random(transmitting.shape)
        return u < probs
