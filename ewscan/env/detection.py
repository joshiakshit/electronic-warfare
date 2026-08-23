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

These are the exact closed-form ROC equations for a single-sample energy
detector on complex Gaussian noise with a deterministic signal of known
power.  For M integrated pulses the chi-squared form would apply; we fix
M = 1 in the MVP.

The ``detect`` function draws a uniform random number and compares it to the
appropriate probability (Pd if the emitter is transmitting, Pfa otherwise),
returning a boolean detection.

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
    """

    def __init__(self, pfa: float, threshold: float | None = None) -> None:
        if not (0.0 < pfa < 1.0):
            raise ValueError(f"pfa must be in (0, 1), got {pfa}")
        self.pfa = pfa
        self.threshold = threshold if threshold is not None else threshold_from_pfa(pfa)
        self._rng: np.random.Generator | None = None

    def reset(self, rng: np.random.Generator) -> None:
        """Bind a fresh RNG for a new episode."""
        self._rng = rng

    def get_pd(self, snr_db: float) -> float:
        """Return the detection probability for a given emitter SNR.

        This is a pure query (no random draw).
        """
        return pd_from_snr(snr_db, self.threshold)

    def get_pfa(self) -> float:
        """Return the actual false-alarm probability implied by the threshold."""
        return pfa_from_threshold(self.threshold)

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
            p = pd_from_snr(snr_db, self.threshold)
        else:
            p = pfa_from_threshold(self.threshold)
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
        pd_vals = np.exp(-self.threshold / (1.0 + snr_lin))
        pfa_val = pfa_from_threshold(self.threshold)

        probs = np.where(transmitting, pd_vals, pfa_val)
        u = self._rng.random(transmitting.shape)
        return u < probs
