"""Reward function for learning schedulers (Phase 1D.1).

Four terms: threat-weighted hit, miss cost, novelty bonus, revisit decay.
See REWARD_SPEC.md for the full design rationale.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from ewscan.contracts import EpisodeLog


@dataclass(frozen=True)
class RewardFunction:
    """Computes per-slot reward from observation context.

    Parameters match the defaults in REWARD_SPEC.md. Override via constructor.
    """

    w_threat: float = 1.0
    c_miss: float = 0.1
    w_novelty: float = 0.2
    w_decay: float = 0.3
    c_retune: float = 0.1
    cooldown: int | None = None
    baseline_threat: float = 0.1

    def compute(
        self,
        detection: bool,
        threat_level: float,
        staleness: int,
        n_bands: int,
        cooldown: int | None = None,
    ) -> float:
        """Compute reward for one slot.

        Parameters
        ----------
        detection : bool
            Whether a signal was detected on the scanned band.
        threat_level : float
            Threat level of the emitter on the scanned band.
            Use baseline_threat if no emitter is known.
        staleness : int
            Slots since this band was last visited.
        n_bands : int
            Total number of bands (used to normalize novelty).
        cooldown : int | None
            Override for the revisit penalty window. Defaults to
            self.cooldown if set, otherwise n_bands.
        """
        cd = cooldown if cooldown is not None else (self.cooldown if self.cooldown is not None else n_bands)

        det = float(detection)
        r_hit = self.w_threat * threat_level * det
        r_miss = -self.c_miss * (1.0 - det)
        r_novelty = self.w_novelty * min(staleness / n_bands, 1.0)
        r_decay = -self.w_decay * max(0.0, 1.0 - staleness / cd) if cd > 0 else 0.0

        return r_hit + r_miss + r_novelty + r_decay

    def compute_episode(self, log: EpisodeLog) -> NDArray[np.float64]:
        """Compute reward for every slot in an episode log.

        Tracks staleness internally using the action sequence.
        Threat levels are read from config.emitters.
        """
        n_bands = log.n_bands
        n_slots = log.n_slots
        k = log.config.k
        cd = self.cooldown if self.cooldown is not None else n_bands

        threat_map = np.full(n_bands, self.baseline_threat, dtype=np.float64)
        for em in log.config.emitters:
            if 0 <= em.band < n_bands:
                threat_map[em.band] = max(threat_map[em.band], em.threat_level)

        staleness = np.full(n_bands, n_bands, dtype=np.intp)
        rewards = np.empty(n_slots, dtype=np.float64)

        for t in range(n_slots):
            bands_t = log.actions[t]
            dets_t = log.detections[t]
            r = 0.0
            for j in range(k):
                band = int(bands_t[j])
                if band < 0 or band >= n_bands:
                    continue
                det = float(dets_t[j])
                s = int(staleness[band])
                r += self.w_threat * threat_map[band] * det
                r += -self.c_miss * (1.0 - det)
                r += self.w_novelty * min(s / n_bands, 1.0)
                r += -self.w_decay * max(0.0, 1.0 - s / cd) if cd > 0 else 0.0
            if log.config.retune_cost_slots > 0 and log.retune_events[t]:
                r -= self.c_retune
            rewards[t] = r

            staleness += 1
            for j in range(k):
                band = int(bands_t[j])
                if 0 <= band < n_bands:
                    staleness[band] = 0

        return rewards
