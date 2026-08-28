"""Average reward accumulator and cost readout estimators from the episode log -- Phase 1E.4.

Estimates accumulated reward and breaks down the component costs (hit reward,
miss cost, novelty bonus, revisit decay) across an episode.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from ewscan.agents.reward import RewardFunction
from ewscan.contracts import EpisodeLog


@dataclass(frozen=True)
class RewardMetrics:
    """Average reward accumulator and cost readout summary for one episode.

    Attributes
    ----------
    total_reward : float
        Total accumulated reward over all slots in the episode.
    average_reward : float
        Average reward per slot (total_reward / n_slots), or NaN if n_slots == 0.
    total_hit_reward : float
        Total reward accumulated from signal hits (threat-weighted).
    total_miss_cost : float
        Total penalty incurred from missed detections (-c_miss per miss).
    total_novelty_bonus : float
        Total bonus accumulated from scanning stale/unvisited bands.
    total_revisit_decay : float
        Total penalty incurred from scanning recently visited bands.
    average_hit_reward : float
        Average hit reward per slot.
    average_miss_cost : float
        Average miss cost per slot.
    average_novelty_bonus : float
        Average novelty bonus per slot.
    average_revisit_decay : float
        Average revisit decay per slot.
    per_slot_rewards : NDArray[np.float64]
        Array of total rewards per slot (shape: (n_slots,)).
    n_slots : int
        Total number of slots in the episode.
    """

    total_reward: float
    average_reward: float
    total_hit_reward: float
    total_miss_cost: float
    total_novelty_bonus: float
    total_revisit_decay: float
    total_retune_penalty: float
    average_hit_reward: float
    average_miss_cost: float
    average_novelty_bonus: float
    average_revisit_decay: float
    average_retune_penalty: float
    per_slot_rewards: NDArray[np.float64]
    n_slots: int


def estimate_reward_metrics(
    log: EpisodeLog,
    rf: RewardFunction | None = None,
) -> RewardMetrics:
    """Compute full reward accumulation and cost readout for an episode log.

    Parameters
    ----------
    log : EpisodeLog
        The episode log to evaluate.
    rf : RewardFunction | None
        The reward function instance to use. Defaults to default RewardFunction().

    Returns
    -------
    RewardMetrics
        Dataclass containing total reward, average reward, component breakdowns,
        and per-slot reward array.
    """
    if rf is None:
        rf = RewardFunction()

    n_slots = log.n_slots
    if n_slots == 0:
        return RewardMetrics(
            total_reward=0.0,
            average_reward=float("nan"),
            total_hit_reward=0.0,
            total_miss_cost=0.0,
            total_novelty_bonus=0.0,
            total_revisit_decay=0.0,
            total_retune_penalty=0.0,
            average_hit_reward=float("nan"),
            average_miss_cost=float("nan"),
            average_novelty_bonus=float("nan"),
            average_revisit_decay=float("nan"),
            average_retune_penalty=float("nan"),
            per_slot_rewards=np.empty(0, dtype=np.float64),
            n_slots=0,
        )

    n_bands = log.n_bands
    k = log.config.k
    cd = rf.cooldown if rf.cooldown is not None else n_bands

    threat_map = np.full(n_bands, rf.baseline_threat, dtype=np.float64)
    for em in log.config.emitters:
        if 0 <= em.band < n_bands:
            threat_map[em.band] = max(threat_map[em.band], em.threat_level)

    staleness = np.full(n_bands, n_bands, dtype=np.intp)
    per_slot_rewards = np.empty(n_slots, dtype=np.float64)
    hit_rewards = np.empty(n_slots, dtype=np.float64)
    miss_costs = np.empty(n_slots, dtype=np.float64)
    novelty_bonuses = np.empty(n_slots, dtype=np.float64)
    revisit_decays = np.empty(n_slots, dtype=np.float64)
    retune_penalties = np.zeros(n_slots, dtype=np.float64)

    for t in range(n_slots):
        bands_t = log.actions[t]
        dets_t = log.detections[t]
        r_hit = r_miss = r_novelty = r_decay = 0.0
        for j in range(k):
            band = int(bands_t[j])
            if band < 0 or band >= n_bands:
                # Invalid action (e.g. -1 "no-op") — contributes zero reward
                continue
            det = float(dets_t[j])
            s = int(staleness[band])
            r_hit += rf.w_threat * threat_map[band] * det
            r_miss += -rf.c_miss * (1.0 - det)
            r_novelty += rf.w_novelty * min(s / n_bands, 1.0)
            r_decay += -rf.w_decay * max(0.0, 1.0 - s / cd) if cd > 0 else 0.0

        if log.config.retune_cost_slots > 0 and log.retune_events[t]:
            retune_penalties[t] = -rf.c_retune

        hit_rewards[t] = r_hit
        miss_costs[t] = r_miss
        novelty_bonuses[t] = r_novelty
        revisit_decays[t] = r_decay
        per_slot_rewards[t] = r_hit + r_miss + r_novelty + r_decay + retune_penalties[t]

        staleness += 1
        for j in range(k):
            band = int(bands_t[j])
            if 0 <= band < n_bands:
                staleness[band] = 0

    tot_hit = float(np.sum(hit_rewards))
    tot_miss = float(np.sum(miss_costs))
    tot_novelty = float(np.sum(novelty_bonuses))
    tot_decay = float(np.sum(revisit_decays))
    tot_retune = float(np.sum(retune_penalties))
    tot_reward = float(np.sum(per_slot_rewards))

    return RewardMetrics(
        total_reward=tot_reward,
        average_reward=tot_reward / n_slots,
        total_hit_reward=tot_hit,
        total_miss_cost=tot_miss,
        total_novelty_bonus=tot_novelty,
        total_revisit_decay=tot_decay,
        total_retune_penalty=tot_retune,
        average_hit_reward=tot_hit / n_slots,
        average_miss_cost=tot_miss / n_slots,
        average_novelty_bonus=tot_novelty / n_slots,
        average_revisit_decay=tot_decay / n_slots,
        average_retune_penalty=tot_retune / n_slots,
        per_slot_rewards=per_slot_rewards,
        n_slots=n_slots,
    )


def estimate_average_reward(
    log: EpisodeLog,
    rf: RewardFunction | None = None,
) -> float:
    """Compute average per-slot reward for an episode log.

    Parameters
    ----------
    log : EpisodeLog
        The episode log to evaluate.
    rf : RewardFunction | None
        The reward function instance to use. Defaults to default RewardFunction().

    Returns
    -------
    float
        Average reward per slot (or NaN if n_slots == 0).
    """
    return estimate_reward_metrics(log, rf=rf).average_reward
