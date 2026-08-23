"""ewscan.agents package.

Scan schedulers and decision agents.
"""

from ewscan.agents.baselines import (
    OracleScheduler,
    PriorWeightedScheduler,
    RoundRobinScheduler,
    UniformRandomScheduler,
)
from ewscan.agents.nonstationary_ucb import DUCB1Scheduler, SWUCB1Scheduler
from ewscan.agents.reward import RewardFunction
from ewscan.agents.stats import BandStatistics
from ewscan.agents.thompson import (
    BetaThompsonSamplingScheduler,
    DiscountedThompsonScheduler,
    ThompsonSamplingScheduler,
)
from ewscan.agents.ucb import UCB1Scheduler

__all__ = [
    "RoundRobinScheduler",
    "UniformRandomScheduler",
    "PriorWeightedScheduler",
    "OracleScheduler",
    "RewardFunction",
    "BandStatistics",
    "UCB1Scheduler",
    "DUCB1Scheduler",
    "SWUCB1Scheduler",
    "ThompsonSamplingScheduler",
    "BetaThompsonSamplingScheduler",
    "DiscountedThompsonScheduler",
]

