"""Seeded random-number-generator factory for ewscan.

Each subsystem gets its own independent ``numpy.random.Generator`` derived from
a root ``SeedSequence`` via ``SeedSequence.spawn``.  Spawning is reproducible:
given the same root seed the same child generators are always produced in the
same order, so a full episode is fully determined by a single integer seed.

Usage::

    from ewscan.rng import make_generators

    rngs = make_generators(seed=42)
    env_rng   = rngs["env"]
    sched_rng = rngs["scheduler"]
    det_rng   = rngs["detection"]

All keys in ``SUBSYSTEMS`` are guaranteed to be present and independent.
Add new subsystem names here (and here only) so that the spawn order—and
therefore every existing seed—stays stable.
"""

from __future__ import annotations

from typing import Dict

import numpy as np

# ---------------------------------------------------------------------------
# Ordered subsystem registry
# ---------------------------------------------------------------------------
# ORDER IS FIXED.  Append new names at the end; never reorder or remove.
# Changing this list is a shared-file edit that requires a sync-gate agreement.
SUBSYSTEMS: tuple[str, ...] = (
    "env",        # environment stepper and truth generation
    "detection",  # square-law detector noise draws
    "scheduler",  # schedulers that need internal randomness (e.g. Thompson)
    "emitter",    # per-emitter Markov / jitter draws
    "metrics",    # reserved for future stochastic metric estimators
)


def make_generators(seed: int | np.random.SeedSequence) -> Dict[str, np.random.Generator]:
    """Return one ``numpy.random.Generator`` per subsystem.

    Parameters
    ----------
    seed:
        Either a plain integer (converted to a ``SeedSequence`` internally) or
        an already-constructed ``SeedSequence``.  Pass a ``SeedSequence`` when
        you need to chain spawning (e.g. multi-episode sweeps).

    Returns
    -------
    dict[str, Generator]
        Keys are exactly the names in ``SUBSYSTEMS``.  The generators are
        independent: drawing from one does not advance any other.
    """
    if isinstance(seed, np.random.SeedSequence):
        ss = seed
    else:
        ss = np.random.SeedSequence(seed)

    children: list[np.random.SeedSequence] = ss.spawn(len(SUBSYSTEMS))
    return {
        name: np.random.default_rng(child)
        for name, child in zip(SUBSYSTEMS, children)
    }


def spawn_episode_seed(root_seed: int, episode_index: int) -> np.random.SeedSequence:
    """Derive a per-episode ``SeedSequence`` from a root seed and episode index.

    Useful in multi-seed sweeps: each episode gets a fully independent RNG
    tree while remaining reproducible from ``(root_seed, episode_index)``.

    Parameters
    ----------
    root_seed:
        The top-level integer seed for the entire sweep.
    episode_index:
        Zero-based index of this episode within the sweep.

    Returns
    -------
    SeedSequence
        Pass to ``make_generators`` to obtain subsystem generators for this
        episode.
    """
    return np.random.SeedSequence(root_seed, spawn_key=(episode_index,))
