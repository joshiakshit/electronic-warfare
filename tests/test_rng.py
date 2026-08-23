"""Tests for ewscan.rng — 1A.3 verification.

Verify criterion (PLAN.md 1A.3):
    Same seed reproduces an identical stream twice.
"""

from __future__ import annotations

import numpy as np
import pytest

from ewscan.rng import SUBSYSTEMS, make_generators, spawn_episode_seed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _draw_floats(rngs: dict, n: int = 20) -> dict[str, list[float]]:
    """Draw *n* floats from each generator; return as plain lists for comparison."""
    return {name: rng.random(n).tolist() for name, rng in rngs.items()}


# ---------------------------------------------------------------------------
# Core reproducibility test (the PLAN verify criterion)
# ---------------------------------------------------------------------------

class TestReproducibility:
    """Same seed reproduces an identical stream twice."""

    def test_integer_seed_reproduces(self):
        rngs_a = make_generators(seed=0)
        rngs_b = make_generators(seed=0)
        assert _draw_floats(rngs_a) == _draw_floats(rngs_b)

    def test_different_seeds_differ(self):
        draws_0 = _draw_floats(make_generators(seed=0))
        draws_1 = _draw_floats(make_generators(seed=1))
        # At least one subsystem must differ (all should, but one is enough)
        assert any(draws_0[k] != draws_1[k] for k in SUBSYSTEMS)

    def test_seed_sequence_input_reproduces(self):
        ss_a = np.random.SeedSequence(42)
        ss_b = np.random.SeedSequence(42)
        assert _draw_floats(make_generators(ss_a)) == _draw_floats(make_generators(ss_b))

    @pytest.mark.parametrize("seed", [0, 1, 42, 2**31 - 1, 99999])
    def test_multiple_seeds_all_reproduce(self, seed):
        assert _draw_floats(make_generators(seed)) == _draw_floats(make_generators(seed))


# ---------------------------------------------------------------------------
# Independence: drawing from one subsystem must not affect another
# ---------------------------------------------------------------------------

class TestIndependence:
    """Subsystem generators are statistically independent."""

    def test_subsystems_are_independent(self):
        """Exhausting one generator must not alter another's stream."""
        rngs_a = make_generators(seed=7)
        rngs_b = make_generators(seed=7)

        # Exhaust "env" in one copy
        _ = rngs_a["env"].random(10_000)

        # All other subsystems must still match
        for name in SUBSYSTEMS:
            if name == "env":
                continue
            assert rngs_a[name].random(50).tolist() == rngs_b[name].random(50).tolist(), \
                f"Subsystem '{name}' was affected by drawing from 'env'"

    def test_all_subsystems_present(self):
        rngs = make_generators(seed=0)
        assert set(rngs.keys()) == set(SUBSYSTEMS)

    def test_generators_are_numpy_generators(self):
        rngs = make_generators(seed=0)
        for name, rng in rngs.items():
            assert isinstance(rng, np.random.Generator), \
                f"'{name}' is {type(rng)}, expected np.random.Generator"


# ---------------------------------------------------------------------------
# spawn_episode_seed helper
# ---------------------------------------------------------------------------

class TestSpawnEpisodeSeed:
    """Per-episode seed derivation is reproducible and episode-disjoint."""

    def test_same_episode_reproduces(self):
        ss_a = spawn_episode_seed(root_seed=0, episode_index=3)
        ss_b = spawn_episode_seed(root_seed=0, episode_index=3)
        g_a = make_generators(ss_a)
        g_b = make_generators(ss_b)
        assert _draw_floats(g_a) == _draw_floats(g_b)

    def test_different_episodes_differ(self):
        g0 = make_generators(spawn_episode_seed(0, 0))
        g1 = make_generators(spawn_episode_seed(0, 1))
        draws_0 = _draw_floats(g0)
        draws_1 = _draw_floats(g1)
        assert any(draws_0[k] != draws_1[k] for k in SUBSYSTEMS)

    def test_different_root_seeds_differ(self):
        g_r0 = make_generators(spawn_episode_seed(0, 0))
        g_r1 = make_generators(spawn_episode_seed(1, 0))
        draws_r0 = _draw_floats(g_r0)
        draws_r1 = _draw_floats(g_r1)
        assert any(draws_r0[k] != draws_r1[k] for k in SUBSYSTEMS)
