# Reward Function Specification — Phase 1D.1

Defines the per-slot reward signal used by learning schedulers and accumulated
by metric 1E.4 (average reward).

## Formula

```
R(t) = R_hit + R_miss + R_novelty + R_decay
```

### Terms

| Term | Formula | Range |
|------|---------|-------|
| Hit reward | `w_threat * threat_level(band) * detection` | [0, w_threat] |
| Miss cost | `-c_miss * (1 - detection)` | [-c_miss, 0] |
| Novelty bonus | `w_novelty * min(staleness / n_bands, 1.0)` | [0, w_novelty] |
| Revisit decay | `-w_decay * max(0, 1 - staleness / cooldown)` | [-w_decay, 0] |

### Variables

- `detection`: 1 if a signal was detected on the scanned band, 0 otherwise.
- `threat_level(band)`: from `EmitterInfo.threat_level` for emitters resident on
  the scanned band. Defaults to `baseline_threat` for bands with no known emitter.
- `staleness`: number of slots since the scheduler last visited this band.
  Initialized to `n_bands` at episode start (so no band is penalized or
  over-rewarded on first visit).
- `cooldown`: number of slots after which the revisit penalty vanishes.
  Default: `n_bands`.

### Default weights

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `w_threat` | 1.0 | A max-threat detection anchors the scale at 1.0. |
| `c_miss` | 0.1 | Mild penalty. Keeps exploration viable. |
| `w_novelty` | 0.2 | 20% of a max-threat hit. Enough pull, not dominant. |
| `w_decay` | 0.3 | Immediate revisit costs 0.3. Breaks camping. |
| `cooldown` | n_bands | One full sweep cycle clears the penalty. |
| `baseline_threat` | 0.1 | Bands with no known emitter are still worth a look. |

## Behavior under key scenarios

| Scenario | Expected R(t) |
|----------|---------------|
| First visit to stale band, detect threat=1.0 | 1.0 + 0.0 + 0.2 + 0.0 = **1.2** |
| Immediate revisit, detect threat=1.0 | 1.0 + 0.0 + 0.0 - 0.3 = **0.7** |
| First visit to stale band, no detection | 0.0 - 0.1 + 0.2 + 0.0 = **0.1** |
| Immediate revisit, no detection | 0.0 - 0.1 + 0.0 - 0.3 = **-0.4** |
| Half-stale visit (staleness = n_bands/2), detect threat=0.5 | 0.5 + 0.0 + 0.1 - 0.15 = **0.45** |

## Design rationale

1. **Why not just detection?** A scheduler that maximizes raw detections camps on
   the loudest emitter regardless of threat. That is the open-loop failure mode.

2. **Why threat weighting?** The problem requires prioritizing threat. A threat=0.1
   harmless radar should not starve a threat=1.0 missile seeker of attention.

3. **Why novelty bonus?** Without it, the scheduler converges to the best single
   band and never leaves. Novelty grows linearly with staleness and caps at one
   sweep cycle, giving a bounded, predictable pull toward unvisited bands.

4. **Why revisit decay?** The novelty bonus rewards going elsewhere, but decay
   explicitly penalizes staying. Together they create a gradient away from the
   current band. Decay vanishes after `cooldown` slots, so revisiting after a
   full rotation is free.

5. **Why miss cost?** Without it, a scheduler that picks random bands suffers no
   explicit penalty for wasting slots. Miss cost makes empty scans costly, pushing
   the scheduler toward bands where detection is likely.

## Interface

```python
from ewscan.agents.reward import RewardFunction

rf = RewardFunction()  # uses defaults
rf = RewardFunction(w_threat=1.0, c_miss=0.1, w_novelty=0.2, w_decay=0.3)

# Per-slot call:
reward = rf.compute(
    detection=True,
    threat_level=0.8,
    staleness=5,
    n_bands=16,
)

# Batch call over an episode log:
rewards = rf.compute_episode(log)
```

## Staleness tracking

The reward function does not own staleness state. It receives `staleness` as an
input. The per-band statistics store (1D.2) tracks staleness and passes it in.

For unit tests and standalone use, `RewardFunction` provides a stateless compute
method. The caller is responsible for maintaining and passing staleness.
