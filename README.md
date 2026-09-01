# E-WAVE

**Adaptive Electronic Support scan scheduling using online machine learning.**

A wideband receiver must monitor N frequency bands but can only scan K at a
time. E-WAVE learns where and when to look using multi-armed bandits, Bayesian
state tracking, and periodic-signal prediction. No offline training data or
neural networks required — all learning happens online during each episode.

## Quick start

```bash
git clone https://github.com/joshiakshit/electronic-warfare.git
cd electronic-warfare
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Run a simulation:

```bash
python -m ewscan.experiments --config contested_spectrum --scheduler belief --seed 42
```

Run the dashboard:

```bash
uvicorn ewscan.api.server:app --reload
# in another terminal
cd frontend && npm install && npm run dev
```

## How it works

```
Environment generates hidden emitter activity across N bands
    ↓
Scheduler chooses K bands to scan
    ↓
Detector returns noisy hit/miss for each chosen band
    ↓
Scheduler updates its model from the results
    ↓
Repeat for T time slots
    ↓
Evaluator scores the scan log against hidden truth
```

The scheduler never sees the truth. It learns only from its own noisy
observations. The Oracle scheduler (which does see truth) provides a
performance ceiling for comparison.

## Schedulers

| Scheduler | Type | Approach |
|---|---|---|
| `round_robin` | Baseline | Visits bands in fixed order |
| `uniform_random` | Baseline | Chooses bands randomly |
| `prior_weighted` | Baseline | Follows an explicit threat prior |
| `oracle` | Ceiling | Reads hidden truth (not deployable) |
| `ucb1` | Bandit | Balances reward with exploration bonus |
| `sliding_window_ucb` | Bandit | UCB with recent-window forgetting |
| `discounted_ucb` | Bandit | UCB with exponential discounting |
| `thompson_sampling` | Bandit | Samples from Beta posteriors |
| `discounted_thompson` | Bandit | Thompson with forgetting |
| `belief` | Bayesian | Tracks per-band ON probability with phase-conditioned occupancy |
| `sniper` | Predictive | Wraps a bandit with periodic-transmission prediction |

**Belief** and **Sniper** are the advanced schedulers. Belief beats Thompson
sampling on all four scenarios. Sniper beats both baselines on periodic
scenarios and falls back to its inner bandit elsewhere.

## Emitters

The simulated environment includes:

- **Gilbert-Elliott**: Markov ON/OFF switching
- **Periodic radar**: repeating active windows with optional jitter
- **Continuous wave**: always active
- **Frequency hopper**: moves between bands
- **Scanning beam**: rotating antenna with varying received power
- Multiple emitters can share a band; powers combine

## Scenarios

| Scenario | Description |
|---|---|
| `sparse_bursty` | Three bursty emitters, 16 bands |
| `mixed_threat` | Continuous, periodic, frequent, and rare activity |
| `periodic_radar` | Three periodic emitters with different timing |
| `contested_spectrum` | Beam, hopping, periodic, and Markov activity |

## Metrics

- Probability of detection and false alarm
- Interception ratio and intercept rate
- Time to first intercept and intercept fraction
- Learner reward (observation-based) and evaluation utility (truth-based)
- Prediction accuracy, coverage, and override telemetry
- Multi-seed means and 95% confidence intervals

## Benchmarks

30 paired seeds, blind track, K=1 over 16 bands:

| Scenario | Belief | vs Thompson |
|---|---:|---|
| mixed_threat | 0.528 | +0.004 |
| periodic_radar | 0.469 | +0.211 |
| sparse_bursty | 0.352 | +0.073 |
| contested_spectrum | 0.213 | +0.085 |

All wins confirmed on held-out seeds (200-229) never used during development.
Full benchmark data in [PLAN.md](PLAN.md).

## Run a benchmark

```bash
python -m ewscan.experiments.sweep \
  --config contested_spectrum \
  --schedulers round_robin,ucb1,thompson_sampling,belief,sniper,oracle \
  --num-seeds 30 \
  --output results.csv \
  --aggregate-output summary.csv
```

## Tests

```bash
pytest tests/
```

```bash
cd frontend && npm run typecheck && npm run lint && npm test && npm run build
```

## Project structure

```
ewscan/
  agents/        Scheduler implementations and learning models
  api/           FastAPI service for the dashboard
  env/           RF environment, emitters, detection, recording
  experiments/   Episode runner, scenarios, registry, sweeps
  metrics/       Detection, interception, reward, prediction, timing
  testing/       Shared test fixtures
  contracts.py   Immutable contracts and interfaces
  detector.py    Detector capability and calibration
  config.py      YAML configuration loading
  rng.py         Independent seeded random streams
frontend/        React + Vite dashboard
configs/         YAML scenario definitions
tests/           Python test suite
```

## Key design properties

- **Information boundary**: non-oracle schedulers never see emitter locations,
  SNR, types, or transition parameters. External intelligence enters only
  through a labelled `ThreatPrior`.
- **Detector consistency**: one immutable detector capability object carries
  calibrated Pfa, threshold, dwell, and Pd. Every component uses the same
  values.
- **Reproducibility**: independent RNG streams for emitters, detection, and
  scheduling. Paired seeds compare algorithms against identical hidden worlds.
- **Honest evaluation**: learner reward (what the scheduler sees) and evaluation
  utility (truth-based scoring) are separate quantities.

## Requirements

- Python 3.9+
- Node.js (for the dashboard)
- NumPy, PyYAML, FastAPI, Uvicorn, Pydantic

## License

MIT

## Contributing

Contributions welcome. See [PLAN.md](PLAN.md) for current status, known limits,
and future work including the live-data replay path and offensive EA roadmap.
