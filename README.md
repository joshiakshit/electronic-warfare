# Electronic Warfare Smart Scan Scheduler

Closed-loop scan scheduling software for Electronic Support receivers. It learns
emitter activity from hits and misses when prior intelligence is unavailable.

The learning methods are online multi-armed bandits and Bayesian state models.
They do not require an offline training dataset or a saved neural network.

## Installation

```bash
pip install -e .
cd frontend
npm install
```

## Running the Showcase Terminal

1. **Start the Simulation Backend (FastAPI)**
```bash
uvicorn ewscan.api.server:app --reload
```

2. **Start the Frontend Dashboard (React/Vite)**
```bash
cd frontend
npm run dev
```

The default demo uses the `contested_spectrum` scenario. It combines a scanning
beam, a frequency-hopping emitter, a periodic radar, and a bursty emitter. The
dashboard compares the selected scheduler with round robin and an oracle ceiling.
It also replays the learned value for every frequency band after each observation.
The initial view uses the Sniper scheduler because it combines bandit learning with
periodic-transmission prediction.

## Benchmarking

Run a 30-seed comparison with confidence intervals:

```bash
python -m ewscan.experiments.sweep \
  --config contested_spectrum \
  --schedulers round_robin,ucb1,sliding_window_ucb,discounted_ucb,thompson_sampling,discounted_thompson,belief,sniper,oracle \
  --num-seeds 30 \
  --output benchmark_runs.csv \
  --aggregate-output benchmark_summary.csv
```

Use `benchmark_summary.csv` for judge-facing comparisons. Report multi-seed
results instead of a single favorable run.

## Problem statement coverage

- Limited instantaneous bandwidth is represented by `k` scanned bands per slot.
- The simulator records truth by emitter, frequency band, and time slot.
- Blind schedulers receive only detector observations.
- UCB and Thompson schedulers learn from online hits and misses.
- The belief scheduler estimates hidden ON and OFF states.
- The Sniper scheduler estimates periodic activity and predicts due transmissions.
- Figures of merit include Pd, Pfa, sensitivity, interception rate, reward,
  prediction accuracy, time to first intercept, and intercept-time error.

Threat priority is scenario metadata. Blind schedulers do not infer threat identity.
The software does not claim automatic threat classification.

## Development

Install with dev dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest tests/
```

## Project Structure

- `ewscan/contracts.py` — Shared data structures
- `ewscan/rng.py` — Seeded RNG per subsystem
- `ewscan/config.py` — Configuration loading
- `ewscan/api/` — FastAPI Server for simulations
- `frontend/` — React/Next.js Terminal Showcase UI
- `ewscan/testing/` — Fixtures and test utilities
- `ewscan/env/` — Simulated RF environment (Track A)
- `ewscan/metrics/` — Performance metrics (Track A)
- `ewscan/experiments/` — Experiment harness (Track A)
- `ewscan/agents/` — Scheduling algorithms (Track B)
