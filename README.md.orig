# Electronic Warfare Scan Scheduler

ML-based adaptive scheduler for Electronic Support (ES) receivers.

## Installation

```bash
pip install -e .
```

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
- `ewscan/testing/` — Fixtures and test utilities
- `ewscan/env/` — Simulated RF environment (Track A)
- `ewscan/metrics/` — Performance metrics (Track A)
- `ewscan/experiments/` — Experiment harness (Track A)
- `ewscan/agents/` — Scheduling algorithms (Track B)
- `ewscan/dashboard/` — Streamlit visualization (Track B)
