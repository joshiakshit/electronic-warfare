# Electronic Warfare Scan Scheduler

ML-based adaptive scheduler for Electronic Support (ES) receivers.

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
