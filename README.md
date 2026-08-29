# E-WAVE: Adaptive Electronic Support Scan Scheduling

E-WAVE is a simulation and decision-support project for adaptive spectrum
scanning. It models an Electronic Support receiver that can observe only a
small part of a wide frequency range at each time step.

The system learns where useful activity is likely to appear. It then chooses
which frequency bands to scan next. It compares fixed scan patterns, online
machine-learning methods, Bayesian state models, and periodic-signal
prediction under the same hidden environment.

E-WAVE is simulation-only. It does not transmit, interfere with signals,
decode private communications, or control radio hardware.

## The problem

A wideband receiver may need to monitor many frequency bands while having only
limited instantaneous bandwidth, processing capacity, or parallel channels.
It cannot inspect every band continuously.

A fixed sweep is simple, but it spends equal time on quiet and active bands.
It can miss short bursts, revisit predictable signals at the wrong time, and
adapt slowly when activity changes.

E-WAVE represents this constraint with:

- `N` frequency bands;
- `K` bands that can be scanned in one time slot;
- hidden emitter activity;
- noisy detections and false alarms;
- retuning and settling costs;
- a scheduler that receives only past observations.

The objective is not only to detect a signal after selecting its band. The
receiver must first choose the right band at the right time.

## What E-WAVE does

For each episode, E-WAVE:

1. Generates hidden emitter activity across bands and time.
2. Asks a scheduler to choose exactly `K` bands.
3. Applies the detector model to those bands.
4. Returns noisy detection results to the scheduler.
5. Lets the scheduler update its online model.
6. Repeats the process for the configured number of slots.
7. Scores the complete log against hidden simulation truth.

The environment supports:

- Gilbert-Elliott ON/OFF emitters;
- periodic radar emitters with dwell, phase, and jitter;
- continuous-wave emitters;
- frequency-hopping emitters;
- rotating scanning-beam emitters;
- multiple emitters occupying the same band;
- configurable SNR, detector threshold, false-alarm probability, and dwell;
- parallel `K`-band actions;
- retune settling intervals.

The project includes a FastAPI backend and a React/Vite dashboard. The default
showcase uses the `contested_spectrum` scenario with beam, hopping, periodic,
and bursty activity.

## How the idea developed

The project started from one question:

> If a receiver cannot observe the full spectrum, can it learn where and when
> to look better than a fixed sweep?

We developed the design in stages:

1. Build deterministic baselines and a reproducible simulator.
2. Add online bandit methods that learn useful bands from hits and misses.
3. Add forgetting so learners can follow changing activity.
4. Model hidden ON/OFF state instead of treating every observation as
   independent.
5. Detect periodic structure and reserve scans near predicted transmissions.
6. Separate hidden simulator truth from all deployable schedulers.
7. Evaluate every method with paired random seeds and common metrics.

This progression kept the system measurable. Every advanced scheduler can be
compared with round robin, random selection, standard learners, and an Oracle
ceiling.

## Machine-learning implementation

E-WAVE uses online learning. It does not require an offline training dataset or
a saved neural network.

### Multi-armed bandits

- **UCB1** balances empirical reward with an uncertainty bonus.
- **Sliding-window UCB** uses recent evidence to follow changes.
- **Discounted UCB** gradually reduces the value of old evidence.
- **Thompson sampling** samples from a Beta posterior for each band.
- **Discounted Thompson sampling** adds forgetting for restless activity.

### Bayesian state tracking

The belief scheduler estimates the probability that each band is currently ON.
It predicts state changes with learned `p01` and `p10` transition rates. It
then corrects the belief using detector probability of detection and false
alarm.

### Periodic prediction

The Sniper scheduler wraps an online learner. It searches sparse observation
history for supported period and phase candidates. A prediction overrides the
inner learner only when the evidence and expected incremental value pass the
configured gates.

### Whittle research scheduler

The repository also contains a numeric Whittle-index scheduler for a
Gilbert-Elliott restless bandit. It learns transition rates, solves the
single-arm subsidy problem on a belief grid, and ranks bands by interpolated
index values.

Sparse observations create gaps between visits to a band. This research path
uses multi-step Markov propagation across those gaps instead of treating distant
observations as adjacent samples.

Whittle remains a research implementation. It is intentionally excluded from
the public scheduler registry because it did not pass its previous release
comparison. It must win a new multi-seed benchmark before release.

## What we innovated

The contributions are system-level combinations and verification mechanisms.
They should not be read as claims that the underlying bandit algorithms were
invented here.

### Gap-aware learning from sparse scans

The receiver rarely revisits one band in consecutive slots. E-WAVE bridges an
arbitrary observation gap with the Markov transition matrix and accumulates
expected one-step transition counts. This lets the model learn from the scan
pattern it actually experiences.

### Sparse periodic prediction with controlled overrides

The periodic path creates candidates from detected-hit gaps, scores them with
positive and negative observations, estimates phase, and validates later
predictions. It records the inner action, executed action, prediction coverage,
and override benefit.

### Enforced information boundaries

Normal schedulers receive a restricted `SchedulerConfig`. It contains no
emitter locations, SNR values, emitter types, transition parameters, or hidden
truth. External intelligence enters only through a labelled `ThreatPrior`.
Blind, prior-aided, and Oracle runs remain separate.

### Detector-consistent Bayesian decisions

One immutable detector capability carries requested false-alarm probability,
effective dwell-aware false-alarm probability, threshold, dwell, and nominal
detection probability. The environment, Bayesian schedulers, metrics, API, and
reports use the same calibrated values.

### Fair and reproducible evaluation

Independent random generators isolate emitter activity, detector noise, and
scheduler randomness. Paired seeds therefore compare schedulers against the
same hidden worlds without random-stream contamination.

### Honest reward and truth separation

The scheduler learns from observable feedback. The evaluator scores against
hidden truth after the episode. E-WAVE reports learner reward and truth-based
evaluation utility as different quantities.

### Explainable replay

The dashboard replays actions, detections, hidden truth, metrics, and each
scheduler's real learning state. It does not present a generated generic
confidence score.

## Schedulers

The public registry includes:

- `round_robin`
- `uniform_random`
- `prior_weighted`
- `oracle`
- `ucb1`
- `sliding_window_ucb`
- `discounted_ucb`
- `thompson_sampling`
- `discounted_thompson`
- `belief`
- `sniper`

Oracle is a simulation ceiling. It is not a deployable learner.

## Scenarios

- `sparse_bursty`: three bursty emitters across sixteen bands.
- `mixed_threat`: continuous, periodic, frequent, and rare activity.
- `periodic_radar`: three periodic emitters with different timing.
- `contested_spectrum`: beam, hopping, periodic, and Markov activity.

Scenario aliases such as `sparse`, `mixed`, `radar`, and `contested` are also
accepted by the command-line tools.

## Metrics

E-WAVE reports:

- probability of detection and false alarm;
- detector sensitivity;
- interception ratio and intercept rate;
- time to first intercept and intercept fraction;
- learner reward and truth-based evaluation utility;
- prediction accuracy, coverage, and override telemetry;
- intercept time error;
- runtime;
- multi-seed means and confidence intervals.

## Installation

Python 3.9 or newer and Node.js are required.

```bash
git clone https://github.com/joshiakshit/electronic-warfare.git
cd electronic-warfare
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cd frontend
npm install
cd ..
```

## Run one simulation

Use a scenario name:

```bash
python -m ewscan.experiments \
  --config contested_spectrum \
  --scheduler sniper \
  --seed 42
```

Use a YAML configuration:

```bash
python -m ewscan.experiments \
  --config configs/mvp.yaml \
  --scheduler ucb1
```

## Run the dashboard

Start the local API:

```bash
uvicorn ewscan.api.server:app --reload
```

Start the frontend in another terminal:

```bash
cd frontend
npm run dev
```

Open the local URL printed by Vite. The API allows the local frontend origin by
default.

## Run a benchmark

The following command runs paired seeds and writes episode-level and aggregate
CSV files:

```bash
python -m ewscan.experiments.sweep \
  --config contested_spectrum \
  --schedulers round_robin,ucb1,thompson_sampling,belief,sniper,oracle \
  --num-seeds 30 \
  --output benchmark_runs.csv \
  --aggregate-output benchmark_summary.csv
```

Use aggregate results and confidence intervals for algorithm comparisons. Do
not select a single favorable seed.

## Tests

Run the Python suite:

```bash
pytest tests/
```

Run frontend checks:

```bash
cd frontend
npm run typecheck
npm run lint
npm test
npm run build
```

## Project structure

```text
ewscan/
  agents/        Scheduler implementations and learning models
  api/           Local FastAPI service
  env/           RF environment, emitters, detection, and recording
  experiments/   Episode runner, scenarios, registry, and sweeps
  metrics/       Detection, interception, reward, prediction, and timing
  testing/       Shared test fixtures
  config.py      YAML loading
  contracts.py   Shared immutable contracts and interfaces
  detector.py    Detector capability and calibration
  rng.py         Independent seeded random streams
frontend/        React and Vite dashboard
configs/         Example YAML scenarios
tests/           Python test suite
```

## Current limits

- The project uses simulated signals and detector outputs, not raw IQ samples.
- It does not classify emitter identity or infer threat type.
- Threat priority is either simulation metadata for evaluation or an explicit
  external prior.
- Whittle remains research-only.
- Live replay and receiver adapters are not implemented.
- Results depend on the declared scenario, detector model, scheduler settings,
  and seed range.
- No scheduler is expected to dominate every scenario and metric.

## Safety boundary

E-WAVE is a passive receive-scheduling simulation. Live transmit effects,
interference, spoofing, active probing, payload interception, and third-party
identifier collection are outside the project scope.
