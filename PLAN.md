# E-WAVE status and plan

Updated 2026-09-02. SIH26055.

## Current status

The core simulation, all release schedulers, metrics, API, and dashboard are
implemented and verified. The Python test suite passes (819 tests). The frontend
type check, lint, unit tests, production build, and npm audit pass.

| Area | State |
|---|---|
| Environment, detector, contracts | implemented and verified |
| Baselines and bandits | implemented and released |
| Belief scheduler | implemented and released, wins on all four scenarios |
| Sniper scheduler | implemented and released, wins on periodic scenarios |
| Whittle scheduler | research-only, excluded from release registry |
| Metrics and evaluation | implemented with edge-case coverage |
| API and dashboard | implemented, localhost-bound, hardened for local demo |
| Python wheel | builds and passes clean-install smoke tests |
| Live data and replay | planned, not implemented |

## Benchmark summary

30 paired seeds, blind track, k=1 over 16 bands. `WIN` means the 95% CI of the
paired difference is entirely above zero.

### Belief wins

| Scenario | Belief interception | vs Thompson (paired 95% CI) |
|---|---:|---|
| mixed_threat | 0.5283 | WIN +0.0036 [+0.0029, +0.0042] |
| periodic_radar | 0.4689 | WIN +0.2108 [+0.1868, +0.2347] |
| sparse_bursty | 0.3523 | WIN +0.0730 [+0.0569, +0.0891] |
| contested_spectrum | 0.2132 | WIN +0.0845 [+0.0709, +0.0982] |

### Sniper wins (periodic scenarios)

| Scenario | Sniper interception | vs Thompson (paired 95% CI) |
|---|---:|---|
| periodic_radar | 0.3103 | WIN +0.0522 [+0.0420, +0.0623] |

On non-periodic scenarios (sparse_bursty, mixed_threat), Sniper reproduces its
inner bandit exactly. That is the intended fallback.

### Held-out confirmation (seeds 200..229)

Every win reproduced on seeds never used during development.

### Runtime

Belief worst: 3.87x UCB1. Sniper worst: 2.57x UCB1. Both under the 5x ceiling.

## Key design decisions

### Phase-conditioned occupancy (the core mechanism)

A Markov belief propagated across a revisit gap decays toward the stationary
prior. At k=1 over 16 bands the gap is 11-16 slots, so the belief carries
nothing at selection time. Phase-conditioned occupancy indexes `P(ON) | slot %
period` instead of by elapsed time. The estimate is equally sharp after a
100-slot gap as after one slot. This defeats the sparse-observation ceiling
where periodic structure exists.

A wrong period spreads hits evenly across phase buckets, collapsing onto the
band marginal rate. Wrong answers are inert, not harmful. This removes the
false-positive/latency trade-off that blocked earlier approaches.

### Gap-1 Markov recency (sparse_bursty fix)

At gap=1 a Markov belief has not decayed at all. "Stay while ON, leave when it
drops" matters for emitters with mean ON runs of 4-6 slots. Requires a sticky
prior on transition counts (p01=p10=0.1) and detector-model likelihood updates
to avoid regressing on always-on carriers.

### Sniper defaults

- Inner scheduler changed from UCB1 to Thompson. UCB1 keeps returning to bands
  with zero hits indefinitely at k=1 over 16 bands.
- Confidence threshold changed from 0.6 to 0.5. The old value was unreachable
  from a Beta(1,1) prior when outcomes were only scored on already-due slots.
  The override decision now uses measured phase occupancy, not the outcome
  window bootstrap.

### Whittle rejection

Whittle uses an exact forward-backward bridge for expected one-step transition
counts. The 20-seed mixed-threat mean was 0.4530 versus UCB1 0.4726 and Thompson
0.5265. It failed its quality gate and is excluded from release registries. It
solves a simpler reward model than the full evaluation utility.

## Known limits and ceilings

### mixed_threat intercept fraction

The clairvoyant k=1 optimum equals camping on the always-on CW band. Any
setting that lifts intercept fraction above Thompson's 0.567 also loses the
interception gate. The two metrics are in quantitative conflict on this scenario.
Measured across a grid of parameters: no operating point satisfies both.

### contested_spectrum frequency hopper

The LFSR hopper has period 255. The phase model caps at max_period=200, so the
hopper is never modelled directly. Raising the cap buys only +0.005 for +0.2x
runtime because a 255-bucket histogram gets ~2 observations per bucket. The real
requirement is a cross-band coupled model that treats hop bands as one emitter
with a shared phase.

### Sparse-observation ceiling on pure Markov spectra

Phase-conditioned occupancy defeats the ceiling only where periodic structure
exists. On a purely Markov spectrum the ceiling stands. The best a blind k=1
scheduler can do is find the highest-occupancy band.

## Information boundaries

- Blind schedulers receive dimensions, detector capability, and past
  observations. No emitter locations, SNR, types, or transition parameters.
- Prior-aided schedulers also receive an explicit ThreatPrior. Results from the
  two tracks stay separate.
- Oracle is the only scheduler that receives truth.
- Settling slots are unavailable sensor data, not quiet observations. No
  detector draw, no learner update, no metric contribution.
- Learner reward uses observations. Evaluation utility uses hidden truth. The
  two are separate quantities.

## Future work

### Live data via wideband replay (next major step)

Capture the full monitored span with a wideband receiver. Channelize into N
bands. The wideband capture is the truth matrix. Replay to a scheduler limited
to K bands per slot. The scheduler, metrics, and runner do not change. This
produces real signals with an exact truth matrix and needs no real-time pacing
or transmit hardware.

Three truth sources, best first:
1. Wideband-oracle record-and-replay (build first).
2. Controlled testbed with known emitters (validation).
3. Weak proxy labels for genuinely uncontrolled air (last resort).

### Cross-band coupled model

Treat hop bands as one emitter with a shared phase. This is the lever for the
contested_spectrum frequency hopper and the general hopper case.

### Whittle revisit

The research implementation is available. A new attempt needs to either align
the solver reward with the full evaluation objective or prove the approximation
is bounded. Must win a multi-seed benchmark before release.

## Offensive / Electronic Attack roadmap

The current system is passive: it listens, learns, and decides where to look.
It never transmits. The offensive track adds transmit actions that use the
passive scheduler's learned model to place energy where it matters.

This is a standalone project now, no longer SIH-bound.

### What the passive side already provides for attack

The scheduler already produces the inputs an attacker needs:

- **Which bands are active right now.** The belief model tracks per-band ON
  probability in real time.
- **When periodic emitters will transmit next.** The Sniper predictor estimates
  period, phase, and active windows.
- **Which emitters matter most.** The threat prior and evaluation utility rank
  targets.
- **Where the gaps are.** Unoccupied bands and OFF phases are known, useful for
  own-force transmission windows.

An attack scheduler selects transmit actions the same way the scan scheduler
selects receive actions: pick K_tx bands and a waveform, observe the effect,
update.

### Offensive features buildable on this codebase

Listed from simplest to hardest. Each builds on the one before it.

**1. Reactive spot jamming (simulated first)**

Detect an emitter, allocate transmit power to its band during predicted ON
windows. The scheduler already knows which bands are active. Add a transmit
action to the episode loop. Measure jamming effectiveness as the fraction of
target ON-slots covered by transmit energy.

Simulation-only addition: a `JamAction` alongside `ScanAction`, a jammer power
budget, and a target-side detection model that computes J/S (jam-to-signal
ratio).

**2. Frequency-follower jammer**

Track a hopping emitter across bands and jam each hop. The cross-band coupled
model (future work above) feeds directly into this. The follower needs to
predict the next hop band before the emitter moves. Latency budget: one slot.

**3. Barrage jamming with power allocation**

Spread transmit power across multiple bands. The scheduler decides how to split
a fixed power budget. Wider coverage means lower J/S per band. The bandit
framework applies directly: each allocation is an arm, the reward is aggregate
disruption.

**4. DRFM (Digital RF Memory) replay**

Capture a signal, store it, retransmit a modified copy. Used for deceptive
jamming: false range returns against radar, false targets. Requires capturing
the actual waveform, not just detecting presence. This is where the
record-and-replay infrastructure from the live data plan becomes a transmit
tool.

**5. Coordinated ES/EA scheduling**

The receiver cannot listen on a band it is jamming (self-interference). The
scheduler must split K channels between receive and transmit, or alternate. This
is a resource-allocation problem on top of the existing bandit model: scanning
gives information, jamming gives effect, and the budget is shared.

**6. Closed-loop effectiveness estimation**

After jamming, did the target change behavior? Did it move bands, reduce power,
or go silent? The passive side observes the result. If the target adapted, the
attack plan must adapt. This closes the OODA loop in simulation.

### Hardware integration

The current project uses simulated IQ and energy detection. Going to hardware
needs these layers:

**Receive side (passive, build first)**

| Component | Role | Examples |
|---|---|---|
| Wideband SDR receiver | captures spectrum | RTL-SDR (cheap/narrow), HackRF (8 MHz), USRP B210 (56 MHz), Ettus X310 (160 MHz) |
| Channelizer | splits wideband capture into N bands | GNURadio polyphase filterbank, or offline FFT channelization |
| Adapter | converts SDR output to `Observation` contract | new module: `ewscan/hw/sdr_adapter.py` |
| Wideband recorder | stores full captures for replay | file sink to SigMF or raw IQ |

This is the live-data-via-replay plan. The scheduler code does not change. Only
the data source changes from simulated to real.

**Transmit side (active, build second)**

| Component | Role | Examples |
|---|---|---|
| TX-capable SDR | generates jamming waveforms | HackRF One (half-duplex), USRP B210 (full-duplex), LimeSDR |
| Power amplifier | extends effective range | band-specific PA, matched to target frequency |
| TX/RX isolation | prevents self-jamming | separate antennas with spatial isolation, or full-duplex SDR with self-interference cancellation |
| Waveform generator | creates jamming signals | noise, tone, swept, DRFM replay via GNURadio flowgraph |
| TX adapter | converts `JamAction` to SDR transmit commands | new module: `ewscan/hw/tx_adapter.py` |

**Minimum hardware for a working prototype**

- Two HackRF One boards: one RX, one TX. About $600 total.
- Two directional antennas for the target band.
- A shielded enclosure or RF cable with attenuators for legal testing without
  over-the-air transmission.
- A laptop running GNURadio and the E-WAVE scheduler.

**Better setup for real range testing**

- USRP B210 (full-duplex, 56 MHz bandwidth, ~$1500).
- External PA for the target band.
- Licensed or authorized test range.

### Implementation path

**Phase 1: Simulated EA (no hardware)**

Add transmit actions to the simulation loop. The environment models jamming
effect on the target side. Measure J/S, target disruption, and power efficiency.
All existing metrics and benchmarking infrastructure applies. This validates the
attack scheduling algorithms before any hardware.

**Phase 2: Receive hardware (passive only)**

Connect an SDR receiver. Implement the wideband replay path. Validate that the
scheduler works on real signals with the same metrics (truth from the wideband
capture). No transmit yet.

**Phase 3: Transmit hardware (controlled environment)**

Add a TX SDR. Test in a shielded enclosure or cable-connected setup. The target
is a second SDR or signal generator you control. Measure jamming effect with
known target parameters. Compare against simulation predictions.

**Phase 4: Closed-loop field testing**

Full ES/EA loop on a licensed test range. The receiver observes, the scheduler
decides, the transmitter acts, the receiver observes the effect. This is the
complete system.

### Offensive AI/ML techniques

The passive side already uses bandits, Bayesian state tracking, and periodic
prediction. The offensive side extends these and adds new ML problems.

**1. RL for jamming resource allocation**

The scan scheduler is a restless multi-armed bandit. The attack scheduler is
the same problem with a different action space: instead of "which bands to
observe," it is "which bands to jam, with how much power." The existing bandit
framework (UCB, Thompson, belief) applies directly. The reward signal changes
from "did I detect activity" to "did my jamming degrade the target."

A joint ES/EA scheduler is a constrained multi-objective bandit: K channels
split between receive (information) and transmit (effect), with a shared budget.
This is a natural RL problem. Model-free approaches (PPO, SAC) can learn the
split from simulation episodes. Model-based approaches can use the learned
belief state as the RL observation.

**2. Adversarial co-evolution (jammer vs target)**

Train two agents against each other. The jammer learns to disrupt. The target
learns to evade (hop faster, change bands, reduce power, go silent). Each
forces the other to improve. This is a two-player zero-sum game.

The simulation already supports frequency hoppers, beam scanners, and Markov
emitters. Making the emitter policy learnable (instead of fixed) creates the
adversarial training loop. The emitter becomes an RL agent that chooses its own
frequency plan to minimize disruption. The jammer agent maximizes it.

This produces robust jamming policies that work against adaptive targets, not
just fixed patterns.

**3. Signal classification for targeted attack**

Before jamming, identify what the signal is. Different targets need different
waveforms: noise against communications, false returns against radar, matched
jamming against spread-spectrum. The passive scheduler collects observations
that feed a classifier.

ML approaches: CNN or transformer on short IQ segments for modulation
recognition (AMC). The classifier output selects the jamming waveform. Training
data comes from simulation or from public signal datasets (RML2016, DeepSig).

This turns blind barrage jamming into targeted smart jamming.

**4. GAN-based deceptive waveform generation**

A DRFM replays a captured signal with modifications. A GAN can learn to
generate realistic false signals without capturing the original first. Train the
generator on captured waveforms of each signal type. The discriminator is the
target's own receiver model (from the simulation).

Application: generate false radar returns at chosen ranges and velocities, or
false communication bursts that waste the target's processing.

**5. Online learning for adaptive power control**

The jammer has a finite power budget. Spending too much on one target leaves
others unjammed. Spending too little has no effect. The optimal allocation
depends on the target's signal strength, modulation, and adaptive behavior.

This is a contextual bandit: the context is the target's observed parameters,
the action is the power level, the reward is the measured disruption. Thompson
sampling with a linear model (LinTS) or a small neural network (NeuralTS) can
learn the mapping online.

**6. Predictive jamming via time-series models**

The Sniper predictor estimates when a periodic emitter will transmit. The same
prediction enables preemptive jamming: start transmitting just before the target
does. For non-periodic targets, a sequence model (LSTM, transformer) trained on
observation history can predict the next active band and timing.

The prediction does not need to be perfect. Even 60-70% accuracy means 60-70%
of jamming energy lands on target instead of on empty spectrum.

**7. Multi-agent cooperative EW**

Multiple distributed receivers and jammers. Each has a local view. They share
observations and coordinate actions. This is a multi-agent RL problem.

The simulation supports this by running multiple scheduler instances against the
same environment, with each instance seeing only its own K bands. Communication
constraints (latency, bandwidth, interception risk) become part of the action
space.

**ML implementation order**

| Phase | Technique | Prerequisite |
|---|---|---|
| Simulated EA | RL jamming allocation (bandits first, then PPO) | JamAction in the episode loop |
| Simulated EA | Adversarial co-evolution | Learnable emitter policies |
| Simulated EA | Predictive jamming | Sniper predictor (already built) |
| RX hardware | Signal classification (AMC) | SDR adapter, training data |
| TX hardware | Adaptive power control | TX adapter, J/S measurement |
| TX hardware | GAN waveform generation | Captured signal dataset |
| Field | Multi-agent cooperative EW | Multiple SDR nodes |

The first three need no hardware. They run in the existing simulation with the
existing benchmark infrastructure.

### Legal boundary

Transmitting jamming signals over the air is illegal in most jurisdictions
without explicit authorization (military, licensed test range, or shielded
enclosure). All development and testing through Phase 3 uses either simulation
or cable/shielded setups. Phase 4 requires a licensed range or authorized
exercise.

## Scenarios

- `sparse_bursty`: three bursty Gilbert-Elliott emitters, 16 bands.
- `mixed_threat`: continuous, periodic, frequent, and rare activity.
- `periodic_radar`: three periodic emitters with different timing.
- `contested_spectrum`: beam, hopping, periodic, and Markov activity.
