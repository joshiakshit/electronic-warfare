# Minimal Java E-WAVE implementation plan

Implementation started 12 October 2026 after the user authorized the first migration
milestone. The Java numerical core and thin recorded-input CLI are implemented
alongside the reference; fixture parity passes. Python, the dashboard and other
algorithms remain intact under the current instruction. No firmware work or removal
is included in this milestone. Evidence and usage: [JAVA_MIGRATION.md](JAVA_MIGRATION.md).
The design below remains the target for later milestones.

## Agreed direction

- Java is the main language; the user has approximately five years of Java experience.
- E-WAVE becomes a reusable adaptive scanning component of a larger application.
- Minimise product scope, dependencies, duplicated state and operational overhead.
- A CLI is sufficient; retire the existing dashboard in the planned restructure.
- Retain one adaptive algorithm, selected from the current project.
- Partner has a Raspberry Pi 4 and is ordering an ESP32-C3 / Super Mini board.
- Approximately eight weeks remain until submission; exact date is unconfirmed.

Minimum code means small responsibilities and few features, not minified code or
omitting validation. A faithful port of the selected algorithm is inherently more
substantial than a toy bandit. Do not promise an arbitrary line-count target.

## Proposed end state

A small Java library with an optional CLI. The library accepts receiver-visible
configuration and past observations, chooses the next band, and exposes the score
that caused the decision. A session runner executes requests through a receiver
interface and streams a compact recording. An enclosing application can call the
library directly; no HTTP service is required.

First live target: one ESP32-C3, one channel request at a time, 2.4 GHz Wi-Fi
discovery observations. This is not general RF energy sensing, payload interception
or universal device discovery. Bluetooth LE discovery is a separate later adapter
mode, not part of the initial scheduling claim.

## Repository findings that determine the port

1. `BeliefScheduler.act()` ranks `PhaseOccupancy.upper_bound()` values. The separate
   `BeliefTracker` and its `TransitionEstimator` feed telemetry, not band selection.
   Port the decision mechanism; do not copy that parallel telemetry state.
2. `PhaseOccupancy` implements marginal detection statistics, phase histograms,
   adjacent-observation recency, detector-model correction, Wilson uncertainty,
   survey optimism, long-period recovery and coupled-band phase inference.
3. The fit uses hit-gap candidates and Beta-Binomial likelihood gates, then
   autocorrelation candidates. Cross-band inference is already implemented despite
   the older roadmap calling it future work.
4. `phase.py`, `period.py`, `history.py` and `pomdp.py` total 1,239 Python lines,
   including documentation and unrelated predictor support. Extract only the
   dependencies reachable from the selected decision path.
5. The current runner is tightly coupled to simulated truth and batch metrics.
   It is a validation reference, not an appropriate live-session implementation.
6. The API runs three complete simulations per request. This and the React
   application are unnecessary for the proposed library/CLI scope.
7. Existing information-boundary and invalid-observation tests are valuable.
   Retire unrelated product features only after equivalent core checks exist.
8. Neither real receiver execution nor Java parity has been verified yet.

The current `belief` implementation is the candidate to retain; its comparative
results support that choice in the tested simulated scenarios, not universal
optimality or live Wi-Fi superiority. Verification results are recorded in ROADMAP.md.

## Target structure: six main source files, one later adapter

Proposed layout, subject to review:

```
pom.xml
src/main/java/ewave/
  AdaptiveScanner.java    Public model API and compact configuration/decision records
  PhaseModel.java         Internal occupancy, recency, uncertainty and coupling
  PeriodFit.java          Internal bounded history and period fitting
  Receiver.java           Capabilities, requests, results and receiver interface
  ScanSession.java        Execute, validate, observe and stream session events
  Main.java               CLI argument handling and recorded/test-input mode
  SerialReceiver.java    Added when the C3 request/result contract is verified
src/test/java/ewave/      Core parity, session and contract tests
src/test/resources/      Small fixed reference fixtures
README.md
IMPLEMENTATION_PLAN.md
ROADMAP.md
LICENSE
```

Use nested records where they belong to one public API; avoid a separate file for
every three-field data carrier. Keep the numerical engine readable. Do not merge
the CLI, numerical model and hardware transport into one large class.

Build target: Java 21 and Maven, producing one normal library JAR with a CLI
entry point. Implementation inspection found JBR 25.0.3 and Maven 3.9.16 in local
IDE installations; the earlier Java 21 identification was not confirmed. The build
pins plugin versions and compiles with `--release 21`. Java 21 runtime and Pi
verification remain open. See JAVA_MIGRATION.md for the exact local build commands.

Core/CLI runtime dependency target: zero. JUnit is a test-only dependency. Add one
serial dependency only if needed for portable, reliable port access; isolate it in
the transport adapter. Do not hand-write an unsafe serial driver to save one
dependency. No Spring, REST server, database, DI framework, scheduler plugins or
microservice network in v1.

## Public behaviour and invariants

The core API offers configuration, selection, valid observation updates and reset.
It receives no emitter identities, simulated truth, hidden SNR or transition
parameters. One model instance belongs to one session and one execution thread.

- Validate channel indices, chronological timestamps/ticks, detector assumptions,
  history capacity and request/result correspondence.
- Missing, failed, settling or timed-out measurements are not negative detections.
- Return defensive copies of mutable arrays in records and snapshots.
- Seed tie-breaking explicitly; Java randomness is not NumPy stream parity.
- Expose actual selection scores, selected channel and fitted period where present.
  Do not label an optimism score as a calibrated probability.
- Keep retained history and session buffering bounded. Stream recording to disk.
- Make a restart/new session reset all per-session state.

Start receiver execution with K=1 because the C3 has a shared radio. Keep top-K
selection support only if the extracted model already requires it for parity;
validate any future adapter's concurrency before permitting parallel requests.

Initial port preserves the existing selection objective. A maximum-revisit rule
changes decisions: if introduced for the live discovery experiment, make it an
explicit session constraint, record forced revisits, and evaluate its tradeoff.
Do not silently combine a new objective with the parity port.

## Numerical port strategy

Preserve the selected decision path in the first port:

1. Fixed-capacity history and marginal counts.
2. Candidate generation and period likelihood gates.
3. Exact phase buckets with unobserved-bucket smoothing fallback.
4. Sticky adjacent-state recency and detector-likelihood correction.
5. Wilson exploration and existing survey bonus.
6. Long-period autocorrelation proposals and coupled-band inference.
7. Top-band selection with documented tie rules.

The unused dense period estimator, predictor confidence windows, Sniper arbitration,
Whittle solver and standalone Bayesian telemetry filter are not dependencies to port.

Beta-Binomial scoring currently uses integer counts and integer prior parameters.
Evaluate a tested log-factorial formulation using the JDK before adding a general
special-functions library. Validate numerical scores near period-selection gates.

The current autocorrelation uses NumPy FFT. Compare a bounded direct correlation
implementation against a small FFT library on the retained horizon before choosing
the Java implementation. Mathematical equivalence does not ensure equal runtime or
identical peak ordering. Preserve coupling/long-period recovery unless evidence
supports an explicit, separately reviewed reduction in scope.

Do not claim Java is faster until decision latency and memory are measured on the
target workload. Avoid speculative native DSP modules in this port.

## Migration and deletion order

1. Pin the current Git revision and document the reference environment.
2. Run current selected-algorithm quality gates; record failures as well as passes.
3. Generate small fixed observation fixtures and expected intermediate/model scores.
4. Implement and test the Java core alongside the reference temporarily.
5. Implement the CLI and receiver-neutral session loop.
6. Verify packaging and embedding without invoking the CLI.
7. Only after parity passes, remove the Python application, React frontend, old API,
   other scheduler implementations and unused metric/configuration modules from
   the shipped tree. The reference remains recoverable in Git history.
8. Rewrite README and the plan around the resulting component, not the SIH showcase.

Do not keep a permanent second runtime or copy the old project into a large archive
directory. Preserve the user's existing `.gitignore` changes and any new work made
before implementation starts. No commit, push or partner message is implied.

Keep round-robin as a tiny test/benchmark reference, not a second production policy
or an algorithm catalogue. Keep essential regression fixtures rather than porting
the entire historical test suite verbatim.

## CLI scope

Provide help, one observation-input mode, a finite session, streaming results and
clear exit statuses. Hardware connection is an additional source once available.

A recorded-input mode updates the model and inspects decisions using actual recorded
observations. It cannot claim counterfactual intercept performance for channels that
were never observed. A labelled all-band test fixture may support comparison, but
its truth must stay outside the scheduler and be clearly identified as test data.

CLI diagnostics go to standard error; machine-readable events go to standard output.
Prefer one simple recording format and bounded parsing. Avoid menus, accounts,
coloured mission dashboards, many subcommands and an extensible plugin system.

## C3 integration contract to agree with the partner

Firmware: C++ using the partner's established Espressif toolchain. Arduino-ESP32
is sufficient to explore selected-channel Wi-Fi scanning; ESP-IDF is appropriate
if already in use. The Java scheduler stays on the Pi/laptop.

Use USB serial so management traffic does not compete with the Wi-Fi scan radio.
Confirm the actual Super Mini USB implementation and board settings rather than
assuming all boards expose the same serial port.

Protocol operations: capability/handshake, scan request, scan result, explicit error.
Each scan result echoes a request identifier and executed channel, with start/end
timing, status and supported discovered-network fields. Bound message length and
result count, reject malformed data, and allow at most one in-flight request.

Agree the scan mode and duration. Active and passive Wi-Fi scans are different
experiments; record the mode and do not mix them in comparisons.

Time needs particular care. The phase model's periods are discrete time units;
request sequence numbers are not elapsed time. Specify a fixed observation cadence
and timestamp-to-tick mapping before hardware validation. Test irregular durations,
missed intervals, delayed replies and device reboot. If the scan spans an interval,
state that it observes discovery within that interval, not instantaneous RF truth.

Do not transfer the simulated nominal Pd/Pfa values as measured C3 calibration.
Treat any model parameters as documented assumptions until controlled measurements
justify them. Discovery of access points is not generic activity of all Wi-Fi clients.

## Meaningful verification and release gates

- Reference parity: fixed histories for periodic, bursty, CW, quiet and coupled
  long-period cases; compare estimates, periods and decision scores with a stated
  numeric tolerance. Equal seed numbers alone are not a parity test.
- Decision parity: identical non-tied scores produce the same selected bands;
  explicitly defined tie behaviour is deterministic and unbiased where required.
- Contract checks: invalid configuration, unknown channel, malformed input,
  duplicate/stale feedback, defensive copying and complete reset.
- Numerical checks: silence/zero hits, one detector miss on a persistent source,
  sparse phase recovery, wrong-period fallback and coupled recovery.
- Session checks: timeout, disconnect, malformed reply, device restart, stop and
  recording integrity. Replay is deterministic for its documented semantics.
- Performance: bounded history, no whole-session telemetry accumulation, warmed
  decision latency and retained memory on laptop and Pi. Thresholds are set from
  the measured receiver cadence, not invented now.
- Hardware gate: a chosen channel executes, returns real observations, and advances
  the next decision. A network list printed independently is insufficient.
- Comparison gate: same receiver, observation budget and controlled experiment;
  repeat runs, vary order and disclose RF/timing uncertainty. Report if round-robin wins.

Do not require a statistical improvement merely to declare the port correct; that
is a separate application-performance claim. Do not call the first release a
validated general-purpose production scanner.

## Decisions for external review

1. Does keeping the complete phase/coupling decision engine satisfy the intended
   scope, or should a reduced policy be evaluated as a separately named experiment?
2. Is Wi-Fi access-point discovery a useful initial live objective, given that
   persistent beacons may favour a predictable sweep?
3. Should the first release include a coverage constraint, or establish parity first?
4. Which bounded autocorrelation implementation meets the Pi cadence without
   creating an unnecessary dependency?
5. Are the proposed library/CLI surface and zero-core-dependency target practical?

Review must not presume payload decryption, broad RF coverage or hardware benchmarks
already exist. Review the plan against the current source, not only old README claims.
