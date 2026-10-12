# Java core: first migration milestone

Implemented 12 October 2026, then verified against the Python reference before
Java-only cleanup. Checkpoint `fb62f3e` preserves the pre-cleanup Python application,
dashboard, other algorithms, fixture generator and Java port. Legacy application
files and the local Python environment have now been removed. Firmware remains
unchanged. The checkpoint is local; nothing has been pushed.

## Build and use

The target is Java 21 and Maven. Plugin and JUnit versions are fixed in `pom.xml`.
There are no runtime dependencies; JUnit is test-only. This host currently provides
JBR 25.0.3 and Maven 3.9.16. The build uses `--release 21` (class major version 65).
Execution on a Java 21 runtime and Raspberry Pi still needs verification.

With a JDK and Maven on PATH:

```sh
mvn clean verify
java -jar target/adaptive-scanner-0.1.0-SNAPSHOT.jar --help
java -jar target/adaptive-scanner-0.1.0-SNAPSHOT.jar replay 3 128 71 observations.csv
```

On the current development host:

```sh
export JAVA_HOME=/opt/android-studio/jbr
export PATH="$JAVA_HOME/bin:/opt/idea-IU-262.10968.63/plugins/maven-plugin/lib/maven3/bin:$PATH"
mvn clean verify
```

Recorded input has four fields and an optional exact header:

```csv
tick,band,detection,valid
0,0,1,1
2,1,0,0
3,2,0,1
```

Ticks are discrete elapsed-time units chosen by the enclosing application. They
must map to a consistent cadence; sequence numbers do not establish elapsed time.
Band indices start at zero. Bits must be `0` or `1`. Unavailable feedback (`valid=0`)
advances feedback chronology without updating counts or treating it as a miss.
Feedback may share a tick across distinct bands, but duplicate feedback on a band
or globally stale ticks are rejected. Choose the next band after all feedback for
that tick in an embedding application.

The CLI inspects a decision after each input row and streams
`next_tick,selected_band,score,period` to stdout. It consumes the recorded band,
regardless of which band the model would have chosen. Replay therefore demonstrates
model updates and deterministic decisions, not counterfactual intercept performance.
It retains no session-sized event list. Input lines are limited to 256 characters.
Errors go to stderr; exit statuses are 0 for success/help, 1 for I/O failure, and
2 for invalid arguments/input. On failure, stdout can contain the completed prefix.

## Embed without the CLI

```java
import ewave.AdaptiveScanner;

var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(16, 2000, 42));
var first = scanner.choose(0, 1);
int band = first.bands()[0];
// Execute a receiver request here, then supply the actual outcome:
scanner.observe(band, 0, true, true);
var next = scanner.choose(1, 1);
double score = next.snapshot().scores()[next.bands()[0]];
scanner.reset();
```

One model belongs to one thread/session. The library accepts no emitter truth,
identities, hidden SNR, or transition parameters. Snapshots and decisions copy
arrays on construction and access. `snapshot(tick)` supports phase inspection at
any nonnegative tick; `choose` requires a tick after the latest feedback.

Uniform selection scores omit the Python scheduler's common 0.1 scale; this leaves
its ranking unchanged. To reproduce an explicit receiver-visible priority map,
use `choose(tick, k, weights)`. Weights are floored at 0.1 as in the reference,
and the decision snapshot exposes the actual weighted selection scores. Optimistic
scores may exceed one and must not be labelled calibrated probabilities.

Top-K selection is retained for parity/embedding, but does not assert receiver
concurrency support. Near ties use the reference tolerance
`abs(score-max) <= 1e-12 + 1e-12*abs(max)`, with uniform Java seeded random choice.
Java and NumPy seeds do not share a random stream. Reset restarts all statistics
and tie-breaking state.

## Frozen numerical evidence

`src/test/resources/reference/manifest.json` records Python revision
`396df5a4862ddfd259077a5f749bca58bfeb420a`, source SHA-256 hashes, Python 3.14.8,
NumPy 2.5.3, fixture hashes, and expected final periods/groups. Generation occurred
before Java implementation. Fixtures are consumed directly by Java tests; Python
is not invoked during Maven builds. The Python generator is retained in the
pre-cleanup checkpoint rather than shipped with the Java library.

To recover the historical application without changing the Java working tree:

```sh
git worktree add --detach ../ewave-python-reference fb62f3e
```

That separate checkout includes `tools/freeze_reference.py` and `pyproject.toml`.
Create its own Python environment and install the project plus the recorded NumPy
version before explicitly regenerating fixtures there. Do not copy regenerated
expectations over the Java fixtures without reviewing the numerical changes.
The generator will record the checkout revision (`fb62f3e`) rather than the original
reference revision; the numerical source hashes are preserved in the checkpoint.

Six fixtures contain 7,021 observations, 1,890 checkpoints, and 4,212 per-band
numerical comparisons. They cover sparse period-20 recovery, aperiodic fallback,
CW detector misses, quiet/unobserved bands, sticky bursts, history eviction,
period-255 recovery, and coupled period-255 inference. Checks span training and
280 final forecast ticks. Fixture hashes are checked by Java tests.

Absolute tolerance is `1e-9` for means, spreads, exploration scores and
Beta-Binomial likelihoods. Periods and coupled members must match exactly; decisions
must match when the highest scores are outside the documented tie tolerance.
This is fixed-history parity, not proof of equivalence for every possible input or
NumPy random stream. It does not validate performance on live Wi-Fi.

Verification on this host:

- `mvn clean verify`: 13 Java tests, no failures (parity, validation, invalid feedback,
  reset, defensive copies, top-K ties, explicit priorities, bounded histories and CLI).
- Python selected core/boundary tests: 92 passed.
- Python regular suite: 811 passed, 16 slow tests deselected.
- Python `tests/agents/test_sparse_gate.py`: all 12 quality gates passed in 121.33 s.
  Other slow tests and frontend build were not run.
- JAR help and direct embedding smoke tests verified locally.

## Numerical choices

`AdaptiveScanner` is the public API; `PhaseModel` owns occupancy, recency,
uncertainty and coupling; `PeriodFit` owns bounded history and fitting. `Main` only
parses and streams replay. The unused belief telemetry, dense estimator, predictor,
Whittle and Sniper paths are not copied.

The Beta(1,10) likelihood uses integer log-factorials instead of a general gamma
library. The gate margins remain 3.5 for fit acceptance, 0.5 for candidate separation,
and 10 for coupled acceptance. Retained history is a per-band fixed ring; marginal
counts and phase histograms preserve the reference's lifetime/update semantics.

Autocorrelation uses the exact sparse direct formula for the reference's centered
binary series, with missing ticks set to zero. Its working memory depends on
retained observations and configured period bounds, not the elapsed-time span.
For lag `l`, span `N`, hit density `m`, and binary series `x`, it computes
`sum(x[t]*x[t+l]) - m*(left_hits+right_hits) + (N-l)*m*m`.

A manual comparison with JTransforms 3.1, after 100 warmups and over 500 repetitions:

| Final band-0 history | Observations | Direct proposal | FFT proposal |
|---|---:|---:|---:|
| Long-period fixture | 2,034 | 2.9874 ms | 0.2772 ms |
| Coupled fixture | 2,251 | 2.8242 ms | 0.2231 ms |

Candidate sets matched on both histories. Direct correlation stays for this milestone
because it preserves the zero-dependency core and bounded span-independent memory.
FFT is faster in this measurement. Revisit this choice against the measured receiver
cadence and Pi workload; these numbers are not full decision latency or a Java/Python
speedup claim. Exactly equal correlation peaks use descending lag order in Java;
NumPy FFT roundoff can reorder such peaks. Fixture parity passed despite this possible
edge difference. Do not claim bitwise or universal candidate parity.

The optional `tools/AutocorrelationComparison.java` reproduces this comparison. It
requires JTransforms 3.1, JLargeArrays 1.5 and commons-math3 3.5 on its manual
classpath; none are Maven project dependencies or shipped in the JAR.

## Next milestone

Add `Receiver` and `ScanSession` for capabilities, request/result correspondence,
one in-flight request, failure statuses, recording and stop/restart handling.
The current CLI is recorded-input inspection and does not control hardware.
Agree fixed tick mapping, scan duration/mode, and nominal detector assumptions
before adding the ESP32-C3 adapter. Pi memory/latency and live observations remain
open gates. The original simulation/evaluation workflows are available in the
checkpoint; Java replacements for those workflows are not part of this cleanup.
