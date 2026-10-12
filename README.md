# E-WAVE adaptive scanner

A small Java library that chooses which band to observe next using phase occupancy,
adjacent-observation recency, uncertainty, and coupled-band inference. It accepts
actual observations through a public API and includes a thin CLI for inspecting
recorded input. The core has zero runtime dependencies.

Requires Java 21 or newer and Maven. Maven plugin and JUnit versions are pinned in
[pom.xml](pom.xml); JUnit is used only for tests.

```sh
mvn clean verify
java -jar target/adaptive-scanner-0.1.0-SNAPSHOT.jar --help
java -jar target/adaptive-scanner-0.1.0-SNAPSHOT.jar replay 3 128 71 observations.csv
```

Input is CSV with an optional exact header. Band indices start at zero; detection
and validity are bits. An unavailable measurement is not counted as a miss.

```csv
tick,band,detection,valid
0,0,1,1
2,1,0,0
3,2,0,1
```

The CLI streams `next_tick,selected_band,score,period` to stdout. Diagnostics go to
stderr. Scores include optimism and can exceed one. Replay updates the model from
the recorded band; it cannot measure outcomes on bands that were never observed.

Embed the JAR directly without invoking the CLI:

```java
import ewave.AdaptiveScanner;

var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(16, 2000, 42));
var decision = scanner.choose(0, 1);
int band = decision.bands()[0];
// Execute a receiver request and provide its actual result:
scanner.observe(band, 0, true, true);
var next = scanner.choose(1, 1);
scanner.reset();
```

One scanner belongs to one thread and session. Ticks must represent a consistent
elapsed-time cadence defined by the caller. The library rejects stale/duplicate
feedback and returns defensive copies of snapshot arrays. Top-K selection is
available, but receiver concurrency must be validated separately.

The repository contains four production source files, Java tests, and six frozen
Python reference fixtures. The Python application, dashboard, HTTP API, simulation
workflows, and other algorithms were retired after fixed-history numerical parity
passed. They remain recoverable at Git checkpoint `fb62f3e`.

Verification: 13 Java tests pass, including 4,212 numerical checks against frozen
reference values with absolute tolerance `1e-9`, exact fitted periods/coupled groups,
and non-tied decision parity. Tests and fixtures remain tracked for reproducible
verification and are excluded from the library JAR. This establishes fixture parity, not live receiver
performance. The JAR targets Java 21 bytecode and has been exercised on Java 25;
Java 21 runtime and Raspberry Pi verification remain open.

Hardware control and receiver/session execution are not implemented yet.
[Java migration notes](JAVA_MIGRATION.md) explain the API, numerical choices,
verification, local toolchain, and recovery of the historical reference.

Licensed under the [MIT license](LICENSE).
