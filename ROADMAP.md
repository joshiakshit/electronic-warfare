# E-WAVE integration roadmap

Updated 12 October 2026. First migration milestone implemented alongside the existing
application; firmware remains unchanged.
The submission is approximately two months away; the exact date is unconfirmed.
Detailed migration design: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

## Locked direction

E-WAVE is a small reusable Java adaptive scanning component within a larger
observation and analysis application. Its initial user interface is a CLI.

Keep the best-supported existing adaptive policy: the decision engine currently
named `belief`, driven by phase occupancy, burst recency and coupled-band inference.
Remove the dashboard, HTTP application and algorithm catalogue in the future
restructure, after the Java port passes reference checks. Round-robin remains an
evaluation reference, not a second production policy.

The user authorized implementation of the first milestone after reviewing the plan.
Current instruction: retain the Python reference, dashboard and other algorithms.
Numerical parity passing does not authorize their removal in this task.

First-milestone evidence:

- Frozen reference revision `396df5a4862ddfd259077a5f749bca58bfeb420a` and source hashes.
- Six checked-in fixture files with 7,021 observations and 4,212 model checkpoints.
- Java scores, means, spreads and likelihoods match within absolute `1e-9`;
  fitted periods, coupled members and non-tied selections match exactly.
- Java: 13 tests pass; Python: 811 regular tests pass (16 deselected), plus
  all 12 selected slow quality gates pass. Other slow gates remain unverified.
- Embeddable library and finite streaming replay CLI build as one JAR with zero
  runtime dependencies, targeting Java 21 bytecode. Verified locally on Java 25;
  Java 21 runtime and Pi execution remain unverified.
- Receiver-neutral session execution and hardware integration are the next milestones.

Build instructions, numerical choices and limitations: [JAVA_MIGRATION.md](JAVA_MIGRATION.md).

## Evidence from the current project

- Python simulation, scheduler implementations, metrics, API and React dashboard exist.
- Earlier verification: 811 Python tests passed; 16 slow tests were excluded.
- Current planning verification: all 12 tests in `test_sparse_gate.py` passed in
  approximately two minutes, covering selected quality, runtime and coverage gates.
- Mixed-threat belief interception: 0.5283 versus Thompson 0.5248, 30 paired seeds.
- Sparse-bursty belief interception: 0.3523 versus Thompson 0.2792, 30 paired seeds.
- Current contested-spectrum belief interception: 0.3402 versus the stored earlier
  belief baseline 0.2132; paired gain 0.1270, 95% CI [0.1143, 0.1397]. This is a
  comparison with the earlier model, not a newly measured competing product.
- Belief runtime was 2.59x UCB1 on mixed threat and 3.76x on periodic radar in the
  selected Python gates. These are not Java performance measurements.
- Coverage in the contested scenario was 0.908 versus Thompson 0.925; the current
  gate permits a 0.02 margin. Maximum capture and discovery coverage remain distinct.
- This is evidence in simulated scenarios, not proof of superiority on real Wi-Fi.
- Frontend checks, all remaining slow tests and Java parity were not verified here.
- There is no implemented receiver-control, waveform-decoding or decryption path.

## Hardware and budget

Available: partner's Raspberry Pi 4.
Reported order: ESP32-C3 / Super Mini. Confirm the listing and quantity: Super Mini
may name the C3 board rather than a separate radio device. No board has been tested.

Proposed first hardware path:

```
Java core/session on laptop or Pi
    -> USB serial request
    -> C3 selected-channel Wi-Fi observation
    -> actual result and timing
    -> Java update, next decision and streamed recording
```

The C3 provides 2.4 GHz Wi-Fi and Bluetooth LE, not Bluetooth Classic, 5 GHz Wi-Fi
or broad-range SDR reception. LE support alone does not establish earphone-audio
capture. The Pi provides a host and USB interfaces; it is not a broad-range SDR.

Budget is approximately INR 5,000, with a preferred first purchase of INR
2,000–2,500 if needed. Reuse the ordered board and existing Pi first. A cheap
RTL-SDR cannot observe the proposed 2.4 GHz Wi-Fi/Bluetooth experiment. No purchases
or partner messages have been made on the user's behalf.

## Submission milestone

Connect a receiver, validate its capabilities, request a supported channel,
consume a real observation, update the model, continue, and export a session.
An enclosing application must be able to embed the Java library without launching
its CLI or an HTTP server.

Initial live scope is Wi-Fi access-point discovery. It does not enumerate every
physical device or recover arbitrary payloads. Use controlled access points for
reference events and label that source of evidence.

Proposed live objective: discovery responsiveness with a defined revisit limit.
The first numerical port preserves the current objective; any revisit override is
an explicit additional constraint evaluated separately. Do not combine changed
selection semantics with the port and then claim reference parity.

## Eight-week plan

| Week | Deliverable | Completion evidence |
|---|---|---|
| 1 | Review this plan; inventory Pi/C3; agree timing and receiver contract; freeze Python reference fixtures | Known capabilities, selected-channel observation prototype and a reviewed minimal scope |
| 2 | Implement Java phase model and period fit | Fixed observation fixtures reproduce reference model scores and fitted periods |
| 3 | Complete library API, CLI and receiver-neutral session loop | Embeddable JAR, finite runs, streamed logs, input/error handling and deterministic replay semantics |
| 4 | Implement and connect the C3 adapter/firmware | A requested channel executes and its actual result drives the next decision |
| 5 | Run repeatable controlled comparisons; resolve timing/calibration assumptions | Report discovery delay, revisit compliance, failure rate and measured decision latency, including regressions |
| 6 | Simplify shipped tree and documentation after parity; refine CLI workflow | One production policy, no demo dashboard/API, no duplicate Python runtime; reference recoverable in Git |
| 7 | Complete Pi verification and integration/failure checks | Timeouts, disconnects, stale replies, reboot, stop and recording integrity are covered |
| 8 | Freeze features and rehearse | Working live demonstration, labelled recorded fallback, architecture explanation and test report |

Firmware work and reference-fixture preparation can proceed alongside the Java
port once implementation is authorized. Test during each milestone; week 7 is
consolidation, not the first testing week. Hardware findings can alter the plan.

## Firmware boundary and ownership

Java owns policy, sessions, recording and analysis integration. Firmware executes
supported requests and reports measurements/errors. Do not duplicate the adaptive
algorithm on the C3.

Proposed split to agree with the partner:

- Firmware owner: board setup, channel scans, USB protocol, timing and failure reports.
- Application owner: Java library, adapter, session execution, CLI and logs.
- Shared: protocol contract, controlled measurements and end-to-end tests.

Keep the partner's existing Espressif toolchain if suitable. C++/Arduino-ESP32 is a
candidate; ESP-IDF is also appropriate. Verify actual USB behaviour and supported
SDK controls on the ordered board.

Every result needs a request identifier, executed channel, observation interval,
status and available discovery data. Use one in-flight request. Failed observations
are unavailable data, not quiet-channel samples.

The discrete-time model needs a documented timestamp-to-tick mapping and consistent
observation cadence. Request counts are not elapsed time. Scan modes, variable
durations and delayed replies must not silently create false periodic structure.

## Performance and production preparation

Keep one backend, bounded history, one observation loop per receiver, streaming
recordings and explicit capabilities. Avoid speculative services and native DSP
components in the first release. Java 21/Maven is the proposed build target.

Set time/memory budgets from the measured receiver cadence. Profile before claiming
a speedup. A production claim requires actual runtime, installation and recovery
verification on the target hardware; a first lab prototype is not automatically
validated for unattended deployment.

Persistent Wi-Fi beacons may give little advantage to adaptive scanning. Repeat
comparisons at the same observation budget and disclose changing RF conditions.
Keep round-robin in evaluation and report honestly if it wins.

## Broader roadmap after the scanning component

| Stage | Capability | Gate before claiming support |
|---|---|---|
| A | Supported BLE discovery observations | Real board test and explicit observation semantics; no claim of unrestricted BLE channel control |
| B | SDR receiver adapter and wider frequency coverage | Obtain receiver access; verify its actual tuning range, instantaneous bandwidth, timing and samples |
| C | Waveform recording and analysis | Preserve complete-enough captures with timing/provenance; measure dropped samples and processing load |
| D | Signal/protocol classification | Labelled examples, measured accuracy, confidence and an unknown class |
| E | Supported protocol decoding | Recover known test messages; integrate established decoders where useful |
| F | Key-assisted decryption for supported test sessions | Legitimately available keys and demonstrated decryption; distinguish wireless-link and application encryption |
| G | Larger application UI/API | Wrap the stable Java library once a real user workflow needs it |

These are separately scoped integrations, not automatic consequences of detecting
radio activity. Broad capture does not prove exact device identity or recover keys.
Transmit/jamming work is outside this submission and begins only as a separate
simulation or authorized controlled-testbed project.

## Fallbacks and honest boundaries

If the C3 cannot execute the required observations, choose a documented smaller
measurement scope or obtain a compatible receiver through the lab. Do not fake
channel control by forwarding independently collected network lists.

Recorded narrowband observations support inspection and deterministic model updates.
They do not reveal counterfactual results on channels that were not observed.
A laptop-only own-traffic capture can demonstrate a separate parser, but does not
prove adaptive RF acquisition or independent wireless decryption.

## Sources

- [C3 hardware capabilities](https://documentation.espressif.com/esp32-c3_datasheet_en.html)
- [C3 Bluetooth LE and Classic exclusion](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-guides/ble/overview.html)
- [Arduino-ESP32 Wi-Fi scanning](https://docs.espressif.com/projects/arduino-esp32/en/latest/api/wifi.html)
- [Raspberry Pi 4 specifications](https://www.raspberrypi.com/products/raspberry-pi-4-model-b/)
- [Wireless capture constraints](https://wiki.wireshark.org/capturesetup/wlan)
- [Supported decoding/decryption requirements](https://www.wireshark.org/docs/wsug_html/)
