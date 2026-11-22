# Current state and agent handoff

Updated: **22 November 2026**. This describes the working tree, including uncommitted changes. Verify source before extending contracts; historical reviews are not proof of the current revision.

## Read first

Read [repository instructions](../AGENTS.md), [setup and module map](../README.md), and [frontend integration boundaries](../frontend/README.md). The [SET review](SET-LAB-REVIEW.md), [scanner benchmark](../tools/passive-scanner.md), [stabilization report](../tools/stabilization-report.md), and [legacy notes](../notes.md) retain dated evidence. Their old launch flags and UI names are not current instructions.

## Confirmed names

| Category | Modules | Implementation entry points |
| --- | --- | --- |
| Discovery | **Sniper**, **Spotter** | SniperController, PacketBridge; PassiveWifiSession and TopologyBuilder client evidence |
| Privacy | **Whistleblower**, **De-cloaker** | TopologyBuilder hidden-name evidence; probe audit reports |
| Identification | **Inspector**, **Profiler** | AP capabilities/topology; inventory, fingerprints and My Network |
| Movement & activity | **Tracker**, **Lookout** | TopologyBuilder roam evidence; scanner/channel reports |

All eight names are confirmed. Use **Lookout**, not Looker; **De-cloaker** is the display name and `decloaker` is the API slug. **Ops** is separate. Capture health, replay, adapter setup/restoration, settings, and saved results are shared infrastructure, not extra passive modules.

Conceptual migrations: Spectrum → Lookout; Probe Lab/probe audit → De-cloaker; Devices/Inventory → Profiler; Map/topology → Spotter/Tracker plus Inspector and Whistleblower for AP details; router/channel watch → Sniper. Preserve class names and compatibility routes unless a separate migration is authorized. Legacy and module routes need not have identical payloads.

## Startup and architecture

- Root `./ewave` presents Live Wi-Fi, Replay a recording, Setup and diagnostics, and Open dashboard without capture.
- Live selects an adapter, asks for monitor-mode confirmation, then runs Java with `--iface IFACE --adaptive --ops`. Sniper becomes available; the user still chooses a target. Ops enablement does not execute an operation.
- Replay selects a PCAP and runs Java without sudo.
- Open dashboard without capture starts an idle loopback API and Vite for browser imports.
- Setup contains dependency checks, build, and restore. Additional shell commands are only `restore IFACE` and help. The old watch/scan/ops/replay shell shortcuts are retired.
- The launcher builds a missing/outdated JAR, starts Vite when frontend dependencies exist, prints its address, and stops its frontend child on exit.
- The Java API uses port 7070 on loopback. Vite starts at port 5173 and can choose another when it is occupied. The launcher prints the bound dashboard URL and a per-launch log path. If Vite fails to start, the launcher reports the failure and starts the API by itself.
- Cleanup attempts restoration of a recorded managed-adapter state. Already-monitor adapters stay in monitor mode. Reconnection is not guaranteed.
- Ewave.java parses HELP/IDLE/CAPTURE/REPLAY. With no capture flags it starts an idle API. There is no current Java terminal menu for running modules.
- React lives in frontend/. The old bundled web assets were removed. Java's ewave.ui package still serves APIs and must not be deleted as frontend. React production assets are not currently served from the JAR.
- The lab portal helper remains JSON-only; no old HTML portal form is supplied by this dashboard.

## Java setup finding

Earlier troubleshooting hit a Java 25 runtime-only installation (`java` existed, `javac` did not), which caused the launcher build to fail. `java-25-openjdk-devel` is now installed on this machine (`/usr/bin/javac` reports `25.0.5`), so default `mvn test` and `./ewave` builds work without overriding `JAVA_HOME`. On a fresh Fedora setup, install the compiler package if `javac` is missing:

```sh
sudo dnf install java-25-openjdk-devel
java -version
javac -version
```

A separate full JDK also exists locally at `/home/joshi/.local/share/project-tools/jdk-25` (`25.0.5`) as a local fallback, not a portable requirement:

```sh
export JAVA_HOME=/home/joshi/.local/share/project-tools/jdk-25
export PATH="$JAVA_HOME/bin:$PATH"
mvn test
```

On other machines use a full JDK 21+. HTTP tests need permission to bind loopback sockets; a sandbox socket denial is an environment failure, not proof of a broken route.

## Frontend status

React/TypeScript/Vite exists and has been polished for desktop. Preserve the dark themes, category sidebar, module tabs, readable data views, sparse borders, and page-level help. Session → Settings offers Slate + Cyan (the default), Graphite + Amber, and Ink + Violet as browser-local preferences. Mobile is not the current priority. Do not restore duplicated descriptions and info icons. Fonts use local fallbacks without Google Fonts requests.

Existing wiring:

- Report GET requests, shared status/health polling, WebSocket refresh signals.
- Sniper exact-name search, direct selection of a currently observed AP, candidate selection, and cancellation of the displayed run.
- Overview count shortcuts, table filters, and a docked observation evidence pane. Lookout compares scanner occupancy estimates and identifies channels without valid samples.
- Spotter’s topology diagram uses the existing client-link report. Selecting an access point or client highlights its wires and filters the table. Inspector groups advertised authentication, ciphers, management frame protection, and AP-reported load.
- Profiler presents inferred labels, retained signal history, and fingerprint observations. Whistleblower presents hidden-name status and captured frame evidence. Tracker groups the reported AP changes by client in chronological order.
- Capture health controls passive start, stop, and fixed-watch tuning on a launcher-prepared monitor adapter. Saved results imports, lists, and replays persistent local PCAPs. Settings manages My Network enrollments, scope, and reference fingerprint samples.
- Explicitly simulated Ops controls; these do not send radio-operation requests.

Incomplete work:

- Real Ops targets, prerequisites, progress, cancellation and results are not integrated.
- The Archer T2U has verified live capture, channel tuning, Sniper search and direct follow, and populated Spotter, De-cloaker, Inspector, Profiler, Tracker, and Lookout reports. The positive hidden-name case was verified with replay.
- A frontend-only server correctly shows No session connected. Do not fabricate observations to hide it.

The user's sequence is frontend polish first, then frontend/backend integration. Preserve existing behavior while making each integration reviewable.

## Backend evidence limits

SniperController has IDLE, SEARCHING, SELECTING, LOCKED and LOST_SEARCHING states. It uses observed SSIDs/AP candidates and PacketBridge radio coordination. Automatic sweeps cover 2.4 GHz channels 1–13. Other bands require a manual frequency or an observed AP. Same-name candidate selection and receiver channel tuning passed on the Archer T2U. Reacquisition after an AP changes channel and Ops interruption/resumption still need hardware trials.

Spotter reports observed clients, not a guaranteed full client list. AP-advertised station count differs from captured client evidence. Whistleblower needs an actual revealing frame. Profiler labels are inferences, not verified identities or guaranteed randomized-MAC correlation. Tracker cannot infer disconnects from silence alone. One adapter cannot observe every channel continuously.

The scanner benchmark remains an offline tradeoff study. Original fixture: old demo 15 frames, previous live rules simulated 69, new adaptive 59. New adaptive found all three bursts and switched less, but does not win every objective. Fixed-channel listening is the known-router baseline; round-robin is the discovery comparison.

Router-name masking has changed in the current topology path: PassiveWifiSession constructs TopologyBuilder with name revelation enabled, and AP reports return observed names. Probe privacy remains separate through --hide-probes, --reveal-probes, and legacy audit.revealSsids. That setting does not anonymize an entire capture/report. Preserve scope, retention, cancellation, capture health, and thread safety.

## Verification record

- `mvn -o package` (system OpenJDK `25.0.5`, with loopback socket access): **153 tests run, 0 failures, 0 errors, 0 skipped** (`BUILD SUCCESS`).
- Follow-up `mvn -o test` (same JDK and loopback access): **154 tests run, 0 failures, 0 errors, 0 skipped**. The additional test verifies a reacquisition from channel 6 to 11 through PacketBridge with a simulated receiver.
- `python3 tools/test_launcher.py`: **10 tests** (`OK`).
- `python3 tools/test_portal.py`: **3 tests** (`OK`).
- `npm --prefix frontend test`: **7 test files, 30 tests passed**.
- `npm --prefix frontend run build`: TypeScript check (`tsc --noEmit`) and Vite production build succeeded.
- Historical 146/147/155-test reports describe earlier working trees; do not report them as current totals.
- Profiler, Whistleblower, and Tracker were checked against the bundled hidden-network replay and a synthetic browser matrix covering all three themes and populated, empty, and disconnected states. The report panes were also checked at the 1024 px desktop minimum.
- Spotter’s topology view was checked with the bundled replay, synthetic link reports, all three themes, and the 1024 px desktop minimum.
- Isolated browser sessions verified idle capture controls, rejection of a malformed PCAP, import and replay of a bundled PCAP, Whistleblower’s populated report, exact-name AP enrollment, and the enrolled-only scope. The restart-and-replay test verifies recording persistence.
- With port 5173 deliberately occupied, the real launcher served the dashboard and proxied idle API requests through the fallback port it printed. Shutdown released the fallback port.
- Polling tests verified that frequent refresh requests let a slow snapshot finish and queue one follow-up. In the browser, switching between the two bundled recordings updated the open Overview from 2 APs and 0 probes to 0 APs and 4 probes without navigation or a reload.
- A browser check with the synthetic probe recording verified that fingerprint evidence appeared in an open Profiler panel after enrollment in another tab. A sample saved in Profiler appeared in the open Settings tab without a reload.
- A browser check against the Java API with simulated receiver commands verified adapter discovery, passive start, successful and rejected tuning, and stop with retained frame counts. The dashboard displayed the simulated receiver on channel 1 alongside the last synthetic frame on channel 6.
- A browser check against the Java API with simulated receiver commands verified that Sniper followed a hidden AP selected from the current capture, found a named AP by exact SSID, and returned to idle when stopped while passive capture continued.
- The browser checks above used offline data. The combined synthetic replay also verified two client links, one hidden name revealed by a probe response, one masked directed probe, advertised security and station count, an enrolled client's signal and fingerprint observations, and one Tracker reassociation.
- Live testing on the TP-Link Archer T2U (`2357:011f`, `rtw88_8821au`) caught two bugs. Sniper could stall when the receiver was already on the first sweep channel. A mode switch could signal the replacement `tcpdump` for statistics before that process delivered its first packet, yielding exit code 138. Both bugs have regression tests. The test run's aggregate measurements and synthetic PCAP are local under `results/passive-verification/`.
- With both fixes installed, the USB receiver tuned to channels 6 and 1 in fixed watch. Starting Sniper from channel 1 completed all 13 channels and locked with an advancing last-heard timestamp. Selecting an observed AP directly locked on channel 11, which the dashboard displayed alongside the matching receiver frequency. Stopping Sniper returned to idle while capture continued. Lookout displayed samples on all 13 channels after returning to adaptive scan.
- Eight subsequent watch/scan transitions produced new frames without capture errors. Stopping kept the accumulated report data and restarting resumed capture. A same-name Sniper search offered two candidates and selection locked onto the chosen radio with fresh beacon evidence. The first trial logged 22,633 decoded frames. Continued live capture then produced two Tracker reassociation events. A controlled live setup is still needed for a hidden-name reveal and Sniper reacquisition after an AP moves channels.
- Two passive 5 GHz trials tuned all 25 channels listed by the driver and decoded 1,364 frames during their measurement windows. Whistleblower reported zero hidden APs and zero reveals in those windows. Adaptive capture resumed after each trial.

### Remaining passive hardware checks

Use a test AP and client under the operator's control. Record event counts, timestamps, channels, and evidence types. Omit SSIDs and device addresses from shared results.

- **Sniper.** Lock onto a test AP and change its 2.4 GHz channel through the AP's normal settings. Confirm Sniper locks onto the same AP on the new channel and records the move. The automated integration test runs this sequence through the capture reader and retune scheduler with synthetic beacons and simulated tune commands.
- **Whistleblower.** Observe the test AP advertising a hidden SSID, then connect a test client that knows the name. Confirm the report attributes the revealed name to a captured frame for the same AP.

## Next-agent checklist

1. Inspect the working-tree diff; preserve other agents' and user changes.
2. Verify a full JDK and frontend dependencies before diagnosing startup.
3. Use synthetic PCAPs for routine integration; keep live radio operations explicitly scoped.
4. Compare frontend requests with PassiveRfServer handlers and response fields.
5. Validate populated, empty, loading, error, stopped and replay views; distinguish real reports from simulated Ops.
6. Verify cancellation and shared-radio ownership before adding session/Ops controls.
7. Run frontend build/tests, Java tests and relevant launcher/helper checks; report environment blockers honestly.
8. Update this handoff and README when behavior changes; preserve historical evidence.
