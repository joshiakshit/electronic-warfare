# Current state and agent handoff

Updated: **25 November 2026**. This describes the working tree, including uncommitted changes. Verify source before extending contracts; historical reviews are not proof of the current revision.

## Read first

Read [repository instructions](../AGENTS.md), [setup and module map](../README.md), [frontend integration boundaries](../frontend/README.md), and the [practical lab guide](LAB-GUIDE.md). The [SET review](SET-LAB-REVIEW.md), [scanner benchmark](../tools/passive-scanner.md), [stabilization report](../tools/stabilization-report.md), and [legacy notes](../notes.md) retain dated evidence. Their old launch flags and UI names are not current instructions.

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
- Live selects an adapter, asks for monitor-mode confirmation, then runs Java with `--iface IFACE --adaptive`. Ops endpoints are enabled for live and idle sessions; replay is passive-only. Sniper becomes available; the user still chooses a target. Starting a session does not execute an Ops operation.
- Replay selects a PCAP and runs Java without sudo.
- Browser replay also disables Ops dynamically: status reports `operationsEnabled: false` and both Ops route prefixes return `404`. Completed, failed, and stopped replay observations remain passive-only until a new live capture replaces them. Target resolution rejects replay topology, and radio leases reject replay sessions even if a request passed the route guard before replay started.
- Open dashboard without capture starts an idle loopback API and Vite for browser imports.
- Setup contains dependency checks, build, and restore. Additional shell commands are only `restore IFACE` and help. The old watch/scan/ops/replay shell shortcuts are retired.
- The launcher builds a missing/outdated JAR, starts Vite when frontend dependencies exist, prints its address, and stops its frontend child on exit.
- The Java API uses port 7070 on loopback. Vite starts at port 5173 and can choose another when it is occupied. The launcher prints the bound dashboard URL and a per-launch log path. If Vite fails to start, the launcher reports the failure and starts the API by itself.
- Cleanup attempts restoration of a recorded managed-adapter state. Already-monitor adapters stay in monitor mode. Reconnection is not guaranteed.
- Ewave.java parses HELP/IDLE/CAPTURE/REPLAY. With no capture flags it starts an idle API with Ops available for readiness checks. There is no current Java terminal menu for running modules.
- Direct Java capture shares the dashboard's capture-start path. `--freq` and `--channel` tune the adapter before starting `tcpdump`; failed or timed-out tuning aborts startup without publishing the requested channel. Tests cover command order, 2.4/5/6 GHz frequency selection, and tuning failures using simulated processes.
- React lives in frontend/. The old bundled web assets were removed. Java's ewave.ui package still serves APIs and must not be deleted as frontend. The opt-in `bundle-frontend` profile packages prebuilt React assets and enables loopback SPA routes. Default builds and the launcher’s Vite workflow remain supported.
- The lab portal helper remains JSON-only; no old HTML portal form is supplied by this dashboard.
- Each evil-twin run uses a separate private temporary directory. Java precreates a `0600` credential log; the elevated Python helper truncates/appends to that inode without changing its owner. Ops status supplies the actual `workDir` and `credentialsFile`. Java and Python tests simulate helper boundaries and restrictive file-opening behavior; elevated radio operations have not been verified by these tests.
- My Network and recordings use the invoking user's home across sudo Live Wi-Fi and unprivileged Idle/Replay. The launcher passes `rf.userHome`; direct sudo launches resolve `SUDO_USER` with `getent`. Explicit store paths still override defaults. Ownership restoration covers newly created parent directories, profile files, recording entry directories, PCAPs, and metadata. Existing data under `/root` requires separate recovery.
- Beacon fallback handles `sudo` exiting with `mdk4: command not found`, keeps the operation slot/radio lease while `mdk3` starts, and preserves diagnostics. Simulated-process tests cover fallback, other failures, cancellation, and temporary SSID-file cleanup; this is not hardware verification.

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

- Report GET requests, shared status and health polling, and coalesced WebSocket report invalidations.
- Sniper exact-name search, direct selection of a currently observed AP, candidate selection, and cancellation of the displayed run.
- Overview count shortcuts, table filters, and a docked observation evidence pane. Lookout highlights the receiver frequency, coupling, and active or recently cleared anomalies. The evidence pane shows period fits, airtime, noise, dwell, and AP-reported load. **Enable adaptive scan** is available from Lookout during fixed Watch capture.
- Spotter’s topology diagram uses the existing client-link report. Selecting an access point or client highlights its wires and filters the table. Inspector groups advertised authentication, ciphers, management frame protection, and AP-reported load.
- Profiler presents inferred labels, retained signal history, fingerprint observations, and confidence-scored probe correlations. Whistleblower presents concealment, reveal evidence and confidence, co-hosted visible SSIDs, and AP security and radio evidence in the drawer. Tracker groups the reported AP changes by client in chronological order.
- Capture health controls passive start, stop, and fixed-watch tuning on a launcher-prepared monitor adapter. Saved results imports and replays persistent local PCAPs and saves, opens, exports, and deletes passive session snapshots. Settings manages My Network enrollments, scope, and reference fingerprint samples.
- Ops is wired to the real backend: capabilities/readiness (with interface `ipv4Addresses` and `activeOperationId`), live evidenced targets enriched with AP security/PMF/AKM/DFS posture and LAN IP correlation (`GET /api/ops/lan-hosts`), deauth and uncloak with a 10s non-blocking post-injection passive channel hold (`holdPassiveFrequency`), Passive→Ops handoffs from Whistleblower/Inspector/Spotter, handshake capture with live `Beacon → M1..M4` progress, verifiable `M1+M2`/`M2+M3` pair tracking, configurable `timeoutSeconds` (`10–180`), early finish (`POST /api/ops/handshake/finish`), and recording export (`POST /api/ops/handshake/save-recording`), PMKID with `captureOnly` mode, split-stage progress, early finish (`POST /api/ops/pmkid/finish`), structured `.22000` hash rows, and standalone verification (`POST /api/ops/pmkid/verify`), multi-SSID beacon flood (`ssids` array up to 50 entries in a private workspace), and evil twin with isolated `dnsmasq` config (`except-interface=lo`, private lease/PID files), live `hostapd` station tracking, DHCP lease tables, and opt-in `configureAddress` (`10.0.0.1/24`), plus `operationId`-scoped stop and bounded session history. Deauth, handshake, and PMKID accept a live target id, an observed AP token, or a raw BSSID, so optional AP/LAN caches are not required for live operations.

Incomplete work:

- Next Ops work: validate each operation on the owned test AP/client and optionally add a customizable HTML captive portal page (`portal_server.py` currently serves JSON only).
- The Archer T2U has verified live capture, channel tuning, Sniper search and direct follow, and populated Spotter, De-cloaker, Inspector, Profiler, Tracker, and Lookout reports. The positive hidden-name case was verified with replay.
- A frontend-only server correctly shows No session connected. Do not fabricate observations to hide it.

The dashboard integrates real backend requests. Keep each operation reviewable and preserve the shared operation slot and radio-lease behavior.

## Session snapshots, streaming, and bundling

- `GET/POST /api/sessions` lists or saves snapshots, and `GET/DELETE /api/sessions/{id}` loads or deletes one. Load with `?download=true` for a JSON attachment. POST takes a name and an optional current `sessionId`. Version 1 saves seven passive report slots, with a null Lookout slot when no scanner is attached. The dashboard views the saved reports read-only and keeps the running session separate.
- The store uses the invoking user's `~/.local/share/ewave/sessions`, overridable with `-Drf.sessionDirectory`. It checks directory and file ownership, rejects symbolic links and multiply linked files, uses private `0700` and `0600` modes, and publishes through an atomic move. The limit is 32 snapshots of 8 MiB each. De-cloaker snapshots preserve observed names, probe sources, and tokenized device evidence on save, load, and export. PCAP imports remain capped at 128 MiB.
- `/ws/events` adds `seq`, `sessionId`, and epoch-millisecond `timestamp` to messages. Sequence starts at 1 per connection. A `summary` marks connect or a new observation session. A `delta` carries affected modules in `payload.modules` at most once per second. PacketBridge revisions track changes independently of the legacy event queue. The dashboard fetches authoritative HTTP reports and refreshes on gaps and disconnects.
- Build the React assets with `npm --prefix frontend run build` and package them with `mvn -Pbundle-frontend package -DskipTests`. Direct links such as `/privacy/de-cloaker` are enabled when the bundled index exists. The default build remains Node-free and uses the same API and WebSocket routes.

## Backend evidence limits

SniperController has IDLE, SEARCHING, SELECTING, LOCKED and LOST_SEARCHING states. It uses observed SSIDs/AP candidates and PacketBridge radio coordination. A new live session resolves the physical radio and reads `iw phy … info`. Adaptive dwell, Sniper sweeps, and Lookout share its enabled 2.4, 5, and 6 GHz frequencies. The list keeps `no IR` and radar-detection flags for receive-only monitoring and excludes disabled entries. The 2.4 GHz channels 1–13 fallback applies when discovery is unavailable. An explicit all-disabled response gives an empty sweep. Sniper counts confirmed dwell separately from failed tunes, and reacquisition timestamps use frequency so equal channel numbers in different bands remain distinct.

Sniper starts each sweep dwell at 120 ms and can extend it to 400 ms to amortize a slow tune. It prioritizes compatible Reduced Neighbor Reports and known affiliated links, then prefers the last band during reacquisition. Scanner scores and activity anomalies rank opportunities when an adaptive scanner is running. Sniper reads scores by zero-based slot and anomalies by the corresponding one-based key. Exact SSID searches retain full-plan coverage before automatic selection. A receive-only CSA jump is committed after a compatible destination advertisement arrives. An unverified jump returns to the prior frequency. AP-origin data and management frames refresh liveness on the locked frequency. Hotspot BSSID rotation is heuristic and requires a complete confirmed pass. Ties surface in candidate selection. The HTTP snapshot exposes session-scoped AP and MLD tokens and the reason for each channel move. [Linux 802.11 element definitions](https://kernel.googlesource.com/pub/scm/linux/kernel/git/wireless/wireless-testing/+/master/include/linux/ieee80211.h)

Spotter reports observed clients, not a guaranteed full client list. AP-advertised station count differs from captured client evidence. Whistleblower can reveal names through client frames, OWE transition elements, or unambiguous RNR Short-SSID matches across captured observations. Profiler labels and address correlations are inferences. Tracker cannot infer disconnects from silence alone. One adapter cannot observe every channel continuously.

- Spotter uses association, data, and supported two-address control frames as membership evidence. It retains roamed and disconnected links until expiry and ignores clear disconnect frames for APs advertising required protected management frames. Multiple BSSID profiles inherit radio metadata from their transmitter. AP and client MLDs and four-address backhaul peers use session-scoped tokens. Spotter and saved reports include the new fields alongside the existing version 1 snapshot fields.

- Lookout starts with one attempt per enabled frequency and then uses weighted scanner choices at confirmed dwell boundaries. With multiple slots it takes the second choice if the first would repeat the previous frequency. `activeFrequencyMhz`, `lastChosenFreqMhz`, and `radio.coverage[].frequencyMhz` disambiguate channel numbers. Legacy scanner arrays use the order of `channels`. Fallback regulatory flags are null. Airtime estimates count frames received while tuned and require at least 100 ms of dwell. QBSS load comes from the highest value advertised by an observed AP on the frequency. A live scanner anomaly can be classified as a beacon flood at 40 beacons in a rolling second. A count of 50 opens an alert independently. Lookout holds per-channel alerts for 15 seconds after activity clears and reports up to 32 active or held episodes with available flood classifications.
- Inspector includes `securityModes` and `managementFeatures` on AP observations. Profiler's `capabilities` summary adds named RSN AKM suites, security modes, radio measurement and neighbor reports, BSS transition and other WNM features, fast transition, the mobility domain, and the Extended Capabilities bitmap when present. Missing advertisements leave features unobserved. The radio observation on each path includes a capture timestamp and the available channel flags, antenna, legacy rate, HT/HE rate parameters, noise, and same-sample SNR.

- Profiler checks saved samples and the signature table before classifying from WPS primary device type, ecosystem vendor IEs, advertised radio capabilities, or IEEE OUI. Data-only clients can show a separately inferred Radiotap PHY. Both Profiler routes include available My Network labels and active confirmed AP context. Enrolled-device detail includes the IE order, vendor tags, and band-invariant cohort. Probe-to-association and preferred-network correlations can use a shared band-invariant cohort at lower heuristic confidence when the exact evidence differs across bands.
- Inspector separates the AP's advertised radio configuration from reception metadata. Beacon and probe response evidence adds Wi-Fi generation, operating and supported widths, spatial streams, BSS color, OUI vendor, AP hostname, WPS hardware and lock state, and modern RSN fields. Its passive audit compares exact SSIDs across APs and checks for weaker security, open networks, WPS lock status, disabled management frame protection, SAE without advertised Hash-to-Element support, and BSS color collisions. The API includes per-AP findings and report totals, and the existing five-field advertised security profile remains compatible.
- Profiler retains separate rows per address. `/api/profiler` adds a nullable `inferredCorrelation` reference and `/api/profiler/{id}` includes the full cluster with pseudonymous members, evidence basis (`SEQUENCE_HANDOFF`, `PROBE_TO_ASSOC`, `PNL_PROFILE`, or `WPS_UUID_E`), and scored transitions. Correlation compares identical probe IE fingerprints or frame-invariant capability cohorts (`IeSignature.capabilityCohortOf`), forward modulo-4096 sequence steps (within 2s), probe-to-association SSID matches (within 15s), and matching multi-SSID directed profiles across sequence resets (within 60s), discarding tied or ambiguous transitions and ignoring retries for timing-based evidence. Matching non-placeholder WPS UUID-E tokens can link locally administered addresses with overlapping observations or distinct fingerprints. Tracker defaults its roam window to 30 seconds (`topology.roamWindowSec`) and can also emit heuristic `INFERRED_MAC_ROTATION` events when a locally administered client uniquely re-associates across related APs with matching capability IEs; handshake capture supports opt-in `allowMacRotation` for randomized-MAC client reconnects. Confidence is a heuristic score, and evidence remains scoped and bounded with probe names and raw MAC addresses omitted from correlation reports.

Multi-band sweeps, cross-band reacquisition logic, and frame and correlation reports have offline regression coverage with synthetic PCAP records and injected query/tune commands. No physical radio was used to verify these additions. Earlier Archer T2U observations below describe the previous implementation.

Field definitions used in these paths are documented by [iw](https://kernel.googlesource.com/pub/scm/linux/kernel/git/jberg/iw/+/c62dc398aa2406bd2dd0aa28ecb34cf4d3a2e1af/info.c), [Radiotap](https://radiotap.org/fields/defined), and hostap's [AKM suite](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/master/src/common/wpa_common.h) and [management capability](https://android.googlesource.com/platform/external/wpa_supplicant_8/+/master/src/common/ieee802_11_defs.h) definitions.

The scanner benchmark remains an offline tradeoff study. Original fixture: old demo 15 frames, previous live rules simulated 69, new adaptive 59. New adaptive found all three bursts and switched less, but does not win every objective. Fixed-channel listening is the known-router baseline; round-robin is the discovery comparison.

De-cloaker always returns observed plaintext probe names and device counts and lists in live and replay. It deduplicates recent retries by tokenized sender and sequence control. SSID List entries and Short-SSID CRC-32 values are tracked as directed targets. Unique retained plaintext matches resolve by name. Collisions remain hash-only. The report exposes Passpoint prevalence, Wi-Fi Direct device names, WPS UUID-E counts, and the distinct Profiler cluster count. MAC and UUID-E identifiers in passive probe processing are session-tokenized in the packet callback. The React view adds the activity chart, exposure and chattiness summaries, and per-network device evidence. Older version 1 snapshots open with the data they saved.

## Verification record

- Ops Lab Workbench (`#9A–#9D`) plus target-selection & cross-band channel hardening (`PassiveWifiSession.authoritativeChannelAndFrequency`, active-only composite `clientId:apId` Ops target IDs, signal-sorted/filtered dropdowns in `Ops.tsx`, and non-clobbering Uncloak manual BSSID input) verification passed `mvn -o test` (**345 tests, 0 failures, 0 errors, 0 skipped**) and `mvn -o package -DskipTests`; `npm --prefix frontend test -- --run` passed **86 tests in 8 files** and `npm --prefix frontend run build` (`tsc --noEmit` + Vite build) succeeded; `python3 tools/test_launcher.py` passed **11 tests** and `python3 tools/test_portal.py` passed **10 tests**. Offline checks use synthetic PCAPs and simulated subprocess commands; additionally, pre-college home hardware validation on `EWAVE-LAB-5G` confirmed live targeted deauth (`holdSeconds: 10`), complete 4-way handshake capture (`M1_M2_M3_M4`), recording save, and session snapshot restore.
- De-cloaker verification passed `mvn test` and `mvn clean package` with **299 tests** each. `npm --prefix frontend test` passed **69 tests in 8 files**, and `npm --prefix frontend run build` succeeded. Synthetic frames exercised retry handling, SSID lists, CRC collision handling, Passpoint, Wi-Fi Direct names, and UUID-E correlation. Loopback HTTP tests verified snapshot loading and export after restart. Headless Brave replay verified the corpus, all 20 activity buckets, and the tokenized device evidence drawer.
- The receive-only Sniper upgrade passed `mvn test` and `mvn clean package` with **272 tests, 0 failures, 0 errors, 0 skipped** in each run. `npm --prefix frontend test` passed **63 tests in 8 files** and the production build passed. The packaged replay API reported Sniper idle and rejected link following with HTTP 409. The new tracking behavior was checked using synthetic frames, simulated tunes, loopback HTTP, and server-rendered frontend tests.
- Randomized-MAC resilience verification passed `mvn -o test` (**250 tests, 0 failures, 0 errors, 0 skipped**) and `npm --prefix frontend test && npm --prefix frontend run build` (**8 files, 61 tests passed**, TypeScript and Vite build succeeded), covering probe-to-association and multi-SSID PNL correlation, dual-band `INFERRED_MAC_ROTATION` roam inference with ambiguity rejection, and opt-in `allowMacRotation` handshake captures on simulated fixtures.
- Session snapshot and event-stream verification passed `mvn -o test` with **246 tests, 0 failures, 0 errors, 0 skipped** and `npm --prefix frontend test && npm --prefix frontend run build` with **8 files, 59 tests passed**. Launcher and portal Python suites passed **11** and **10** tests. Both offline Maven package variants passed. Replay smoke on `--port 0` verified direct browser routes and assets in the bundled JAR, the HTTP and WebSocket guards, and disabled Ops. Headless Brave exercised save, masked JSON export, opening and browsing saved reports, and deletion.
- Passive multi-band and frame/identity enrichment verification used `mvn -o test` (**242 tests, 0 failures, 0 errors, 0 skipped**) and `npm --prefix frontend test && npm --prefix frontend run build` (**8 files, 57 tests passed**, TypeScript and Vite build succeeded).
- Earlier working-tree verification follows.
- `mvn -o test` (system OpenJDK `25.0.5`, with loopback socket access): **229 tests run, 0 failures, 0 errors, 0 skipped** (`BUILD SUCCESS`) across active unit/process tests, HTTP route suites, target resolution, capabilities, radio coordination, decoders, scanners, and passive analyzers.
- Ops route tests resolve a live `targetId` without the AP/LAN caches, resolve observed AP tokens, report tool/cache/wordlist readiness, interface `ipv4Addresses`, `activeOperationId`, scoped PMKID target/frequency forwarding, opt-in evil-twin `configureAddress`, `operationId`-scoped stop (`409` on mismatch), bounded `/api/ops/history`, and cancellation through simulated processes. No live radio Ops operation has been executed yet.
- `python3 tools/test_launcher.py`: **11 tests** (`OK`).
- `python3 tools/test_portal.py`: **10 tests** (`OK`).
- Local JAR smoke: an idle session started without a flag reports `operationsEnabled: true` and serves `/api/ops/capabilities` with **200**; a replay session returns **404** `Lab operations require a live capture session`. The Java `--help` output no longer lists an Ops flag, and the launcher starts live capture with `--iface IFACE --adaptive`.
- `npm --prefix frontend test`: **8 test files, 55 tests passed**.
- `npm --prefix frontend run build`: TypeScript check (`tsc --noEmit`) and Vite production build succeeded with the real Ops console.
- Historical 146/147/153/154/155-test reports describe earlier working trees; do not report them as current totals.
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

### Ops hardware checks

Use the owned test AP/client and record the operation, target, channel, duration, command, output, cancellation, and adapter restoration. Prioritize deauth/uncloak client effect, handshake validity, PMKID target scoping, beacon visibility, and evil-twin DHCP/portal reachability. Do not share captured keys or portal credentials.

## Recent correctness fixes (24 November)

- Uncloak rejects previously revealed hidden names. Fresh advertisement pickers use `/api/capture/access-points`; Inspector keeps its longer historical retention. Ops resolves advertised AP tokens through measured session details, preserving 6 GHz frequencies and rejecting unknown frequencies. The open evil-twin configuration rejects unsupported channels and uses `hw_mode=b` on channel 14.
- The live default tick is 20 ms, with a 20-second period-fitting horizon; synthetic tests reach the beacon-cycle and high-frequency hints. EHT map parsing uses the measured band when a frame sets a reserved 2.4 GHz width bit alongside wider-band flags. This is defensive parsing of mixed flags, not evidence that the reserved combination is a valid multi-band capability IE.
- Fresh sessions reset probe counters and raw profiler state; same-session restart retains them. Idle Profiler uses an empty inventory schema. Probe audit stores directed names with their owning probe so eviction stays consistent. Capture stop is available during an Ops pause and cancels deferred resume without freeing the active operation's lease.
- PSK verification uses a target BSSID, quiet output, a 1 MiB diagnostic limit with independent outcome parsing, and terminal status stages. Verification retains the prior capture's target for repeated checks. PMKID verification streams through valid hashes with per-attempt outcomes and a shared five-minute deadline. Tests use offline fixtures and simulated commands; these changes have not been verified on radio hardware.

## Report, storage, and local API hardening (24 November)

- Report filtering searches observed values and display labels without JSON property names or null/boolean serialization. Overview uses readable AP-change evidence methods. Restricted browser storage no longer breaks category navigation; tab preferences are optional. Ops diagnostics render once, and continuous-operation polling supersedes the start snapshot.
- Malformed recording metadata is skipped while valid recordings remain listable and replayable. The event-consumer shutdown test now first observes the actual `ewave-api-events` thread and verifies its termination.
- The loopback guard accepts bracketed IPv6 hosts and rejects cross-site/same-site fetch metadata even without Origin. Every API POST requires the appropriate media type: JSON by default, octet-stream for recording uploads. Frontend bodyless POST requests send the JSON media type too.
- Handshake captures use private per-run temporary directories. Existing custom capture directories must be backend-owned, private, and free of symbolic links; new custom directories are created securely. Evil-twin work directories are created atomically without adopting existing paths. Credential paths are checked for owner, permissions, regular-file type, and hard links. Python opens without following links, validates before truncation, and rejects a replacement inode during submission.
- Maven resources and shading exclude Python bytecode/cache directories and module descriptors. The packaged portal source remains included. Global JSON/CSV ignore patterns were removed, exposing the frontend manifests/lockfile for version control; the stray root lockfile was removed.
- Verification on this working tree: `mvn clean package` ran **222 tests, 0 failures/errors/skips** and built the shaded JAR; `npm --prefix frontend test` passed **51 tests in 8 files**; frontend production build passed; portal helper **10 tests** and launcher **11 tests** passed. JAR inspection found no Python bytecode/cache entries or module descriptors, and `java -jar … --help` succeeded. Frontend regressions use server rendering and pure-function checks; these changes have not been browser-checked or tested on radio hardware.

## Next-agent checklist

1. Inspect the working-tree diff; preserve other agents' and user changes.
2. Verify a full JDK and frontend dependencies before diagnosing startup.
3. Use synthetic PCAPs for routine integration; keep live radio operations explicitly scoped.
4. Compare frontend requests with PassiveRfServer handlers and response fields.
5. Validate populated, empty, loading, error, stopped and replay views, including real Ops results.
6. Verify cancellation and shared-radio ownership when changing session/Ops controls.
7. Run frontend build/tests, Java tests and relevant launcher/helper checks; report environment blockers honestly.
8. Update this handoff and README when behavior changes; preserve historical evidence.
