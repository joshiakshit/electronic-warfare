# ewave

ewave is a Java 21 Wi-Fi analysis backend paired with the React web dashboard in `frontend/`. It captures and replays 802.11 frames, tracks access points (Sniper), builds client/topology and hidden-network evidence, audits probe requests, and serves HTTP/WebSocket APIs on loopback (`127.0.0.1:7070`).

## Run ewave

Install a **full JDK 21 or newer** (including `javac`), Maven, and Node.js/npm compatible with the installed Vite version. Install frontend dependencies once with `npm --prefix frontend install`. A Java runtime alone cannot build this project.

On Fedora, the missing compiler can be installed with `sudo dnf install java-25-openjdk-devel`. Verify both `java -version` and `javac -version`. If using `JAVA_HOME`, point it at the full JDK and add its `bin` directory to `PATH`.

From the repository root:

```sh
./ewave
```

Choose:
1. **`1. Live Wi-Fi`** — select an adapter, confirm switching it to monitor mode, and open the web dashboard (`http://127.0.0.1:5173`). The backend starts with adaptive scanning and Ops endpoints enabled; Sniper is available to select a target. Starting a session does not execute an operation. On exit the launcher attempts to restore the recorded managed-adapter state. An adapter already in monitor mode is left there.
2. **`2. Replay a recording`** — select a PCAP recording to inspect it in the web dashboard as your normal user without `sudo`.
3. **`3. Setup and diagnostics`** — use the submenu to check dependencies, build the backend JAR, or restore an adapter (`./ewave restore IFACE`).
4. **`4. Open dashboard without capture`** — start the idle loopback API and frontend as your normal user. Import and play recordings or open saved snapshots under **Session → Saved results**. Ops readiness is available here; live radio operations require **Live Wi-Fi**.

The shell accepts `./ewave`, `./ewave restore IFACE`, and `./ewave --help`. Older shortcuts such as `watch`, `scan`, `ops`, `replay`, `doctor`, and `build` are not shell subcommands now; use the menu. Direct Java flags remain available with `java -jar target/ewave-0.1.0-SNAPSHOT.jar --help`.

For direct Java capture, `--freq MHz` or `--channel CH --band B` tunes the prepared monitor adapter before starting capture. A failed or timed-out tune aborts startup. Without either flag, fixed watch starts on the adapter's existing channel; `--adaptive` enables channel hopping instead.

Live scanning defaults to a 20 ms sampling tick so short-period fingerprint hints can be fitted; `--tick-ms` still accepts 10–2000 ms. The live scanner retains a 20-second maximum fitting horizon. Period hints are inferences from sampled activity, not verified device identities or beacon measurements.

Adaptive capture and Sniper use the physical adapter's enabled 2.4, 5, and 6 GHz frequencies from `iw phy … info`. They can listen on `no IR` channels and skip disabled channels. If discovery is unavailable, the passive sweep falls back to 2.4 GHz channels 1–13. The live scanner derives its slots from that frequency list. A driver can still reject a tune, which leaves the frequency without confirmed coverage. Offline tests exercise discovery, tuning decisions, and reports with synthetic captures and injected commands. Physical multi-band tuning remains unverified for this change.

The launcher rebuilds missing or outdated Java artifacts and starts the Vite development server when frontend dependencies exist. Open the dashboard address it prints after Vite starts. The API uses port 7070. The dashboard starts at port 5173 or uses the next free port. If Vite fails to start, the launcher reports its log path and starts the API by itself. The launcher uses Vite for its development workflow.

For frontend-only work:

```sh
npm --prefix frontend run dev -- --host 127.0.0.1
```

Without a backend, “No session connected” is expected. See [frontend setup and integration limits](frontend/README.md).

### Optional single-JAR dashboard

Build the frontend before packaging its production assets.

```sh
npm --prefix frontend run build
mvn -Pbundle-frontend package -DskipTests
java -jar target/ewave-0.1.0-SNAPSHOT.jar --port 0
```

Open the printed loopback URL. The JAR serves the dashboard and direct links such as `/overview`, `/privacy/de-cloaker`, and `/ops`. The Maven profile copies `frontend/dist` without invoking Node. Default Maven builds are Java-only and leave dashboard routes unavailable. Vite development and the launcher menu still work with either build.


Live capture requires Linux, `tcpdump`, compatible hardware, and `sudo` privileges. Lab operations require their external tools and an authorized lab. Depending on the operation, Ops uses `iw`, `aireplay-ng`, `tcpdump`, `tshark`, `aircrack-ng`, `hcxdumptool`, `hcxpcapngtool`, `mdk4`/`mdk3`, `hostapd`, `dnsmasq`, `python3`, and a wordlist. The Ops readiness strip and `GET /api/ops/capabilities` list what is installed.

## API integration

The HTTP server implementation is `ewave.ui.PassiveRfServer`. Its existing package name remains part of the Java interface.

| Module / Area | Primary Routes | Legacy Compatibility Aliases |
| --- | --- | --- |
| Session & capture | `GET /api/status`, `GET /api/capture/health`, `GET /api/capture/adapters`, `GET /api/capture/access-points`, `POST /api/capture/start`, `POST /api/capture/stop`, `POST /api/capture/channel` | `GET /api/capture-health` |
| Session snapshots | `GET/POST /api/sessions`, `GET/DELETE /api/sessions/{id}` | — |
| Saved recordings | `GET/POST /api/recordings`, `POST /api/recordings/{id}/replay` | — |
| Sniper (router watch) | `GET /api/sniper`, `POST /api/sniper`, `POST /api/sniper/select`, `POST /api/sniper/link`, `DELETE /api/sniper`, `DELETE /api/sniper/{id}` | `GET/POST/DELETE /api/channels/watch*` |
| Spotter | `GET /api/spotter` | `GET /api/topology`, `GET /api/topology.dot` |
| Whistleblower | `GET /api/whistleblower` | `GET /api/topology` |
| De-cloaker | `GET /api/decloaker`, `GET /api/decloaker/demo` | `GET /api/probe-audit*` |
| Inspector | `GET /api/inspector` | `GET /api/topology` |
| Profiler & My Network | `GET /api/profiler`, `GET /api/profiler/{id}`, `GET/POST /api/profiler/network`, `POST /api/profiler/network/find`, `GET/POST/DELETE /api/profiler/fingerprints*` | `GET /api/inventory*`, `GET/POST /api/my-network*`, `GET/POST/DELETE /api/fingerprint-samples*` |
| Tracker | `GET /api/tracker` | `GET /api/topology` |
| Lookout | `GET /api/lookout`, `GET /api/lookout/demo` | `GET /api/channels`, `GET /api/channels/demo` |
| Lab Ops | `GET /api/ops/{capabilities,targets,aps,scan-lan,status,history}`, `POST /api/ops/{deauth,uncloak,handshake,handshake/verify,pmkid,beacon,evil-twin,stop}`, `DELETE /api/ops/history` | `/api/attack/*` |
| WebSocket stream | `/ws/events` | `—` |

Retired text-mode endpoints (`GET /api/devices`, `GET /api/profiles`, `GET /api/probes`) return `410 Gone` with their replacement route when operations are enabled. Existing request validation and same-origin loopback restrictions apply. Cross-site and same-site browser fetches are rejected, including requests without an Origin header. JSON POST routes require `Content-Type: application/json`; recording uploads require `application/octet-stream`. Direct local clients without browser fetch headers remain supported. The Vite configuration proxies `/api` and `/ws` to this backend with `changeOrigin: false`. The dashboard uses these routes for passive reports, Sniper, capture controls, recording replay, My Network, and the Ops console.

`GET /api/ops/capabilities` reports tool availability, monitor/AP interfaces (with current `ipv4Addresses`), cache freshness, the configured wordlist, `activeOperation`, `activeOperationId`, and per-operation readiness. Deauth, handshake, and optional PMKID scoping accept a live evidenced `targetId`, an observed AP `apId` token, or an explicit `apBssid`; the server resolves addresses and frequency from the current session. PMKID also compiles an `hcxdumptool` BPF filter, accepts optional `frequencyMhz`, and filters converted `.22000` lines to the target AP inside a per-run private workspace directory. The cached AP and LAN routes remain optional legacy inputs. Set `-Drf.wordlist=/path/to/wordlist` (or `EWAVE_WORDLIST`) before `-jar` to prefill Ops wordlist requests; an explicit `wordlistPath` still overrides it.

Sniper and Ops AP pickers use `/api/capture/access-points`, which returns fresh advertised APs with measured frequency. Inspector retains historical and data-inferred APs for passive analysis; these rows are not automatically selectable targets. Ops prefers live measured frequency over a stale cache, including on 6 GHz, and rejects unknown frequencies. Legacy channel-only handshake calls use 2.4/5 GHz numbering; specify `frequencyMhz` for a raw 6 GHz target. Uncloak rejects hidden APs whose name has already been revealed. The current open evil-twin configuration supports 2.4/5 GHz channels only; channel 14 uses DSSS mode.

`GET /api/inspector` includes `findingsCount` and `evilTwinSuspects` alongside `accessPoints` and `essGroups`. AP rows retain session-scoped BSSID tokens and include `apRadio` (generation, operating and maximum width, spatial streams, and BSS color), vendor and advertised hostname when available, and WPS information merged from beacons and probe responses. Security evidence includes the group management cipher, RSNXE features, beacon protection, and OCVC. Each row's `securityFindings` lists passive observations such as weaker security on another AP with the same SSID. A downgrade finding identifies a suspected rogue AP based on captured advertisements.

Sniper orders its receive-only sweeps using reported channel hints, recent scanner evidence when available, and same-band preferences during reacquisition. It tracks announced channel switches, rolls back when a destination advertisement cannot be verified, and reports the active sweep frequency, ignored decoys, spoof warnings, and channel-move triggers. `POST /api/sniper/link` accepts `{"frequencyMhz":5975}` during a live Sniper lock to tune to an unambiguous supported affiliated link and verify its advertisement. Sniper returns session-scoped tokens for AP and multi-link device addresses. A locally administered AP can be followed after a heuristic BSSID change when a complete confirmed sweep finds exactly one compatible replacement.

Lookout attempts each receiver frequency once before weighted adaptive selection takes over at dwell boundaries. **Enable adaptive scan** switches a running fixed Watch session to Scan from the report.

`GET /api/lookout` and `GET /api/channels` key coverage by frequency. Legacy scanner arrays follow the order of `channels`. Each row includes `sampleCount`, regulatory flags, fitted period and confidence, frequency-keyed coupling, and receiver `dwellMs`. The report adds captured-frame `estimatedAirtime` after 100 ms of dwell, `medianNoiseDbm` when reported by the driver, frequency-matched AP and active client counts, and the highest advertised `qbssUtilization` on that frequency. The interference flag is a heuristic based on the noise floor or a gap between AP-reported load and captured airtime. A rolling count of 50 captured beacons in one second can open a beacon-flood alert on its own. With a live scanner flag, 40 beacons in that window classify the alert as a beacon flood. Anomaly rows retain flood classifications for 15 seconds after activity clears. `recentAnomalies` lists up to 32 active or recently cleared episodes.

Inspector adds advertised SAE and OWE modes, 802.11k/v/r management features, Extended Capabilities, and captured Radiotap metadata when available. Tracker uses a 30-second default roam window (`topology.roamWindowSec`) and can report heuristic `INFERRED_MAC_ROTATION` transitions when a locally administered client rotates MACs unambiguously across related APs with matching capability IEs. Handshake capture supports opt-in `allowMacRotation` for randomized-MAC client reconnects.

`GET /api/tracker` includes `accessPoints` for AP names and channel context, `devices` with any enrolled labels, and up to 256 `btmRejections` with status codes. `roams` includes the evidence method, transition type, bands and channels when known, uplink RSSI, and observed dwell time. A reversal within 60 seconds is marked as ping-pong. Accepted BSS Transition Management responses can annotate a matching hop within 15 seconds. Data-only switches between links of the same Wi-Fi 7 multi-link device are omitted. Tracker saves these fields in session snapshots.

Profiler's inventory and detail routes report the classification basis, OS hint, My Network label, and latest active confirmed AP link when available. `fingerprintHint` is reserved for saved samples and signature-table matches. Data-only clients can show a PHY generation, width, and stream count inferred from Radiotap. Enrolled devices can inspect each retained fingerprint's IE order, vendor tag identifiers, and band-invariant cohort, and save it as a reference sample.

Matching inventory rows include an `inferredCorrelation` reference. Device details include the cluster, its transition evidence (`SEQUENCE_HANDOFF`, `PROBE_TO_ASSOC`, `PNL_PROFILE`, or `WPS_UUID_E`), and heuristic confidence. Cross-band probe-to-association and preferred-network matches can use a shared band-invariant cohort at reduced confidence. Correlation uses session-scoped IDs and returns the shared directed-SSID count.

Spotter and topology reports include `meshLinks`, control-frame evidence, and the link states `ACTIVE`, `ROAMED_AWAY`, and `DISCONNECTED`. Access point rows can identify nontransmitted Multiple BSSID profiles, shared radio groups, Wi-Fi 7 multi-link devices, and TWT responders. Spotter shows the gap between an AP's advertised station count and the active clients observed on that AP. Older saved reports continue to open, with links that lack a state displayed as active.

Whistleblower reports a hidden AP's concealment mode, any null-padding length, and its reveal confidence. Association requests supply tentative names until passive evidence confirms the association. A matching AP rejection withdraws the tentative name. Advertisements can supply names through OWE transition elements or unambiguous Reduced Neighbor Report Short-SSID matches. The match corpus includes plaintext directed probes in scope. Hidden rows can also identify mesh and backhaul roles, a session-scoped OWE peer, and visible SSIDs that share a radio, MLD, or OWE relationship. The four fields in `hiddenSsidEvidence` and the version 1 snapshot format are preserved.

De-cloaker always includes observed probe SSIDs and probing-device counts, IDs, and last-seen times in live and replay reports. It deduplicates probe retries from the same sender and sequence control within one second. The corpus records plaintext SSIDs, nested SSID List entries, and Short-SSID targets. A Short-SSID resolves when its CRC-32 matches a single retained plaintext name. Unmatched and ambiguous values appear as `Short-SSID 0x…` and count as directed probes. Each corpus row reports its strongest source in `source` and all observed sources in `sources`. The report groups exposures using hotspot, router-default, and enterprise patterns. Set `-Daudit.corporateSsids=Office WiFi,Guest WiFi` as a quoted JVM argument before `-jar` to add exact enterprise names.

The dashboard shows activity in 30-second buckets, distinct networks probed per address, locally administered address share, and the current count of inferred Profiler clusters. It also reports Passpoint indicators, Wi-Fi Direct device names by tokenized sender, and counts of WPS Enrollee UUIDs seen on multiple addresses. Profiler uses an exact token match between locally administered addresses as `WPS_UUID_E` evidence with a heuristic confidence score of 0.95. Passive probe reports use session-scoped device IDs and retain only a session token for WPS UUID-E. [Wi-Fi Direct device fields in hostap](https://w1.fi/wpa_supplicant/devel/structp2p__peer__info.html)

PSK verification selects one BSSID with quiet, noninteractive `aircrack-ng` output. Imported captures require `apBssid`; captures from the current handshake operation retain their target for subsequent verification. Diagnostic output is capped at 1 MiB while final key/miss outcomes remain detectable beyond that cap. PMKID verification checks successive valid hashes until a key is found or all hashes miss, within one shared five-minute verification window.

Ops endpoints are enabled automatically for live and idle sessions; replay exposes passive analysis only. The Ops console is a real local control surface. It shows command output, results, portal credentials, recent session history (`GET`/`DELETE /api/ops/history`), and the current operation state from the backend. All operations share one server-wide slot and one physical-radio lease; `POST /api/ops/stop` cancels the running operation and optionally accepts `{"operationId":"<uuid>"}` to prevent stopping a newer run (returning `409` on mismatch and `{"stopped":false}` when idle).

Stopping passive capture is allowed while Ops has paused it. Status exposes `capturePausedForOps` until resume is cancelled or the lease ends; **Stop capture** cancels automatic capture resume while the active operation keeps its slot and radio lease. New capture sessions reset probe counters and raw profiler observations, while same-interface watch/scan changes and stop/restart retain the current session. Idle Profiler returns an empty inventory, and De-cloaker evicts probe counts and their SSID samples together.

Beacon starts with `mdk4` and falls back to `mdk3` when `sudo` reports that `mdk4` is missing. Status and command output update as the fallback starts; the operation keeps its slot and radio lease throughout. Permission, interface, and argument errors do not trigger a fallback.

Starting replay from the dashboard disables Ops for that session, including after replay completes, fails, or is stopped. `/api/status` reports `operationsEnabled: false`, and both `/api/ops/*` and the legacy `/api/attack/*` routes return `404`. Starting a new live capture restores Ops when enabled at launch and replaces the replay observations.

Each evil-twin run uses a private temporary work directory, reported as `workDir` in Ops status. Java creates its `credentials.tsv` with mode `0600` before starting the elevated portal helper. The helper preserves that file's owner so an unprivileged backend can display submissions; `credentialsFile` reports the log path. Work directories must be new and private; credential files must be private, backend-owned regular files without symbolic or multiple hard links. The portal validates ownership before truncating the file and refuses replacement inodes during submission. Handshake captures use a separate private temporary directory for each run.

The lab portal helper exposes JSON at GET requests and accepts its existing
form-encoded `POST /submit`, returning `{"status":"recorded"}`. Its bundled HTML
form and success page have been removed. It retains the existing helper lifecycle,
submission recording and file permissions. Evil twin leaves interface IPv4
unchanged by default, or accepts opt-in `"configureAddress": true` to bring up
the AP interface and assign `10.0.0.1/24` via `sudo ip` with teardown on exit;
the helper binds on all interfaces.

### WebSocket report updates

`/ws/events` starts each connection with a `summary`. It sends another summary when the observation session changes, and coalesces changed report names into a `delta` at most once per second.

```json
{"type":"delta","seq":3,"sessionId":"6fbd44d0-79cf-4555-814d-8010cd72fbc1","timestamp":1764000000000,"payload":{"modules":["status","profiler","decloaker"]}}
```

`seq` starts at 1 and increments for every message on the connection. `sessionId` identifies the current observation session and is null when idle. Timestamps are epoch milliseconds. The `payload.modules` values identify the HTTP reports to reload. Other event types carry the same sequence and session fields. On disconnect or a sequence gap the dashboard refreshes from HTTP and reconnects. Periodic HTTP polling also reconciles time-based report changes.

## Replay and privacy

Classic 802.11 PCAP is supported. PCAPNG must be converted separately.
Synthetic captures are in `src/test/resources/probes/`. The hidden-network fixture
contains two hidden APs and a later response revealing one name.

Browser imports are limited to 128 MiB per recording. The recording library persists in
`~/.local/share/ewave/recordings` for the invoking user, including live sessions elevated through sudo. Set
`-Drf.recordingDirectory=/path/to/recordings` before `-jar` to choose another directory.
The browser uploads the file it was given and replays it by library ID. Malformed recording metadata is skipped so other recordings remain available.

In **Session → Saved results**, save the current Spotter, Whistleblower, De-cloaker, Inspector, Profiler, Tracker, and Lookout summaries. Open them later as read-only reports or use **Export JSON**. Lookout is unavailable in a snapshot when no scanner report was available at save time. Opening a snapshot leaves the backend capture session as it was.

`POST /api/sessions` accepts a JSON `name` and an optional `sessionId` to ensure the active session still matches. `GET /api/sessions` lists metadata, `GET /api/sessions/{id}` loads the versioned reports, `?download=true` returns an attachment, and `DELETE /api/sessions/{id}` removes the local snapshot. The library holds up to 32 snapshots of 8 MiB each and skips unreadable snapshot records. The invoking user's private store is `~/.local/share/ewave/sessions`. Set `-Drf.sessionDirectory=/path/to/sessions` before `-jar` to override it.

Snapshots contain derived passive reports. They omit PCAP data, Ops results, credentials, and PSKs. Loading and exporting snapshots preserve the probe names, device evidence, and grouped names saved in the original report, including when the backend is idle. Older snapshots can only display evidence they originally stored.

My Network defaults to `~/.config/ewave/my-network.json` for the same invoking user. Live, Replay, and Idle share these defaults even when sudo resets the backend's home to `/root`. The launcher passes `rf.userHome`; direct sudo launches resolve `SUDO_USER` through the account database. Explicit `--profile` / `rf.networkProfile` and `rf.recordingDirectory` paths take priority. Newly created storage parents and saved files retain the invoking user's ownership. Files saved by older versions under `/root` are not migrated automatically.

Topology returns observed AP names. Review AP names, probed SSIDs, and Wi-Fi Direct device names before sharing exported reports. Ops targets and operation results contain real client and BSSID addresses for the local console, so review Ops output before sharing it. Session identifiers, scope and retention settings still apply. The reports under `tools/` document historical evaluations;
their screenshots and dashboard instructions describe the retired frontend.

## Passive feature map

All eight passive module names are confirmed. Use these spellings in documentation, UI, and future work; API slugs remain lowercase.

| # | Module | Dashboard category | Responsibility and evidence limit |
| --- | --- | --- | --- |
| 1 | **Sniper** | Discovery | Find a target by SSID or observed AP identifier, lock onto it, and search again after silence. Automatic discovery sweeps enabled adapter frequencies across 2.4, 5, and 6 GHz. |
| 2 | **Spotter** | Discovery | Show clients observed associating or exchanging traffic with an AP. It cannot enumerate silent clients; AP-advertised station count is a separate measurement. |
| 3 | **Whistleblower** | Privacy | Report hidden SSID evidence from captured frames, including OWE and RNR matches, with its source and confidence. |
| 4 | **De-cloaker** | Privacy | Review probed network names and Short-SSID hashes, observed devices, and evidence linking randomized addresses. |
| 5 | **Inspector** | Identification | Read advertised security and roaming capabilities, AP load, and captured per-frame radio metadata when present. |
| 6 | **Profiler** | Identification | Review observed device inventory, inferred classifications, and confidence-scored correlations between locally administered probe sources. Each address keeps its own device row. |
| 7 | **Tracker** | Movement & activity | Show observed AP changes with supporting evidence. Silence alone is not a disconnect. |
| 8 | **Lookout** | Movement & activity | Review scanner/channel observations. Channel hopping trades reception time for coverage. |

**Ops** is separate from the eight passive modules. Capture health, adapter setup/restoration, replay, settings, and saved results are shared session tools, not extra passive modules.

**Name migration:** Spectrum → Lookout; Probe Lab/probe audit → De-cloaker; Devices/Inventory → Profiler; Map/topology → Spotter and Tracker, with AP capabilities in Inspector and hidden-name evidence in Whistleblower; router/channel watch → Sniper. These are conceptual mappings, not promises that legacy and new endpoints have identical payloads. Use **Lookout**, never Looker.

Distinguish same-name radios by AP identifier/BSSID. The topology report leaves unknown AP names blank.

For a step-by-step practical lab covering every module, read [the lab guide](docs/LAB-GUIDE.md). For implementation boundaries and the next work, read [the agent handoff](docs/CURRENT-STATE.md). Older reviews are historical evidence, not current startup instructions.

## Optional Wi-Fi vendor names

Capture, replay, and device classification work with the default build.
Generate local lookup catalogs to display additional Wi-Fi manufacturer names.

For Wi-Fi names, install Wireshark's `tshark` and export its manufacturer table
from the repository root.

```sh
tshark -G manuf > src/main/resources/oui.txt
```

Run `mvn clean package` to include the generated manufacturer tables.
Keep the generated catalogs and any JAR built with them local. For a distributable
default build, package from a fresh checkout.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/main/java/ewave/` | Launcher, scanner, capture, decoders, device profiling, lab operations, and HTTP server |
| `src/main/resources/` | Classification rules and the lab portal API helper |
| `src/test/` | Java tests and checked-in synthetic and numerical fixtures |
| `tools/` | Offline benchmarks, scanner trials, and their results |
| `frontend/` | React/TypeScript desktop dashboard, Vite, and frontend tests |
| `docs/CURRENT-STATE.md` | Current agent handoff and verification boundaries |
| `docs/LAB-GUIDE.md` | Step-by-step practical guide for every module and Ops |

## Development

```sh
mvn test
python3 tools/test_launcher.py
python3 tools/test_portal.py
npm --prefix frontend test
npm --prefix frontend run build
```

The launcher tests use fake Java and system commands; they never modify real
interfaces or services.

The scanner also has a separate CSV replay entry point. Run
`java -cp target/ewave-0.1.0-SNAPSHOT.jar ewave.core.Main --help` for its input
format and usage.

## License

[MIT](LICENSE)
