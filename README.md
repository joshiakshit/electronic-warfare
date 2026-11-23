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
4. **`4. Open dashboard without capture`** — start the idle loopback API and frontend as your normal user. Import and play recordings under **Session → Saved results**. Ops readiness is available here; live radio operations require **Live Wi-Fi**.

The shell accepts `./ewave`, `./ewave restore IFACE`, and `./ewave --help`. Older shortcuts such as `watch`, `scan`, `ops`, `replay`, `doctor`, and `build` are not shell subcommands now; use the menu. Direct Java flags remain available with `java -jar target/ewave-0.1.0-SNAPSHOT.jar --help`.

The launcher rebuilds missing or outdated Java artifacts and starts the Vite development server when frontend dependencies exist. Open the dashboard address it prints after Vite starts. The API uses port 7070. The dashboard starts at port 5173 or uses the next free port. If Vite fails to start, the launcher reports its log path and starts the API by itself. This is a development-server workflow; the React build is not served from the Java JAR.

For frontend-only work:

```sh
npm --prefix frontend run dev -- --host 127.0.0.1
```

Without a backend, “No session connected” is expected. See [frontend setup and integration limits](frontend/README.md).

Live capture requires Linux, `tcpdump`, compatible hardware, and `sudo` privileges. Lab operations require their external tools and an authorized lab. Depending on the operation, Ops uses `iw`, `aireplay-ng`, `tcpdump`, `tshark`, `aircrack-ng`, `hcxdumptool`, `hcxpcapngtool`, `mdk4`/`mdk3`, `hostapd`, `dnsmasq`, `python3`, and a wordlist. The Ops readiness strip and `GET /api/ops/capabilities` list what is installed.

## API integration

The HTTP server implementation is `ewave.ui.PassiveRfServer`. Its existing package name remains part of the Java interface.

| Module / Area | Primary Routes | Legacy Compatibility Aliases |
| --- | --- | --- |
| Session & capture | `GET /api/status`, `GET /api/capture/health`, `GET /api/capture/adapters`, `POST /api/capture/start`, `POST /api/capture/stop`, `POST /api/capture/channel` | `GET /api/capture-health` |
| Saved recordings | `GET/POST /api/recordings`, `POST /api/recordings/{id}/replay` | — |
| Sniper (router watch) | `GET /api/sniper`, `POST /api/sniper`, `POST /api/sniper/select`, `DELETE /api/sniper`, `DELETE /api/sniper/{id}` | `GET/POST/DELETE /api/channels/watch*` |
| Spotter | `GET /api/spotter` | `GET /api/topology`, `GET /api/topology.dot` |
| Whistleblower | `GET /api/whistleblower` | `GET /api/topology` |
| De-cloaker | `GET /api/decloaker`, `GET /api/decloaker/demo` | `GET /api/probe-audit*` |
| Inspector | `GET /api/inspector` | `GET /api/topology` |
| Profiler & My Network | `GET /api/profiler`, `GET /api/profiler/{id}`, `GET/POST /api/profiler/network`, `POST /api/profiler/network/find`, `GET/POST/DELETE /api/profiler/fingerprints*` | `GET /api/inventory*`, `GET/POST /api/my-network*`, `GET/POST/DELETE /api/fingerprint-samples*` |
| Tracker | `GET /api/tracker` | `GET /api/topology` |
| Lookout | `GET /api/lookout`, `GET /api/lookout/demo` | `GET /api/channels`, `GET /api/channels/demo` |
| Lab Ops | `GET /api/ops/{capabilities,targets,aps,scan-lan,status,stop}`, `POST /api/ops/{deauth,uncloak,handshake,handshake/verify,pmkid,beacon,evil-twin}` | `/api/attack/*` |
| WebSocket stream | `/ws/events` | `—` |

Retired text-mode endpoints (`GET /api/devices`, `GET /api/profiles`, `GET /api/probes`) return `410 Gone` with their replacement route when operations are enabled. Existing request validation and same-origin loopback restrictions apply. The Vite configuration proxies `/api` and `/ws` to this backend with `changeOrigin: false`. The dashboard uses these routes for passive reports, Sniper, capture controls, recording replay, My Network, and the Ops console.

`GET /api/ops/capabilities` reports tool availability, monitor/AP interfaces, cache freshness, the configured wordlist, and per-operation readiness. Deauth and handshake accept a live evidenced `targetId`, an observed AP `apId` token, or an explicit `apBssid`; the server resolves addresses and frequency from the current session. The cached AP and LAN routes remain optional legacy inputs. Set `-Drf.wordlist=/path/to/wordlist` (or `EWAVE_WORDLIST`) before `-jar` to prefill Ops wordlist requests; an explicit `wordlistPath` still overrides it.

Ops endpoints are enabled automatically for live and idle sessions; replay exposes passive analysis only. The Ops console is a real local control surface. It shows command output, results, portal credentials, and the current operation state from the backend. All operations share one server-wide slot and one physical-radio lease, and `/api/ops/stop` cancels the running operation.

The lab portal helper exposes JSON at GET requests and accepts its existing
form-encoded `POST /submit`, returning `{"status":"recorded"}`. Its bundled HTML
form and success page have been removed. It retains the existing helper lifecycle,
submission recording and file permissions. The lab AP still requires manual
network setup; the helper binds on all interfaces.

## Replay and privacy

Classic 802.11 PCAP is supported. PCAPNG must be converted separately.
Synthetic captures are in `src/test/resources/probes/`. The hidden-network fixture
contains two hidden APs and a later response revealing one name.

Browser imports are limited to 128 MiB per recording. The recording library persists in
`~/.local/share/ewave/recordings` for the backend's launch account. Set
`-Drf.recordingDirectory=/path/to/recordings` before `-jar` to choose another directory.
The browser uploads the file it was given and replays it by library ID.

```sh
java -Daudit.revealSsids=false -jar target/ewave-0.1.0-SNAPSHOT.jar --replay capture.pcap --port 0
```

AP names returned by topology are plain observed SSIDs. The legacy `audit.revealSsids` setting and `--hide-probes` / `--reveal-probes` flags control probe-name visibility; they do not anonymize every AP name in an exported report. Ops targets and operation results contain real client and BSSID addresses for the local console, so review Ops output before sharing it. Session identifiers, scope and retention settings still apply. The reports under `tools/` document historical evaluations;
their screenshots and dashboard instructions describe the retired frontend.

## Passive feature map

All eight passive module names are confirmed. Use these spellings in documentation, UI, and future work; API slugs remain lowercase.

| # | Module | Dashboard category | Responsibility and evidence limit |
| --- | --- | --- | --- |
| 1 | **Sniper** | Discovery | Find a target by SSID or observed AP identifier, lock onto it, and search again after silence. Automatic discovery currently sweeps 2.4 GHz channels 1–13. Live search and following were verified on the Archer T2U. Reacquisition after an AP changes channels still needs a hardware trial. |
| 2 | **Spotter** | Discovery | Show clients observed associating or exchanging traffic with an AP. It cannot enumerate silent clients; AP-advertised station count is a separate measurement. |
| 3 | **Whistleblower** | Privacy | Reveal a hidden SSID only when a captured frame supplies its name; preserve the evidence source. |
| 4 | **De-cloaker** | Privacy | Review names disclosed in probe requests, subject to probe privacy settings. |
| 5 | **Inspector** | Identification | Read an AP's advertised security, capabilities, and station/utilization fields when present. |
| 6 | **Profiler** | Identification | Review observed device inventory, enrolled identities, and fingerprint clues. Inferred labels are not verified identities. |
| 7 | **Tracker** | Movement & activity | Show observed AP changes with supporting evidence. Silence alone is not a disconnect. |
| 8 | **Lookout** | Movement & activity | Review scanner/channel observations. Channel hopping trades reception time for coverage. |

**Ops** is separate from the eight passive modules. Capture health, adapter setup/restoration, replay, settings, and saved results are shared session tools, not extra passive modules.

**Name migration:** Spectrum → Lookout; Probe Lab/probe audit → De-cloaker; Devices/Inventory → Profiler; Map/topology → Spotter and Tracker, with AP capabilities in Inspector and hidden-name evidence in Whistleblower; router/channel watch → Sniper. These are conceptual mappings, not promises that legacy and new endpoints have identical payloads. Use **Lookout**, never Looker.

Router-name masking is no longer a pending request in the current topology path: it returns observed AP names. Distinguish same-name radios by AP identifier/BSSID; an unknown name stays unknown. Probe-name privacy remains separate.

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
