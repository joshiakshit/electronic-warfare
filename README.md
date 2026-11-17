# ewave

ewave is a Java 21 Wi-Fi analysis backend. It captures and replays Wi-Fi frames,
builds device inventory and topology, audits probe requests, and provides HTTP
APIs and WebSocket events on loopback.

## Run the backend

Build with JDK 21 or newer and Maven:

```sh
mvn clean package
java -jar target/ewave-0.1.0-SNAPSHOT.jar --replay src/test/resources/probes/probe-requests.pcap --port 7070
```

The printed address is the API base URL. Query a report with:

```sh
curl http://127.0.0.1:7070/api/status
curl http://127.0.0.1:7070/api/capture-health
curl http://127.0.0.1:7070/api/topology
```

The root path and former dashboard assets return 404. Replay leaves the reports
available until Ctrl+C. The packaged JAR contains backend resources only.

## Launcher

Run `./ewave` for the terminal menu, or use a command:

| Task | Command |
| --- | --- |
| Fixed-channel capture | `./ewave watch wlo1 --freq 2412` |
| Adaptive 2.4 GHz capture | `./ewave scan wlo1` |
| Capture with lab operation endpoints | `./ewave ops wlo1` |
| Replay a recording | `./ewave replay home-phone-join.pcap` |
| Replay the bundled example | `./ewave replay` |
| Text probes | `./ewave probes wlo1` |
| Packet summary | `./ewave summary wlo1` |
| Check dependencies | `./ewave doctor` |
| Build and test | `./ewave build` |
| Restore managed Wi-Fi | `./ewave restore wlo1` |

Add `--port 0` for an available port. Watch, scan, Ops and probes prepare monitor
mode after confirmation. They disconnect the selected Wi-Fi adapter; Ethernet
remains available. Stop capture before restoring the adapter, then reconnect
using the desktop network menu or a saved NetworkManager connection profile.

The script builds as your user and launches API sessions through sudo, including
replay, using root's application profile. Direct Java replay works without
elevation. Live capture requires Linux, tcpdump, compatible hardware and capture
permissions. Lab operations require their external tools and an authorized lab.

## API integration

The HTTP server implementation is `ewave.ui.PassiveRfServer`. Its existing package
name remains part of the Java interface.

| API | Purpose |
| --- | --- |
| `GET /api/status` | Capture state and operation availability |
| `GET /api/capture-health` | Reception, decoding, diagnostics and replay status |
| `GET /api/inventory` | Observed device inventory |
| `GET /api/inventory/{id}/details` | Signal samples and fingerprint evidence |
| `GET /api/topology` | APs, observed client links and movement evidence |
| `GET /api/topology.dot` | Graph export |
| `GET /api/my-network` | Enrolled APs and devices |
| `POST /api/my-network/find` | Find observed APs by exact SSID |
| `GET /api/probe-audit` | Probe privacy report |
| `GET /api/probe-audit/demo` | Synthetic probe example |
| `GET /api/channels` | Scanner state when attached |
| `GET /api/channels/watch` | AP watch state |
| `GET /api/channels/demo` | Offline scanner comparison |
| `GET /api/fingerprint-samples` | Saved lab samples |
| `/api/attack/*` | Lab operation endpoints when enabled |
| `/ws/events` | WebSocket events |

Profile, fingerprint and AP-watch mutation routes remain available in the server.
Existing request validation and same-origin loopback restrictions apply. For a
future React development server, proxy `/api` and `/ws` to this backend and ensure
upstream Host and Origin satisfy those checks. Cross-origin access has not been
enabled. The React interface still needs to be built.

The lab portal helper exposes JSON at GET requests and accepts its existing
form-encoded `POST /submit`, returning `{"status":"recorded"}`. Its bundled HTML
form and success page have been removed. It retains the existing helper lifecycle,
submission recording and file permissions. The lab AP still requires manual
network setup; the helper binds on all interfaces.

## Replay and privacy

Classic 802.11 PCAP is supported. PCAPNG must be converted separately.
Synthetic captures are in `src/test/resources/probes/`. The hidden-network fixture
contains two hidden APs and a later response revealing one name.

```sh
java -Daudit.revealSsids=false -jar target/ewave-0.1.0-SNAPSHOT.jar --replay capture.pcap --port 0
```

Name visibility, session identifiers, scope and retention settings continue to
apply to API reports. The reports under `tools/` document historical evaluations;
their screenshots and dashboard instructions describe the retired frontend.

## Passive feature map

### Module names and responsibilities

| Module | Name | Category | Responsibility |
| --- | --- | --- | --- |
| 1 | **Sniper** | Router tracking | Follow a chosen access point by its radio address and observe which channel it uses. |
| 2 | **Spotter** | Client discovery | Identify clients heard joining or exchanging traffic with a particular access point. |
| 3 | **Whistleblower** | Network name discovery | Reveal a hidden network's name when a later frame supplies it. Record the frame source and time. |
| 4 | **De-cloaker** | Probe privacy | Show which network names a device discloses while searching for Wi-Fi. |

Candidate names for the remaining passive capabilities:

| Proposed name | Category | Responsibility |
| --- | --- | --- |
| **Inspector** | Router profiling | Read the security settings and Wi-Fi capabilities the router advertises. |
| **Profiler** | Device recognition | Recognize enrolled addresses and collect fingerprint clues about a device family. |
| **Tracker** | Client movement | Follow an observed client switching access points. Include its signal history as supporting evidence. |
| **Lookout** | Channel monitoring | Surface changes in observed channel activity and show advertised airtime utilization when available. |

Capture health, replay, and the scanner comparison are shared tools. Ops is a separate feature group.
These names describe backend responsibilities for the future React client.

**Backlog — disable router-name masking.** Display the actual SSID when an access point
advertises it, in future API consumers. Distinguish
same-name radios by BSSID. If no frame has supplied a name, display “Hidden network.”
Names disclosed by clients in probe requests have their own visibility setting in De-cloaker.


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

## Development

```sh
mvn test
python3 tools/test_launcher.py
python3 tools/test_portal.py
```

The launcher tests use fake Java and system commands; they never modify real
interfaces or services.

The scanner also has a separate CSV replay entry point. Run
`java -cp target/ewave-0.1.0-SNAPSHOT.jar ewave.core.Main --help` for its input
format and usage.

## License

[MIT](LICENSE)
