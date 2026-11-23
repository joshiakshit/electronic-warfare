# ewave frontend

React + TypeScript desktop client for the local Java backend. The dashboard reads reports, controls passive sessions, replays local recordings, manages My Network, and runs backend Lab Ops.

See [current project state](../docs/CURRENT-STATE.md), the [practical lab guide](../docs/LAB-GUIDE.md), and the [confirmed eight-module map](../README.md#passive-feature-map). Sniper, Spotter, Whistleblower, De-cloaker, Inspector, Profiler, Tracker, and Lookout are final names; Ops is separate.

## Run locally

From the repository root, start a backend session (offline replay example):

```sh
mvn package
java -jar target/ewave-0.1.0-SNAPSHOT.jar --replay src/test/resources/probes/probe-requests.pcap --port 7070
```

In another terminal:

```sh
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open the Vite URL printed in the terminal. To package or run the frontend checks:

```sh
npm run build
npm test
```

Use **Open dashboard without capture** in `./ewave` to start an idle API for browser uploads. For live capture, the launcher prepares a Wi-Fi adapter and restores its original mode on exit. **Session → Capture health** starts passive watch or adaptive capture on an already-prepared monitor adapter, stops capture or replay, and tunes the receiver during fixed-channel watch when the backend allows it. Navigation does not alter the current capture.

Capture health labels the receiver reading and the last captured frame’s channel separately. The session bar uses a receiver reading when available during live capture and labels frame-derived channels when it shows them.

The Vite proxy forwards `/api` and `/ws` to `127.0.0.1:7070` with `changeOrigin: false`. This preserves the browser's loopback Host and Origin pairing required by `PassiveRfServer`; the backend's same-origin and loopback checks remain enabled.

## API integration

The frontend polls authoritative snapshots and uses `/ws/events` to request an early refresh at most once per second. Each poller lets its current request finish and queues at most one follow-up. Changing modules aborts the old report request. Changing capture sessions also clears the previous session’s reports and Overview counts.

| UI | Backend route |
| --- | --- |
| Session bar and Overview | `GET /api/status`, `GET /api/capture/health`, `GET /api/topology` |
| Capture health | `GET /api/capture/adapters`, `POST /api/capture/start`, `POST /api/capture/stop`, `POST /api/capture/channel` |
| Sniper | `GET /api/sniper`, `GET /api/inspector` for observed APs, `POST /api/sniper`, `POST /api/sniper/select`, `DELETE /api/sniper/{id}` |
| Spotter | `GET /api/spotter` |
| Whistleblower | `GET /api/whistleblower` |
| De-cloaker | `GET /api/decloaker` |
| Inspector | `GET /api/inspector` |
| Profiler | `GET /api/profiler`, `GET /api/profiler/{id}` |
| Tracker | `GET /api/tracker` |
| Lookout | `GET /api/lookout` |
| Settings | `GET/POST /api/profiler/network`, `POST /api/profiler/network/find`, `GET/POST/DELETE /api/profiler/fingerprints*` |
| Saved results | `GET/POST /api/recordings`, `POST /api/recordings/{id}/replay` |
| Ops | `GET /api/ops/capabilities`, `GET /api/ops/targets`, `POST /api/ops/{deauth,uncloak,handshake,pmkid,beacon,evil-twin}`, `GET /api/ops/{status,handshake/status,pmkid/status,beacon/status,evil-twin/status}`, `POST /api/ops/handshake/verify`, `POST /api/ops/stop` |
| Event refresh | `WS /ws/events` |

## Current capability limits

- Capture start from the dashboard requires an idle receiver and an already-prepared monitor interface. The launcher handles monitor-mode preparation and restoration.
- Saved results persists imported classic 802.11 PCAPs locally and recreates their reports through replay. Import up to 128 MiB per file. The current session must be stopped before starting a different recording.
- My Network manages device and AP enrollment and capture scope. Changes to the effective scope clear current observations. Profiler can save reference samples from the fingerprint evidence available for enrolled devices.
- Lookout charts the scanner's occupancy estimates by band and uses valid sample counts to distinguish unavailable estimates from zero. AP-advertised utilization is available in Inspector's AP evidence.
- Probe device identifiers are returned only when enabled by the backend. SSID visibility follows backend privacy configuration; the UI displays only names returned in the report.
- Ops endpoints are enabled automatically for live and idle sessions; replay is passive-only. The API stays on loopback. The console reads `GET /api/ops/capabilities` for tool, interface, cache, wordlist, and per-operation readiness. Deauth and handshake accept a live evidenced target, an observed AP token, or a raw BSSID; PMKID, beacon, and evil twin use explicit interface and parameter forms. All operations share one server-wide slot and one physical-radio lease, and **Stop operation** cancels the running operation.
- WebSocket events contain device, packet, probe, attack, or channel updates. A reconnect requests a fresh snapshot, and timed polling continues while the socket is disconnected.

The frontend keeps raw SSIDs as text, shows backend values without generating packet counts or identities, and opens an evidence panel for selected rows. Device family labels are presented as inferred fingerprint classifications, with confidence where supplied by the API.

## Desktop presentation

The layout targets laptop and desktop windows (1024px minimum). Category navigation stays in the sidebar; modules appear once in the page tabs. Page-level help provides the module purpose without repeated inline descriptions. Technical evidence help remains beside station counts, where the distinction matters.

Choose Slate + Cyan (the default), Graphite + Amber, or Ink + Violet under **Session → Settings**. The dashboard remembers your choice in the browser.

Overview links capture totals and topology counts to their reports. Missing counts display a dash. Observation tables stay visible beside the evidence pane, with technical fields under **Raw fields**. De-cloaker explicitly labels probe names withheld by the backend. Typography uses local system fonts, and the interface honors reduced-motion preferences.

In Spotter, switch between the access point table and **Topology**. Select an access point or client in the diagram to filter the client-links table. Solid wires represent association or reassociation evidence, and dashed wires represent data-frame evidence. Large diagrams show a bounded subset and offer an endpoint picker. The client-links table provides the full matching report. AP-reported station counts and observed client counts have separate columns.

During live passive capture, Sniper can search for an exact network name or follow an AP from the current capture. The AP picker includes the observed identifier and channel, including for APs whose name is unavailable. **Stop Sniper** stops the displayed run.

Ops presents six live operations beside a readiness strip and target evidence. Capability chips show which backend tools are available; missing tools are listed per operation. Deauth and handshake select from live evidenced client targets or observed APs. Handshake also offers an offline PSK verification card. PMKID, beacon, and evil twin expose their explicit interface, SSID, channel, wordlist, and portal fields. The output pane polls the operation status once per second and renders command text, stage, output, deauth/handshake/PMKID results, and portal credentials.

In Inspector, the evidence pane groups advertised security and load alongside the capture observations. It displays AP-reported channel utilization as a percentage. [ETSI WLAN Access Information API](https://www.etsi.org/deliver/etsi_gs/MEC/001_099/028/02.03.01_60/gs_mec028v020301p.pdf)

Profiler lists inferred labels and confidence. Its evidence pane refreshes retained signal samples and fingerprint observations while open. My Network refreshes the saved fingerprint list while Settings is open. Whistleblower displays a revealing frame and its capture time when the report supplies them. Tracker groups AP changes by client and shows them oldest first within each group.

