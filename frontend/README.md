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

For a standalone dashboard, run `npm --prefix frontend run build` followed by `mvn -Pbundle-frontend package -DskipTests` from the repository root. Start the JAR with `--port 0` and open the loopback URL it prints. The Maven profile copies the prebuilt `frontend/dist` files. Vite remains the frontend development server.

## API integration

The server sends a `summary` on connect and on observation session changes. Each `delta` names the affected HTTP reports under `payload.modules`, coalesced at most once a second. Every message carries `seq` (starting at 1 per connection), `sessionId` (null while idle), and `timestamp` (epoch milliseconds).

A delta refreshes status or the active report when that part of the dashboard changed. Disconnects, sequence gaps, and summaries trigger an immediate HTTP refresh. While disconnected, report polling runs every four seconds and status polling every five seconds. While connected, both reconcile every 15 seconds when no earlier refresh is queued. Each poller lets the in-flight request finish and queues at most one follow-up. Changing modules aborts the old report request. Changing capture sessions clears the previous session’s live reports and Overview counts.

| UI | Backend route |
| --- | --- |
| Session bar and Overview | `GET /api/status`, `GET /api/capture/health`, `GET /api/topology` |
| Capture health | `GET /api/capture/adapters`, `POST /api/capture/start`, `POST /api/capture/stop`, `POST /api/capture/channel` |
| Sniper | `GET /api/sniper`, `GET /api/capture/access-points` for selectable APs, `POST /api/sniper`, `POST /api/sniper/select`, `POST /api/sniper/link`, `DELETE /api/sniper/{id}` |
| Spotter | `GET /api/spotter` |
| Whistleblower | `GET /api/whistleblower` |
| De-cloaker | `GET /api/decloaker` |
| Inspector | `GET /api/inspector` |
| Profiler | `GET /api/profiler`, `GET /api/profiler/{id}` |
| Tracker | `GET /api/tracker` |
| Lookout | `GET /api/lookout` |
| Settings | `GET/POST /api/profiler/network`, `POST /api/profiler/network/find`, `GET/POST/DELETE /api/profiler/fingerprints*` |
| Saved recordings | `GET/POST /api/recordings`, `POST /api/recordings/{id}/replay` |
| Session snapshots | `GET/POST /api/sessions`, `GET/DELETE /api/sessions/{id}`, `GET /api/sessions/{id}?download=true` |
| Ops | `GET /api/ops/capabilities`, `GET /api/ops/targets`, `GET /api/ops/history`, `DELETE /api/ops/history`, `POST /api/ops/{deauth,uncloak,handshake,pmkid,beacon,evil-twin}`, `GET /api/ops/{status,handshake/status,pmkid/status,beacon/status,evil-twin/status}`, `POST /api/ops/handshake/verify`, `POST /api/ops/stop` |
| Event refresh | `WS /ws/events` |

## Current capability limits

- Capture start from the dashboard requires an idle receiver and an already-prepared monitor interface. The launcher handles monitor-mode preparation and restoration.
- Saved results persists imported classic 802.11 PCAPs locally and recreates their reports through replay. Import up to 128 MiB per file. The current session must be stopped before starting a different recording.
- Session snapshots preserve up to seven passive summaries. Save with a name, open the reports read-only, export JSON, or delete the local entry. Profiler saves its inventory summary. Live signal and fingerprint detail requests are disabled in archived reports.
- My Network manages device and AP enrollment and capture scope. Changes to the effective scope clear current observations. Profiler can save reference samples from the fingerprint evidence available for enrolled devices.
- Lookout charts scanner occupancy across the adapter's discovered 2.4, 5, and 6 GHz frequencies. It marks the active receiver, coupled channels, and active or recent anomalies. The table and evidence drawer show sample counts, fitted periods, captured-frame airtime, receiver noise and dwell, AP-reported QBSS load, and regulatory flags. A running Watch session can switch modes with **Enable adaptive scan** in the report.
- De-cloaker displays observed probe names and Short-SSID hashes with each row’s source and session-tokenized devices. Archived reports display the evidence saved in the snapshot.
- Ops endpoints are enabled automatically for live and idle sessions; replay is passive-only. The API stays on loopback. The console reads `GET /api/ops/capabilities` for tool, interface (`ipv4Addresses`), cache, wordlist, `activeOperationId`, and per-operation readiness. Deauth, handshake, and optional PMKID scoping accept a live target or observed AP/raw BSSID; beacon and evil twin use explicit interface and parameter forms (including opt-in `configureAddress` for `10.0.0.1/24` on the AP interface). All operations share one server-wide slot and one physical-radio lease, **Stop operation** sends the active `operationId` when known, and **Recent operations** shows bounded session history from `GET /api/ops/history`.
- Ops and Sniper pickers use fresh advertisements from `/api/capture/access-points`; historical Inspector rows remain available as reports. Revealed hidden names are excluded from uncloak. Imported PSK verification requires an AP BSSID, and the current evil-twin form supports 2.4/5 GHz channels only. Capture controls also offer **Stop capture** while Ops has paused capture, cancelling its automatic resume.

The frontend keeps raw SSIDs as text, shows backend values without generating packet counts or identities, and opens an evidence panel for selected rows. Device family labels are presented as inferred fingerprint classifications, with confidence where supplied by the API.

## Desktop presentation

The layout targets laptop and desktop windows (1024px minimum). Category navigation stays in the sidebar; modules appear once in the page tabs. Page-level help provides the module purpose without repeated inline descriptions. Technical evidence help remains beside station counts, where the distinction matters.

Choose Slate + Cyan (the default), Graphite + Amber, or Ink + Violet under **Session → Settings**. The dashboard remembers your choice in the browser.

Overview links capture totals and topology counts to their reports. Missing counts display a dash. Observation tables stay visible beside the evidence pane, with technical fields under **Raw fields**. De-cloaker shows activity over the last ten minutes, exposure categories, the number of distinct networks probed per address, and side-channel and correlation metrics above the corpus. Typography uses local system fonts, and the interface honors reduced-motion preferences.

In Spotter, switch between the access point table and **Topology**. Select an access point or client in the diagram to filter the client-links table. Solid wires represent association or reassociation evidence, and dashed wires represent data-frame evidence. Roamed and disconnected links use dimmed wires. **Active links only** filters both views. Large diagrams show a bounded subset and offer an endpoint picker. The AP table shows the active and historical client counts and the difference between the AP-reported station count and the active count. Captured four-address backhaul traffic appears in a separate Mesh / WDS table.

During live passive capture, Sniper can search for an exact network name or follow an AP from the current capture. Search shows the active sweep frequency, confirmed coverage, and unavailable frequencies. The AP picker includes the observed identifier and frequency, including for APs whose name is unavailable. The run shows pending channel switches, decoy and spoof counts, and the reason and recovery time for each recorded move. **Follow link** requests a supported affiliated frequency. **Stop Sniper** stops the displayed run.

Ops presents six live operations beside a readiness strip and target evidence. Capability chips show which backend tools are available; missing tools are listed per operation. Deauth and handshake select from live evidenced client targets or observed APs. Handshake also offers an offline PSK verification card. PMKID supports optional AP/frequency scoping alongside unscoped capture, beacon configures SSID/channel/rate, and evil twin shows current AP interface IPv4 readiness with an opt-in `10.0.0.1/24` assignment toggle. The output pane polls the operation status once per second and renders command text, stage, output, deauth/handshake/PMKID results, and portal credentials above the session **Recent operations** history table.

In Inspector, the evidence pane groups advertised security, 802.11k/v/r capabilities, and AP load alongside captured Radiotap metadata when present. AP-reported channel utilization displays as a percentage. [ETSI WLAN Access Information API](https://www.etsi.org/deliver/etsi_gs/MEC/001_099/028/02.03.01_60/gs_mec028v020301p.pdf)

Profiler counts devices, classified devices, randomized MACs, and correlated MAC clusters. The inventory shows inferred classes, OS hints, classification evidence, My Network labels, and active AP links where available. The evidence pane refreshes retained signal samples and shows IE tag order, vendor identifiers, and the band-invariant cohort for fingerprints available to enrolled devices. Correlation detail shows session-scoped device IDs and the evidence basis (`SEQUENCE_HANDOFF`, `PROBE_TO_ASSOC`, `PNL_PROFILE`, or `WPS_UUID_E`) for each transition, with heuristic confidence and a shared directed-SSID count.

My Network refreshes the saved fingerprint list while Settings is open. Whistleblower displays a revealing frame and its capture time when the report supplies them. Tracker groups AP changes by client and shows them oldest first within each group, labeling `INFERRED_MAC_ROTATION` events as `Inferred MAC rotation (heuristic)`. On Ops → **Handshake capture**, selecting a locally administered client target defaults **Accept rotated client MAC on reconnect** on so EAPOL exchanges from a rotated randomized MAC can be captured cleanly.


Report filters search observed values and readable labels, excluding JSON property names and absent flags. Tab and theme preferences remain optional when browser storage is restricted. Ops displays each diagnostic once, with polling updates taking precedence over continuous-operation start snapshots.
