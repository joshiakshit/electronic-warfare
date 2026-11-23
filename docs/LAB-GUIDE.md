# ewave practical lab guide

This guide walks through every ewave module on equipment you own. Use one test access point (AP), one or two test clients, and an isolated channel. Do not run active operations against networks or devices you do not control. Active operations generate real 802.11 frames, can disconnect clients, and can expose credentials.

Ops is enabled automatically in live and idle sessions. Replay is passive-only. There is no `--ops` flag and no separate Ops menu item.

## 1. What each module needs

| Module | Main input | Works with a prepared monitor adapter? | Extra setup |
| --- | --- | --- | --- |
| Sniper | Live monitor capture | Yes | A test AP; 2.4 GHz automatic sweep, 5 GHz manual or observed |
| Spotter | Live monitor capture | Yes | A client connected to the test AP and generating traffic |
| Whistleblower | Live monitor capture | Yes | A hidden AP and a later frame that reveals its name |
| De-cloaker | Live monitor capture | Yes | Test-client probe requests; probe privacy settings decide name visibility |
| Inspector | Live monitor capture | Yes | An observed AP; some fields depend on what the AP advertises |
| Profiler | Live monitor capture | Yes | Test-client traffic; optional My Network enrollment |
| Tracker | Live monitor capture | Yes | A client that moves or reassociates between APs or channels |
| Lookout | Adaptive or fixed monitor capture | Yes | Traffic on more than one channel to compare occupancy |
| Ops | Live session plus external tools | Yes, with tools installed | Deauth needs a target and interface; PMKID needs `hcxdumptool`/`hcxpcapngtool`; beacon needs `mdk4`/`mdk3`; evil twin needs a separate AP interface and IP setup |

## 2. Prepare the lab

### 2.1 Hardware

- Linux host with a Wi-Fi adapter that supports monitor mode. The project's verified adapter is the TP-Link Archer T2U (`rtw88_8821au`).
- A test AP you control. A second AP is useful for Tracker roaming tests.
- One or two test clients you control (phone, laptop, or SBC).
- Optional second adapter or receiver for independent observation.
- A quiet channel (often 1, 6, or 11 in 2.4 GHz) and low transmit power. Keep the lab away from neighboring networks.

### 2.2 Software

Fedora example; package names vary by distribution:

```sh
sudo dnf install java-25-openjdk-devel maven nodejs npm tcpdump iw
sudo dnf install aircrack-ng wireshark-cli hcxdumptool hcxtools mdk4 hostapd dnsmasq wordlists python3
```

What provides what:

| Command | Package |
| --- | --- |
| `aireplay-ng`, `aircrack-ng` | `aircrack-ng` |
| `tshark` | `wireshark-cli` |
| `hcxdumptool` | `hcxdumptool` |
| `hcxpcapngtool` | `hcxtools` |
| `mdk4` / `mdk3` | `mdk4` / distribution package |
| `hostapd`, `dnsmasq` | `hostapd`, `dnsmasq` |
| Wordlist | `wordlists` or your own dictionary |

Build once from the repository root:

```sh
mvn clean package
npm --prefix frontend install
```

Check readiness:

- `./ewave` → **3. Setup and diagnostics** → dependency check.
- Or start a live session and open **Ops**. The readiness strip reports every tool, monitor interface, cache, wordlist, and per-operation readiness.
- `GET /api/ops/capabilities` returns the same data.

For a default wordlist path, pass `-Drf.wordlist=/path/to/wordlist` before `-jar`; `EWAVE_WORDLIST` works too. The Ops forms still accept an explicit path.

### 2.3 Prepare the test AP and client

1. Configure the AP with a lab SSID, for example `EWAVE-LAB`, WPA2-PSK, and channel 6.
2. Write down the AP BSSID and channel.
3. Connect a test client and generate traffic (`ping`, a video stream, or a file transfer).
4. For hidden-SSID work, configure a second SSID with SSID broadcast disabled. Connect the client once so it knows the name.
5. For roaming work, configure a second AP with the same SSID on a different channel, or reassociate the client manually.
6. For evil-twin work, reserve a separate AP-capable adapter. One radio cannot be both the monitor capture interface and the evil-twin AP at the same time.

### 2.4 Start ewave

```sh
./ewave
```

Choose **1. Live Wi-Fi**, select the adapter, and confirm monitor mode. The launcher prepares the adapter, builds the JAR if needed, starts the dashboard, and restores the adapter when the session exits.

The dashboard URL is printed in the terminal. The API normally runs on `127.0.0.1:7070`; Vite uses `5173` or the next free port. The backend stays on loopback.

Open **Session → Capture health** and confirm:

- the capture is running;
- the receiver channel and frequency are correct;
- decoded frames are increasing;
- kernel drops and errors are absent.

Useful modes:

- **2. Replay a recording**: passive analysis only; Ops is unavailable.
- **4. Open dashboard without capture**: idle API and dashboard. Ops readiness is available, but active operations need an interface and a target.

## 3. Passive modules

### 3.1 Sniper — find and follow an AP

**Purpose:** find a network by SSID or observed AP, lock onto it, and keep following its channel.

1. Keep the test AP on channel 6 and note its SSID.
2. Open **Discovery → Sniper**.
3. Enter the exact SSID (`EWAVE-LAB`) or select a currently observed AP from the picker.
4. Start the search. The run moves through `SEARCHING` and `LOCKED`.
5. Confirm the locked channel/frequency and the advancing last-heard time.
6. To test reacquisition, change the AP to channel 11 through its normal settings. Watch for `LOST_SEARCHING` and a new lock.
7. Stop Sniper. Passive capture continues.

Record the state transitions, candidate list, locked BSSID/channel, and timestamps.

Limits: the automatic sweep covers 2.4 GHz channels 1–13. A 5 GHz/6 GHz target needs a manual frequency or an observed AP. Same-name APs appear as candidates. Reacquisition after a channel change still needs the hardware check.

### 3.2 Spotter — observed clients and topology

**Purpose:** show clients observed associating or exchanging data with an AP.

1. Connect the test client to the test AP and generate traffic.
2. Open **Discovery → Spotter**.
3. Review the client-links table.
4. Switch to **Topology**; select an AP or client to highlight wires and filter the table.
5. Compare the observed client count with the AP-advertised station count.
6. Open a row's evidence pane to see the evidence source and timing.

Record each client's evidence type (association/reassociation/data), first/last seen, channel, and the AP's advertised station count.

Limits: Spotter shows observed clients, not every silent client. An AP-advertised station count is a separate measurement.

### 3.3 Whistleblower — hidden network names

**Purpose:** reveal a hidden SSID when a captured frame supplies the name.

1. Configure the test AP with a hidden SSID and connect the test client.
2. Start live capture.
3. Open **Privacy → Whistleblower**.
4. Trigger a client reassociation (disconnect/reconnect) so a revealing frame is captured.
5. Inspect the AP row for the revealed name, the revealing frame, its source, and the capture time.

Record the AP BSSID, hidden status, revealed name, evidence source, and timestamp.

Limits: if no captured frame contains the name, the name stays unknown. A beacon alone does not reveal a hidden SSID.

### 3.4 De-cloaker — probe requests

**Purpose:** review SSIDs disclosed in client probe requests.

1. With the test client connected, turn Wi-Fi off and on, or forget/reconnect to the test network, to generate probes.
2. Open **Privacy → De-cloaker**.
3. Review the probe corpus, named and general probes, and the evidence pane.
4. Note when a probe name is withheld by backend privacy settings.

Record probe counts, returned names or masked values, and capture times.

Limits: only observed probes appear. `--hide-probes` / `--reveal-probes` (or `-Daudit.revealSsids`) control probe-name visibility; they do not anonymize every AP name in a report.

### 3.5 Inspector — AP security and capabilities

**Purpose:** read an AP's advertised security, capabilities, and load fields.

1. Start live capture with the test AP visible.
2. Open **Identification → Inspector**.
3. Select the test AP.
4. Read the advertised security (WPA2/WPA3, group/pairwise ciphers, authentication, management-frame protection), channel, bandwidth, station count, utilization, beacon interval, and country.
5. Compare the values with the AP configuration.

Record the advertised fields and whether each was present.

Limits: Inspector reports advertised values. Missing or stale fields are not proof that a capability is absent.

### 3.6 Profiler — inventory and fingerprints

**Purpose:** review observed devices, inferred labels, signal history, and fingerprint clues.

1. Generate traffic from the test client.
2. Open **Identification → Profiler**.
3. Review the inventory; open the test client's row.
4. Inspect the inferred label, confidence, vendor, retained signal history, and fingerprint observations.
5. Open **Session → Settings** to enroll the client or AP in My Network, apply scope, and save a reference fingerprint sample.
6. Return to Profiler and confirm the evidence updates.

Record the inferred label and confidence, signal samples, fingerprint hashes, and enrollment/scope state.

Limits: labels are inferences, not verified identities. A locally administered address is not proof of rotation, and Profiler does not correlate randomized addresses.

### 3.7 Tracker — AP changes

**Purpose:** show observed client AP changes with supporting evidence.

1. Connect the test client to AP A.
2. Move it to AP B, or reassociate it, so a reassociation or data-path change is captured.
3. Open **Movement & activity → Tracker**.
4. Review the per-client groups, the from/to APs, the evidence method, and the timestamps.

Record each transition, method, and time.

Limits: silence alone is not a disconnect. A transition needs explicit association, reassociation, or data evidence.

### 3.8 Lookout — channel observations

**Purpose:** compare scanner/channel occupancy and identify channels without valid samples.

1. Start adaptive capture, or fixed watch and tune channels manually.
2. Generate traffic on channels 1, 6, and 11 at different times.
3. Open **Movement & activity → Lookout**.
4. Compare the occupancy estimates, sample counts, bands, and channels with no valid samples.
5. Switch between adaptive and fixed watch in **Capture health** to see the coverage tradeoff.

Record the occupancy estimate, sample count, channel, band, and capture mode.

Limits: one adapter cannot observe every channel continuously. Channel hopping trades reception time for coverage; a low sample count is not proof of an idle channel.

## 4. Ops — active lab operations

### 4.1 Readiness and target sources

1. Start a **Live Wi-Fi** session.
2. Open **Ops**.
3. Confirm the readiness strip is green for the operation you plan to run.
4. Use one of these target sources:
   - **Client target**: a live evidenced client/AP pair from passive capture.
   - **Observed AP**: an AP token from the current topology.
   - **Raw BSSID / cached AP**: for direct lab calls.
5. Use an interface already in monitor mode for deauth, handshake, PMKID, and beacon. Use a separate AP interface for evil twin.

Only one operation runs at a time. The operation takes a physical-radio lease; passive capture resumes when it ends. **Stop operation** cancels the active operation.

### 4.2 Deauthentication

1. Select a client target or an observed AP.
2. Choose the monitor interface.
3. Set the deauth count. `0` runs the bounded 30-second continuous test window.
4. Start the operation and watch the command/output pane.
5. Observe the test client in Spotter/Tracker/Whistleblower for a reconnect.
6. Stop if needed and record the command, output, duration, and observed client effect.

Use the owned client. The result's `success` means the process ran; it is not proof that the client disconnected. Management-frame protection can prevent the effect.

### 4.3 Network-name reveal (uncloak)

1. Configure the test AP with a hidden SSID and keep one test client associated.
2. Open Ops → **Network name reveal**.
3. Select a hidden AP with an observed client, or enter its AP token/BSSID.
4. Choose the monitor interface and start.
5. The operation sends a short targeted deauth so the client reconnects.
6. Check **Whistleblower** for the revealed name and its frame evidence.
7. Stop and record the target, result message, revealed name, and timestamp.

The AP must be hidden, have an observed client, and the client must reconnect for a possible reveal. If the name is already known, the backend rejects the operation.

### 4.4 Handshake capture and PSK verification

1. Open Ops → **Handshake capture**.
2. Select the client target or observed AP; choose the monitor interface.
3. Start. The status waits for the target AP beacon.
4. When the stage says **Ready — reconnect your device now**, disconnect and reconnect the test client.
5. Wait for `COMPLETE` (or `PARTIAL`/`NO_EAPOL`/`TARGET_NOT_SEEN`) and note the capture path and messages.
6. The capture path is pre-filled in the **Verify a capture** card.
7. Choose a wordlist and click **Verify PSK**.
8. Record the outcome, capture path, verification result, and whether the key was found.

Captures are written under `/tmp/ewave-captures/` with restricted permissions. Stop the operation if it is still running.

### 4.5 PMKID capture

1. Open Ops → **PMKID capture**.
2. Select the monitor interface, wordlist, and duration (1–300 seconds).
3. Start and wait for the capture/conversion/verification result.
4. Record whether a PMKID was captured, whether the wordlist found a key, and the capture/hash paths.
5. Stop and review.

Current limitation: the PMKID workflow does not yet filter by target BSSID; it captures what `hcxdumptool` sees. Use an isolated lab channel, keep the duration short, and do not run it where other networks are in range.

### 4.6 Beacon flood

1. Open Ops → **Beacon flood**.
2. Choose the monitor interface, SSID, channel, and rate (1–10000 beacons/second).
3. Start.
4. Observe the SSID on the test client or an independent scanner.
5. Stop after the planned window and record the command, rate, channel, and observed result.

Keep the rate low and the duration short. Use only on the owned lab channel.

### 4.7 Evil twin

The backend starts `hostapd`, `dnsmasq`, and the Python portal helper, but it does **not** create the AP interface or assign its IP address. `wlo1ap` in the form is only an example name. If the interface does not exist, hostapd logs `Interface wlo1ap wasn't started`, `No such device`, and dnsmasq logs `unknown interface wlo1ap`.

Start by listing the real interfaces and checking AP support:

```sh
iw dev
iw list | sed -n '/Supported interface modes/,/Band 1/p'
```

Choose one of these lab setups:

- **Separate AP adapter (recommended):** keep the monitor adapter receiving and use a second AP-capable interface for the evil twin.
- **Single-radio switch:** stop passive capture, switch the monitor interface to managed mode, use it as the AP, then switch it back to monitor after the exercise.
- **Built-in AP plus USB monitor:** create a virtual AP interface on the built-in radio. If its driver allows only one channel across managed and AP interfaces, the AP must use the same channel as the existing managed connection.

For a single-radio switch, replace `wlp5s0f3u1` with your monitor interface and stop capture in **Session → Capture health** first:

```sh
sudo nmcli device set wlp5s0f3u1 managed no
sudo ip link set wlp5s0f3u1 down
sudo iw dev wlp5s0f3u1 set type managed
sudo ip link set wlp5s0f3u1 up
sudo ip addr replace 10.0.0.1/24 dev wlp5s0f3u1
```

Then open Ops → **Evil twin** and enter the **actual interface name** (`wlp5s0f3u1` in this example), the SSID, channel, and portal port. The backend writes `/tmp/ewave-evil-twin/hostapd.conf`, `dnsmasq.conf`, and `portal_server.py`, then starts the three helpers.

Connect the test client to the open SSID. `dnsmasq` serves `10.0.0.10–10.0.0.100` with `10.0.0.1` as gateway/DNS. Open `http://10.0.0.1/` from the client. The current helper returns a JSON service status on `GET`; there is no bundled HTML form. The `POST /submit` endpoint records form fields. For a lab exercise, submit a test form:

```sh
curl -X POST -d 'username=lab-user&password=lab-pass' http://10.0.0.1/submit
```

The response is `{"status":"recorded"}`. Watch the Ops credentials table or `/tmp/ewave-portal-creds.txt` for the recorded test values.

Stop the operation. For the single-radio flow, restore the interface to monitor mode and restart capture:

```sh
sudo ip addr flush dev wlp5s0f3u1
sudo ip link set wlp5s0f3u1 down
sudo iw dev wlp5s0f3u1 set type monitor
sudo ip link set wlp5s0f3u1 up
```

If hostapd still reports `Driver does not support authentication/association or connect commands` after `iw dev` shows the interface in managed mode, that driver/interface cannot provide a usable AP. Use the built-in radio's AP interface or a second adapter instead.

Limits: the generated `hostapd` configuration is an open AP. A matching SSID does not make a client join automatically. The backend does not set the `10.0.0.1` address for you, and the bundled portal has no HTML page. Use dummy credentials only.

### 4.8 Stop and cleanup

1. Click **Stop operation** if the operation is still running.
2. Stop passive capture in **Session → Capture health** if you are finished.
3. Exit `./ewave` with `Ctrl+C`.
4. Confirm the adapter returned to managed mode:

   ```sh
   iw dev
   nmcli device status
   ```

5. If restoration failed, run:

   ```sh
   ./ewave restore IFACE
   ```

## 5. Replay and evidence

- **Replay** runs a PCAP through the passive modules without a radio. Ops endpoints are unavailable in replay; this is intentional because active operations need a live interface and a current target.
- **Session → Saved results** imports and replays local PCAPs. Imports are limited to 128 MiB per file and persist in `~/.local/share/ewave/recordings`.
- Record the session, capture mode, channel, timestamps, frame counts, target, operation command/output, and result.
- Sanitize SSIDs, MAC addresses, captured keys, and portal credentials before sharing a report.

## 6. Suggested 90-minute practical sequence

| Step | Time | Activity | Checkpoint |
| --- | ---: | --- | --- |
| 1 | 10 min | Prepare AP/client, install tools, build, start Live Wi-Fi | Capture health shows frames |
| 2 | 15 min | Sniper search/follow, Spotter clients/topology, Inspector fields | AP locked, client observed, security read |
| 3 | 15 min | Hidden SSID + Whistleblower, client probes + De-cloaker | Name reveal or explicit no-reveal, probe corpus |
| 4 | 20 min | Profiler inventory/signals, Tracker reassociation, Lookout channels | Device evidence, AP change, channel samples |
| 5 | 10 min | Ops readiness, deauth/uncloak | Command output, client reconnect, name evidence |
| 6 | 10 min | Handshake capture and PSK verification | CAPTURE outcome, verification result |
| 7 | 15 min | PMKID, beacon, evil twin | PMKID result, beacon visible, portal credential row |
| 8 | 5 min | Stop, restore, sanitize evidence | Adapter managed, report complete |

## 7. Troubleshooting

| Symptom | Check |
| --- | --- |
| No adapter listed | `iw dev`; driver support; adapter not in use by another process |
| Monitor mode fails | `./ewave` → Setup; try `./ewave restore IFACE`; re-plug adapter |
| Dashboard does not open | Launcher log path; Vite installed; port; API on 7070 |
| No frames | Monitor interface, channel, capture running, capture health counts |
| Ops unavailable | Replay is passive-only; use **Live Wi-Fi**; verify the session is running |
| Ops shows missing tools | Install the package from the readiness strip; click refresh |
| Operation returns 409 | Another operation owns the slot/radio; click **Stop operation** |
| No Ops targets | Connect the test client, generate traffic, wait for passive evidence |
| No hidden-name reveal | Hidden AP must have an associated client; capture the revealing frame |
| No handshake | Reconnect the client while the status is **Ready**; check channel and MFP |
| PMKID empty | Adapter/tool compatibility, duration, nearby test AP; inspect output |
| Beacon not visible | Correct monitor interface/channel; rate; independent scanner |
| Evil twin no DHCP | AP interface is separate and up; `10.0.0.1/24` assigned; hostapd/dnsmasq logs |
| Adapter still monitor after exit | `./ewave restore IFACE`; `nmcli device status` |

## 8. Authorization and containment

- Run active operations only on devices and networks you own.
- Keep the lab on a controlled channel and low power; do not target neighboring networks.
- Use dummy portal credentials.
- Treat captured handshakes, PMKIDs, keys, MAC addresses, and portal credentials as sensitive.
- Stop operations and restore the adapter when the exercise ends.
