# ewave

ewave is a local Wi-Fi analysis dashboard. It captures or replays Wi-Fi traffic,
audits probe requests, and visualizes observed devices and channel activity. An
adaptive scanner scores channels from recorded observations. The dashboard binds
to loopback.

## Quick start

The repository includes a single launcher. Install JDK 21 or newer and Maven,
then run:

```sh
./ewave                     # Build if needed, then open the offline demo
./ewave replay capture.pcap # Replay your own classic 802.11 PCAP
./ewave doctor              # Report dependencies and wireless interfaces
./ewave live wlan0mon       # Passive capture on a prepared monitor interface
./ewave live wlan0mon --adaptive # Add 2.4 GHz channel hopping
```

Open the loopback URL printed at startup; press Ctrl+C to stop. Add `--port 0`
to choose an available port. Live capture requires Linux, `tcpdump`, capture
permissions, and a monitor-capable adapter already configured in monitor mode.
Channel hopping also requires `iw` and permission to run `sudo iw`. The launcher
does not install tools or change the adapter mode. `doctor` reports tool
availability; it does not verify capture permissions or successful reception.

The launcher runs `mvn package` when the JAR is missing or source files are newer.
An up-to-date build needs only Java to replay. Use `./ewave build` to force a
build, or `./ewave --help` for shortcuts and advanced flag passthrough. For
example, `./ewave --probes --iface wlan0mon` retains the text probe mode and
`./ewave live wlan0mon --ops` enables authorized lab operations.

To mask network names in replay:

```sh
JAVA_TOOL_OPTIONS=-Daudit.revealSsids=false ./ewave replay capture.pcap
```

You can also build and run the JAR directly:

Install Java 21 or newer and Maven, then build the runnable JAR.

```sh
git clone https://github.com/joshiakshit/electronic-warfare.git
cd electronic-warfare
mvn clean package
```

Try the dashboard with the bundled synthetic capture. Once the JAR is built,
replay and the dashboard work without internet access, radio hardware, or
elevated privileges.

```sh
java -jar target/ewave-0.1.0-SNAPSHOT.jar \
  --replay src/test/resources/probes/probe-requests.pcap --port 0
```

Open the loopback URL printed at startup. Replay processes four probe requests
and leaves the dashboard available for inspection. Press Ctrl+C to stop it.

## Using the dashboard

New to ewave? Open **Start here** in the sidebar for a short guide to the views,
the numbers, and a suggested tour. Each view also has a **How to read** section.
The theme control at the bottom of the sidebar switches between **Paper**,
**Dusk**, and **Midnight**; the choice is saved in the browser.

## Probe Lab demo

Open **Probe Lab** and select **Built-in example**, or append `#probe-demo`
to the printed URL, to see a finding from a sample Wi-Fi request.
Expand **See the two decoded requests** to compare a named request with
one that asks about nearby networks in general.
ewave decodes both synthetic frames with the monitor-capture parser and shows
the receive channel and the name carried in the frame, if any. The replay
leaves the current capture and its privacy settings alone.

Use **Current capture** for a prepared lab receiver and a pretested lab phone.
The finding shows how many observed requests carried names. Names are visible
by default in files opened with `--replay` and masked by default in live
capture. Use `-Daudit.revealSsids=false` before `-jar` to mask replay names for
sharing, or `-Daudit.revealSsids=true` to show names in a controlled live lab.
Append `#probe` to the URL to open the current capture's findings directly.

**Map → Hidden network names** lists access points whose beacons omit the
network name. When a received probe response, association request, or
reassociation request supplies a name for that access point, ewave shows
the frame type and timestamp. The same replay and live name visibility
settings apply here. To try it offline, replay
`src/test/resources/probes/hidden-network.pcap` and choose **All access
points** in the **Map** focus menu. The fixture contains two hidden
beacons and a named response from one of those access points.

## Adaptive scanner demo

Open **Spectrum** and select **Run comparison**. This works in offline replay
with the bundled JAR. All three policies start on channel 6 and receive the same
12-second scripted scenario, with frame bursts on channels 6, 11, and 1.
The adaptive run uses the live passive discovery policy and a simulated
25 ms channel-change delay. Round-robin advances one channel per
100 ms tick with the same retune cost. The fixed run stays on channel 6.
Compare the first captured frame per burst, listening time, and missed frames.
The missed-frame counts come from the fixture's known transmissions.
**Compare listening policies** in Probe Lab opens this separate benchmark.
See the [offline evaluation](tools/passive-scanner.md) for the before-and-after
results, per-burst delays, and commands to repeat the experiments.

### Repeat the comparison on a lab radio

Before each run, check **Capture health → Capture readiness** for the adapter
mode and recent frame reception. In adaptive mode it also shows which channels
have received a frame while tuned there after a successful tune in this session.

Use an isolated C20 and a prepared monitor interface. Manage the router over
Ethernet so changing its 2.4 GHz channel does not disconnect the control
session. Use a dedicated lab SSID and confirm you can identify the router's
beacons. Keep the monitor and router in the same positions between trials.

1. Start the fixed trial with the monitor tuned to channel 6. Run
   `java -jar target/ewave-0.1.0-SNAPSHOT.jar --passive-rf --iface wlo1 --port 0`
   and check the channel in **Capture health**. Change the C20 from 6 to 11
   and then to 1, recording when its beacons start on each channel.
2. Return the C20 to channel 6. Repeat the same sequence and dwell durations
   with `--passive-rf --adaptive --iface wlo1 --port 0`. In **Spectrum**,
   compare the requested channel, the successful tune command, and the
   channel reported by the most recent received frame. Record successful
   command times and listening time by channel. Repeat both trials to
   account for channel-change timing variation.
3. For per-burst detection latency, record the first C20 beacon observed
   on each channel and compare it with a timestamped reference capture of
   the burst onset. Use a separate receiver or transmitter-side ground truth
   for absolute frame misses. ewave's receive counts alone cannot establish
   how many frames went unheard.

For a live comparison in the dashboard, open **Spectrum → Watch an access
point**. Find the lab AP by its exact Wi-Fi name, start the watch, and wait for
a fresh frame before changing the router's channel. The watch ends at the
first observation on a different channel. Use **Stop watch** to record a fixed
run that never observes the move. **Save run** keeps up to ten results in the
browser for the dashboard address, so use the same port for both trials.
The observation gap includes any time spent changing the AP's channel.
In a live adaptive run, **Spectrum → Channel coverage** shows the last
successful tune and the last decoded frame on each 2.4 GHz channel. It marks
channels where the radio confirmed a tune and no newer frame was decoded.

The router's channel changes are a hardware analogue of the scripted
bursts. The fixture delay is a model input, while the live dashboard
reports elapsed time for successful tune commands. Live passive adaptive mode
visits channels 1–13 in order. After tuning, it listens for at least 100 ms
and gives slower tune commands a longer minimum dwell (up to 500 ms).
Recent decoded frames extend the visit up to 1.2 seconds, checked at the
next timer tick. The Spectrum view still displays model scores. Slower
ticks and retune delays can lengthen the sweep. Stop each trial with Ctrl+C.

## Live capture

Live Wi-Fi capture requires Linux, `tcpdump`, capture permissions, and a
compatible adapter.

Replace `wlo1` with the appropriate Wi-Fi interface. Prepare monitor
mode for passive Wi-Fi inventory and adaptive capture.

For example, to start passive Wi-Fi capture from the repository root:

```sh
java -jar target/ewave-0.1.0-SNAPSHOT.jar --passive-rf --iface wlo1
```

| Mode | Arguments after the JAR path |
| --- | --- |
| Wi-Fi summary and spectrum (with Ops) | `--iface wlo1` |
| Passive Wi-Fi inventory and probe audit | `--passive-rf --iface wlo1` |
| Live device inventory and adaptive Spectrum on a monitor interface | `--passive-rf --adaptive --iface wlo1` |
| Passive Wi-Fi with authorized lab operations | `--passive-rf --ops --iface wlo1` |
| Text probe-request stream (with Ops) on a monitor interface | `--probes --iface wlo1` |
| Offline 802.11 PCAP replay | `--replay <file>` |

Wi-Fi summary mode uses the current interface configuration and requests 2.4 GHz
channel changes through `sudo iw` as the adaptive scanner selects channels.
Run the JAR with `--help` for all launcher options. Passive RF and replay modes
disable lab operations by default (`--passive-rf --ops` enables them on passive
monitor capture), while the standard live and `--probes` modes enable the Ops
controls. Contradictory mode flag combinations (such as `--probes --passive-rf`,
`--probes --adaptive`, `--adaptive --ops`, or `--replay --iface`) fail before
capture starts. Use these controls only on networks and devices you are
authorized to test.

### Restoring networking after a live session

The launcher does not change the adapter mode or NetworkManager state; it starts
`tcpdump` and, in adaptive modes, requests channel changes with `sudo iw`. If
you moved the adapter to monitor mode yourself, restore managed mode after the
JAR has exited. Use an Ethernet or console session so the restore does not depend
on the captured radio.

```sh
sudo ip link set wlo1 down
sudo iw dev wlo1 set type managed
sudo ip link set wlo1 up
sudo systemctl start NetworkManager
```

Replace `wlo1` with the capture interface. Start NetworkManager after the
interface is back in managed mode, and reconnect with
`nmcli device wifi connect <SSID>` if Wi-Fi does not return. If setup failed
after NetworkManager was stopped, these commands are the supported recovery
path. They are safe to repeat.

The Ops **AP cache** and **LAN cache** views read snapshots taken while the
adapter is managed. Recreate them in managed mode if the dashboard reports them
missing (install `arp-scan` and `nmcli` first):

```sh
sudo arp-scan --localnet > /tmp/ewave-lan-hosts.txt
sudo nmcli --terse --escape yes --fields SSID,BSSID,CHAN,FREQ \
  device wifi list ifname wlo1 --rescan yes > /tmp/ewave-wifi-aps.txt
```

Restart ewave after recreating the caches. API errors for a missing cache point
here.

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
| `src/main/resources/` | Dashboard assets and classification rules |
| `src/test/` | Java tests and checked-in synthetic and numerical fixtures |
| `tools/` | Offline benchmarks, scanner trials, and their results |

## Development

```sh
mvn test
```

The scanner also has a separate CSV replay entry point. Run
`java -cp target/ewave-0.1.0-SNAPSHOT.jar ewave.core.Main --help` for its input
format and usage.

## License

[MIT](LICENSE)
