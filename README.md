# ewave

ewave is a local Wi-Fi analysis dashboard. It captures or replays Wi-Fi traffic,
audits probe requests, and visualizes observed devices and channel activity. An
adaptive scanner scores channels from recorded observations. The dashboard binds
to loopback.

## Quick start

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
The adaptive run uses the scanner's scoring model with a fixed seed and a
simulated 25 ms channel-change delay. Round-robin advances one channel per
100 ms tick with the same retune cost. The fixed run stays on channel 6.
Compare the first captured frame per burst, listening time, and missed frames.
The missed-frame counts come from the fixture's known transmissions.
**Compare listening policies** in Probe Lab opens this separate benchmark.

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
also revisits channels 1–13 in order. A survey starts about once per second
at the default tick rate and listens for at least 250 ms after a successful
tune. The scores steer the receiver between surveys. Slower ticks and
retune delays can lengthen the sweep. Stop each trial with Ctrl+C.

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
| Wi-Fi summary and spectrum | `--iface wlo1` |
| Passive Wi-Fi inventory and probe audit | `--passive-rf --iface wlo1` |
| Live Intel and adaptive Spectrum on a monitor interface | `--passive-rf --adaptive --iface wlo1` |

Wi-Fi summary mode uses the current interface configuration and requests 2.4 GHz
channel changes through `sudo iw` as the adaptive scanner selects channels.
Run the JAR with `--help` for all launcher options. Passive RF mode disables lab operations
by default. The standard live launcher enables the Ops controls. Use these
controls only on networks and devices you are authorized to test.

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
| `tools/` | Numerical comparison tools |

## Development

```sh
mvn test
```

The scanner also has a separate CSV replay entry point. Run
`java -cp target/ewave-0.1.0-SNAPSHOT.jar ewave.core.Main --help` for its input
format and usage.

## License

[MIT](LICENSE)
