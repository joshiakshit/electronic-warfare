# ewave

ewave is a local RF analysis dashboard for Wi-Fi and Bluetooth Low Energy
(BLE). It captures or replays Wi-Fi traffic, audits probe requests, summarizes
BLE advertisements, and visualizes observed devices and channel activity. An
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

## Live capture

Live Wi-Fi capture requires Linux, `tcpdump`, capture permissions, and a
compatible adapter. Live BLE requires Linux, Python 3, capture permissions,
and a compatible HCI adapter.

Replace `wlo1` or HCI index `0` with the appropriate adapter. Prepare monitor
mode for passive Wi-Fi inventory and combined capture.

For example, to start passive Wi-Fi capture from the repository root:

```sh
java -jar target/ewave-0.1.0-SNAPSHOT.jar --passive-rf --iface wlo1
```

| Mode | Arguments after the JAR path |
| --- | --- |
| Wi-Fi summary and spectrum | `--iface wlo1` |
| Passive Wi-Fi inventory and probe audit | `--passive-rf --iface wlo1` |
| Live Intel and adaptive Spectrum on a monitor interface | `--passive-rf --adaptive --iface wlo1` |
| Passive BLE | `--passive-rf --ble --hci 0` |
| Passive Wi-Fi and BLE | `--passive-rf --probes --iface wlo1 --ble --hci 0` |

Wi-Fi summary mode uses the current interface configuration and requests 2.4 GHz
channel changes through `sudo iw` as the adaptive scanner selects channels.
Run the JAR with `--help` for all launcher options. Passive RF mode disables lab operations
by default. The standard live launcher enables the Ops controls. Use these
controls only on networks and devices you are authorized to test.

## Optional vendor and Bluetooth names

Capture, replay, and device classification work with the default build. The
full lookup catalogs are generated locally when you want Wi-Fi manufacturer
names or BLE registry matches for company IDs and service UUIDs.

For Wi-Fi names, install Wireshark's `tshark` and export its manufacturer table
from the repository root.

```sh
tshark -G manuf > src/main/resources/oui.txt
```

For BLE names, use Python 3 with PyYAML and a checkout of the
[Bluetooth SIG Assigned Numbers repository](https://bitbucket.org/bluetooth-SIG/public/).
Run the generator with the path to that checkout.

```sh
python3 tools/generate_ble_catalogs.py /path/to/bluetooth-sig-public
```

Run `mvn clean package` again to include the generated catalogs in your local JAR.
Keep the generated catalogs and any JAR built with them local. For a distributable
default build, package from a fresh checkout.

## Repository layout

| Path | Purpose |
| --- | --- |
| `src/main/java/ewave/` | Launcher, scanner, capture, decoders, device profiling, lab operations, and HTTP server |
| `src/main/resources/` | Dashboard assets, classification rules, and BLE capture helper |
| `src/test/` | Java tests and checked-in synthetic and numerical fixtures |
| `tools/` | Numerical comparison and optional BLE catalog generator |

## Development

```sh
mvn test
```

The scanner also has a separate CSV replay entry point. Run
`java -cp target/ewave-0.1.0-SNAPSHOT.jar ewave.core.Main --help` for its input
format and usage.

## License

[MIT](LICENSE)
