package ewave;

import ewave.capture.PacketBridge;
import ewave.capture.BleBridge;
import ewave.core.AdaptiveScanner;
import ewave.ui.PassiveRfServer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/** Command-line entry point for ewave capture and its web UI. */
public final class Ewave {
    private Ewave() { }

    public static void main(String[] args) throws IOException, InterruptedException {
        String iface = "wlo1";
        int port = 7070;
        int bands = 13;
        boolean probes = false;
        boolean ble = false;
        boolean passiveRf = false;
        boolean adaptive = false;
        boolean ops = false;
        int hci = 0;
        Path replay = null;
        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            if (option.equals("--help")) {
                System.out.println("Usage: java -jar ewave-0.1.0-SNAPSHOT.jar [--iface INTERFACE] [--port PORT] [--bands BANDS] [--passive-rf] [--adaptive] [--ops] [--probes] [--ble] [--hci INDEX] [--replay FILE]");
                System.out.println("--passive-rf: privacy-filtered reports on loopback. Wi-Fi by default, --ble for BLE only, --probes --ble for both.");
                System.out.println("--adaptive: combine channel hopping and Spectrum with --passive-rf on a prepared monitor interface.");
                System.out.println("--ops: enable the local lab operations when using --passive-rf.");
                System.out.println("--probes: passively decode Wi-Fi probe requests on a prepared monitor-mode interface.");
                System.out.println("--ble: passive BLE advertisements (Python 3/Linux); --hci selects the adapter (default 0).");
                System.out.println("--replay FILE: process an 802.11 PCAP offline using its capture timestamps.");
                System.out.println("--ble runs BLE only; combine --ble --probes for both radios.");
                return;
            }
            if (option.equals("--probes")) {
                probes = true;
                continue;
            }
            if (option.equals("--passive-rf")) { passiveRf = true; continue; }
            if (option.equals("--adaptive")) { adaptive = true; continue; }
            if (option.equals("--ops")) { ops = true; continue; }
            if (option.equals("--ble")) { ble = true; continue; }
            if (!option.equals("--iface") && !option.equals("--port") && !option.equals("--bands") && !option.equals("--hci") && !option.equals("--replay")) {
                throw new IllegalArgumentException("Unknown option: " + option);
            }
            if (++i == args.length || args[i].startsWith("--")) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            switch (option) {
                case "--iface" -> iface = args[i];
                case "--port" -> port = Integer.parseInt(args[i]);
                case "--bands" -> bands = Integer.parseInt(args[i]);
                case "--hci" -> hci = Integer.parseInt(args[i]);
                case "--replay" -> replay = Path.of(args[i]);
                default -> throw new AssertionError(option);
            }
        }
        if (iface.isBlank()) throw new IllegalArgumentException("Interface must not be blank");
        if (port < 0 || port > 65535) throw new IllegalArgumentException("Port must be in 0..65535");
        if (hci < 0 || hci > 65535) throw new IllegalArgumentException("HCI adapter index must be in 0..65535");

        if (replay != null && (ops || probes || ble))
            throw new IllegalArgumentException("--replay cannot be combined with --ops, --probes or --ble");
        boolean operations = replay == null && (ops || !passiveRf);
        boolean monitor = probes || passiveRf && !ble;
        if (adaptive && (!passiveRf || !monitor || replay != null || ops))
            throw new IllegalArgumentException("--adaptive requires passive Wi-Fi capture without --ops or --replay");
        var shutdown = new CountDownLatch(1);
        try (var bridge = new PacketBridge(); var bluetooth = new BleBridge(bridge.getEventQueue(), bridge.getProfiler());
             var server = new PassiveRfServer(bridge, bluetooth, operations)) {
            Thread hook = new Thread(() -> {
                try {
                    try { bridge.stop(); } finally { bluetooth.stop(); }
                } finally {
                    try { server.close(); } finally { shutdown.countDown(); }
                }
            }, "ewave-shutdown");
            Runtime.getRuntime().addShutdownHook(hook);
            try {
                if (replay != null) bridge.startReplay(replay);
                else if (monitor) bridge.startPassive(iface, operations,
                        adaptive ? new AdaptiveScanner(AdaptiveScanner.Config.defaults(bands, 2048, 42L)) : null);
                else if (!ble) bridge.start(iface, new AdaptiveScanner(AdaptiveScanner.Config.defaults(bands, 2048, 42L)));
                if (ble) bluetooth.startPassive(hci);
                server.start(port);
                System.out.println("ewave running on http://127.0.0.1:" + server.port());
                shutdown.await();
            } finally {
                try { Runtime.getRuntime().removeShutdownHook(hook); }
                catch (IllegalStateException shuttingDown) { /* The JVM is already running the hook. */ }
            }
        }
    }
}
