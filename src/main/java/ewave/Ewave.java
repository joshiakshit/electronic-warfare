package ewave;

import ewave.capture.PacketBridge;
import ewave.core.AdaptiveScanner;
import ewave.ui.PassiveRfServer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;

/** Command-line entry point for ewave capture and its web UI. */
public final class Ewave {
    public enum Mode { HELP, PACKETS, PROBES, PASSIVE_RF, REPLAY }

    public record LaunchPlan(Mode mode, String iface, int port, int bands, int tickMs,
                             boolean adaptive, boolean operations, Path replay) {}

    private Ewave() { }

    public static LaunchPlan parse(String... args) {
        String iface = "wlo1";
        boolean ifaceSpecified = false;
        int port = 7070;
        int bands = 13;
        int tickMs = PacketBridge.DEFAULT_TICK_MS;
        boolean probes = false;
        boolean passiveRf = false;
        boolean adaptive = false;
        boolean ops = false;
        Path replay = null;
        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--help" -> {
                    return new LaunchPlan(Mode.HELP, iface, port, bands, tickMs, false, false, null);
                }
                case "--probes" -> probes = true;
                case "--passive-rf" -> passiveRf = true;
                case "--adaptive" -> adaptive = true;
                case "--ops" -> ops = true;
                case "--iface" -> {
                    iface = optionValue(args, ++i, option);
                    ifaceSpecified = true;
                }
                case "--port" -> port = Integer.parseInt(optionValue(args, ++i, option));
                case "--tick-ms" -> tickMs = Integer.parseInt(optionValue(args, ++i, option));
                case "--bands" -> bands = Integer.parseInt(optionValue(args, ++i, option));
                case "--replay" -> replay = Path.of(optionValue(args, ++i, option));
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        if (iface.isBlank()) throw new IllegalArgumentException("Interface must not be blank");
        if (port < 0 || port > 65535) throw new IllegalArgumentException("Port must be in 0..65535");
        if (tickMs < 10 || tickMs > 2000) throw new IllegalArgumentException("--tick-ms must be 10..2000");
        if (bands < 13) throw new IllegalArgumentException("Channels 1..13 require at least 13 scanner bands");
        if (replay != null && replay.toString().isBlank())
            throw new IllegalArgumentException("Replay file must not be blank");
        if (replay != null && (passiveRf || probes || adaptive || ops || ifaceSpecified))
            throw new IllegalArgumentException("--replay cannot be combined with --iface, --passive-rf, --adaptive, --ops, or --probes");
        if (probes && (passiveRf || adaptive || ops))
            throw new IllegalArgumentException("--probes cannot be combined with --passive-rf, --adaptive, or --ops");
        if (adaptive && (!passiveRf || ops))
            throw new IllegalArgumentException("--adaptive requires passive Wi-Fi capture without --ops or --replay");
        if (ops && !passiveRf)
            throw new IllegalArgumentException("--ops requires --passive-rf; standard live capture already enables lab operations");

        if (replay != null) return new LaunchPlan(Mode.REPLAY, iface, port, bands, tickMs, false, false, replay);
        if (probes) return new LaunchPlan(Mode.PROBES, iface, port, bands, tickMs, false, true, null);
        if (passiveRf) return new LaunchPlan(Mode.PASSIVE_RF, iface, port, bands, tickMs, adaptive, ops, null);
        return new LaunchPlan(Mode.PACKETS, iface, port, bands, tickMs, true, true, null);
    }

    private static String optionValue(String[] args, int index, String option) {
        if (index >= args.length || args[index].startsWith("--")) {
            throw new IllegalArgumentException("Missing value for " + option);
        }
        return args[index];
    }

    public static void startCapture(LaunchPlan plan, PacketBridge bridge) throws IOException {
        int anomalyHistory = Math.max(60, Math.ceilDiv(6000, plan.tickMs()));
        switch (plan.mode()) {
            case REPLAY -> bridge.startReplay(plan.replay());
            case PROBES -> bridge.startProbes(plan.iface());
            case PASSIVE_RF -> bridge.startPassive(plan.iface(), plan.operations(), plan.adaptive()
                    ? new AdaptiveScanner(AdaptiveScanner.Config.defaults(plan.bands(), 2048, 42L), anomalyHistory) : null);
            case PACKETS -> bridge.start(plan.iface(),
                    new AdaptiveScanner(AdaptiveScanner.Config.defaults(plan.bands(), 2048, 42L), anomalyHistory));
            case HELP -> throw new IllegalArgumentException("Cannot start capture for help mode");
        }
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar ewave-0.1.0-SNAPSHOT.jar [--iface INTERFACE] [--port PORT] [--bands BANDS] [--tick-ms MS] [--passive-rf] [--adaptive] [--ops] [--probes] [--replay FILE]");
        System.out.println("Default (no mode flag): live Wi-Fi summary, spectrum scanner, and lab operations.");
        System.out.println("--passive-rf: privacy-filtered reports on loopback. Capture Wi-Fi in monitor mode.");
        System.out.println("--adaptive: combine channel hopping and Spectrum with --passive-rf on a prepared monitor interface.");
        System.out.println("--tick-ms MS: scanner tick (default 100, range 10..2000). Anomaly history covers at least six seconds of valid observations.");
        System.out.println("--ops: enable the local lab operations when using --passive-rf.");
        System.out.println("--probes: decode named Wi-Fi probe requests (text mode with lab operations) on a prepared monitor interface.");
        System.out.println("--replay FILE: process an 802.11 PCAP offline using its capture timestamps.");
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        LaunchPlan plan = parse(args);
        if (plan.mode() == Mode.HELP) {
            printHelp();
            return;
        }
        var shutdown = new CountDownLatch(1);
        try (var bridge = new PacketBridge(plan.tickMs());
             var server = new PassiveRfServer(bridge, plan.operations())) {
            Thread hook = new Thread(() -> {
                try {
                    bridge.stop();
                } finally {
                    try { server.close(); } finally { shutdown.countDown(); }
                }
            }, "ewave-shutdown");
            Runtime.getRuntime().addShutdownHook(hook);
            try {
                startCapture(plan, bridge);
                server.start(plan.port());
                System.out.println("ewave API running on http://127.0.0.1:" + server.port());
                shutdown.await();
            } finally {
                try { Runtime.getRuntime().removeShutdownHook(hook); }
                catch (IllegalStateException shuttingDown) { /* The JVM is already running the hook. */ }
            }
        }
    }
}
