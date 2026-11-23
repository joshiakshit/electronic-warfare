package ewave;

import ewave.capture.PacketBridge;
import ewave.core.AdaptiveScanner;
import ewave.ui.PassiveRfServer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;

/** Command-line entry point for ewave capture and local HTTP/WebSocket API server. */
public final class Ewave {
    public enum Mode { HELP, IDLE, CAPTURE, REPLAY }

    public record LaunchPlan(Mode mode, String iface, int port, int bands, int tickMs,
                             boolean adaptive, boolean operations, Path replay) {}

    public record LaunchConfig(LaunchPlan plan, Integer frequencyMhz,
                               Boolean revealProbes, String scope, Path profile) {}

    private Ewave() { }

    public static LaunchPlan parse(String... args) {
        return parseConfig(args).plan();
    }

    public static LaunchConfig parseConfig(String... args) {
        String iface = "wlo1";
        boolean ifaceSpecified = false;
        int port = 7070;
        int bands = 13;
        int tickMs = PacketBridge.DEFAULT_TICK_MS;
        boolean passiveRf = false;
        boolean adaptive = false;
        Integer freqMhz = null;
        Integer channel = null;
        String band = null;
        Boolean revealProbes = null;
        String scope = null;
        Path profile = null;
        Path replay = null;
        for (int i = 0; i < args.length; i++) {
            String option = args[i];
            switch (option) {
                case "--help", "-h" -> {
                    var helpPlan = new LaunchPlan(Mode.HELP, iface, port, bands, tickMs, false, false, null);
                    return new LaunchConfig(helpPlan, null, null, null, null);
                }
                case "--probes" -> throw new IllegalArgumentException(
                        "--probes text capture has been removed; use De-cloaker on binary capture (--iface <iface> or --replay <pcap>)");
                case "--passive-rf" -> passiveRf = true;
                case "--adaptive" -> adaptive = true;
                case "--reveal-probes" -> {
                    if (Boolean.FALSE.equals(revealProbes))
                        throw new IllegalArgumentException("--reveal-probes cannot be combined with --hide-probes");
                    revealProbes = Boolean.TRUE;
                }
                case "--hide-probes" -> {
                    if (Boolean.TRUE.equals(revealProbes))
                        throw new IllegalArgumentException("--reveal-probes cannot be combined with --hide-probes");
                    revealProbes = Boolean.FALSE;
                }
                case "--iface" -> {
                    iface = optionValue(args, ++i, option);
                    ifaceSpecified = true;
                }
                case "--port" -> port = Integer.parseInt(optionValue(args, ++i, option));
                case "--tick-ms" -> tickMs = Integer.parseInt(optionValue(args, ++i, option));
                case "--bands" -> bands = Integer.parseInt(optionValue(args, ++i, option));
                case "--freq" -> freqMhz = Integer.parseInt(optionValue(args, ++i, option));
                case "--channel" -> channel = Integer.parseInt(optionValue(args, ++i, option));
                case "--band" -> band = optionValue(args, ++i, option);
                case "--scope" -> scope = optionValue(args, ++i, option);
                case "--profile" -> profile = Path.of(optionValue(args, ++i, option));
                case "--replay" -> replay = Path.of(optionValue(args, ++i, option));
                default -> throw new IllegalArgumentException("Unknown option: " + option);
            }
        }
        if (iface.isBlank()) throw new IllegalArgumentException("Interface must not be blank");
        if (port < 0 || port > 65535) throw new IllegalArgumentException("Port must be in 0..65535");
        if (tickMs < 10 || tickMs > 2000) throw new IllegalArgumentException("--tick-ms must be 10..2000");
        if (bands < 13) throw new IllegalArgumentException("Channels 1..13 require at least 13 scanner bands");
        if (freqMhz != null && (freqMhz < 2300 || freqMhz > 7125))
            throw new IllegalArgumentException("--freq must be in 2300..7125 MHz");
        if (freqMhz != null && (channel != null || band != null))
            throw new IllegalArgumentException("--freq cannot be combined with --channel or --band");
        if (band != null && channel == null)
            throw new IllegalArgumentException("--band requires --channel");
        Integer resolvedFreq = freqMhz != null ? freqMhz : channel == null ? null : resolveFrequency(channel, band);
        if (replay != null && replay.toString().isBlank())
            throw new IllegalArgumentException("Replay file must not be blank");
        if (replay != null && (passiveRf || adaptive || ifaceSpecified || resolvedFreq != null))
            throw new IllegalArgumentException("--replay cannot be combined with --iface, --passive-rf, --adaptive, --freq, or --channel");
        if (adaptive && !passiveRf && !ifaceSpecified && resolvedFreq == null)
            throw new IllegalArgumentException("--adaptive requires --iface (or --passive-rf)");
        if (adaptive && resolvedFreq != null)
            throw new IllegalArgumentException("--freq/--channel cannot be combined with --adaptive");
        if (scope != null && scope.isBlank())
            throw new IllegalArgumentException("--scope must not be blank");
        if (profile != null && profile.toString().isBlank())
            throw new IllegalArgumentException("--profile must not be blank");

        LaunchPlan plan;
        if (replay != null) plan = new LaunchPlan(Mode.REPLAY, iface, port, bands, tickMs, false, false, replay);
        else if (passiveRf || ifaceSpecified || adaptive || resolvedFreq != null)
            plan = new LaunchPlan(Mode.CAPTURE, iface, port, bands, tickMs, adaptive, true, null);
        else plan = new LaunchPlan(Mode.IDLE, iface, port, bands, tickMs, false, true, null);
        return new LaunchConfig(plan, resolvedFreq, revealProbes, scope, profile);
    }

    public static int resolveFrequency(int channel, String band) {
        if (channel < 1 || channel > 233) throw new IllegalArgumentException("--channel must be in 1..233");
        if (band == null) {
            if (channel <= 13 || channel == 14 || (channel >= 149 && channel <= 177)) {
                if (channel == 14) return 2484;
                throw new IllegalArgumentException("Channel " + channel
                        + " is ambiguous across Wi-Fi bands; specify --band 2.4, 5, or 6 (or use --freq MHz)");
            }
            if (channel >= 32 && channel <= 144 && channel % 4 == 0) return 5000 + 5 * channel;
            throw new IllegalArgumentException("Channel " + channel
                    + " requires --band 2.4, 5, or 6 (or use --freq MHz)");
        }
        String normalized = band.strip().toLowerCase(Locale.ROOT).replace("ghz", "").strip();
        return switch (normalized) {
            case "2.4", "24" -> {
                if (channel == 14) yield 2484;
                if (channel >= 1 && channel <= 13) yield 2407 + 5 * channel;
                throw new IllegalArgumentException("2.4 GHz supports channels 1..14");
            }
            case "5" -> {
                if (channel >= 32 && channel <= 177) yield 5000 + 5 * channel;
                throw new IllegalArgumentException("5 GHz supports channels 32..177");
            }
            case "6" -> {
                if (channel == 2) yield 5935;
                if (channel >= 1 && channel <= 233 && (channel - 1) % 4 == 0) yield 5950 + 5 * channel;
                throw new IllegalArgumentException("6 GHz supports channel 2 and 1, 5, 9, ... 233");
            }
            default -> throw new IllegalArgumentException("Unsupported --band: " + band + " (expected 2.4, 5, or 6)");
        };
    }

    private static String optionValue(String[] args, int index, String option) {
        if (index >= args.length || args[index].startsWith("--")) {
            throw new IllegalArgumentException("Missing value for " + option);
        }
        return args[index];
    }

    public static void startCapture(LaunchPlan plan, PacketBridge bridge) throws IOException {
        startCapture(new LaunchConfig(plan, null, null, null, null), bridge);
    }

    public static void startCapture(LaunchConfig config, PacketBridge bridge) throws IOException {
        LaunchPlan plan = config.plan();
        int anomalyHistory = Math.max(60, Math.ceilDiv(6000, plan.tickMs()));
        if (config.frequencyMhz() != null) {
            bridge.setFixedFrequencyMhz(config.frequencyMhz());
        }
        switch (plan.mode()) {
            case IDLE -> { }
            case REPLAY -> bridge.startReplay(plan.replay());
            case CAPTURE -> bridge.startPassive(plan.iface(), plan.operations(), plan.adaptive()
                    ? new AdaptiveScanner(AdaptiveScanner.Config.defaults(plan.bands(), 2048, 42L), anomalyHistory) : null);
            case HELP -> throw new IllegalArgumentException("Cannot start capture for help mode");
        }
    }

    private static void printHelp() {
        System.out.println("Usage: java -jar ewave-0.1.0-SNAPSHOT.jar [options]");
        System.out.println("  --iface INTERFACE     Wireless capture interface (default: wlo1)");
        System.out.println("  --adaptive            2.4 GHz channel hopping during live capture");
        System.out.println("  --freq MHz            Initial frequency in MHz (2300..7125)");
        System.out.println("  --channel CH --band B Channel + band (2.4, 5, or 6) converted to frequency");
        System.out.println("  --replay FILE         Replay an 802.11 PCAP file offline");
        System.out.println("  --reveal-probes       Reveal client-probed SSIDs in De-cloaker");
        System.out.println("  --hide-probes         Mask client-probed SSIDs in De-cloaker");
        System.out.println("  --scope BSSID,...     Restrict passive scope to comma-separated BSSIDs");
        System.out.println("  --profile FILE        Path to My Network JSON profile");
        System.out.println("  --port PORT           Loopback HTTP/WebSocket port (default: 7070, 0 = auto)");
        System.out.println("Advanced: --tick-ms MS (10..2000), --bands BANDS (>= 13), --passive-rf (compat)");
    }

    private static void applySystemProperties(LaunchConfig config) {
        if (config.revealProbes() != null) {
            System.setProperty("audit.revealSsids", Boolean.toString(config.revealProbes()));
        }
        if (config.scope() != null) {
            System.setProperty("rf.bssids", config.scope());
        }
        if (config.profile() != null) {
            System.setProperty("rf.networkProfile", config.profile().toAbsolutePath().toString());
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        LaunchConfig config = parseConfig(args);
        LaunchPlan plan = config.plan();
        if (plan.mode() == Mode.HELP) {
            printHelp();
            return;
        }
        applySystemProperties(config);
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
                startCapture(config, bridge);
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
