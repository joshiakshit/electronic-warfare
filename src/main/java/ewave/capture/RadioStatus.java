package ewave.capture;

import ewave.decoder.Dot11FrameDecoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.IntStream;

/** Reads receiver settings and physical-radio capabilities from sysfs and iw. */
public final class RadioStatus {
    private static final Pattern INTERFACE = Pattern.compile("[A-Za-z0-9_.-]{1,15}");
    private static final Pattern PHY_NAME = Pattern.compile("[A-Za-z0-9_.-]{1,63}");
    private static final Pattern CHANNEL = Pattern.compile(
            "(?m)^\\s*channel (\\d+) \\((\\d+) MHz\\), width: (\\d+) MHz(?: \\(([^)]+)\\))?");
    private static final Pattern TYPE = Pattern.compile("(?m)^\\s*type (\\S+)");
    private static final Pattern WIPHY = Pattern.compile("(?m)^\\s*wiphy\\s+(\\d+)");
    private static final Pattern PHY_FREQUENCY = Pattern.compile(
            "(?m)^\\h*\\*\\h+(\\d{4})(?:\\.0+)?\\h+MHz\\h+\\[(\\d{1,3})\\]([^\\r\\n]*)");
    static final List<Channel> FALLBACK_CHANNELS = IntStream.rangeClosed(1, 13)
            .mapToObj(channel -> new Channel(channel, 2407 + channel * 5, null, null)).toList();
    public record Settings(String interfaceType, Integer channel, Integer frequencyMhz, Integer widthMhz,
                           String widthMode, long sampledAt) { }
    public record Channel(int channel, int frequencyMhz, Boolean noIr, Boolean radarDetection) { }

    private RadioStatus() { }

    static Optional<List<Channel>> readChannels(String iface) {
        return readChannels(iface, RadioStatus::readWiphy, RadioStatus::readOutput);
    }

    static Optional<List<Channel>> readChannels(String iface, Function<String, String> wiphy,
                                                Function<List<String>, String> commandOutput) {
        if (iface == null || !INTERFACE.matcher(iface).matches() || iface.startsWith("-")) return Optional.empty();
        String phy = wiphy.apply(iface);
        if (phy == null || !PHY_NAME.matcher(phy).matches() || phy.startsWith("-")) return Optional.empty();
        return Optional.ofNullable(commandOutput.apply(List.of("iw", "phy", phy, "info")))
                .flatMap(RadioStatus::parseChannels);
    }

    static Optional<List<Channel>> parseChannels(String output) {
        var channels = new TreeMap<Integer, Channel>();
        var disabled = new HashSet<Integer>();
        var rows = PHY_FREQUENCY.matcher(output);
        while (rows.find()) {
            int frequency = Integer.parseInt(rows.group(1));
            int channel = Integer.parseInt(rows.group(2));
            if (channel == 0 || Dot11FrameDecoder.channel(frequency) != channel) continue;
            String flags = rows.group(3).toLowerCase(Locale.ROOT);
            if (flags.contains("disabled")) {
                disabled.add(frequency);
                continue;
            }
            var entry = new Channel(channel, frequency, flags.contains("no ir") || flags.contains("passive scan"),
                    flags.contains("radar detection"));
            channels.merge(frequency, entry, (a, b) -> new Channel(channel, frequency,
                    a.noIr() || b.noIr(), a.radarDetection() || b.radarDetection()));
        }
        if (channels.isEmpty() && disabled.isEmpty()) return Optional.empty();
        disabled.forEach(channels::remove);
        return Optional.of(List.copyOf(channels.values()));
    }

    private static String readOutput(List<String> command) {
        Process process = null;
        try {
            var builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().put("LC_ALL", "C");
            process = builder.start();
            var input = process.getInputStream();
            int limit = 1024 * 1024;
            var output = new FutureTask<>(() -> {
                try (input) { return input.readNBytes(limit); }
            });
            Thread.startVirtualThread(output);
            if (!process.waitFor(750, TimeUnit.MILLISECONDS) || process.exitValue() != 0) return null;
            byte[] bytes = output.get(100, TimeUnit.MILLISECONDS);
            return bytes.length < limit ? new String(bytes, StandardCharsets.UTF_8) : null;
        } catch (IOException | SecurityException | ExecutionException | TimeoutException unavailable) {
            return null;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
    }

    /** Discovers operator-prepared monitor interfaces without changing radio configuration. */
    public static List<String> monitorInterfaces() throws IOException {
        Path interfaces = Path.of("/sys/class/net");
        if (Files.notExists(interfaces)) return List.of();
        try (var entries = Files.list(interfaces)) {
            return entries.map(entry -> entry.getFileName().toString())
                    .filter(name -> {
                        Settings settings = read(name);
                        return settings != null && "monitor".equals(settings.interfaceType());
                    })
                    .sorted().toList();
        }
    }

    static String readWiphy(String iface) {
        if (iface == null || !INTERFACE.matcher(iface).matches() || iface.startsWith("-")) return iface;
        Path sysfs = Path.of("/sys/class/net", iface, "phy80211", "name");
        try {
            if (Files.isReadable(sysfs)) {
                String phy = Files.readString(sysfs, StandardCharsets.UTF_8).strip();
                if (!phy.isEmpty()) return phy;
            }
        } catch (IOException ignored) { /* Fall back to iw info below. */ }
        String output = readOutput(List.of("iw", "dev", iface, "info"));
        if (output == null) return iface;
        var match = WIPHY.matcher(output);
        return match.find() ? "phy" + match.group(1) : iface;
    }

    static Settings read(String iface) {
        if (iface == null || !INTERFACE.matcher(iface).matches() || iface.startsWith("-")) return null;
        String output = readOutput(List.of("iw", "dev", iface, "info"));
        return output == null ? null : parse(output, System.currentTimeMillis());
    }

    static Settings parse(String output, long now) {
        var type = TYPE.matcher(output);
        String mode = type.find() ? type.group(1) : null;
        var match = CHANNEL.matcher(output);
        if (!match.find()) return mode == null ? null : new Settings(mode, null, null, null, null, now);
        return new Settings(mode, Integer.parseInt(match.group(1)), Integer.parseInt(match.group(2)),
                Integer.parseInt(match.group(3)), match.group(4), now);
    }
}
