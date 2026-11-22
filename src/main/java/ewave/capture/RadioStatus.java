package ewave.capture;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/** Reads the tuned monitor channel, width, and physical radio from sysfs / iw. */
public final class RadioStatus {
    private static final Pattern INTERFACE = Pattern.compile("[A-Za-z0-9_.-]{1,15}");
    private static final Pattern CHANNEL = Pattern.compile(
            "(?m)^\\s*channel (\\d+) \\((\\d+) MHz\\), width: (\\d+) MHz(?: \\(([^)]+)\\))?");
    private static final Pattern TYPE = Pattern.compile("(?m)^\\s*type (\\S+)");
    private static final Pattern WIPHY = Pattern.compile("(?m)^\\s*wiphy\\s+(\\d+)");
    public record Settings(String interfaceType, Integer channel, Integer frequencyMhz, Integer widthMhz,
                           String widthMode, long sampledAt) { }

    private RadioStatus() { }

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
        Process process = null;
        try {
            var builder = new ProcessBuilder("iw", "dev", iface, "info").redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().put("LC_ALL", "C");
            process = builder.start();
            if (!process.waitFor(750, TimeUnit.MILLISECONDS) || process.exitValue() != 0) return iface;
            try (var input = process.getInputStream()) {
                String output = new String(input.readNBytes(4096), StandardCharsets.UTF_8);
                var match = WIPHY.matcher(output);
                return match.find() ? "phy" + match.group(1) : iface;
            }
        } catch (IOException | SecurityException unavailable) {
            return iface;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return iface;
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
    }

    static Settings read(String iface) {
        if (!INTERFACE.matcher(iface).matches() || iface.startsWith("-")) return null;
        Process process = null;
        try {
            var builder = new ProcessBuilder("iw", "dev", iface, "info").redirectError(ProcessBuilder.Redirect.DISCARD);
            builder.environment().put("LC_ALL", "C");
            process = builder.start();
            if (!process.waitFor(750, TimeUnit.MILLISECONDS) || process.exitValue() != 0) return null;
            try (var input = process.getInputStream()) {
                return parse(new String(input.readNBytes(4096), StandardCharsets.UTF_8), System.currentTimeMillis());
            }
        } catch (IOException unavailable) {
            return null;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            if (process != null && process.isAlive()) process.destroyForcibly();
        }
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
