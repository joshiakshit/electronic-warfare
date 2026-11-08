package ewave.capture;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/** Reads the tuned monitor channel and width from iw. */
public final class RadioStatus {
    private static final Pattern INTERFACE = Pattern.compile("[A-Za-z0-9_.-]{1,15}");
    private static final Pattern CHANNEL = Pattern.compile(
            "(?m)^\\s*channel (\\d+) \\((\\d+) MHz\\), width: (\\d+) MHz(?: \\(([^)]+)\\))?");
    private static final Pattern TYPE = Pattern.compile("(?m)^\\s*type (\\S+)");
    public record Settings(String interfaceType, Integer channel, Integer frequencyMhz, Integer widthMhz,
                           String widthMode, long sampledAt) { }

    private RadioStatus() { }

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
