package ewave.active;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/** NetworkManager's escaped, terse SSID/BSSID/channel/frequency snapshot taken before monitor mode. */
public final class WifiAccessPoints {
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");
    public record AccessPoint(String ssid, String bssid, int channel, int frequencyMhz) {
        public AccessPoint { channel = HandshakeAnalyzer.normalizeChannel(channel); }
    }
    private final Path cache;

    public WifiAccessPoints() { this(Path.of("/tmp/ewave-wifi-aps.txt")); }
    public WifiAccessPoints(Path cache) { this.cache = Objects.requireNonNull(cache); }

    public List<AccessPoint> all() throws IOException { return parse(Files.readAllLines(cache)); }

    static List<AccessPoint> parse(List<String> lines) {
        var result = new LinkedHashMap<String, AccessPoint>();
        for (String line : lines) {
            var fields = split(line);
            if (fields.size() != 4 || !MAC.matcher(fields.get(1)).matches()) continue;
            try {
                String cachedChannel = fields.get(2).strip();
                int channel = cachedChannel.isEmpty() || cachedChannel.equals("--") || cachedChannel.equalsIgnoreCase("null")
                        ? 6 : HandshakeAnalyzer.normalizeChannel(Integer.parseInt(cachedChannel));
                int frequency = Integer.parseInt(fields.get(3).replaceFirst("\\s*MHz$", "").strip());
                if (channel > 233 || frequency < 2300 || frequency > 7125) continue;
                String bssid = fields.get(1).toUpperCase(Locale.ROOT);
                result.putIfAbsent(bssid, new AccessPoint(fields.get(0), bssid, channel, frequency));
            } catch (NumberFormatException invalid) { /* Ignore incomplete scan records. */ }
        }
        return List.copyOf(result.values());
    }

    private static List<String> split(String line) {
        var fields = new ArrayList<String>();
        var field = new StringBuilder();
        boolean escaped = false;
        for (char value : line.toCharArray()) {
            if (escaped) { field.append(value); escaped = false; }
            else if (value == '\\') escaped = true;
            else if (value == ':') { fields.add(field.toString()); field.setLength(0); }
            else field.append(value);
        }
        if (escaped) return List.of();
        fields.add(field.toString());
        return fields;
    }
}
