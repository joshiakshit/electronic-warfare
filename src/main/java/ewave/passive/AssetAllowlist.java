package ewave.passive;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

final class AssetAllowlist {
    private final Map<String, String> entries;

    AssetAllowlist() throws IOException {
        var parsed = new HashMap<String, String>();
        String filename = System.getProperty("ble.assets");
        if (filename != null) {
            try (var source = Files.newBufferedReader(Path.of(filename))) {
                for (String line; (line = source.readLine()) != null;) {
                    if (line.isBlank() || line.startsWith("#") || line.equals("type,identifier,label")) continue;
                    String[] fields = line.split(",", 3);
                    if (fields.length != 3 || fields[2].isBlank() || parsed.size() >= 512)
                        throw new IOException("Invalid BLE asset enrollment row or enrollment limit exceeded");
                    String type = fields[0].strip(), id = fields[1].strip().toLowerCase(Locale.ROOT);
                    boolean valid = switch (type) {
                        case "public", "random static" -> id.matches("[0-9a-f]{2}(:[0-9a-f]{2}){5}");
                        case "ibeacon" -> id.matches("[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}:[0-9]{1,5}:[0-9]{1,5}");
                        default -> false;
                    };
                    if (!valid || parsed.putIfAbsent(type + ":" + id, fields[2].strip()) != null)
                        throw new IOException("Invalid or duplicate BLE asset enrollment");
                }
            }
        }
        entries = Map.copyOf(parsed);
    }

    Match match(String addressType, String address, BleClassifier.Beacon beacon) {
        if (!addressType.equals("public") && !addressType.equals("random static")) return null;
        String key = addressType + ":" + address;
        if (entries.containsKey(key)) return new Match(key, entries.get(key));
        if (beacon == null) return null;
        key = "ibeacon:" + beacon.enrollmentKey();
        String label = entries.get(key);
        return label == null ? null : new Match(key, label);
    }

    record Match(String key, String label) { }
}
