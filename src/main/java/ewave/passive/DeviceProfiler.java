package ewave.passive;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import ewave.model.PacketEvent;
import ewave.model.ProbeRequest;

import java.io.IOException;
import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/** Session-local, MAC-keyed observations. Guesses and distance estimates are not verified facts.
 * Only transmitters contribute signal readings. Rotating addresses are never correlated.
 */
public final class DeviceProfiler {
    public static final int UNKNOWN_RSSI = 127;
    public static final int DEFAULT_TX_POWER = -59;
    private final ConcurrentHashMap<String, DeviceProfile> profiles = new ConcurrentHashMap<>();
    private final OuiLookup oui;

    public void clear() { profiles.clear(); }

    public record DeviceProfile(String mac, String vendor, String guessedType,
                                List<String> probedSsids,
                                int lastRssi,
                                @JsonSerialize(using = DistanceSerializer.class) double estimatedMeters,
                                @JsonSerialize(using = ToStringSerializer.class) Instant firstSeen,
                                @JsonSerialize(using = ToStringSerializer.class) Instant lastSeen,
                                int packetCount,
                                @JsonProperty("isRandomMac") boolean isRandomMac) {
        public DeviceProfile {
            probedSsids = List.copyOf(probedSsids);
        }
    }

    /** JSON uses null for an unavailable estimate, never an invented range or a NaN string. */
    public static final class DistanceSerializer extends JsonSerializer<Double> {
        @Override public void serialize(Double value, JsonGenerator output, SerializerProvider provider) throws IOException {
            if (Double.isFinite(value)) output.writeNumber(value);
            else output.writeNull();
        }
    }

    public DeviceProfiler() { this(new OuiLookup()); }

    OuiLookup ouiLookup() { return oui; }

    public DeviceProfiler(OuiLookup oui) {
        this.oui = Objects.requireNonNull(oui);
    }

    public void observe(PacketEvent event) {
        Objects.requireNonNull(event);
        if (!isUnicast(event.srcMac())) return;
        update(event.srcMac(), event.timestamp(), event.rssi(), List.of(), false);
    }

    /** Typed probe fields are unavailable in a generic PacketEvent summary. */
    public void observe(ProbeRequest event) {
        Objects.requireNonNull(event);
        if (!isUnicast(event.sourceMac())) return;
        List<String> ssids = event.wildcard() || event.ssid() == null || event.ssid().isEmpty()
                ? List.of() : List.of(event.ssid());
        update(event.sourceMac(), event.timestamp(), event.rssi(), ssids, false);
    }

    /** A named probe from tcpdump text, which supplies no reliable signal measurement. */
    public void observeProbe(String mac, String ssid) {
        if (ssid == null || ssid.isBlank() || !isUnicast(mac)) return;
        update(mac, System.currentTimeMillis(), Double.NaN, List.of(ssid), true);
    }

    public Collection<DeviceProfile> all() {
        return profiles.values().stream().sorted(Comparator.comparing(DeviceProfile::mac)).toList();
    }

    public DeviceProfile get(String mac) {
        String key = normalize(mac);
        return key == null ? null : profiles.get(key);
    }

    private void update(String mac, long timestamp, double signal, List<String> ssids, boolean retainSignal) {
        String key = normalize(mac);
        if (key == null) return;
        int rssi = Double.isFinite(signal) && signal >= -127 && signal <= 126
                ? (int) Math.round(signal) : UNKNOWN_RSSI;
        double meters = rssi == UNKNOWN_RSSI ? Double.NaN
                : Math.clamp(Math.pow(10.0, (DEFAULT_TX_POWER - rssi) / 20.0), 0.5, 50.0);
        Instant seen = Instant.ofEpochMilli(timestamp);
        boolean randomMac = (Integer.parseInt(key.substring(0, 2), 16) & 0x02) != 0;
        profiles.compute(key, (address, previous) -> {
            if (previous == null) return new DeviceProfile(address, oui.lookup(address), "Unknown",
                    ssids, rssi, meters, seen, seen, 1, randomMac);
            boolean newest = !seen.isBefore(previous.lastSeen());
            return new DeviceProfile(address, previous.vendor(), previous.guessedType(),
                    merge(previous.probedSsids(), ssids),
                    newest && !retainSignal ? rssi : previous.lastRssi(),
                    newest && !retainSignal ? meters : previous.estimatedMeters(),
                    seen.isBefore(previous.firstSeen()) ? seen : previous.firstSeen(),
                    newest ? seen : previous.lastSeen(),
                    previous.packetCount() == Integer.MAX_VALUE ? Integer.MAX_VALUE : previous.packetCount() + 1,
                    randomMac);
        });
    }

    private static String normalize(String mac) {
        if (mac == null || !mac.matches("(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}")) return null;
        String key = mac.toUpperCase(Locale.ROOT);
        return key;
    }

    private static boolean isUnicast(String mac) {
        String key = normalize(mac);
        return key != null && !key.equals("00:00:00:00:00:00")
                && (Integer.parseInt(key.substring(0, 2), 16) & 1) == 0;
    }

    private static List<String> merge(List<String> previous, List<String> added) {
        var result = new LinkedHashSet<>(previous);
        result.addAll(added);
        return List.copyOf(result);
    }
}
