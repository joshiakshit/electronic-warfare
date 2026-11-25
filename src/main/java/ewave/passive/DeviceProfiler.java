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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

/** Session-local, MAC-keyed observations. Guesses and distance estimates are not verified facts.
 * Only transmitters contribute signal readings. Binary probe correlations live in PassiveWifiSession.
 */
public final class DeviceProfiler {
    public static final int UNKNOWN_RSSI = 127;
    public static final int DEFAULT_TX_POWER = -59;
    public static final int PROFILE_LIMIT = 4096;
    public static final int PROBED_SSID_LIMIT = 512;
    private static final Pattern MAC_PATTERN = Pattern.compile("(?i)[0-9a-f]{2}(:[0-9a-f]{2}){5}");
    private final ConcurrentHashMap<String, DeviceProfile> profiles = new ConcurrentHashMap<>();
    private final OuiLookup oui;
    private final int profileLimit;
    private final AtomicLong evictedProfiles = new AtomicLong();

    public void clear() {
        profiles.clear();
        evictedProfiles.set(0);
    }

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
        this(oui, PROFILE_LIMIT);
    }

    DeviceProfiler(OuiLookup oui, int profileLimit) {
        if (profileLimit < 1) throw new IllegalArgumentException("profileLimit must be positive");
        this.oui = Objects.requireNonNull(oui);
        this.profileLimit = profileLimit;
    }

    public int profileLimit() { return profileLimit; }

    public long evictedCount() { return evictedProfiles.get(); }

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
        boolean[] inserted = new boolean[1];
        profiles.compute(key, (address, previous) -> {
            if (previous == null) {
                inserted[0] = true;
                return new DeviceProfile(address, oui.lookup(address), "Unknown",
                        ssids, rssi, meters, seen, seen, 1, randomMac);
            }
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
        if (inserted[0] && profiles.size() > profileLimit) evictOldest(key);
    }

    private void evictOldest(String keepKey) {
        synchronized (profiles) {
            while (profiles.size() > profileLimit) {
                String oldestKey = null;
                Instant oldestSeen = Instant.MAX;
                for (var entry : profiles.entrySet()) {
                    if (entry.getKey().equals(keepKey)) continue;
                    Instant seen = entry.getValue().lastSeen();
                    if (oldestKey == null || seen.isBefore(oldestSeen)) {
                        oldestSeen = seen;
                        oldestKey = entry.getKey();
                    }
                }
                if (oldestKey == null) break;
                if (profiles.remove(oldestKey) != null) evictedProfiles.incrementAndGet();
            }
        }
    }

    private static String normalize(String mac) {
        if (mac == null || !MAC_PATTERN.matcher(mac).matches()) return null;
        return mac.toUpperCase(Locale.ROOT);
    }

    private static boolean isUnicast(String mac) {
        String key = normalize(mac);
        return key != null && !key.equals("00:00:00:00:00:00")
                && (Integer.parseInt(key.substring(0, 2), 16) & 1) == 0;
    }

    private static List<String> merge(List<String> previous, List<String> added) {
        if (added.isEmpty()) return previous;
        var result = new LinkedHashSet<>(previous);
        result.addAll(added);
        if (result.size() <= PROBED_SSID_LIMIT) return List.copyOf(result);
        var list = new ArrayList<>(result);
        return List.copyOf(list.subList(list.size() - PROBED_SSID_LIMIT, list.size()));
    }
}
