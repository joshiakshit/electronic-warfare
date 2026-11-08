package ewave.passive;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** Operator-enrolled addresses. Observed addresses are never added automatically. */
public record MyNetworkProfile(List<Entry> accessPoints, List<Entry> devices, boolean restrictCapture,
                               @JsonInclude(JsonInclude.Include.NON_EMPTY) List<FingerprintSample> fingerprintSamples) {
    private static final Pattern UNICAST = Pattern.compile("(?:[0-9a-f][02468ace]:)(?:[0-9a-f]{2}:){4}[0-9a-f]{2}");
    private static final int SAMPLE_LIMIT = 512;
    public static final MyNetworkProfile EMPTY = new MyNetworkProfile(List.of(), List.of(), false);

    public record Entry(UUID id, String address, String label) {
        public Entry {
            Objects.requireNonNull(id, "An entry ID is required");
            address = normalizeAddress(address);
            label = label == null ? "" : label.strip();
            if (label.isBlank() || label.length() > 64 || label.codePoints().anyMatch(Character::isISOControl))
                throw new IllegalArgumentException("Enter a label of 1–64 characters");
        }
    }

    public record Change(String action, UUID id, String address, String observedId, String label, Boolean restricted) { }
    public record NamedEntry(UUID id, String label, String token) { }
    public record NearbyAp(String token, int channel, Double rssi, long lastSeen) { }
    public record View(List<NamedEntry> accessPoints, List<NamedEntry> devices, List<NearbyAp> observedAccessPoints,
                       boolean restrictCapture, boolean commandLineScope) { }
    public record SampleChange(String observedId, String hash, WifiInventory.FrameSource source, String family,
                               String osHint) { }
    public record FingerprintSample(UUID id, String family, String osHint, WifiInventory.FingerprintObservation evidence) {
        public FingerprintSample {
            Objects.requireNonNull(id, "A sample ID is required");
            Objects.requireNonNull(evidence, "Fingerprint evidence is required");
            family = sampleLabel(family, "device class", true);
            osHint = sampleLabel(osHint, "OS hint", false);
        }
    }

    public MyNetworkProfile(List<Entry> accessPoints, List<Entry> devices, boolean restrictCapture) {
        this(accessPoints, devices, restrictCapture, List.of());
    }

    public MyNetworkProfile {
        accessPoints = validated(accessPoints, 64);
        devices = validated(devices, 256);
        fingerprintSamples = List.copyOf(fingerprintSamples == null ? List.of() : fingerprintSamples);
        if (fingerprintSamples.size() > SAMPLE_LIMIT)
            throw new IllegalArgumentException("The fingerprint set is limited to " + SAMPLE_LIMIT + " samples");
        if (restrictCapture && accessPoints.isEmpty())
            throw new IllegalArgumentException("Add at least one access point before restricting capture");
    }

    private static String sampleLabel(String text, String field, boolean required) {
        String value = text == null ? "" : text.strip();
        if ((required && value.isEmpty()) || value.length() > 64 || value.codePoints().anyMatch(Character::isISOControl))
            throw new IllegalArgumentException("Enter a valid " + field + " of up to 64 characters");
        return value;
    }

    public MyNetworkProfile saveSample(SampleChange change, WifiInventory.FingerprintObservation evidence) {
        var sample = new FingerprintSample(UUID.randomUUID(), change.family, change.osHint, evidence);
        var samples = new ArrayList<>(fingerprintSamples);
        for (int i = 0; i < samples.size(); i++) {
            var existing = samples.get(i);
            if (existing.evidence.hash().equals(evidence.hash()) && existing.evidence.source() == evidence.source()
                    && existing.family.equals(sample.family) && existing.osHint.equals(sample.osHint)) {
                samples.set(i, new FingerprintSample(existing.id, sample.family, sample.osHint, evidence));
                return new MyNetworkProfile(accessPoints, devices, restrictCapture, samples);
            }
        }
        samples.add(sample);
        return new MyNetworkProfile(accessPoints, devices, restrictCapture, samples);
    }

    public MyNetworkProfile removeSample(UUID id) {
        var samples = fingerprintSamples.stream().filter(sample -> !sample.id.equals(id)).toList();
        return new MyNetworkProfile(accessPoints, devices, restrictCapture, samples);
    }

    private static List<Entry> validated(List<Entry> entries, int maximum) {
        List<Entry> values = List.copyOf(entries == null ? List.of() : entries);
        if (values.size() > maximum) throw new IllegalArgumentException("This list is limited to " + maximum + " entries");
        var ids = new HashSet<UUID>();
        var addresses = new HashSet<String>();
        for (Entry entry : values)
            if (!ids.add(entry.id) || !addresses.add(entry.address))
                throw new IllegalArgumentException("Each address can only be enrolled once per list");
        return values;
    }

    static String normalizeAddress(String address) {
        String normalized = address == null ? "" : address.strip().toLowerCase(Locale.ROOT);
        if (!UNICAST.matcher(normalized).matches() || normalized.equals("00:00:00:00:00:00"))
            throw new IllegalArgumentException("Enter a unicast MAC address such as 00:11:22:33:44:55");
        return normalized;
    }

    public MyNetworkProfile change(Change change, String observedBssid) {
        if (change == null || change.action == null) throw new IllegalArgumentException("A setup action is required");
        return switch (change.action) {
            case "save-ap" -> new MyNetworkProfile(upsert(accessPoints, change, observedBssid), devices, restrictCapture, fingerprintSamples);
            case "save-device" -> new MyNetworkProfile(accessPoints, upsert(devices, change, null), restrictCapture, fingerprintSamples);
            case "remove-ap" -> new MyNetworkProfile(remove(accessPoints, change.id), devices, restrictCapture, fingerprintSamples);
            case "remove-device" -> new MyNetworkProfile(accessPoints, remove(devices, change.id), restrictCapture, fingerprintSamples);
            case "scope" -> {
                if (change.restricted == null) throw new IllegalArgumentException("Specify whether to restrict capture");
                yield new MyNetworkProfile(accessPoints, devices, change.restricted, fingerprintSamples);
            }
            default -> throw new IllegalArgumentException("Unknown setup action");
        };
    }

    private static List<Entry> upsert(List<Entry> current, Change change, String observedBssid) {
        var entries = new ArrayList<>(current);
        if (change.id != null) {
            for (int i = 0; i < entries.size(); i++) {
                Entry existing = entries.get(i);
                if (existing.id.equals(change.id)) {
                    entries.set(i, new Entry(existing.id, existing.address, change.label));
                    return entries;
                }
            }
            throw new IllegalArgumentException("The saved entry no longer exists");
        }
        String address = normalizeAddress(observedBssid != null ? observedBssid : change.address);
        for (int i = 0; i < entries.size(); i++) {
            Entry existing = entries.get(i);
            if (existing.address.equals(address)) {
                entries.set(i, new Entry(existing.id, address, change.label));
                return entries;
            }
        }
        entries.add(new Entry(UUID.randomUUID(), address, change.label));
        return entries;
    }

    private static List<Entry> remove(List<Entry> entries, UUID id) {
        if (id == null || entries.stream().noneMatch(entry -> entry.id.equals(id)))
            throw new IllegalArgumentException("The saved entry no longer exists");
        return entries.stream().filter(entry -> !entry.id.equals(id)).toList();
    }
}
