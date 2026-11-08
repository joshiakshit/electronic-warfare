package ewave.passive;

import ewave.decoder.CapabilityDecoder;
import ewave.decoder.Dot11Frame;

import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;

/** Bounded transmitter profiles. The enclosing RF session owns synchronization. */
public final class WifiInventory {
    private static final int LIMIT = 4096, SIGNAL_LIMIT = 64, FINGERPRINT_LIMIT = 8;
    public enum Role { AP, CLIENT, UNKNOWN }
    public enum FrameSource {
        ASSOCIATION_REQUEST, REASSOCIATION_REQUEST, PROBE_REQUEST, PROBE_RESPONSE, BEACON
    }
    public record SignalSample(long timestamp, double rssi) { }
    public record FingerprintObservation(String hash, FrameSource source, long observations,
                                         String generation, int maxWidthMhz, int spatialStreams) { }
    public record Detail(List<SignalSample> signalHistory, List<FingerprintObservation> fingerprints) { }
    public record FingerprintHint(String family, String osHint, double confidence) { }
    private record FingerprintKey(String hash, FrameSource source) { }
    public record Device(String id, Role role, String oui, String vendor, boolean locallyAdministered,
                         List<String> bands, CapabilityDecoder.Summary capabilities, boolean pmBitSeen,
                         String ieSignatureHash, List<String> ieOrder, int beaconIntervalTu,
                         long firstSeen, long lastSeen, long packetCount, Double rssiMin, Double rssiMedian, Double rssiMax,
                         String classLabel, String osHint, double classConfidence,
                         long directedProbeCount, long wildcardProbeCount, boolean randomizedScanSeen,
                         boolean wpsUuidESeen, FingerprintHint fingerprintHint) { }

    private final OuiLookup oui;
    private final FingerprintDb fingerprints;
    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);

    WifiInventory(OuiLookup oui, FingerprintDb fingerprints) { this.oui = oui; this.fingerprints = fingerprints; }

    void observe(Dot11Frame frame, String id, boolean local, String signature, boolean directed, boolean wps) {
        Entry entry = entries.computeIfAbsent(id, key -> new Entry(oui.registration(frame.addr2()).orElse(null)));
        if (entries.size() > LIMIT) entries.pollFirstEntry();
        entry.local = local;
        entry.packetCount++;
        entry.first = Math.min(entry.first, frame.timestamp());
        entry.last = Math.max(entry.last, frame.timestamp());
        String band = band(frame.frequencyMhz());
        if (band != null) entry.bands.add(band);
        if (Double.isFinite(frame.rssi())) {
            if (entry.rssi.size() == SIGNAL_LIMIT) entry.rssi.removeFirst();
            entry.rssi.addLast(frame.rssi());
            entry.addSignal(frame.timestamp(), frame.rssi());
        }
        if (frame.type() == 2) entry.pm |= frame.powerSave();
        if (frame.apAdvertisement() && frame.addr2().equals(frame.addr3()) && (frame.capability() & 1) != 0) {
            entry.role = Role.AP;
            entry.beacon = frame.beaconIntervalTu();
        } else if (entry.role != Role.AP && (frame.probe() || frame.management()
                && (frame.subtype() == 0 || frame.subtype() == 2))) {
            entry.role = Role.CLIENT;
        }
        if (frame.probe()) {
            if (directed) entry.directed++; else entry.wildcard++;
            entry.wps |= wps;
        }
        if (signature != null) {
            var observed = CapabilityDecoder.decode(frame.ies(), frame.frequencyMhz(), frame.apAdvertisement());
            entry.capabilities = merge(entry.capabilities, observed);
            if (frame.ies().elements().stream().anyMatch(ie -> ie.id() != 0 && ie.id() != 3 && ie.id() != 5))
                entry.addFingerprint(frame, signature, observed);
            var finding = fingerprints.get(signature);
            if (entry.signature == null || entry.finding == null || finding != null
                    && finding.confidence() >= entry.finding.confidence()) {
                entry.signature = signature;
                entry.order = frame.ies().elements().stream().filter(ie -> ie.id() != 0 && ie.id() != 3 && ie.id() != 5)
                        .map(ie -> ie.id() == 255 ? "255:" + ie.extension() : Integer.toString(ie.id())).toList();
                entry.finding = finding;
            }
        }
    }

    void confirmClient(String id, String mac, long time) {
        Entry entry = entries.computeIfAbsent(id, key -> new Entry(oui.registration(mac).orElse(null)));
        if (entries.size() > LIMIT) entries.pollFirstEntry();
        entry.local = (Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0;
        entry.first = Math.min(entry.first, time);
        entry.last = Math.max(entry.last, time);
        if (entry.role == Role.UNKNOWN) entry.role = Role.CLIENT;
    }

    void clear() { entries.clear(); }

    void purge(long cutoff) { entries.values().removeIf(entry -> entry.last < cutoff); }

    List<Device> snapshot() {
        return entries.entrySet().stream().map(row -> row.getValue().snapshot(row.getKey()))
                .sorted(Comparator.comparing(Device::id)).toList();
    }

    Detail detail(String id, long cutoff) {
        Entry entry = entries.get(id);
        if (entry == null) return null;
        entry.observations.values().removeIf(value -> value.lastSeen < cutoff);
        return new Detail(entry.signalHistory.stream().filter(sample -> sample.timestamp >= cutoff).toList(),
                entry.observations.sequencedValues().reversed().stream().map(value -> value.observation).toList());
    }

    static String band(int mhz) {
        if (mhz >= 2400 && mhz < 2500) return "2.4 GHz";
        if (mhz >= 4900 && mhz < 5925) return "5 GHz";
        if (mhz >= 5925 && mhz <= 7125) return "6 GHz";
        return null;
    }

    private static CapabilityDecoder.Summary merge(CapabilityDecoder.Summary a, CapabilityDecoder.Summary b) {
        if (a == null) return b;
        String generation = rank(a.wifiGeneration()) >= rank(b.wifiGeneration()) ? a.wifiGeneration() : b.wifiGeneration();
        return new CapabilityDecoder.Summary(generation, Math.max(a.spatialStreams(), b.spatialStreams()),
                Math.max(a.maxWidthMhz(), b.maxWidthMhz()), a.sgi() || b.sgi(), a.ldpc() || b.ldpc(),
                a.stbcTx() || b.stbcTx(), a.stbcRx() || b.stbcRx(), a.suBeamformee() || b.suBeamformee(),
                a.muBeamformee() || b.muBeamformee(), a.sixGhzCapability() || b.sixGhzCapability(),
                b.smPowerSave().equals("Unknown") ? a.smPowerSave() : b.smPowerSave(),
                union(a.supportedRates(), b.supportedRates()), union(a.basicRates(), b.basicRates()));
    }

    private static int rank(String name) {
        return switch (name) {
            case "Wi-Fi 7" -> 7;
            case "Wi-Fi 6E" -> 6;
            case "Wi-Fi 6" -> 5;
            case "Wi-Fi 5" -> 4;
            case "Wi-Fi 4" -> 3;
            case "802.11b" -> 1;
            case "Unknown" -> 0;
            default -> 2;
        };
    }

    private static List<Double> union(List<Double> a, List<Double> b) {
        var values = new LinkedHashSet<>(a);
        values.addAll(b);
        return List.copyOf(values);
    }

    static double median(List<Double> sorted) {
        int middle = sorted.size() / 2;
        return (sorted.get(middle) + sorted.get((sorted.size() - 1) / 2)) / 2;
    }

    private static final class Entry {
        final OuiLookup.Registration vendor;
        final LinkedHashSet<String> bands = new LinkedHashSet<>();
        final ArrayDeque<Double> rssi = new ArrayDeque<>();
        final ArrayDeque<SignalSample> signalHistory = new ArrayDeque<>();
        final LinkedHashMap<FingerprintKey, TimedFingerprint> observations = new LinkedHashMap<>(8, 0.75f, true);
        Role role = Role.UNKNOWN;
        CapabilityDecoder.Summary capabilities;
        FingerprintDb.Finding finding;
        List<String> order = List.of();
        boolean local, pm, wps;
        int beacon;
        String signature;
        long first = Long.MAX_VALUE, last, packetCount, directed, wildcard;

        Entry(OuiLookup.Registration vendor) { this.vendor = vendor; }

        void addSignal(long time, double value) {
            SignalSample lastSample = signalHistory.peekLast();
            if (lastSample != null && lastSample.timestamp > time) return;
            if (lastSample != null && lastSample.timestamp / 1000 == time / 1000) signalHistory.removeLast();
            else if (signalHistory.size() == SIGNAL_LIMIT) signalHistory.removeFirst();
            signalHistory.addLast(new SignalSample(time, value));
        }

        void addFingerprint(Dot11Frame frame, String hash, CapabilityDecoder.Summary caps) {
            FrameSource source = switch (frame.subtype()) {
                case 0 -> FrameSource.ASSOCIATION_REQUEST;
                case 2 -> FrameSource.REASSOCIATION_REQUEST;
                case 4 -> FrameSource.PROBE_REQUEST;
                case 5 -> FrameSource.PROBE_RESPONSE;
                case 8 -> FrameSource.BEACON;
                default -> throw new IllegalStateException("Unexpected fingerprint frame subtype");
            };
            var key = new FingerprintKey(hash, source);
            TimedFingerprint previous = observations.get(key);
            long count = previous == null ? 1 : previous.observation.observations + 1;
            long time = previous == null ? frame.timestamp() : Math.max(previous.lastSeen, frame.timestamp());
            var evidence = new FingerprintObservation(hash, source, count, caps.wifiGeneration(),
                    caps.maxWidthMhz(), caps.spatialStreams());
            observations.put(key, new TimedFingerprint(evidence, time));
            if (observations.size() > FINGERPRINT_LIMIT) observations.pollFirstEntry();
        }

        Device snapshot(String id) {
            List<Double> samples = rssi.stream().sorted().toList();
            String label = finding != null ? finding.family() : vendor != null ? vendor.vendor() : "UNCLASSIFIED";
            double confidence = finding != null ? finding.confidence() : vendor != null ? 0.3 : local ? 0.1 : 0;
            return new Device(id, role, vendor == null ? null : vendor.prefix(),
                    local ? "Locally administered" : vendor == null ? "Unknown" : vendor.vendor(),
                    local, List.copyOf(bands), capabilities, pm, signature, order, beacon, first, last, packetCount,
                    samples.isEmpty() ? null : samples.getFirst(), samples.isEmpty() ? null : median(samples),
                    samples.isEmpty() ? null : samples.getLast(), label, finding == null ? null : finding.osHint(),
                    confidence, directed, wildcard, local && (directed + wildcard > 0), wps,
                    finding == null ? null : new FingerprintHint(finding.family(), finding.osHint(), finding.confidence()));
        }
    }

    private record TimedFingerprint(FingerprintObservation observation, long lastSeen) { }
}
