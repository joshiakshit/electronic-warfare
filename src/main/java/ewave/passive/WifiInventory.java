package ewave.passive;

import com.fasterxml.jackson.annotation.JsonInclude;
import ewave.decoder.CapabilityDecoder;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.IeSignature;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_EMPTY;

/** Bounded transmitter profiles. The enclosing RF session owns synchronization. */
public final class WifiInventory {
    private static final int LIMIT = 4096, SIGNAL_LIMIT = 64, FINGERPRINT_LIMIT = 8;
    public enum Role { AP, CLIENT, UNKNOWN }
    public enum FrameSource {
        ASSOCIATION_REQUEST, REASSOCIATION_REQUEST, PROBE_REQUEST, PROBE_RESPONSE, BEACON
    }
    public record SignalSample(long timestamp, double rssi) { }
    public record FingerprintObservation(String hash, FrameSource source, long observations,
                                         String generation, int maxWidthMhz, int spatialStreams,
                                         @JsonInclude(NON_EMPTY) List<String> ieOrder,
                                         @JsonInclude(NON_EMPTY) List<String> vendorElements,
                                         @JsonInclude(NON_EMPTY) String bandCohort) {
        public FingerprintObservation(String hash, FrameSource source, long observations,
                                      String generation, int maxWidthMhz, int spatialStreams) {
            this(hash, source, observations, generation, maxWidthMhz, spatialStreams, List.of(), List.of(), null);
        }

        public FingerprintObservation {
            ieOrder = ieOrder == null ? List.of() : List.copyOf(ieOrder);
            vendorElements = vendorElements == null ? List.of() : List.copyOf(vendorElements);
        }
    }
    public record AssociatedAp(String apId, String ssid, int channel, int frequencyMhz, String source) { }
    public record Detail(List<SignalSample> signalHistory, List<FingerprintObservation> fingerprints,
                         Dot11Frame.RadioObservation radioObservation, ProbeCorrelation.Cluster inferredCorrelation,
                         String enrolledLabel, AssociatedAp associatedAp, String osHint, String classificationBasis,
                         String inferredGeneration, Integer inferredWidthMhz, Integer inferredStreams) {
        public Detail withoutFingerprints() {
            return new Detail(signalHistory, List.of(), radioObservation, inferredCorrelation, enrolledLabel,
                    associatedAp, osHint, classificationBasis, inferredGeneration, inferredWidthMhz, inferredStreams);
        }
    }
    public record FingerprintHint(String family, String osHint, double confidence) { }
    private record FingerprintKey(String hash, FrameSource source) { }
    public record Device(String id, Role role, String oui, String vendor, boolean locallyAdministered,
                         List<String> bands, CapabilityDecoder.Summary capabilities, boolean pmBitSeen,
                         String ieSignatureHash, List<String> ieOrder, int beaconIntervalTu,
                         long firstSeen, long lastSeen, long packetCount, Double rssiMin, Double rssiMedian, Double rssiMax,
                         String classLabel, String osHint, double classConfidence,
                         long directedProbeCount, long wildcardProbeCount, boolean randomizedScanSeen,
                         boolean wpsUuidESeen, FingerprintHint fingerprintHint, String classificationBasis,
                         String inferredGeneration, Integer inferredWidthMhz, Integer inferredStreams) { }

    private final OuiLookup oui;
    private final FingerprintDb fingerprints;
    private final ProbeCorrelation correlations;
    private final SessionIdentifiers ids;
    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(16, 0.75f, true);

    WifiInventory(OuiLookup oui, FingerprintDb fingerprints, SessionIdentifiers ids) {
        this.oui = oui;
        this.fingerprints = fingerprints;
        this.ids = ids;
        this.correlations = new ProbeCorrelation(ids);
    }

    void observe(Dot11Frame frame, String id, boolean local, String signature, boolean directed,
                 boolean newProbe, List<String> directedNameTokens, String wpsUuidToken) {
        Entry entry = entries.computeIfAbsent(id, key -> new Entry(oui.registration(frame.addr2()).orElse(null)));
        evictIfFull();
        entry.cachedSnapshot = null;
        entry.local = local;
        entry.androidScanPrefix = local && frame.addr2().startsWith("da:a1:19:");
        entry.packetCount++;
        entry.first = Math.min(entry.first, frame.timestamp());
        entry.last = Math.max(entry.last, frame.timestamp());
        String band = band(frame.frequencyMhz());
        if (band != null && entry.bands.add(band)) entry.bandSnapshot = null;
        if (Double.isFinite(frame.rssi())) {
            if (entry.rssi.size() == SIGNAL_LIMIT) entry.rssi.removeFirst();
            entry.rssi.addLast(frame.rssi());
            entry.addSignal(frame.timestamp(), frame.rssi());
        }
        if (frame.radiotap() != null && (entry.radioObservation == null
                || frame.timestamp() >= entry.radioObservation.timestamp())) {
            entry.radioObservation = frame.radioObservation();
        }
        if (frame.type() == 2) {
            entry.pm |= frame.powerSave();
            entry.observeDataRadio(frame);
        }
        if (frame.apAdvertisement() && frame.addr2().equals(frame.addr3()) && (frame.capability() & 1) != 0) {
            entry.role = Role.AP;
            entry.beacon = frame.beaconIntervalTu();
            correlations.remove(id);
        } else if (entry.role != Role.AP && (frame.probe() || frame.management()
                && (frame.subtype() == 0 || frame.subtype() == 2))) {
            entry.role = Role.CLIENT;
        }
        String bandCohort = signature == null ? null : IeSignature.bandInvariantCohortOf(frame.ies());
        if (frame.probe()) {
            if (directed) entry.directed++; else entry.wildcard++;
            entry.wps |= wpsUuidToken != null;
            if (local && entry.role == Role.CLIENT && newProbe) {
                if (wpsUuidToken != null) correlations.observeWps(id, frame.timestamp(), frame.sequenceNumber(), wpsUuidToken);
                if (!frame.retry()) {
                    String fingerprint = IeSignature.hasCapabilityEvidence(frame.ies()) ? signature : null;
                    String cohort = fingerprint != null ? IeSignature.capabilityCohortOf(frame.ies()) : null;
                    correlations.observe(id, frame.timestamp(), frame.sequenceNumber(), fingerprint, cohort,
                            bandCohort, directedNameTokens, false);
                }
            }
        } else if (frame.management() && (frame.subtype() == 0 || frame.subtype() == 2)
                && local && entry.role == Role.CLIENT && !frame.retry()
                && frame.ies() != null && IeSignature.hasCapabilityEvidence(frame.ies())) {
            String cohort = IeSignature.capabilityCohortOf(frame.ies());
            byte[] ssid = frame.ies().first(0);
            String ssidToken = ssid.length > 0 && !Dot11InformationElements.hidden(ssid)
                    ? ids.id("correlation-ssid", ssid) : null;
            correlations.observe(id, frame.timestamp(), frame.sequenceNumber(), signature, cohort, bandCohort,
                    ssidToken == null ? List.of() : List.of(ssidToken), true);
        }
        if (signature != null) {
            var observed = CapabilityDecoder.decode(frame.ies(), frame.frequencyMhz(), frame.apAdvertisement(), frame.capability());
            entry.capabilities = merge(entry.capabilities, observed);
            entry.classifier.observe(frame.ies(), frame.timestamp(), frame.apAdvertisement());
            List<String> order = frame.ies().elements().stream().filter(ie -> ie.id() != 0 && ie.id() != 3 && ie.id() != 5)
                    .map(ie -> ie.id() == 255 ? "255:" + ie.extension() : Integer.toString(ie.id())).toList();
            if (!order.isEmpty()) entry.addFingerprint(frame, signature, observed, order, bandCohort);
            var finding = fingerprints.get(signature);
            if (entry.signature == null || entry.finding == null || finding != null
                    && finding.confidence() >= entry.finding.confidence()) {
                entry.signature = signature;
                entry.order = order;
                entry.finding = finding;
            }
        }
    }

    void confirmClient(String id, String mac, long time) {
        Entry entry = entries.computeIfAbsent(id, key -> new Entry(oui.registration(mac).orElse(null)));
        evictIfFull();
        entry.cachedSnapshot = null;
        entry.local = (Integer.parseInt(mac.substring(0, 2), 16) & 2) != 0;
        entry.androidScanPrefix = entry.local && mac.startsWith("da:a1:19:");
        entry.first = Math.min(entry.first, time);
        entry.last = Math.max(entry.last, time);
        if (entry.role == Role.UNKNOWN) entry.role = Role.CLIENT;
    }

    private void evictIfFull() {
        if (entries.size() > LIMIT) correlations.remove(entries.pollFirstEntry().getKey());
    }

    void clear() {
        entries.clear();
        correlations.clear();
    }

    /** Re-evaluates retained signatures after the fingerprint table or saved samples change. */
    void reclassify() {
        for (Entry entry : entries.values()) entry.reclassify(fingerprints);
    }

    void purge(long cutoff) {
        entries.values().removeIf(entry -> entry.last < cutoff);
        correlations.purge(cutoff);
    }

    Map<String, ProbeCorrelation.Cluster> correlations() { return correlations.snapshot(); }

    List<Device> prepareSnapshot() {
        var result = new ArrayList<Device>(entries.size());
        for (var row : entries.entrySet()) result.add(row.getValue().snapshot(row.getKey()));
        return result;
    }

    List<Device> snapshot() {
        var result = prepareSnapshot();
        result.sort(Comparator.comparing(Device::id));
        return List.copyOf(result);
    }

    Detail detail(String id, long cutoff, String enrolledLabel, AssociatedAp associatedAp) {
        Entry entry = entries.get(id);
        if (entry == null) return null;
        entry.observations.values().removeIf(value -> value.lastSeen < cutoff);
        var device = entry.snapshot(id);
        return new Detail(entry.signalHistory.stream().filter(sample -> sample.timestamp >= cutoff).toList(),
                entry.observations.sequencedValues().reversed().stream().map(value -> value.observation).toList(),
                entry.radioObservation != null && entry.radioObservation.timestamp() >= cutoff ? entry.radioObservation : null,
                correlations.snapshot().get(id), enrolledLabel, associatedAp, device.osHint(), device.classificationBasis(),
                device.inferredGeneration(), device.inferredWidthMhz(), device.inferredStreams());
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
                union(a.supportedRates(), b.supportedRates()), union(a.basicRates(), b.basicRates()),
                union(a.rsnAkmSuites(), b.rsnAkmSuites()), union(a.securityModes(), b.securityModes()),
                merge(a.managementFeatures(), b.managementFeatures()));
    }

    private static CapabilityDecoder.ManagementFeatures merge(CapabilityDecoder.ManagementFeatures a,
                                                               CapabilityDecoder.ManagementFeatures b) {
        return new CapabilityDecoder.ManagementFeatures(a.radioMeasurement() || b.radioMeasurement(),
                a.neighborReport() || b.neighborReport(), a.bssTransition() || b.bssTransition(),
                a.wnmSleep() || b.wnmSleep(), a.timBroadcast() || b.timBroadcast(), a.fastTransition() || b.fastTransition(),
                b.mobilityDomain() == null ? a.mobilityDomain() : b.mobilityDomain(),
                b.extendedCapabilitiesHex() == null ? a.extendedCapabilitiesHex() : b.extendedCapabilitiesHex(),
                a.twtResponder() || b.twtResponder());
    }

    static int rank(String name) {
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

    private static <T> List<T> union(List<T> a, List<T> b) {
        if (b.isEmpty() || a.equals(b)) return a;
        if (a.isEmpty()) return b;
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
        final StructuralDeviceClassifier classifier = new StructuralDeviceClassifier();
        final LinkedHashSet<String> bands = new LinkedHashSet<>();
        final ArrayDeque<Double> rssi = new ArrayDeque<>();
        final ArrayDeque<SignalSample> signalHistory = new ArrayDeque<>();
        final LinkedHashMap<FingerprintKey, TimedFingerprint> observations = new LinkedHashMap<>(8, 0.75f, true);
        Role role = Role.UNKNOWN;
        CapabilityDecoder.Summary capabilities;
        Dot11Frame.RadioObservation radioObservation;
        Dot11Frame.RadioObservation dataPhyObservation;
        FingerprintDb.Finding finding;
        List<String> order = List.of();
        boolean local, pm, wps, androidScanPrefix, dataRadioSeen;
        int beacon;
        String signature;
        long first = Long.MAX_VALUE, last, packetCount, directed, wildcard;
        List<String> bandSnapshot = List.of();
        Device cachedSnapshot;

        Entry(OuiLookup.Registration vendor) { this.vendor = vendor; }

        void observeDataRadio(Dot11Frame frame) {
            var radio = frame.radiotap();
            if (radio == null || capabilities != null) return;
            dataRadioSeen = true;
            if ((radio.he() != null || radio.ht() != null)
                    && (dataPhyObservation == null || frame.timestamp() >= dataPhyObservation.timestamp()))
                dataPhyObservation = frame.radioObservation();
        }

        void addSignal(long time, double value) {
            SignalSample lastSample = signalHistory.peekLast();
            if (lastSample != null && lastSample.timestamp > time) return;
            if (lastSample != null && lastSample.timestamp / 1000 == time / 1000) signalHistory.removeLast();
            else if (signalHistory.size() == SIGNAL_LIMIT) signalHistory.removeFirst();
            signalHistory.addLast(new SignalSample(time, value));
        }

        void reclassify(FingerprintDb db) {
            String bestSignature = signature;
            List<String> bestOrder = order;
            FingerprintDb.Finding best = db.get(signature);
            for (TimedFingerprint value : observations.values()) {
                FingerprintDb.Finding candidate = db.get(value.observation.hash());
                if (candidate != null && (best == null || candidate.confidence() > best.confidence())) {
                    best = candidate;
                    bestSignature = value.observation.hash();
                    bestOrder = value.observation.ieOrder();
                }
            }
            signature = bestSignature;
            order = bestOrder;
            finding = best;
            cachedSnapshot = null;
        }

        void addFingerprint(Dot11Frame frame, String hash, CapabilityDecoder.Summary caps, List<String> order,
                            String bandCohort) {
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
                    caps.maxWidthMhz(), caps.spatialStreams(), order, frame.ies().vendorElements(), bandCohort);
            observations.put(key, new TimedFingerprint(evidence, time));
            if (observations.size() > FINGERPRINT_LIMIT) observations.pollFirstEntry();
        }

        Device snapshot(String id) {
            if (cachedSnapshot != null) return cachedSnapshot;
            Double min = null, med = null, max = null;
            int n = rssi.size();
            if (n == 1) {
                double only = rssi.peekFirst();
                min = med = max = only;
            } else if (n > 1) {
                double[] samples = new double[n];
                int idx = 0;
                for (double v : rssi) samples[idx++] = v;
                Arrays.sort(samples);
                min = samples[0];
                max = samples[n - 1];
                med = (samples[n / 2] + samples[(n - 1) / 2]) / 2.0;
            }
            if (bandSnapshot == null) bandSnapshot = List.copyOf(bands);
            String generation = null;
            Integer width = null, streams = null;
            if (capabilities == null && dataPhyObservation != null) {
                var radio = dataPhyObservation.metadata();
                if (radio.he() != null) {
                    String receivedBand = band(dataPhyObservation.frequencyMhz());
                    boolean sixGhz = "6 GHz".equals(receivedBand)
                            || receivedBand == null && bandSnapshot.equals(List.of("6 GHz"));
                    generation = sixGhz ? "Wi-Fi 6E" : "Wi-Fi 6";
                    width = widthMhz(radio.he().bandwidthOrRu());
                    streams = radio.he().spaceTimeStreams();
                } else {
                    generation = "Wi-Fi 4";
                    width = widthMhz(radio.ht().bandwidth());
                    Integer mcs = radio.ht().mcs();
                    if (mcs != null && mcs >= 0 && mcs <= 31) streams = 1 + mcs / 8;
                    else if (Integer.valueOf(32).equals(mcs)) streams = 1;
                }
            }
            String registeredVendor = vendor == null ? null : vendor.vendor();
            var classification = classifier.classify(finding, role, local, androidScanPrefix, registeredVendor,
                    bandSnapshot, capabilities, dataRadioSeen, generation);
            cachedSnapshot = new Device(id, role, vendor == null ? null : vendor.prefix(),
                    local ? "Locally administered" : vendor == null ? "Unknown" : vendor.vendor(),
                    local, bandSnapshot, capabilities, pm, signature, order, beacon, first, last, packetCount,
                    min, med, max, classification.family(), classification.osHint(), classification.confidence(),
                    directed, wildcard, local && (directed + wildcard > 0), wps,
                    finding == null ? null : new FingerprintHint(finding.family(), finding.osHint(), finding.confidence()),
                    classification.basis(), generation, width, streams);
            return cachedSnapshot;
        }

        private static Integer widthMhz(String observed) {
            return switch (observed) {
                case "20 MHz", "20 MHz lower", "20 MHz upper" -> 20;
                case "40 MHz" -> 40;
                case "80 MHz" -> 80;
                case "160/80+80 MHz" -> 160;
                case null, default -> null;
            };
        }
    }

    private record TimedFingerprint(FingerprintObservation observation, long lastSeen) { }
}
