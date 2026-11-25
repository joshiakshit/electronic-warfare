package ewave.passive;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.IeSignature;
import ewave.decoder.MultipleBssidDecoder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/** Only pseudonymized or aggregate observations outlive the packet callback. */
public final class PassiveWifiSession {
    private static final int AP_DIRECTORY_LIMIT = 512;
    private static final int CLIENT_DIRECTORY_LIMIT = 4096;
    private static final long DIRECTORY_TTL = TimeUnit.MINUTES.toMillis(10);
    private record ObservedAp(String address, byte[] ssidBytes, String ssid, String ssidToken,
                              int channel, int frequencyMhz, int beaconIntervalTu, Double rssi, long time,
                              Dot11Frame advertisement) { }
    private record ObservedClient(String address, long time) { }
    public record Observation(boolean inventory, boolean probe, boolean topology) {
        public Observation(boolean inventory, boolean probe) { this(inventory, probe, inventory); }
    }
    public record ObservedApDetails(String token, @JsonIgnore String bssid, byte[] ssidBytes, String ssid,
                                    int channel, int frequencyMhz, int beaconIntervalTu, Double rssi, long lastSeen,
                                    @JsonIgnore Dot11Frame advertisement) {
        public ObservedApDetails(String token, String bssid, byte[] ssidBytes, String ssid,
                                 int channel, int frequencyMhz, int beaconIntervalTu, Double rssi, long lastSeen) {
            this(token, bssid, ssidBytes, ssid, channel, frequencyMhz, beaconIntervalTu, rssi, lastSeen, null);
        }

        public ObservedApDetails {
            ssidBytes = ssidBytes == null ? null : ssidBytes.clone();
        }
        @Override public byte[] ssidBytes() { return ssidBytes == null ? null : ssidBytes.clone(); }
    }
    private static final Observation IGNORED = new Observation(false, false);
    private static final Observation INVENTORY = new Observation(true, false);
    private static final Observation TOPOLOGY_ONLY = new Observation(false, false, true);
    private static final Observation PROBE_ONLY = new Observation(false, true);
    private static final Observation BOTH = new Observation(true, true);

    private final UUID sessionId = UUID.randomUUID();
    private final boolean replaySession;
    private final LongSupplier clock;
    private final SessionIdentifiers ids = new SessionIdentifiers();
    private final long retention = RfSettings.retentionMillis();
    private final List<String> commandLineBssids = configuredBssids();
    private final LinkedHashMap<String, ObservedAp> observedAps = new LinkedHashMap<>(16, .75f, true);
    private final LinkedHashMap<String, ObservedClient> observedClients = new LinkedHashMap<>(16, .75f, true);
    private List<String> bssids;
    private Map<String, String> enrolledLabels = Map.of();
    private boolean neighborhoodProbes;
    private final FingerprintDb fingerprints;
    private final WifiInventory inventory;
    private final ProbeAuditAggregator audit;
    private final TopologyBuilder topology;
    private long nextPurge;

    public PassiveWifiSession(DeviceProfiler profiler) throws IOException {
        this(profiler, MyNetworkProfile.EMPTY);
    }

    public PassiveWifiSession(DeviceProfiler profiler, MyNetworkProfile profile) throws IOException {
        this(profiler, profile, System::currentTimeMillis);
    }

    public PassiveWifiSession(DeviceProfiler profiler, MyNetworkProfile profile, LongSupplier clock) throws IOException {
        this(profiler, profile, clock, false);
    }

    public static PassiveWifiSession forReplay(DeviceProfiler profiler, MyNetworkProfile profile, LongSupplier clock)
            throws IOException {
        return new PassiveWifiSession(profiler, profile, clock, true);
    }

    private PassiveWifiSession(DeviceProfiler profiler, MyNetworkProfile profile, LongSupplier clock,
                               boolean replaySession) throws IOException {
        this.replaySession = replaySession;
        this.clock = Objects.requireNonNull(clock);
        fingerprints = new FingerprintDb();
        inventory = new WifiInventory(profiler.ouiLookup(), fingerprints, ids);
        audit = new ProbeAuditAggregator(ids);
        topology = new TopologyBuilder(ids, this::allowsBssid, true, profiler.ouiLookup());
        configure(profile);
    }

    public UUID sessionId() { return sessionId; }
    public boolean isReplaySession() { return replaySession; }

    public record EvidencedTarget(String id, String mac, String type, String vendor, String label, int rssi,
                                  String apId, String apBssid, String apSsid, int channel, int frequencyMhz,
                                  String evidenceSource, long lastSeen, UUID sessionId) { }

    public synchronized boolean hasAssociationEvidence(String clientId, String apId) {
        var evidence = topology.associationEvidence(clientId, apId);
        return evidence != null && evidence.lastSeen() > clock.getAsLong() - topology.associationRetention(retention);
    }

    /** Returns only clients confirmed by association or data relationships in live capture; replay is analysis-only. */
    public synchronized List<EvidencedTarget> evidencedTargets(DeviceProfiler profiler) {
        if (replaySession) return List.of();
        long now = clock.getAsLong();
        purge(now);
        TopologyBuilder.Snapshot snap = topology.prepareSnapshot(retention).build();
        var apMap = new java.util.HashMap<String, TopologyBuilder.AccessPoint>();
        for (var ap : snap.accessPoints()) apMap.put(ap.bssid(), ap);
        var invMap = new java.util.HashMap<String, WifiInventory.Device>();
        for (var dev : inventory.prepareSnapshot()) invMap.put(dev.id(), dev);
        var targets = new java.util.ArrayList<EvidencedTarget>();
        for (var edge : snap.edges()) {
            var evidence = topology.associationEvidence(edge.clientId(), edge.bssid());
            if (evidence == null || evidence.lastSeen() <= now - topology.associationRetention(retention)) continue;
            String clientMac = observedClient(edge.clientId());
            if (clientMac == null) continue;
            String apBssid = observedBssid(edge.bssid());
            if (apBssid == null) continue;
            var inv = invMap.get(edge.clientId());
            var prof = profiler == null ? null : profiler.get(clientMac);
            String type = inv != null && inv.classLabel() != null && !"UNCLASSIFIED".equals(inv.classLabel())
                    ? inv.classLabel() : prof != null ? prof.guessedType() : "Client";
            String vendor = inv != null ? inv.vendor() : prof != null ? prof.vendor() : "Unknown";
            int rssi = prof != null && prof.lastRssi() != DeviceProfiler.UNKNOWN_RSSI ? prof.lastRssi()
                    : inv != null && inv.rssiMedian() != null ? (int) Math.round(inv.rssiMedian())
                    : DeviceProfiler.UNKNOWN_RSSI;
            var apInfo = apMap.get(edge.bssid());
            String apSsid = apInfo != null ? apInfo.ssid() : null;
            if (apSsid == null) {
                var obs = directlyObservedAp(edge.bssid());
                if (obs != null) apSsid = obs.ssid();
            }
            targets.add(new EvidencedTarget(edge.clientId(), clientMac, type, vendor, type + " · " + vendor,
                    rssi, edge.bssid(), apBssid, apSsid, Dot11FrameDecoder.channel(evidence.frequencyMhz()),
                    evidence.frequencyMhz(), evidence.source(), evidence.lastSeen(), sessionId));
        }
        return List.copyOf(targets);
    }

    public synchronized boolean configure(MyNetworkProfile profile) {
        useFingerprintSamples(profile.fingerprintSamples());
        var labels = new LinkedHashMap<String, String>();
        profile.devices().forEach(entry -> labels.put(addressId(entry.address()), entry.label()));
        profile.accessPoints().forEach(entry -> labels.put(addressId(entry.address()), entry.label()));
        enrolledLabels = Map.copyOf(labels);
        List<String> next = !commandLineBssids.isEmpty() ? commandLineBssids
                : profile.restrictCapture() ? profile.accessPoints().stream().map(MyNetworkProfile.Entry::address).toList()
                : List.of();
        if (Objects.equals(bssids, next)) return false;
        bssids = next;
        neighborhoodProbes = Boolean.parseBoolean(System.getProperty("rf.neighborhoodProbes", Boolean.toString(next.isEmpty())));
        inventory.clear();
        topology.clear();
        audit.clear();
        observedClients.clear();
        observedAps.values().removeIf(ap -> ap.advertisement == null);
        return true;
    }

    /** Applies saved My Network reference samples to inventory classification, including retained devices. */
    public synchronized void useFingerprintSamples(List<MyNetworkProfile.FingerprintSample> samples) {
        fingerprints.useSamples(samples);
        inventory.reclassify();
    }

    public boolean commandLineScope() { return !commandLineBssids.isEmpty(); }

    public synchronized String observedBssid(String token) {
        ObservedAp ap = observedAps.get(token);
        return ap == null || ap.advertisement == null || ap.time < clock.getAsLong() - DIRECTORY_TTL ? null : ap.address;
    }

    /** Resolves a topology client token for active operations without exposing addresses in reports. */
    public synchronized String observedClient(String token) {
        ObservedClient client = observedClients.get(token);
        return client == null || client.time < clock.getAsLong() - DIRECTORY_TTL ? null : client.address;
    }

    public synchronized List<MyNetworkProfile.NearbyAp> observedAccessPoints() {
        long cutoff = clock.getAsLong() - DIRECTORY_TTL;
        return observedAps.entrySet().stream().filter(row -> row.getValue().time >= cutoff)
                .map(row -> new MyNetworkProfile.NearbyAp(row.getKey(), row.getValue().ssid,
                        row.getValue().channel, row.getValue().frequencyMhz,
                        row.getValue().rssi, row.getValue().time))
                .sorted(Comparator.comparing(MyNetworkProfile.NearbyAp::token)).toList();
    }

    public synchronized ObservedApDetails observedAp(String token) {
        ObservedAp ap = observedAps.get(token);
        if (ap == null || ap.time < clock.getAsLong() - DIRECTORY_TTL) return null;
        return new ObservedApDetails(token, ap.address, ap.ssidBytes, ap.ssid, ap.channel, ap.frequencyMhz,
                ap.beaconIntervalTu, ap.rssi, ap.time, ap.advertisement);
    }

    public synchronized ObservedApDetails directlyObservedAp(String token) {
        var ap = observedAp(token);
        return ap == null || ap.advertisement() == null ? null : ap;
    }

    public static boolean isDfsFrequency(int frequencyMhz) {
        return (frequencyMhz >= 5250 && frequencyMhz <= 5330)
                || (frequencyMhz >= 5490 && frequencyMhz <= 5730);
    }

    public static String summarizePmf(List<TopologyBuilder.AdvertisedSecurity> advertisedSecurity) {
        if (advertisedSecurity == null || advertisedSecurity.isEmpty()) return null;
        var rsn = advertisedSecurity.stream().filter(p -> "RSN".equals(p.protocol())).toList();
        var profiles = rsn.isEmpty() ? advertisedSecurity : rsn;
        boolean capable = false;
        for (var profile : profiles) {
            String pmf = profile.managementFrameProtection();
            if ("Required".equalsIgnoreCase(pmf)) return "Required";
            if ("Capable".equalsIgnoreCase(pmf)) capable = true;
        }
        return capable ? "Capable" : "Disabled";
    }

    public static List<String> akmSuitesOf(List<TopologyBuilder.AdvertisedSecurity> advertisedSecurity) {
        if (advertisedSecurity == null || advertisedSecurity.isEmpty()) return List.of();
        return advertisedSecurity.stream()
                .flatMap(profile -> profile.authentication().stream())
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    public record SelectableAccessPoint(String bssid, String ssid, boolean ssidHidden, int channel,
                                        int frequencyMhz, List<String> clients, long lastSeen,
                                        String security, String managementFrameProtection,
                                        List<String> akmSuites, Double rssiDbm, boolean dfsChannel) {
        public SelectableAccessPoint {
            clients = clients == null ? List.of() : List.copyOf(clients);
            akmSuites = akmSuites == null ? List.of() : List.copyOf(akmSuites);
        }

        public SelectableAccessPoint(String bssid, String ssid, boolean ssidHidden, int channel,
                                     int frequencyMhz, List<String> clients, long lastSeen) {
            this(bssid, ssid, ssidHidden, channel, frequencyMhz, clients, lastSeen,
                    null, null, List.of(), null, isDfsFrequency(frequencyMhz));
        }
    }

    /** Fresh advertised APs that can be resolved by Sniper and Ops, rather than historical topology rows. */
    public synchronized List<SelectableAccessPoint> selectableAccessPoints() {
        var snapshot = topology();
        return snapshot.accessPoints().stream().map(ap -> {
            var details = directlyObservedAp(ap.bssid());
            return details == null || details.frequencyMhz() <= 0 ? null : new SelectableAccessPoint(
                    ap.bssid(), ap.ssid(), ap.ssidHidden(), details.channel(), details.frequencyMhz(),
                    ap.clients(), details.lastSeen(), ap.security(), summarizePmf(ap.advertisedSecurity()),
                    akmSuitesOf(ap.advertisedSecurity()), details.rssi(), isDfsFrequency(details.frequencyMhz()));
        }).filter(Objects::nonNull).toList();
    }

    public synchronized List<String> findAccessPoints(String name) {
        byte[] bytes = name == null ? new byte[0] : name.getBytes(StandardCharsets.UTF_8);
        return findAccessPoints(bytes);
    }

    public synchronized List<String> findAccessPoints(byte[] exactSsidBytes) {
        if (exactSsidBytes == null || exactSsidBytes.length == 0 || exactSsidBytes.length > 32)
            throw new IllegalArgumentException("Enter a network name of 1–32 Wi-Fi bytes");
        long cutoff = clock.getAsLong() - DIRECTORY_TTL;
        return observedAps.entrySet().stream()
                .filter(row -> row.getValue().advertisement != null && row.getValue().time >= cutoff
                        && Arrays.equals(exactSsidBytes, row.getValue().ssidBytes))
                .map(Map.Entry::getKey).toList();
    }

    public synchronized Observation observe(Dot11Frame frame) {
        long now = clock.getAsLong();
        if (now >= nextPurge) purge(now);
        if (frame.timestamp() < now - retention) return IGNORED;
        String frameBssid = bssid(frame);
        var profiles = frame.apAdvertisement()
                ? MultipleBssidDecoder.decode(frame).stream().filter(profile -> allowsBssid(profile.bssid())).toList()
                : List.<MultipleBssidDecoder.Profile>of();
        if (frame.apAdvertisement() && frameBssid != null && (frame.capability() & 1) != 0) {
            int mhz = frame.frequencyMhz();
            int ch = Dot11FrameDecoder.channel(mhz);
            byte[] ds = frame.ies().first(3), ht = frame.ies().first(61);
            if ("2.4 GHz".equals(WifiInventory.band(mhz)) && ds.length == 1 && ds[0] > 0 && ds[0] <= 14) {
                ch = ds[0];
                mhz = ch == 14 ? 2484 : 2407 + ch * 5;
            } else if ("5 GHz".equals(WifiInventory.band(mhz)) && ht.length >= 22) {
                ch = ht[0] & 0xff;
            }
            if (ch == 0 && ds.length == 1) {
                ch = ds[0] & 0xff;
                if (ch >= 1 && ch <= 13) mhz = ch == 14 ? 2484 : 2407 + ch * 5;
            }
            if (allowsBssid(frameBssid)) {
                rememberAdvertisement(frameBssid, frame.ies().first(0), ch, mhz, frame, true);
            }
            for (var profile : profiles) {
                rememberAdvertisement(profile.bssid(), profile.ies().first(0), ch, mhz, frame, false);
            }
        } else if (frame.management() && (frame.subtype() == 0 || frame.subtype() == 2)
                && frameBssid != null && frameBssid.equals(frame.addr1())) {
            String token = addressId(frameBssid);
            var previous = observedAps.get(token);
            byte[] ssid = frame.ies() == null ? new byte[0] : frame.ies().first(0);
            if (previous != null && previous.ssidBytes == null && !Dot11InformationElements.hidden(ssid)) {
                observedAps.put(token, new ObservedAp(previous.address, ssid.clone(),
                        Dot11InformationElements.ssidLabel(ssid), ids.id("topology-ssid", ssid),
                        previous.channel, previous.frequencyMhz, previous.beaconIntervalTu,
                        previous.rssi, Math.max(previous.time, frame.timestamp()), previous.advertisement));
            }
        }
        boolean peersOnly = frame.type() == 1 || (frame.type() == 2 && frame.ds() == 3);
        boolean inScope = peersOnly ? allowsBssid(frame.addr1()) || allowsBssid(frame.addr2()) : allowsBssid(frameBssid);
        boolean auditProbe = frame.probe() && (inScope || neighborhoodProbes);
        if (!inScope && !auditProbe && profiles.isEmpty()) return IGNORED;

        String sender = addressId(frame.addr2());
        if (!inScope && !profiles.isEmpty()) {
            topology.observe(frame, sender, profiles);
            return TOPOLOGY_ONLY;
        }
        if (peersOnly) {
            String client = topology.observe(frame, sender, profiles);
            if (client != null) inventory.confirmClient(addressId(client), client, frame.timestamp());
            return client == null ? TOPOLOGY_ONLY : INVENTORY;
        }
        boolean local = OuiLookup.isLocallyAdministered(HexFormat.ofDelimiter(":").parseHex(frame.addr2()));
        boolean capabilities = frame.management() && (frame.probe() || frame.apAdvertisement()
                || frame.subtype() == 0 || frame.subtype() == 2);
        String signature = capabilities ? IeSignature.of(frame.ies()) : null;
        boolean directed = false;
        boolean newProbe = false;
        String wpsUuidToken = null;
        List<String> directedNameTokens = List.of();
        if (auditProbe) {
            var ies = frame.ies();
            byte[] ssid = ies.first(0);
            var ssidList = ies.probeSsidsInList();
            var shortSsids = ies.shortSsidList();
            boolean hasPrimary = !Dot11InformationElements.hidden(ssid);
            directed = hasPrimary || !ssidList.isEmpty() || !shortSsids.isEmpty();
            newProbe = !audit.duplicate(frame.timestamp(), sender, frame.sequenceControl(), frame.retry());
            if (newProbe) {
                wpsUuidToken = ies.wpsUuidE().map(uuidBytes -> ids.id("wps-uuid", uuidBytes)).orElse(null);
                audit.observe(frame.timestamp(), sender, local, signature, wpsUuidToken, ssid, ssidList, shortSsids,
                        ies.hasPasspoint(), ies.p2pDeviceName().orElse(null));
                if (inScope && local) {
                    var names = new java.util.ArrayList<>(ssidList);
                    if (hasPrimary) names.add(ssid);
                    directedNameTokens = names.stream().map(name -> ids.id("correlation-ssid", name))
                            .distinct().sorted().toList();
                }
            }
        }
        if (!inScope) return newProbe ? PROBE_ONLY : IGNORED;
        inventory.observe(frame, sender, local, signature, directed, newProbe, directedNameTokens, wpsUuidToken);
        String client = topology.observe(frame, sender, profiles);
        if (client != null) {
            String clientId = addressId(client);
            if (frameBssid != null && topology.associationEvidence(clientId, addressId(frameBssid)) != null) {
                observedClients.put(clientId, new ObservedClient(client, frame.timestamp()));
                if (observedClients.size() > CLIENT_DIRECTORY_LIMIT) observedClients.pollFirstEntry();
            }
            inventory.confirmClient(clientId, client, frame.timestamp());
        }
        return newProbe ? BOTH : INVENTORY;
    }

    private void rememberAdvertisement(String address, byte[] ssid, int channel, int frequency, Dot11Frame frame,
                                       boolean transmitted) {
        String token = addressId(address);
        audit.observeAdvertisement(ssid, frame.timestamp());
        var previous = observedAps.get(token);
        if (previous != null && (frame.timestamp() < previous.time || !transmitted && previous.advertisement != null))
            return;
        boolean hidden = Dot11InformationElements.hidden(ssid);
        byte[] ssidBytes = hidden ? (previous == null ? null : previous.ssidBytes) : ssid.clone();
        String ssidLabel = hidden ? (previous == null ? null : previous.ssid) : Dot11InformationElements.ssidLabel(ssid);
        String ssidToken = hidden ? (previous == null ? null : previous.ssidToken) : ids.id("topology-ssid", ssid);
        int interval = frame.beaconIntervalTu() > 0 ? frame.beaconIntervalTu()
                : (previous == null ? 100 : previous.beaconIntervalTu);
        Double rssi = Double.isFinite(frame.rssi()) ? Double.valueOf(frame.rssi())
                : (previous == null ? null : previous.rssi);
        observedAps.put(token, new ObservedAp(address, ssidBytes, ssidLabel, ssidToken,
                channel, frequency, interval, rssi, frame.timestamp(), transmitted ? frame : null));
        if (observedAps.size() > AP_DIRECTORY_LIMIT) observedAps.pollFirstEntry();
    }

    private static List<String> configuredBssids() {
        String configured = System.getProperty("rf.bssids", "");
        if (configured.isBlank()) return List.of();
        var addresses = new LinkedHashSet<String>();
        try {
            for (String raw : configured.split(",", -1)) addresses.add(MyNetworkProfile.normalizeAddress(raw));
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("rf.bssids must contain comma-separated unicast BSSIDs", invalid);
        }
        return List.copyOf(addresses);
    }

    private boolean allowsBssid(String bssid) { return bssids.isEmpty() || bssid != null && bssids.contains(bssid); }

    private static String bssid(Dot11Frame frame) {
        if (frame.management()) {
            String bssid = frame.addr3();
            return switch (frame.subtype()) {
                case 0, 2 -> bssid.equals(frame.addr1()) ? bssid : null;
                case 1, 3, 5, 8 -> bssid.equals(frame.addr2()) ? bssid : null;
                case 4 -> bssid;
                case 10, 11, 12, 13 -> bssid.equals(frame.addr1()) || bssid.equals(frame.addr2()) ? bssid : null;
                default -> null;
            };
        }
        if (frame.type() != 2) return null;
        return switch (frame.ds()) {
            case 0 -> frame.addr3();
            case 1 -> frame.addr1();
            case 2 -> frame.addr2();
            default -> null;
        };
    }

    public synchronized int scopedBssidCount() { return bssids.size(); }
    public synchronized boolean neighborhoodProbes() { return neighborhoodProbes; }
    public synchronized String preferredApId() { return bssids.isEmpty() ? null : addressId(bssids.getFirst()); }

    public String addressId(String mac) { return ids.id("wifi", mac.toLowerCase(Locale.ROOT)); }

    public List<WifiInventory.Device> inventory() {
        List<WifiInventory.Device> snapshot;
        synchronized (this) {
            purge(clock.getAsLong());
            snapshot = inventory.prepareSnapshot();
        }
        snapshot.sort(Comparator.comparing(WifiInventory.Device::id));
        return List.copyOf(snapshot);
    }

    public record ProfilerDevice(@JsonUnwrapped WifiInventory.Device device,
                                 ProbeCorrelation.Reference inferredCorrelation, String enrolledLabel,
                                 WifiInventory.AssociatedAp associatedAp) { }

    public record TrackerDevice(@JsonUnwrapped WifiInventory.Device device, String enrolledLabel) { }

    public synchronized List<TrackerDevice> trackerDevices() {
        purge(clock.getAsLong());
        return inventory.snapshot().stream().map(device -> new TrackerDevice(device, enrolledLabels.get(device.id()))).toList();
    }

    public synchronized List<ProfilerDevice> profilerReport() {
        purge(clock.getAsLong());
        var clusters = inventory.correlations();
        var associatedAps = topology.associatedAps(null);
        return inventory.snapshot().stream().map(device -> {
            var cluster = clusters.get(device.id());
            return new ProfilerDevice(device, cluster == null ? null : cluster.reference(),
                    enrolledLabels.get(device.id()), associatedAps.get(device.id()));
        }).toList();
    }

    public synchronized WifiInventory.Detail inventoryDetail(String id) {
        long now = clock.getAsLong();
        purge(now);
        return inventory.detail(id, now - retention, enrolledLabels.get(id), topology.associatedAps(id).get(id));
    }

    public ProbeAuditAggregator.Report audit() {
        ProbeAuditAggregator.PendingReport pending;
        synchronized (this) {
            long now = clock.getAsLong();
            inventory.purge(now - retention);
            int clusters = (int) inventory.correlations().values().stream()
                    .map(ProbeCorrelation.Cluster::id).distinct().count();
            pending = audit.prepareSnapshot(now, retention, clusters);
        }
        return pending.build();
    }

    public TopologyBuilder.Snapshot topology() {
        TopologyBuilder.PendingSnapshot pending;
        synchronized (this) {
            purge(clock.getAsLong());
            pending = topology.prepareSnapshot(retention);
        }
        return pending.build();
    }

    public synchronized void purge() { purge(clock.getAsLong()); }

    private void purge(long now) {
        nextPurge = now + TimeUnit.MINUTES.toMillis(1);
        observedAps.values().removeIf(ap -> ap.time < now - DIRECTORY_TTL);
        observedClients.values().removeIf(client -> client.time < now - DIRECTORY_TTL);
        inventory.purge(now - retention);
        topology.purge(now, retention);
        audit.purge(now, retention);
    }
}
