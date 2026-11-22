package ewave.passive;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.IeSignature;

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
                              int channel, int frequencyMhz, int beaconIntervalTu, Double rssi, long time) { }
    private record ObservedClient(String address, long time) { }
    public record Observation(boolean inventory, boolean probe) { }
    public record ObservedApDetails(String token, String bssid, byte[] ssidBytes, String ssid,
                                    int channel, int frequencyMhz, int beaconIntervalTu, Double rssi, long lastSeen) {
        public ObservedApDetails {
            ssidBytes = ssidBytes == null ? null : ssidBytes.clone();
        }
        @Override public byte[] ssidBytes() { return ssidBytes == null ? null : ssidBytes.clone(); }
    }
    private static final Observation IGNORED = new Observation(false, false);
    private static final Observation INVENTORY = new Observation(true, false);
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
    private final boolean revealProbeNames;
    private List<String> bssids;
    private boolean neighborhoodProbes;
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
                               boolean revealNamesByDefault) throws IOException {
        this.replaySession = revealNamesByDefault;
        this.clock = Objects.requireNonNull(clock);
        inventory = new WifiInventory(profiler.ouiLookup(), new FingerprintDb());
        revealProbeNames = Boolean.parseBoolean(
                System.getProperty("audit.revealSsids", Boolean.toString(revealNamesByDefault)));
        audit = new ProbeAuditAggregator(revealProbeNames);
        topology = new TopologyBuilder(ids, this::allowsBssid, true);
        configure(profile);
    }

    public UUID sessionId() { return sessionId; }
    public boolean isReplaySession() { return replaySession; }
    public boolean revealProbeNames() { return revealProbeNames; }

    public record EvidencedTarget(String id, String mac, String type, String vendor, String label, int rssi,
                                  String apId, String apBssid, String apSsid, int channel, int frequencyMhz,
                                  String evidenceSource, long lastSeen, UUID sessionId) { }

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
                var obs = observedAp(edge.bssid());
                if (obs != null) apSsid = obs.ssid();
            }
            targets.add(new EvidencedTarget(edge.clientId(), clientMac, type, vendor, type + " · " + vendor,
                    rssi, edge.bssid(), apBssid, apSsid, edge.channel(), edge.frequencyMhz(),
                    edge.source(), edge.lastSeen(), sessionId));
        }
        return List.copyOf(targets);
    }

    public synchronized boolean configure(MyNetworkProfile profile) {
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
        return true;
    }

    public boolean commandLineScope() { return !commandLineBssids.isEmpty(); }

    public synchronized String observedBssid(String token) {
        ObservedAp ap = observedAps.get(token);
        return ap == null || ap.time < clock.getAsLong() - DIRECTORY_TTL ? null : ap.address;
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
                ap.beaconIntervalTu, ap.rssi, ap.time);
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
                .filter(row -> row.getValue().time >= cutoff && Arrays.equals(exactSsidBytes, row.getValue().ssidBytes))
                .map(Map.Entry::getKey).toList();
    }

    public synchronized Observation observe(Dot11Frame frame) {
        long now = clock.getAsLong();
        if (now >= nextPurge) purge(now);
        if (frame.timestamp() < now - retention) return IGNORED;
        String frameBssid = bssid(frame);
        if (frame.apAdvertisement() && frameBssid != null && (frame.capability() & 1) != 0) {
            String token = addressId(frameBssid);
            var previous = observedAps.get(token);
            byte[] ssid = frame.ies().first(0);
            boolean hidden = Dot11InformationElements.hidden(ssid);
            byte[] ssidBytes = hidden ? (previous == null ? null : previous.ssidBytes) : ssid.clone();
            String ssidLabel = hidden ? (previous == null ? null : previous.ssid) : Dot11InformationElements.ssidLabel(ssid);
            String ssidToken = hidden ? (previous == null ? null : previous.ssidToken) : ids.id("topology-ssid", ssid);
            int mhz = frame.frequencyMhz();
            int ch = Dot11FrameDecoder.channel(mhz);
            byte[] ds = frame.ies().first(3), ht = frame.ies().first(61);
            if ("2.4 GHz".equals(WifiInventory.band(mhz)) && ds.length == 1 && ds[0] > 0 && ds[0] <= 14) {
                ch = ds[0];
                mhz = 2407 + ch * 5;
            } else if ("5 GHz".equals(WifiInventory.band(mhz)) && ht.length >= 22) {
                ch = ht[0] & 0xff;
            }
            if (ch == 0 && ds.length == 1) {
                ch = ds[0] & 0xff;
                if (ch >= 1 && ch <= 13) mhz = 2407 + ch * 5;
            }
            if (previous == null || frame.timestamp() >= previous.time) {
                int interval = frame.beaconIntervalTu() > 0 ? frame.beaconIntervalTu()
                        : (previous == null ? 100 : previous.beaconIntervalTu);
                Double rssi = Double.isFinite(frame.rssi()) ? Double.valueOf(frame.rssi())
                        : (previous == null ? null : previous.rssi);
                observedAps.put(token, new ObservedAp(frameBssid, ssidBytes, ssidLabel, ssidToken,
                        ch, mhz, interval, rssi, frame.timestamp()));
            }
            if (observedAps.size() > AP_DIRECTORY_LIMIT) observedAps.pollFirstEntry();
        } else if (frame.management() && (frame.subtype() == 0 || frame.subtype() == 2)
                && frameBssid != null && frameBssid.equals(frame.addr1())) {
            String token = addressId(frameBssid);
            var previous = observedAps.get(token);
            byte[] ssid = frame.ies() == null ? new byte[0] : frame.ies().first(0);
            if (previous != null && previous.ssidBytes == null && !Dot11InformationElements.hidden(ssid)) {
                observedAps.put(token, new ObservedAp(previous.address, ssid.clone(),
                        Dot11InformationElements.ssidLabel(ssid), ids.id("topology-ssid", ssid),
                        previous.channel, previous.frequencyMhz, previous.beaconIntervalTu,
                        previous.rssi, Math.max(previous.time, frame.timestamp())));
            }
        }
        boolean inScope = bssids.isEmpty() || allowsBssid(frameBssid);
        boolean auditProbe = frame.probe() && (inScope || neighborhoodProbes);
        if (!inScope && !auditProbe) return IGNORED;

        String sender = addressId(frame.addr2());
        boolean local = OuiLookup.isLocallyAdministered(HexFormat.ofDelimiter(":").parseHex(frame.addr2()));
        boolean capabilities = frame.management() && (frame.probe() || frame.apAdvertisement()
                || frame.subtype() == 0 || frame.subtype() == 2);
        String signature = capabilities ? IeSignature.of(frame.ies()) : null;
        boolean directed = false, wps = false;
        if (auditProbe) {
            byte[] ssid = frame.ies().first(0);
            directed = !Dot11InformationElements.hidden(ssid);
            wps = frame.ies().hasWpsUuidE();
            audit.observe(frame.timestamp(), sender, local, signature, wps, ssid, directed, ids);
        }
        if (!inScope) return PROBE_ONLY;
        inventory.observe(frame, sender, local, signature, directed, wps);
        String client = topology.observe(frame, sender);
        if (client != null) {
            observedClients.put(addressId(client), new ObservedClient(client, frame.timestamp()));
            if (observedClients.size() > CLIENT_DIRECTORY_LIMIT) observedClients.pollFirstEntry();
            inventory.confirmClient(addressId(client), client, frame.timestamp());
        }
        return auditProbe ? BOTH : INVENTORY;
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
                case 11 -> bssid.equals(frame.addr1()) || bssid.equals(frame.addr2()) ? bssid : null;
                default -> null;
            };
        }
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

    public synchronized WifiInventory.Detail inventoryDetail(String id) {
        long now = clock.getAsLong();
        purge(now);
        return inventory.detail(id, now - retention);
    }

    public ProbeAuditAggregator.Report audit() {
        ProbeAuditAggregator.PendingReport pending;
        synchronized (this) {
            pending = audit.prepareSnapshot(clock.getAsLong(), retention);
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
