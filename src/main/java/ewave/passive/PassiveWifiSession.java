package ewave.passive;

import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.decoder.IeSignature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/** Only pseudonymized or aggregate observations outlive the packet callback. */
public final class PassiveWifiSession {
    private static final int AP_DIRECTORY_LIMIT = 512;
    private static final int CLIENT_DIRECTORY_LIMIT = 4096;
    private static final long DIRECTORY_TTL = TimeUnit.MINUTES.toMillis(10);
    private record ObservedAp(String address, String ssidToken, int channel, Double rssi, long time) { }
    private record ObservedClient(String address, long time) { }
    public record Observation(boolean inventory, boolean probe) { }
    private static final Observation IGNORED = new Observation(false, false);
    private static final Observation INVENTORY = new Observation(true, false);
    private static final Observation PROBE_ONLY = new Observation(false, true);
    private static final Observation BOTH = new Observation(true, true);

    private final LongSupplier clock;
    private final SessionIdentifiers ids = new SessionIdentifiers();
    private final long retention = RfSettings.retentionMillis();
    private final List<String> commandLineBssids = configuredBssids();
    private final LinkedHashMap<String, ObservedAp> observedAps = new LinkedHashMap<>(16, .75f, true);
    private final LinkedHashMap<String, ObservedClient> observedClients = new LinkedHashMap<>(16, .75f, true);
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
        this.clock = Objects.requireNonNull(clock);
        inventory = new WifiInventory(profiler.ouiLookup(), new FingerprintDb());
        boolean revealNames = Boolean.parseBoolean(
                System.getProperty("audit.revealSsids", Boolean.toString(revealNamesByDefault)));
        audit = new ProbeAuditAggregator(revealNames);
        topology = new TopologyBuilder(ids, this::allowsBssid, revealNames);
        configure(profile);
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
                .map(row -> new MyNetworkProfile.NearbyAp(row.getKey(), row.getValue().channel,
                        row.getValue().rssi, row.getValue().time))
                .sorted(java.util.Comparator.comparing(MyNetworkProfile.NearbyAp::token)).toList();
    }

    public synchronized List<String> findAccessPoints(String name) {
        byte[] bytes = name == null ? new byte[0] : name.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0 || bytes.length > 32)
            throw new IllegalArgumentException("Enter a network name of 1–32 Wi-Fi bytes");
        String ssidToken = ids.id("topology-ssid", bytes);
        long cutoff = clock.getAsLong() - DIRECTORY_TTL;
        return observedAps.entrySet().stream()
                .filter(row -> row.getValue().time >= cutoff && ssidToken.equals(row.getValue().ssidToken))
                .map(java.util.Map.Entry::getKey).toList();
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
            String ssidToken = Dot11InformationElements.hidden(ssid) ? previous == null ? null : previous.ssidToken
                    : ids.id("topology-ssid", ssid);
            if (previous == null || frame.timestamp() >= previous.time)
                observedAps.put(token, new ObservedAp(frameBssid, ssidToken, Dot11FrameDecoder.channel(frame.frequencyMhz()),
                        Double.isFinite(frame.rssi()) ? frame.rssi() : null, frame.timestamp()));
            if (observedAps.size() > AP_DIRECTORY_LIMIT) observedAps.pollFirstEntry();
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

    public synchronized List<WifiInventory.Device> inventory() { purge(clock.getAsLong()); return inventory.snapshot(); }
    public synchronized WifiInventory.Detail inventoryDetail(String id) {
        long now = clock.getAsLong();
        purge(now);
        return inventory.detail(id, now - retention);
    }
    public synchronized ProbeAuditAggregator.Report audit() { return audit.snapshot(clock.getAsLong(), retention); }
    public synchronized TopologyBuilder.Snapshot topology() { purge(clock.getAsLong()); return topology.snapshot(retention); }

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
