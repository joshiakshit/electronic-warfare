package ewave.passive;

import ewave.model.BleAdvertisement;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;

/** Unenrolled BLE reports only contribute to aggregate counters and a short distinct-address window. */
public final class PassiveBleSession {
    private static final int ADDRESS_LIMIT = 8192, HISTORY_LIMIT = 128;
    private static final long ADDRESS_WINDOW = TimeUnit.MINUTES.toMillis(15);
    private static final long INTERVAL_GAP_MS = 10_000;

    public record Sample(long timestamp, Integer rssi, String proximityZone) { }
    public record Asset(String id, String label, String addressType, String pduType, boolean connectable,
                        boolean scannable, boolean directed, String deviceClass, double confidence,
                        List<String> companies, List<String> services, List<String> continuityTypes,
                        List<String> eddystoneTypes, String fastPairModelId, boolean fastPairNonDiscoverable,
                        int localNameLength, Integer flags, Integer appearance, Integer txPower,
                        Double intervalMsMedian, List<Sample> history) { }
    public record RegistryMatch(String kind, String code, String name, long advertisements) { }
    public record Report(long advertisements, Map<String, Long> advertisementsByClass,
                         Map<String, Long> pduCounts, Map<String, Long> addressTypeCounts,
                         Map<String, Long> protocolCounts, Map<String, Long> companyCounts,
                         Map<String, Long> serviceCounts, Map<String, Integer> observedAddressesByClass,
                         int addressWindowMinutes, boolean addressLimitReached, List<Asset> enrolledAssets,
                         List<RegistryMatch> registryMatches) { }
    private record Address(long lastSeen, String deviceClass) { }

    private final SessionIdentifiers ids = new SessionIdentifiers();
    private final BleClassifier classifier = new BleClassifier();
    private final AssetAllowlist allowlist = new AssetAllowlist();
    private final long retention = RfSettings.retentionMillis();
    private final double exponent = Double.parseDouble(System.getProperty("ble.pathLossExponent", "2.5"));
    private final Integer referencePower = System.getProperty("ble.refPower1m") == null ? null
            : RfSettings.integer("ble.refPower1m", -59, -127, 0);

    private final LinkedHashMap<String, Address> addresses = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<String, Long> sensitive = new LinkedHashMap<>(16, 0.75f, true);
    private final Map<String, History> assets = new TreeMap<>();
    private final Map<String, Long> classes = new TreeMap<>(), pdus = new TreeMap<>(), addressTypes = new TreeMap<>(),
            protocols = new TreeMap<>(), servicesByUuid = new TreeMap<>();
    private final Map<Integer, Long> companiesById = new TreeMap<>();
    private long advertisements, nextPurge, overflowTime = -1;

    public PassiveBleSession() throws IOException {
        if (!Double.isFinite(exponent) || exponent <= 0) throw new IllegalArgumentException("ble.pathLossExponent must be positive");
    }

    public synchronized void observe(BleAdvertisement advertisement) {
        long now = System.currentTimeMillis(), time = advertisement.timestamp();
        if (now >= nextPurge) purge(now);
        if (time < now - retention) return;
        var finding = classifier.classify(advertisement);
        String kind = finding.deviceClass().name();
        String address = ids.id("ble-address", advertisement.deviceId());
        var asset = allowlist.match(advertisement.addressType(), advertisement.address(), finding.beacon());
        boolean health = finding.deviceClass() == BleClassifier.DeviceClass.HEALTH_PERSONAL;
        if (health) {
            sensitive.merge(address, time, Math::max);
            if (sensitive.size() > ADDRESS_LIMIT) sensitive.pollFirstEntry();
            addresses.remove(address);
            assets.values().removeIf(history -> address.equals(history.lastAddress));
            if (asset != null) assets.remove(ids.id("ble-asset", asset.key()));
        }
        if (sensitive.containsKey(address)) kind = "HEALTH_PERSONAL";
        String pdu = pdu(advertisement);
        advertisements++;
        classes.merge(kind, 1L, Long::sum);
        if (kind.equals("HEALTH_PERSONAL") || finding.services().contains("fd6f")) return;
        for (int company : finding.companies()) {
            if (classifier.company(company) != null) companiesById.merge(company, 1L, Long::sum);
        }
        for (String service : finding.services()) {
            if (classifier.service(service) != null) servicesByUuid.merge(service, 1L, Long::sum);
        }
        pdus.merge(pdu, 1L, Long::sum);
        addressTypes.merge(advertisement.addressType(), 1L, Long::sum);
        finding.continuityTypes().forEach(type -> protocols.merge("Apple " + type, 1L, Long::sum));
        finding.eddystoneTypes().forEach(type -> protocols.merge("Eddystone " + type, 1L, Long::sum));
        if (finding.fastPairModel() != null) protocols.merge("Fast Pair discoverable", 1L, Long::sum);
        if (finding.fastPairNonDiscoverable()) protocols.merge("Fast Pair non-discoverable", 1L, Long::sum);

        Address previous = addresses.get(address);
        if (previous == null || time >= previous.lastSeen) addresses.put(address, new Address(time, kind));
        if (addresses.size() > ADDRESS_LIMIT) overflowTime = Math.max(overflowTime, addresses.pollFirstEntry().getValue().lastSeen);

        if (asset == null) return;
        String assetId = ids.id("ble-asset", asset.key());
        var history = assets.computeIfAbsent(assetId, key -> new History());
        if (!history.samples.isEmpty() && time < history.samples.getLast().timestamp) return;
        if (!advertisement.scanResponse()) {
            if (!Objects.equals(history.lastAddress, address) || !Objects.equals(history.lastSid, advertisement.advertisingSid()))
                history.times.clear();
            history.lastSid = advertisement.advertisingSid();
            if (!history.times.isEmpty() && time - history.times.getLast() > INTERVAL_GAP_MS) history.times.clear();
            if (history.times.isEmpty() || time > history.times.getLast()) {
                if (history.times.size() == 32) history.times.removeFirst();
                history.times.addLast(time);
            }
        }
        history.lastAddress = address;
        if (history.samples.size() == HISTORY_LIMIT) history.samples.removeFirst();
        Integer power = finding.beacon() == null ? referencePower : Integer.valueOf(finding.beacon().referencePower());
        String zone = zone(history.samples, advertisement.rssi(), power);
        history.samples.addLast(new Sample(time, advertisement.rssi(), zone));
        List<String> companies = finding.companies().stream().sorted().map(id -> {
            String name = classifier.company(id);
            return name == null ? "0x%04x".formatted(id) : name;
        }).toList();
        List<String> services = finding.services().stream().sorted().map(id -> {
            String name = classifier.service(id);
            return name == null ? "0x" + id : name;
        }).toList();
        int nameLength = advertisement.payload().structures().stream()
                .filter(structure -> structure.type() == 8 || structure.type() == 9)
                .mapToInt(structure -> structure.dataHex().length() / 2).max().orElse(0);
        var payload = advertisement.payload();
        history.latest = new Asset(assetId, asset.label(), advertisement.addressType(), pdu, advertisement.connectable(),
                advertisement.scannable(), advertisement.directed(), kind, finding.confidence(), companies, services,
                finding.continuityTypes().stream().sorted().toList(), finding.eddystoneTypes().stream().sorted().toList(),
                finding.fastPairModel(), finding.fastPairNonDiscoverable(), nameLength, payload.flags(), payload.appearance(),
                payload.txPower() == null ? advertisement.txPower() : payload.txPower(), null, List.of());
    }

    public synchronized Report snapshot() {
        long now = System.currentTimeMillis();
        purge(now);
        var distinct = new TreeMap<String, Integer>();
        addresses.values().forEach(address -> distinct.merge(address.deviceClass, 1, Integer::sum));
        var matches = new ArrayList<RegistryMatch>();
        var companies = new TreeMap<String, Long>();
        var services = new TreeMap<String, Long>();
        companiesById.forEach((id, count) -> {
            String name = classifier.company(id);
            matches.add(new RegistryMatch("COMPANY_ID", "0x%04X".formatted(id), name, count));
            companies.merge(name, count, Long::sum);
        });
        servicesByUuid.forEach((id, count) -> {
            String name = classifier.service(id);
            String kind = classifier.adoptedService(id) ? "GATT_SERVICE" : "MEMBER_UUID";
            matches.add(new RegistryMatch(kind, "0x" + id.toUpperCase(java.util.Locale.ROOT), name, count));
            services.merge(name, count, Long::sum);
        });
        matches.sort(Comparator.comparingLong(RegistryMatch::advertisements).reversed()
                .thenComparing(RegistryMatch::kind).thenComparing(RegistryMatch::code));
        return new Report(advertisements, Map.copyOf(classes), Map.copyOf(pdus), Map.copyOf(addressTypes), Map.copyOf(protocols),
                Map.copyOf(companies), Map.copyOf(services), Map.copyOf(distinct), 15, overflowTime >= now - ADDRESS_WINDOW,
                assets.values().stream().map(History::snapshot).toList(), List.copyOf(matches));
    }

    public synchronized void purge() { purge(System.currentTimeMillis()); }

    private void purge(long now) {
        nextPurge = now + TimeUnit.MINUTES.toMillis(1);
        sensitive.values().removeIf(lastSeen -> lastSeen < now - Math.min(retention, ADDRESS_WINDOW));
        addresses.values().removeIf(address -> address.lastSeen < now - Math.min(retention, ADDRESS_WINDOW));
        assets.values().removeIf(history -> {
            history.samples.removeIf(sample -> sample.timestamp < now - retention);
            history.times.removeIf(time -> time < now - retention);
            return history.samples.isEmpty();
        });
    }

    private String zone(ArrayDeque<Sample> samples, Integer rssi, Integer power) {
        if (rssi == null || power == null || power < -127 || power > 0) return null;
        var signals = new ArrayList<Double>();
        signals.add(rssi.doubleValue());
        for (Sample sample : samples.reversed()) {
            if (sample.rssi != null) signals.add(sample.rssi.doubleValue());
            if (signals.size() == 5) break;
        }
        signals.sort(Comparator.naturalOrder());
        double meters = Math.pow(10, (power - WifiInventory.median(signals)) / (10 * exponent));
        return meters < 1 ? "IMMEDIATE" : meters < 5 ? "NEAR" : "FAR";
    }

    private static String pdu(BleAdvertisement advertisement) {
        int type = advertisement.hciEventType();
        if (type < 0) return "UNKNOWN";
        if (advertisement.extended() && (type & 16) != 0) {
            type = switch (type & 31) {
                case 0x13 -> 0;
                case 0x15 -> 1;
                case 0x10 -> 2;
                case 0x12 -> 3;
                case 0x1a, 0x1b -> 4;
                default -> -1;
            };
        } else if (advertisement.extended()) {
            return advertisement.scanResponse() ? "EXTENDED_SCAN_RESPONSE" : "EXTENDED_ADV";
        }
        return switch (type) {
            case 0 -> "ADV_IND";
            case 1 -> "ADV_DIRECT_IND";
            case 2 -> "ADV_NONCONN_IND";
            case 3 -> "ADV_SCAN_IND";
            case 4 -> "SCAN_RSP";
            default -> "UNKNOWN";
        };
    }

    private static final class History {
        final ArrayDeque<Sample> samples = new ArrayDeque<>();
        final ArrayDeque<Long> times = new ArrayDeque<>();
        Asset latest;
        String lastAddress;
        Integer lastSid;

        Asset snapshot() {
            var deltas = new ArrayList<Double>();
            long previous = -1;
            for (long time : times) {
                if (previous >= 0) deltas.add((double) (time - previous));
                previous = time;
            }
            deltas.sort(Comparator.naturalOrder());
            return new Asset(latest.id, latest.label, latest.addressType, latest.pduType, latest.connectable,
                    latest.scannable, latest.directed, latest.deviceClass, latest.confidence, latest.companies,
                    latest.services, latest.continuityTypes, latest.eddystoneTypes, latest.fastPairModelId,
                    latest.fastPairNonDiscoverable, latest.localNameLength, latest.flags, latest.appearance,
                    latest.txPower, deltas.size() < 4 ? null : WifiInventory.median(deltas), List.copyOf(samples));
        }
    }
}
