package ewave.passive;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.model.BleAdvertisement;
import ewave.model.BlePayload;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

final class BleClassifier {
    enum DeviceClass { PHONE_TABLET, WEARABLE, AUDIO, BEACON_TAG, HID, HEALTH_PERSONAL, IOT_SENSOR, TRACKER, INFRASTRUCTURE, UNKNOWN }

    record Rule(List<String> services, String continuity, Integer company, Boolean connectable,
                Integer appearanceCategory, String protocol, DeviceClass deviceClass, double confidence) { }
    record Beacon(UUID uuid, int major, int minor, int referencePower) {
        String enrollmentKey() { return uuid + ":" + major + ":" + minor; }
    }
    record Classification(DeviceClass deviceClass, double confidence, Set<String> services, Set<Integer> companies,
                          Set<String> continuityTypes, Set<String> eddystoneTypes, String fastPairModel,
                          boolean fastPairNonDiscoverable, Beacon beacon) { }

    private final Map<Integer, String> companies = loadCatalog("company-identifiers.csv");
    private final Map<Integer, String> gatt = loadCatalog("gatt-services.csv");
    private final Map<Integer, String> members = loadCatalog("member-services.csv");
    private final List<Rule> rules;

    BleClassifier() throws IOException {
        try (var resource = getClass().getResourceAsStream("/ble/rules.json")) {
            rules = List.of(new ObjectMapper().readValue(resource, Rule[].class));
        }
    }

    String company(int id) { return companies.get(id); }
    String service(String id) {
        int assigned = Integer.parseInt(id, 16);
        String name = gatt.get(assigned);
        return name != null ? name : members.get(assigned);
    }

    boolean adoptedService(String id) { return gatt.containsKey(Integer.parseInt(id, 16)); }

    Classification classify(BleAdvertisement advertisement) {
        BlePayload payload = advertisement.payload();
        var serviceIds = new LinkedHashSet<String>();
        for (String uuid : payload.serviceUuids()) addAssigned(serviceIds, uuid);
        var companyIds = new LinkedHashSet<Integer>();
        var types = new LinkedHashSet<String>();
        var eddystone = new LinkedHashSet<String>();
        Beacon beacon = null;
        for (var mfr : payload.manufacturerData()) {
            companyIds.add(mfr.companyId());
            if (mfr.companyId() == 0x004c) {
                Beacon found = apple(HexFormat.of().parseHex(mfr.dataHex()), types);
                if (found != null) beacon = found;
            }
        }
        String fastPairModel = null;
        boolean nonDiscoverable = false;
        for (var data : payload.serviceData()) {
            addAssigned(serviceIds, data.uuid());
            switch (BleDecoder.extract16BitUuid(data.uuid())) {
                case 0xfe2c -> {
                    if (data.dataHex().length() == 6) fastPairModel = data.dataHex();
                    else if (data.dataHex().length() > 6) nonDiscoverable = true;
                }
                case 0xfeaa -> {
                    if (data.dataHex().length() < 2) continue;
                    String type = switch (data.dataHex().substring(0, 2)) {
                        case "00" -> "UID";
                        case "10" -> "URL";
                        case "20" -> "TLM";
                        case "30" -> "EID";
                        default -> null;
                    };
                    if (type != null) eddystone.add(type);
                }
                default -> { }
            }
        }

        DeviceClass kind = DeviceClass.UNKNOWN;
        double confidence = 0;
        for (Rule rule : rules) {
            if (rule.services != null && rule.services.stream().noneMatch(serviceIds::contains)) continue;
            if (rule.continuity != null && !types.contains(rule.continuity)) continue;
            if (rule.company != null && !companyIds.contains(rule.company)) continue;
            if (rule.connectable != null && advertisement.connectable() != rule.connectable) continue;
            if (rule.appearanceCategory != null && (payload.appearance() == null
                    || rule.appearanceCategory != payload.appearance() >> 6)) continue;
            if ("Eddystone".equals(rule.protocol) && eddystone.isEmpty()) continue;
            kind = rule.deviceClass;
            confidence = rule.confidence;
            break;
        }
        return new Classification(kind, confidence, Set.copyOf(serviceIds), Set.copyOf(companyIds),
                Set.copyOf(types), Set.copyOf(eddystone), fastPairModel, nonDiscoverable, beacon);
    }

    private static void addAssigned(Set<String> ids, String uuid) {
        int id = BleDecoder.extract16BitUuid(uuid);
        if (id >= 0) ids.add("%04x".formatted(id));
    }

    private static final Map<Integer, String> APPLE = Map.ofEntries(
            Map.entry(2, "iBeacon"), Map.entry(3, "AirPrint"), Map.entry(5, "AirDrop"),
            Map.entry(6, "HomeKit"), Map.entry(7, "Proximity Pairing"), Map.entry(8, "Hey Siri"),
            Map.entry(9, "AirPlay Target"), Map.entry(10, "AirPlay Source"), Map.entry(11, "Magic Switch"),
            Map.entry(12, "Handoff"), Map.entry(13, "Tethering Target"), Map.entry(14, "Tethering Source"),
            Map.entry(15, "Nearby Action"), Map.entry(16, "Nearby Info"), Map.entry(18, "Find My"));

    private static Beacon apple(byte[] data, Set<String> types) {
        Beacon beacon = null;
        for (int pos = 0; data.length - pos >= 2;) {
            int type = data[pos++] & 0xff, length = data[pos++] & 0xff;
            if (length > data.length - pos) break;
            if (type == 2 && length == 21) {
                var bytes = java.nio.ByteBuffer.wrap(data, pos, length);
                beacon = new Beacon(new UUID(bytes.getLong(), bytes.getLong()), bytes.getShort() & 0xffff,
                        bytes.getShort() & 0xffff, bytes.get());
                types.add("iBeacon");
            } else if (type != 2) {
                types.add(APPLE.getOrDefault(type, "APPLE_0x%02x".formatted(type)));
            }
            pos += length;
        }
        return beacon;
    }

    private Map<Integer, String> loadCatalog(String file) throws IOException {
        var result = new HashMap<Integer, String>();
        var resource = getClass().getResourceAsStream("/ble/" + file);
        if (resource == null) return Map.of();
        try (var reader = new BufferedReader(new InputStreamReader(resource, StandardCharsets.UTF_8))) {
            reader.readLine();
            for (String row; (row = reader.readLine()) != null;) {
                String[] fields = row.split(",", 2);
                String name = fields[1];
                if (name.startsWith("\"")) name = name.substring(1, name.length() - 1).replace("\"\"", "\"");
                result.put(Integer.parseInt(fields[0], 16), name);
            }
        }
        return Map.copyOf(result);
    }
}
