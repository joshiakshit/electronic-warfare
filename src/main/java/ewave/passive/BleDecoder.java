package ewave.passive;

import java.util.Map;
import java.util.regex.Pattern;

/** Manufacturer payload hints, not authenticated device/model identification.
 * Payload bytes start AFTER the two-byte Bluetooth company identifier.
 */
public final class BleDecoder {
    public record BleFindings(String deviceType, String detail, boolean notable) { }

    private static final Pattern BASE_UUID = Pattern.compile(
            "0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb", Pattern.CASE_INSENSITIVE);
    private static final Map<Integer, String> SERVICES = Map.ofEntries(
            Map.entry(0xFCF1, "Google Nearby Share (Android phone)"),
            Map.entry(0xFD69, "Google Find My Device"),
            Map.entry(0xFDDF, "OPPO device service"),
            Map.entry(0xFEAA, "Google Eddystone Beacon"),
            Map.entry(0xFD5A, "Samsung SmartThings"),
            Map.entry(0x180D, "Heart Rate Monitor"),
            Map.entry(0x1812, "HID Device (keyboard/mouse/gamepad)"),
            Map.entry(0x180F, "Battery Service"),
            Map.entry(0x110B, "Audio Device (speaker/headphones)"),
            Map.entry(0x1803, "Link Loss (wearable)"),
            Map.entry(0x00EE, "Espressif custom service"),
            Map.entry(0x00FF, "Espressif custom service"));

    public BleFindings decode(int companyId, byte[] payload) {
        if (companyId == 0x004C) {
            int type = payload == null || payload.length == 0 ? -1 : Byte.toUnsignedInt(payload[0]);
            String label = switch (type) {
                case 0x02 -> "iBeacon";
                case 0x0C -> "Apple Handoff";
                case 0x0F -> "Apple Nearby Action";
                case 0x10 -> "Apple Nearby Info";
                case 0x09 -> "AirPlay device";
                default -> "Apple device";
            };
            boolean notable = type == 0x02 || type == 0x0C || type == 0x0F || type == 0x10;
            return new BleFindings(label, type < 0 ? "Apple company ID; no payload subtype available"
                    : "Apple company ID; payload subtype 0x" + Integer.toHexString(type)
                    + " (heuristic; device type and activity are unverified)", notable);
        }
        return switch (companyId) {
            case 0x0006 -> new BleFindings("Windows device", "Microsoft company ID (device type unverified)", false);
            case 0x0075 -> new BleFindings("Samsung device", "Samsung company ID (device type unverified)", false);
            case 0x0ECB -> new BleFindings("OPPO device", "OPPO company ID (device type unverified)", false);
            case 0x038F -> new BleFindings("IoT module (AI-Link)", "AI-Link company ID (device type unverified)", false);
            default -> new BleFindings("Unknown (company=0x" + Integer.toHexString(companyId) + ")",
                    "Unrecognized Bluetooth company ID", false);
        };
    }

    public String decodeService(int uuid16) { return SERVICES.get(uuid16); }

    /** Extracts an assigned number only from a complete Bluetooth base UUID. */
    public static int extract16BitUuid(String fullUuid) {
        if (fullUuid == null) return -1;
        var matcher = BASE_UUID.matcher(fullUuid);
        return matcher.matches() ? Integer.parseInt(matcher.group(1), 16) : -1;
    }

    public static String decodeServiceUuid(String fullUuid) {
        int code = extract16BitUuid(fullUuid);
        if (code == -1) return "Custom: " + fullUuid;
        return SERVICES.getOrDefault(code, "Service 0x" + Integer.toHexString(code));
    }
}
