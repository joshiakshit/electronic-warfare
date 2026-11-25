package ewave.decoder;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.IntPredicate;

/** Ordered TLVs, including repeated and extension elements. Scoped to one decoded frame. */
public record Dot11InformationElements(List<Element> elements) {
    public Dot11InformationElements { elements = List.copyOf(elements); }

    public record Element(int id, byte[] value) {
        public Element { value = value.clone(); }
        @Override public byte[] value() { return value.clone(); }
        public int size() { return value.length; }
        public int extension() { return id == 255 && value.length > 0 ? value[0] & 0xff : -1; }
        public String vendorOui() {
            return id == 221 && value.length >= 3 ? HexFormat.of().formatHex(value, 0, 3) : null;
        }
        public String vendorKey() {
            return id == 221 && value.length >= 4 ? HexFormat.of().formatHex(value, 0, 4) : null;
        }
    }

    static Dot11InformationElements parse(byte[] frame, int start, int end) {
        var elements = new ArrayList<Element>();
        boolean hasSsid = false;
        for (int pos = start; pos < end;) {
            if (end - pos < 2) return null;
            int id = frame[pos++] & 0xff, length = frame[pos++] & 0xff;
            if (length > end - pos || (id == 0 && (hasSsid || length > 32))) return null;
            hasSsid |= id == 0;
            elements.add(new Element(id, Arrays.copyOfRange(frame, pos, pos + length)));
            pos += length;
        }
        return new Dot11InformationElements(elements);
    }

    public byte[] first(int id) {
        for (var element : elements) if (element.id == id) return element.value();
        return new byte[0];
    }

    public byte[] extension(int id) {
        for (var element : elements) if (element.extension() == id) return element.value();
        return new byte[0];
    }

    public boolean has(int id) { return elements.stream().anyMatch(element -> element.id == id); }

    static boolean capabilityBit(byte[] capabilities, int bit) {
        int octet = bit / 8;
        return octet < capabilities.length && (capabilities[octet] & (1 << (bit % 8))) != 0;
    }

    public static boolean hidden(byte[] ssid) {
        for (byte octet : ssid) if (octet != 0) return false;
        return true;
    }

    public static String ssidLabel(byte[] ssid) {
        String name = new String(ssid, StandardCharsets.UTF_8);
        return Arrays.equals(ssid, name.getBytes(StandardCharsets.UTF_8))
                ? name : "SSID bytes " + HexFormat.ofDelimiter(" ").formatHex(ssid);
    }

    /** Non-placeholder WPS enrollee identifier. Tokenize it before retaining observations. */
    public Optional<byte[]> wpsUuidE() {
        byte[] payload = vendorPayload("0050f204");
        return wpsAttribute(payload, 0, payload.length, 0x1047, size -> size == 16,
                bytes -> !all(bytes, (byte) 0) && !all(bytes, (byte) 0xff));
    }

    public boolean hasWpsUuidE() { return wpsUuidE().isPresent(); }

    public record WpsDeviceType(int category, int subcategory) { }

    public Optional<WpsDeviceType> wpsPrimaryDeviceType() {
        byte[] payload = vendorPayload("0050f204");
        return wpsAttribute(payload, 0, payload.length, 0x1054, size -> size == 8, bytes -> true)
                .map(bytes -> new WpsDeviceType(unsignedShort(bytes, 0), unsignedShort(bytes, 6)));
    }

    public Optional<String> wpsManufacturer() {
        byte[] payload = vendorPayload("0050f204");
        return wpsAttribute(payload, 0, payload.length, 0x1021, size -> size > 0 && size <= 64, bytes -> true)
                .map(bytes -> new String(bytes, StandardCharsets.UTF_8).strip());
    }

    /** Retains vendor identifiers and type bytes without retaining vendor payloads. */
    public List<String> vendorElements() {
        return elements.stream().filter(element -> element.id == 221 && element.size() >= 3)
                .map(Dot11InformationElements::vendorLabel).distinct().toList();
    }

    private static String vendorLabel(Element element) {
        String key = element.vendorKey();
        if (key != null) {
            switch (key) {
                case "0050f204": return "00:50:f2:04 (WPS)";
                case "0050f202": return "00:50:f2:02 (WMM)";
                case "0050f208": return "00:50:f2:08 (Microsoft)";
                case "506f9a09": return "50:6f:9a:09 (Wi-Fi P2P)";
                default: break;
            }
        }
        return switch (element.vendorOui()) {
            case "0017f2" -> "00:17:f2 (Apple)";
            case "00a040" -> "00:a0:40 (Apple)";
            case "0000f0" -> "00:00:f0 (Samsung)";
            case "001a11" -> "00:1a:11 (Google)";
            default -> HexFormat.ofDelimiter(":").formatHex(element.value, 0, Math.min(4, element.size()));
        };
    }

    public List<byte[]> probeSsidsInList() {
        var names = new ArrayList<byte[]>();
        for (var element : elements) {
            if (element.id != 84) continue;
            byte[] bytes = element.value;
            for (int pos = 0; bytes.length - pos >= 2;) {
                int id = bytes[pos++] & 0xff, size = bytes[pos++] & 0xff;
                if (size > bytes.length - pos) break;
                if (id == 0 && size > 0 && size <= 32) {
                    byte[] ssid = Arrays.copyOfRange(bytes, pos, pos + size);
                    if (!hidden(ssid)) names.add(ssid);
                }
                pos += size;
            }
        }
        return List.copyOf(names);
    }

    public List<Integer> shortSsidList() {
        var hashes = new ArrayList<Integer>();
        for (var element : elements) {
            if (element.extension() != 58 || element.size() < 5 || (element.size() - 1) % 4 != 0) continue;
            var entries = ByteBuffer.wrap(element.value, 1, element.size() - 1).order(ByteOrder.LITTLE_ENDIAN);
            while (entries.hasRemaining()) hashes.add(entries.getInt());
        }
        return List.copyOf(hashes);
    }

    public boolean hasPasspoint() {
        return elements.stream().anyMatch(element -> element.id == 107 || element.id == 111
                || "506f9a10".equals(element.vendorKey()));
    }

    public Optional<String> p2pDeviceName() {
        byte[] bytes = vendorPayload("506f9a09");
        for (int pos = 0; bytes.length - pos >= 3;) {
            int id = bytes[pos++] & 0xff;
            int size = (bytes[pos++] & 0xff) | (bytes[pos++] & 0xff) << 8;
            if (size > bytes.length - pos) break;
            if (id == 0x0d && size >= 17) {
                // Skip device address, config methods, primary type and secondary types.
                int attributes = pos + 17 + 8 * (bytes[pos + 16] & 0xff);
                if (attributes <= pos + size) {
                    var name = wpsAttribute(bytes, attributes, pos + size, 0x1011,
                            length -> length > 0 && length <= 32, value -> true)
                            .map(value -> new String(value, StandardCharsets.UTF_8)
                                    .replaceAll("[\\p{Cc}\\p{Cf}]", "").strip())
                            .filter(value -> !value.isEmpty());
                    if (name.isPresent()) return name;
                }
            }
            pos += size;
        }
        return Optional.empty();
    }

    private byte[] vendorPayload(String key) {
        var payload = new ByteArrayOutputStream();
        for (var element : elements) {
            if (key.equals(element.vendorKey())) payload.write(element.value, 4, element.size() - 4);
        }
        return payload.toByteArray();
    }

    private static Optional<byte[]> wpsAttribute(byte[] bytes, int start, int end, int type,
                                                 IntPredicate validSize, java.util.function.Predicate<byte[]> valid) {
        for (int pos = start; end - pos >= 4;) {
            int attr = unsignedShort(bytes, pos);
            int size = unsignedShort(bytes, pos + 2);
            pos += 4;
            if (size > end - pos) break;
            if (attr == type && validSize.test(size)) {
                byte[] value = Arrays.copyOfRange(bytes, pos, pos + size);
                if (valid.test(value)) return Optional.of(value);
            }
            pos += size;
        }
        return Optional.empty();
    }

    private static int unsignedShort(byte[] bytes, int pos) {
        return (bytes[pos] & 0xff) << 8 | (bytes[pos + 1] & 0xff);
    }

    private static boolean all(byte[] value, byte match) {
        for (byte octet : value) if (octet != match) return false;
        return true;
    }
}
