package ewave.decoder;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/** Ordered TLVs, including repeated and extension elements. Scoped to one decoded frame. */
public record Dot11InformationElements(List<Element> elements) {
    public Dot11InformationElements { elements = List.copyOf(elements); }

    public record Element(int id, byte[] value) {
        public Element { value = value.clone(); }
        @Override public byte[] value() { return value.clone(); }
        public int extension() { return id == 255 && value.length > 0 ? value[0] & 0xff : -1; }
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

    public static boolean hidden(byte[] ssid) {
        for (byte octet : ssid) if (octet != 0) return false;
        return true;
    }

    public static String ssidLabel(byte[] ssid) {
        String name = new String(ssid, StandardCharsets.UTF_8);
        return Arrays.equals(ssid, name.getBytes(StandardCharsets.UTF_8))
                ? name : "SSID bytes " + HexFormat.ofDelimiter(" ").formatHex(ssid);
    }

    /** WPS UUID-E presence only. Never reads or returns the identifier itself. */
    public boolean hasWpsUuidE() {
        for (var element : elements) {
            if (!"0050f204".equals(element.vendorKey())) continue;
            byte[] bytes = element.value;
            for (int pos = 4; bytes.length - pos >= 4;) {
                int attr = (bytes[pos] & 0xff) << 8 | bytes[pos + 1] & 0xff;
                int size = (bytes[pos + 2] & 0xff) << 8 | bytes[pos + 3] & 0xff;
                pos += 4;
                if (size > bytes.length - pos) break;
                if (attr == 0x1047 && size == 16) return true;
                pos += size;
            }
        }
        return false;
    }
}
