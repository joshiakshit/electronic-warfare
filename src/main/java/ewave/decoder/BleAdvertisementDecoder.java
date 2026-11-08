package ewave.decoder;

import ewave.model.BlePayload;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.UUID;

/** Bluetooth GAP Advertising Data decoder. No vendor/owner guesses or network requests. */
public final class BleAdvertisementDecoder {
    private BleAdvertisementDecoder() { }

    public static BlePayload decode(byte[] bytes) {
        if (bytes == null || bytes.length > 1650) throw new IllegalArgumentException("BLE advertising data exceeds 1650 bytes");
        String name = null;
        boolean completeName = false;
        Integer flags = null, txPower = null, appearance = null;
        var uuids = new LinkedHashSet<String>();
        var manufacturers = new ArrayList<BlePayload.ManufacturerData>();
        var services = new ArrayList<BlePayload.ServiceData>();
        var structures = new ArrayList<BlePayload.Structure>();
        var warnings = new ArrayList<String>();
        for (int cursor = 0; cursor < bytes.length;) {
            int length = bytes[cursor++] & 0xff;
            if (length == 0) {
                for (int p = cursor; p < bytes.length; p++) if (bytes[p] != 0) {
                    warnings.add("Nonzero bytes after AD terminator"); break;
                }
                break;
            }
            if (cursor + length > bytes.length) { warnings.add("Truncated AD structure"); break; }
            int type = bytes[cursor] & 0xff, start = cursor + 1, size = length - 1;
            String hex = HexFormat.of().formatHex(bytes, start, start + size);
            structures.add(new BlePayload.Structure(type, hex));
            switch (type) {
                case 0x01 -> {
                    if (size >= 1 && size <= 3) flags = bytes[start] & 0xff;
                    else warnings.add("Invalid flags length");
                }
                case 0x08, 0x09 -> {
                    if (name == null || type == 0x09 || !completeName) {
                        name = displayName(bytes, start, size);
                        completeName = type == 0x09;
                    }
                }
                case 0x0a -> {
                    if (size == 1) txPower = (int) bytes[start];
                    else warnings.add("Invalid TX power length");
                }
                case 0x19 -> {
                    if (size == 2) appearance = u16(bytes, start);
                    else warnings.add("Invalid appearance length");
                }
                case 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 -> {
                    int width = type <= 3 ? 2 : type <= 5 ? 4 : 16;
                    if (size % width != 0) warnings.add("Invalid service UUID list length");
                    else for (int p = start; p < start + size; p += width) uuids.add(uuid(bytes, p, width));
                }
                case 0x16, 0x20, 0x21 -> {
                    int width = type == 0x16 ? 2 : type == 0x20 ? 4 : 16;
                    if (size < width) warnings.add("Truncated service data UUID");
                    else services.add(new BlePayload.ServiceData(uuid(bytes, start, width),
                            HexFormat.of().formatHex(bytes, start + width, start + size)));
                }
                case 0xff -> {
                    if (size < 2) warnings.add("Missing manufacturer company ID");
                    else manufacturers.add(new BlePayload.ManufacturerData(u16(bytes, start),
                            HexFormat.of().formatHex(bytes, start + 2, start + size)));
                }
                default -> { /* Unknown AD structures remain visible as raw hex. */ }
            }
            cursor += length;
        }
        return new BlePayload(name, completeName, flags, txPower, appearance,
                uuids.stream().toList(), manufacturers, services, structures, warnings);
    }

    private static String uuid(byte[] bytes, int offset, int width) {
        ByteBuffer value = ByteBuffer.wrap(bytes, offset, width).order(ByteOrder.LITTLE_ENDIAN);
        if (width == 2) return String.format("0000%04x-0000-1000-8000-00805f9b34fb", u16(bytes, offset));
        if (width == 4) return String.format("%08x-0000-1000-8000-00805f9b34fb", value.getInt());
        long low = value.getLong(), high = value.getLong();
        return new UUID(high, low).toString();
    }

    private static String displayName(byte[] bytes, int offset, int length) {
        try {
            String decoded = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes, offset, length)).toString();
            var result = new StringBuilder();
            decoded.codePoints().forEach(c -> {
                if (c == '\\') result.append("\\\\");
                else if (Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)
                    result.append(String.format("\\u%04x", c));
                else result.appendCodePoint(c);
            });
            return result.toString();
        } catch (CharacterCodingException invalid) {
            return "hex:" + HexFormat.of().formatHex(bytes, offset, offset + length);
        }
    }
    private static int u16(byte[] bytes, int p) { return (bytes[p] & 0xff) | (bytes[p + 1] & 0xff) << 8; }
}
