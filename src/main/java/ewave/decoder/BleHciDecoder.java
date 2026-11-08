package ewave.decoder;

import ewave.model.BleAdvertisement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.LinkedHashSet;

/** HCI LE legacy/extended advertising reports, including multiple reports per event.
 * Partial extended payloads are skipped; this implementation does not reassemble them.
 */
public final class BleHciDecoder {
    private final LinkedHashSet<String> incomplete = new LinkedHashSet<>();
    public BleHciDecoder() { }

    /** Input starts at the HCI event code (no H4 packet-type prefix). */
    public static List<BleAdvertisement> decode(byte[] event, long timestamp) {
        return new BleHciDecoder().accept(event, timestamp);
    }

    /** Reuse one instance per capture stream to suppress final pieces of known
     * fragmented reports as well as reports explicitly marked incomplete.
     */
    public List<BleAdvertisement> accept(byte[] event, long timestamp) {
        if (event == null || event.length < 4 || timestamp < 0 || (event[0] & 0xff) != 0x3e
                || (event[1] & 0xff) != event.length - 2) return List.of();
        int subevent = event[2] & 0xff;
        if (subevent != 0x02 && subevent != 0x0d) return List.of();
        boolean extended = subevent == 0x0d;
        var result = new ArrayList<BleAdvertisement>();
        int cursor = 4;
        for (int i = 0, count = event[3] & 0xff; i < count; i++) {
            int headerLength = extended ? 24 : 9;
            if (cursor + headerLength > event.length) return List.of();
            int type = extended ? u16(event, cursor) : event[cursor] & 0xff;
            int addressOffset = cursor + (extended ? 3 : 2);
            int addressType = event[cursor + (extended ? 2 : 1)] & 0xff;
            int size = event[cursor + headerLength - 1] & 0xff;
            int start = cursor + headerLength, end = start + size;
            if (end + (extended ? 0 : 1) > event.length) return List.of();
            if (!extended && (size > 31 || type > 4)) return List.of();
            boolean skipFragment = false;
            if (extended) {
                String key = addressType + ":" + address(event, addressOffset) + ":"
                        + (event[cursor + 11] & 0xff) + ":" + (type & 8);
                int status = (type >> 5) & 3;
                if (status == 1) {
                    incomplete.add(key);
                    if (incomplete.size() > 512) incomplete.remove(incomplete.iterator().next());
                    skipFragment = true;
                } else if (status != 0) { incomplete.remove(key); skipFragment = true; }
                else skipFragment = incomplete.remove(key);
            }
            if (!skipFragment && addressType <= 3) {
                String address = address(event, addressOffset);
                String kind = addressType(addressType, event[addressOffset + 5]);
                if (!address.equals("00:00:00:00:00:00") && !address.equals("ff:ff:ff:ff:ff:ff")) {
                    byte[] data = Arrays.copyOfRange(event, start, end);
                    int rssi = event[extended ? cursor + 13 : end];
                    Integer tx = extended ? signal(event[cursor + 12]) : null;
                    Integer sid = extended && (event[cursor + 11] & 0xff) <= 15 ? event[cursor + 11] & 0xff : null;
                    result.add(new BleAdvertisement("ble:" + addressType + ":" + address, address, kind,
                            extended ? (type & 8) != 0 : type == 4, extended, sid,
                            signal(rssi), tx, timestamp, HexFormat.of().formatHex(data), BleAdvertisementDecoder.decode(data), type));
                }
            }
            cursor = end + (extended ? 0 : 1);
        }
        return cursor == event.length ? List.copyOf(result) : List.of();
    }

    private static Integer signal(int value) { return value == 127 ? null : value; }
    private static int u16(byte[] b, int p) { return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8; }
    private static String address(byte[] b, int start) {
        byte[] address = new byte[6];
        for (int i = 0; i < 6; i++) address[i] = b[start + 5 - i];
        return HexFormat.ofDelimiter(":").formatHex(address);
    }
    private static String addressType(int type, byte highByte) {
        return switch (type) {
            case 0 -> "public";
            case 2 -> "public identity (controller-resolved)";
            case 3 -> "random identity (controller-resolved)";
            default -> switch ((highByte & 0xff) >>> 6) {
                case 0 -> "random non-resolvable";
                case 1 -> "random resolvable";
                case 3 -> "random static";
                default -> "random (reserved address bits)";
            };
        };
    }
}
