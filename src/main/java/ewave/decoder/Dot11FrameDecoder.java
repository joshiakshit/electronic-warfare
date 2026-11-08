package ewave.decoder;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HexFormat;

/** Decodes supported 802.11 management frames and data headers from binary capture.
 * Supports LINKTYPE_IEEE802_11 (105) and LINKTYPE_IEEE802_11_RADIOTAP (127).
 */
public final class Dot11FrameDecoder {
    private Dot11FrameDecoder() { }

    private static final int[] ALIGNMENTS = {8, 1, 1, 2, 2, 1};
    private static final int[] SIZES = {8, 1, 1, 4, 2, 1};

    /** Reads the monitor header and only those frame fields needed by passive consumers. */
    public static Dot11Frame decodeAny(byte[] packet, int linkType, long timestamp) {
        if (packet == null || timestamp < 0) return null;
        int offset = 0, end = packet.length, frequency = 0;
        double rssi = Double.NaN;
        Long tsft = null;
        if (linkType == 127) {
            if (end < 8 || packet[0] != 0) return null;
            offset = u16(packet, 2);
            if (offset < 8 || offset > end) return null;
            int present = i32(packet, 4), word = present, cursor = 8;
            while ((word & 0x80000000) != 0) {
                if (cursor + 4 > offset) return null;
                word = i32(packet, cursor);
                cursor += 4;
            }
            for (int bit = 0; bit <= 5; bit++) {
                if ((present & (1 << bit)) == 0) continue;
                cursor = (cursor + ALIGNMENTS[bit] - 1) & -ALIGNMENTS[bit];
                if (cursor + SIZES[bit] > offset) return null;
                if (bit == 0) tsft = i64(packet, cursor);
                if (bit == 1) {
                    int flags = packet[cursor] & 0xff;
                    if ((flags & 0x40) != 0) return null;
                    if ((flags & 0x10) != 0) end -= 4;
                }
                if (bit == 3) frequency = u16(packet, cursor);
                if (bit == 5) rssi = packet[cursor];
                cursor += SIZES[bit];
            }
        } else if (linkType != 105) {
            return null;
        }
        if (end - offset < 24) return null;
        int control = u16(packet, offset), type = (control >> 2) & 3, subtype = (control >> 4) & 15;
        int flags = control >> 8, sequence = u16(packet, offset + 22);
        if ((control & 3) != 0 || (type != 0 && type != 2)) return null;
        String source = mac(packet, offset + 10);
        if ((packet[offset + 10] & 1) != 0 || source.equals("00:00:00:00:00:00")) return null;

        int body = offset + 24, tid = -1, interval = 0, capability = 0, status = -1, auth = -1;
        String addr4 = null, currentAp = null;
        Long beaconTsf = null;
        Dot11InformationElements ies = null;
        if (type == 2) {
            if ((flags & 3) == 3) {
                if (end - body < 6) return null;
                addr4 = mac(packet, body);
                body += 6;
            }
            if ((subtype & 8) != 0) {
                if (end - body < 2) return null;
                tid = packet[body] & 15;
                body += 2;
                if ((flags & 0x80) != 0 && end - body < 4) return null;
            }
        } else {
            if ((flags & 0x47) != 0 || (sequence & 15) != 0) return null;
            if ((flags & 0x80) != 0) body += 4;
            int fixed = managementLength(subtype);
            if (fixed < 0 || end - body < fixed) return null;
            switch (subtype) {
                case 0, 2 -> capability = u16(packet, body);
                case 1, 3 -> status = u16(packet, body + 2);
                case 5, 8 -> {
                    beaconTsf = i64(packet, body);
                    interval = u16(packet, body + 8);
                    capability = u16(packet, body + 10);
                }
                case 11 -> { auth = u16(packet, body); status = u16(packet, body + 4); }
                default -> { }
            }
            if (subtype == 2) currentAp = mac(packet, body + 4);
            if (subtype != 11) {
                ies = Dot11InformationElements.parse(packet, body + fixed, end);
                if (ies == null) return null;
            }
        }
        return new Dot11Frame(type, subtype, flags, sequence, tid, mac(packet, offset + 4), source,
                mac(packet, offset + 16), addr4, timestamp, frequency, rssi, tsft, end - offset, ies,
                beaconTsf, interval, capability, currentAp, status, auth);
    }

    /** Header peek for diagnostics, including types the inventory decoder intentionally ignores. */
    public static int frameControl(byte[] packet, int linkType) {
        int offset = 0;
        if (linkType == 127) {
            if (packet.length < 8 || packet[0] != 0) return -1;
            offset = u16(packet, 2);
            if (offset < 8) return -1;
        } else if (linkType != 105) {
            return -1;
        }
        if (packet.length - offset < 2) return -1;
        int control = u16(packet, offset);
        return (control & 3) == 0 ? control : -1;
    }

    public static boolean supportedFrameControl(int control) {
        int type = (control >>> 2) & 3;
        return type == 2 || type == 0 && managementLength((control >>> 4) & 15) >= 0;
    }

    private static int managementLength(int subtype) {
        return switch (subtype) {
            case 0 -> 4;
            case 1, 3, 11 -> 6;
            case 2 -> 10;
            case 4 -> 0;
            case 5, 8 -> 12;
            default -> -1;
        };
    }

    public static int channel(int mhz) {
        if (mhz == 2484) return 14;
        if (mhz >= 2412 && mhz <= 2472 && (mhz - 2407) % 5 == 0) return (mhz - 2407) / 5;
        if (mhz >= 5005 && mhz <= 5895 && mhz % 5 == 0) return (mhz - 5000) / 5;
        if (mhz == 5935) return 2;
        if (mhz >= 5955 && mhz <= 7115 && (mhz - 5950) % 5 == 0) return (mhz - 5950) / 5;
        return 0;
    }

    private static String mac(byte[] bytes, int offset) {
        return HexFormat.ofDelimiter(":").formatHex(bytes, offset, offset + 6);
    }
    private static int u16(byte[] b, int p) { return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8; }
    private static long i64(byte[] b, int p) { return ByteBuffer.wrap(b, p, 8).order(ByteOrder.LITTLE_ENDIAN).getLong(); }
    private static int i32(byte[] b, int p) { return u16(b, p) | u16(b, p + 2) << 16; }
}
