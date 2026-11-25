package ewave.decoder;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HexFormat;
import java.util.List;

/** Decodes supported 802.11 management frames and data headers from binary capture.
 * Supports LINKTYPE_IEEE802_11 (105) and LINKTYPE_IEEE802_11_RADIOTAP (127).
 */
public final class Dot11FrameDecoder {
    public static final int FT_ACTION_REQUEST = 601;
    public static final int FT_ACTION_RESPONSE = 602;
    public static final int BTM_ACTION_REQUEST = 1007;
    public static final int BTM_ACTION_RESPONSE = 1008;

    private Dot11FrameDecoder() { }

    /** Reads the monitor header and only those frame fields needed by passive consumers. */
    public static Dot11Frame decodeAny(byte[] packet, int linkType, long timestamp) {
        if (packet == null || timestamp < 0) return null;
        int offset = 0, end = packet.length, frequency = 0;
        double rssi = Double.NaN;
        Long tsft = null;
        Radiotap radiotap = null;
        if (linkType == 127) {
            var header = Radiotap.parse(packet);
            if (header == null || (header.flags() & 0x40) != 0) return null;
            offset = header.length();
            if ((header.flags() & 0x10) != 0) end -= 4;
            frequency = header.frequencyMhz();
            tsft = header.tsft();
            radiotap = header.metadata();
            if (radiotap.signalDbm() != null) rssi = radiotap.signalDbm();
        } else if (linkType != 105) {
            return null;
        }
        if (end - offset < 16) return null;
        int control = u16(packet, offset), type = (control >> 2) & 3, subtype = (control >> 4) & 15;
        int flags = control >> 8;
        if (!supportedFrameControl(control) || (type != 1 && end - offset < 24)) return null;
        String source = mac(packet, offset + 10);
        if ((packet[offset + 10] & 1) != 0 || source.equals("00:00:00:00:00:00")) return null;
        if (type == 1) {
            return new Dot11Frame(type, subtype, flags, 0, -1, mac(packet, offset + 4), source,
                    null, null, timestamp, frequency, rssi, tsft, end - offset, null,
                    null, 0, 0, null, -1, -1, radiotap);
        }

        int sequence = u16(packet, offset + 22);
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
            if ((sequence & 15) != 0) return null;
            boolean protectedBody = (flags & 0x40) != 0;
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
                case 10, 12 -> { if (!protectedBody) status = u16(packet, body); }
                case 13 -> {
                    int category = packet[body] & 0xff, action = packet[body + 1] & 0xff;
                    if (category == 6 && (action == 1 || action == 2)) {
                        fixed = action == 1 ? 14 : 16;
                        if (end - body < fixed) return null;
                        currentAp = mac(packet, body + 8);
                        auth = action == 1 ? FT_ACTION_REQUEST : FT_ACTION_RESPONSE;
                        if (action == 2) status = u16(packet, body + 14);
                    } else {
                        if (category == 10 && action == 7) {
                            if (end - body < 7) return null;
                            auth = BTM_ACTION_REQUEST;
                        } else if (category == 10 && action == 8) {
                            if (end - body < 5) return null;
                            auth = BTM_ACTION_RESPONSE;
                            status = packet[body + 3] & 0xff;
                            if (status == 0 && end - body >= 11) currentAp = mac(packet, body + 5);
                        }
                        ies = new Dot11InformationElements(List.of());
                    }
                }
                default -> { }
            }
            if (subtype == 2) currentAp = mac(packet, body + 4);
            if (subtype != 11 && ies == null) {
                ies = protectedBody ? new Dot11InformationElements(List.of())
                        : Dot11InformationElements.parse(packet, body + fixed, end);
                if (ies == null) return null;
            }
        }
        return new Dot11Frame(type, subtype, flags, sequence, tid, mac(packet, offset + 4), source,
                mac(packet, offset + 16), addr4, timestamp, frequency, rssi, tsft, end - offset, ies,
                beaconTsf, interval, capability, currentAp, status, auth, radiotap);
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
        if (control < 0 || (control & 3) != 0) return false;
        int type = (control >>> 2) & 3;
        int subtype = (control >>> 4) & 15;
        int flags = control >>> 8;
        return switch (type) {
            case 0 -> managementLength(subtype) >= 0 && (flags & 0x07) == 0
                    && ((flags & 0x40) == 0 || subtype == 10 || subtype == 12);
            case 1 -> subtype >= 8 && subtype <= 10;
            case 2 -> true;
            default -> false;
        };
    }

    private static int managementLength(int subtype) {
        return switch (subtype) {
            case 0 -> 4;
            case 1, 3, 11 -> 6;
            case 2 -> 10;
            case 4 -> 0;
            case 5, 8 -> 12;
            case 10, 12, 13 -> 2;
            default -> -1;
        };
    }

    public static int channel(int mhz) {
        if (mhz == 2484) return 14;
        if (mhz >= 2412 && mhz <= 2472 && (mhz - 2407) % 5 == 0) return (mhz - 2407) / 5;
        if (mhz >= 4910 && mhz <= 4980 && mhz % 5 == 0) return (mhz - 4000) / 5;
        if (mhz >= 5005 && mhz < 5925 && mhz % 5 == 0) return (mhz - 5000) / 5;
        if (mhz == 5935) return 2;
        if (mhz >= 5955 && mhz <= 7115 && (mhz - 5950) % 5 == 0) return (mhz - 5950) / 5;
        return 0;
    }

    private static String mac(byte[] bytes, int offset) {
        return HexFormat.ofDelimiter(":").formatHex(bytes, offset, offset + 6);
    }
    private static int u16(byte[] b, int p) { return (b[p] & 0xff) | (b[p + 1] & 0xff) << 8; }
    private static long i64(byte[] b, int p) { return ByteBuffer.wrap(b, p, 8).order(ByteOrder.LITTLE_ENDIAN).getLong(); }
}
