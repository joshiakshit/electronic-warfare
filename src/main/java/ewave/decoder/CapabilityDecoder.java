package ewave.decoder;

import java.util.LinkedHashSet;
import java.util.List;

/** Capability advertisements are upper bounds, independent of negotiated link parameters. */
public final class CapabilityDecoder {
    private CapabilityDecoder() { }

    public record Summary(String wifiGeneration, int spatialStreams, int maxWidthMhz,
                          boolean sgi, boolean ldpc, boolean stbcTx, boolean stbcRx,
                          boolean suBeamformee, boolean muBeamformee, boolean sixGhzCapability, String smPowerSave,
                          List<Double> supportedRates, List<Double> basicRates) { }

    public static Summary decode(Dot11InformationElements ies, int frequency) {
        return decode(ies, frequency, false);
    }

    public static Summary decode(Dot11InformationElements ies, int frequency, boolean fromAp) {
        var rates = new LinkedHashSet<Double>();
        var basic = new LinkedHashSet<Double>();
        for (var element : ies.elements()) {
            if (element.id() != 1 && element.id() != 50) continue;
            for (byte value : element.value()) {
                int rate = value & 127;
                if (rate == 0 || rate >= 120) continue;
                rates.add(rate / 2.0);
                if (value < 0) basic.add(rate / 2.0);
            }
        }
        String generation = rates.isEmpty() ? "Unknown"
                : rates.stream().allMatch(r -> r == 1 || r == 2 || r == 5.5 || r == 11) ? "802.11b"
                : frequency >= 5000 ? "802.11a" : frequency > 0 ? "802.11g" : "802.11a/g";
        int width = rates.isEmpty() ? 0 : 20, streams = 0;
        boolean sgi = false, ldpc = false, tx = false, rx = false, su = false, mu = false;
        String smps = "Unknown";
        byte[] ht = ies.first(45), vht = ies.first(191), he = ies.extension(35), eht = ies.extension(108);
        if (ht.length >= 26) {
            generation = "Wi-Fi 4";
            int info = u16(ht, 0);
            width = (info & 2) == 0 ? 20 : 40;
            for (int i = 0; i < 4; i++) if (ht[3 + i] != 0) streams = i + 1;
            ldpc = (info & 1) != 0;
            sgi = (info & 0x60) != 0;
            tx = (info & 0x80) != 0;
            rx = (info & 0x300) != 0;
            smps = switch ((info >> 2) & 3) {
                case 0 -> "Static";
                case 1 -> "Dynamic";
                case 3 -> "Disabled";
                default -> "Reserved";
            };
        }
        if (vht.length >= 12) {
            generation = "Wi-Fi 5";
            int info = u16(vht, 0) | u16(vht, 2) << 16;
            width = (info & 12) == 4 || (info & 12) == 8 ? 160 : 80;
            streams = Math.max(streams, streams(u16(vht, 4)));
            ldpc |= (info & 16) != 0;
            sgi |= (info & 96) != 0;
            tx |= (info & 128) != 0;
            rx |= (info & 0x700) != 0;
            su = (info & (1 << 12)) != 0;
            mu = (info & (1 << 20)) != 0;
        }
        if (he.length >= 22) {
            generation = frequency >= 5925 && frequency <= 7125 ? "Wi-Fi 6E" : "Wi-Fi 6";
            int widths = he[7] & 0xff;
            int heWidth = (widths & 24) != 0 ? 160 : (widths & 4) != 0 ? 80 : (widths & 2) != 0 ? 40 : 20;
            width = Math.max(width, heWidth);
            streams = Math.max(streams, streams(u16(he, 18)));
            ldpc |= (he[8] & 0x20) != 0;
            tx |= (he[9] & 4) != 0 || (he[14] & 0x40) != 0;
            rx |= (he[9] & 8) != 0 || (he[14] & 0x80) != 0;
            su |= (he[11] & 1) != 0;
            int cursor = 22;
            for (int flag : new int[]{8, 16}) {
                if ((widths & flag) == 0) continue;
                if (he.length >= cursor + 4) streams = Math.max(streams, streams(u16(he, cursor)));
                cursor += 4;
            }
        }
        if (eht.length >= 15 && he.length >= 22) {
            int widths = he[7] & 0xff;
            boolean wide320 = (eht[3] & 2) != 0;
            int size = (widths & 2) != 0 ? 3
                    : 3 * (Integer.bitCount(widths & 12) + (wide320 ? 1 : 0));
            if (size == 0) size = fromAp ? 3 : 4;
            if (eht.length >= 12 + size) {
                generation = "Wi-Fi 7";
                if (wide320 && frequency >= 5925 && frequency <= 7125) width = 320;
                su |= (eht[3] & 0x40) != 0;
                for (int i = 12; i < 12 + size; i++) {
                    int nss = eht[i] & 15;
                    if (nss <= 8) streams = Math.max(streams, nss);
                }
            }
        }
        return new Summary(generation, streams, width, sgi, ldpc, tx, rx, su, mu,
                ies.extension(59).length == 3, smps,
                List.copyOf(rates), List.copyOf(basic));
    }

    private static int streams(int map) {
        for (int n = 8; n > 0; n--) if (((map >> (2 * (n - 1))) & 3) != 3) return n;
        return 0;
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 0xff) | (data[offset + 1] & 0xff) << 8;
    }
}
