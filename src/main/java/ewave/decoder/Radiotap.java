package ewave.decoder;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Receiver metadata reported for one frame. An absent or unknown field is null. */
public record Radiotap(Integer channelFlags, Double legacyRateMbps, Integer signalDbm, Integer noiseDbm,
                       Integer antenna, Integer snrDb, HtRate ht, HeRate he) {
    public record HtRate(Integer mcs, String bandwidth, Boolean shortGuardInterval) { }
    public record HeRate(String format, Integer mcs, Integer spaceTimeStreams, String bandwidthOrRu,
                         Double guardIntervalUs, Boolean dualCarrierModulation) { }

    record Header(int length, int flags, int frequencyMhz, Long tsft, Radiotap metadata) { }
    private record AntennaSample(Integer signal, Integer noise, Integer antenna) { }

    private static final int[] ALIGNMENTS = {8, 1, 1, 2, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2, 2,
            1, 1, 4, 1, 4, 2, 8, 2, 2, 2, 1, 2};
    private static final int[] SIZES = {8, 1, 1, 4, 2, 1, 1, 2, 2, 2, 1, 1, 1, 1, 2, 2,
            1, 1, 8, 3, 8, 12, 12, 12, 12, 6, 1, 4};
    private static final String[] HT_BANDWIDTHS = {"20 MHz", "40 MHz", "20 MHz lower", "20 MHz upper"};
    private static final String[] HE_FORMATS = {"HE SU", "HE extended SU", "HE MU", "HE trigger-based"};
    private static final String[] HE_BANDWIDTHS = {"20 MHz", "40 MHz", "80 MHz", "160/80+80 MHz",
            "26-tone RU", "52-tone RU", "106-tone RU", "242-tone RU", "484-tone RU", "996-tone RU", "2×996-tone RU"};
    private static final double[] HE_GI = {0.8, 1.6, 3.2};

    static Header parse(byte[] packet) {
        if (packet.length < 8 || packet[0] != 0) return null;
        int length = u16(packet, 2);
        if (length < 8 || length > packet.length) return null;
        int cursor = 4, word;
        do {
            if (length - cursor < 4) return null;
            word = i32(packet, cursor);
            cursor += 4;
        } while (word < 0);
        int presentEnd = cursor;
        int flags = 0, frequency = 0, base = 0;
        boolean standard = true;
        Long tsft = null;
        Integer channelFlags = null;
        Double rate = null;
        HtRate ht = null;
        HeRate he = null;
        AntennaSample sample = new AntennaSample(null, null, null);
        for (int pos = 4; pos < presentEnd; pos += 4) {
            word = i32(packet, pos);
            Integer signal = null, noise = null, antenna = null;
            boolean unknown = false;
            if (standard) {
                for (int bit = 0; bit < 29; bit++) {
                    if ((word & (1 << bit)) == 0) continue;
                    int index = base + bit;
                    if (index >= SIZES.length) {
                        // An unknown layout (or terminal TLV area) prevents walking later fields.
                        unknown = true;
                        break;
                    }
                    cursor = align(cursor, ALIGNMENTS[index]);
                    if (length - cursor < SIZES[index]) return null;
                    switch (index) {
                        case 0 -> { if (tsft == null) tsft = ByteBuffer.wrap(packet, cursor, 8).order(ByteOrder.LITTLE_ENDIAN).getLong(); }
                        case 1 -> flags |= packet[cursor] & 0xff;
                        case 2 -> { if (rate == null) rate = (packet[cursor] & 0xff) / 2.0; }
                        case 3 -> {
                            if (channelFlags == null) {
                                frequency = u16(packet, cursor);
                                channelFlags = u16(packet, cursor + 2);
                            }
                        }
                        case 5 -> signal = (int) packet[cursor];
                        case 6 -> noise = (int) packet[cursor];
                        case 11 -> antenna = packet[cursor] & 0xff;
                        case 19 -> { if (ht == null) ht = htRate(packet, cursor); }
                        case 23 -> { if (he == null) he = heRate(packet, cursor); }
                        default -> { }
                    }
                    cursor += SIZES[index];
                }
                if (sample.signal() == null && (signal != null || sample.noise() == null && sample.antenna() == null)) {
                    sample = new AntennaSample(signal, noise, antenna);
                }
            }
            if (unknown) break;
            if ((word & 0x40000000) != 0) {
                cursor = align(cursor, 2);
                if (length - cursor < 6) return null;
                cursor += 6 + u16(packet, cursor + 4);
                if (cursor > length) return null;
                standard = false;
                base = 0;
            } else if ((word & 0x20000000) != 0) {
                standard = true;
                base = 0;
            } else {
                base += 32;
            }
        }
        Integer snr = sample.signal() == null || sample.noise() == null ? null : sample.signal() - sample.noise();
        return new Header(length, flags, frequency, tsft,
                new Radiotap(channelFlags, rate, sample.signal(), sample.noise(), sample.antenna(), snr, ht, he));
    }

    private static HtRate htRate(byte[] packet, int offset) {
        int known = packet[offset] & 0xff, flags = packet[offset + 1] & 0xff;
        return new HtRate((known & 2) != 0 ? packet[offset + 2] & 0xff : null,
                (known & 1) != 0 ? HT_BANDWIDTHS[flags & 3] : null, (known & 4) != 0 ? (flags & 4) != 0 : null);
    }

    private static HeRate heRate(byte[] packet, int offset) {
        int data1 = u16(packet, offset), data2 = u16(packet, offset + 2), data3 = u16(packet, offset + 4);
        int data5 = u16(packet, offset + 8), streams = u16(packet, offset + 10) & 15;
        int bandwidth = data5 & 15, gi = (data5 >> 4) & 3;
        return new HeRate(HE_FORMATS[data1 & 3], (data1 & 0x20) != 0 ? (data3 >> 8) & 15 : null,
                streams == 0 ? null : streams,
                (data1 & 0x4000) != 0 && bandwidth < HE_BANDWIDTHS.length ? HE_BANDWIDTHS[bandwidth] : null,
                (data2 & 2) != 0 && gi < HE_GI.length ? HE_GI[gi] : null,
                (data1 & 0x40) != 0 ? (data3 & 0x1000) != 0 : null);
    }

    private static int align(int offset, int alignment) { return (offset + alignment - 1) & -alignment; }
    private static int u16(byte[] packet, int offset) { return (packet[offset] & 0xff) | (packet[offset + 1] & 0xff) << 8; }
    private static int i32(byte[] packet, int offset) { return u16(packet, offset) | u16(packet, offset + 2) << 16; }
}
