package ewave.decoder;

import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.CRC32;

/** Decodes channel and link hints from received AP advertisements. */
public final class Dot11ChannelSwitchDecoder {
    private static final HexFormat MAC_FORMAT = HexFormat.ofDelimiter(":");

    private Dot11ChannelSwitchDecoder() {}

    public record ChannelSwitch(int mode, int channel, int frequencyMhz, int switchCount) {}

    public record Neighbor(int operatingClass, int channel, int frequencyMhz, String bssid, Integer shortSsid,
                           boolean sameSsid, boolean coLocated, Integer mldId, Integer linkId) {}

    public record BasicMultiLink(String mldMac, Integer linkId) {}

    public static ChannelSwitch decodeChannelSwitch(Dot11InformationElements ies, int currentFrequencyMhz) {
        byte[] extended = ies.first(60);
        if (extended.length == 4) {
            int channel = u8(extended, 2);
            int frequency = operatingFrequency(u8(extended, 1), channel);
            if (frequency != 0) return new ChannelSwitch(u8(extended, 0), channel, frequency, u8(extended, 3));
        }
        byte[] basic = ies.first(37);
        if (basic.length != 3) return null;
        int channel = u8(basic, 1);
        int frequency = frequencyInBand(bandOf(currentFrequencyMhz), channel);
        return frequency == 0 ? null : new ChannelSwitch(u8(basic, 0), channel, frequency, u8(basic, 2));
    }

    public static List<Neighbor> decodeReducedNeighborReport(Dot11InformationElements ies) {
        var neighbors = new ArrayList<Neighbor>();
        for (var element : ies.elements()) {
            if (element.id() != 201) continue;
            byte[] bytes = element.value();
            for (int offset = 0; bytes.length - offset >= 4;) {
                int header = u16(bytes, offset);
                int count = ((header >>> 4) & 0x0f) + 1;
                int length = header >>> 8;
                int operatingClass = u8(bytes, offset + 2);
                int channel = u8(bytes, offset + 3);
                int frequency = operatingFrequency(operatingClass, channel);
                offset += 4;
                if (length == 0 || count * length > bytes.length - offset) break;
                if ((header & 0x03) == 0 && frequency != 0) {
                    for (int entry = 0; entry < count; entry++) {
                        neighbors.add(decodeNeighbor(bytes, offset + entry * length, length,
                                operatingClass, channel, frequency));
                    }
                }
                offset += count * length;
            }
        }
        return List.copyOf(neighbors);
    }

    private static Neighbor decodeNeighbor(byte[] bytes, int offset, int length,
                                           int operatingClass, int channel, int frequency) {
        String bssid = length >= 7 ? MAC_FORMAT.formatHex(bytes, offset + 1, offset + 7) : null;
        Integer shortSsid = null;
        int bssParams = 0;
        if (length >= 11) {
            shortSsid = u32(bytes, offset + 7);
            if (length >= 12) bssParams = u8(bytes, offset + 11);
        } else if (length == 5 || length == 6) {
            shortSsid = u32(bytes, offset + 1);
            if (length == 6) bssParams = u8(bytes, offset + 5);
        } else if (length == 2 || length == 3) {
            bssParams = u8(bytes, offset + 1);
        } else if (length == 8 || length == 9) {
            bssParams = u8(bytes, offset + 7);
        }
        return new Neighbor(operatingClass, channel, frequency, bssid, shortSsid,
                (bssParams & 0x02) != 0, (bssParams & 0x40) != 0,
                length >= 16 ? u8(bytes, offset + 13) : null,
                length >= 16 ? u8(bytes, offset + 14) & 0x0f : null);
    }

    public static int shortSsidCrc32(byte[] ssidBytes) {
        var crc = new CRC32();
        crc.update(ssidBytes);
        return (int) crc.getValue();
    }

    public static BasicMultiLink decodeBasicMultiLink(Dot11InformationElements ies) {
        byte[] value = ies.extension(107);
        if (value.length < 10) return null;
        int control = u16(value, 1);
        int commonLength = u8(value, 3);
        if ((control & 0x07) != 0 || commonLength < 7 || commonLength > value.length - 3) return null;
        Integer linkId = null;
        if ((control & 0x0010) != 0) {
            if (commonLength < 8) return null;
            linkId = u8(value, 10) & 0x0f;
        }
        return new BasicMultiLink(MAC_FORMAT.formatHex(value, 4, 10), linkId);
    }

    private static int operatingFrequency(int operatingClass, int channel) {
        if (operatingClass >= 81 && operatingClass <= 84) return frequencyInBand(2, channel);
        if (operatingClass >= 115 && operatingClass <= 130) return frequencyInBand(5, channel);
        if (operatingClass >= 131 && operatingClass <= 137) return frequencyInBand(6, channel);
        return 0;
    }

    private static int bandOf(int frequency) {
        if (frequency >= 2412 && frequency <= 2484) return 2;
        if (frequency >= 5005 && frequency < 5925) return 5;
        if (frequency >= 5935 && frequency <= 7115) return 6;
        return 0;
    }

    private static int frequencyInBand(int band, int channel) {
        return switch (band) {
            case 2 -> channel == 14 ? 2484 : channel >= 1 && channel <= 13 ? 2407 + 5 * channel : 0;
            case 5 -> channel >= 1 && channel <= 184 ? 5000 + 5 * channel : 0;
            case 6 -> channel == 2 ? 5935 : channel >= 1 && channel <= 233 ? 5950 + 5 * channel : 0;
            default -> 0;
        };
    }

    private static int u8(byte[] value, int offset) { return value[offset] & 0xff; }

    private static int u16(byte[] value, int offset) {
        return u8(value, offset) | u8(value, offset + 1) << 8;
    }

    private static int u32(byte[] value, int offset) {
        return u16(value, offset) | u16(value, offset + 2) << 16;
    }
}
