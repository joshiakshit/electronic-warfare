package ewave.decoder;

import java.nio.charset.StandardCharsets;

/** Hostname and hardware details advertised in AP management frames. */
public final class ApHardwareDecoder {
    private ApHardwareDecoder() { }

    public record WpsInfo(String state, Boolean apSetupLocked, String manufacturer, String modelName,
                          String modelNumber, String deviceName) {
        private WpsInfo merge(WpsInfo newer) {
            return new WpsInfo(prefer(newer.state, state), prefer(newer.apSetupLocked, apSetupLocked),
                    prefer(newer.manufacturer, manufacturer), prefer(newer.modelName, modelName),
                    prefer(newer.modelNumber, modelNumber), prefer(newer.deviceName, deviceName));
        }

        private static <T> T prefer(T latest, T previous) { return latest == null ? previous : latest; }
    }

    public record Summary(String apHostname, WpsInfo wpsInfo) { }

    public static Summary decode(Dot11InformationElements ies) {
        byte[] ccx = ies.first(133);
        String hostname = ccx.length >= 26 ? ascii(ccx, 10, 16) : null;
        WpsInfo wps = null;
        for (var ie : ies.elements()) {
            String vendor = ie.vendorKey();
            if ("000b8601".equals(vendor) && hostname == null) {
                byte[] data = ie.value();
                if (data.length >= 6 && data[4] == 3) hostname = ascii(data, 5, Math.min(32, data.length - 5));
            } else if ("0050f204".equals(vendor)) {
                WpsInfo decoded = wps(ie.value());
                wps = wps == null ? decoded : wps.merge(decoded);
            }
        }
        return new Summary(hostname, wps);
    }

    private static WpsInfo wps(byte[] data) {
        String state = null, manufacturer = null, modelName = null, modelNumber = null, deviceName = null;
        Boolean locked = null;
        for (int pos = 4; data.length - pos >= 4;) {
            int id = u16be(data, pos);
            int length = u16be(data, pos + 2);
            pos += 4;
            if (length > data.length - pos) break;
            switch (id) {
                case 0x1044 -> {
                    if (length == 1 && data[pos] == 1) state = "Unconfigured";
                    if (length == 1 && data[pos] == 2) state = "Configured";
                }
                case 0x1057 -> {
                    if (length == 1) locked = data[pos] != 0;
                }
                case 0x1021 -> manufacturer = utf8(data, pos, length);
                case 0x1023 -> modelName = utf8(data, pos, length);
                case 0x1024 -> modelNumber = utf8(data, pos, length);
                case 0x1011 -> deviceName = utf8(data, pos, length);
                default -> { }
            }
            pos += length;
        }
        return new WpsInfo(state, locked, manufacturer, modelName, modelNumber, deviceName);
    }

    private static int u16be(byte[] data, int pos) {
        return (data[pos] & 0xff) << 8 | (data[pos + 1] & 0xff);
    }

    private static String ascii(byte[] data, int pos, int length) {
        var label = new StringBuilder(length);
        for (int i = pos; i < pos + length && data[i] != 0; i++) {
            if (data[i] >= 0x20 && data[i] <= 0x7e) label.append((char) data[i]);
        }
        return nonblank(label);
    }

    private static String utf8(byte[] data, int pos, int length) {
        var label = new StringBuilder();
        new String(data, pos, length, StandardCharsets.UTF_8).codePoints()
                .filter(ApHardwareDecoder::printable).limit(64).forEach(label::appendCodePoint);
        return nonblank(label);
    }

    private static boolean printable(int codePoint) {
        return codePoint != 0xfffd && switch (Character.getType(codePoint)) {
            case Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR -> false;
            default -> true;
        };
    }

    private static String nonblank(StringBuilder label) {
        String text = label.toString().strip();
        return text.isEmpty() ? null : text;
    }
}
