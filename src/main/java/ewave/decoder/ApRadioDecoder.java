package ewave.decoder;

/** Operating parameters advertised by an AP, independently of advertised capabilities. */
public final class ApRadioDecoder {
    private ApRadioDecoder() { }

    public record Operation(int widthMhz, Integer bssColor) { }

    public static Operation decode(Dot11InformationElements ies) {
        byte[] ht = ies.first(61);
        int width = ht.length < 2 ? 0 : (ht[1] & 4) != 0 && (ht[1] & 3) != 0 ? 40 : 20;

        int vhtWidth = vhtWidth(ies.first(192), 0);
        if (vhtWidth != 0) width = vhtWidth;

        byte[] he = ies.extension(36);
        Integer color = null;
        if (he.length >= 5) {
            int colorInfo = he[4] & 0xff;
            if ((colorInfo & 0x80) == 0 && (colorInfo & 0x3f) != 0) color = colorInfo & 0x3f;
            if (he.length >= 7) {
                int pos = 7;
                if ((he[2] & 0x40) != 0) {
                    int embeddedVhtWidth = vhtWidth(he, pos);
                    if (embeddedVhtWidth != 0) width = embeddedVhtWidth;
                    pos += 3;
                }
                if ((he[2] & 0x80) != 0) pos++;
                if ((he[3] & 0x02) != 0 && he.length - pos >= 5) width = 20 << (he[pos + 1] & 3);
            }
        }

        byte[] eht = ies.extension(106);
        if (eht.length >= 9 && (eht[1] & 1) != 0) {
            int code = eht[6] & 7;
            if (code <= 4) width = 20 << code;
        }
        return new Operation(width, color);
    }

    private static int vhtWidth(byte[] data, int pos) {
        if (data.length - pos < 3) return 0;
        int center0 = data[pos + 1] & 0xff;
        int center1 = data[pos + 2] & 0xff;
        return switch (data[pos] & 0xff) {
            case 1 -> center1 != 0 && Math.abs(center1 - center0) == 8 ? 160 : 80;
            case 2, 3 -> 160;
            default -> 0;
        };
    }
}
