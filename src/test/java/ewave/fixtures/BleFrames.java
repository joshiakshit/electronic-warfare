package ewave.fixtures;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public final class BleFrames {
    private BleFrames() { }
    public static byte[] ad(int type, byte[] data) {
        var out = new ByteArrayOutputStream();
        out.write(data.length + 1); out.write(type); out.writeBytes(data);
        return out.toByteArray();
    }
    public static byte[] data() {
        return concat(ad(1, new byte[]{6}), ad(9, "Lab Tag".getBytes(StandardCharsets.UTF_8)),
                ad(3, new byte[]{0x0f, 0x18}), ad(0xff, HexFormat.of().parseHex("4c00010203")));
    }
    public static byte[] legacy(byte[] data) { return legacy(data, 1, HexFormat.of().parseHex("5544332211c2")); }
    public static byte[] legacy(byte[] data, int addressType, byte[] address) {
        return event(2, concat(new byte[]{0, (byte) addressType}, address,
                new byte[]{(byte) data.length}, data, new byte[]{-55}));
    }
    public static byte[] extended(byte[] data, int properties, int addressType) {
        var header = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        header.putShort((short) properties).put((byte) addressType).put(HexFormat.of().parseHex("5544332211c2"))
                .put((byte) 1).put((byte) 2).put((byte) 7).put((byte) -8).put((byte) -65)
                .putShort((short) 0).put((byte) 0).put(new byte[6]).put((byte) data.length);
        return event(0x0d, concat(header.array(), data));
    }
    public static byte[] event(int subevent, byte[]... reports) {
        byte[] data = concat(reports);
        return concat(new byte[]{0x3e, (byte) (data.length + 2), (byte) subevent, (byte) reports.length}, data);
    }
    public static byte[] snoop(int format, int index, byte[]... events) {
        var out = new ByteArrayOutputStream();
        out.writeBytes("btsnoop\0".getBytes(StandardCharsets.US_ASCII));
        out.writeBytes(ByteBuffer.allocate(8).putInt(1).putInt(format).array());
        for (int i = 0; i < events.length; i++) {
            byte[] packet = format == 1002 ? concat(new byte[]{4}, events[i]) : events[i];
            int flags = format == 1002 ? 3 : index << 16 | 3;
            out.writeBytes(ByteBuffer.allocate(24).putInt(packet.length).putInt(packet.length)
                    .putInt(flags).putInt(0).putLong(0x00dcddb30f2f8000L + 1_700_000_000_000_000L + i * 1000L).array());
            out.writeBytes(packet);
        }
        return out.toByteArray();
    }
    public static byte[] concat(byte[]... arrays) {
        var out = new ByteArrayOutputStream();
        for (byte[] bytes : arrays) out.writeBytes(bytes);
        return out.toByteArray();
    }
}
