package ewave.fixtures;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** Synthetic frames: no real device addresses or captured network names. */
public final class ProbeFrames {
    private ProbeFrames() { }

    public static byte[] frame(String ssid) { return frame(ssid.getBytes(StandardCharsets.UTF_8)); }

    public static byte[] frame(byte[] ssid) {
        var bytes = new ByteArrayOutputStream();
        bytes.writeBytes(HexFormat.of().parseHex("40000000ffffffffffff021122334455ffffffffffff1000"));
        bytes.write(0);
        bytes.write(ssid.length);
        bytes.writeBytes(ssid);
        bytes.writeBytes(HexFormat.of().parseHex("010482848b9632030c1218dd0400112201"));
        return bytes.toByteArray();
    }

    public static byte[] radiotap(byte[] frame) {
        byte[] result = new byte[13 + frame.length];
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 0).put((byte) 0).putShort((short) 13).putInt(0x28)
                .putShort((short) 2437).putShort((short) 0xa0).put((byte) -47).put(frame);
        return result;
    }

    public static byte[] pcap(ByteOrder order, boolean nanos, int linkType, byte[]... packets) {
        var bytes = new ByteArrayOutputStream();
        bytes.writeBytes(ByteBuffer.allocate(24).order(order)
                .putInt(nanos ? 0xa1b23c4d : 0xa1b2c3d4).putShort((short) 2).putShort((short) 4)
                .putInt(0).putInt(0).putInt(262144).putInt(linkType).array());
        for (int i = 0; i < packets.length; i++) {
            byte[] packet = packets[i];
            bytes.writeBytes(ByteBuffer.allocate(16).order(order).putInt(1700000000 + i)
                    .putInt(nanos ? 123456789 : 123456).putInt(packet.length).putInt(packet.length).array());
            bytes.writeBytes(packet);
        }
        return bytes.toByteArray();
    }
}
