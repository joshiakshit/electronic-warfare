package ewave.capture;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.BooleanSupplier;

/** Reads classic monitor-mode PCAP records in either byte order with bounded packet lengths. */
public final class MonitorPcapReader {
    private static final int MAX_PACKET = 1_048_576;

    @FunctionalInterface
    interface PacketConsumer {
        void accept(byte[] packet, int linkType, long timestamp);
    }

    @FunctionalInterface
    interface RecordConsumer {
        void accept(byte[] packet, int linkType, long timestamp, boolean complete);
    }

    private MonitorPcapReader() { }

    static void read(InputStream input, PacketConsumer consumer) throws IOException {
        readRecords(input, (packet, linkType, timestamp, complete) -> {
            if (complete) consumer.accept(packet, linkType, timestamp);
        });
    }

    static void readRecords(InputStream input, RecordConsumer consumer) throws IOException {
        read(input, consumer, null, () -> false);
    }

    /** Forwards complete records so a stop in the middle of a packet leaves a readable file. */
    public static void relay(InputStream input, OutputStream output, BooleanSupplier stopping) throws IOException {
        read(input, null, output, stopping);
    }

    private static void read(InputStream input, RecordConsumer consumer, OutputStream output, BooleanSupplier stopping)
            throws IOException {
        byte[] header = input.readNBytes(24);
        if (header.length == 0)
            throw new EOFException("No PCAP data received; check the capture interface and tcpdump permissions");
        if (header.length < 24) throw new EOFException("Truncated PCAP header (" + header.length + " of 24 bytes)");
        int magic = ByteBuffer.wrap(header).getInt();
        boolean nanos = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
        ByteOrder order = switch (magic) {
            case 0xa1b2c3d4, 0xa1b23c4d -> ByteOrder.BIG_ENDIAN;
            case 0xd4c3b2a1, 0x4d3cb2a1 -> ByteOrder.LITTLE_ENDIAN;
            default -> throw new IOException("Expected classic PCAP from tcpdump (PCAPNG is not supported)");
        };
        ByteBuffer global = ByteBuffer.wrap(header).order(order);
        if (global.getShort(4) != 2 || global.getShort(6) != 4) throw new IOException("Unsupported PCAP version");
        long snaplen = Integer.toUnsignedLong(global.getInt(16));
        int network = global.getInt(20), linkType = network & 0xffff;
        if (linkType != 105 && linkType != 127)
            throw new IOException("Capture requires an 802.11 monitor-mode interface; PCAP link type " + linkType);
        if (consumer != null && network != linkType) throw new IOException("Unsupported PCAP link-type flags");
        if (snaplen == 0 || snaplen > MAX_PACKET) throw new IOException("Unsupported PCAP snapshot length");
        if (output != null) {
            output.write(header);
            output.flush();
        }
        while (!Thread.currentThread().isInterrupted()) {
            byte[] record = readBytes(input, 16, stopping);
            if (record.length == 0) return;
            if (record.length < 16) {
                if (stopping.getAsBoolean()) return;
                throw new EOFException("Truncated PCAP stream");
            }
            ByteBuffer fields = ByteBuffer.wrap(record).order(order);
            long seconds = Integer.toUnsignedLong(fields.getInt());
            long fraction = Integer.toUnsignedLong(fields.getInt());
            long captured = Integer.toUnsignedLong(fields.getInt());
            long original = Integer.toUnsignedLong(fields.getInt());
            if (captured > snaplen || captured > original || captured > MAX_PACKET || original > MAX_PACKET)
                throw new IOException("Invalid PCAP packet length");
            if (fraction >= (nanos ? 1_000_000_000L : 1_000_000L)) throw new IOException("Invalid PCAP timestamp");
            byte[] packet = readBytes(input, (int) captured, stopping);
            if (packet.length < captured) {
                if (stopping.getAsBoolean()) return;
                throw new EOFException("Truncated PCAP stream");
            }
            if (output != null) {
                output.write(record);
                output.write(packet);
                output.flush();
            }
            if (consumer != null) {
                consumer.accept(packet, linkType, seconds * 1000 + fraction / (nanos ? 1_000_000 : 1000), captured == original);
            }
        }
    }

    private static byte[] readBytes(InputStream input, int length, BooleanSupplier stopping) throws IOException {
        try {
            return input.readNBytes(length);
        } catch (IOException failure) {
            if (stopping.getAsBoolean()) return new byte[0];
            throw failure;
        }
    }
}
