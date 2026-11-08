package ewave.capture;

import ewave.decoder.BleHciDecoder;
import ewave.model.BleAdvertisement;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Consumer;

/** Bounded, streaming BTSnoop reader: H4 (1002) or BlueZ monitor (2001). */
public final class BleCaptureReader {
    private static final long EPOCH_OFFSET = 0x00dcddb30f2f8000L;
    private BleCaptureReader() { }

    public static void read(InputStream input, int adapter, Consumer<BleAdvertisement> consumer) throws IOException {
        byte[] header = input.readNBytes(16);
        if (header.length == 0) throw new EOFException("No BLE capture data received; check adapter and capture permissions");
        if (header.length != 16) throw new EOFException("Truncated BTSnoop header");
        var global = ByteBuffer.wrap(header);
        if (!new String(header, 0, 8, StandardCharsets.US_ASCII).equals("btsnoop\0") || global.getInt(8) != 1)
            throw new IOException("Expected BTSnoop version 1");
        int format = global.getInt(12);
        if (format != 1002 && format != 2001) throw new IOException("Unsupported BTSnoop link type " + format);
        var decoder = new BleHciDecoder();
        while (!Thread.currentThread().isInterrupted()) {
            int first = input.read();
            if (first < 0) return;
            byte[] record = new byte[24];
            record[0] = (byte) first;
            System.arraycopy(exact(input, 23), 0, record, 1, 23);
            var fields = ByteBuffer.wrap(record);
            long original = Integer.toUnsignedLong(fields.getInt()), length = Integer.toUnsignedLong(fields.getInt());
            int flags = fields.getInt();
            fields.getInt(); // Cumulative controller drops are not inferred as advertisements.
            long timestamp = fields.getLong();
            if (length > 65535 || original > 65535 || length > original) throw new IOException("Invalid BTSnoop record length");
            if (timestamp < EPOCH_OFFSET) throw new IOException("Invalid BTSnoop timestamp");
            byte[] packet = exact(input, (int) length);
            if (length != original) continue;
            byte[] event;
            if (format == 1002) {
                if (packet.length == 0 || packet[0] != 4) continue;
                event = Arrays.copyOfRange(packet, 1, packet.length);
            } else {
                if ((flags & 0xffff) != 3 || (flags >>> 16) != adapter) continue;
                event = packet;
            }
            for (var advertisement : decoder.accept(event, (timestamp - EPOCH_OFFSET) / 1000))
                consumer.accept(advertisement);
        }
    }

    private static byte[] exact(InputStream input, int size) throws IOException {
        byte[] bytes = input.readNBytes(size);
        if (bytes.length != size) throw new EOFException("Truncated BTSnoop record");
        return bytes;
    }
}
