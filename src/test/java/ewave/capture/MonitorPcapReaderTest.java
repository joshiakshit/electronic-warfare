package ewave.capture;

import ewave.fixtures.ProbeFrames;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11Frame;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.function.Consumer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MonitorPcapReaderTest {
    @Test void streamsBothByteOrdersAndTimestampResolutions() throws Exception {
        for (var order : List.of(ByteOrder.BIG_ENDIAN, ByteOrder.LITTLE_ENDIAN)) {
            for (boolean nanos : new boolean[]{false, true}) {
                var probes = new ArrayList<Dot11Frame>();
                byte[] bytes = ProbeFrames.pcap(order, nanos, 127,
                        ProbeFrames.radiotap(ProbeFrames.frame("Lab")), ProbeFrames.radiotap(ProbeFrames.frame("")));
                readProbes(new ByteArrayInputStream(bytes), probes::add);
                assertEquals(2, probes.size());
                assertEquals(1_700_000_000_123L, probes.getFirst().timestamp());
                assertTrue(probes.getLast().ies().first(0).length == 0);
            }
        }
    }

    @Test void rejectsBadHeadersUnsupportedLinksAndUnsafeRecordLengths() {
        byte[] good = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 105, ProbeFrames.frame("Lab"));
        for (int cut : new int[]{0, 3, 23, 25, 39, good.length - 1}) {
            assertThrows(IOException.class, () -> read(Arrays.copyOf(good, cut)));
        }
        byte[] ethernet = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 1);
        assertTrue(assertThrows(IOException.class, () -> read(ethernet)).getMessage().contains("monitor-mode"));
        for (int offset : new int[]{0, 16, 32, 36}) {
            byte[] bad = good.clone();
            ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putInt(offset, -1);
            assertThrows(IOException.class, () -> read(bad));
        }
        byte[] badTimestamp = good.clone();
        ByteBuffer.wrap(badTimestamp).order(ByteOrder.LITTLE_ENDIAN).putInt(28, 1_000_000);
        assertThrows(IOException.class, () -> read(badTimestamp));
    }

    @Test void distinguishesNoCaptureOutputFromAnIncompletePcapHeader() {
        var empty = assertThrows(IOException.class, () -> read(new byte[0]));
        assertTrue(empty.getMessage().contains("No PCAP data received"));
        var partial = assertThrows(IOException.class, () -> read(new byte[7]));
        assertTrue(partial.getMessage().contains("Truncated PCAP header (7 of 24 bytes)"));
    }

    @Test void skipsTruncatedAndNonProbePacketsAndContinuesAfterMalformedFrames() throws Exception {
        byte[] nonProbe = ProbeFrames.frame("Beacon");
        nonProbe[0] = (byte) 0x80;
        byte[] bytes = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 105,
                ProbeFrames.frame("cut"), nonProbe, new byte[4], ProbeFrames.frame("Good"));
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).putInt(36, 999); // First record was snapped.
        var result = read(bytes);
        assertEquals(1, result.size());
        assertEquals("476f6f64", HexFormat.of().formatHex(result.getFirst().ies().first(0)));
    }

    @Test void decodesCheckedInPcapFixture() throws Exception {
        var probes = new ArrayList<Dot11Frame>();
        try (var stream = getClass().getResourceAsStream("/probes/probe-requests.pcap")) {
            assertNotNull(stream);
            readProbes(stream, probes::add);
        }
        assertEquals(List.of("4c61622028677565737429", "", "436166c3a9", "fffe"),
                probes.stream().map(probe -> HexFormat.of().formatHex(probe.ies().first(0))).toList());
    }

    private static void readProbes(InputStream input, Consumer<Dot11Frame> probes) throws IOException {
        MonitorPcapReader.read(input, (packet, linkType, timestamp) -> {
            var probe = Dot11FrameDecoder.decodeAny(packet, linkType, timestamp);
            if (probe != null && probe.probe()) probes.accept(probe);
        });
    }

    private static List<Dot11Frame> read(byte[] bytes) throws IOException {
        var result = new ArrayList<Dot11Frame>();
        readProbes(new ByteArrayInputStream(bytes), result::add);
        return result;
    }
}
