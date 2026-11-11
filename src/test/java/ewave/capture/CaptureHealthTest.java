package ewave.capture;

import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class CaptureHealthTest {
    @Test void samplesRadioSettingsAndAgesRateBuckets() {
        var radio = RadioStatus.parse("""
                Interface wlo1
                    type monitor
                    channel 6 (2437 MHz), width: 20 MHz (no HT), center1: 2437 MHz
                """, 1234);
        assertEquals(new RadioStatus.Settings("monitor", 6, 2437, 20, "no HT", 1234), radio);
        var health = new CaptureHealth();
        health.updateRadio(radio);
        health.record(0x0040, true, null, 1234, 1250, 1000);
        health.record(0x00c0, true, null, 1234, 1250, 1000);
        health.record(0x0008, false, null, 1235, 1255, 1001);
        var fresh = health.snapshot("passive-rf", "wlo1", true, null, null, null, 1300, 2000);
        assertEquals(45L, fresh.sinceLastFrameMs());
        assertEquals(2L, fresh.frameCounts().get("management"));
        assertEquals(0.2, fresh.framesPerSecond().get("management"));
        assertEquals(1, fresh.rejected());
        assertEquals(1, fresh.unsupported());
        assertEquals(1, fresh.truncated());
        assertNull(fresh.kernelDrops());
        health.diagnostics("tcpdump: 3 packets captured, 5 packets received by filter, 2 packets dropped by kernel", 1350);
        var later = health.snapshot("passive-rf", "wlo1", true, null, null, null, 12000, 12000);
        assertEquals(0.0, later.framesPerSecond().get("management"));
        assertEquals(2L, later.kernelDrops());
        assertEquals(1350L, later.dropStatsAt());
        assertSame(radio, later.radio());
    }

    @Test void replaysAnOldPcapThroughInventoryAndAuditWithoutStartingAProcess(@TempDir Path directory) throws Exception {
        byte[] probe = ProbeFrames.radiotap(ProbeFrames.frame("Replay only"));
        byte[] unsupported = ProbeFrames.radiotap(new byte[]{4, 0});
        byte[] truncated = ProbeFrames.radiotap(new byte[]{8, 0});
        byte[] bad = new byte[]{0};
        byte[] pcap = ProbeFrames.pcap(ByteOrder.BIG_ENDIAN, true, 127, probe, unsupported, truncated, bad);
        int thirdRecord = 24 + 16 + probe.length + 16 + unsupported.length;
        ByteBuffer.wrap(pcap).putInt(thirdRecord + 12, truncated.length + 4);
        Path file = directory.resolve("recorded.pcap");
        Files.write(file, pcap);
        try (var bridge = new PacketBridge(builder -> {
            fail("Offline replay started an external process");
            return null;
        }, Map.of())) {
            bridge.startReplay(file);
            awaitReplay(bridge);
            var report = bridge.getCaptureHealth();
            assertEquals("replay", report.mode());
            assertEquals("COMPLETE", report.replayState());
            assertEquals("recorded.pcap", report.source());
            assertEquals(1_700_000_003_123L, report.referenceTime());
            assertEquals(1_700_000_003_123L, report.lastPacketAt());
            assertEquals(1L, report.decoded());
            assertEquals(1L, report.rejected());
            assertEquals(1L, report.unsupported());
            assertEquals(1L, report.truncated());
            assertEquals(6, report.observedChannel());
            assertNull(report.radio());
            assertNull(report.kernelDrops());
            assertNull(report.sinceLastFrameMs());
            assertEquals(1, bridge.getPassiveWifi().inventory().size());
            assertEquals(1_700_000_000_123L, bridge.getPassiveWifi().inventory().getFirst().firstSeen());
            assertEquals(1, bridge.getPassiveWifi().audit().totalProbes());
            assertEquals("Replay only", bridge.getPassiveWifi().audit().corpus().getFirst().name());

            Path broken = directory.resolve("broken.pcap");
            Files.write(broken, new byte[]{0, 0, 0});
            bridge.startReplay(broken);
            awaitReplay(bridge);
            assertEquals("FAILED", bridge.getCaptureHealth().replayState());
            assertTrue(bridge.getCaptureHealth().error().contains("Truncated PCAP header"));
        }
    }

    private static void awaitReplay(PacketBridge bridge) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (bridge.isRunning() && System.nanoTime() < deadline) Thread.sleep(5);
        assertFalse(bridge.isRunning());
    }
}
