package ewave.capture;

import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
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

    @Test void capturesPermissionDiagnosticsInBothStreamOrdersWithoutLeakingIntoQuietNextRun() throws Exception {
        String permission = "tcpdump: wlo1: You don't have permission to capture on that device (socket: Operation not permitted)";
        var processes = new java.util.ArrayDeque<DiagnosticProcess>();
        var first = new DiagnosticProcess(1);
        var second = new DiagnosticProcess(1);
        var quiet = new DiagnosticProcess(0);
        processes.add(first);
        processes.add(second);
        processes.add(quiet);

        try (var bridge = new PacketBridge(builder -> processes.removeFirst(), Map.of())) {
            // Order 1: stderr diagnostic arrives before stdout EOF and exit 1.
            bridge.startPassive("wlo1", false);
            first.writeStderr(permission + "\n");
            first.awaitStderrConsumed();
            first.closeStderr();
            first.closeStdout();
            first.finish();
            awaitReplay(bridge);
            var report1 = bridge.getCaptureHealth();
            assertFalse(report1.running());
            assertTrue(report1.error().contains("exit"));
            assertTrue(report1.error().contains("code 1"));
            assertTrue(report1.error().contains("Operation not permitted"), report1.error());

            // Order 2: stdout EOF and exit arrive first; long stderr diagnostic arrives shortly after.
            bridge.startPassive("wlo1", false);
            second.closeStdout();
            Thread.sleep(25);
            String longDiag = permission + " " + "extra-detail-".repeat(25);
            second.writeStderr(longDiag + "\n");
            second.closeStderr();
            second.finish();
            awaitReplay(bridge);
            var report2 = bridge.getCaptureHealth();
            assertTrue(report2.error().contains("code 1"));
            assertTrue(report2.error().contains("Operation not permitted"), report2.error());
            assertTrue(report2.error().length() <= 256, "Expected bounded error length: " + report2.error().length());

            // Quiet valid live run: routine stderr banner + PCAP header + 0 frames, still alive.
            bridge.startPassive("wlo1", false);
            quiet.writeStderr("tcpdump: listening on wlo1, link-type IEEE802_11_RADIO (802.11 plus radiotap header), snapshot length 2048 bytes\n");
            quiet.writeStdout(ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127));
            Thread.sleep(40);
            var live = bridge.getCaptureHealth();
            assertTrue(live.running());
            assertNull(live.error());
            assertNull(bridge.getCaptureStatus().get("captureError"));
            assertEquals(0L, live.decoded());
        }
    }

    @Test void distinguishesCumulativeTotalsFromTenSecondRatesAndReportsUnknownKernelDrops(@TempDir Path dir) throws Exception {
        byte[] valid = ProbeFrames.radiotap(ProbeFrames.frame("Window test"));
        byte[] unsupported = ProbeFrames.radiotap(new byte[]{4, 0}); // Control frame (type 1)
        byte[] truncated = ProbeFrames.radiotap(new byte[]{8, 0});   // Data frame (type 2) with truncated record length
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, valid, valid, unsupported, truncated, valid);

        int rec0 = 24;
        int rec1 = rec0 + 16 + valid.length;
        int rec2 = rec1 + 16 + valid.length;
        int rec3 = rec2 + 16 + unsupported.length;
        int rec4 = rec3 + 16 + truncated.length;
        var buf = ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(rec0, 1_700_000_000);
        buf.putInt(rec1, 1_700_000_000);
        buf.putInt(rec2, 1_700_000_012);
        buf.putInt(rec3, 1_700_000_012);
        buf.putInt(rec3 + 12, truncated.length + 4);
        buf.putInt(rec4, 1_700_000_015);

        Path file = dir.resolve("windowed.pcap");
        Files.write(file, pcap);
        try (var bridge = new PacketBridge()) {
            bridge.startReplay(file);
            awaitReplay(bridge);
            var health = bridge.getCaptureHealth();
            assertEquals("COMPLETE", health.replayState());
            assertEquals(10, health.rateWindowSeconds());
            assertEquals(3L, health.decoded());
            assertEquals(1L, health.unsupported());
            assertEquals(1L, health.truncated());
            assertEquals(0L, health.rejected());
            assertEquals(3L, health.frameCounts().get("management"));
            assertEquals(1L, health.frameCounts().get("control"));
            assertEquals(1L, health.frameCounts().get("data"));
            // Reference time is 1_700_000_015s: only t=15s management frame is inside (5s..15s].
            assertEquals(0.1, health.framesPerSecond().get("management"));
            assertEquals(0.1, health.framesPerSecond().get("control"));
            assertEquals(0.1, health.framesPerSecond().get("data"));
            assertNull(health.kernelDrops());
        }
    }

    private static final class DiagnosticProcess extends Process {
        private final PipedInputStream stdout = new PipedInputStream(4096);
        private final PipedOutputStream stdoutWriter = new PipedOutputStream(stdout);
        private final PipedInputStream stderr = new PipedInputStream(4096);
        private final PipedOutputStream stderrWriter = new PipedOutputStream(stderr);
        private final CountDownLatch exited = new CountDownLatch(1);
        private final int exitCode;

        DiagnosticProcess(int exitCode) throws IOException { this.exitCode = exitCode; }

        void writeStdout(byte[] bytes) throws IOException {
            stdoutWriter.write(bytes);
            stdoutWriter.flush();
        }

        void closeStdout() throws IOException { stdoutWriter.close(); }

        void writeStderr(String line) throws IOException {
            stderrWriter.write(line.getBytes(StandardCharsets.UTF_8));
            stderrWriter.flush();
        }

        void awaitStderrConsumed() throws InterruptedException, IOException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
            while (stderr.available() > 0 && System.nanoTime() < deadline) Thread.sleep(5);
            Thread.sleep(20);
        }

        void closeStderr() throws IOException { stderrWriter.close(); }
        void finish() { exited.countDown(); }

        @Override public InputStream getInputStream() { return stdout; }
        @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
        @Override public InputStream getErrorStream() { return stderr; }
        @Override public int waitFor() throws InterruptedException { exited.await(); return exitCode; }
        @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
            return exited.await(timeout, unit);
        }
        @Override public int exitValue() {
            if (isAlive()) throw new IllegalThreadStateException();
            return exitCode;
        }
        @Override public boolean isAlive() { return exited.getCount() != 0; }
        @Override public void destroy() {
            exited.countDown();
            try { stdoutWriter.close(); } catch (IOException ignored) { }
            try { stderrWriter.close(); } catch (IOException ignored) { }
        }
    }

    private static void awaitReplay(PacketBridge bridge) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (bridge.isRunning() && System.nanoTime() < deadline) Thread.sleep(5);
        assertFalse(bridge.isRunning());
    }
}
