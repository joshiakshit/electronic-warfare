package ewave.capture;

import ewave.core.AdaptiveScanner;
import ewave.fixtures.ProbeFrames;
import ewave.model.EwaveEvent;
import ewave.passive.DeviceProfiler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class PacketBridgeTest {
    private static AdaptiveScanner scanner() {
        return new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71));
    }

    @Test void loadsIeeeAndSimpleOuiFormats() throws IOException {
        String text = "# comment\nIEEE registry\n"
                + "00-11-22   (hex)   First Vendor\n"
                + "001122     (base 16)   First Vendor\n"
                + "00:AA:BB\tSecond Vendor\n"
                + "A4:C3:F0\tIntel\tIntel Corporate\n"
                + "AABBCC Third Vendor\n"
                + "    42 Example Road\n";
        assertEquals(Map.of("001122", "First Vendor", "00aabb", "Second Vendor", "aabbcc", "Third Vendor",
                        "a4c3f0", "Intel Corporate"),
                PacketBridge.loadVendors(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))));
    }

    @Test void retunesToTheScannerChoiceWithoutHoldingUpObservationWindows() throws Exception {
        var capture = new FakeProcess();
        var tune = new FakeProcess();
        var started = new LinkedBlockingQueue<ProcessBuilder>();
        var scanner = scanner();
        var expected = scanner();
        for (int band = 0; band < 13; band++) expected.observe(band, 0, false);
        int chosen = expected.choose(1, 1).bands()[0] + 1;
        try (var bridge = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("tcpdump")) return capture;
            started.add(builder);
            return tune;
        }, Map.of())) {
            bridge.startPassive("wlo1", false, scanner);
            var command = started.poll(2, TimeUnit.SECONDS);
            assertNotNull(command);
            assertEquals(List.of("sudo", "iw", "dev", "wlo1", "set", "freq", Integer.toString(2407 + chosen * 5)),
                    command.command());
            assertEquals(ProcessBuilder.Redirect.DISCARD, command.redirectOutput());
            assertEquals(ProcessBuilder.Redirect.DISCARD, command.redirectError());
            assertTrue(tune.isAlive());
            assertNull(bridge.getChannelSnapshot().activeChannel());
            await(() -> !tune.isAlive());
        }
    }

    @Test void readAndLaunchFailuresLeaveBridgeRestartable() throws Exception {
        FakeProcess failedRead = new FakeProcess() {
            @Override public InputStream getInputStream() {
                return new InputStream() {
                    @Override public int read() throws IOException { throw new IOException("simulated read failure"); }
                };
            }
        };
        FakeProcess healthy = new FakeProcess();
        AtomicInteger launches = new AtomicInteger();
        try (PacketBridge bridge = summaryBridge(builder -> switch (launches.getAndIncrement()) {
            case 0 -> throw new IOException("simulated launch failure");
            case 1 -> failedRead;
            default -> healthy;
        }, Map.of())) {
            assertThrows(IOException.class, () -> bridge.startPassive("wlo1", false, scanner()));
            assertFalse(bridge.isRunning());
            bridge.startPassive("wlo1", false, scanner());
            await(() -> !bridge.isRunning());
            await(() -> !failedRead.isAlive());
            bridge.startPassive("wlo1", false, scanner());
            healthy.writeBytes(recentProbePcap());
            await(() -> bridge.getPassiveWifi() != null && !bridge.getPassiveWifi().inventory().isEmpty());
            assertTrue(bridge.isRunning());
        }
    }

    @Test void validatesStartAndChannelArguments() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
            assertThrows(IllegalArgumentException.class, () -> bridge.startPassive(" "));
            assertThrows(IllegalArgumentException.class, () -> bridge.startPassive("wlo1", false,
                    new AdaptiveScanner(AdaptiveScanner.Config.defaults(12, 128, 71))));
            assertThrows(IllegalArgumentException.class, () -> bridge.setChannel(0));
            assertThrows(IllegalArgumentException.class, () -> bridge.setChannel(15));
            bridge.startPassive("wlo1", false, scanner());
            assertThrows(IllegalStateException.class, () -> bridge.startPassive("wlo1", false, scanner()));
            assertTrue(bridge.isRunning());
        }
    }

    @Test void forciblyStopsAnUnresponsiveProcessAndPreservesCallerInterrupt() throws Exception {
        AtomicInteger forced = new AtomicInteger();
        FakeProcess process = new FakeProcess() {
            @Override public void destroy() { /* Simulate a child ignoring graceful termination. */ }
            @Override public Process destroyForcibly() {
                forced.incrementAndGet();
                try { finish(); } catch (IOException failure) { throw new AssertionError(failure); }
                return this;
            }
        };
        try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
            bridge.startPassive("wlo1", false, scanner());
            bridge.stop();
            assertEquals(1, forced.get());
            assertFalse(process.isAlive());

            FakeProcess interruptedProcess = new FakeProcess();
            try (PacketBridge interruptedBridge = summaryBridge(builder -> interruptedProcess, Map.of())) {
                interruptedBridge.startPassive("wlo1", false, scanner());
                Thread.currentThread().interrupt();
                try {
                    interruptedBridge.stop();
                    assertTrue(Thread.currentThread().isInterrupted());
                    assertFalse(interruptedProcess.isAlive());
                } finally {
                    Thread.interrupted();
                }
            }
        }
    }

    @Test void reportsTcpdumpExitCodeWithStderrDiscarded() throws Exception {
        FakeProcess process = new FakeProcess() {
            @Override public InputStream getInputStream() { return InputStream.nullInputStream(); }
            @Override public int exitValue() { return 1; }
        };
        process.finish();
        try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
            bridge.startPassive("wlo1", false);
            await(() -> !bridge.isRunning());
            String error = bridge.getCaptureStatus().get("captureError").toString();
            assertTrue(error.contains("tcpdump exited with code 1"));
            assertEquals("wlo1", bridge.getCaptureStatus().get("captureInterface"));
        }
    }

    @Test void boundsEventQueueAndCountsDroppedEventsWhenConsumerStalls() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("sudo")) throw new IOException("Simulated unavailable retune");
            return process;
        }, Map.of(), new DeviceProfiler(), 100, 1, 1)) {
            assertEquals(1, bridge.getEventQueueCapacity());
            bridge.startPassive("wlo1", false);
            // A single radiotap probe triggers both WIFI_DEVICE_SEEN and PROBE_RECEIVED, overflowing capacity 1.
            process.writeBytes(recentProbePcap());
            // The drop is counted after removing the old event and before offering the new one.
            await(() -> bridge.getDroppedEvents() >= 1 && bridge.getEventQueue().size() == 1);
            assertEquals(1, bridge.getEventQueue().size());
            assertEquals(1, bridge.getCaptureStatus().get("eventQueueCapacity"));
            assertEquals(bridge.getDroppedEvents(), bridge.getCaptureStatus().get("eventsDropped"));
        }
    }

    private static byte[] recentProbePcap() {
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127,
                ProbeFrames.radiotap(ProbeFrames.frame("LabNet")));
        ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).putInt(24, (int) (System.currentTimeMillis() / 1000));
        return pcap;
    }

    private static PacketBridge summaryBridge(PacketBridge.ProcessStarter capture, Map<String, String> vendors) {
        return new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("sudo")) throw new IOException("Simulated unavailable retune");
            return capture.start(builder);
        }, vendors);
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(condition.getAsBoolean(), "Condition did not become true");
    }

    private static class FakeProcess extends Process {
        private final PipedInputStream stdout = new PipedInputStream(8192);
        private final PipedOutputStream writer;
        private final CountDownLatch exited = new CountDownLatch(1);

        FakeProcess() throws IOException { writer = new PipedOutputStream(stdout); }

        void writeBytes(byte[] bytes) throws IOException {
            writer.write(bytes);
            writer.flush();
        }

        void finish() throws IOException {
            writer.close();
            exited.countDown();
        }

        @Override public InputStream getInputStream() { return stdout; }
        @Override public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
        @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
        @Override public int waitFor() throws InterruptedException { exited.await(); return 0; }
        @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
            return exited.await(timeout, unit);
        }
        @Override public int exitValue() {
            if (isAlive()) throw new IllegalThreadStateException();
            return 0;
        }
        @Override public boolean isAlive() { return exited.getCount() != 0; }
        @Override public void destroy() {
            try { finish(); } catch (IOException failure) { throw new AssertionError(failure); }
        }
        @Override public Process destroyForcibly() { destroy(); return this; }
    }
}
