package ewave.capture;

import ewave.core.AdaptiveScanner;
import ewave.model.DeviceRecord;
import ewave.model.PacketEvent;
import ewave.model.EwaveEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
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
    private static final String SRC = "00:11:22:33:44:55";
    private static final String DST = "00:aa:bb:cc:dd:ee";
    private static final String ETHERNET = "1700000000.123456 " + SRC + " > " + DST
            + ", ethertype IPv4 (0x0800), length 128: IP 192.0.2.1 > 192.0.2.2: UDP, length 86";

    private static AdaptiveScanner scanner() {
        return new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71));
    }

    @Test void parsesEthernetWithoutConfusingPayloadLengthWithFrameLength() {
        PacketEvent packet = PacketBridge.parseLine(ETHERNET.toUpperCase(), 6);
        assertNotNull(packet);
        assertEquals(SRC, packet.srcMac());
        assertEquals(DST, packet.dstMac());
        assertEquals(128, packet.length());
        assertEquals(1_700_000_000_123L, packet.timestamp());
        assertEquals(6, packet.channel());
        assertTrue(Double.isNaN(packet.rssi()));
        assertEquals("IPV4", packet.protocol());
        assertEquals(ETHERNET.toUpperCase(), packet.rawSummary());
    }

    @Test void parsesRadiotapAddressesSignalAndChannelIncludingChannel14() {
        String line = "1700000000.250000 100us tsft 1.0 Mb/s 2437 MHz 11g -47.5dBm signal "
                + "BSSID:00:99:88:77:66:55 DA:" + DST + " SA:" + SRC + " Data length 256";
        var packet = PacketBridge.parseLine(line, 1);
        assertNotNull(packet);
        assertEquals(SRC, packet.srcMac());
        assertEquals(DST, packet.dstMac());
        assertEquals(6, packet.channel());
        assertEquals(-47.5, packet.rssi());
        assertEquals("802.11", packet.protocol());
        assertEquals(14, PacketBridge.parseLine(line.replace("2437", "2484"), 1).channel());
        assertEquals(0, PacketBridge.parseLine(line.replace("2437", "5180"), 1).channel());
        assertEquals(11, PacketBridge.parseLine(line.replace("2437 MHz", "channel 11"), 1).channel());
        assertEquals(6, PacketBridge.parseLine(line.replace("SA:", "TA:").replace("DA:", "RA:"), 1).channel());
        assertEquals(0, PacketBridge.parseLine(ETHERNET, 0).channel());
    }

    @Test void skipsMalformedAndIncompleteLines() {
        for (String line : List.of("", "tcpdump: listening on wlo1", ETHERNET.replace("1700000000.123456", "NaN"),
                ETHERNET.replace(SRC, "not-a-mac"), ETHERNET.replace("length", "size"),
                ETHERNET.replace("128", "999999999999999999999"),
                ETHERNET.replace("1700000000.123456", "9".repeat(400)))) {
            assertNull(PacketBridge.parseLine(line, 1), line);
        }
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

    @Test void launchesWithoutShellAndCreatesUpdatesImmutableDeviceRecords() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = summaryBridge(builder -> {
            assertEquals(List.of("tcpdump", "-i", "wlo1;echo", "-e", "-l", "-n", "-tt"), builder.command());
            assertEquals(ProcessBuilder.Redirect.INHERIT, builder.redirectError());
            assertFalse(builder.redirectErrorStream());
            return process;
        }, Map.of("001122", "Lab Vendor"))) {
            Map<String, DeviceRecord> view = bridge.getDevices();
            bridge.setChannel(6);
            bridge.start("wlo1;echo", scanner());
            process.write(ETHERNET);
            EwaveEvent appeared = bridge.getEventQueue().poll(2, TimeUnit.SECONDS);
            assertNotNull(appeared);
            assertEquals(EwaveEvent.DEVICE_APPEARED, appeared.type());
            DeviceRecord first = (DeviceRecord) appeared.payload();
            assertEquals(SRC, first.mac());
            assertEquals("Lab Vendor", first.vendor());
            assertNotNull(bridge.getPacketQueue().poll(2, TimeUnit.SECONDS));
            assertEquals(2, view.size());
            assertEquals("Unknown", view.get(DST).vendor());
            assertThrows(UnsupportedOperationException.class, () -> view.remove(SRC));
            bridge.getEventQueue().clear();

            process.write("1700000001.500000 2437 MHz -36dBm signal DA:" + DST + " SA:" + SRC + " Data length 88");
            EwaveEvent update = bridge.getEventQueue().poll(2, TimeUnit.SECONDS);
            assertNotNull(update);
            assertEquals(EwaveEvent.DEVICE_UPDATED, update.type());
            DeviceRecord latest = (DeviceRecord) update.payload();
            assertEquals(-36, latest.rssi());
            assertEquals(first.firstSeen(), latest.firstSeen());
            assertEquals(1_700_000_001_500L, latest.lastSeen());
            assertEquals(1_700_000_000_123L, first.lastSeen()); // Already emitted payload is unchanged.
            await(() -> view.get(SRC).lastSeen() == latest.lastSeen());
            assertTrue(Double.isNaN(view.get(DST).rssi()));
            bridge.stop();
            assertFalse(bridge.isRunning());
            assertFalse(process.isAlive());
            assertEquals(1, bridge.getPacketQueue().size()); // Partial window is drained on stop.
            bridge.stop();
        }
    }

    @Test void observesQuietWindowsResetsDetectionsAndKeepsTicksAcrossRestart() throws Exception {
        FakeProcess first = new FakeProcess();
        FakeProcess second = new FakeProcess();
        var processes = new ArrayDeque<>(List.of(first, second));
        var scanner = scanner();
        try (PacketBridge bridge = summaryBridge(builder -> processes.remove(), Map.of())) {
            bridge.setChannel(6);
            bridge.start("wlo1", scanner);
            first.write(ETHERNET);
            assertNotNull(bridge.getPacketQueue().poll(2, TimeUnit.SECONDS));
            await(() -> observations(scanner) >= 3);
            bridge.stop();
            long completed = observations(scanner);
            var expected = scanner();
            for (long tick = 0; tick < completed; tick++) {
                for (int band = 0; band < 13; band++) expected.observe(band, tick, band == 5 && tick == 0, true);
            }
            assertArrayEquals(expected.snapshot(completed).means(), scanner.snapshot(completed).means());
            long[] counts = scanner.snapshot(completed).counts();
            assertEquals(13, counts.length);
            for (int band = 0; band < 13; band++) assertEquals(completed, counts[band]);

            bridge.start("wlo1", scanner);
            await(() -> observations(scanner) > completed);
            assertTrue(bridge.isRunning()); // Duplicate tick feedback would stop the session.
            bridge.stop();
        }
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
            bridge.start("wlo1", scanner);
            var command = started.poll(1, TimeUnit.SECONDS);
            assertNotNull(command);
            assertEquals(List.of("sudo", "iw", "dev", "wlo1", "set", "freq", Integer.toString(2407 + chosen * 5)),
                    command.command());
            assertEquals(ProcessBuilder.Redirect.DISCARD, command.redirectOutput());
            assertEquals(ProcessBuilder.Redirect.DISCARD, command.redirectError());
            await(() -> observations(scanner) >= 3);
            assertTrue(tune.isAlive());
            assertNull(bridge.getChannelSnapshot().activeChannel());
            await(() -> !tune.isAlive());
        }
    }

    @Test void mapsFirstAndLastChannelsToScannerBandBoundaries() throws Exception {
        for (int channel : new int[]{1, 13}) {
            FakeProcess process = new FakeProcess();
            var scanner = scanner();
            try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
                bridge.setChannel(channel);
                bridge.start("wlo1", scanner);
                process.write(ETHERNET);
                assertNotNull(bridge.getPacketQueue().poll(2, TimeUnit.SECONDS));
                bridge.stop();
                long completed = observations(scanner);
                var expected = scanner();
                for (long tick = 0; tick < completed; tick++) {
                    for (int band = 0; band < 13; band++) {
                        expected.observe(band, tick, band == channel - 1 && tick == 0, true);
                    }
                }
                assertTrue(completed > 0);
                assertArrayEquals(expected.snapshot(completed).means(), scanner.snapshot(completed).means());
            }
        }
    }

    @Test void channel14AndUnknownPacketsAreQueuedWithoutFalseChannelDetections() throws Exception {
        FakeProcess process = new FakeProcess();
        var scanner = scanner();
        try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
            bridge.start("wlo1", scanner);
            process.write(ETHERNET);
            assertEquals(0, bridge.getPacketQueue().poll(2, TimeUnit.SECONDS).channel());
            bridge.setChannel(14);
            process.write(ETHERNET);
            assertEquals(14, bridge.getPacketQueue().poll(2, TimeUnit.SECONDS).channel());
            bridge.stop();
            long completed = observations(scanner);
            var expected = scanner();
            for (long tick = 0; tick < completed; tick++) {
                for (int band = 0; band < 13; band++) expected.observe(band, tick, false, true);
            }
            assertArrayEquals(expected.snapshot(completed).means(), scanner.snapshot(completed).means());
        }
    }

    @Test void eofStopsCaptureAndDrainsPendingPackets() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
            bridge.start("wlo1", scanner());
            process.write(ETHERNET);
            await(() -> bridge.getDevices().size() == 2);
            process.finish();
            await(() -> !bridge.isRunning());
            assertEquals(ETHERNET, bridge.getPacketQueue().poll(2, TimeUnit.SECONDS).rawSummary());
            assertFalse(process.isAlive());
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
            assertThrows(IOException.class, () -> bridge.start("wlo1", scanner()));
            assertFalse(bridge.isRunning());
            bridge.start("wlo1", scanner());
            await(() -> !bridge.isRunning());
            await(() -> !failedRead.isAlive());
            bridge.start("wlo1", scanner());
            healthy.write(ETHERNET);
            assertNotNull(bridge.getPacketQueue().poll(2, TimeUnit.SECONDS));
            assertTrue(bridge.isRunning());
        }
    }

    @Test void validatesStartAndChannelArgumentsAndExcludesGroupAddresses() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = summaryBridge(builder -> process, Map.of())) {
            assertThrows(IllegalArgumentException.class, () -> bridge.start(" ", scanner()));
            assertThrows(NullPointerException.class, () -> bridge.start("wlo1", null));
            assertThrows(IllegalArgumentException.class, () -> bridge.start("wlo1",
                    new AdaptiveScanner(AdaptiveScanner.Config.defaults(12, 128, 71))));
            assertThrows(IllegalArgumentException.class, () -> bridge.setChannel(0));
            assertThrows(IllegalArgumentException.class, () -> bridge.setChannel(15));
            bridge.start("wlo1", scanner());
            assertThrows(IllegalStateException.class, () -> bridge.start("wlo1", scanner()));
            process.write(ETHERNET.replace(DST, "ff:ff:ff:ff:ff:ff"));
            assertNotNull(bridge.getPacketQueue().poll(2, TimeUnit.SECONDS));
            assertEquals(1, bridge.getDevices().size());
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
            bridge.start("wlo1", scanner());
            bridge.stop();
            assertEquals(1, forced.get());
            assertFalse(process.isAlive());

            FakeProcess interruptedProcess = new FakeProcess();
            try (PacketBridge interruptedBridge = summaryBridge(builder -> interruptedProcess, Map.of())) {
                interruptedBridge.start("wlo1", scanner());
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

    @Test void parsesBothProbeTextFormatsAndOnlyTheSourceAddress() {
        var quoted = PacketBridge.parseProbeLine("14:23:11.123456 A4:C3:F0:11:22:33 (oui Unknown) > Broadcast (oui Unknown), SSID 'HomeNetwork', [...]");
        assertNotNull(quoted);
        assertEquals("a4:c3:f0:11:22:33", quoted.sourceMac());
        assertEquals("HomeNetwork", quoted.ssid());
        var alternate = PacketBridge.parseProbeLine("14:23:11 BSSID:ff:ff:ff:ff:ff:ff DA:ff:ff:ff:ff:ff:ff SA:" + SRC
                + " Probe Request (Lab (guest)) [1.0 2.0 Mbit]");
        assertNotNull(alternate);
        assertEquals(SRC, alternate.sourceMac());
        assertEquals("Lab (guest)", alternate.ssid());
        assertEquals("CollegeWiFi", PacketBridge.parseProbeLine("TA:" + SRC + " Probe Request (CollegeWiFi)").ssid());
        assertEquals("Café lab", PacketBridge.parseProbeLine(SRC + " > Broadcast, SSID 'Café lab'").ssid());
        assertEquals("  padded  ", PacketBridge.parseProbeLine(SRC + " > Broadcast, SSID '  padded  '").ssid());
        var addressInName = PacketBridge.parseProbeLine(SRC + " > Broadcast, SSID 'SA:" + DST + "'");
        assertEquals(SRC, addressInName.sourceMac());
        assertEquals("SA:" + DST, addressInName.ssid());
        assertEquals("SSID 'Lab'", PacketBridge.parseProbeLine(SRC + " > Broadcast, Probe Request (SSID 'Lab')").ssid());
    }

    @Test void skipsWildcardUnrelatedAndMalformedProbeText() {
        assertNull(PacketBridge.parseProbeLine(null));
        for (String line : List.of("", "tcpdump: listening on wlo1", ETHERNET,
                SRC + " > Broadcast, SSID ''", SRC + " > Broadcast, Probe Request ()",
                SRC + " > Broadcast, SSID '   '", SRC + " > Broadcast, Probe Request (   )",
                SRC + " > Broadcast, Probe Request", SRC + " > Broadcast, SSID 'unterminated",
                "not-a-mac > Broadcast, SSID 'Lab'", "ff:ff:ff:ff:ff:ff > Broadcast, SSID 'Lab'",
                "00:00:00:00:00:00 > Broadcast, SSID 'Lab'")) {
            assertNull(PacketBridge.parseProbeLine(line), line);
        }
    }

    @Test void capturesTextProbesUpdatesProfilesOnceAndCountsDistinctSources() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = new PacketBridge(builder -> {
            assertEquals(List.of("sudo", "tcpdump", "-i", "wlo1", "-e", "-l", "-s", "256",
                    "type mgt subtype probe-req"), builder.command());
            assertEquals(ProcessBuilder.Redirect.DISCARD, builder.redirectError());
            assertFalse(builder.redirectErrorStream());
            return process;
        }, Map.of())) {
            bridge.startProbes("wlo1");
            assertThrows(IllegalStateException.class, () -> bridge.startProbes("wlo1"));
            assertEquals("probes", bridge.getCaptureStatus().get("captureMode"));
            process.write("14:23:11 A4:C3:F0:11:22:33 (oui Unknown) > Broadcast, SSID 'HomeNetwork'");
            process.write("14:23:12 a4:c3:f0:11:22:33 > Broadcast, SSID 'HomeNetwork'");
            process.write("14:23:13 DA:ff:ff:ff:ff:ff:ff SA:a4:c3:f0:11:22:33 Probe Request (CollegeWiFi)");
            process.write("14:23:14 " + SRC + " > Broadcast, SSID 'Other lab'");
            process.write("14:23:15 " + DST + " > Broadcast, SSID ''");
            process.write("14:23:16 " + DST + " > Broadcast, Probe Request ()");
            process.write("unrelated output");
            await(() -> bridge.getProbeRequests().size() == 4);
            var device = bridge.getDevices().get("a4:c3:f0:11:22:33");
            assertEquals(2, bridge.getDevices().size());
            assertEquals(List.of("HomeNetwork", "CollegeWiFi"), device.probedSsids());
            assertEquals("3", device.metadata().get("probeRequests"));
            assertTrue(Double.isNaN(device.rssi()));
            assertEquals(List.of("HomeNetwork", "CollegeWiFi"), bridge.getProfiler().get(device.mac()).probedSsids());
            assertEquals(3, bridge.getProfiler().get(device.mac()).packetCount());
            assertEquals(1, bridge.getProfiler().get(SRC).packetCount());
            assertEquals(EwaveEvent.DEVICE_APPEARED, bridge.getEventQueue().remove().type());
            assertEquals(EwaveEvent.PROBE_REQUEST, bridge.getEventQueue().remove().type());
            assertEquals(4L, bridge.getCaptureStatus().get("probeRequests"));
            assertNull(bridge.getChannelSnapshot());
            assertTrue(bridge.getPacketQueue().isEmpty());
            var snapshot = bridge.getProbeRequests();
            assertThrows(UnsupportedOperationException.class, snapshot::clear);
            bridge.stop();
            assertEquals(4, snapshot.size());
            assertEquals(4, bridge.getProbeRequests().size());
            assertFalse(process.isAlive());
            assertFalse(bridge.getCaptureStatus().containsKey("captureError"));
        }
    }

    @Test void boundsRecentProbeEventsAndRetainsTheFullDistinctNetworkList() throws Exception {
        FakeProcess process = new FakeProcess();
        try (PacketBridge bridge = new PacketBridge(builder -> process, Map.of())) {
            bridge.startProbes("wlo1");
            for (int i = 0; i < 300; i++) process.write(SRC + " > Broadcast, SSID 'Network " + i + "'");
            await(() -> bridge.getCaptureStatus().get("probeRequests").equals(300L));
            assertEquals(PacketBridge.RECENT_PROBE_LIMIT, bridge.getProbeRequests().size());
            assertEquals("Network 44", bridge.getProbeRequests().getFirst().ssid());
            var device = bridge.getDevices().get(SRC);
            assertEquals(300, device.probedSsids().size());
            assertEquals("Network 0", device.probedSsids().getFirst());
            assertEquals("Network 299", device.probedSsids().getLast());
            assertEquals(device.probedSsids(), bridge.getProfiler().get(SRC).probedSsids());
        }
    }

    @Test void preservesProbeHistoryAcrossRestartAndReportsEof() throws Exception {
        FakeProcess first = new FakeProcess();
        FakeProcess second = new FakeProcess();
        var processes = new ArrayDeque<>(List.of(first, second));
        try (PacketBridge bridge = new PacketBridge(builder -> processes.remove(), Map.of())) {
            assertThrows(IllegalArgumentException.class, () -> bridge.startProbes(" "));
            bridge.startProbes("wlo1");
            first.write(SRC + " > Broadcast, Probe Request (First lab)");
            await(() -> bridge.getProbeRequests().size() == 1);
            bridge.stop();
            bridge.startProbes("wlo1");
            assertFalse(bridge.getCaptureStatus().containsKey("captureError"));
            second.write(SRC + " > Broadcast, SSID 'Other lab'");
            await(() -> bridge.getProbeRequests().size() == 2);
            second.finish();
            await(() -> !bridge.isRunning());
            assertTrue(bridge.getCaptureStatus().get("captureError").toString().contains("Probe capture ended"));
            assertEquals(List.of("First lab", "Other lab"), bridge.getDevices().get(SRC).probedSsids());
            assertEquals(2, bridge.getProfiler().get(SRC).packetCount());
        }
    }

    @Test void reportsTcpdumpExitCodeWithStderrDiscarded() throws Exception {
        FakeProcess process = new FakeProcess() {
            @Override public InputStream getInputStream() { return InputStream.nullInputStream(); }
            @Override public int exitValue() { return 1; }
        };
        process.finish();
        try (PacketBridge bridge = new PacketBridge(builder -> process, Map.of())) {
            bridge.startProbes("wlo1");
            await(() -> !bridge.isRunning());
            String error = bridge.getCaptureStatus().get("captureError").toString();
            assertTrue(error.contains("tcpdump exited with code 1"));
            assertTrue(error.contains("monitor interface and tcpdump permissions"));
            assertEquals("wlo1", bridge.getCaptureStatus().get("captureInterface"));
        }
    }

    private static PacketBridge summaryBridge(PacketBridge.ProcessStarter capture, Map<String, String> vendors) {
        return new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("sudo")) throw new IOException("Simulated unavailable retune");
            return capture.start(builder);
        }, vendors);
    }

    private static long observations(AdaptiveScanner scanner) {
        synchronized (scanner) { return scanner.snapshot(0).counts()[1]; }
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

        void write(String line) throws IOException {
            writer.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            writer.flush();
        }

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
