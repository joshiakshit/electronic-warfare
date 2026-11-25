package ewave.capture;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.PacketEvent;
import ewave.passive.DeviceProfiler;
import ewave.ui.PassiveRfServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class CaptureSessionLifecycleTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    @TempDir Path directory;

    @Test void replayAndNewLiveSessionsClearCountersAndRawProfilesButSameSessionRestartsPreserveThem() throws Exception {
        String previous = System.setProperty("rf.networkProfile", directory.resolve("network.json").toString());
        var receivers = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        try (var bridge = new PacketBridge(builder -> {
            var receiver = new StreamingCaptureProcess();
            receivers.add(receiver);
            return receiver;
        }, Map.of())) {
            seedProfile(bridge);
            bridge.startReplay(Path.of("src/test/resources/probes/probe-requests.pcap"));
            await(() -> !bridge.isRunning());
            assertEquals(4L, bridge.getCaptureStatus().get("probeRequests"));
            assertTrue(bridge.getProfiler().all().isEmpty());
            seedProfile(bridge);
            bridge.configureRuntimeCapture("watch", "lab0mon", null, null, 13, true);
            assertEquals(0L, bridge.getCaptureStatus().get("probeRequests"));
            assertTrue(bridge.getProfiler().all().isEmpty());
            byte[] packet = ProbeFrames.radiotap(ProbeFrames.frame("Lab"));
            byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, packet);
            ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).putInt(24, (int) (System.currentTimeMillis() / 1000));
            receivers.getFirst().write(pcap);
            await(() -> bridge.getCaptureStatus().get("probeRequests").equals(1L));
            assertEquals(1, bridge.getProfiler().all().size());
            var sessionId = bridge.getPassiveWifi().sessionId();
            bridge.stopRuntimeCapture();
            bridge.configureRuntimeCapture("watch", "lab0mon", null, null, 13, true);
            assertEquals(sessionId, bridge.getPassiveWifi().sessionId());
            assertEquals(1L, bridge.getCaptureStatus().get("probeRequests"));
            assertEquals(1, bridge.getProfiler().all().size());
            bridge.stopRuntimeCapture();
            bridge.configureRuntimeCapture("watch", "lab1mon", null, null, 13, true);
            assertNotEquals(sessionId, bridge.getPassiveWifi().sessionId());
            assertEquals(0L, bridge.getCaptureStatus().get("probeRequests"));
            assertTrue(bridge.getProfiler().all().isEmpty());
        } finally {
            restore(previous);
        }
    }

    @Test void stoppingCaptureThroughTheApiCancelsAnOpsPausedResumeWithoutReleasingTheLease() throws Exception {
        String previous = System.setProperty("rf.networkProfile", directory.resolve("network.json").toString());
        var launches = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        try (var bridge = new PacketBridge(builder -> {
            var receiver = new StreamingCaptureProcess();
            launches.add(receiver);
            return receiver;
        }, Map.of(), new DeviceProfiler(), 20, 32, 32, iface -> null, iface -> "phy0");
             var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            bridge.startPassive("lab0mon", true);
            bridge.startSniperBySsid("Lab");
            try (var lease = bridge.acquireOpsLease("lab0ap", true)) {
                assertFalse(bridge.isRunning());
                assertEquals(true, bridge.getCaptureStatus().get("capturePausedForOps"));
                var response = client.send(HttpRequest.newBuilder(URI.create(base(server) + "/api/capture/stop"))
                        .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(200, response.statusCode(), response.body());
                assertFalse(JSON.readTree(response.body()).path("captureRunning").asBoolean());
                assertFalse(JSON.readTree(response.body()).path("capturePausedForOps").asBoolean());
                assertEquals(SniperController.State.IDLE, bridge.sniperState().run().state());
                assertThrows(IllegalStateException.class, () -> bridge.configureRuntimeCapture(
                        "watch", "lab0mon", null, null, 13, true));
            }
            assertFalse(bridge.isRunning());
            assertEquals(1, launches.size(), "Closing the lease must not restart a capture the user stopped");
        } finally {
            restore(previous);
        }
    }

    @Test void idleProfilerReturnsAnEmptyInventoryRatherThanRawMacProfiles() throws Exception {
        try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            seedProfile(bridge);
            var response = client.send(HttpRequest.newBuilder(URI.create(base(server) + "/api/profiler")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertEquals("[]", response.body());
        }
    }

    private static void seedProfile(PacketBridge bridge) {
        bridge.getProfiler().observe(new PacketEvent("02:aa:bb:cc:dd:ee", "ff:ff:ff:ff:ff:ff", 6,
                -50, 24, "802.11", System.currentTimeMillis(), null));
    }

    private static String base(PassiveRfServer server) { return "http://127.0.0.1:" + server.port(); }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean());
    }

    private static void restore(String previous) {
        if (previous == null) System.clearProperty("rf.networkProfile");
        else System.setProperty("rf.networkProfile", previous);
    }
}
