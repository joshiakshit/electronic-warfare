package ewave.capture;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.passive.DeviceProfiler;
import ewave.ui.PassiveRfServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class ReplayOpsIsolationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String AP = "02:11:22:33:44:55";
    @TempDir Path directory;

    @ParameterizedTest
    @CsvSource({"false, false", "false, true", "true, false", "true, true"})
    void browserReplayDisablesOpsUntilANewLiveSession(boolean initiallyLive, boolean recordingLibrary) throws Exception {
        Path recordingDirectory = directory.resolve("recordings");
        String previous = System.setProperty("rf.recordingDirectory", recordingDirectory.toString());
        var receiver = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge(builder -> receiver, Map.of());
             var server = new PassiveRfServer(bridge, true, monitor -> {
                 fail("Replay must never create an injector");
                 return null;
             }, new LanScanner(), new WifiAccessPoints(directory.resolve("missing-aps"))).start(0);
             var client = HttpClient.newHttpClient()) {
            String base = "http://127.0.0.1:" + server.port();
            if (initiallyLive) bridge.startPassive("lab0mon", true);
            assertTrue(JSON.readTree(get(client, base + "/api/status").body()).path("operationsEnabled").asBoolean());
            assertEquals(200, get(client, base + "/api/ops/targets").statusCode());
            if (initiallyLive) assertEquals(200, post(client, base + "/api/capture/stop", "{}").statusCode());

            byte[] pcap = capture();
            HttpResponse<String> replay;
            if (recordingLibrary) {
                var uploaded = client.send(HttpRequest.newBuilder(URI.create(base + "/api/recordings?name=lab.pcap"))
                        .header("Content-Type", "application/octet-stream")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(pcap)).build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(201, uploaded.statusCode(), uploaded.body());
                String id = JSON.readTree(uploaded.body()).path("id").asText();
                replay = post(client, base + "/api/recordings/" + id + "/replay", "{}");
            } else {
                Path file = Files.write(directory.resolve("lab.pcap"), pcap);
                replay = post(client, base + "/api/capture/start", JSON.writeValueAsString(
                        Map.of("mode", "replay", "replayPath", file.toString())));
            }
            assertEquals(200, replay.statusCode(), replay.body());
            assertFalse(JSON.readTree(get(client, base + "/api/status").body()).path("operationsEnabled").asBoolean());
            await(() -> !bridge.isRunning());
            assertEquals("COMPLETE", bridge.getCaptureHealth().replayState());
            var session = bridge.getPassiveWifi();
            var topology = session.topology();
            assertEquals(1, topology.accessPoints().size());
            assertEquals(1, topology.edges().size(), "Historical client evidence must be present for this regression");
            String apId = topology.accessPoints().getFirst().bssid();
            String clientId = topology.edges().getFirst().clientId();
            assertNotNull(session.observedBssid(apId));
            assertNotNull(session.observedClient(clientId));
            assertTrue(session.evidencedTargets(bridge.getProfiler()).isEmpty());
            assertEquals(200, get(client, base + "/api/spotter").statusCode());
            assertOpsBlocked(client, base, apId, clientId);
            assertThrows(IllegalStateException.class, () -> bridge.acquireOpsLease("lab0mon", true));

            assertEquals(200, post(client, base + "/api/capture/stop", "{}").statusCode());
            assertOpsBlocked(client, base, apId, clientId);
            var live = post(client, base + "/api/capture/start", "{\"mode\":\"watch\",\"interface\":\"lab0mon\"}");
            assertEquals(200, live.statusCode(), live.body());
            assertFalse(bridge.isReplaySession());
            assertTrue(bridge.getPassiveWifi().topology().accessPoints().isEmpty());
            assertTrue(JSON.readTree(get(client, base + "/api/status").body()).path("operationsEnabled").asBoolean());
            assertEquals(200, get(client, base + "/api/ops/targets").statusCode());
        } finally {
            if (previous == null) System.clearProperty("rf.recordingDirectory");
            else System.setProperty("rf.recordingDirectory", previous);
        }
    }

    @Test void leaseRejectsReplayStartedWhileTheOperationWasResolvingItsRadio() throws Exception {
        var resolving = new CountDownLatch(1);
        var proceed = new CountDownLatch(1);
        try (var bridge = new PacketBridge(builder -> {
            fail("No external process may run"); return null;
        }, Map.of(), new DeviceProfiler(), 100, 32, 32, iface -> null, iface -> {
            resolving.countDown();
            try {
                assertTrue(proceed.await(3, TimeUnit.SECONDS));
            } catch (InterruptedException stopped) {
                throw new AssertionError(stopped);
            }
            return "phy-test";
        }); var executor = Executors.newSingleThreadExecutor()) {
            var result = executor.submit(() -> assertThrows(IllegalStateException.class,
                    () -> bridge.acquireOpsLease("lab0mon", false)));
            try {
                assertTrue(resolving.await(3, TimeUnit.SECONDS));
                bridge.startReplay(Files.write(directory.resolve("replay.pcap"), capture()));
            } finally {
                proceed.countDown();
            }
            assertTrue(result.get(3, TimeUnit.SECONDS).getMessage().contains("replay"));
        }
    }

    @Test void stoppedAndFailedReplayAlsoKeepOpsDisabled() throws Exception {
        for (boolean failReplay : new boolean[]{false, true}) {
            try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge, true).start(0);
                 var client = HttpClient.newHttpClient()) {
                Path file = Files.write(directory.resolve("terminal.pcap"), failReplay ? new byte[24] : capture());
                synchronized (bridge) {
                    bridge.startReplay(file);
                    assertTrue(bridge.isRunning());
                    assertTrue(bridge.isReplaySession());
                    assertThrows(IllegalStateException.class, () -> bridge.acquireOpsLease("lab0mon", false));
                    if (!failReplay) bridge.stopRuntimeCapture();
                }
                await(() -> !bridge.isRunning());
                assertEquals(failReplay ? "FAILED" : "STOPPED", bridge.getCaptureHealth().replayState());
                String base = "http://127.0.0.1:" + server.port();
                assertOpsBlocked(client, base, "old-ap", "old-client");
                assertThrows(IllegalStateException.class, () -> bridge.acquireOpsLease("lab0mon", false));
            }
        }
    }

    private static void assertOpsBlocked(HttpClient client, String base, String apId, String clientId) throws Exception {
        assertFalse(JSON.readTree(get(client, base + "/api/status").body()).path("operationsEnabled").asBoolean());
        for (String prefix : List.of("/api/ops", "/api/attack")) {
            for (String route : List.of("capabilities", "targets", "aps", "scan-lan", "status", "handshake/status",
                    "pmkid/status", "beacon/status", "evil-twin/status")) {
                assertEquals(404, get(client, base + prefix + "/" + route).statusCode(), prefix + "/" + route);
            }
            for (String selector : List.of("apId", "targetId", "apBssid")) {
                String value = selector.equals("apId") ? apId : selector.equals("targetId") ? clientId : AP;
                String body = JSON.writeValueAsString(Map.of(selector, value, "interface", "lab0mon"));
                for (String route : List.of("deauth", "handshake"))
                    assertEquals(404, post(client, base + prefix + "/" + route, body).statusCode());
            }
            for (String value : List.of(apId, AP))
                assertEquals(404, post(client, base + prefix + "/uncloak",
                        JSON.writeValueAsString(Map.of("bssid", value))).statusCode());
            for (String route : List.of("pmkid", "beacon", "evil-twin", "handshake/verify", "stop"))
                assertEquals(404, post(client, base + prefix + "/" + route, "{}").statusCode());
        }
    }

    private static byte[] capture() {
        var hex = HexFormat.of();
        byte[] beacon = hex.parseHex("80000000ffffffffffff0211223344550211223344551000"
                + "0000000000000000640001000000");
        byte[] data = hex.parseHex("0801000002112233445502aabbccddee0211223344552000");
        return ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, true, 127, ProbeFrames.radiotap(beacon),
                ProbeFrames.radiotap(data), ProbeFrames.radiotap(data), ProbeFrames.radiotap(data));
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(10);
        assertTrue(condition.getAsBoolean());
    }

    private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, String url, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
