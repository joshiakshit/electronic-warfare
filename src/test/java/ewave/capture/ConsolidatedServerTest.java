package ewave.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.core.AdaptiveScanner;
import ewave.fixtures.BleFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.DeviceRecord;
import ewave.model.EwaveEvent;
import ewave.ui.PassiveRfServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.Date;
import java.util.Map;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class ConsolidatedServerTest {
    private static final String MAC = "02:11:22:33:44:55";
    private final ObjectMapper mapper = new ObjectMapper();

    @Test void servesNewUiAndRejectsCrossOriginOperations() throws Exception {
        try (var bridge = new PacketBridge();
             var ble = new BleBridge(bridge.getEventQueue(), bridge.getProfiler());
             var server = new PassiveRfServer(bridge, ble, true).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(200, get(client, server, "/").statusCode());
            for (String asset : List.of("/ewave.js", "/ewave.css", "/graph.js", "/spectrum.js"))
                assertEquals(200, get(client, server, asset).statusCode(), asset);
            assertEquals(404, get(client, server, "/dashboard.js").statusCode());
            assertEquals(503, get(client, server, "/api/channels").statusCode());
            assertEquals(404, post(client, server, "/api/attack", "{}").statusCode());
            var foreign = client.send(HttpRequest.newBuilder(uri(server, "/api/attack/stop"))
                    .header("Origin", "https://foreign.example")
                    .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(403, foreign.statusCode());
            assertEquals(200, post(client, server, "/api/attack/stop", "").statusCode());
        }
    }

    @Test void channelsAndDevicesComeFromTheCaptureScannerEvenAfterCaptureStops() throws Exception {
        String packet = "1700000000.123456 " + MAC
                + " > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 128: UDP";
        var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71));
        Process process = new Process() {
            @Override public InputStream getInputStream() { return new ByteArrayInputStream((packet + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
            @Override public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
            @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
            @Override public int waitFor() { return 0; }
            @Override public int exitValue() { return 0; }
            @Override public void destroy() { }
        };
        try (var bridge = new PacketBridge(builder -> process, Map.of("021122", "Lab Vendor"));
             var ble = new BleBridge(bridge.getEventQueue(), bridge.getProfiler());
             var server = new PassiveRfServer(bridge, ble, true).start(0);
             var client = HttpClient.newHttpClient()) {
            bridge.start("lab0", scanner);
            // The queued packet proves the finite capture has finished publishing its devices.
            assertNotNull(bridge.getPacketQueue().poll(3, TimeUnit.SECONDS));
            bridge.stop();
            var profiles = get(client, server, "/api/profiles");
            assertEquals(200, profiles.statusCode());
            var profile = mapper.readTree(profiles.body()).get(0);
            assertEquals(MAC, profile.path("mac").asText());
            assertEquals(1, profile.path("packetCount").asInt());
            assertTrue(profile.path("estimatedMeters").isNull());
            var channels = get(client, server, "/api/channels");
            assertEquals(200, channels.statusCode());
            assertEquals(wire(bridge.getChannelSnapshot()), mapper.readTree(channels.body()));
            var devices = mapper.readTree(get(client, server, "/api/devices").body());
            assertEquals("Lab Vendor", devices.path(MAC).path("vendor").asText());
            assertEquals(MAC, devices.path(MAC).path("mac").asText());
            assertFalse(bridge.isRunning());
        }
    }

    @Test void broadcastsQueueAndDirectEventsToMultipleClientsAndStopsTheConsumer() throws Exception {
        try (var bridge = new PacketBridge();
             var ble = new BleBridge(bridge.getEventQueue(), bridge.getProfiler());
             var server = new PassiveRfServer(bridge, ble, true).start(0);
             var client = HttpClient.newHttpClient()) {
            var first = new Events();
            var second = new Events();
            WebSocket one = connect(client, server, first);
            WebSocket two = connect(client, server, second);
            try {
                var device = new DeviceRecord(MAC, "Lab", null, DeviceRecord.DeviceType.IOT,
                        -45, 1000, 2000, null, null);
                var appeared = EwaveEvent.deviceAppeared(device);
                bridge.getEventQueue().put(appeared);
                JsonNode expected = wire(appeared);
                assertEquals(expected, first.next(mapper));
                assertEquals(expected, second.next(mapper));

                var updated = EwaveEvent.deviceUpdated(device);
                server.broadcast(updated);
                assertEquals(wire(updated), first.next(mapper));
                assertEquals(wire(updated), second.next(mapper));

                server.broadcast(new EwaveEvent("DATE_FORMAT", 0, new Date(0)));
                assertTrue(first.next(mapper).path("payload").isTextual());
                assertTrue(second.next(mapper).path("payload").asText().startsWith("1970-01-01"));

                one.sendClose(WebSocket.NORMAL_CLOSURE, "done").get(3, TimeUnit.SECONDS);
                assertNotNull(first.closed.poll(3, TimeUnit.SECONDS));
                // Serialization failures are isolated to the bad event, not the consumer thread.
                bridge.getEventQueue().put(new EwaveEvent("INVALID", 0, new Object()));
                bridge.getEventQueue().put(updated);
                assertEquals(wire(updated), second.next(mapper));
            } finally {
                one.abort();
                two.abort();
            }
            server.stop();
            assertTrue(Thread.getAllStackTraces().keySet().stream()
                    .noneMatch(thread -> thread.isAlive() && thread.getName().equals("ewave-ui-events")));
            var pending = EwaveEvent.attackStarted(Map.of("targetMac", MAC));
            bridge.getEventQueue().put(pending);
            assertSame(pending, bridge.getEventQueue().poll(1, TimeUnit.SECONDS));
        }
    }

    @Test void exposesDecodedProbeHistoryAndDeviceEnrichmentOverRestAndWebSocket() throws Exception {
        byte[] bytes = ("14:23:11 " + MAC + " > Broadcast, SSID 'Lab (guest)'\n").getBytes(StandardCharsets.UTF_8);
        Process process = new Process() {
            @Override public InputStream getInputStream() { return new ByteArrayInputStream(bytes); }
            @Override public OutputStream getOutputStream() { return new ByteArrayOutputStream(); }
            @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
            @Override public int waitFor() { return 0; }
            @Override public int exitValue() { return 0; }
            @Override public void destroy() { }
        };
        try (var bridge = new PacketBridge(builder -> process, Map.of());
             var ble = new BleBridge(bridge.getEventQueue(), bridge.getProfiler());
             var server = new PassiveRfServer(bridge, ble, true).start(0);
             var client = HttpClient.newHttpClient()) {
            var events = new Events();
            var socket = connect(client, server, events);
            try {
                bridge.startProbes("wlo1");
                var deviceEvent = events.next(mapper);
                assertEquals(EwaveEvent.DEVICE_APPEARED, deviceEvent.path("type").asText());
                assertEquals("Lab (guest)", deviceEvent.at("/payload/probedSsids/0").asText());
                var probe = events.next(mapper);
                assertEquals(EwaveEvent.PROBE_REQUEST, probe.path("type").asText());
                assertEquals("Lab (guest)", probe.at("/payload/ssid").asText());
                var history = mapper.readTree(get(client, server, "/api/probes").body());
                assertEquals(1, history.size());
                assertEquals(probe.path("payload"), history.get(0));
                var profile = mapper.readTree(get(client, server, "/api/profiles").body()).get(0);
                assertEquals("Lab (guest)", profile.path("probedSsids").get(0).asText());
                assertEquals(1, profile.path("packetCount").asInt());
                assertEquals(127, profile.path("lastRssi").asInt());
                assertTrue(profile.path("estimatedMeters").isNull());
                assertEquals("probes", mapper.readTree(get(client, server, "/api/status").body()).path("wifi").path("captureMode").asText());
                assertEquals(503, get(client, server, "/api/channels").statusCode());
            } finally {
                socket.abort();
            }
        }
    }

    @Test void servesBleDevicesReportsAndLiveEventsWithoutMergingWifiRecords() throws Exception {
        var process = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge();
             var ble = new BleBridge(bridge.getEventQueue(), builder -> process, bridge.getProfiler());
             var server = new PassiveRfServer(bridge, ble, true).start(0);
             var client = HttpClient.newHttpClient()) {
            var events = new Events();
            var socket = connect(client, server, events);
            try {
                ble.start(0);
                process.write(BleFrames.snoop(1002,0,BleFrames.legacy(BleFrames.data())));
                var deviceEvent = events.next(mapper);
                assertEquals(EwaveEvent.BLE_DEVICE_UPDATED,deviceEvent.path("type").asText());
                assertEquals("Lab Tag",deviceEvent.at("/payload/lastAdvertisedName").asText());
                var advertisement = events.next(mapper);
                assertEquals(EwaveEvent.BLE_ADVERTISEMENT,advertisement.path("type").asText());
                var history = get(client,server,"/api/ble/advertisements");
                assertEquals(200,history.statusCode());
                assertEquals(advertisement.path("payload"),mapper.readTree(history.body()).get(0));
                var devices = mapper.readTree(get(client,server,"/api/ble/devices").body());
                assertEquals(1,devices.size());
                assertEquals(mapper.readTree("{}"),mapper.readTree(get(client,server,"/api/devices").body()));
                var status = mapper.readTree(get(client,server,"/api/ble/status").body());
                assertTrue(status.path("captureRunning").asBoolean());
                assertEquals("passive",status.path("scanMode").asText());
            } finally { socket.abort(); }
        }
    }

    @Test void exposesSharedWifiAndBleProfilesOncePerCapturedFrame() throws Exception {
        var wifiProcess = new StreamingCaptureProcess();
        var bleProcess = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge(builder -> wifiProcess, Map.of());
             var ble = new BleBridge(bridge.getEventQueue(), builder -> bleProcess, bridge.getProfiler());
             var server = new PassiveRfServer(bridge, ble, true).start(0);
             var client = HttpClient.newHttpClient()) {
            bridge.startProbes("lab0mon");
            ble.start(0);
            wifiProcess.write((MAC + " > Broadcast, Probe Request (Research lab)\n").getBytes(StandardCharsets.UTF_8));
            bleProcess.write(BleFrames.snoop(1002, 0, BleFrames.legacy(BleFrames.concat(
                    BleFrames.ad(0xff, new byte[]{0x4c, 0, 0x02}),
                    BleFrames.ad(3, new byte[]{0x0d, 0x18, (byte) 0xf1, (byte) 0xfc}),
                    BleFrames.ad(0x16, new byte[]{0x69, (byte) 0xfd})))));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (bridge.getProfiler().all().size() < 2 && System.nanoTime() < deadline) Thread.sleep(5);
            assertEquals(2, bridge.getProfiler().all().size());
            assertSame(bridge.getProfiler(), ble.getProfiler());
            var response = get(client, server, "/api/profiles");
            assertEquals(200, response.statusCode());
            var profiles = mapper.readTree(response.body());
            assertTrue(profiles.isArray());
            assertEquals(2, profiles.size());
            assertEquals("Research lab", profiles.get(0).path("probedSsids").get(0).asText());
            assertEquals("iBeacon", profiles.get(1).path("guessedType").asText());
            assertEquals("Heart Rate Monitor", profiles.get(1).path("services").get(0).asText());
            assertEquals("Google Nearby Share (Android phone)", profiles.get(1).path("services").get(1).asText());
            assertEquals("Google Find My Device", profiles.get(1).path("services").get(2).asText());
            assertTrue(Instant.parse(profiles.get(0).path("firstSeen").asText()).isAfter(Instant.now().minusSeconds(30)));
            assertEquals("2023-11-14T22:13:20Z", profiles.get(1).path("firstSeen").asText());
            assertTrue(profiles.get(0).path("estimatedMeters").isNull());
            assertTrue(profiles.get(1).path("estimatedMeters").isNumber());
            for (var profile : profiles) {
                assertEquals(1, profile.path("packetCount").asInt());
                assertTrue(profile.path("isRandomMac").isBoolean());
                assertTrue(profile.path("isRandomMac").asBoolean());
            }
            bridge.stop();
            ble.stop();
            assertEquals(profiles, mapper.readTree(get(client, server, "/api/profiles").body()));
        }
    }

    private static URI uri(PassiveRfServer server, String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private JsonNode wire(Object value) throws Exception {
        return mapper.readTree(mapper.writeValueAsString(value));
    }

    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, path)).timeout(Duration.ofSeconds(5)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String path, String json) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, path)).timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static WebSocket connect(HttpClient client, PassiveRfServer server, Events listener) throws Exception {
        return client.newWebSocketBuilder().buildAsync(
                URI.create("ws://localhost:" + server.port() + "/ws/events"), listener).get(3, TimeUnit.SECONDS);
    }

    private static final class Events implements WebSocket.Listener {
        private final BlockingQueue<String> messages = new LinkedBlockingQueue<>();
        private final BlockingQueue<Integer> closed = new LinkedBlockingQueue<>();
        private final StringBuilder partial = new StringBuilder();

        @Override public java.util.concurrent.CompletionStage<?> onText(WebSocket socket, CharSequence text, boolean last) {
            partial.append(text);
            if (last) {
                messages.add(partial.toString());
                partial.setLength(0);
            }
            socket.request(1);
            return null;
        }

        @Override public java.util.concurrent.CompletionStage<?> onClose(WebSocket socket, int status, String reason) {
            closed.add(status);
            return null;
        }

        JsonNode next(ObjectMapper mapper) throws Exception {
            String json = messages.poll(3, TimeUnit.SECONDS);
            assertNotNull(json, "Expected a broadcast event");
            return mapper.readTree(json);
        }
    }
}
