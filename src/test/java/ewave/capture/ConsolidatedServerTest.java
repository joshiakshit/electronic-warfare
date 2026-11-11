package ewave.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.core.AdaptiveScanner;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.DeviceRecord;
import ewave.model.EwaveEvent;
import ewave.passive.DeviceProfiler;
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
             var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(200, get(client, server, "/").statusCode());
            for (String asset : List.of("/ewave.js", "/ewave.css", "/graph.js", "/spectrum.js"))
                assertEquals(200, get(client, server, asset).statusCode(), asset);
            assertEquals(404, get(client, server, "/dashboard.js").statusCode());
            var channels = get(client, server, "/api/channels");
            assertEquals(503, channels.statusCode());
            assertEquals("no scanner attached", mapper.readTree(channels.body()).path("error").asText());
            assertEquals(404, post(client, server, "/api/attack", "{}").statusCode());
            var foreign = client.send(HttpRequest.newBuilder(uri(server, "/api/attack/stop"))
                    .header("Origin", "https://foreign.example")
                    .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(403, foreign.statusCode());
            assertEquals(200, post(client, server, "/api/attack/stop", "").statusCode());
        }
    }

    @Test void comparesThreePoliciesOnTheSameFixtureWithoutACapture() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, false).start(0);
             var client = HttpClient.newHttpClient()) {
            var response = get(client, server, "/api/channels/demo");
            assertEquals(200, response.statusCode());
            assertEquals(response.body(), get(client, server, "/api/channels/demo").body());
            var demo = mapper.readTree(response.body());
            assertEquals(6, demo.path("fixedChannel").asInt());
            assertEquals(0, demo.at("/fixed/detections/0/delayMs").asInt(-1));
            assertTrue(demo.at("/fixed/detections/1/delayMs").isNull());
            assertEquals(1350, demo.at("/adaptive/detections/1/delayMs").asInt());
            assertEquals(950, demo.at("/adaptive/detections/2/delayMs").asInt());
            assertEquals(450, demo.at("/roundRobin/detections/1/delayMs").asInt());
            assertEquals(1150, demo.at("/roundRobin/detections/2/delayMs").asInt());
            assertEquals(13, demo.at("/roundRobin/channelsVisited").asInt());
            assertEquals(119, demo.at("/roundRobin/retunes").asInt());
            for (String name : List.of("fixed", "roundRobin", "adaptive")) {
                var run = demo.path(name);
                long dwell = 0;
                for (var channel : run.path("dwellMs")) dwell += channel.asLong();
                assertEquals(demo.path("durationMs").asLong(),
                        dwell + run.path("retunes").asLong() * demo.path("simulatedRetuneMs").asLong());
                assertEquals(140, run.path("capturedFrames").asInt() + run.path("missedFrames").asInt());
            }
        }
    }

    @Test void decodesSyntheticProbeDemoWithoutEnablingCaptureOrDisclosingLiveNames() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(404, get(client, server, "/api/probe-audit").statusCode());
            var response = get(client, server, "/api/probe-audit/demo");
            assertEquals(200, response.statusCode());
            var samples = mapper.readTree(response.body());
            assertEquals(2, samples.size());
            assertEquals("Lab (guest)", samples.get(0).path("networkName").asText());
            assertEquals(6, samples.get(0).path("channel").asInt());
            assertTrue(samples.get(1).path("networkName").isNull());
            assertEquals(1000, samples.get(1).path("elapsedMs").asInt());
            assertEquals(404, get(client, server, "/api/probe-audit").statusCode());
        }
    }

    @Test void exposesChannelsWhileTheCaptureScannerIsRunningAndKeepsDevicesAfterStop() throws Exception {
        String packet = "1700000000.123456 " + MAC
                + " > ff:ff:ff:ff:ff:ff, ethertype IPv4 (0x0800), length 128: UDP";
        var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71), 120);
        var process = new StreamingCaptureProcess();
        var tuned = new StreamingCaptureProcess();
        tuned.finish();
        try (var bridge = new PacketBridge(builder -> builder.command().getFirst().equals("sudo") ? tuned : process,
                     Map.of("021122", "Lab Vendor"), new DeviceProfiler(), 50);
             var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            bridge.start("lab0", scanner);
            process.write((packet + "\n").getBytes(StandardCharsets.UTF_8));
            assertNotNull(bridge.getPacketQueue().poll(3, TimeUnit.SECONDS));

            var channels = get(client, server, "/api/channels");
            assertEquals(200, channels.statusCode());
            var response = mapper.readTree(channels.body());
            Instant.parse(response.path("timestamp").asText());
            assertEquals(50, response.path("tickMs").asInt());
            assertEquals(13, response.at("/radio/dwellMs").size());
            assertTrue(response.at("/radio/coverage").isArray());
            assertTrue(response.at("/radio/coverage").isEmpty());
            assertTrue(response.at("/radio/lastObservedChannel").isNull());
            int chosen = response.path("lastChosen").asInt();
            assertTrue(chosen >= 1 && chosen <= 13);
            assertEquals(2407 + chosen * 5, response.path("lastChosenFreqMhz").asInt());
            assertEquals(13, response.path("channels").size());
            var first = response.path("channels").get(0);
            assertEquals(1, first.path("channel").asInt());
            assertEquals(2412, first.path("freqMhz").asInt());
            assertEquals(response.path("scores").get(0).asDouble(), first.path("score").asDouble());
            assertEquals(response.path("means").get(0).asDouble(), first.path("occupancyMean").asDouble());
            assertEquals(0, first.path("fittedPeriodMs").asDouble());
            assertEquals(0, first.path("fitConfidence").asDouble());
            assertEquals("Transient / mobile", first.path("deviceHint").asText());
            assertTrue(first.path("coupledWith").isEmpty());
            assertTrue(first.path("anomaly").isNull());

            bridge.stop();
            var profiles = get(client, server, "/api/profiles");
            assertEquals(200, profiles.statusCode());
            var profile = mapper.readTree(profiles.body()).get(0);
            assertEquals(MAC, profile.path("mac").asText());
            assertEquals(1, profile.path("packetCount").asInt());
            assertTrue(profile.path("estimatedMeters").isNull());
            assertEquals(503, get(client, server, "/api/channels").statusCode());
            var devices = mapper.readTree(get(client, server, "/api/devices").body());
            assertEquals("Lab Vendor", devices.path(MAC).path("vendor").asText());
            assertEquals(MAC, devices.path(MAC).path("mac").asText());
            assertFalse(bridge.isRunning());
        }
    }

    @Test void broadcastsQueueAndDirectEventsToMultipleClientsAndStopsTheConsumer() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true).start(0);
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
             var server = new PassiveRfServer(bridge, true).start(0);
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
