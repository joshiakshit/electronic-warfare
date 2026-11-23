package ewave.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.Ewave;
import ewave.core.AdaptiveScanner;
import ewave.decoder.Dot11FrameDecoder;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.DeviceRecord;
import ewave.model.EwaveEvent;
import ewave.passive.DeviceProfiler;
import ewave.passive.MyNetworkProfile;
import ewave.passive.PassiveWifiSession;
import ewave.ui.PassiveRfServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.io.TempDir;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.Date;
import java.util.HexFormat;
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

    @Test void servesOnlyApiAndRejectsCrossOriginOperations() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(404, get(client, server, "/").statusCode());
            for (String asset : List.of("/index.html", "/ewave.js", "/ewave.css", "/graph.js", "/spectrum.js",
                    "/ap-watch.js", "/probe-demo.js", "/ewave.svg", "/portal/portal.html"))
                assertEquals(404, get(client, server, asset).statusCode(), asset);
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
            assertEquals(50, demo.at("/adaptive/detections/1/delayMs").asInt());
            assertEquals(850, demo.at("/adaptive/detections/2/delayMs").asInt());
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
        byte[] pcap = ewave.fixtures.ProbeFrames.pcap(java.nio.ByteOrder.LITTLE_ENDIAN, false, 127,
                ewave.fixtures.ProbeFrames.radiotap(ewave.fixtures.ProbeFrames.frame("LabNet")));
        java.nio.ByteBuffer.wrap(pcap).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putInt(24, (int) (System.currentTimeMillis() / 1000));
        var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71), 120);
        var process = new StreamingCaptureProcess();
        var tuned = new StreamingCaptureProcess();
        tuned.finish();
        try (var bridge = new PacketBridge(builder -> builder.command().getFirst().equals("sudo") ? tuned : process,
                     Map.of("021122", "Lab Vendor"), new DeviceProfiler(), 50);
             var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            bridge.startPassive("lab0", true, scanner);
            process.write(pcap);
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while ((bridge.getPassiveWifi() == null || bridge.getPassiveWifi().inventory().isEmpty()
                    || bridge.getChannelSnapshot() == null || bridge.getChannelSnapshot().lastChosen() == null)
                    && System.nanoTime() < deadline) {
                Thread.sleep(15);
            }
            assertFalse(bridge.getPassiveWifi().inventory().isEmpty());
            assertNotNull(bridge.getChannelSnapshot().lastChosen());

            var channels = get(client, server, "/api/channels");
            assertEquals(200, channels.statusCode());
            var response = mapper.readTree(channels.body());
            Instant.parse(response.path("timestamp").asText());
            assertEquals(50, response.path("tickMs").asInt());
            assertEquals(13, response.at("/radio/dwellMs").size());
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
            var profiler = get(client, server, "/api/profiler");
            assertEquals(200, profiler.statusCode());
            var observed = mapper.readTree(profiler.body()).get(0);
            assertEquals(1, observed.path("packetCount").asInt());
            assertEquals(503, get(client, server, "/api/channels").statusCode());

            // Retired text-mode endpoints return 410 Gone with explicit migration pointers.
            for (String retired : List.of("/api/devices", "/api/profiles", "/api/probes")) {
                var gone = get(client, server, retired);
                assertEquals(410, gone.statusCode(), retired);
                assertFalse(mapper.readTree(gone.body()).path("replacement").asText().isEmpty(), retired);
            }
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
        byte[] pcap = ewave.fixtures.ProbeFrames.pcap(java.nio.ByteOrder.LITTLE_ENDIAN, false, 127,
                ewave.fixtures.ProbeFrames.radiotap(ewave.fixtures.ProbeFrames.frame("Lab (guest)")));
        java.nio.ByteBuffer.wrap(pcap).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putInt(24, (int) (System.currentTimeMillis() / 1000));
        var process = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge(builder -> process, Map.of());
             var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            var events = new Events();
            var socket = connect(client, server, events);
            try {
                bridge.startPassive("wlo1", false);
                process.write(pcap);
                var first = events.next(mapper).path("type").asText();
                var second = events.next(mapper).path("type").asText();
                assertEquals(List.of("WIFI_DEVICE_SEEN", "PROBE_RECEIVED"), List.of(first, second));
                var decloaker = mapper.readTree(get(client, server, "/api/decloaker").body());
                assertEquals(1, decloaker.path("totalProbes").asInt());
                assertEquals(1, decloaker.path("directedProbes").asInt());
                assertEquals(410, get(client, server, "/api/probes").statusCode());
                assertEquals("watch", mapper.readTree(get(client, server, "/api/status").body())
                        .path("wifi").path("captureMode").asText());
                assertEquals(503, get(client, server, "/api/channels").statusCode());
            } finally {
                socket.abort();
            }
        }
    }

    @Test void parsesLaunchModesRejectsContradictoryFlagsAndDispatchesExpectedCommands(@TempDir Path dir) throws Exception {
        assertEquals(new Ewave.LaunchPlan(Ewave.Mode.HELP, "wlo1", 7070, 13, 100, false, false, null),
                Ewave.parse("--help"));
        assertEquals(new Ewave.LaunchPlan(Ewave.Mode.IDLE, "wlo1", 7070, 13, 100, false, true, null),
                Ewave.parse());
        assertEquals(new Ewave.LaunchPlan(Ewave.Mode.CAPTURE, "mon0", 7070, 13, 100, false, true, null),
                Ewave.parse("--iface", "mon0"));
        assertEquals(new Ewave.LaunchPlan(Ewave.Mode.CAPTURE, "mon0", 7070, 13, 100, false, true, null),
                Ewave.parse("--passive-rf", "--iface", "mon0"));
        assertEquals(new Ewave.LaunchPlan(Ewave.Mode.CAPTURE, "mon0", 7070, 13, 100, true, true, null),
                Ewave.parse("--passive-rf", "--adaptive", "--iface", "mon0"));
        assertEquals(new Ewave.LaunchPlan(Ewave.Mode.REPLAY, "wlo1", 7070, 13, 100, false, false, Path.of("sample.pcap")),
                Ewave.parse("--replay", "sample.pcap"));

        for (String[] invalid : List.of(
                new String[]{"--probes"},
                new String[]{"--probes", "--iface", "mon0"},
                new String[]{"--replay", "sample.pcap", "--passive-rf"},
                new String[]{"--replay", "sample.pcap", "--iface", "wlo1"},
                new String[]{"--adaptive"},
                new String[]{"--bands", "12"},
                new String[]{"--tick-ms", "5"},
                new String[]{"--tick-ms", "2001"},
                new String[]{"--port", "70000"},
                new String[]{"--iface", "  "},
                new String[]{"--unknown"}
        )) {
            assertThrows(IllegalArgumentException.class, () -> Ewave.parse(invalid), String.join(" ", invalid));
        }

        List<List<String>> launched = new java.util.concurrent.CopyOnWriteArrayList<>();
        try (var bridge = new PacketBridge(builder -> {
            launched.add(List.copyOf(builder.command()));
            return new StreamingCaptureProcess();
        }, Map.of())) {
            Ewave.startCapture(Ewave.parse(), bridge);
            assertTrue(launched.isEmpty(), () -> "Idle launch should not start capture: " + launched);
            assertFalse(bridge.isRunning());

            Ewave.startCapture(Ewave.parse("--passive-rf", "--iface", "mon0"), bridge);
            assertTrue(launched.stream().anyMatch(cmd -> cmd.getFirst().equals("tcpdump") && cmd.contains("IEEE802_11_RADIO")),
                    () -> "Launched: " + launched);
            bridge.stop();
            launched.clear();

            Ewave.startCapture(Ewave.parse("--iface", "mon0"), bridge);
            assertTrue(launched.stream().anyMatch(cmd -> cmd.getFirst().equals("tcpdump") && cmd.contains("IEEE802_11_RADIO")),
                    () -> "Launched: " + launched);
            bridge.stop();
            launched.clear();

            Path tempPcap = dir.resolve("cli-replay.pcap");
            byte[] header = ewave.fixtures.ProbeFrames.pcap(java.nio.ByteOrder.LITTLE_ENDIAN, false, 127);
            Files.write(tempPcap, header);
            Ewave.startCapture(Ewave.parse("--replay", tempPcap.toString()), bridge);
            assertTrue(launched.isEmpty());
        }
    }

    @Test void parsesChannelBandRevealAndScopeFlagsAndMatchesExactSsidBytes() throws Exception {
        var c1 = Ewave.parseConfig("--passive-rf", "--iface", "wlo1", "--channel", "6", "--band", "2.4",
                "--reveal-probes", "--scope", "00:11:22:33:44:55");
        assertEquals(2437, c1.frequencyMhz());
        assertEquals(Boolean.TRUE, c1.revealProbes());
        assertEquals("00:11:22:33:44:55", c1.scope());

        assertEquals(5500, Ewave.parseConfig("--passive-rf", "--channel", "100", "--band", "5").frequencyMhz());
        assertEquals(5955, Ewave.parseConfig("--passive-rf", "--channel", "1", "--band", "6").frequencyMhz());
        assertEquals(2484, Ewave.parseConfig("--passive-rf", "--channel", "14").frequencyMhz());
        assertEquals(5180, Ewave.parseConfig("--passive-rf", "--channel", "36").frequencyMhz());
        assertEquals(Boolean.FALSE, Ewave.parseConfig("--replay", "sample.pcap", "--hide-probes").revealProbes());

        for (String[] invalid : List.of(
                new String[]{"--passive-rf", "--channel", "6"},
                new String[]{"--passive-rf", "--channel", "149"},
                new String[]{"--passive-rf", "--band", "2.4"},
                new String[]{"--passive-rf", "--freq", "2437", "--channel", "6", "--band", "2.4"},
                new String[]{"--passive-rf", "--adaptive", "--freq", "2437"},
                new String[]{"--replay", "sample.pcap", "--freq", "2437"},
                new String[]{"--passive-rf", "--reveal-probes", "--hide-probes"},
                new String[]{"--interactive"},
                new String[]{"--report-dir", "reports"}
        )) {
            assertThrows(IllegalArgumentException.class, () -> Ewave.parseConfig(invalid), String.join(" ", invalid));
        }

        // Exact SSID byte matching distinguishes raw non-UTF-8 octets from replacement characters.
        var session = new PassiveWifiSession(new DeviceProfiler(), MyNetworkProfile.EMPTY, () -> 1_000L);
        byte[] rawBytes = new byte[]{(byte) 0xff, (byte) 0xfe, 'A'};
        byte[] replacementChars = "\ufffd\ufffdA".getBytes(StandardCharsets.UTF_8);
        String apA = "00:11:22:33:44:55", apB = "00:11:22:33:44:66";
        session.observe(Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(beacon(apA, rawBytes)), 127, 1_000L));
        session.observe(Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(beacon(apB, replacementChars)), 127, 1_000L));
        assertEquals(List.of(session.addressId(apA)), session.findAccessPoints(rawBytes));
        assertEquals(List.of(session.addressId(apB)), session.findAccessPoints(replacementChars));
    }

    private static byte[] beacon(String bssid, byte[] ssid) {
        byte[] mac = HexFormat.ofDelimiter(":").parseHex(bssid);
        byte[] bcast = HexFormat.of().parseHex("ffffffffffff");
        var buf = ByteBuffer.allocate(24 + 12 + 2 + ssid.length).order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort((short) 0x0080).putShort((short) 0).put(bcast).put(mac).put(mac).putShort((short) 0);
        buf.putLong(1L).putShort((short) 100).putShort((short) 1);
        buf.put((byte) 0).put((byte) ssid.length).put(ssid);
        return buf.array();
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
