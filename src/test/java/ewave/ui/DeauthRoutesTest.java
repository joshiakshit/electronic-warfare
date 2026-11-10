package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.FrameInjector;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.fixtures.CompletedProcess;
import ewave.capture.PacketBridge;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.PacketEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class DeauthRoutesTest {
    private static final String AP = "02:11:22:33:44:55";
    private static final String REQUEST = "{\"apBssid\":\"" + AP + "\",\"count\":10,\"interface\":\"wlo1\"}";
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path temporary;

    @Test void missingApCacheReturnsAnActionableErrorAndPreventsInjection() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true, monitor -> new FrameInjector(monitor,
                     builder -> { fail("must not start without a cached AP"); return null; }), new LanScanner(),
                     new WifiAccessPoints(temporary.resolve("missing-aps"))).start(0);
             var client = HttpClient.newHttpClient()) {
            var aps = get(client, server, "/api/attack/aps");
            assertEquals(404, aps.statusCode());
            assertTrue(mapper.readTree(aps.body()).path("error").asText().contains("No Wi-Fi AP cache found"));
            assertEquals(400, client.send(post(server, REQUEST), HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }

    @Test void scanLanReturnsCachedHostsAndReportsMissingCache() throws Exception {
        Path table = temporary.resolve("ewave-lan-hosts.txt");
        Files.write(table, List.of("Interface: wlo1, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.29.136",
                "Starting arp-scan with 256 hosts",
                "192.168.29.94\t46:f9:b7:de:09:48\t(Unknown: locally administered)",
                "192.168.29.136 aa:bb:cc:dd:ee:ff (This laptop)",
                "#192.168.29.20 00:11:22:33:44:55 (Comment)", "Ending arp-scan"));
        for (boolean fails : new boolean[]{false, true}) {
            var scanner = new LanScanner(fails ? temporary.resolve("missing-arp") : table);
            try (var bridge = new PacketBridge();
                 var server = new PassiveRfServer(bridge, true, FrameInjector::new, scanner, cachedAps()).start(0);
                 var client = HttpClient.newHttpClient()) {
                var response = get(client, server, "/api/attack/scan-lan");
                if (fails) {
                    assertEquals(404, response.statusCode());
                    assertEquals("No LAN cache found. Restart ewave with ./scripts/start-ewave.sh to populate.",
                            mapper.readTree(response.body()).path("error").asText());
                } else {
                    assertEquals(200, response.statusCode());
                    assertEquals(mapper.readTree("[{\"ip\":\"192.168.29.94\",\"mac\":\"46:f9:b7:de:09:48\",\"vendor\":\"Unknown: locally administered\"}]"),
                            mapper.readTree(response.body()));
                }
            }
        }
    }

    @Test void exposesTargetsRunsBroadcastAndStreamsOutputWhileRejectingOverlaps() throws Exception {
        var process = new StreamingCaptureProcess();
        var launched = new CountDownLatch(1);
        var command = new AtomicReference<List<String>>();
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true, monitor -> new FrameInjector(monitor, builder -> {
                 if (builder.command().get(1).equals("iw")) return new CompletedProcess("", 0);
                command.set(builder.command()); launched.countDown(); return process;
             }), new LanScanner(), cachedAps()).start(0);
             var client = HttpClient.newHttpClient()) {
            bridge.getProfiler().observe(new PacketEvent(AP, "ff:ff:ff:ff:ff:ff", 6, -70, 50, "802.11", 1000, "lab"));
            var targets = mapper.readTree(get(client, server, "/api/attack/targets").body());
            assertEquals(1, targets.size());
            assertEquals(5, targets.get(0).size());
            assertEquals(AP, targets.at("/0/id").asText());
            assertEquals("Unknown", targets.at("/0/type").asText());
            assertEquals(AP, targets.at("/0/mac").asText());
            assertEquals(-70, targets.at("/0/rssi").asInt());
            var aps = mapper.readTree(get(client, server, "/api/attack/aps").body());
            assertEquals(AP, aps.at("/0/bssid").asText());
            assertEquals(2, aps.at("/0/channel").asInt());
            assertEquals(2417, aps.at("/0/frequencyMhz").asInt());
            assertTrue(targets.at("/0/label").isTextual());
            assertFalse(mapper.readTree(get(client, server, "/api/attack/status").body()).path("running").asBoolean());

            var pending = client.sendAsync(post(server, REQUEST), HttpResponse.BodyHandlers.ofString());
            assertTrue(launched.await(3, TimeUnit.SECONDS));
            process.write("injecting frames\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            // Publication of a live chunk must precede completion of the synchronous POST.
            var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            String output = "";
            while (System.nanoTime() < deadline && !output.contains("injecting frames")) {
                var status = mapper.readTree(get(client, server, "/api/attack/status").body());
                assertTrue(status.path("running").asBoolean());
                output = status.path("output").asText();
            }
            assertTrue(output.contains("injecting frames"));
            assertFalse(pending.isDone());
            assertEquals(409, client.send(post(server, REQUEST), HttpResponse.BodyHandlers.ofString()).statusCode());
            assertEquals(List.of("sudo", "aireplay-ng", "--ignore-negative-one", "--deauth", "10", "-a", AP, "wlo1"), command.get());
            process.finish();
            var response = pending.get(3, TimeUnit.SECONDS);
            assertEquals(200, response.statusCode());
            var result = mapper.readTree(response.body());
            assertEquals(6, result.size());
            assertTrue(result.path("success").asBoolean());
            assertEquals("deauth", result.path("attackType").asText());
            assertTrue(result.path("output").asText().endsWith("injecting frames\n"));
            assertTrue(result.path("command").asText().startsWith("sudo iw dev wlo1 set freq 2417\n"));
            assertNotNull(Instant.parse(result.path("timestamp").asText()));
            var status = mapper.readTree(get(client, server, "/api/attack/status").body());
            assertFalse(status.path("running").asBoolean());
            assertEquals(result, status.path("result"));
        }
    }

    @Test void validatesJsonTypesAndArgumentsAndReturnsLaunchErrorsAsResults() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true, monitor -> new FrameInjector(monitor,
                     builder -> {
                         if (builder.command().get(1).equals("iw")) return new CompletedProcess("", 0);
                         throw new IOException("aireplay-ng missing");
                     }), new LanScanner(), cachedAps()).start(0);
             var client = HttpClient.newHttpClient()) {
            for (String body : new String[]{"null", "[]", "{", "{}", REQUEST + " {}",
                    REQUEST.replace(AP, "--help"), REQUEST.replace(AP, "02:00:00:00:00:99"), REQUEST.replace("10", "-1"), REQUEST.replace("10", "1.5"),
                    REQUEST.replace("10", "\"10\""), REQUEST.replace("10", "true"), REQUEST.replace("10", "2147483648"),
                    REQUEST.replace("wlo1", "--help"), REQUEST.replace("wlo1", "a b"),
                    REQUEST.replace("}", ",\"clientMac\":\"bad\"}"), REQUEST.replace("}", ",\"clientMac\":42}")}) {
                var response = client.send(post(server, body), HttpResponse.BodyHandlers.ofString());
                assertEquals(400, response.statusCode(), body);
                assertTrue(mapper.readTree(response.body()).has("error"));
            }
            var response = client.send(post(server, REQUEST), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            assertFalse(mapper.readTree(response.body()).path("success").asBoolean());
            assertTrue(mapper.readTree(response.body()).path("output").asText().contains("aireplay-ng missing"));
        }
    }

    @Test void stopAndServerShutdownKillActiveInjection() throws Exception {
        for (boolean shutdown : new boolean[]{false, true}) {
            var process = new StreamingCaptureProcess();
            var launched = new CountDownLatch(1);
            try (var bridge = new PacketBridge();
                 var server = new PassiveRfServer(bridge, true, monitor -> new FrameInjector(monitor, builder -> {
                     if (builder.command().get(1).equals("iw")) return new CompletedProcess("", 0);
                 launched.countDown(); return process;
                 }), new LanScanner(), cachedAps()).start(0);
                 var client = HttpClient.newHttpClient()) {
                var pending = client.sendAsync(post(server, REQUEST), HttpResponse.BodyHandlers.ofString());
                assertTrue(launched.await(3, TimeUnit.SECONDS));
                if (shutdown) server.stop();
                else {
                    var response = client.send(HttpRequest.newBuilder(uri(server, "/api/attack/stop"))
                            .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
                    assertEquals(200, response.statusCode());
                    assertTrue(mapper.readTree(response.body()).path("stopped").asBoolean());
                    var result = mapper.readTree(pending.get(3, TimeUnit.SECONDS).body());
                    assertFalse(result.path("success").asBoolean());
                    assertTrue(result.path("output").asText().contains("Stopped by request"));
                }
                assertFalse(process.isAlive());
            }
        }
    }

    private WifiAccessPoints cachedAps() throws IOException {
        Path cache = temporary.resolve("aps.txt");
        Files.writeString(cache, "Lab AP:02\\:11\\:22\\:33\\:44\\:55:2:2417 MHz\n");
        return new WifiAccessPoints(cache);
    }

    private static URI uri(PassiveRfServer server, String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }
    private static HttpRequest post(PassiveRfServer server, String body) {
        return HttpRequest.newBuilder(uri(server, "/api/attack/deauth"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }
    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, path)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
