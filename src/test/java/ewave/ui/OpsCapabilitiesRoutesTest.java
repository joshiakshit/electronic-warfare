package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.BeaconFlood;
import ewave.active.FrameInjector;
import ewave.active.LanScanner;
import ewave.active.PmkidCapture;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class OpsCapabilitiesRoutesTest {
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path directory;

    @Test void exposesToolCacheAndOperationReadiness() throws Exception {
        Path aps = Files.writeString(directory.resolve("aps.txt"),
                "Lab AP:02\\:11\\:22\\:33\\:44\\:55:6:2437 MHz\n");
        Path lan = Files.writeString(directory.resolve("lan.txt"),
                "192.168.1.20 02:aa:bb:cc:dd:01 (Lab device)\n");
        Path wordlist = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        String previous = System.getProperty("rf.wordlist");
        System.setProperty("rf.wordlist", wordlist.toString());
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true, FrameInjector::new, new LanScanner(lan),
                     new WifiAccessPoints(aps)).start(0);
             var client = HttpClient.newHttpClient()) {
            var response = get(client, server, "/api/ops/capabilities");
            assertEquals(200, response.statusCode(), response.body());
            var body = mapper.readTree(response.body());
            assertTrue(body.path("operationsEnabled").asBoolean());
            assertEquals(13, body.path("tools").size());
            assertEquals(7, body.path("operations").size());
            assertTrue(body.at("/caches/accessPoints/path").asText().endsWith("aps.txt"));
            assertEquals(1, body.at("/caches/accessPoints/entries").asInt());
            assertEquals(1, body.at("/caches/lanHosts/entries").asInt());
            assertTrue(body.path("monitorInterfaces").isArray());
            assertTrue(body.path("interfaces").isArray());
            assertTrue(body.path("activeOperation").isNull());
            assertTrue(body.path("activeOperationId").isNull());
            if (!body.path("interfaces").isEmpty()) {
                assertTrue(body.at("/interfaces/0/ipv4Addresses").isArray());
            }
            assertEquals(wordlist.toString(), body.at("/wordlist/path").asText());
            assertTrue(body.at("/wordlist/available").asBoolean());
            assertTrue(body.at("/operations").findValues("id").stream()
                    .anyMatch(id -> id.asText().equals("deauth")));
        } finally {
            if (previous == null) System.clearProperty("rf.wordlist");
            else System.setProperty("rf.wordlist", previous);
        }
    }

    @Test void reportsActiveOperationIdWhileAnOperationIsRunning() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, true, FrameInjector::new, new LanScanner(),
                     new WifiAccessPoints(directory.resolve("missing-aps")),
                     settings -> { fail("handshake must not start"); return null; },
                     settings -> new PmkidCapture(settings.monitorInterface()),
                     settings -> new BeaconFlood(settings.monitorInterface(),
                             builder -> new StreamingCaptureProcess())).start(0);
             var client = HttpClient.newHttpClient()) {
            var started = client.send(HttpRequest.newBuilder(
                            URI.create("http://localhost:" + server.port() + "/api/ops/beacon"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"interface\":\"wlo1\",\"ssid\":\"beacon-id\"}"))
                    .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, started.statusCode(), started.body());
            var caps = mapper.readTree(get(client, server, "/api/ops/capabilities").body());
            assertEquals("beacon", caps.path("activeOperation").asText());
            assertFalse(caps.path("activeOperationId").isNull());
            assertNotNull(UUID.fromString(caps.path("activeOperationId").asText()));
            assertEquals(200, client.send(HttpRequest.newBuilder(
                            URI.create("http://localhost:" + server.port() + "/api/ops/stop"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build(), HttpResponse.BodyHandlers.ofString()).statusCode());
            var idleCaps = mapper.readTree(get(client, server, "/api/ops/capabilities").body());
            assertTrue(idleCaps.path("activeOperationId").isNull());
        }
    }

    @Test void isUnavailableWhenOperationsAreDisabled() throws Exception {
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, false).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(404, get(client, server, "/api/ops/capabilities").statusCode());
        }
    }

    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
