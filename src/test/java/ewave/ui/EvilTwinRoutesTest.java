package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.EvilTwin;
import ewave.active.FrameInjector;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.fixtures.StreamingCaptureProcess;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class EvilTwinRoutesTest {
    private static final String REQUEST = "{\"interface\":\"wlo1ap\",\"ssid\":\"ewave-portal\","
            + "\"channel\":6,\"portalPort\":8080}";
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path directory;

    @Test void startsReportsLiveCredentialsAndStopsThePortal() throws Exception {
        var processes = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        Path creds = directory.resolve("creds.txt");
        try (var bridge = new PacketBridge();
             var server = server(bridge, factory(processes));
             var client = HttpClient.newHttpClient()) {
            var response = post(client, server, REQUEST);
            assertEquals(200, response.statusCode(), response.body());
            var started = mapper.readTree(response.body());
            assertTrue(started.path("running").asBoolean());
            assertEquals("ewave-portal", started.path("ssid").asText());
            assertEquals("http://10.0.0.1:8080/", started.path("portalUrl").asText());
            assertEquals(3, processes.size());

            Files.writeString(creds, "2026-01-01T10:00:00\t10.0.0.42\tstudent\tsecret\n");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            var status = mapper.readTree(get(client, server).body());
            while (status.path("credentials").isEmpty() && System.nanoTime() < deadline) {
                Thread.sleep(50);
                status = mapper.readTree(get(client, server).body());
            }
            assertEquals(1, status.path("credentials").size());
            assertEquals("student", status.at("/credentials/0/username").asText());
            assertEquals("secret", status.at("/credentials/0/password").asText());
            assertEquals("10.0.0.42", status.at("/credentials/0/client").asText());

            assertEquals(200, post(client, server, "/api/attack/stop", "{}").statusCode());
            for (var process : processes) assertFalse(process.isAlive());
            var stopped = mapper.readTree(get(client, server).body());
            assertFalse(stopped.path("running").asBoolean());
            assertEquals(1, stopped.path("credentials").size());
        }
    }

    @Test void rejectsInvalidRequestsAndReportsLaunchFailures() throws Exception {
        var empty = new CopyOnWriteArrayList<StreamingCaptureProcess>();
        try (var bridge = new PacketBridge();
             var server = server(bridge, factory(empty));
             var client = HttpClient.newHttpClient()) {
            for (String body : new String[]{"null", "[]", "{", "{}", "{\"ssid\":42}", "{\"ssid\":\"\"}",
                    "{\"ssid\":\"lab\",\"channel\":0}", "{\"ssid\":\"lab\",\"portalPort\":0}",
                    "{\"ssid\":\"lab\",\"portalPort\":70000}", "{\"ssid\":\"lab\",\"interface\":\"a b\"}"})
                assertEquals(400, post(client, server, body).statusCode(), body);
            assertTrue(empty.isEmpty());
        }
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> new EvilTwin(settings.apInterface(), settings.ssid(),
                     settings.channel(), settings.portalPort(), directory.resolve("work").toString(),
                     directory.resolve("creds.txt").toString(), builder -> {
                         throw new IOException("hostapd is missing");
                     }));
             var client = HttpClient.newHttpClient()) {
            var failure = post(client, server, REQUEST);
            assertEquals(500, failure.statusCode());
            assertEquals("hostapd is missing", mapper.readTree(failure.body()).path("error").asText());
            assertFalse(mapper.readTree(get(client, server).body()).path("running").asBoolean());
        }
    }

    private Function<PassiveRfServer.EvilTwinSettings, EvilTwin> factory(List<StreamingCaptureProcess> processes) {
        return settings -> new EvilTwin(settings.apInterface(), settings.ssid(), settings.channel(),
                settings.portalPort(), directory.resolve("work").toString(), directory.resolve("creds.txt").toString(),
                builder -> {
                    var process = new StreamingCaptureProcess();
                    processes.add(process);
                    return process;
                });
    }

    private PassiveRfServer server(PacketBridge bridge,
                                   Function<PassiveRfServer.EvilTwinSettings, EvilTwin> evilTwinFactory) throws Exception {
        return new PassiveRfServer(bridge, true, FrameInjector::new, new LanScanner(),
                new WifiAccessPoints(directory.resolve("missing-aps")),
                settings -> { fail("handshake must not start"); return null; },
                settings -> { fail("PMKID must not start"); return null; } /* placeholder */,
                settings -> { fail("beacon must not start"); return null; },
                evilTwinFactory).start(0);
    }

    private static URI uri(PassiveRfServer server, String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, "/api/attack/evil-twin/status")).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String body) throws Exception {
        return post(client, server, "/api/attack/evil-twin", body);
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String path, String body)
            throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
