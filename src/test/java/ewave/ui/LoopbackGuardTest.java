package ewave.ui;

import ewave.capture.PacketBridge;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LoopbackGuardTest {
    @Test void acceptsOnlyLoopbackHostsAndSameOriginFetches() {
        for (String host : List.of("localhost:5174", "127.0.0.1:7070", "[::1]:7070", "[::1]")) {
            assertTrue(PassiveRfServer.isLocal(host, null, null));
            assertTrue(PassiveRfServer.isLocal(host, "http://" + host, "same-origin"));
            assertTrue(PassiveRfServer.isLocal(host, null, "none"));
            assertFalse(PassiveRfServer.isLocal(host, null, "cross-site"));
            assertFalse(PassiveRfServer.isLocal(host, null, "same-site"));
            assertFalse(PassiveRfServer.isLocal(host, "null", null));
            assertFalse(PassiveRfServer.isLocal(host, "http://foreign.example", null));
        }
        for (String host : List.of("localhost.evil.test", "[::2]", "192.168.1.1", "localhost@evil.test"))
            assertFalse(PassiveRfServer.isLocal(host, null, null));
        assertFalse(PassiveRfServer.isLocal(null, null, null));
    }

    @Test void rejectsSimplePostsAndOriginlessCrossSiteRequestsBeforeMutation() throws Exception {
        try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge, true).start(0);
             var client = HttpClient.newHttpClient()) {
            String base = "http://127.0.0.1:" + server.port();
            for (String route : List.of("/api/capture/stop", "/api/ops/stop", "/api/sniper", "/api/my-network")) {
                for (String type : List.of("", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data")) {
                    var request = HttpRequest.newBuilder(URI.create(base + route));
                    if (!type.isEmpty()) request.header("Content-Type", type);
                    var response = client.send(request.POST(HttpRequest.BodyPublishers.ofString("{}")).build(),
                            HttpResponse.BodyHandlers.ofString());
                    assertEquals(415, response.statusCode(), route + " " + type);
                }
            }
            var crossSite = HttpRequest.newBuilder(URI.create(base + "/api/capture/stop"))
                    .header("Sec-Fetch-Site", "cross-site").header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build();
            assertEquals(403, client.send(crossSite, HttpResponse.BodyHandlers.ofString()).statusCode());
            var allowed = HttpRequest.newBuilder(URI.create(base + "/api/ops/stop"))
                    .header("Sec-Fetch-Site", "same-origin").header("Origin", base)
                    .header("Content-Type", "application/json; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build();
            assertEquals(200, client.send(allowed, HttpResponse.BodyHandlers.ofString()).statusCode());
            var upload = HttpRequest.newBuilder(URI.create(base + "/api/recordings?name=fixture.pcap"))
                    .header("Content-Type", "text/plain").POST(HttpRequest.BodyPublishers.ofString("{}")).build();
            assertEquals(415, client.send(upload, HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }
}
