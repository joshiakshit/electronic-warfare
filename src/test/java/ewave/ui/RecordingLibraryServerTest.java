package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.capture.PacketBridge;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.io.ByteArrayInputStream;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.*;

class RecordingLibraryServerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    @TempDir Path directory;

    @Test
    void browsableRecordingSurvivesRestartAndReplaysThroughThePassiveReports() throws Exception {
        String property = "rf.recordingDirectory";
        String previous = System.setProperty(property, directory.toString());
        try (var client = HttpClient.newHttpClient()) {
            byte[] pcap = Files.readAllBytes(Path.of("src/test/resources/probes/probe-requests.pcap"));
            String id;
            try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0)) {
                String base = base(server);
                assertEquals(0, JSON.readTree(get(client, base + "/api/recordings").body()).size());
                assertEquals(403, upload(client, base, "foreign.pcap", pcap, "http://other.test").statusCode());
                assertEquals(400, upload(client, base, "..%2Foutside.pcap", pcap, base).statusCode());
                assertEquals(400, upload(client, base, "invalid.pcap", new byte[24], base).statusCode());
                assertEquals(0, JSON.readTree(get(client, base + "/api/recordings").body()).size());
                try (var files = Files.list(directory)) {
                    assertEquals(0, files.count(), "Rejected imports must not leave a staging directory");
                }

                var imported = upload(client, base, "Probe%20sample.pcap", pcap, base);
                assertEquals(201, imported.statusCode(), imported.body());
                var item = JSON.readTree(imported.body());
                id = item.path("id").asText();
                assertEquals("Probe sample.pcap", item.path("name").asText());
                assertEquals(pcap.length, item.path("bytes").asInt());
                assertFalse(item.has("path"));
                assertFalse(bridge.isRunning(), "Import is separate from replay");
            }

            try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0)) {
                String base = base(server);
                assertEquals(id, JSON.readTree(get(client, base + "/api/recordings").body()).get(0).path("id").asText());
                var replay = post(client, base + "/api/recordings/" + id + "/replay");
                assertEquals(200, replay.statusCode(), replay.body());
                var status = JSON.readTree(replay.body());
                assertEquals(id, status.path("recordingId").asText());
                assertEquals("Probe sample.pcap", status.path("captureSource").asText());
                assertFalse(status.path("sessionId").asText().isBlank());
                assertTrue(status.path("captureStartedAt").asLong() > 0);
                long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
                while (bridge.isRunning() && System.nanoTime() < deadline) Thread.sleep(10);
                var health = JSON.readTree(get(client, base + "/api/capture/health").body());
                assertEquals("COMPLETE", health.path("replayState").asText());
                var probes = JSON.readTree(get(client, base + "/api/decloaker").body());
                assertTrue(probes.path("totalProbes").asInt() > 0);
                assertEquals(400, post(client, base + "/api/recordings/not-a-uuid/replay").statusCode());
                assertEquals(404, post(client, base + "/api/recordings/00000000-0000-0000-0000-000000000000/replay").statusCode());
            }
        } finally {
            if (previous == null) System.clearProperty(property);
            else System.setProperty(property, previous);
        }
    }

    @Test void defaultLibraryIsSharedBetweenElevatedAndNormalUserHomes() throws Exception {
        String oldHome = System.getProperty("user.home");
        String oldOperatorHome = System.getProperty("rf.userHome");
        String oldLibrary = System.getProperty("rf.recordingDirectory");
        Path operator = Files.createDirectory(directory.resolve("operator"));
        Path root = Files.createDirectory(directory.resolve("root"));
        try {
            System.clearProperty("rf.recordingDirectory");
            System.setProperty("user.home", root.toString());
            System.setProperty("rf.userHome", operator.toString());
            var elevated = new RecordingLibrary(JSON);
            var imported = elevated.add("fixture.pcap", new ByteArrayInputStream(
                    Files.readAllBytes(Path.of("src/test/resources/probes/probe-requests.pcap"))));
            Path recording = operator.resolve(".local/share/ewave/recordings").resolve(imported.id().toString());
            assertTrue(Files.isDirectory(recording));
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(recording));
            assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(recording.resolve("capture.pcap")));
            assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(recording.resolve("recording.json")));
            assertFalse(Files.exists(root.resolve(".local")));
            System.setProperty("user.home", operator.toString());
            System.clearProperty("rf.userHome");
            var normal = new RecordingLibrary(JSON);
            assertEquals(imported, normal.find(imported.id()));
            assertEquals(imported, normal.recordings().getFirst());
            assertArrayEquals(Files.readAllBytes(elevated.file(imported.id())),
                    Files.readAllBytes(normal.file(imported.id())));
        } finally {
            if (oldHome == null) System.clearProperty("user.home"); else System.setProperty("user.home", oldHome);
            if (oldOperatorHome == null) System.clearProperty("rf.userHome"); else System.setProperty("rf.userHome", oldOperatorHome);
            if (oldLibrary == null) System.clearProperty("rf.recordingDirectory"); else System.setProperty("rf.recordingDirectory", oldLibrary);
        }
    }

    @Test void corruptMetadataDoesNotHideValidRecordingsOrBreakReplay() throws Exception {
        String previous = System.setProperty("rf.recordingDirectory", directory.toString());
        try (var client = HttpClient.newHttpClient()) {
            var library = new RecordingLibrary(JSON);
            var valid = library.add("valid.pcap", new ByteArrayInputStream(
                    Files.readAllBytes(Path.of("src/test/resources/probes/probe-requests.pcap"))));
            for (String metadata : new String[]{"{broken", "", "{\"id\":\"not-a-uuid\"}"}) {
                Path corrupt = Files.createDirectory(directory.resolve(java.util.UUID.randomUUID().toString()));
                Files.writeString(corrupt.resolve("recording.json"), metadata);
                Files.copy(library.file(valid.id()), corrupt.resolve("capture.pcap"));
            }
            try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0)) {
                var response = get(client, base(server) + "/api/recordings");
                assertEquals(200, response.statusCode(), response.body());
                var rows = JSON.readTree(response.body());
                assertEquals(1, rows.size());
                assertEquals(valid.id().toString(), rows.get(0).path("id").asText());
                assertEquals(200, post(client, base(server) + "/api/recordings/" + valid.id() + "/replay").statusCode());
            }
        } finally {
            if (previous == null) System.clearProperty("rf.recordingDirectory");
            else System.setProperty("rf.recordingDirectory", previous);
        }
    }

    private static String base(PassiveRfServer server) {
        return "http://127.0.0.1:" + server.port();
    }

    private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> upload(HttpClient client, String base, String name, byte[] data, String origin)
            throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(base + "/api/recordings?name=" + name))
                .header("Content-Type", "application/octet-stream").header("Origin", origin)
                .POST(HttpRequest.BodyPublishers.ofByteArray(data)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
