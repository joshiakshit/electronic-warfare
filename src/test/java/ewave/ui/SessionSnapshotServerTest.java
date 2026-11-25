package ewave.ui;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ewave.capture.PacketBridge;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.decoder.Dot11InformationElements;
import ewave.passive.MyNetworkProfile;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class SessionSnapshotServerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String DIRECTORY = "rf.sessionDirectory";
    @TempDir Path temporary;
    private Path directory;
    private String oldDirectory;

    @BeforeEach void configureStorage() {
        directory = temporary.resolve("sessions");
        oldDirectory = System.setProperty(DIRECTORY, directory.toString());
    }

    @AfterEach void restoreProperties() {
        restore(DIRECTORY, oldDirectory);
    }

    @Test void restoresUnmaskedPassiveReportsAndExportsProbeEvidenceAfterRestart() throws Exception {
        try (var client = HttpClient.newHttpClient()) {
            String id;
            JsonNode probeEvidence;
            try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge, true).start(0)) {
                String url = "http://127.0.0.1:" + server.port();
                assertEquals(409, request(client, url + "/api/sessions", "POST", "{\"name\":\"Empty\"}").statusCode());
                replay(bridge);
                assertEquals(409, request(client, url + "/api/sessions", "POST",
                        "{\"name\":\"Stale\",\"sessionId\":\"stale\"}").statusCode());
                var saved = request(client, url + "/api/sessions", "POST", "{\"name\":\"Offline evidence\"}");
                assertEquals(201, saved.statusCode(), saved.body());
                id = JSON.readTree(saved.body()).path("id").asText();
                var snapshot = JSON.readTree(request(client, url + "/api/sessions/" + id, "GET", null).body());
                assertEquals(1, snapshot.path("version").asInt());
                assertEquals(7, snapshot.path("reports").size());
                probeEvidence = snapshot.at("/reports/decloaker");
                var live = JSON.readTree(request(client, url + "/api/decloaker", "GET", null).body());
                assertEquals(live, probeEvidence);
                assertEquals(live, JSON.readTree(request(client, url + "/api/probe-audit", "GET", null).body()));
                assertFullProbeEvidence(probeEvidence, bridge.getPassiveWifi().addressId("02:11:22:33:44:55"));
                assertTrue(snapshot.at("/reports/decloaker/totalProbes").asInt() > 0);
                assertTrue(snapshot.at("/reports/decloaker/corpus/0/name").isTextual());
                assertTrue(snapshot.at("/reports/profiler").isArray());
                assertTrue(snapshot.at("/reports/lookout").isNull());
                assertFalse(JSON.readTree(request(client, url + "/api/status", "GET", null).body())
                        .path("operationsEnabled").asBoolean());
            }

            try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0)) {
                String url = "http://127.0.0.1:" + server.port();
                String snapshotUrl = url + "/api/sessions/" + id;
                assertEquals(id, JSON.readTree(request(client, url + "/api/sessions", "GET", null).body())
                        .get(0).path("id").asText());
                var export = request(client, snapshotUrl + "?download=true", "GET", null);
                assertEquals(200, export.statusCode());
                assertEquals("no-store", export.headers().firstValue("Cache-Control").orElseThrow());
                assertTrue(export.headers().firstValue("Content-Disposition").orElseThrow().startsWith("attachment;"));
                var loaded = request(client, snapshotUrl, "GET", null);
                assertEquals(200, loaded.statusCode());
                assertEquals(probeEvidence, JSON.readTree(loaded.body()).at("/reports/decloaker"));
                assertEquals(probeEvidence, JSON.readTree(export.body()).at("/reports/decloaker"));
                assertNull(bridge.getPassiveWifi(), "Opening a saved report does not create a capture session");
                var foreign = HttpRequest.newBuilder(URI.create(snapshotUrl)).header("Origin", "http://example.test")
                        .DELETE().build();
                assertEquals(403, client.send(foreign, HttpResponse.BodyHandlers.discarding()).statusCode());
                assertEquals(200, request(client, snapshotUrl, "DELETE", null).statusCode());
                assertEquals(404, request(client, snapshotUrl, "GET", null).statusCode());
            }
        }
    }

    @Test void writesFullProbeEvidenceToPrivateSnapshotFiles() throws Exception {
        try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            replay(bridge);
            String url = "http://127.0.0.1:" + server.port();
            var saved = request(client, url + "/api/sessions", "POST", "{\"name\":\"Probe evidence\"}");
            assertEquals(201, saved.statusCode(), saved.body());
            String id = JSON.readTree(saved.body()).path("id").asText();
            var stored = JSON.readTree(directory.resolve(id + ".json").toFile());
            assertFullProbeEvidence(stored.at("/reports/decloaker"),
                    bridge.getPassiveWifi().addressId("02:11:22:33:44:55"));
            assertEquals(List.of("id", "name", "savedAt", "sessionId", "version", "reports"),
                    java.util.stream.StreamSupport.stream(
                            java.util.Spliterators.spliteratorUnknownSize(stored.fieldNames(), 0), false).toList());
        }
    }

    @Test void includesTokenizedSpotterEvidenceInBothReportsAndTheSavedSnapshot() throws Exception {
        try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            replay(bridge);
            var session = bridge.getPassiveWifi();
            long time = bridge.getCaptureHealth().referenceTime();
            String parent = "00:12:23:34:45:ae", child = "00:12:23:34:45:af";
            String station = "02:67:78:89:aa:bb", peer = "00:de:ad:be:ef:02", mld = "00:ab:cd:ef:12:23";
            session.configure(new MyNetworkProfile(List.of(),
                    List.of(new MyNetworkProfile.Entry(UUID.randomUUID(), station, "Lab phone")), false));
            byte[] profile = {2, 0, 6, 85, 1, 1, 0, 1, 'G'};
            byte[] multiLink = java.util.HexFormat.of().parseHex("6b000007" + mld.replace(":", ""));
            var ies = new Dot11InformationElements(List.of(new Dot11InformationElements.Element(71, profile),
                    new Dot11InformationElements.Element(255, multiLink)));
            session.observe(new Dot11Frame(0, 8, 0, 0, -1, "ff:ff:ff:ff:ff:ff", parent, parent, null,
                    time, 5975, -52, null, 0, ies, 0L, 100, 1, null, -1, -1));
            session.observe(new Dot11Frame(0, 1, 0, 0, -1, station, child, child, null,
                    time, 5975, -52, null, 0, new Dot11InformationElements(List.of()), null, 0, 0, null, 0, -1));
            session.observe(new Dot11Frame(2, 0, 3, 0, -1, parent, peer, child, station,
                    time, 5975, -52, null, 30, null, null, 0, 0, null, -1, -1));
            var emptyIes = new Dot11InformationElements(List.of());
            session.observe(new Dot11Frame(0, 13, 0, 16, -1, station, child, child, null,
                    time, 5975, -52, null, 40, emptyIes, null, 0, 0, parent, 0, Dot11FrameDecoder.FT_ACTION_RESPONSE));
            session.observe(new Dot11Frame(0, 13, 0, 32, -1, child, station, child, null,
                    time, 5975, -62, null, 29, emptyIes, null, 0, 0, null, 7, Dot11FrameDecoder.BTM_ACTION_RESPONSE));

            String url = "http://127.0.0.1:" + server.port();
            var spotter = JSON.readTree(request(client, url + "/api/spotter", "GET", null).body());
            var topology = JSON.readTree(request(client, url + "/api/topology", "GET", null).body());
            assertEquals(spotter.path("meshLinks"), topology.path("meshLinks"));
            assertEquals(1, spotter.path("meshLinks").size());
            assertEquals(5975, spotter.at("/meshLinks/0/frequencyMhz").asInt());
            assertEquals("ACTIVE", spotter.at("/edges/0/state").asText());
            assertEquals(session.addressId(station), spotter.at("/edges/0/clientId").asText());
            assertEquals(session.addressId(child), spotter.at("/edges/0/bssid").asText());
            assertTrue(spotter.path("accessPoints").findValues("nonTransmitted").stream().anyMatch(node -> node.asBoolean()));
            assertTrue(spotter.path("accessPoints").findValues("mldId").stream().anyMatch(node -> node.isTextual()));

            String stationId = session.addressId(station);
            var tracker = JSON.readTree(request(client, url + "/api/tracker", "GET", null).body());
            assertEquals(spotter.path("accessPoints"), tracker.path("accessPoints"));
            assertEquals("FT_OVER_DS", tracker.at("/roams/0/method").asText());
            assertEquals(session.addressId(parent), tracker.at("/roams/0/toBssid").asText());
            assertEquals(stationId, tracker.at("/btmRejections/0/clientId").asText());
            assertEquals(session.addressId(child), tracker.at("/btmRejections/0/apId").asText());
            assertEquals(7, tracker.at("/btmRejections/0/statusCode").asInt());
            assertTrue(tracker.path("devices").findValues("enrolledLabel").stream()
                    .anyMatch(label -> "Lab phone".equals(label.asText())));
            var profiler = JSON.readTree(request(client, url + "/api/profiler", "GET", null).body());
            var detail = JSON.readTree(request(client, url + "/api/profiler/" + stationId, "GET", null).body());
            assertEquals(session.addressId(child), detail.at("/associatedAp/apId").asText());
            assertEquals(5975, detail.at("/associatedAp/frequencyMhz").asInt());
            assertEquals("ASSOC", detail.at("/associatedAp/source").asText());

            var saved = request(client, url + "/api/sessions", "POST", "{\"name\":\"Spotter evidence\"}");
            assertEquals(201, saved.statusCode(), saved.body());
            String id = JSON.readTree(saved.body()).path("id").asText();
            var stored = JSON.readTree(directory.resolve(id + ".json").toFile());
            assertEquals(1, stored.path("version").asInt());
            assertEquals(spotter, stored.at("/reports/spotter"));
            assertEquals(tracker, stored.at("/reports/tracker"));
            assertEquals(profiler, stored.at("/reports/profiler"));

            for (var report : List.of(spotter, topology, tracker, profiler, detail, stored)) {
                for (String address : List.of(parent, child, station, peer, mld)) {
                    assertFalse(report.toString().contains(address));
                }
            }
        }
    }

    @Test void preservesWhistleblowerEvidenceAndTokenizedOwePeersInVersionOneSnapshots() throws Exception {
        try (var bridge = new PacketBridge(); var server = new PassiveRfServer(bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            replay(bridge);
            var session = bridge.getPassiveWifi();
            long time = bridge.getCaptureHealth().referenceTime();
            String hidden = "00:12:23:34:45:ae", peer = "00:12:23:34:45:af";
            byte[] transition = java.util.HexFormat.of().parseHex("506f9a1c0012233445af034c6162");
            var ies = new Dot11InformationElements(List.of(new Dot11InformationElements.Element(0, new byte[3]),
                    new Dot11InformationElements.Element(221, transition)));
            session.observe(new Dot11Frame(0, 8, 0, 0, -1, "ff:ff:ff:ff:ff:ff", hidden, hidden, null,
                    time, 5975, -52, null, 0, ies, 0L, 100, 1, null, -1, -1));

            String url = "http://127.0.0.1:" + server.port();
            var response = request(client, url + "/api/whistleblower", "GET", null);
            assertEquals(200, response.statusCode());
            var report = JSON.readTree(response.body());
            assertEquals(1, report.path("revealedCount").asInt());
            var ap = report.at("/accessPoints/0");
            assertEquals(session.addressId(hidden), ap.path("bssid").asText());
            assertEquals(session.addressId(peer), ap.path("owePeerBssid").asText());
            assertEquals("AP_AUTHORITATIVE", ap.path("revealConfidence").asText());
            assertEquals("NULL_PADDED", ap.path("concealmentMode").asText());
            assertEquals(3, ap.path("maskedSsidLength").asInt());
            var evidence = ap.path("hiddenSsidEvidence");
            assertEquals(4, evidence.size());
            assertEquals("Lab", evidence.path("name").asText());
            assertEquals("OWE_TRANSITION", evidence.path("source").asText());

            var saved = request(client, url + "/api/sessions", "POST", "{\"name\":\"Whistleblower evidence\"}");
            assertEquals(201, saved.statusCode(), saved.body());
            String id = JSON.readTree(saved.body()).path("id").asText();
            var snapshot = JSON.readTree(request(client, url + "/api/sessions/" + id, "GET", null).body());
            assertEquals(1, snapshot.path("version").asInt());
            assertEquals(report, snapshot.at("/reports/whistleblower"));
            for (String address : List.of(hidden, peer)) {
                assertFalse(response.body().contains(address));
                assertFalse(snapshot.toString().contains(address));
            }
        }
    }

    @Test void skipsCorruptAndLinkedFilesAndEnforcesPrivatePermissions() throws Exception {
        var store = new SessionSnapshotStore(JSON);
        var entry = store.save("Valid", UUID.randomUUID(), reports());
        Path valid = directory.resolve(entry.id() + ".json");
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(directory));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(valid));

        UUID corruptId = UUID.randomUUID();
        Path corrupt = privateFile(corruptId);
        Files.writeString(corrupt, "{broken");
        UUID symbolicId = UUID.randomUUID();
        Files.createSymbolicLink(directory.resolve(symbolicId + ".json"), valid);
        UUID hardId = UUID.randomUUID();
        Path outside = Files.copy(valid, temporary.resolve("outside.json"));
        Files.createLink(directory.resolve(hardId + ".json"), outside);
        assertEquals(List.of(entry), store.list());
        assertNull(store.load(corruptId));
        assertTrue(store.delete(corruptId));
        assertFalse(store.delete(symbolicId));
        assertFalse(store.delete(hardId));

        Path alias = Files.createSymbolicLink(temporary.resolve("alias"), directory);
        System.setProperty(DIRECTORY, alias.toString());
        assertThrows(java.io.IOException.class, () -> new SessionSnapshotStore(JSON).list());
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-xr-x"));
        assertThrows(java.io.IOException.class, store::list);
    }

    @Test void limitsSnapshotSizeAndCountWithoutPublishingIncompleteFiles() throws Exception {
        var store = new SessionSnapshotStore(JSON);
        var session = UUID.randomUUID();
        var oversized = reports().put("extra", "x".repeat(SessionSnapshotStore.MAX_BYTES));
        assertThrows(SessionSnapshotStore.Limit.class, () -> store.save("Oversized", session, oversized));
        try (var files = Files.list(directory)) {
            assertEquals(List.of(".save.lock"), files.map(path -> path.getFileName().toString()).toList());
        }
        for (int i = 0; i < SessionSnapshotStore.MAX_SNAPSHOTS; i++) store.save("Snapshot " + i, session, reports());
        assertEquals(SessionSnapshotStore.MAX_SNAPSHOTS, store.list().size());
        assertThrows(SessionSnapshotStore.Limit.class, () -> store.save("Library full", session, reports()));
    }

    private static void assertFullProbeEvidence(JsonNode audit, String deviceId) {
        var corpus = audit.path("corpus");
        assertFalse(corpus.isEmpty());
        corpus.forEach(row -> {
            assertTrue(row.path("name").isTextual());
            assertEquals(1, row.path("deviceCount").asInt());
            assertEquals(deviceId, row.at("/devices/0/id").asText());
            assertTrue(java.util.stream.StreamSupport.stream(audit.path("ssidTokens").path(row.path("exposure").asText()).spliterator(), false)
                    .anyMatch(name -> name.equals(row.path("name"))));
        });
        assertFalse(audit.toString().contains("02:11:22:33:44:55"));
    }

    private Path privateFile(UUID id) throws Exception {
        return Files.createFile(directory.resolve(id + ".json"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    }

    private static ObjectNode reports() {
        var reports = JSON.createObjectNode();
        reports.putObject("spotter").putArray("accessPoints");
        ((ObjectNode) reports.path("spotter")).putArray("edges");
        reports.putObject("whistleblower").putArray("accessPoints");
        reports.putObject("decloaker").putArray("corpus");
        reports.putObject("inspector").putArray("accessPoints");
        reports.putArray("profiler");
        reports.putObject("tracker").putArray("roams");
        reports.putNull("lookout");
        return reports;
    }

    private static void replay(PacketBridge bridge) throws Exception {
        bridge.startReplay(Path.of("src/test/resources/probes/probe-requests.pcap"));
        long deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos();
        while (bridge.isRunning() && System.nanoTime() < deadline) Thread.sleep(10);
        assertEquals("COMPLETE", bridge.getCaptureStatus().get("replayState"));
    }

    private static HttpResponse<String> request(HttpClient client, String url, String method, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/json").method(method,
                        body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void restore(String property, String value) {
        if (value == null) System.clearProperty(property);
        else System.setProperty(property, value);
    }
}
