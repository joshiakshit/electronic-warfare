package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.BeaconFlood;
import ewave.active.FrameInjector;
import ewave.active.LanScanner;
import ewave.active.PmkidCapture;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.fixtures.CompletedProcess;
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
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class LabOpsRoutesTest {
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path directory;

    @Test void pmkidRouteRunsTheFullPipelineAndExposesItsStatus() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        Path words = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        try (var bridge = new PacketBridge();
             var server = server(bridge,
                     settings -> new PmkidCapture(settings.monitorInterface(), directory.resolve("captures").toString(),
                             pmkidStarter(commands)),
                     settings -> { fail("beacon must not start"); return null; });
             var client = HttpClient.newHttpClient()) {
            var response = post(client, server, "/api/attack/pmkid",
                    "{\"interface\":\"wlo1\",\"wordlistPath\":\"" + words + "\",\"durationSeconds\":1}");
            assertEquals(200, response.statusCode(), response.body());
            var result = mapper.readTree(response.body());
            assertTrue(result.path("captured").asBoolean());
            assertTrue(result.path("vulnerable").asBoolean());
            assertEquals("lab password", result.path("psk").asText());
            assertTrue(result.path("pcapngPath").asText().endsWith(".pcapng"));
            assertTrue(result.path("hashPath").asText().endsWith(".22000"));
            assertTrue(result.path("output").asText().contains("KEY FOUND!"));
            assertEquals(3, commands.size());

            var status = mapper.readTree(get(client, server, "/api/attack/pmkid/status").body());
            assertFalse(status.path("running").asBoolean());
            assertEquals("Complete", status.path("stage").asText());
        }
    }

    @Test void pmkidStatusAndStopTerminateTheLiveCapture() throws Exception {
        Path words = Files.writeString(directory.resolve("words.txt"), "word\n");
        var process = new StreamingCaptureProcess();
        var launched = new CountDownLatch(1);
        try (var bridge = new PacketBridge();
             var server = server(bridge,
                     settings -> new PmkidCapture(settings.monitorInterface(), directory.toString(), builder -> {
                         launched.countDown();
                         return process;
                     }),
                     settings -> { fail("beacon must not start"); return null; });
             var client = HttpClient.newHttpClient()) {
            var pending = client.sendAsync(request(server, "/api/attack/pmkid",
                    "{\"interface\":\"wlo1\",\"wordlistPath\":\"" + words + "\",\"durationSeconds\":5}"),
                    HttpResponse.BodyHandlers.ofString());
            assertTrue(launched.await(3, TimeUnit.SECONDS));
            var status = mapper.readTree(get(client, server, "/api/attack/pmkid/status").body());
            assertTrue(status.path("running").asBoolean());
            assertTrue(status.path("stage").asText().startsWith("Capturing PMKIDs"));
            assertEquals(200, post(client, server, "/api/attack/stop", "{}").statusCode());
            var stopped = pending.get(3, TimeUnit.SECONDS);
            assertEquals(409, stopped.statusCode(), stopped.body());
            assertTrue(mapper.readTree(stopped.body()).path("error").asText().contains("Stopped by request"));
            assertFalse(process.isAlive());
            assertFalse(mapper.readTree(get(client, server, "/api/attack/pmkid/status").body())
                    .path("running").asBoolean());
        }
    }

    @Test void beaconRouteStartsReportsAndStopsOneFloodAtATime() throws Exception {
        var process = new StreamingCaptureProcess();
        var commands = new CopyOnWriteArrayList<List<String>>();
        try (var bridge = new PacketBridge();
             var server = server(bridge,
                     settings -> { fail("PMKID must not start"); return null; },
                     settings -> new BeaconFlood(settings.monitorInterface(), builder -> {
                         commands.add(List.copyOf(builder.command()));
                         return process;
                     }));
             var client = HttpClient.newHttpClient()) {
            var started = post(client, server, "/api/attack/beacon",
                    "{\"interface\":\"wlo1\",\"ssid\":\"ewave-lab\",\"channel\":6,\"rate\":80}");
            assertEquals(200, started.statusCode(), started.body());
            var status = mapper.readTree(started.body());
            assertTrue(status.path("running").asBoolean());
            assertEquals("mdk4", status.path("tool").asText());
            assertEquals(List.of("sudo", "mdk4", "wlo1", "b", "-n", "ewave-lab", "-c", "6", "-s", "80"),
                    commands.getFirst());
            assertEquals(409, post(client, server, "/api/attack/beacon",
                    "{\"interface\":\"wlo1\",\"ssid\":\"second\",\"channel\":1}").statusCode());
            assertEquals(200, post(client, server, "/api/attack/stop", "{}").statusCode());
            assertFalse(process.isAlive());
            var stopped = mapper.readTree(get(client, server, "/api/attack/beacon/status").body());
            assertFalse(stopped.path("running").asBoolean());
        }
    }

    @Test void rejectsInvalidRequestsAndReportsMissingWordlistsBeforeLaunching() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        Path words = Files.writeString(directory.resolve("words.txt"), "word\n");
        try (var bridge = new PacketBridge();
             var server = server(bridge,
                     settings -> new PmkidCapture(settings.monitorInterface(), directory.toString(),
                             pmkidStarter(commands)),
                     settings -> new BeaconFlood(settings.monitorInterface(), builder -> {
                         commands.add(List.copyOf(builder.command()));
                         return new StreamingCaptureProcess();
                     }));
             var client = HttpClient.newHttpClient()) {
            for (String body : new String[]{"null", "[]", "{", "{}", "{\"wordlistPath\":42}",
                    "{\"wordlistPath\":\"" + words + "\",\"durationSeconds\":0}",
                    "{\"wordlistPath\":\"" + words + "\",\"durationSeconds\":301}",
                    "{\"wordlistPath\":\"" + words + "\",\"durationSeconds\":\"1\"}",
                    "{\"wordlistPath\":\"" + words + "\",\"interface\":\"a b\"}"})
                assertEquals(400, post(client, server, "/api/attack/pmkid", body).statusCode(), body);
            var missing = post(client, server, "/api/attack/pmkid",
                    "{\"wordlistPath\":\"" + directory.resolve("missing") + "\"}");
            assertEquals(404, missing.statusCode());
            assertEquals("Wordlist not found. Install: sudo dnf install wordlists",
                    mapper.readTree(missing.body()).path("error").asText());

            for (String body : new String[]{"null", "[]", "{", "{}", "{\"ssid\":42}",
                    "{\"ssid\":\"\"}", "{\"ssid\":\"lab\",\"channel\":0}", "{\"ssid\":\"lab\",\"channel\":234}",
                    "{\"ssid\":\"lab\",\"rate\":0}", "{\"ssid\":\"lab\",\"rate\":10001}",
                    "{\"ssid\":\"lab\",\"interface\":\"a b\"}"})
                assertEquals(400, post(client, server, "/api/attack/beacon", body).statusCode(), body);
            assertTrue(commands.isEmpty());
        }
    }

    @Test void pmkidRouteForwardsTargetBssidAndFrequencyAndRejectsInvalidScope() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        var capturedSettings = new AtomicReference<PassiveRfServer.PmkidSettings>();
        Path words = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        try (var bridge = new PacketBridge();
             var server = server(bridge,
                     settings -> {
                         capturedSettings.set(settings);
                         return new PmkidCapture(settings.monitorInterface(), settings.apBssid(),
                                 settings.frequencyMhz(), directory.resolve("captures").toString(),
                                 pmkidStarter(commands));
                     },
                     settings -> { fail("beacon must not start"); return null; });
             var client = HttpClient.newHttpClient()) {
            for (String body : new String[]{
                    "{\"wordlistPath\":\"" + words + "\",\"apBssid\":\"bad-mac\"}",
                    "{\"wordlistPath\":\"" + words + "\",\"frequencyMhz\":\"abc\"}",
                    "{\"wordlistPath\":\"" + words + "\",\"frequencyMhz\":1200}",
                    "{\"wordlistPath\":\"" + words + "\",\"apId\":\"ap-missing\"}"})
                assertEquals(400, post(client, server, "/api/ops/pmkid", body).statusCode(), body);

            var response = post(client, server, "/api/ops/pmkid",
                    "{\"interface\":\"wlo1\",\"wordlistPath\":\"" + words + "\",\"durationSeconds\":2,"
                            + "\"apBssid\":\"fc:69:0c:15:82:64\",\"frequencyMhz\":2437}");
            assertEquals(200, response.statusCode(), response.body());
            assertNotNull(capturedSettings.get());
            assertEquals("fc:69:0c:15:82:64", capturedSettings.get().apBssid());
            assertEquals(2437, capturedSettings.get().frequencyMhz());
            var json = mapper.readTree(response.body());
            assertEquals("fc:69:0c:15:82:64", json.path("targetApBssid").asText());
            assertEquals(2437, json.path("frequencyMhz").asInt());
            assertTrue(commands.stream().anyMatch(cmd -> cmd.size() > 1 && cmd.get(1).equals("hcxdumptool")
                    && cmd.contains("-f") && cmd.contains("2437")
                    && cmd.stream().anyMatch(arg -> arg.startsWith("--bpf="))));
        }
    }

    @Test void tracksOperationHistoryScopesStopByOperationIdAndClearsHistory() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        Path words = Files.writeString(directory.resolve("words.txt"), "lab password\n");
        try (var bridge = new PacketBridge();
             var server = server(bridge,
                     settings -> new PmkidCapture(settings.monitorInterface(), settings.apBssid(),
                             settings.frequencyMhz(), directory.resolve("captures").toString(),
                             pmkidStarter(commands)),
                     settings -> new BeaconFlood(settings.monitorInterface(), builder -> {
                         commands.add(List.copyOf(builder.command()));
                         return new StreamingCaptureProcess();
                     }));
             var client = HttpClient.newHttpClient()) {
            var pmkidResponse = post(client, server, "/api/ops/pmkid",
                    "{\"interface\":\"wlo1\",\"wordlistPath\":\"" + words + "\",\"durationSeconds\":1,"
                            + "\"apBssid\":\"fc:69:0c:15:82:64\"}");
            assertEquals(200, pmkidResponse.statusCode(), pmkidResponse.body());

            var started = post(client, server, "/api/ops/beacon",
                    "{\"interface\":\"wlo1\",\"ssid\":\"lab-net\",\"channel\":6,\"rate\":80}");
            assertEquals(200, started.statusCode(), started.body());

            var caps = mapper.readTree(get(client, server, "/api/ops/capabilities").body());
            assertEquals("beacon", caps.path("activeOperation").asText());
            String activeId = caps.path("activeOperationId").asText();
            assertNotNull(UUID.fromString(activeId));

            assertEquals(400, post(client, server, "/api/ops/stop", "{\"operationId\":\"not-a-uuid\"}").statusCode());
            var mismatch = post(client, server, "/api/ops/stop",
                    "{\"operationId\":\"" + UUID.randomUUID() + "\"}");
            assertEquals(409, mismatch.statusCode(), mismatch.body());
            assertEquals("beacon", mapper.readTree(get(client, server, "/api/ops/capabilities").body())
                    .path("activeOperation").asText());

            var stoppedMatch = post(client, server, "/api/ops/stop",
                    "{\"operationId\":\"" + activeId + "\"}");
            assertEquals(200, stoppedMatch.statusCode(), stoppedMatch.body());
            assertTrue(mapper.readTree(stoppedMatch.body()).path("stopped").asBoolean());

            var capsAfter = mapper.readTree(get(client, server, "/api/ops/capabilities").body());
            assertTrue(capsAfter.path("activeOperation").isNull());
            assertTrue(capsAfter.path("activeOperationId").isNull());

            var idleScopedStop = post(client, server, "/api/ops/stop",
                    "{\"operationId\":\"" + activeId + "\"}");
            assertEquals(200, idleScopedStop.statusCode());
            assertFalse(mapper.readTree(idleScopedStop.body()).path("stopped").asBoolean());
            assertTrue(mapper.readTree(post(client, server, "/api/ops/stop", "{}").body()).path("stopped").asBoolean());

            var historyResp = get(client, server, "/api/ops/history");
            assertEquals(200, historyResp.statusCode(), historyResp.body());
            assertFalse(historyResp.body().contains("lab password"));
            var history = mapper.readTree(historyResp.body());
            assertEquals(2, history.size());
            assertEquals("beacon", history.get(0).path("operation").asText());
            assertEquals("lab-net", history.get(0).path("target").asText());
            assertEquals("STOPPED", history.get(0).path("outcome").asText());
            assertEquals("pmkid", history.get(1).path("operation").asText());
            assertEquals("fc:69:0c:15:82:64", history.get(1).path("target").asText());
            assertEquals("PSK_FOUND", history.get(1).path("outcome").asText());

            var attackHistory = mapper.readTree(get(client, server, "/api/attack/history").body());
            assertEquals(2, attackHistory.size());

            var cleared = client.send(HttpRequest.newBuilder(uri(server, "/api/ops/history")).DELETE().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, cleared.statusCode());
            assertTrue(mapper.readTree(cleared.body()).path("cleared").asBoolean());
            assertEquals(0, mapper.readTree(get(client, server, "/api/ops/history").body()).size());
        }
    }

    private PassiveRfServer server(PacketBridge bridge,
                                   java.util.function.Function<PassiveRfServer.PmkidSettings, PmkidCapture> pmkid,
                                   java.util.function.Function<PassiveRfServer.BeaconSettings, BeaconFlood> beacon)
            throws Exception {
        return new PassiveRfServer(bridge, true, FrameInjector::new, new LanScanner(),
                new WifiAccessPoints(directory.resolve("missing-aps")),
                settings -> { fail("handshake must not start"); return null; }, pmkid, beacon).start(0);
    }

    private static PmkidCapture.ProcessStarter pmkidStarter(List<List<String>> commands) {
        return builder -> {
            var command = List.copyOf(builder.command());
            commands.add(command);
            if (command.getFirst().equals("hcxdumptool")
                    && command.stream().anyMatch(arg -> arg.startsWith("--bpfc="))) {
                return new CompletedProcess("2\n32 0 0 16\n6 0 0 65535\n", 0);
            }
            if (command.get(1).equals("hcxdumptool")) {
                Files.write(Path.of(command.get(command.indexOf("-w") + 1)), new byte[]{0x0a, 0x0d, 0x0d, 0x0a});
                return new CompletedProcess("capture\n", 0);
            }
            if (command.getFirst().equals("hcxpcapngtool")) {
                Files.writeString(Path.of(command.get(command.indexOf("-o") + 1)),
                        "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*"
                                + "686173686361742d6573736964***\n");
                return new CompletedProcess("converted\n", 0);
            }
            if (command.getFirst().equals("aircrack-ng"))
                return new CompletedProcess("KEY FOUND! [ lab password ]\n", 0);
            throw new IOException("Unexpected command: " + command);
        };
    }

    private static URI uri(PassiveRfServer server, String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, path)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest request(PassiveRfServer server, String path, String body) {
        return HttpRequest.newBuilder(uri(server, path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String path, String body)
            throws Exception {
        return client.send(request(server, path, body), HttpResponse.BodyHandlers.ofString());
    }
}
