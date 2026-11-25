package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.FrameInjector;
import ewave.active.HandshakeAnalyzer;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.fixtures.CompletedProcess;
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
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class HandshakeRoutesTest {
    private static final String AP = "02:11:22:33:44:55";
    private static final String CAPTURE = "{\"apBssid\":\"" + AP + "\",\"channel\":6,\"interface\":\"wlo1\"}";
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path directory;

    private PassiveRfServer server(PacketBridge bridge,
                                 Function<PassiveRfServer.HandshakeSettings, HandshakeAnalyzer> factory) throws Exception {
        Path aps = Files.writeString(directory.resolve("aps.txt"), "Lab AP:02\\:11\\:22\\:33\\:44\\:55:6:2437 MHz\n");
        return new PassiveRfServer(bridge, true, FrameInjector::new, new LanScanner(),
                new WifiAccessPoints(aps), factory).start(0);
    }

    private HandshakeAnalyzer analyzer(PassiveRfServer.HandshakeSettings settings, HandshakeAnalyzer.ProcessStarter starter) {
        return new HandshakeAnalyzer(settings.monitorInterface(), settings.apBssid(), settings.clientMac(), settings.channel(),
                settings.frequencyMhz(), directory.resolve("captures").toString(),
                builder -> builder.command().contains("iw") ? new CompletedProcess("", 0) : starter.start(builder));
    }

    @Test void returnsCaptureAndVerificationRecordsWithIsoTimestampsAndFullOutput() throws Exception {
        var verificationOutput = new AtomicReference<>("KEY FOUND! [ lab password ]\n");
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> analyzer(settings, builder -> {
                 if (builder.command().getFirst().equals("tshark")) {
                     Files.writeString(Path.of(builder.command().get(builder.command().indexOf("-w") + 1)),
                             "synthetic capture header and payload");
                     return new CompletedProcess(completeExchange(), 0);
                 }
                 if (builder.command().contains("tcpdump")) {
                     return new CompletedProcess(java.util.HexFormat.of().parseHex("d4c3b2a1020004000000000000000000000004007f000000"), 0);
                 }
                 return new CompletedProcess(verificationOutput.get(), verificationOutput.get().contains("FOUND!") ? 0 : 1);
             })); var client = HttpClient.newHttpClient()) {
            var capture = post(client, server, "/api/attack/handshake", CAPTURE.replace(",\"interface\":\"wlo1\"", ""));
            assertEquals(200, capture.statusCode(), capture.body());
            var result = mapper.readTree(capture.body());
            assertTrue(result.path("handshakeDetected").asBoolean());
            assertEquals("02:11:22:33:44:66", result.path("clientMac").asText());
            assertEquals(2437, result.path("frequencyMhz").asInt());
            assertEquals("COMPLETE", result.path("outcome").asText());
            assertEquals("[1,2,3,4]", result.path("messages").toString());
            assertEquals(AP, result.path("apBssid").asText());
            assertNotNull(Instant.parse(result.path("timestamp").asText()));
            var words = Files.writeString(directory.resolve("wordlist.txt"), "lab password");
            var request = mapper.createObjectNode().put("capFilePath", result.path("capFilePath").asText()).put("wordlistPath", words.toString());
            for (boolean found : new boolean[]{true, false}) {
                if (!found) verificationOutput.set("KEY NOT FOUND\n");
                var response = post(client, server, "/api/attack/handshake/verify", request.toString());
                assertEquals(200, response.statusCode(), response.body());
                var verified = mapper.readTree(response.body());
                assertEquals(4, verified.size());
                assertEquals(found, verified.path("vulnerable").asBoolean());
                if (found) assertEquals("lab password", verified.path("psk").asText());
                else assertTrue(verified.path("psk").isNull());
                assertEquals(verificationOutput.get(), verified.path("fullOutput").asText());
                assertNotNull(Instant.parse(verified.path("timestamp").asText()));
                assertEquals(found ? "PSK found" : "Key not found", mapper.readTree(
                        get(client, server, "/api/attack/handshake/status").body()).path("stage").asText());
            }
        }
    }

    @Test void rejectsInvalidJsonAndFilesWithoutLaunchingAndReturnsExactWordlistHint() throws Exception {
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> analyzer(settings, builder -> {
                 fail("invalid request must not launch"); return null;
             })); var client = HttpClient.newHttpClient()) {
            for (String body : new String[]{"{", "[]", "null", "{}", CAPTURE + " {}", CAPTURE.replace(AP, "--help"),
                    CAPTURE.replace("6", "234"), CAPTURE.replace("6", "true"),
                    CAPTURE.replace("6", "\"6\""), CAPTURE.replace("6", "1.5"), CAPTURE.replace("6", "2147483648"),
                    CAPTURE.replace("wlo1", "--help"), CAPTURE.replace("wlo1", "a b"),
                    CAPTURE.replace("}", ",\"clientMac\":42}"), CAPTURE.replace("}", ",\"clientMac\":\"bad\"}")}) {
                var response = post(client, server, "/api/attack/handshake", body);
                assertEquals(400, response.statusCode(), body + response.body());
            }
            for (String body : new String[]{"null", "[]", "{", "{}", "{\"capFilePath\":42,\"wordlistPath\":true}"})
                assertEquals(400, post(client, server, "/api/attack/handshake/verify", body).statusCode());
            var request = mapper.createObjectNode().put("capFilePath", "/missing.cap").put("wordlistPath", directory.resolve("missing").toString());
            var response = post(client, server, "/api/attack/handshake/verify", request.toString());
            assertEquals(404, response.statusCode());
            assertEquals(HandshakeAnalyzer.WORDLIST_MISSING, mapper.readTree(response.body()).path("error").asText());
            request.put("wordlistPath", Files.writeString(directory.resolve("words"), "words").toString());
            assertEquals(404, post(client, server, "/api/attack/handshake/verify", request.toString()).statusCode());
        }
    }

    @Test void passesTargetNameResolvesMissingChannelsFromEvidenceAndRejectsNonpositiveChannels() throws Exception {
        var selected = new AtomicReference<PassiveRfServer.HandshakeSettings>();
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> {
                 selected.set(settings);
                 return analyzer(settings, builder -> { throw new java.io.IOException("capture fixture unavailable"); });
             }); var client = HttpClient.newHttpClient()) {
            for (String channel : new String[]{"0", "-1"})
                assertEquals(400, post(client, server, "/api/attack/handshake", CAPTURE.replace("\"channel\":6", "\"channel\":" + channel)).statusCode());
            for (String channel : new String[]{"null", "missing"}) {
                String body = channel.equals("missing") ? CAPTURE.replace("\"channel\":6,", "")
                        : CAPTURE.replace("\"channel\":6", "\"channel\":" + channel);
                assertEquals(500, post(client, server, "/api/attack/handshake", body).statusCode());
                assertEquals(6, selected.get().channel());
                assertEquals("Lab AP", selected.get().ssid());
                assertEquals(2437, selected.get().frequencyMhz());
            }
            String body = CAPTURE.replace("}", ",\"ssid\":\"Selected network\"}");
            assertEquals(500, post(client, server, "/api/attack/handshake", body).statusCode());
            assertEquals("Selected network", selected.get().ssid());
            assertEquals(400, post(client, server, "/api/attack/handshake",
                    CAPTURE.replace("}", ",\"frequencyMhz\":2417}")).statusCode());
            assertEquals(400, post(client, server, "/api/attack/handshake", CAPTURE.replace("}", ",\"ssid\":42}")).statusCode());
        }
    }

    @Test void exposesLiveStagesRejectsOverlappingInjectionAndSupportsStopAndShutdown() throws Exception {
        for (boolean shutdown : new boolean[]{false, true}) {
            var dump = new StreamingCaptureProcess();
            var decoder = new StreamingCaptureProcess();
            var launched = new CountDownLatch(1);
            try (var bridge = new PacketBridge();
                 var server = server(bridge, settings -> analyzer(settings, builder -> {
                     if (builder.command().getFirst().equals("tshark")) return decoder;
                     launched.countDown();
                     return dump;
                 })); var client = HttpClient.newHttpClient()) {
                var pending = client.sendAsync(request(server, "/api/attack/handshake", CAPTURE), HttpResponse.BodyHandlers.ofString());
                assertTrue(launched.await(3, TimeUnit.SECONDS));
                var status = client.send(HttpRequest.newBuilder(uri(server, "/api/attack/handshake/status")).build(), HttpResponse.BodyHandlers.ofString());
                assertTrue(mapper.readTree(status.body()).path("running").asBoolean());
                assertTrue(mapper.readTree(status.body()).path("stage").asText().startsWith("Waiting for target AP beacon"));
                assertEquals(409, post(client, server, "/api/attack/handshake", CAPTURE).statusCode());
                assertEquals(409, post(client, server, "/api/attack/deauth", CAPTURE.replace("\"channel\":6", "\"count\":10")).statusCode());
                if (shutdown) server.stop();
                else {
                    assertEquals(200, post(client, server, "/api/attack/stop", "{}").statusCode());
                    var stopped = pending.get(3, TimeUnit.SECONDS);
                    assertEquals(409, stopped.statusCode(), stopped.body());
                    assertTrue(mapper.readTree(stopped.body()).path("error").asText().contains("Stopped by request"));
                }
                assertFalse(dump.isAlive());
                assertFalse(decoder.isAlive());
            }
        }
    }

    @Test void reportsToolErrorsAsJsonInsteadOfSuccessfulDictionaryMisses() throws Exception {
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> analyzer(settings, builder -> {
                 if (builder.command().getFirst().equals("tshark")) throw new java.io.IOException("tshark missing");
                 return new CompletedProcess("No valid WPA handshakes found.", 1);
             })); var client = HttpClient.newHttpClient()) {
            var capture = post(client, server, "/api/attack/handshake", CAPTURE);
            assertEquals(500, capture.statusCode());
            assertTrue(mapper.readTree(capture.body()).path("error").asText().contains("tshark missing"));
            var request = mapper.createObjectNode().put("capFilePath", Files.writeString(directory.resolve("invalid.cap"), "bad").toString())
                    .put("wordlistPath", Files.writeString(directory.resolve("words"), "word").toString());
            request.put("apBssid", AP);
            var verify = post(client, server, "/api/attack/handshake/verify", request.toString());
            assertEquals(500, verify.statusCode());
            assertTrue(mapper.readTree(verify.body()).path("error").asText().contains("No valid WPA handshakes"));
        }
    }

    @Test void forwardsAllowMacRotationFlagAndRejectsNonBooleanValues() throws Exception {
        var captured = new AtomicReference<PassiveRfServer.HandshakeSettings>();
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> {
                 captured.set(settings);
                 return new HandshakeAnalyzer(settings.monitorInterface(), settings.apBssid(), settings.clientMac(),
                         settings.channel(), settings.frequencyMhz(), directory.resolve("captures").toString(),
                         builder -> {
                             if (builder.command().contains("iw")) return new CompletedProcess("", 0);
                             if (builder.command().getFirst().equals("tshark")) {
                                 Files.writeString(Path.of(builder.command().get(builder.command().indexOf("-w") + 1)),
                                         "synthetic capture header and payload");
                                 return new CompletedProcess(completeExchange(), 0);
                             }
                             if (builder.command().contains("tcpdump")) {
                                 return new CompletedProcess(java.util.HexFormat.of().parseHex("d4c3b2a1020004000000000000000000000004007f000000"), 0);
                             }
                             return new CompletedProcess("", 0);
                         }, settings.allowMacRotation());
             });
             var client = HttpClient.newHttpClient()) {
            assertEquals(400, post(client, server, "/api/ops/handshake",
                    "{\"apBssid\":\"" + AP + "\",\"channel\":6,\"allowMacRotation\":\"yes\"}").statusCode());
            var response = post(client, server, "/api/ops/handshake",
                    "{\"apBssid\":\"" + AP + "\",\"clientMac\":\"02:11:22:33:44:99\",\"channel\":6,"
                            + "\"interface\":\"wlo1\",\"allowMacRotation\":true}");
            assertEquals(200, response.statusCode(), response.body());
            assertTrue(captured.get().allowMacRotation());
            assertTrue(mapper.readTree(response.body()).path("handshakeDetected").asBoolean());
            assertEquals("02:11:22:33:44:66", mapper.readTree(response.body()).path("clientMac").asText());
        }
    }

    @Test void forwardsTimeoutSupportsEarlyFinishAndSavesVerifiedRecording() throws Exception {
        var capturedSettings = new AtomicReference<PassiveRfServer.HandshakeSettings>();
        byte[] validCapHeader = java.util.HexFormat.of().parseHex("d4c3b2a1020004000000000000000000000004007f000000");
        byte[] radiotapBeacon = new byte[13 + 38];
        java.nio.ByteBuffer.wrap(radiotapBeacon).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .put((byte) 0).put((byte) 0).putShort((short) 13).putInt(0x28)
                .putShort((short) 2437).putShort((short) 0xa0).put((byte) -42)
                .putShort((short) 0x0080);
        byte[] fullCap = new byte[validCapHeader.length + 16 + radiotapBeacon.length];
        System.arraycopy(validCapHeader, 0, fullCap, 0, validCapHeader.length);
        java.nio.ByteBuffer.wrap(fullCap, validCapHeader.length, 16).order(java.nio.ByteOrder.LITTLE_ENDIAN)
                .putInt((int) (System.currentTimeMillis() / 1000)).putInt(0)
                .putInt(radiotapBeacon.length).putInt(radiotapBeacon.length);
        System.arraycopy(radiotapBeacon, 0, fullCap, validCapHeader.length + 16, radiotapBeacon.length);

        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> {
                 capturedSettings.set(settings);
                 return new HandshakeAnalyzer(settings.monitorInterface(), settings.apBssid(), settings.clientMac(),
                         settings.channel(), settings.frequencyMhz(), directory.resolve("hs-captures").toString(),
                         builder -> {
                             if (builder.command().contains("iw")) return new CompletedProcess("", 0);
                             if (builder.command().getFirst().equals("tshark")) {
                                 Files.write(Path.of(builder.command().get(builder.command().indexOf("-w") + 1)),
                                         fullCap);
                                 return new CompletedProcess(completeExchange(), 0);
                             }
                             if (builder.command().contains("tcpdump")) {
                                 return new CompletedProcess(validCapHeader, 0);
                             }
                             return new CompletedProcess("", 0);
                         }, settings.allowMacRotation());
             });
             var client = HttpClient.newHttpClient()) {
            assertEquals(400, post(client, server, "/api/ops/handshake",
                    "{\"apBssid\":\"" + AP + "\",\"channel\":6,\"timeoutSeconds\":5}").statusCode());
            var response = post(client, server, "/api/ops/handshake",
                    "{\"apBssid\":\"" + AP + "\",\"channel\":6,\"interface\":\"wlo1\",\"timeoutSeconds\":45}");
            assertEquals(200, response.statusCode(), response.body());
            assertEquals(45, capturedSettings.get().timeoutSeconds());
            var json = mapper.readTree(response.body());
            assertTrue(json.path("verifiable").asBoolean());

            assertFalse(mapper.readTree(post(client, server, "/api/ops/handshake/finish", "{}").body())
                    .path("finishing").asBoolean());

            assertEquals(400, post(client, server, "/api/ops/handshake/save-recording",
                    "{\"capFilePath\":\"/tmp/wrong-path.cap\"}").statusCode());
            var saved = post(client, server, "/api/ops/handshake/save-recording",
                    "{\"name\":\"lab-handshake.pcap\"}");
            assertEquals(201, saved.statusCode(), saved.body());
            var savedJson = mapper.readTree(saved.body());
            assertEquals("lab-handshake.pcap", savedJson.path("name").asText());

            var recordings = mapper.readTree(get(client, server, "/api/recordings").body());
            assertTrue(recordings.findValuesAsText("id").contains(savedJson.path("id").asText()));
            assertTrue(recordings.findValuesAsText("name").contains("lab-handshake.pcap"));
        }

        // Verify POST /api/ops/handshake/finish while a handshake capture is live.
        var launched = new java.util.concurrent.CountDownLatch(1);
        var dump = new StreamingCaptureProcess();
        var decoder = new StreamingCaptureProcess();
        try (var bridge = new PacketBridge();
             var server = server(bridge, settings -> new HandshakeAnalyzer(settings.monitorInterface(),
                     settings.apBssid(), settings.clientMac(), settings.channel(), settings.frequencyMhz(),
                     directory.resolve("hs-finish").toString(), builder -> {
                         if (builder.command().contains("iw")) return new CompletedProcess("", 0);
                         if (builder.command().getFirst().equals("tshark")) {
                             Files.write(Path.of(builder.command().get(builder.command().indexOf("-w") + 1)), fullCap);
                             return decoder;
                         }
                         if (builder.command().contains("tcpdump")) {
                             launched.countDown();
                             return dump;
                         }
                         return new CompletedProcess("", 0);
                     }));
             var client = HttpClient.newHttpClient()) {
            var pending = client.sendAsync(request(server, "/api/ops/handshake", CAPTURE),
                    HttpResponse.BodyHandlers.ofString());
            assertTrue(launched.await(3, TimeUnit.SECONDS));
            String clientMac = "02:11:22:33:44:66";
            String partialRows = "0x0028\t2437\t" + AP + "\t" + AP + "\t" + clientMac + "\t\t\t\t1\t1\tnonce\tTrue\n"
                    + "0x0028\t2437\t" + AP + "\t" + clientMac + "\t" + AP + "\t\t\t\t2\t1\tnonce\tTrue\n";
            decoder.write(partialRows.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
            while (System.nanoTime() < deadline) {
                if (mapper.readTree(get(client, server, "/api/ops/handshake/status").body())
                        .path("verifiable").asBoolean()) {
                    break;
                }
                Thread.sleep(20);
            }
            var finishRes = post(client, server, "/api/ops/handshake/finish", "{}");
            assertEquals(200, finishRes.statusCode());
            assertTrue(mapper.readTree(finishRes.body()).path("finishing").asBoolean());
            decoder.finish();
            var finished = pending.get(3, TimeUnit.SECONDS);
            assertEquals(200, finished.statusCode(), finished.body());
            var finishedJson = mapper.readTree(finished.body());
            assertEquals("PARTIAL", finishedJson.path("outcome").asText());
            assertTrue(finishedJson.path("verifiable").asBoolean());
            assertEquals("M1_M2", finishedJson.path("verifiablePair").asText());
        }
    }

    private static String completeExchange() {
        var rows = new StringBuilder();
        String client = "02:11:22:33:44:66";
        for (int message = 1; message <= 4; message++) {
            boolean fromAp = message == 1 || message == 3;
            rows.append(String.join("\t", "0x0028", "2437", AP, fromAp ? AP : client, fromAp ? client : AP,
                    "", "", "", String.valueOf(message), message < 3 ? "1" : "2", "nonce", "True")).append('\n');
        }
        return rows.toString();
    }

    private static URI uri(PassiveRfServer server, String path) { return URI.create("http://localhost:" + server.port() + path); }
    private static HttpRequest request(PassiveRfServer server, String path, String body) {
        return HttpRequest.newBuilder(uri(server, path)).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }
    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server, String path) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + server.port() + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String path, String body) throws Exception {
        return client.send(request(server, path, body), HttpResponse.BodyHandlers.ofString());
    }
}
