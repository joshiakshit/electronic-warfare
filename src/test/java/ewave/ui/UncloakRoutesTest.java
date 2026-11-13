package ewave.ui;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.FrameInjector;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.fixtures.CompletedProcess;
import ewave.fixtures.ProbeFrames;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class UncloakRoutesTest {
    private static final String AP = "02:11:22:33:44:55";
    private static final String AP2 = "02:11:22:33:44:66";
    private static final String CLIENT = "02:aa:bb:cc:dd:ee";
    private static final String BROADCAST = "ff:ff:ff:ff:ff:ff";
    private final ObjectMapper mapper = new ObjectMapper();
    @TempDir Path directory;

    @Test void sendsTargetedDeauthForATopologyTokenUsingTheCachedFrequency() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        Path cache = Files.writeString(directory.resolve("aps.txt"), "Lab AP:" + escape(AP) + ":6:2417 MHz\n");
        try (var bridge = new PacketBridge()) {
            bridge.startReplay(capture(hiddenBeacon(AP), data(AP, CLIENT, 1),
                    data(AP, CLIENT, 2), data(AP, CLIENT, 3)));
            awaitReplay(bridge);
            String token = bridge.getPassiveWifi().addressId(AP);
            assertEquals(token, bridge.getPassiveWifi().topology().accessPoints().getFirst().bssid());
            try (var server = server(bridge, new WifiAccessPoints(cache), commands);
                 var client = HttpClient.newHttpClient()) {
                var response = post(client, server,
                        "{\"bssid\":\"" + token + "\",\"interface\":\"wlo1\"}");
                assertEquals(200, response.statusCode(), response.body());
                var result = mapper.readTree(response.body());
                assertEquals(3, result.size());
                assertEquals("deauth_sent", result.path("status").asText());
                assertEquals(CLIENT, result.path("targetClient").asText());
                assertEquals("SSID will appear in Map within 10s if client reconnects.",
                        result.path("message").asText());

                assertEquals(List.of("sudo", "iw", "dev", "wlo1", "set", "freq", "2417"), commands.get(0));
                assertEquals(List.of("sudo", "aireplay-ng", "--ignore-negative-one", "--deauth", "8", "-a", AP,
                        "-c", CLIENT, "wlo1"), commands.get(1));
            }
        }
    }

    @Test void acceptsAnActualBssidAndFallsBackToTheTopologyChannel() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        try (var bridge = new PacketBridge()) {
            bridge.startReplay(capture(hiddenBeacon(AP), data(AP, CLIENT, 1),
                    data(AP, CLIENT, 2), data(AP, CLIENT, 3)));
            awaitReplay(bridge);
            try (var server = server(bridge, new WifiAccessPoints(directory.resolve("missing-aps")), commands);
                 var client = HttpClient.newHttpClient()) {
                var response = post(client, server,
                        "{\"bssid\":\"" + AP + "\",\"interface\":\"wlo1\"}");
                assertEquals(200, response.statusCode(), response.body());
                assertEquals(CLIENT, mapper.readTree(response.body()).path("targetClient").asText());
                assertEquals(List.of("sudo", "iw", "dev", "wlo1", "set", "freq", "2437"), commands.get(0));
                assertEquals(AP, commands.get(1).get(6));
                assertEquals(CLIENT, commands.get(1).get(8));
            }
        }
    }

    @Test void rejectsKnownNamesMissingClientsAndInvalidRequestsWithoutInjecting() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        try (var bridge = new PacketBridge()) {
            bridge.startReplay(capture(namedBeacon(AP, "Known Lab"), hiddenBeacon(AP2)));
            awaitReplay(bridge);
            var session = bridge.getPassiveWifi();
            String known = session.addressId(AP), hidden = session.addressId(AP2);
            String ssidToken = session.topology().accessPoints().stream()
                    .filter(point -> point.bssid().equals(known)).findFirst().orElseThrow().ssidToken();
            try (var server = server(bridge, new WifiAccessPoints(directory.resolve("missing-aps")), commands);
                 var client = HttpClient.newHttpClient()) {
                for (String bssid : List.of(known, AP)) {
                    var response = post(client, server, "{\"bssid\":\"" + bssid + "\",\"interface\":\"wlo1\"}");
                    assertEquals(400, response.statusCode(), response.body());
                    assertEquals("SSID already known", mapper.readTree(response.body()).path("error").asText());
                    assertEquals(ssidToken, mapper.readTree(response.body()).path("ssid").asText());
                }
                var noClients = post(client, server, "{\"bssid\":\"" + hidden + "\",\"interface\":\"wlo1\"}");
                assertEquals(400, noClients.statusCode());
                assertEquals("No associated clients visible",
                        mapper.readTree(noClients.body()).path("error").asText());

                for (String body : new String[]{"null", "[]", "{", "{}", "{\"bssid\":42}",
                        "{\"bssid\":\"--help\",\"interface\":\"wlo1\"}",
                        "{\"bssid\":\"" + hidden + "\",\"interface\":\"a b\"}"}) {
                    assertEquals(400, post(client, server, body).statusCode(), body);
                }
            }
        }
        assertTrue(commands.isEmpty());
    }

    @Test void reportsAnUnavailableTopologyAndDisabledOperations() throws Exception {
        var commands = new CopyOnWriteArrayList<List<String>>();
        try (var bridge = new PacketBridge();
             var server = server(bridge, new WifiAccessPoints(directory.resolve("missing-aps")), commands);
             var client = HttpClient.newHttpClient()) {
            var response = post(client, server, "{\"bssid\":\"" + AP + "\",\"interface\":\"wlo1\"}");
            assertEquals(400, response.statusCode());
            assertEquals("Wi-Fi topology is unavailable",
                    mapper.readTree(response.body()).path("error").asText());
        }
        try (var bridge = new PacketBridge();
             var server = new PassiveRfServer(bridge, false, monitor -> new FrameInjector(monitor,
                     builder -> { fail("operations are disabled"); return null; }), new LanScanner(),
                     new WifiAccessPoints(directory.resolve("missing-aps"))).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(404, post(client, server, "{\"bssid\":\"" + AP + "\",\"interface\":\"wlo1\"}").statusCode());
        }
        assertTrue(commands.isEmpty());
    }

    private PassiveRfServer server(PacketBridge bridge, WifiAccessPoints accessPoints, List<List<String>> commands)
            throws Exception {
        return new PassiveRfServer(bridge, true, monitor -> new FrameInjector(monitor, builder -> {
            commands.add(List.copyOf(builder.command()));
            return new CompletedProcess("", 0);
        }), new LanScanner(), accessPoints).start(0);
    }

    private Path capture(byte[]... frames) throws IOException {
        byte[][] packets = new byte[frames.length][];
        for (int i = 0; i < frames.length; i++) packets[i] = ProbeFrames.radiotap(frames[i]);
        Path file = Files.createTempFile(directory, "uncloak-", ".pcap");
        Files.write(file, ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, true, 127, packets));
        return file;
    }

    private static void awaitReplay(PacketBridge bridge) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (System.nanoTime() < deadline) {
            Object state = bridge.getCaptureStatus().get("replayState");
            if ("COMPLETE".equals(state) || "FAILED".equals(state)) break;
            Thread.sleep(20);
        }
        assertEquals("COMPLETE", bridge.getCaptureStatus().get("replayState"));
        assertFalse(bridge.isRunning());
    }

    private static byte[] hiddenBeacon(String bssid) { return beacon(8, bssid, new byte[0], 1); }

    private static byte[] namedBeacon(String bssid, String ssid) {
        return beacon(8, bssid, ssid.getBytes(StandardCharsets.UTF_8), 1);
    }

    private static byte[] beacon(int subtype, String ap, byte[] ssid, long tsf) {
        byte[] fixed = ByteBuffer.allocate(12).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(tsf).putShort((short) 100).putShort((short) 1).array();
        return join(header(subtype << 4, 0, BROADCAST, ap, ap, 1), fixed, ie(0, ssid));
    }

    private static byte[] data(String ap, String client, int sequence) {
        return header(0x08, 0x01, ap, client, ap, sequence);
    }

    private static byte[] header(int control, int flags, String a, String b, String c, int sequence) {
        return ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).put((byte) control).put((byte) flags)
                .putShort((short) 0).put(mac(a)).put(mac(b)).put(mac(c)).putShort((short) (sequence << 4)).array();
    }

    private static byte[] ie(int id, byte[] value) { return join(new byte[]{(byte) id, (byte) value.length}, value); }

    private static byte[] join(byte[]... parts) {
        var result = ByteBuffer.allocate(java.util.Arrays.stream(parts).mapToInt(part -> part.length).sum());
        for (byte[] part : parts) result.put(part);
        return result.array();
    }

    private static byte[] mac(String address) {
        return java.util.HexFormat.ofDelimiter(":").parseHex(address);
    }

    private static String escape(String bssid) { return bssid.replace(":", "\\:"); }

    private static URI uri(PassiveRfServer server, String path) {
        return URI.create("http://localhost:" + server.port() + path);
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String body) throws Exception {
        return client.send(HttpRequest.newBuilder(uri(server, "/api/attack/uncloak"))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
