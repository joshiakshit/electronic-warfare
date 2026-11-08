package ewave.capture;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.fixtures.BleFrames;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.ui.PassiveRfServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class PassiveRfCaptureTest {
    @Test void streamsBinaryCapturesToReadOnlyReportsWithoutLegacyEventsOrRawIdentifiers() throws Exception {
        var wifiProcess = new StreamingCaptureProcess();
        var bleProcess = new StreamingCaptureProcess();
        try (var wifi = new PacketBridge(builder -> {
            assertEquals(List.of("tcpdump", "-i", "lab0mon", "-y", "IEEE802_11_RADIO", "-U", "-s",
                    "0", "-n", "-w", "-", "type mgt or type data"), builder.command());
            return wifiProcess;
        }, Map.of());
             var ble = new BleBridge(wifi.getEventQueue(), builder -> bleProcess, wifi.getProfiler());
             var server = new PassiveRfServer(wifi, ble);
             var client = HttpClient.newHttpClient()) {
            wifi.startPassive("lab0mon");
            ble.startPassive(0);
            server.start(0);
            long now = System.currentTimeMillis();
            byte[] packet = ProbeFrames.radiotap(ProbeFrames.frame("PrivateLabSSID"));
            byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, true, 127, packet);
            ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).putInt(24, (int) (now / 1000));
            wifiProcess.write(pcap);
            byte[] snoop = BleFrames.snoop(1002, 0, BleFrames.legacy(BleFrames.data()));
            ByteBuffer.wrap(snoop).putLong(32, 0x00dcddb30f2f8000L + now * 1000L);
            bleProcess.write(snoop);
            await(() -> wifi.getCaptureStatus().get("probeRequests").equals(1L)
                    && ble.getStatus().get("advertisements").equals(1L));

            var mapper = new ObjectMapper();
            var inventory = get(client, server, "/api/inventory");
            var audit = get(client, server, "/api/probe-audit");
            var summary = get(client, server, "/api/ble/summary");
            for (var response : List.of(inventory, audit, summary)) {
                assertEquals(200, response.statusCode());
                assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
                for (String privateData : List.of("PrivateLabSSID", "02:11:22:33:44:55", "c2:11:22:33:44:55", "Lab Tag", "4c00010203"))
                    assertFalse(response.body().contains(privateData));
            }
            assertEquals(1, mapper.readTree(inventory.body()).size());
            assertEquals(1, mapper.readTree(audit.body()).path("distinctDirectedSsids").asInt());
            assertEquals(1, mapper.readTree(summary.body()).path("advertisements").asInt());
            assertEquals(0, mapper.readTree(summary.body()).path("enrolledAssets").size());
            assertEquals(200, get(client, server, "/").statusCode());
            assertEquals(404, get(client, server, "/api/attack/scan-lan").statusCode());
            assertEquals(404, get(client, server, "/api/ble/advertisements").statusCode());
            assertEquals(404, get(client, server, "/api/probes").statusCode());
            assertTrue(wifi.getEventQueue().isEmpty());
            assertTrue(wifi.getProfiler().all().isEmpty());
            assertTrue(ble.getAdvertisements().isEmpty());
        }
    }

    @Test void enrollsObservedApAndPinsDeviceWithoutExposingAddresses(@TempDir Path temp) throws Exception {
        Path file = temp.resolve("my-network.json");
        String previous = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", file.toString());
        try {
            var process = new StreamingCaptureProcess();
            try (var wifi = new PacketBridge(builder -> process, Map.of());
                 var ble = new BleBridge(wifi.getEventQueue(), wifi.getProfiler());
                 var server = new PassiveRfServer(wifi, ble).start(0);
                 var client = HttpClient.newHttpClient()) {
                wifi.startPassive("lab0mon");
                byte[] home = beacon("001122334455", "Fixture Home");
                byte[] nearby = beacon("00aabbccddee", "Fixture Nearby");
                process.write(pcap(home, nearby));
                await(() -> {
                    try { return wifi.myNetwork().observedAccessPoints().size() == 2; }
                    catch (java.io.IOException failure) { throw new java.io.UncheckedIOException(failure); }
                });

                var mapper = new ObjectMapper();
                var match = mapper.readTree(post(client, server, "/api/my-network/find", "{\"ssid\":\"Fixture Home\"}").body());
                assertEquals(1, match.size());
                String apToken = match.get(0).asText();
                var saved = post(client, server, "/api/my-network",
                        "{\"action\":\"save-ap\",\"observedId\":\"" + apToken + "\",\"label\":\"Home 2.4 GHz\"}");
                assertEquals(200, saved.statusCode(), saved.body());
                assertEquals(apToken, mapper.readTree(saved.body()).at("/accessPoints/0/token").asText());
                assertFalse(saved.body().contains("00:11:22:33:44:55"));
                assertFalse(saved.body().contains("00:aa:bb:cc:dd:ee"));
                assertEquals(200, post(client, server, "/api/my-network",
                        "{\"action\":\"save-device\",\"address\":\"76:11:22:33:44:55\",\"label\":\"My Phone\"}").statusCode());
                var profile = mapper.readTree(get(client, server, "/api/my-network").body());
                assertEquals("My Phone", profile.at("/devices/0/label").asText());
                assertEquals(wifi.getPassiveWifi().addressId("76:11:22:33:44:55"), profile.at("/devices/0/token").asText());
                assertFalse(profile.toString().contains("76:11:22:33:44:55"));
                assertEquals(200, post(client, server, "/api/my-network",
                        "{\"action\":\"scope\",\"restricted\":true}").statusCode());
                assertTrue(wifi.getPassiveWifi().inventory().isEmpty());
                assertEquals(2, wifi.myNetwork().observedAccessPoints().size());
                byte[] more = pcap(home, nearby);
                process.write(java.util.Arrays.copyOfRange(more, 24, more.length));
                await(() -> wifi.getPassiveWifi().inventory().size() == 1);
                assertEquals(apToken, wifi.getPassiveWifi().inventory().getFirst().id());
                String savedId = profile.at("/accessPoints/0/id").asText();
                assertEquals(400, post(client, server, "/api/my-network",
                        "{\"action\":\"remove-ap\",\"id\":\"" + savedId + "\"}").statusCode());
            }
            assertEquals("rw-------", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
            try (var reopened = new PacketBridge()) {
                assertEquals("My Phone", reopened.myNetwork().devices().getFirst().label());
                assertEquals("Home 2.4 GHz", reopened.myNetwork().accessPoints().getFirst().label());
                assertTrue(reopened.myNetwork().restrictCapture());
            }
        } finally {
            restoreProperty("rf.networkProfile", previous);
        }
    }

    @Test void savesAndExportsFingerprintsOnlyFromObservedEnrolledDevices(@TempDir Path temp) throws Exception {
        Path profile = temp.resolve("my-network.json");
        Files.writeString(profile, "{\"accessPoints\":[],\"devices\":[],\"restrictCapture\":false}");
        String previous = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", profile.toString());
        try {
            var process = new StreamingCaptureProcess();
            var mapper = new ObjectMapper();
            try (var wifi = new PacketBridge(builder -> process, Map.of());
                 var ble = new BleBridge(wifi.getEventQueue(), wifi.getProfiler());
                 var server = new PassiveRfServer(wifi, ble).start(0);
                 var client = HttpClient.newHttpClient()) {
                wifi.startPassive("lab0mon");
                byte[] packet = ProbeFrames.radiotap(ProbeFrames.frame("PrivateFixture"));
                process.write(pcap(packet, packet));
                await(() -> wifi.getCaptureStatus().get("probeRequests").equals(2L));
                var device = wifi.getPassiveWifi().inventory().getFirst();
                String path = "/api/inventory/" + device.id() + "/details";
                String sample = mapper.writeValueAsString(Map.of("observedId", device.id(), "hash", device.ieSignatureHash(),
                        "source", "PROBE_REQUEST", "family", "Phone", "osHint", "Fixture OS"));
                var details = mapper.readTree(get(client, server, path).body());
                assertEquals(-47, details.at("/signalHistory/0/rssi").asInt());
                assertEquals(0, details.path("fingerprints").size());
                assertEquals(400, post(client, server, "/api/fingerprint-samples", sample).statusCode());
                var pin = post(client, server, "/api/my-network",
                        "{\"action\":\"save-device\",\"address\":\"02:11:22:33:44:55\",\"label\":\"Fixture phone\"}");
                assertEquals(200, pin.statusCode(), pin.body());
                details = mapper.readTree(get(client, server, path).body());
                assertEquals(2, details.at("/fingerprints/0/observations").asInt());
                assertEquals(400, post(client, server, "/api/fingerprint-samples",
                        sample.replace("PROBE_REQUEST", "PROBE_RESPONSE")).statusCode());
                var saved = post(client, server, "/api/fingerprint-samples", sample);
                assertEquals(200, saved.statusCode(), saved.body());
                assertEquals(saved.body(), post(client, server, "/api/fingerprint-samples", sample).body());
                var exported = get(client, server, "/api/fingerprint-samples");
                assertEquals(saved.body(), exported.body());
                for (String privateData : List.of("02:11:22:33:44:55", device.id(), "PrivateFixture", "Fixture phone"))
                    assertFalse(exported.body().contains(privateData));
                assertNull(wifi.getPassiveWifi().inventory().getFirst().fingerprintHint());
                var pinId = mapper.readTree(pin.body()).at("/devices/0/id").asText();
                assertEquals(200, post(client, server, "/api/my-network",
                        "{\"action\":\"remove-device\",\"id\":\"" + pinId + "\"}").statusCode());
                assertEquals(400, post(client, server, "/api/fingerprint-samples", sample).statusCode());
                try (var reopened = new PacketBridge()) {
                    assertEquals("Phone", reopened.fingerprintSamples().getFirst().family());
                }
                var id = mapper.readTree(exported.body()).at("/0/id").asText();
                var delete = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/api/fingerprint-samples/" + id))
                        .DELETE().build();
                assertEquals("[]", client.send(delete, HttpResponse.BodyHandlers.ofString()).body());
            }
        } finally {
            restoreProperty("rf.networkProfile", previous);
        }
    }

    private static byte[] beacon(String address, String name) {
        byte[] mac = HexFormat.of().parseHex(address), ssid = name.getBytes(StandardCharsets.UTF_8);
        var frame = ByteBuffer.allocate(38 + ssid.length).order(ByteOrder.LITTLE_ENDIAN);
        frame.putShort((short) 0x80).putShort((short) 0).put(HexFormat.of().parseHex("ffffffffffff"))
                .put(mac).put(mac).putShort((short) 0).putLong(0).putShort((short) 100).putShort((short) 1)
                .put((byte) 0).put((byte) ssid.length).put(ssid);
        return ProbeFrames.radiotap(frame.array());
    }

    private static byte[] pcap(byte[] first, byte[] second) {
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, first, second);
        int now = (int) (System.currentTimeMillis() / 1000);
        ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).putInt(24, now).putInt(40 + first.length, now);
        return pcap;
    }

    private static HttpResponse<String> post(HttpClient client, PassiveRfServer server, String path, String body)
            throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + path))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    @Test void neighborhoodAuditDoesNotPopulateOutOfScopeLabTargets() throws Exception {
        String oldBssids = System.getProperty("rf.bssids");
        String oldProbes = System.getProperty("rf.neighborhoodProbes");
        try {
            System.setProperty("rf.bssids", "00:11:22:33:44:55");
            System.setProperty("rf.neighborhoodProbes", "true");
            var process = new StreamingCaptureProcess();
            try (var wifi = new PacketBridge(builder -> process, Map.of())) {
                wifi.startPassive("lab0mon", true);
                byte[] allowed = ProbeFrames.frame("Scoped");
                System.arraycopy(HexFormat.of().parseHex("001122334455"), 0, allowed, 16, 6);
                byte[] neighbor = ProbeFrames.frame("Nearby");
                neighbor[15]++;
                byte[] packet = ProbeFrames.radiotap(allowed);
                byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, packet, ProbeFrames.radiotap(neighbor));
                int now = (int) (System.currentTimeMillis() / 1000);
                ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN)
                        .putInt(24, now).putInt(24 + 16 + packet.length, now);
                process.write(pcap);
                await(() -> wifi.getCaptureStatus().get("probeRequests").equals(2L));
                assertEquals(1, wifi.getCaptureStatus().get("scopedBssidCount"));
                assertEquals(1, wifi.getPassiveWifi().inventory().size());
                assertEquals(2, wifi.getPassiveWifi().audit().totalProbes());
                assertEquals(List.of("02:11:22:33:44:55"),
                        wifi.getProfiler().all().stream().map(profile -> profile.mac().toLowerCase(java.util.Locale.ROOT)).toList());
            }
        } finally {
            restoreProperty("rf.bssids", oldBssids);
            restoreProperty("rf.neighborhoodProbes", oldProbes);
        }
    }

    private static void restoreProperty(String name, String previous) {
        if (previous == null) System.clearProperty(name);
        else System.setProperty(name, previous);
    }

    @Test void rejectsAlternativeExecutablesAndTcpdumpWritePaths() {
        var command = new ArrayList<>(PassiveCommandGuard.monitor("lab0mon"));
        command.set(command.indexOf("-w") + 1, "capture.pcap");
        assertThrows(IllegalArgumentException.class, () -> PassiveCommandGuard.requireWifi(command, "lab0mon"));
        assertThrows(IllegalArgumentException.class, () -> PassiveCommandGuard.requireWifi(
                List.of("hcitool", "lescan"), "lab0mon"));
        assertThrows(IllegalArgumentException.class, () -> PassiveCommandGuard.requireWifi(
                PassiveCommandGuard.monitor("-bad"), "-bad"));
    }

    private static HttpResponse<String> get(HttpClient client, PassiveRfServer server, String path) throws Exception {
        var uri = URI.create("http://127.0.0.1:" + server.port() + path);
        return client.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(condition.getAsBoolean());
    }
}
