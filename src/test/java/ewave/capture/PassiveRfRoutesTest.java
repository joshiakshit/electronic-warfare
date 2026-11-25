package ewave.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.fixtures.CompletedProcess;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.passive.DeviceProfiler;
import ewave.ui.PassiveRfServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class PassiveRfRoutesTest {
    private static final String SOURCE = "02:11:22:33:44:55";
    private static final String AFFILIATED = "02:11:22:33:44:66";
    private static final String UNSUPPORTED = "02:11:22:33:44:77";
    private static final String MLD = "02:aa:bb:cc:dd:ee";
    private static final byte[] SSID = "Fixture AP".getBytes(StandardCharsets.UTF_8);
    private static final HexFormat HEX = HexFormat.ofDelimiter(":");
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test void followsOnlySupportedAffiliatedLinksAndKeepsEveryAddressPseudonymous() throws Exception {
        try (var radio = new RadioFixture();
             var server = new PassiveRfServer(radio.bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            assertEquals(400, request(client, server, "/api/sniper/link", "{}").statusCode());
            assertEquals(400, request(client, server, "/api/sniper/link", "{\"frequencyMhz\":5975.5}").statusCode());
            assertEquals(409, request(client, server, "/api/sniper/link", "{\"frequencyMhz\":5975}").statusCode());

            radio.bridge.startPassive("lab0mon", false);
            // Basic MLE, one RNR neighbor in the same MLD, and one co-located same-SSID neighbor.
            radio.write(2412, beacon(SOURCE, true, "ff0b6b10000802aabbccddee01"
                    + "c9200010830500021122334466785634120000000200"
                    + "000883150002112233447742"));
            var reports = radio.bridge.getPassiveWifi();
            String apId = reports.addressId(SOURCE);
            await(() -> reports.observedAp(apId) != null);
            var started = request(client, server, "/api/sniper", "{\"apId\":\"" + apId + "\"}");
            var run = run(started);
            assertEquals(apId, run.path("lockedApId").asText());
            assertEquals(reports.addressId(MLD), run.path("mldId").asText());
            assertEquals(2, run.path("affiliatedLinks").size());
            assertEquals(2, run.at("/affiliatedLinks/0/linkId").asInt());
            assertEquals(reports.addressId(AFFILIATED), run.at("/affiliatedLinks/0/apId").asText());
            assertTrue(run.at("/affiliatedLinks/0/supported").asBoolean());
            assertEquals(reports.addressId(UNSUPPORTED), run.at("/affiliatedLinks/1/apId").asText());
            assertFalse(run.at("/affiliatedLinks/1/supported").asBoolean());
            assertPrivate(started.body());
            await(() -> radio.tuned(2412));

            assertEquals(400, request(client, server, "/api/sniper/link", "{\"frequencyMhz\":6055}").statusCode());
            assertEquals(400, request(client, server, "/api/sniper/link", "{\"frequencyMhz\":2437}").statusCode());
            var following = request(client, server, "/api/sniper/link", "{\"frequencyMhz\":5975}");
            assertEquals(5975, run(following).path("pendingAffiliatedLinkFrequencyMhz").asInt());
            assertPrivate(following.body());
            await(() -> radio.tuned(5975));
            radio.write(5975, beacon(AFFILIATED, true, "ff0b6b10000802aabbccddee02"));
            await(() -> Integer.valueOf(5975).equals(radio.bridge.sniperState().run().lockedFrequencyMhz()));
            var result = request(client, server, "/api/sniper", null);
            var followed = run(result);
            assertEquals(reports.addressId(AFFILIATED), followed.path("lockedApId").asText());
            assertEquals("AFFILIATED_LINK_SWITCH", followed.at("/moves/0/trigger").asText());
            assertEquals(2412, followed.at("/moves/0/fromFrequencyMhz").asInt());
            assertEquals(5975, followed.at("/moves/0/toFrequencyMhz").asInt());
            assertPrivate(result.body());
        }
    }

    @Test void reportsHeartbeatDecoyRejectionAndCsaConfirmationOrRollback() throws Exception {
        try (var radio = new RadioFixture();
             var server = new PassiveRfServer(radio.bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            radio.bridge.startPassive("lab0mon", false);
            radio.write(2412, beacon(SOURCE, true, ""));
            var reports = radio.bridge.getPassiveWifi();
            String apId = reports.addressId(SOURCE);
            await(() -> reports.observedAp(apId) != null);
            long previous = run(request(client, server, "/api/sniper", "{\"apId\":\"" + apId + "\"}"))
                    .at("/lastHeard/timestamp").asLong();
            await(() -> radio.tuned(2412));
            radio.write(2412, header(0x0208, SOURCE, AFFILIATED, 0).array());
            await(() -> radio.bridge.sniperState().run().lastHeard().timestamp() > previous);
            long heartbeat = run(request(client, server, "/api/sniper", null)).at("/lastHeard/timestamp").asLong();
            radio.write(2412, beacon(SOURCE, false, ""));
            await(() -> radio.bridge.sniperState().run().decoyFramesIgnored() == 1);
            assertEquals(heartbeat, run(request(client, server, "/api/sniper", null)).at("/lastHeard/timestamp").asLong());

            radio.write(2412, beacon(SOURCE, true, "2503000601"));
            await(() -> radio.tuned(2437));
            var pending = run(request(client, server, "/api/sniper", null));
            assertEquals(2437, pending.at("/pendingChannelSwitch/frequencyMhz").asInt());
            assertEquals(2412, pending.path("lockedFrequencyMhz").asInt());
            radio.write(2437, beacon(SOURCE, true, ""));
            await(() -> Integer.valueOf(2437).equals(radio.bridge.sniperState().run().lockedFrequencyMhz()));
            assertEquals("CSA", run(request(client, server, "/api/sniper", null)).at("/moves/0/trigger").asText());

            radio.write(2437, beacon(SOURCE, true, "3c0400830501"));
            await(() -> radio.tuned(5975));
            await(() -> radio.tuned(2437));
            var rolledBack = request(client, server, "/api/sniper", null);
            var run = run(rolledBack);
            assertEquals(1, run.path("spoofWarnings").asInt());
            assertEquals(1, run.path("moves").size());
            assertTrue(run.path("pendingChannelSwitch").isNull());
            assertPrivate(rolledBack.body());
        }
    }

    @Test void reportsHotspotRotationOnlyAfterACompletePass() throws Exception {
        try (var radio = new RadioFixture();
             var server = new PassiveRfServer(radio.bridge).start(0);
             var client = HttpClient.newHttpClient()) {
            radio.bridge.startPassive("lab0mon", false);
            radio.write(2412, beacon(SOURCE, true, "7f0108"));
            var reports = radio.bridge.getPassiveWifi();
            String apId = reports.addressId(SOURCE);
            await(() -> reports.observedAp(apId) != null);
            run(request(client, server, "/api/sniper", "{\"apId\":\"" + apId + "\"}"));
            await(() -> Integer.valueOf(2437).equals(radio.bridge.sniperState().run().activeSweepFrequencyMhz()));
            radio.write(2437, beacon(AFFILIATED, true, "7f0108"));
            await(() -> radio.bridge.sniperState().run().bssidRotated());
            var response = request(client, server, "/api/sniper", null);
            var rotated = run(response);
            assertEquals("LOCKED", rotated.path("state").asText());
            assertEquals(reports.addressId(AFFILIATED), rotated.path("lockedApId").asText());
            assertEquals("HEURISTIC_BSSID_ROTATION", rotated.at("/moves/0/trigger").asText());
            assertPrivate(response.body());
        }
    }

    private static void assertPrivate(String body) {
        for (String address : List.of(SOURCE, AFFILIATED, UNSUPPORTED, MLD)) {
            assertFalse(body.contains(address), "Raw Wi-Fi address in Sniper response");
        }
    }

    private static JsonNode run(HttpResponse<String> response) throws Exception {
        assertEquals(200, response.statusCode(), response.body());
        return JSON.readTree(response.body()).path("run");
    }

    private static HttpResponse<String> request(HttpClient client, PassiveRfServer server, String path, String body)
            throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + path));
        if (body != null) {
            builder.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body));
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static byte[] beacon(String address, boolean protectedNetwork, String ies) {
        byte[] extra = HexFormat.of().parseHex(ies);
        var frame = header(0x0080, address, address, 12 + 2 + SSID.length + extra.length);
        frame.putLong(1).putShort((short) 100).putShort((short) (protectedNetwork ? 17 : 1));
        frame.put((byte) 0).put((byte) SSID.length).put(SSID).put(extra);
        return frame.array();
    }

    private static ByteBuffer header(int control, String transmitter, String address3, int bodyLength) {
        return ByteBuffer.allocate(24 + bodyLength).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) control).putShort((short) 0).put(HEX.parseHex("ff:ff:ff:ff:ff:ff"))
                .put(HEX.parseHex(transmitter)).put(HEX.parseHex(address3)).putShort((short) 0);
    }

    private static void await(BooleanSupplier predicate) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(4);
        while (!predicate.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        assertTrue(predicate.getAsBoolean(), "Timed out waiting for simulated receiver state");
    }

    private static final class RadioFixture implements AutoCloseable {
        final StreamingCaptureProcess capture;
        final PacketBridge bridge;
        boolean wroteHeader;

        RadioFixture() throws IOException {
            capture = new StreamingCaptureProcess();
            bridge = new PacketBridge(builder -> {
                if (builder.command().getFirst().equals("tcpdump")) return capture;
                assertEquals(List.of("sudo", "iw", "dev", "lab0mon", "set", "freq"), builder.command().subList(0, 6));
                return new CompletedProcess("", 0);
            }, Map.of(), new DeviceProfiler(), 20, 64, 64, iface -> null, iface -> "phy8",
                    iface -> Optional.of(List.of(new RadioStatus.Channel(1, 2412, false, false),
                            new RadioStatus.Channel(6, 2437, false, false), new RadioStatus.Channel(5, 5975, true, false))));
        }

        boolean tuned(int frequency) {
            return Integer.valueOf(frequency).equals(bridge.getCaptureStatus().get("frequencyMhz"));
        }

        void write(int frequency, byte[] frame) throws Exception {
            byte[] packet = ProbeFrames.radiotap(frame);
            ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) frequency);
            byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, packet);
            long now = System.currentTimeMillis();
            ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).position(24)
                    .putInt((int) (now / 1000)).putInt((int) (now % 1000) * 1000);
            capture.write(wroteHeader ? Arrays.copyOfRange(pcap, 24, pcap.length) : pcap);
            wroteHeader = true;
        }

        @Override public void close() { bridge.close(); }
    }
}
