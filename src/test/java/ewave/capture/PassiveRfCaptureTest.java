package ewave.capture;

import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.core.AdaptiveScanner;
import ewave.decoder.Dot11FrameDecoder;
import ewave.fixtures.CompletedProcess;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.passive.DeviceProfiler;
import ewave.ui.PassiveRfServer;
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
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(15)
class PassiveRfCaptureTest {
    @Test void sharesTheDiscoveredFrequencyPlanAcrossSniperLookoutAndInspector() throws Exception {
        var capture = new StreamingCaptureProcess();
        var tunes = new LinkedBlockingQueue<Integer>();
        try (var wifi = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("tcpdump")) return capture;
            assertEquals(List.of("sudo", "iw", "dev", "lab0mon", "set", "freq"), builder.command().subList(0, 6));
            tunes.add(Integer.parseInt(builder.command().getLast()));
            return new CompletedProcess("", 0);
        }, Map.of(), new DeviceProfiler(), 100, 64, 64, iface -> null, iface -> "phy8",
                iface -> RadioStatus.readChannels(iface, ignored -> "phy8", command -> RadioStatusTest.PHY_INFO));
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            wifi.configureRuntimeCapture("scan", "lab0mon", null, null, 13, false);
            wifi.startSniperBySsid("Synthetic 6 GHz");
            for (int frequency : List.of(2412, 5260, 5955)) {
                assertEquals(frequency, tunes.poll(3, TimeUnit.SECONDS));
            }
            await(() -> Integer.valueOf(5955).equals(wifi.getChannelSnapshot().radio().lastConfirmedFrequencyMhz()));

            byte[] beacon = beacon("001122334455", "Synthetic 6 GHz");
            byte[] ies = HexFormat.of().parseHex("30140100000fac040100000fac040100000fac12c000460502000000007f030000083603123400");
            byte[] packet = Arrays.copyOf(beacon, beacon.length + ies.length);
            System.arraycopy(ies, 0, packet, beacon.length, ies.length);
            ByteBuffer.wrap(packet).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) 5955);
            capture.write(timedPcap(packet));
            await(() -> wifi.sniperState().run().state() == SniperController.State.LOCKED);
            assertEquals(5955, wifi.sniperState().run().lockedFrequencyMhz());
            assertEquals(3, wifi.sniperState().run().channelsSwept());

            var mapper = new ObjectMapper();
            var lookout = mapper.readTree(get(client, server, "/api/lookout").body());
            assertEquals(3, lookout.path("channels").size());
            assertEquals(3, lookout.path("counts").size());
            assertEquals(2412, lookout.at("/channels/0/freqMhz").asInt());
            assertEquals(52, lookout.at("/channels/1/channel").asInt());
            assertTrue(lookout.at("/channels/1/radarDetection").asBoolean());
            assertEquals(1, lookout.at("/channels/0/channel").asInt());
            assertEquals(1, lookout.at("/channels/2/channel").asInt());
            assertEquals(5955, lookout.at("/channels/2/freqMhz").asInt());
            assertTrue(lookout.at("/channels/2/noIr").asBoolean());
            assertEquals(lookout.at("/counts/2").asLong(), lookout.at("/channels/2/sampleCount").asLong());
            assertTrue(lookout.at("/radio/coverage/0/lastFrameAtMs").isNull());
            assertTrue(lookout.at("/radio/coverage/2/lastFrameWhileTunedAtMs").isNumber());
            assertEquals(0, lookout.at("/channels/0/apCount").asInt(-1));
            assertEquals(1, lookout.at("/channels/2/apCount").asInt(-1));
            assertEquals(5955, lookout.path("activeFrequencyMhz").asInt());

            var inspector = mapper.readTree(get(client, server, "/api/inspector").body()).at("/accessPoints/0");
            assertEquals("OWE (Enhanced Open)", inspector.at("/securityModes/0").asText());
            assertTrue(inspector.at("/managementFeatures/neighborReport").asBoolean());
            assertTrue(inspector.at("/managementFeatures/bssTransition").asBoolean());
            assertTrue(inspector.at("/managementFeatures/fastTransition").asBoolean());
            assertEquals("1234", inspector.at("/managementFeatures/mobilityDomain").asText());
            assertEquals(5955, inspector.at("/radioObservation/frequencyMhz").asInt());
        }
    }

    @Test void completesTheInitialSurveyThenSelectsActiveChannelsAtDwellBoundaries() throws Exception {
        var capture = new StreamingCaptureProcess();
        record Tune(int frequency, long time) {}
        var tunes = new LinkedBlockingQueue<Tune>();
        try (var wifi = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("tcpdump")) return capture;
            tunes.add(new Tune(Integer.parseInt(builder.command().getLast()), System.nanoTime()));
            return new CompletedProcess("", 0);
        }, Map.of(), new DeviceProfiler(), 20, 64, 64, iface -> null, iface -> "phy8",
                iface -> RadioStatus.parseChannels("* 2412 MHz [1]\n* 2437 MHz [6]\n* 2462 MHz [11]"))) {
            wifi.configureRuntimeCapture("scan", "lab0mon", null, null, 13, false);
            var first = tunes.poll(3, TimeUnit.SECONDS);
            var second = tunes.poll(3, TimeUnit.SECONDS);
            assertNotNull(first);
            assertNotNull(second);
            assertEquals(2412, first.frequency());
            assertEquals(2437, second.frequency());
            await(() -> Integer.valueOf(2437).equals(wifi.getChannelSnapshot().radio().lastConfirmedFrequencyMhz()));

            byte[] active = ProbeFrames.radiotap(ProbeFrames.frame(""));
            for (int sample = 0; sample < 18; sample++) {
                writeTimedFrames(capture, sample == 0, active);
                Thread.sleep(25);
            }
            var third = tunes.poll(3, TimeUnit.SECONDS);
            var fourth = tunes.poll(3, TimeUnit.SECONDS);
            var fifth = tunes.poll(3, TimeUnit.SECONDS);
            assertNotNull(third);
            assertNotNull(fourth);
            assertNotNull(fifth);
            assertEquals(2462, third.frequency());
            assertEquals(2437, fourth.frequency());
            assertNotEquals(fourth.frequency(), fifth.frequency());
            var hops = List.of(first, second, third, fourth, fifth);
            for (int index = 1; index < hops.size(); index++) {
                assertTrue(hops.get(index).time() - hops.get(index - 1).time() >= TimeUnit.MILLISECONDS.toNanos(100));
            }
        }
    }

    @Test void reportsTunedAirtimeAndNoiseWithFrequencyMatchedQbssAndClients() throws Exception {
        var capture = new StreamingCaptureProcess();
        try (var wifi = singleChannelScanner(capture);
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            wifi.configureRuntimeCapture("scan", "lab0mon", null, null, 13, false);
            await(() -> Integer.valueOf(2437).equals(wifi.getChannelSnapshot().radio().lastConfirmedFrequencyMhz()));
            byte[] strongLoad = withNoiseAndRate(beacon("001122334455", "Load Fixture"), -94, "0b050200cc0000");
            byte[] weakLoad = withNoiseAndRate(beacon("001122334466", "Second AP"), -96, "0b050100400000");
            byte[] clientFrame = assocResponse("001122334455", "021122334455");
            writeTimedFrames(capture, true, strongLoad, weakLoad, clientFrame);
            await(() -> wifi.getPassiveWifi().topology().edges().size() == 1);
            await(() -> wifi.getChannelSnapshot().radio().dwellMs().getFirst() >= 500);

            long expectedAirtime = Math.round((strongLoad.length - 16) * 8.0 / 12) + 44L
                    + Math.round((weakLoad.length - 16) * 8.0 / 12) + 44L
                    + Math.round((clientFrame.length - 13) * 8.0 / 6) + 44L;
            var lookout = new ObjectMapper().readTree(get(client, server, "/api/lookout").body());
            var channel = lookout.at("/channels/0");
            assertEquals(expectedAirtime, lookout.at("/radio/coverage/0/airtimeMicrosWhileTuned").asLong());
            assertEquals(-95, lookout.at("/radio/coverage/0/medianNoiseDbm").asInt());
            assertEquals(-95, channel.path("medianNoiseDbm").asInt());
            assertEquals(2, channel.path("apCount").asInt());
            assertEquals(1, channel.path("activeClientCount").asInt());
            assertEquals(0.8, channel.path("qbssUtilization").asDouble(), 1e-9);
            assertEquals(expectedAirtime / (1000.0 * channel.path("dwellMs").asLong()),
                    channel.path("estimatedAirtime").asDouble(), 1e-9);
            assertTrue(channel.path("nonWifiInterferenceSuspected").asBoolean());
        }
    }

    @Test void servesActiveAndHeldFloodEvidenceFromSyntheticCapture() throws Exception {
        var capture = new StreamingCaptureProcess();
        try (var wifi = singleChannelScanner(capture);
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            wifi.configureRuntimeCapture("scan", "lab0mon", null, null, 13, false);
            await(() -> wifi.getChannelSnapshot().scanner().counts()[0] >= 10);

            var deauthFrames = new byte[8][];
            Arrays.fill(deauthFrames, syntheticDisconnect());
            writeTimedFrames(capture, true, deauthFrames);
            await(() -> wifi.getCaptureHealth().decoded() == deauthFrames.length);
            var mapper = new ObjectMapper();
            var active = mapper.readTree(get(client, server, "/api/lookout").body());
            assertEquals("DEAUTH_FLOOD", active.at("/channels/0/anomaly/floodType").asText());
            assertTrue(active.at("/channels/0/anomaly/activeNow").asBoolean());
            assertEquals(2437, active.at("/recentAnomalies/0/freqMhz").asInt());

            await(() -> {
                var anomaly = wifi.getChannelSnapshot().heldAnomalies().get(2437);
                return anomaly != null && !anomaly.activeNow();
            });
            var quiet = mapper.readTree(get(client, server, "/api/lookout").body());
            assertTrue(quiet.path("anomalies").isEmpty());
            assertEquals("DEAUTH_FLOOD", quiet.at("/channels/0/anomaly/floodType").asText());
            assertFalse(quiet.at("/channels/0/anomaly/activeNow").asBoolean(true));
            assertEquals(active.at("/recentAnomalies/0/detectedAt"), quiet.at("/recentAnomalies/0/detectedAt"));

            var beaconFrames = new byte[50][];
            Arrays.fill(beaconFrames, withNoiseAndRate(beacon("001122334455", "Beacon Fixture"), -74, ""));
            writeTimedFrames(capture, false, beaconFrames);
            await(() -> {
                var anomaly = wifi.getChannelSnapshot().heldAnomalies().get(2437);
                return anomaly != null && "BEACON_FLOOD".equals(anomaly.floodType());
            });
            var beaconReport = mapper.readTree(get(client, server, "/api/lookout").body());
            assertEquals("BEACON_FLOOD", beaconReport.at("/channels/0/anomaly/floodType").asText());
            assertTrue(beaconReport.at("/channels/0/anomaly/activeNow").asBoolean());
            assertEquals(-74, beaconReport.at("/channels/0/medianNoiseDbm").asInt());
            assertTrue(beaconReport.at("/channels/0/qbssUtilization").isNull());
            assertTrue(beaconReport.at("/channels/0/nonWifiInterferenceSuspected").asBoolean());
            assertEquals(2, beaconReport.path("recentAnomalies").size());
        }
    }

    @Test void opensAndHoldsABeaconFloodWithoutAFlagFromTheScanner() {
        var anomalies = new LookoutAnomalies(List.of(new RadioStatus.Channel(6, 2437, false, false)));
        var frame = Dot11FrameDecoder.decodeAny(beacon("001122334455", "Beacon Fixture"), 127, 0);
        var now = Instant.parse("2026-01-01T00:00:00Z");
        long second = TimeUnit.SECONDS.toNanos(1);
        long interval = TimeUnit.MILLISECONDS.toNanos(20);
        for (int index = 0; index < 49; index++) {
            assertFalse(anomalies.observeFrame(0, frame, index * interval));
        }
        anomalies.update(0, null, 48 * interval, now.plusMillis(960));
        assertNull(anomalies.onChannel(0, 48 * interval));

        long crossing = 49 * interval;
        assertTrue(anomalies.observeFrame(0, frame, crossing));
        anomalies.update(0, null, crossing, now.plusMillis(980));
        var active = anomalies.onChannel(0, crossing);
        assertTrue(active.activeNow());
        assertEquals("BEACON_FLOOD", active.reason());
        assertEquals("BEACON_FLOOD", active.floodType());

        anomalies.update(0, null, second, now.plusSeconds(1));
        var held = anomalies.onChannel(0, second);
        assertFalse(held.activeNow());
        assertEquals("BEACON_FLOOD", held.floodType());
        assertEquals(active.detectedAt(), held.detectedAt());
        assertEquals(List.of(held), anomalies.recent(second));
        assertNull(anomalies.onChannel(0, crossing + 15 * second));
    }

    @Test void rollingDisconnectThresholdAndHoldExpireOnMonotonicBoundaries() {
        var anomalies = new LookoutAnomalies(List.of(new RadioStatus.Channel(6, 2437, false, false)));
        var frame = Dot11FrameDecoder.decodeAny(syntheticDisconnect(), 127, 0);
        long second = TimeUnit.SECONDS.toNanos(1);
        var wallTime = Instant.parse("2026-01-01T00:00:00Z");
        for (int index = 0; index < 7; index++) {
            assertFalse(anomalies.observeFrame(0, frame, 0));
        }
        // Seven older frames fall out of the window even when the next one arrives.
        assertFalse(anomalies.observeFrame(0, frame, second));
        anomalies.update(0, null, second, wallTime);
        assertNull(anomalies.onChannel(0, second));
        for (int index = 0; index < 7; index++) anomalies.observeFrame(0, frame, second);
        anomalies.update(0, null, second, wallTime);
        assertTrue(anomalies.onChannel(0, second).activeNow());
        anomalies.update(0, null, 2 * second, wallTime.plusSeconds(1));
        assertFalse(anomalies.onChannel(0, 16 * second - 1).activeNow());
        assertEquals(wallTime, anomalies.recent(16 * second - 1).getFirst().lastActiveAt());
        assertNull(anomalies.onChannel(0, 16 * second));
        assertTrue(anomalies.recent(16 * second).isEmpty());
    }

    @Test void retainsFloodEvidenceAfterTheLiveClassifierClearsAndBoundsEpisodeHistory() {
        var anomalies = new LookoutAnomalies(List.of(new RadioStatus.Channel(6, 2437, false, false)));
        var frame = Dot11FrameDecoder.decodeAny(beacon("001122334455", "Beacon Fixture"), 127, 0);
        long second = TimeUnit.SECONDS.toNanos(1);
        var now = Instant.parse("2026-01-01T00:00:00Z");
        var flag = new AdaptiveScanner.AnomalyFlag(1, 3.2, now, "UNUSUAL_BURST");
        for (int index = 0; index < 40; index++) anomalies.observeFrame(0, frame, 0);
        anomalies.update(0, flag, 0, now);
        assertEquals("BEACON_FLOOD", anomalies.onChannel(0, 0).floodType());
        anomalies.update(0, flag, second, now.plusSeconds(1));
        assertNull(anomalies.onChannel(0, second).floodType());
        anomalies.update(0, null, 2 * second, now.plusSeconds(2));
        assertEquals("BEACON_FLOOD", anomalies.onChannel(0, 2 * second).floodType());
        for (int episode = 1; episode <= 32; episode++) {
            long elapsedMs = 2_000L + 2 * episode;
            long elapsed = TimeUnit.MILLISECONDS.toNanos(elapsedMs);
            var started = now.plusMillis(elapsedMs);
            anomalies.update(0, new AdaptiveScanner.AnomalyFlag(1, 3.2, started, "UNUSUAL_BURST"), elapsed, started);
            anomalies.update(0, null, elapsed + 1, started);
        }
        var recent = anomalies.recent(3 * second);
        assertEquals(32, recent.size());
        assertEquals(now.plusMillis(2064), recent.getFirst().detectedAt());
        assertTrue(recent.stream().noneMatch(anomaly -> "BEACON_FLOOD".equals(anomaly.floodType())));
    }

    private static PacketBridge singleChannelScanner(StreamingCaptureProcess capture) {
        return new PacketBridge(builder -> builder.command().getFirst().equals("tcpdump")
                ? capture : new CompletedProcess("", 0), Map.of(), new DeviceProfiler(), 20, 64, 64,
                iface -> null, iface -> "phy8", iface -> RadioStatus.parseChannels("* 2437 MHz [6]"));
    }

    private static byte[] syntheticDisconnect() {
        byte[] frame = assocResponse("001122334455", "021122334455");
        frame[13] = (byte) 0xc0;
        return frame;
    }

    private static byte[] withNoiseAndRate(byte[] radiotapFrame, int noise, String extraElements) {
        byte[] extra = HexFormat.of().parseHex(extraElements);
        return ByteBuffer.allocate(radiotapFrame.length + 3 + extra.length).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) 0).putShort((short) 16).putInt(0x6c)
                .put((byte) 24).put((byte) 0).putShort((short) 2437).putShort((short) 0xa0)
                .put((byte) -47).put((byte) noise)
                .put(radiotapFrame, 13, radiotapFrame.length - 13).put(extra).array();
    }

    private static void writeTimedFrames(StreamingCaptureProcess capture, boolean header, byte[]... frames) throws IOException {
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, frames);
        var buffer = ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN);
        long now = System.currentTimeMillis();
        int offset = 24;
        for (byte[] frame : frames) {
            buffer.putInt(offset, (int) (now / 1000)).putInt(offset + 4, (int) (now % 1000) * 1000);
            offset += 16 + frame.length;
        }
        capture.write(header ? pcap : Arrays.copyOfRange(pcap, 24, pcap.length));
    }

    @Test void replayServesProbabilisticProbeClustersWithPrivacyAndCapabilityEvidence(@TempDir Path dir) throws Exception {
        String first = "02:11:22:33:44:01", second = "02:11:22:33:44:02";
        byte[] elements = HexFormat.of().parseHex("30180100000fac040100000fac040200000fac02000fac08c0007f03000008");
        byte[][] frames = new byte[2][];
        for (int index = 0; index < frames.length; index++) {
            byte[] probe = ProbeFrames.frame("Fixture-private-name", index == 0 ? first : second, index);
            byte[] frame = Arrays.copyOf(probe, probe.length + elements.length);
            System.arraycopy(elements, 0, frame, probe.length, elements.length);
            frames[index] = ProbeFrames.radiotap(frame);
        }
        Path path = dir.resolve("correlation.pcap");
        Files.write(path, ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, frames));

        try (var wifi = new PacketBridge(builder -> { throw new AssertionError("Unexpected process " + builder.command()); }, Map.of());
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            wifi.startReplay(path);
            await(() -> !wifi.isRunning());
            assertEquals(2, wifi.getCaptureHealth().decoded());
            String id = wifi.getPassiveWifi().addressId(first);
            String otherId = wifi.getPassiveWifi().addressId(second);
            var mapper = new ObjectMapper();
            var response = get(client, server, "/api/profiler");
            assertEquals(200, response.statusCode());
            var rows = mapper.readTree(response.body());
            assertEquals(2, rows.size());
            String clusterId = rows.get(0).at("/inferredCorrelation/id").asText();
            assertFalse(clusterId.isBlank());
            for (var row : rows) {
                assertTrue(List.of(id, otherId).contains(row.path("id").asText()));
                assertEquals(clusterId, row.at("/inferredCorrelation/id").asText());
                assertEquals(2, row.at("/inferredCorrelation/memberCount").asInt());
                assertEquals("PSK", row.at("/capabilities/rsnAkmSuites/0").asText());
                assertEquals("SAE", row.at("/capabilities/rsnAkmSuites/1").asText());
                assertEquals("WPA2/WPA3-Personal transition", row.at("/capabilities/securityModes/0").asText());
                assertTrue(row.at("/capabilities/managementFeatures/bssTransition").asBoolean());
            }
            var detailResponse = get(client, server, "/api/profiler/" + id);
            assertEquals(200, detailResponse.statusCode());
            var detail = mapper.readTree(detailResponse.body());
            assertEquals(0, detail.path("fingerprints").size());
            assertEquals(clusterId, detail.at("/inferredCorrelation/id").asText());
            assertEquals("Probabilistic inferred correlation", detail.at("/inferredCorrelation/inference").asText());
            assertEquals(0.85, detail.at("/inferredCorrelation/confidence").asDouble());
            assertEquals(otherId, detail.at("/inferredCorrelation/memberIds/1").asText());
            assertEquals(1, detail.at("/inferredCorrelation/evidence/0/sharedDirectedSsidCount").asInt());
            assertEquals(-47, detail.at("/radioObservation/metadata/signalDbm").asInt());
            for (String data : List.of(response.body(), detailResponse.body())) {
                assertFalse(data.contains(first) || data.contains(second) || data.contains("Fixture-private-name"));
            }
        }
    }

    @Test void replayServesInspectorFindingsAndAdvertisedDetailsWithTokenizedApIds(@TempDir Path dir) throws Exception {
        String secureBssid = "00:aa:bb:cc:dd:ee", openBssid = "02:aa:bb:cc:dd:ef";
        byte[] secure = beacon("00aabbccddee", "Test ESS");
        byte[] elements = HexFormat.of().parseHex("301a0100000fac040100000fac040100000fac08c0400000000fac06"
                + "f40170" + "3d022405");
        byte[] advertised = Arrays.copyOf(secure, secure.length + elements.length);
        System.arraycopy(elements, 0, advertised, secure.length, elements.length);
        Path recording = dir.resolve("inspector.pcap");
        Files.write(recording, ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127,
                advertised, beacon("02aabbccddef", "Test ESS")));

        try (var wifi = new PacketBridge(builder -> { throw new AssertionError("Unexpected process " + builder.command()); }, Map.of());
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            wifi.startReplay(recording);
            await(() -> !wifi.isRunning());
            var response = get(client, server, "/api/inspector");
            assertEquals(200, response.statusCode(), response.body());
            assertFalse(response.body().contains(secureBssid));
            assertFalse(response.body().contains(openBssid));
            var report = new ObjectMapper().readTree(response.body());
            assertEquals(2, report.path("essGroups").size());
            assertEquals(2, report.path("findingsCount").asInt());
            assertEquals(1, report.path("evilTwinSuspects").asInt());
            String secureId = wifi.getPassiveWifi().addressId(secureBssid);
            String openId = wifi.getPassiveWifi().addressId(openBssid);
            var rows = report.path("accessPoints");
            assertEquals(2, rows.size());
            for (var row : rows) {
                assertEquals("Test ESS", row.path("ssid").asText());
                if (secureId.equals(row.path("bssid").asText())) {
                    assertEquals("BIP-CMAC-128", row.path("groupManagementCipher").asText());
                    assertTrue(row.path("ocvc").asBoolean());
                    assertEquals("SAE H2E", row.at("/rsnxeFeatures/0").asText());
                    assertEquals(40, row.at("/apRadio/operatingWidthMhz").asInt());
                    assertTrue(row.path("securityFindings").isArray());
                    assertTrue(row.path("securityFindings").isEmpty());
                } else {
                    assertEquals(openId, row.path("bssid").asText());
                    assertEquals("ESS_SECURITY_DOWNGRADE", row.at("/securityFindings/0/code").asText());
                    assertEquals("HIGH", row.at("/securityFindings/0/severity").asText());
                }
            }
        }
    }

    @Test void reportsAnExplicitEmptyPlanWithoutFallingBackToDisabledFrequencies() throws Exception {
        var capture = new StreamingCaptureProcess();
        var tuneAttempts = new java.util.concurrent.atomic.AtomicInteger();
        try (var wifi = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("tcpdump")) return capture;
            tuneAttempts.incrementAndGet();
            return new CompletedProcess("", 1);
        }, Map.of(), new DeviceProfiler(), 20, 64, 64, iface -> null, iface -> "phy8",
                iface -> RadioStatus.parseChannels("* 2412 MHz [1] (disabled)"));
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            wifi.configureRuntimeCapture("scan", "lab0mon", null, null, 13, false);
            var sniper = wifi.startSniperBySsid("Fixture").run();
            assertEquals(0, sniper.sweepChannelCount());
            assertTrue(sniper.initialSweepComplete());
            await(() -> wifi.getChannelSnapshot().scanner().tick() >= 4);
            var report = new ObjectMapper().readTree(get(client, server, "/api/lookout").body());
            assertTrue(report.path("channels").isEmpty());
            assertTrue(report.path("counts").isEmpty());
            assertEquals(0, tuneAttempts.get());
        }
    }
    @Test void servesInventoryAndAdaptiveChannelsFromOneMonitorCapture() throws Exception {
        var capture = new StreamingCaptureProcess();
        var tune = new StreamingCaptureProcess();
        var retunes = new LinkedBlockingQueue<List<String>>();
        try (var wifi = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("tcpdump")) return capture;
            retunes.add(List.copyOf(builder.command()));
            return tune;
        }, Map.of());
             var server = new PassiveRfServer(wifi);
             var client = HttpClient.newHttpClient()) {
            var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71));
            wifi.startPassive("lab0mon", false, scanner);
            server.start(0);
            byte[] packet = ProbeFrames.radiotap(ProbeFrames.frame("Fixture"));
            byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, true, 127, packet);
            ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN).putInt(24, (int) (System.currentTimeMillis() / 1000));
            capture.write(pcap);
            assertNotNull(retunes.poll(3, TimeUnit.SECONDS));
            await(() -> wifi.getChannelSnapshot().scanner().counts()[5] == 1);
            var mapper = new ObjectMapper();
            assertEquals(1, mapper.readTree(get(client, server, "/api/inventory").body()).size());
            var channels = mapper.readTree(get(client, server, "/api/channels").body());
            assertEquals(13, channels.path("channels").size());
            assertEquals(6, channels.at("/radio/lastObservedChannel").asInt());
            var coverage = channels.at("/radio/coverage");
            assertEquals(13, coverage.size());
            assertEquals(6, coverage.at("/5/channel").asInt());
            assertTrue(coverage.at("/5/lastFrameAtMs").isNumber());
            assertTrue(coverage.at("/5/lastTuneAtMs").isNull());
            assertTrue(coverage.at("/5/lastFrameWhileTunedAtMs").isNull());
            assertTrue(coverage.at("/0/lastFrameAtMs").isNull());
            assertEquals(1, channels.path("counts").get(5).asInt());
            assertEquals(0, channels.path("counts").get(0).asInt());

            tune.finish();
            await(() -> wifi.getChannelSnapshot().radio().successfulRetunes() > 0);
            var tuned = mapper.readTree(get(client, server, "/api/channels").body());
            assertTrue(tuned.at("/radio/lastConfirmedChannel").isIntegralNumber());
            assertTrue(tuned.at("/radio/meanRetuneMs").asDouble() >= 0);
            int confirmed = tuned.at("/radio/lastConfirmedChannel").asInt();
            var confirmedCoverage = tuned.at("/radio/coverage").get(confirmed - 1);
            assertTrue(confirmedCoverage.path("lastTuneAtMs").isNumber());
            if (confirmed != 6) assertTrue(confirmedCoverage.path("lastFrameAtMs").isNull());
            assertEquals(coverage.at("/5/lastFrameAtMs"), tuned.at("/radio/coverage/5/lastFrameAtMs"));
            assertTrue(confirmedCoverage.path("lastFrameWhileTunedAtMs").isNull());

            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            var radio = wifi.getChannelSnapshot().radio();
            while (radio.coverage().stream().noneMatch(entry -> entry.lastFrameWhileTunedAtMs() != null)
                    && System.nanoTime() < deadline) {
                int listenChannel = radio.lastConfirmedChannel();
                byte[] frame = ProbeFrames.radiotap(ProbeFrames.frame("Fixture"));
                ByteBuffer.wrap(frame).order(ByteOrder.LITTLE_ENDIAN)
                        .putShort(8, PacketBridge.channelFrequencyMhz(listenChannel).shortValue());
                byte[] more = timedPcap(frame, true);
                capture.write(java.util.Arrays.copyOfRange(more, 24, more.length));
                Thread.sleep(20);
                radio = wifi.getChannelSnapshot().radio();
            }
            assertTrue(radio.coverage().stream().anyMatch(entry -> entry.lastFrameWhileTunedAtMs() != null));
        }
    }

    @Test void streamsBinaryCapturesToReadOnlyReportsWithoutLegacyEventsOrRawIdentifiers() throws Exception {
        var wifiProcess = new StreamingCaptureProcess();
        try (var wifi = new PacketBridge(builder -> {
            assertEquals(List.of("tcpdump", "-i", "lab0mon", "-y", "IEEE802_11_RADIO", "-U", "-s",
                    "0", "-n", "-w", "-", "type mgt or type data"), builder.command());
            return wifiProcess;
        }, Map.of());
             var server = new PassiveRfServer(wifi);
             var client = HttpClient.newHttpClient()) {
            wifi.startPassive("lab0mon");
            server.start(0);
            long now = System.currentTimeMillis();
            byte[] packet = ProbeFrames.radiotap(ProbeFrames.frame("PrivateLabSSID"));
            byte[] general = ProbeFrames.radiotap(ProbeFrames.frame(""));
            byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, true, 127, packet, general);
            ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN)
                    .putInt(24, (int) (now / 1000)).putInt(40 + packet.length, (int) (now / 1000));
            wifiProcess.write(pcap);
            await(() -> wifi.getCaptureStatus().get("probeRequests").equals(2L));

            var mapper = new ObjectMapper();
            var inventory = get(client, server, "/api/inventory");
            var audit = get(client, server, "/api/probe-audit");
            for (var response : List.of(inventory, audit)) {
                assertEquals(200, response.statusCode());
                assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
                assertFalse(response.body().contains("02:11:22:33:44:55"));
            }
            assertFalse(inventory.body().contains("PrivateLabSSID"));
            assertEquals(1, mapper.readTree(inventory.body()).size());
            var report = mapper.readTree(audit.body());
            assertEquals("PrivateLabSSID", report.at("/corpus/0/name").asText());
            assertEquals(1, report.at("/corpus/0/deviceCount").asInt());
            assertEquals(2, report.path("totalProbes").asInt());
            assertEquals(1, report.path("directedProbes").asInt());
            assertEquals(1, report.path("distinctDirectedSsids").asInt());
            assertEquals(404, get(client, server, "/").statusCode());
            assertEquals(404, get(client, server, "/api/attack/scan-lan").statusCode());
            assertEquals(404, get(client, server, "/api/probes").statusCode());
            assertTrue(wifi.getEventQueue().isEmpty());
            assertTrue(wifi.getProfiler().all().isEmpty());
        }
    }

    @Test void watchesAnObservedAccessPointThroughThePassiveHttpApi() throws Exception {
        var process = new StreamingCaptureProcess();
        try (var wifi = new PacketBridge(builder -> process, Map.of());
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            String endpoint = "/api/channels/watch";
            String bssid = "00:11:22:33:44:55";
            String body = "{\"apId\":\"%s\"}";
            assertEquals(409, post(client, server, endpoint, body.formatted("unknown")).statusCode());

            wifi.startPassive("lab0mon");
            byte[] channelSix = beacon("001122334455", "Fixture Lab");
            byte[] channelOne = channelSix.clone();
            ByteBuffer.wrap(channelOne).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) 2412);
            process.write(timedPcap(channelSix));
            String token = wifi.getPassiveWifi().addressId(bssid);
            await(() -> wifi.getPassiveWifi().observedBssid(token) != null);
            assertEquals(400, post(client, server, endpoint, body.formatted("unknown")).statusCode());
            var started = post(client, server, endpoint, body.formatted(token));
            assertEquals(200, started.statusCode(), started.body());
            assertFalse(started.body().contains(bssid));
            assertEquals(409, post(client, server, endpoint, body.formatted(token)).statusCode());

            byte[] initial = timedPcap(channelSix);
            process.write(java.util.Arrays.copyOfRange(initial, 24, initial.length));
            await(() -> wifi.apWatchState().run().lastHeard() != null);
            Thread.sleep(5);
            byte[] moved = timedPcap(channelOne);
            process.write(java.util.Arrays.copyOfRange(moved, 24, moved.length));
            await(() -> wifi.apWatchState().run().heardAgain() != null);

            var response = get(client, server, endpoint);
            var report = new ObjectMapper().readTree(response.body());
            assertFalse(response.body().contains(bssid));
            assertEquals(token, report.at("/run/apId").asText());
            assertEquals(6, report.at("/run/lastHeard/channel").asInt());
            assertEquals(1, report.at("/run/heardAgain/channel").asInt());
            assertTrue(report.at("/run/tuned").isNull());
            assertTrue(report.at("/run/endedAt").isNumber());
        }
    }

    private static byte[] timedPcap(byte[] packet) { return timedPcap(packet, false); }

    private static byte[] timedPcap(byte[] packet, boolean nanos) {
        long now = System.currentTimeMillis();
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, nanos, 127, packet);
        ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(24, (int) (now / 1000)).putInt(28, (int) (now % 1000) * (nanos ? 1_000_000 : 1_000));
        return pcap;
    }

    @Test void enrollsObservedApAndPinsDeviceWithoutExposingAddresses(@TempDir Path temp) throws Exception {
        Path file = temp.resolve("my-network.json");
        String previous = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", file.toString());
        try {
            var process = new StreamingCaptureProcess();
            try (var wifi = new PacketBridge(builder -> process, Map.of());
                 var server = new PassiveRfServer(wifi).start(0);
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
                 var server = new PassiveRfServer(wifi).start(0);
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
                var profilerDetail = get(client, server, "/api/profiler/" + device.id());
                assertEquals(200, profilerDetail.statusCode());
                assertFalse(profilerDetail.body().contains("02:11:22:33:44:55"));
                var enriched = mapper.readTree(profilerDetail.body());
                assertEquals("Fixture phone", enriched.path("enrolledLabel").asText());
                assertEquals(mapper.readTree("[\"1\",\"50\",\"221\"]"), enriched.at("/fingerprints/0/ieOrder"));
                assertEquals("00:11:22:01", enriched.at("/fingerprints/0/vendorElements/0").asText());
                assertEquals(400, post(client, server, "/api/fingerprint-samples",
                        sample.replace("PROBE_REQUEST", "PROBE_RESPONSE")).statusCode());
                var saved = post(client, server, "/api/fingerprint-samples", sample);
                assertEquals(200, saved.statusCode(), saved.body());
                assertEquals(saved.body(), post(client, server, "/api/fingerprint-samples", sample).body());
                var exported = get(client, server, "/api/fingerprint-samples");
                assertEquals(saved.body(), exported.body());
                for (String privateData : List.of("02:11:22:33:44:55", device.id(), "PrivateFixture", "Fixture phone"))
                    assertFalse(exported.body().contains(privateData));
                var hint = wifi.getPassiveWifi().inventory().getFirst().fingerprintHint();
                assertEquals("Phone", hint.family());
                assertEquals("Fixture OS", hint.osHint());
                assertEquals("Phone", wifi.getPassiveWifi().inventory().getFirst().classLabel());
                var profiler = get(client, server, "/api/profiler");
                assertFalse(profiler.body().contains("02:11:22:33:44:55"));
                assertEquals("SAVED_SAMPLE", mapper.readTree(profiler.body()).at("/0/classificationBasis").asText());
                assertEquals("Fixture phone", mapper.readTree(profiler.body()).at("/0/enrolledLabel").asText());
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
                assertNull(wifi.getPassiveWifi().inventory().getFirst().fingerprintHint());
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
                List.of("other-capture", "lab0mon"), "lab0mon"));
        assertThrows(IllegalArgumentException.class, () -> PassiveCommandGuard.requireWifi(
                PassiveCommandGuard.monitor("-bad"), "-bad"));
    }

    @Test void ignoresSixGhzChannelOneInTwoFourGhzScannerWhilePreservingInventoryHealthAndFiveGhzReplay(@TempDir Path dir)
            throws Exception {
        var capture = new StreamingCaptureProcess();
        var tunes = new LinkedBlockingQueue<List<String>>();
        try (var wifi = new PacketBridge(builder -> {
            if (builder.command().getFirst().equals("tcpdump")) return capture;
            tunes.add(List.copyOf(builder.command()));
            return new ewave.fixtures.CompletedProcess("", 0);
        }, Map.of());
             var server = new PassiveRfServer(wifi).start(0);
             var client = HttpClient.newHttpClient()) {
            var scanner = new AdaptiveScanner(AdaptiveScanner.Config.defaults(13, 128, 71));
            wifi.startPassive("lab0mon", false, scanner);

            byte[] sixGhz = beacon("001122334455", "SixGhz Lab");
            ByteBuffer.wrap(sixGhz).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) 5955);
            capture.write(timedPcap(sixGhz));
            await(() -> wifi.getCaptureHealth().decoded() == 1);

            var mapper = new ObjectMapper();
            var firstChannels = mapper.readTree(get(client, server, "/api/channels").body());
            assertEquals(0L, firstChannels.path("counts").get(0).asLong());
            assertTrue(firstChannels.at("/radio/lastObservedChannel").isNull());
            assertTrue(firstChannels.at("/radio/coverage/0/lastFrameAtMs").isNull());
            assertEquals(1, wifi.getPassiveWifi().inventory().size());
            var sixHealth = wifi.getCaptureHealth();
            assertEquals(5955, sixHealth.observedFrequencyMhz());
            assertEquals(1, sixHealth.observedChannel());

            byte[] twoFourGhz = beacon("001122334466", "TwoFourGhz Lab");
            ByteBuffer.wrap(twoFourGhz).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) 2412);
            byte[] nextRecord = timedPcap(twoFourGhz);
            capture.write(java.util.Arrays.copyOfRange(nextRecord, 24, nextRecord.length));
            await(() -> wifi.getChannelSnapshot().scanner().counts()[0] == 1);

            var secondChannels = mapper.readTree(get(client, server, "/api/channels").body());
            assertEquals(1L, secondChannels.path("counts").get(0).asLong());
            assertEquals(1, secondChannels.at("/radio/lastObservedChannel").asInt());
            assertTrue(secondChannels.at("/radio/coverage/0/lastFrameAtMs").isNumber());

            wifi.stop();
            byte[] fiveGhz = beacon("001122334477", "FiveGhz Lab");
            ByteBuffer.wrap(fiveGhz).order(ByteOrder.LITTLE_ENDIAN).putShort(8, (short) 5500);
            Path fiveGhzPcap = dir.resolve("5ghz.pcap");
            Files.write(fiveGhzPcap, timedPcap(fiveGhz));
            wifi.startReplay(fiveGhzPcap);
            await(() -> !wifi.isRunning());
            assertEquals(5500, wifi.getCaptureHealth().observedFrequencyMhz());
            assertEquals(100, wifi.getCaptureHealth().observedChannel());
        }
    }

    @Test void enforcesOriginHandlesProfileErrorsClearsClientsOnScopeChangeAndStopsReplayCleanly(@TempDir Path temp)
            throws Exception {
        Path profileDir = Files.createDirectories(temp.resolve("cfg"));
        Path profile = profileDir.resolve("my-network.json");
        String previous = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", profile.toString());
        try {
            // 1. Corrupt profile JSON fails cleanly over HTTP without uncaught crashes.
            Files.writeString(profile, "{corrupt json");
            try (var wifi = new PacketBridge();
                 var server = new PassiveRfServer(wifi).start(0);
                 var client = HttpClient.newHttpClient()) {
                assertEquals(500, get(client, server, "/api/my-network").statusCode());
                assertEquals(500, get(client, server, "/api/fingerprint-samples").statusCode());
                var badOrigin = client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.port() + "/api/my-network"))
                        .header("Origin", "https://foreign.example").GET().build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(403, badOrigin.statusCode());
            }

            // 2. Old profile format without fingerprintSamples loads; failed save preserves usable state;
            //    mid-session scope change clears previously observed client associations.
            Files.writeString(profile, "{\"accessPoints\":[],\"devices\":[],\"restrictCapture\":false}");
            var process = new StreamingCaptureProcess();
            var mapper = new ObjectMapper();
            try (var wifi = new PacketBridge(builder -> process, Map.of());
                 var server = new PassiveRfServer(wifi).start(0);
                 var client = HttpClient.newHttpClient()) {
                wifi.startPassive("lab0mon");
                byte[] home = beacon("001122334455", "Scope Home");
                byte[] nearby = beacon("00aabbccddee", "Scope Nearby");
                byte[] assoc = assocResponse("00aabbccddee", "021122334455");
                byte[] initialPcap = timedPcap(home);
                process.write(initialPcap);
                byte[] rec2 = timedPcap(nearby);
                byte[] rec3 = timedPcap(assoc);
                process.write(java.util.Arrays.copyOfRange(rec2, 24, rec2.length));
                process.write(java.util.Arrays.copyOfRange(rec3, 24, rec3.length));
                await(() -> wifi.getPassiveWifi().observedClient(wifi.getPassiveWifi().addressId("02:11:22:33:44:55")) != null);
                String clientToken = wifi.getPassiveWifi().addressId("02:11:22:33:44:55");

                String homeToken = wifi.getPassiveWifi().addressId("00:11:22:33:44:55");
                assertEquals(200, post(client, server, "/api/my-network",
                        "{\"action\":\"save-ap\",\"observedId\":\"" + homeToken + "\",\"label\":\"My Home\"}").statusCode());
                assertEquals(200, post(client, server, "/api/my-network",
                        "{\"action\":\"scope\",\"restricted\":true}").statusCode());
                assertNull(wifi.getPassiveWifi().observedClient(clientToken));

                // Block directory writes to simulate save failure and confirm previous usable state remains.
                Files.setPosixFilePermissions(profileDir, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
                try {
                    var failedSave = post(client, server, "/api/my-network",
                            "{\"action\":\"scope\",\"restricted\":false}");
                    assertEquals(500, failedSave.statusCode());
                    assertFalse(mapper.readTree(failedSave.body()).path("error").asText().isBlank());
                    var current = mapper.readTree(get(client, server, "/api/my-network").body());
                    assertTrue(current.path("restrictCapture").asBoolean());
                    assertEquals("My Home", current.at("/accessPoints/0/label").asText());
                } finally {
                    Files.setPosixFilePermissions(profileDir, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
                }

                // 3. Stopping replay mid-stream yields STOPPED state cleanly without error.
                byte[] samplePacket = ProbeFrames.radiotap(ProbeFrames.frame("Bulk"));
                byte[] oneRec = timedPcap(samplePacket);
                byte[] recordOnly = java.util.Arrays.copyOfRange(oneRec, 24, oneRec.length);
                Path bulkPcap = temp.resolve("bulk.pcap");
                try (var out = Files.newOutputStream(bulkPcap)) {
                    out.write(java.util.Arrays.copyOf(oneRec, 24));
                    for (int i = 0; i < 60_000; i++) out.write(recordOnly);
                }
                wifi.stop();
                wifi.startReplay(bulkPcap);
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (wifi.getCaptureHealth().decoded() == 0 && System.nanoTime() < deadline) Thread.onSpinWait();
                wifi.stop();
                var stopped = wifi.getCaptureHealth();
                assertFalse(wifi.isRunning());
                assertEquals("STOPPED", stopped.replayState());
                assertNull(stopped.error());
            }
        } finally {
            restoreProperty("rf.networkProfile", previous);
        }
    }

    private static byte[] assocResponse(String ap, String client) {
        byte[] apMac = HexFormat.of().parseHex(ap), cliMac = HexFormat.of().parseHex(client);
        var frame = ByteBuffer.allocate(30).order(ByteOrder.LITTLE_ENDIAN);
        frame.putShort((short) 0x0010).putShort((short) 0)
                .put(cliMac).put(apMac).put(apMac)
                .putShort((short) 0x0010).putShort((short) 1).putShort((short) 0).putShort((short) 1);
        return ProbeFrames.radiotap(frame.array());
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
