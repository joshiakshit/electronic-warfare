package ewave.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ewave.active.BeaconFlood;
import ewave.active.EvilTwin;
import ewave.active.FrameInjector;
import ewave.active.HandshakeAnalyzer;
import ewave.active.LanScanner;
import ewave.active.PmkidCapture;
import ewave.active.WifiAccessPoints;
import ewave.decoder.Dot11Frame;
import ewave.decoder.Dot11FrameDecoder;
import ewave.fixtures.CompletedProcess;
import ewave.fixtures.ProbeFrames;
import ewave.fixtures.StreamingCaptureProcess;
import ewave.model.AttackResult;
import ewave.passive.DeviceProfiler;
import ewave.passive.PassiveWifiSession;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

@Timeout(20)
class RadioCoordinationTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String AP_MAC = "00:11:22:33:44:55";
    private static final String CLIENT_MAC = "02:aa:bb:cc:dd:01";
    private static final String UNLINKED_MAC = "02:11:22:33:44:55";

    @Test void sharesOwnershipAcrossVirtualInterfacesOnSamePhysicalRadioAndCoordinatesPendingRetune(@TempDir Path dir)
            throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var capture = new StreamingCaptureProcess();
            var retuneStarted = new CountDownLatch(1);
            var allowRetuneFinish = new CountDownLatch(1);
            try (var bridge = new PacketBridge(builder -> {
                if (builder.command().getFirst().equals("tcpdump")) return capture;
                retuneStarted.countDown();
                return new BlockingProcess(allowRetuneFinish);
            }, Map.of(), new DeviceProfiler(), 20, 64, 64,
                    iface -> null, iface -> iface.startsWith("wlo1") ? "phy0" : iface)) {
                var scanner = new ewave.core.AdaptiveScanner(ewave.core.AdaptiveScanner.Config.defaults(13, 128, 7L));
                bridge.startPassive("wlo1", true, scanner);

                assertTrue(retuneStarted.await(5, TimeUnit.SECONDS), "Adaptive capture should start an initial retune");

                var leaseAcquired = new CountDownLatch(1);
                var leaseRef = new AtomicReference<PacketBridge.OpsLease>();
                var executor = Executors.newSingleThreadExecutor();
                try {
                    executor.submit(() -> {
                        leaseRef.set(bridge.acquireOpsLease("wlo1ap", false));
                        leaseAcquired.countDown();
                    });
                    // Must wait while iw tune is still running before granting the radio lease.
                    assertFalse(leaseAcquired.await(80, TimeUnit.MILLISECONDS));
                    allowRetuneFinish.countDown();
                    assertTrue(leaseAcquired.await(5, TimeUnit.SECONDS));

                    // Same physical radio (wlo1 and wlo1ap -> phy0) must reject a second concurrent lease.
                    assertThrows(IllegalStateException.class, () -> bridge.acquireOpsLease("wlo1", false));

                    // Different physical radio can acquire independently.
                    try (var secondRadio = bridge.acquireOpsLease("wlan1", false)) {
                        assertNotNull(secondRadio);
                    }

                    leaseRef.get().close();
                    try (var reacquired = bridge.acquireOpsLease("wlo1", false)) {
                        assertNotNull(reacquired);
                    }
                } finally {
                    allowRetuneFinish.countDown();
                    executor.shutdownNow();
                }
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    @Test void failedOrCancelledOpsReleasesLeaseAndDoesNotResumeCancelledSniper(@TempDir Path dir) throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var captureStreams = new CopyOnWriteArrayList<StreamingCaptureProcess>();
            var tuneCommands = new CopyOnWriteArrayList<List<String>>();
            try (var bridge = new PacketBridge(builder -> {
                if (builder.command().getFirst().equals("tcpdump")) {
                    var proc = new StreamingCaptureProcess();
                    captureStreams.add(proc);
                    return proc;
                }
                tuneCommands.add(List.copyOf(builder.command()));
                return new CompletedProcess("", 0);
            }, Map.of(), new DeviceProfiler(), 20, 64, 64,
                    iface -> null, iface -> iface.startsWith("lab0") ? "phy0" : iface)) {
                bridge.startPassive("lab0mon", true, null);
                assertEquals(1, captureStreams.size());
                writeFrames(captureStreams.getFirst(), 2437, rawBeacon(AP_MAC, "ewave lab".getBytes(StandardCharsets.UTF_8), 6),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 1),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 2),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 3));

                awaitCondition(() -> bridge.getPassiveWifi() != null
                        && !bridge.getPassiveWifi().findAccessPoints("ewave lab").isEmpty()
                        && !bridge.getPassiveWifi().evidencedTargets(bridge.getProfiler()).isEmpty());
                String apId = bridge.getPassiveWifi().findAccessPoints("ewave lab").getFirst();
                bridge.startSniperByApId(apId);
                assertEquals(SniperController.State.LOCKED, bridge.sniperState().run().state());
                assertEquals(2437, bridge.sniperState().run().lockedFrequencyMhz());

                Path wordlist = dir.resolve("words.txt");
                Files.writeString(wordlist, "password123\n");
                Path apCache = dir.resolve("wifi-aps.txt");
                Files.writeString(apCache, "ewave lab:" + AP_MAC.replace(":", "\\:") + ":6:2437 MHz\n");
                var pmkidStarted = new CountDownLatch(1);
                var pmkidRelease = new CountDownLatch(1);

                try (var server = new PassiveRfServer(bridge, true,
                        iface -> new FrameInjector(iface, builder -> new CompletedProcess("Inject failed", 1)),
                        new LanScanner(), new WifiAccessPoints(apCache),
                        s -> new HandshakeAnalyzer(s.monitorInterface(), s.apBssid(), s.clientMac(), s.channel(), s.frequencyMhz()),
                        s -> new PmkidCapture(s.monitorInterface(), dir.resolve("pmkid-cap").toString(), builder -> {
                            pmkidStarted.countDown();
                            if (builder.command().stream().anyMatch(arg -> arg.contains("hcxdumptool"))) {
                                return new BlockingProcess(pmkidRelease);
                            }
                            return new CompletedProcess("no pmkid", 1);
                        }),
                        s -> new BeaconFlood(s.monitorInterface(), builder -> {
                            throw new java.io.IOException("Simulated mdk4 unavailable");
                        }),
                        s -> new EvilTwin(s.apInterface(), s.ssid(), s.channel(), s.portalPort())).start(0);
                     var client = HttpClient.newHttpClient()) {

                    String baseUrl = "http://127.0.0.1:" + server.port();

                    // 1. Failing deauth HTTP op must release the lease cleanly and restore Sniper lock.
                    tuneCommands.clear();
                    var deauthRes = postJson(client, baseUrl + "/api/ops/deauth",
                            "{\"apBssid\":\"" + AP_MAC + "\",\"clientMac\":\"" + CLIENT_MAC + "\",\"count\":2,\"interface\":\"lab0ap\"}");
                    assertEquals(200, deauthRes.statusCode(), deauthRes.body());
                    assertFalse(JSON.readTree(deauthRes.body()).path("success").asBoolean());
                    awaitCondition(() -> tuneCommands.stream().anyMatch(cmd -> cmd.contains("2437")));
                    assertEquals(SniperController.State.LOCKED, bridge.sniperState().run().state());

                    // 2. Failing beacon start must immediately release lease (another op can run next).
                    var beaconRes = postJson(client, baseUrl + "/api/ops/beacon",
                            "{\"interface\":\"lab0ap\",\"ssid\":\"lab\",\"channel\":6,\"rate\":10}");
                    assertEquals(500, beaconRes.statusCode());

                    // 3. PMKID pauses monitor capture, Sniper is cancelled mid-PMKID -> must NOT resume on finish.
                    var executor = Executors.newSingleThreadExecutor();
                    try {
                        var future = executor.submit(() -> postJson(client, baseUrl + "/api/ops/pmkid",
                                "{\"interface\":\"lab0mon\",\"wordlistPath\":\"" + wordlist + "\",\"durationSeconds\":5}"));
                        assertTrue(pmkidStarted.await(5, TimeUnit.SECONDS));

                        // Cancel Sniper over HTTP while Ops owns the radio.
                        var delReq = HttpRequest.newBuilder(URI.create(baseUrl + "/api/sniper")).DELETE().build();
                        var delRes = client.send(delReq, HttpResponse.BodyHandlers.ofString());
                        assertEquals(200, delRes.statusCode());
                        assertEquals(SniperController.State.IDLE, bridge.sniperState().run().state());

                        tuneCommands.clear();
                        pmkidRelease.countDown();
                        future.get(5, TimeUnit.SECONDS);

                        // Monitor capture resumes with a new tcpdump process & preserves PassiveWifiSession,
                        // while Sniper remains IDLE and does NOT lock back to 2437.
                        awaitCondition(() -> captureStreams.size() == 2 && bridge.isRunning());
                        assertEquals(SniperController.State.IDLE, bridge.sniperState().run().state());
                        assertFalse(bridge.getPassiveWifi().findAccessPoints("ewave lab").isEmpty());
                    } finally {
                        pmkidRelease.countDown();
                        executor.shutdownNow();
                    }
                }
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    @Test void buildsEvidencedOpsTargetsExcludingUnlinkedApBeaconsAndReturnsEmptyForReplay(@TempDir Path dir)
            throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var clock = new AtomicLong(System.currentTimeMillis() - 1_000L);
            var profiler = new DeviceProfiler();
            var live = new PassiveWifiSession(profiler, ewave.passive.MyNetworkProfile.EMPTY);

            byte[] beaconRaw = rawBeacon(AP_MAC, "ewave lab".getBytes(StandardCharsets.UTF_8), 6);
            Dot11Frame beacon = Dot11FrameDecoder.decodeAny(ProbeFrames.radiotap(beaconRaw), 127, clock.get());
            assertNotNull(beacon);
            live.observe(beacon);

            // Confirmed client-to-AP ToDS data frames (3 distinct sequences satisfy topology.minEvidence=3)
            for (int seq = 1; seq <= 3; seq++) {
                byte[] toDsRaw = rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", seq);
                Dot11Frame dataFrame = Dot11FrameDecoder.decodeAny(
                        ProbeFrames.radiotap(toDsRaw), 127, clock.addAndGet(100));
                assertNotNull(dataFrame);
                live.observe(dataFrame);
            }

            // Unassociated probe request from another device (must NOT appear as an evidenced client target)
            Dot11Frame probe = Dot11FrameDecoder.decodeAny(
                    ProbeFrames.radiotap(ProbeFrames.frame("GuestWifi")), 127, clock.addAndGet(100));
            assertNotNull(probe);
            live.observe(probe);

            var targets = live.evidencedTargets(profiler);
            assertEquals(1, targets.size());
            var target = targets.getFirst();
            assertEquals(CLIENT_MAC, target.mac());
            assertEquals(AP_MAC, target.apBssid());
            assertEquals("ewave lab", target.apSsid());
            assertEquals(6, target.channel());
            assertEquals(2437, target.frequencyMhz());
            assertNotNull(target.evidenceSource());
            assertNotNull(target.sessionId());
            assertTrue(targets.stream().noneMatch(t -> t.mac().equals(AP_MAC) || t.mac().equals(UNLINKED_MAC)));

            // Replay session must return empty Ops targets even with identical evidenced traffic.
            var replay = PassiveWifiSession.forReplay(profiler, ewave.passive.MyNetworkProfile.EMPTY, clock::get);
            replay.observe(beacon);
            for (int seq = 1; seq <= 3; seq++) {
                replay.observe(Dot11FrameDecoder.decodeAny(
                        ProbeFrames.radiotap(rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", seq)),
                        127, clock.addAndGet(100)));
            }
            assertTrue(replay.isReplaySession());
            assertTrue(replay.evidencedTargets(profiler).isEmpty());
        } finally {
            restoreProfileProperty(prev);
        }
    }

    @Test void deauthUsesALiveEvidencedTargetWithoutAnApCache(@TempDir Path dir) throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var captureStreams = new CopyOnWriteArrayList<StreamingCaptureProcess>();
            var injectorCommands = new CopyOnWriteArrayList<List<String>>();
            try (var bridge = new PacketBridge(builder -> {
                if (builder.command().getFirst().equals("tcpdump")) {
                    var proc = new StreamingCaptureProcess();
                    captureStreams.add(proc);
                    return proc;
                }
                return new CompletedProcess("", 0);
            }, Map.of(), new DeviceProfiler(), 20, 64, 64, iface -> null, iface -> "phy0");
                 var server = new PassiveRfServer(bridge, true, monitor -> new FrameInjector(monitor, builder -> {
                     injectorCommands.add(List.copyOf(builder.command()));
                     return new CompletedProcess("injected\n", 0);
                 }), new LanScanner(dir.resolve("missing-lan")),
                         new WifiAccessPoints(dir.resolve("missing-aps"))).start(0);
                 var client = HttpClient.newHttpClient()) {
                String base = "http://127.0.0.1:" + server.port();
                var start = postJson(client, base + "/api/capture/start",
                        "{\"mode\":\"watch\",\"interface\":\"lab0mon\",\"channel\":6,\"band\":\"2.4\"}");
                assertEquals(200, start.statusCode(), start.body());

                byte[] beacon = rawBeacon(AP_MAC, "ewave lab".getBytes(StandardCharsets.UTF_8), 6);
                writeFrames(captureStreams.getFirst(), 2437, beacon,
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 1),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 2),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 3));
                awaitCondition(() -> bridge.getPassiveWifi() != null
                        && !bridge.getPassiveWifi().evidencedTargets(bridge.getProfiler()).isEmpty());

                var targets = JSON.readTree(get(client, base + "/api/ops/targets").body());
                assertEquals(1, targets.size());
                String targetId = targets.at("/0/id").asText();
                var response = postJson(client, base + "/api/ops/deauth",
                        "{\"targetId\":\"" + targetId + "\",\"count\":2,\"interface\":\"lab0mon\"}");
                assertEquals(200, response.statusCode(), response.body());
                var result = JSON.readTree(response.body());
                assertTrue(result.path("success").asBoolean(), response.body());
                assertEquals("deauth", result.path("attackType").asText());
                assertEquals(List.of("sudo", "iw", "dev", "lab0mon", "set", "freq", "2437"),
                        injectorCommands.get(0));
                assertEquals(List.of("sudo", "aireplay-ng", "--ignore-negative-one", "--deauth", "2",
                        "-a", AP_MAC, "-c", CLIENT_MAC, "lab0mon"), injectorCommands.get(1));

                var capabilities = JSON.readTree(get(client, base + "/api/ops/capabilities").body());
                assertEquals(7, capabilities.path("operations").size());
                assertFalse(capabilities.at("/caches/accessPoints/available").asBoolean());
                assertFalse(capabilities.at("/caches/lanHosts/available").asBoolean());
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    @Test void runtimeCaptureControlAndModuleEndpointsWorkEndToEnd(@TempDir Path dir) throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var captureStreams = new CopyOnWriteArrayList<StreamingCaptureProcess>();
            var tuneCommands = new CopyOnWriteArrayList<List<String>>();
            try (var bridge = new PacketBridge(builder -> {
                if (builder.command().getFirst().equals("tcpdump")) {
                    var proc = new StreamingCaptureProcess();
                    captureStreams.add(proc);
                    return proc;
                }
                tuneCommands.add(List.copyOf(builder.command()));
                return new CompletedProcess("", 0);
            }, Map.of("001122", "TestRouter"), new DeviceProfiler(), 20, 64, 64,
                    iface -> null, iface -> "phy0");
                 var passiveServer = new PassiveRfServer(bridge, false).start(0);
                 var opsServer = new PassiveRfServer(bridge, true).start(0);
                 var client = HttpClient.newHttpClient()) {

                String opsBase = "http://127.0.0.1:" + opsServer.port();
                String passiveBase = "http://127.0.0.1:" + passiveServer.port();

                // Passive server blocks /api/ops/* while exposing module analysis views
                assertEquals(404, get(client, passiveBase + "/api/ops/status").statusCode());
                assertEquals(200, get(client, opsBase + "/api/ops/status").statusCode());

                // Start live watch capture on ch 6 (2.4 GHz)
                var startWatch = postJson(client, opsBase + "/api/capture/start",
                        "{\"mode\":\"watch\",\"interface\":\"lab0mon\",\"channel\":6,\"band\":\"2.4\"}");
                assertEquals(200, startWatch.statusCode());
                assertTrue(tuneCommands.stream().anyMatch(cmd -> cmd.contains("2437")));
                writeFrames(captureStreams.getFirst(), 2437, rawBeacon(AP_MAC, "ewave lab".getBytes(StandardCharsets.UTF_8), 6),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 1),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 2),
                        rawToDsData(AP_MAC, CLIENT_MAC, "ff:ff:ff:ff:ff:ff", 3));
                awaitCondition(() -> bridge.getPassiveWifi() != null
                        && !bridge.getPassiveWifi().topology().accessPoints().isEmpty());

                // Tune runtime channel to ch 11 (2462 MHz) and keep session
                tuneCommands.clear();
                var retuneRes = postJson(client, opsBase + "/api/capture/channel",
                        "{\"channel\":11,\"band\":\"2.4\"}");
                assertEquals(200, retuneRes.statusCode());
                assertTrue(tuneCommands.stream().anyMatch(cmd -> cmd.contains("2462")));
                assertEquals(1, JSON.readTree(get(client, opsBase + "/api/inspector").body())
                        .path("accessPoints").size());

                // Invalid replay request must fail with 400 BEFORE stopping active live capture!
                var badReplay = postJson(client, opsBase + "/api/capture/start",
                        "{\"mode\":\"replay\",\"replayPath\":\"" + dir.resolve("missing.pcap") + "\"}");
                assertEquals(400, badReplay.statusCode());
                assertTrue(bridge.isRunning());

                var busyStart = postJson(client, opsBase + "/api/capture/start",
                        "{\"mode\":\"scan\",\"interface\":\"lab0mon\",\"requireIdle\":true}");
                assertEquals(409, busyStart.statusCode());
                assertEquals("watch", bridge.getCaptureStatus().get("captureMode"));

                // Switch watch -> scan on same interface preserves AP observations in /api/inspector and attaches Lookout
                var switchScan = postJson(client, opsBase + "/api/capture/start",
                        "{\"mode\":\"scan\",\"interface\":\"lab0mon\"}");
                assertEquals(200, switchScan.statusCode());
                assertEquals("scan", JSON.readTree(switchScan.body()).path("captureMode").asText());
                assertEquals(1, JSON.readTree(get(client, opsBase + "/api/inspector").body())
                        .path("accessPoints").size());

                // Verify module-aligned endpoints on shared state
                for (String path : List.of("/api/capture/health", "/api/capture/access-points", "/api/sniper", "/api/spotter",
                        "/api/whistleblower", "/api/decloaker", "/api/decloaker/demo", "/api/inspector",
                        "/api/profiler", "/api/profiler/network", "/api/profiler/fingerprints",
                        "/api/tracker", "/api/lookout", "/api/lookout/demo", "/api/ops/targets")) {
                    var res = get(client, opsBase + path);
                    assertEquals(200, res.statusCode(), "Expected 200 for " + path);
                }

                // Sniper HTTP lifecycle
                var startSniper = postJson(client, opsBase + "/api/sniper", "{\"ssid\":\"ewave lab\"}");
                assertEquals(200, startSniper.statusCode());
                assertEquals("SEARCHING", JSON.readTree(startSniper.body()).path("run").path("state").asText());
                var stopSniper = client.send(HttpRequest.newBuilder(URI.create(opsBase + "/api/sniper"))
                        .DELETE().build(), HttpResponse.BodyHandlers.ofString());
                assertEquals(200, stopSniper.statusCode());
                assertEquals("IDLE", JSON.readTree(stopSniper.body()).path("run").path("state").asText());

                // Switch to valid replay -> resets session cleanly & clears Ops targets
                Path replayPcap = Path.of("src/test/resources/probes/probe-requests.pcap");
                var startReplay = postJson(client, opsBase + "/api/capture/start",
                        "{\"mode\":\"replay\",\"replayPath\":\"" + replayPcap + "\"}");
                assertEquals(200, startReplay.statusCode());
                assertEquals("replay", JSON.readTree(startReplay.body()).path("captureMode").asText());
                awaitCondition(() -> {
                    var h = bridge.getCaptureHealth();
                    return h != null && "replay".equals(h.mode());
                });
                assertEquals(404, get(client, opsBase + "/api/ops/targets").statusCode());
                assertFalse(JSON.readTree(get(client, opsBase + "/api/status").body())
                        .path("operationsEnabled").asBoolean());

                // Stop runtime capture
                var stopCapture = postJson(client, opsBase + "/api/capture/stop", "{}");
                assertEquals(200, stopCapture.statusCode());
                assertFalse(JSON.readTree(stopCapture.body()).path("captureRunning").asBoolean());
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    @Test void opsHoldPinsPassiveScanChannelAfterReleaseAndPermitsBackToBackLease(@TempDir Path dir) throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var captureStreams = new CopyOnWriteArrayList<StreamingCaptureProcess>();
            var tuneCommands = new CopyOnWriteArrayList<List<String>>();
            try (var bridge = new PacketBridge(builder -> {
                if (builder.command().getFirst().equals("tcpdump")) {
                    var proc = new StreamingCaptureProcess();
                    captureStreams.add(proc);
                    return proc;
                }
                tuneCommands.add(List.copyOf(builder.command()));
                return new CompletedProcess("", 0);
            }, Map.of("001122", "TestRouter"), new DeviceProfiler(), 20, 64, 64,
                    iface -> null, iface -> "phy0");
                 var server = new PassiveRfServer(bridge, true).start(0);
                 var client = HttpClient.newHttpClient()) {

                String base = "http://127.0.0.1:" + server.port();
                var startScan = postJson(client, base + "/api/capture/start",
                        "{\"mode\":\"scan\",\"interface\":\"lab0mon\"}");
                assertEquals(200, startScan.statusCode(), startScan.body());
                awaitCondition(() -> tuneCommands.size() >= 2);

                try (var first = bridge.acquireOpsLease("lab0mon", false)) {
                    bridge.holdPassiveFrequency(2437, java.time.Duration.ofSeconds(10));
                    tuneCommands.clear();
                }

                // Releasing the lease during an active hold retunes to the held frequency and suppresses channel hops.
                awaitCondition(() -> tuneCommands.stream().anyMatch(cmd -> cmd.contains("2437")));
                Thread.sleep(350);
                assertTrue(tuneCommands.stream().allMatch(cmd -> cmd.contains("2437")),
                        "Scanner hopped away during active hold: " + tuneCommands);

                // Back-to-back Ops lease still succeeds without conflict and clears the previous hold on release.
                tuneCommands.clear();
                try (var second = bridge.acquireOpsLease("lab0mon", false)) {
                    assertNotNull(second);
                }
                awaitCondition(() -> tuneCommands.stream().anyMatch(cmd -> !cmd.contains("2437") && !cmd.contains("2462")));
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    @Test void enrichesLiveOpsTargetsDeauthAndLanHostsWithSecurityPmfAndDfsMetadata(@TempDir Path dir) throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var captureStreams = new CopyOnWriteArrayList<StreamingCaptureProcess>();
            Path lanTable = dir.resolve("ewave-lan-hosts.txt");
            String clientMac = "02:aa:bb:cc:dd:ee";
            java.nio.file.Files.write(lanTable, List.of(
                    "Interface: lab0mon, type: EN10MB, MAC: aa:bb:cc:dd:ee:ff, IPv4: 192.168.29.136",
                    "192.168.29.94\t" + clientMac + "\t(TestPhone)"));

            try (var bridge = new PacketBridge(builder -> {
                if ("tcpdump".equals(builder.command().getFirst())) {
                    var proc = new StreamingCaptureProcess();
                    captureStreams.add(proc);
                    return proc;
                }
                return new CompletedProcess("", 0);
            }, Map.of("02aabb", "PhoneCo"), new DeviceProfiler(), 20, 64, 64,
                    iface -> null, iface -> "phy0");
                 var server = new PassiveRfServer(bridge, true,
                         monitor -> new ewave.active.FrameInjector(monitor, b -> new CompletedProcess("", 0)),
                         new ewave.active.LanScanner(lanTable),
                         new ewave.active.WifiAccessPoints(dir.resolve("missing-aps"))).start(0);
                 var client = HttpClient.newHttpClient()) {
                String base = "http://127.0.0.1:" + server.port();
                var startRes = postJson(client, base + "/api/capture/start",
                        "{\"mode\":\"watch\",\"interface\":\"lab0mon\",\"channel\":52,\"band\":\"5\"}");
                assertEquals(200, startRes.statusCode(), startRes.body());
                assertFalse(captureStreams.isEmpty());

                byte[] pcap = syntheticDfsWpa3Pcap(AP_MAC, clientMac, "LabWPA3", 52, 5260);
                captureStreams.getFirst().write(pcap);

                var targetsRef = new java.util.concurrent.atomic.AtomicReference<com.fasterxml.jackson.databind.JsonNode>();
                awaitCondition(() -> {
                    var arr = JSON.readTree(get(client, base + "/api/ops/targets").body());
                    targetsRef.set(arr);
                    return arr.size() == 1 && !arr.at("/0/apSecurity").isMissingNode()
                            && !arr.at("/0/apSecurity").isNull();
                });

                var first = targetsRef.get().get(0);
                String targetId = first.path("id").asText();
                assertTrue(first.path("apSecurity").asText().contains("RSN"), first.toString());
                assertEquals("Required", first.path("pmfStatus").asText());
                assertEquals(List.of("SAE"), List.of(first.at("/akmSuites/0").asText()));
                assertTrue(first.path("dfsChannel").asBoolean());
                assertEquals("192.168.29.94", first.path("lanIp").asText());

                var hostsRes = JSON.readTree(get(client, base + "/api/ops/lan-hosts").body());
                assertTrue(hostsRes.path("available").asBoolean());
                assertEquals(1, hostsRes.path("hosts").size());
                var host = hostsRes.path("hosts").get(0);
                assertEquals("192.168.29.94", host.path("ip").asText());
                assertTrue(host.path("wirelessMatched").asBoolean());
                assertEquals(targetId, host.path("targetId").asText());
                assertEquals(52, host.path("channel").asInt());
                assertEquals("LabWPA3", host.path("apSsid").asText());

                var deauthRes = postJson(client, base + "/api/ops/deauth",
                        "{\"targetId\":\"" + targetId + "\",\"count\":2,\"interface\":\"lab0mon\"}");
                assertEquals(200, deauthRes.statusCode(), deauthRes.body());
                var deauthJson = JSON.readTree(deauthRes.body());
                assertTrue(deauthJson.path("success").asBoolean());
                assertEquals(10, deauthJson.path("holdSeconds").asInt());
                assertEquals("Required", deauthJson.path("pmfStatus").asText());
                assertTrue(deauthJson.path("dfsChannel").asBoolean());
                assertTrue(deauthJson.path("pmfWarning").asText().contains("802.11w PMF"));
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    private static byte[] syntheticDfsWpa3Pcap(String apBssid, String clientMac, String ssid, int ch, int freqMhz) {
        byte[] ap = HexFormat.ofDelimiter(":").parseHex(apBssid);
        byte[] cli = HexFormat.ofDelimiter(":").parseHex(clientMac);
        byte[] bcast = HexFormat.of().parseHex("ffffffffffff");
        byte[] ssidBytes = ssid.getBytes(StandardCharsets.UTF_8);
        // RSN IE: version=1, group=CCMP, pairwise=CCMP, akm=SAE (00:0f:ac:08), RSN caps=0x00c0 (MFPC+MFPR -> Required)
        byte[] rsn = new byte[]{
                48, 20, 1, 0,
                0x00, 0x0f, (byte) 0xac, 4,
                1, 0, 0x00, 0x0f, (byte) 0xac, 4,
                1, 0, 0x00, 0x0f, (byte) 0xac, 8,
                (byte) 0xc0, 0x00
        };
        var beaconBuf = ByteBuffer.allocate(24 + 12 + 2 + ssidBytes.length + 3 + rsn.length)
                .order(ByteOrder.LITTLE_ENDIAN);
        beaconBuf.putShort((short) 0x0080).putShort((short) 0).put(bcast).put(ap).put(ap).putShort((short) 0);
        beaconBuf.putLong(1L).putShort((short) 100).putShort((short) 0x0011);
        beaconBuf.put((byte) 0).put((byte) ssidBytes.length).put(ssidBytes);
        beaconBuf.put((byte) 3).put((byte) 1).put((byte) ch);
        beaconBuf.put(rsn);

        byte[][] frames = new byte[4][];
        frames[0] = beaconBuf.array();
        for (int seq = 1; seq <= 3; seq++) {
            var dataBuf = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN);
            dataBuf.putShort((short) 0x0108).putShort((short) 0).put(ap).put(cli).put(bcast)
                    .putShort((short) (seq << 4)).putInt(0);
            frames[seq] = dataBuf.array();
        }

        byte[][] packets = new byte[frames.length][];
        for (int i = 0; i < frames.length; i++) packets[i] = radiotapAtFreq(frames[i], freqMhz);
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, packets);
        var buffer = ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN);
        int offset = 24;
        int now = (int) (System.currentTimeMillis() / 1000);
        for (byte[] packet : packets) {
            buffer.putInt(offset, now);
            offset += 16 + packet.length;
        }
        return pcap;
    }

    @Test void resolvesAuthoritativeFiveGhzHtChannelAcrossStaleRadiotapAndFiltersRoamedTargets(@TempDir Path dir)
            throws Exception {
        String prev = System.getProperty("rf.networkProfile");
        System.setProperty("rf.networkProfile", dir.resolve("my-network.json").toString());
        try {
            var captureStreams = new CopyOnWriteArrayList<StreamingCaptureProcess>();
            String ap2 = "00:11:22:33:44:66";
            String cli = "02:aa:bb:cc:dd:ee";
            try (var bridge = new PacketBridge(builder -> {
                if ("tcpdump".equals(builder.command().getFirst())) {
                    var proc = new StreamingCaptureProcess();
                    captureStreams.add(proc);
                    return proc;
                }
                return new CompletedProcess("", 0);
            }, Map.of("02aabb", "PhoneCo"), new DeviceProfiler(), 20, 64, 64,
                    iface -> null, iface -> "phy0");
                 var server = new PassiveRfServer(bridge, true).start(0);
                 var client = HttpClient.newHttpClient()) {
                String base = "http://127.0.0.1:" + server.port();
                var startRes = postJson(client, base + "/api/capture/start",
                        "{\"mode\":\"watch\",\"interface\":\"lab0mon\",\"channel\":1,\"band\":\"2.4\"}");
                assertEquals(200, startRes.statusCode(), startRes.body());

                // 5 GHz HT Operation IE (ID 61, len 22, primary channel 36) arriving with stale 2412 MHz radiotap
                byte[] ssid5 = "Lab5G".getBytes(StandardCharsets.UTF_8);
                byte[] mac1 = HexFormat.ofDelimiter(":").parseHex(AP_MAC);
                byte[] bcast = HexFormat.of().parseHex("ffffffffffff");
                var htBeacon = ByteBuffer.allocate(24 + 12 + 2 + ssid5.length + 24).order(ByteOrder.LITTLE_ENDIAN);
                htBeacon.putShort((short) 0x0080).putShort((short) 0).put(bcast).put(mac1).put(mac1).putShort((short) 0);
                htBeacon.putLong(1L).putShort((short) 100).putShort((short) 1);
                htBeacon.put((byte) 0).put((byte) ssid5.length).put(ssid5);
                htBeacon.put((byte) 61).put((byte) 22).put((byte) 36).put(new byte[21]);

                writeFrames(captureStreams.getFirst(), 2412, htBeacon.array(),
                        rawToDsData(AP_MAC, cli, bcastHex(), 1),
                        rawToDsData(AP_MAC, cli, bcastHex(), 2),
                        rawToDsData(AP_MAC, cli, bcastHex(), 3));

                awaitCondition(() -> JSON.readTree(get(client, base + "/api/ops/targets").body()).size() == 1);
                var apsJson = JSON.readTree(get(client, base + "/api/capture/access-points").body()).path("accessPoints");
                assertEquals(36, apsJson.at("/0/channel").asInt());
                assertEquals(5180, apsJson.at("/0/frequencyMhz").asInt());

                var targets1 = JSON.readTree(get(client, base + "/api/ops/targets").body());
                var session = bridge.getPassiveWifi();
                assertEquals(session.addressId(cli) + ":" + session.addressId(AP_MAC), targets1.at("/0/id").asText());
                assertEquals(36, targets1.at("/0/channel").asInt());
                assertEquals(5180, targets1.at("/0/frequencyMhz").asInt());

                // Client roams to AP2 on CH 11 -> historical AP1 link becomes ROAMED_AWAY and drops out of Ops targets.
                appendFrames(captureStreams.getFirst(), 2462,
                        rawBeacon(ap2, "Lab24".getBytes(StandardCharsets.UTF_8), 11),
                        rawToDsData(ap2, cli, bcastHex(), 4),
                        rawToDsData(ap2, cli, bcastHex(), 5),
                        rawToDsData(ap2, cli, bcastHex(), 6));

                awaitCondition(() -> {
                    var t = JSON.readTree(get(client, base + "/api/ops/targets").body());
                    return t.size() == 1 && "Lab24".equals(t.at("/0/apSsid").asText());
                });
                var targets2 = JSON.readTree(get(client, base + "/api/ops/targets").body());
                assertEquals(1, targets2.size());
                assertEquals(session.addressId(cli) + ":" + session.addressId(ap2), targets2.at("/0/id").asText());
                assertEquals(11, targets2.at("/0/channel").asInt());
                assertEquals(2462, targets2.at("/0/frequencyMhz").asInt());
            }
        } finally {
            restoreProfileProperty(prev);
        }
    }

    private static String bcastHex() { return "ff:ff:ff:ff:ff:ff"; }

    private static void appendFrames(StreamingCaptureProcess proc, int freqMhz, byte[]... frames) throws Exception {
        byte[][] packets = new byte[frames.length][];
        for (int i = 0; i < frames.length; i++) packets[i] = radiotapAtFreq(frames[i], freqMhz);
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, packets);
        var buffer = ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN);
        int offset = 24;
        int now = (int) (System.currentTimeMillis() / 1000);
        for (byte[] packet : packets) {
            buffer.putInt(offset, now);
            offset += 16 + packet.length;
        }
        proc.write(java.util.Arrays.copyOfRange(pcap, 24, pcap.length));
    }

    private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> postJson(HttpClient client, String url, String json) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void writeInitialBeacon(StreamingCaptureProcess proc, String bssid, String ssid,
                                           int ch, int freqMhz) throws Exception {
        writeFrames(proc, freqMhz, rawBeacon(bssid, ssid.getBytes(StandardCharsets.UTF_8), ch));
    }

    /** Writes several radiotap frames under one PCAP header so the stream stays parseable. */
    private static void writeFrames(StreamingCaptureProcess proc, int freqMhz, byte[]... frames) throws Exception {
        byte[][] packets = new byte[frames.length][];
        for (int i = 0; i < frames.length; i++) packets[i] = radiotapAtFreq(frames[i], freqMhz);
        byte[] pcap = ProbeFrames.pcap(ByteOrder.LITTLE_ENDIAN, false, 127, packets);
        var buffer = ByteBuffer.wrap(pcap).order(ByteOrder.LITTLE_ENDIAN);
        int offset = 24;
        int now = (int) (System.currentTimeMillis() / 1000);
        for (byte[] packet : packets) {
            buffer.putInt(offset, now);
            offset += 16 + packet.length;
        }
        proc.write(pcap);
    }

    private static byte[] radiotapAtFreq(byte[] frame, int freqMhz) {
        byte[] result = new byte[13 + frame.length];
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN)
                .put((byte) 0).put((byte) 0).putShort((short) 13).putInt(0x28)
                .putShort((short) freqMhz).putShort((short) 0xa0).put((byte) -45).put(frame);
        return result;
    }

    private static byte[] rawBeacon(String bssid, byte[] ssid, int dsChannel) {
        byte[] mac = HexFormat.ofDelimiter(":").parseHex(bssid);
        byte[] bcast = HexFormat.of().parseHex("ffffffffffff");
        var buf = ByteBuffer.allocate(24 + 12 + 2 + ssid.length + 3).order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort((short) 0x0080).putShort((short) 0).put(bcast).put(mac).put(mac).putShort((short) 0);
        buf.putLong(0L).putShort((short) 100).putShort((short) 1);
        buf.put((byte) 0).put((byte) ssid.length).put(ssid);
        buf.put((byte) 3).put((byte) 1).put((byte) dsChannel);
        return buf.array();
    }

    private static byte[] rawToDsData(String apBssid, String clientMac, String dstMac, int seqNum) {
        byte[] ap = HexFormat.ofDelimiter(":").parseHex(apBssid);
        byte[] cli = HexFormat.ofDelimiter(":").parseHex(clientMac);
        byte[] dst = HexFormat.ofDelimiter(":").parseHex(dstMac);
        var buf = ByteBuffer.allocate(24 + 4).order(ByteOrder.LITTLE_ENDIAN);
        buf.putShort((short) 0x0108).putShort((short) 0).put(ap).put(cli).put(dst).putShort((short) (seqNum << 4));
        buf.putInt(0);
        return buf.array();
    }

    private static void awaitCondition(CheckedBoolean condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(6);
        while (!condition.get() && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        assertTrue(condition.get(), "Timed out waiting for condition");
    }

    private static void restoreProfileProperty(String prev) {
        if (prev == null) System.clearProperty("rf.networkProfile");
        else System.setProperty("rf.networkProfile", prev);
    }

    @FunctionalInterface
    private interface CheckedBoolean { boolean get() throws Exception; }

    private static final class BlockingProcess extends Process {
        private final CountDownLatch release;
        private final AtomicBoolean destroyed = new AtomicBoolean();

        BlockingProcess(CountDownLatch release) { this.release = release; }

        @Override public java.io.OutputStream getOutputStream() { return java.io.OutputStream.nullOutputStream(); }
        @Override public java.io.InputStream getInputStream() { return java.io.InputStream.nullInputStream(); }
        @Override public java.io.InputStream getErrorStream() { return java.io.InputStream.nullInputStream(); }

        @Override public int waitFor() throws InterruptedException {
            release.await();
            return 0;
        }

        @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
            return release.await(timeout, unit);
        }

        @Override public int exitValue() {
            if (release.getCount() > 0 && !destroyed.get()) throw new IllegalThreadStateException();
            return 0;
        }

        @Override public void destroy() {
            destroyed.set(true);
            release.countDown();
        }

        @Override public boolean isAlive() {
            return !destroyed.get() && release.getCount() > 0;
        }
    }
}
