package ewave.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import ewave.active.FrameInjector;
import ewave.active.HandshakeAnalyzer;
import ewave.active.BeaconFlood;
import ewave.active.PmkidCapture;
import ewave.active.EvilTwin;
import ewave.active.LanScanner;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.capture.ProbeDemo;
import ewave.capture.RadioStatus;
import ewave.core.ScannerDemo;
import ewave.model.EwaveEvent;
import ewave.passive.TopologyBuilder;
import ewave.passive.MyNetworkProfile;
import ewave.passive.PassiveWifiSession;
import io.javalin.http.Context;
import io.javalin.http.ForbiddenResponse;
import io.javalin.http.NotFoundResponse;
import io.javalin.Javalin;
import io.javalin.json.JavalinJackson;
import io.javalin.websocket.WsContext;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.regex.Pattern;

/** Loopback HTTP API for RF capture and opt-in lab operations. */
public final class PassiveRfServer implements AutoCloseable {
    public static final int PORT = 7070;
    private static final System.Logger LOG = System.getLogger(PassiveRfServer.class.getName());
    private static final ScannerDemo.Comparison SCANNER_DEMO = ScannerDemo.compare();
    private static final Pattern MAC = Pattern.compile("(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}");

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final Set<WsContext> clients = ConcurrentHashMap.newKeySet();
    private final RecordingLibrary recordingLibrary = new RecordingLibrary(mapper);
    private final BlockingQueue<EwaveEvent> events;
    private static final Pattern LOOPBACK_HOST = Pattern.compile("(?i)(?:127\\.0\\.0\\.1|localhost)(?::[0-9]{1,5})?");
    private final PacketBridge wifi;
    private final boolean operations;
    private final Function<String, FrameInjector> injectorFactory;
    private final LanScanner lanScanner;
    private final WifiAccessPoints accessPoints;
    private final Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory;
    private final Function<PmkidSettings, PmkidCapture> pmkidFactory;
    private final Function<BeaconSettings, BeaconFlood> beaconFactory;
    private final Function<EvilTwinSettings, EvilTwin> evilTwinFactory;
    private final long startedAt = System.currentTimeMillis();
    private final Javalin app;
    private final Object injectionLock = new Object();
    private FrameInjector activeInjector;
    private HandshakeAnalyzer activeHandshake;
    private PmkidCapture activePmkid;
    private BeaconFlood activeBeacon;
    private EvilTwin activeEvilTwin;
    private PacketBridge.OpsLease activeOpsLease;
    private volatile HandshakeAnalyzer latestHandshake;
    private volatile FrameInjector latestInjector;
    private volatile PmkidCapture latestPmkid;
    private volatile BeaconFlood latestBeacon;
    private volatile EvilTwin latestEvilTwin;
    private volatile boolean closing;
    private Thread eventThread;
    private ScheduledExecutorService scannerEvents;
    private final Map<Integer, Instant> reconnectWatches = new ConcurrentHashMap<>();

    public record HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel, String ssid,
                                    int frequencyMhz) {
        public HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel) {
            this(monitorInterface, apBssid, clientMac, channel, null, HandshakeAnalyzer.frequencyMhz(channel));
        }
    }

    public record PmkidSettings(String monitorInterface, String wordlistPath, int durationSeconds) {}
    public record BeaconSettings(String monitorInterface, String ssid, int channel, int rate) {}
    public record EvilTwinSettings(String apInterface, String ssid, int channel, int portalPort) {}

    public PassiveRfServer(PacketBridge bridge) {
        this(bridge, false);
    }

    public PassiveRfServer(PacketBridge bridge, boolean operations) {
        this(bridge, operations, FrameInjector::new, new LanScanner(), new WifiAccessPoints());
    }

    /** Injectable boundaries for tests using fixture streams and cached neighbors. */
    public PassiveRfServer(PacketBridge bridge, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints) {
        this(bridge, operations, injectorFactory, lanScanner, accessPoints,
                settings -> new HandshakeAnalyzer(settings.monitorInterface(), settings.apBssid(), settings.clientMac(),
                        settings.channel(), settings.frequencyMhz()));
    }

    public PassiveRfServer(PacketBridge bridge, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints, Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory) {
        this(bridge, operations, injectorFactory, lanScanner, accessPoints, handshakeFactory,
                settings -> new PmkidCapture(settings.monitorInterface()),
                settings -> new BeaconFlood(settings.monitorInterface()));
    }

    /** Additional process boundaries for PMKID capture and beacon flooding in tests. */
    public PassiveRfServer(PacketBridge bridge, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints, Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory,
                           Function<PmkidSettings, PmkidCapture> pmkidFactory,
                           Function<BeaconSettings, BeaconFlood> beaconFactory) {
        this(bridge, operations, injectorFactory, lanScanner, accessPoints, handshakeFactory, pmkidFactory,
                beaconFactory, settings -> new EvilTwin(settings.apInterface(), settings.ssid(), settings.channel(),
                        settings.portalPort()));
    }

    /** Additional process boundary for the evil-twin helper processes in tests. */
    public PassiveRfServer(PacketBridge bridge, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints, Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory,
                           Function<PmkidSettings, PmkidCapture> pmkidFactory,
                           Function<BeaconSettings, BeaconFlood> beaconFactory,
                           Function<EvilTwinSettings, EvilTwin> evilTwinFactory) {
        wifi = Objects.requireNonNull(bridge);
        this.operations = operations;
        this.injectorFactory = Objects.requireNonNull(injectorFactory);
        this.lanScanner = Objects.requireNonNull(lanScanner);
        this.accessPoints = Objects.requireNonNull(accessPoints);
        this.handshakeFactory = Objects.requireNonNull(handshakeFactory);
        this.pmkidFactory = Objects.requireNonNull(pmkidFactory);
        this.beaconFactory = Objects.requireNonNull(beaconFactory);
        this.evilTwinFactory = Objects.requireNonNull(evilTwinFactory);
        events = bridge.getEventQueue();
        app = Javalin.create(config -> {
            config.jsonMapper(new JavalinJackson(mapper, false));
        });
        app.before(ctx -> {
            ctx.header("Cache-Control", "no-store");
            if (!isLocal(ctx.header("Host"), ctx.header("Origin")))
                throw new ForbiddenResponse("Same-origin loopback access required");
            if (!operations && (ctx.path().startsWith("/api/attack/") || ctx.path().startsWith("/api/ops/")))
                throw new NotFoundResponse("Lab operations are disabled");
        });
        registerReports();
        registerOperations();
        app.ws("/ws/events", ws -> {
            ws.onConnect(ctx -> {
                if (isLocal(ctx.header("Host"), ctx.header("Origin"))) clients.add(ctx);
                else ctx.closeSession(1008, "Same-origin loopback access required");
            });
            ws.onClose(clients::remove);
            ws.onError(clients::remove);
        });
    }

    private static boolean isLocal(String host, String origin) {
        return host != null && LOOPBACK_HOST.matcher(host).matches()
                && (origin == null || origin.equalsIgnoreCase("http://" + host));
    }

    private void registerReports() {
        io.javalin.http.Handler healthHandler = ctx -> {
            var health = wifi.getCaptureHealth();
            if (health == null) ctx.status(503).json(Map.of("error", "Wi-Fi monitor capture or replay is unavailable"));
            else ctx.json(health);
        };
        io.javalin.http.Handler myNetworkGet = ctx -> {
            try {
                ctx.json(wifi.myNetwork());
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not read My Network profile", failure);
                ctx.status(500).json(Map.of("error", "Could not read the local My Network profile"));
            }
        };
        io.javalin.http.Handler myNetworkPost = ctx -> {
            final MyNetworkProfile.Change change;
            try {
                change = mapper.readValue(ctx.body(), MyNetworkProfile.Change.class);
            } catch (JsonProcessingException invalid) {
                ctx.status(400).json(Map.of("error", "Invalid My Network setup request"));
                return;
            }
            try {
                ctx.json(wifi.changeMyNetwork(change));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not save My Network profile", failure);
                ctx.status(500).json(Map.of("error", "Could not save the local My Network profile"));
            }
        };
        io.javalin.http.Handler myNetworkFind = ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) {
                unavailable(ctx, "Wi-Fi");
                return;
            }
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a network name");
                var name = body.path("ssid");
                ctx.json(session.findAccessPoints(name.isTextual() ? name.textValue() : null));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "Enter a network name of 1–32 Wi-Fi bytes"));
            }
        };
        io.javalin.http.Handler inventoryList = ctx -> {
            var session = wifi.getPassiveWifi();
            if (session != null) ctx.json(session.inventory());
            else if (operations) ctx.json(wifi.getProfiler().all());
            else unavailable(ctx, "Wi-Fi");
        };
        io.javalin.http.Handler inventoryDetail = ctx -> {
            var detail = wifi.inventoryDetail(ctx.pathParam("id"));
            if (detail == null) throw new NotFoundResponse("No retained Wi-Fi device matches this ID");
            ctx.json(detail);
        };
        io.javalin.http.Handler fingerprintsGet = ctx -> {
            try {
                ctx.json(wifi.fingerprintSamples());
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not read fingerprint samples", failure);
                ctx.status(500).json(Map.of("error", "Could not read the local My Network profile"));
            }
        };
        io.javalin.http.Handler fingerprintsPost = ctx -> {
            final MyNetworkProfile.SampleChange change;
            try {
                change = mapper.readValue(ctx.body(), MyNetworkProfile.SampleChange.class);
            } catch (JsonProcessingException invalid) {
                ctx.status(400).json(Map.of("error", "Invalid fingerprint sample request"));
                return;
            }
            try {
                ctx.json(wifi.saveFingerprintSample(change));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not save fingerprint sample", failure);
                ctx.status(500).json(Map.of("error", "Could not save the local My Network profile"));
            }
        };
        io.javalin.http.Handler fingerprintsDelete = ctx -> {
            final UUID id;
            try {
                id = UUID.fromString(ctx.pathParam("id"));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "Invalid fingerprint sample ID"));
                return;
            }
            try {
                ctx.json(wifi.removeFingerprintSample(id));
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not update fingerprint samples", failure);
                ctx.status(500).json(Map.of("error", "Could not save the local My Network profile"));
            }
        };
        io.javalin.http.Handler probeAuditHandler = ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) unavailable(ctx, "Wi-Fi"); else ctx.json(session.audit());
        };
        io.javalin.http.Handler channelsHandler = ctx -> {
            var state = wifi.getChannelSnapshot();
            if (state == null) ctx.status(503).json(Map.of("error", "no scanner attached"));
            else ctx.json(channelResponse(state));
        };

        app.get("/api/status", ctx -> ctx.json(Map.of("wifi", wifi.getCaptureStatus(),
                "startedAt", startedAt, "operationsEnabled", operations)));
        app.get("/api/capture-health", healthHandler);
        app.get("/api/capture/health", healthHandler);
        app.get("/api/capture/adapters", ctx -> {
            try {
                ctx.json(RadioStatus.monitorInterfaces());
            } catch (java.io.IOException unavailable) {
                ctx.status(503).json(Map.of("error", "Could not list monitor interfaces"));
            }
        });
        app.get("/api/recordings", ctx -> {
            try {
                ctx.json(recordingLibrary.recordings());
            } catch (java.io.IOException failure) {
                LOG.log(System.Logger.Level.WARNING, "Could not list recordings", failure);
                ctx.status(500).json(Map.of("error", "Could not read the local recording library"));
            }
        });
        app.post("/api/recordings", this::handleRecordingUpload);
        app.post("/api/recordings/{id}/replay", this::handleRecordingReplay);
        app.post("/api/capture/start", this::handleCaptureStart);
        app.post("/api/capture/stop", ctx -> {
            try {
                ctx.json(wifi.stopRuntimeCapture());
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Capture cannot be stopped right now")));
            }
        });
        app.post("/api/capture/channel", this::handleCaptureChannel);

        // Sniper routes + legacy channel-watch routes
        app.get("/api/sniper", ctx -> ctx.json(wifi.sniperState()));
        app.post("/api/sniper", this::handleSniperStart);
        app.post("/api/sniper/select", this::handleSniperSelect);
        app.delete("/api/sniper", ctx -> ctx.json(wifi.stopSniper()));
        app.delete("/api/sniper/{id}", ctx -> {
            try {
                ctx.json(wifi.stopSniper(UUID.fromString(ctx.pathParam("id"))));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "The Sniper run has changed."));
            }
        });

        // Module analysis views over shared PassiveWifiSession / PacketBridge state
        app.get("/api/spotter", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) { unavailable(ctx, "Wi-Fi"); return; }
            var topology = session.topology();
            ctx.json(Map.of("accessPoints", topology.accessPoints(), "edges", topology.edges(),
                    "devices", session.inventory(), "essGroups", topology.essGroups()));
        });
        app.get("/api/whistleblower", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) { unavailable(ctx, "Wi-Fi"); return; }
            var hidden = session.topology().accessPoints().stream()
                    .filter(TopologyBuilder.AccessPoint::ssidHidden).toList();
            long revealed = hidden.stream()
                    .filter(ap -> ap.ssid() != null && !ap.ssid().isEmpty()).count();
            ctx.json(Map.of("accessPoints", hidden, "hiddenCount", hidden.size(), "revealedCount", revealed));
        });
        app.get("/api/decloaker", probeAuditHandler);
        app.get("/api/decloaker/demo", ctx -> ctx.json(ProbeDemo.replay()));
        app.get("/api/inspector", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) { unavailable(ctx, "Wi-Fi"); return; }
            var topology = session.topology();
            ctx.json(Map.of("accessPoints", topology.accessPoints(), "essGroups", topology.essGroups()));
        });
        app.get("/api/profiler", inventoryList);
        app.get("/api/profiler/network", myNetworkGet);
        app.post("/api/profiler/network", myNetworkPost);
        app.post("/api/profiler/network/find", myNetworkFind);
        app.get("/api/profiler/fingerprints", fingerprintsGet);
        app.post("/api/profiler/fingerprints", fingerprintsPost);
        app.delete("/api/profiler/fingerprints/{id}", fingerprintsDelete);
        app.get("/api/profiler/{id}", inventoryDetail);
        app.get("/api/tracker", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) { unavailable(ctx, "Wi-Fi"); return; }
            var topology = session.topology();
            ctx.json(Map.of("roams", topology.roams(), "edges", topology.edges(), "devices", session.inventory()));
        });
        app.get("/api/lookout", channelsHandler);
        app.get("/api/lookout/demo", ctx -> ctx.json(SCANNER_DEMO));

        // Compatibility aliases for existing API callers
        app.get("/api/my-network", myNetworkGet);
        app.post("/api/my-network", myNetworkPost);
        app.post("/api/my-network/find", myNetworkFind);
        app.get("/api/inventory", inventoryList);
        app.get("/api/inventory/{id}/details", inventoryDetail);
        app.get("/api/fingerprint-samples", fingerprintsGet);
        app.post("/api/fingerprint-samples", fingerprintsPost);
        app.delete("/api/fingerprint-samples/{id}", fingerprintsDelete);
        app.get("/api/probe-audit", probeAuditHandler);
        app.get("/api/probe-audit/demo", ctx -> ctx.json(ProbeDemo.replay()));
        app.get("/api/topology", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) unavailable(ctx, "Wi-Fi"); else ctx.json(session.topology());
        });
        app.get("/api/topology.dot", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) unavailable(ctx, "Wi-Fi"); else ctx.contentType("text/vnd.graphviz").result(
                    TopologyBuilder.dot(session.topology()));
        });
        app.get("/api/channels/watch", ctx -> ctx.json(wifi.apWatchState()));
        app.post("/api/channels/watch", ctx -> {
            try {
                var body = mapper.readTree(ctx.body());
                var ap = body == null ? null : body.get("apId");
                if (ap == null || !ap.isTextual()) throw new IllegalArgumentException("Choose an access point.");
                ctx.json(wifi.startApWatch(ap.textValue()));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid watch request.")));
            } catch (IllegalStateException unavailable) {
                ctx.status(409).json(Map.of("error", unavailable.getMessage()));
            }
        });
        app.delete("/api/channels/watch/{id}", ctx -> {
            try {
                ctx.json(wifi.stopApWatch(UUID.fromString(ctx.pathParam("id"))));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", "The watch run has changed."));
            }
        });
        app.get("/api/channels/demo", ctx -> ctx.json(SCANNER_DEMO));
        app.get("/api/channels", channelsHandler);
        if (operations) {
            app.get("/api/devices", ctx -> ctx.status(410).json(Map.of(
                    "error", "Text-mode /api/devices has been retired", "replacement", "/api/profiler")));
            app.get("/api/profiles", ctx -> ctx.status(410).json(Map.of(
                    "error", "Legacy /api/profiles has been retired", "replacement", "/api/profiler")));
            app.get("/api/probes", ctx -> ctx.status(410).json(Map.of(
                    "error", "Text-mode /api/probes has been retired", "replacement", "/api/decloaker")));
        }
    }

    private record ChannelDetails(int channel, int freqMhz, double score, double occupancyMean,
                                  double fittedPeriodMs, double fitConfidence, String deviceHint,
                                  List<Integer> coupledWith, ChannelAnomaly anomaly) {}

    private record ChannelAnomaly(double deviation, Instant detectedAt, String reason, long durationMs) {}

    private ObjectNode channelResponse(PacketBridge.ChannelSnapshot state) {
        var snapshot = state.scanner();
        double[] scores = snapshot.scores(), means = snapshot.means();
        int[] coupledMembers = snapshot.coupledMembers();
        var channels = new ArrayList<ChannelDetails>();
        for (int band = 0; band < Math.min(13, scores.length); band++) {
            int channel = band + 1;
            var fingerprint = snapshot.fingerprints().get(band);
            List<Integer> coupledWith = Arrays.binarySearch(coupledMembers, band) < 0 ? List.of()
                    : Arrays.stream(coupledMembers).map(index -> index + 1)
                            .filter(peer -> peer != channel && peer <= 13).boxed().toList();
            var flag = snapshot.anomalies().get(channel);
            var anomaly = flag == null ? null : new ChannelAnomaly(flag.deviation(), flag.detectedAt(),
                    flag.reason(), flag.durationMillis(state.timestamp()));
            channels.add(new ChannelDetails(channel, PacketBridge.channelFrequencyMhz(channel), scores[band],
                    means[band], fingerprint.fittedPeriodMs(), fingerprint.fitConfidence(), fingerprint.deviceHint(),
                    coupledWith, anomaly));
        }

        // Preserve the score arrays in the public channel API.
        ObjectNode response = mapper.valueToTree(snapshot);
        response.put("tickMs", wifi.getTickMs());
        response.set("radio", mapper.valueToTree(state.radio()));
        response.put("activeChannel", state.activeChannel());
        response.put("lastChosen", state.lastChosen());
        response.put("lastChosenFreqMhz", state.lastChosen() == null ? null
                : PacketBridge.channelFrequencyMhz(state.lastChosen()));
        response.put("timestamp", state.timestamp().toString());
        response.set("channels", mapper.valueToTree(channels));
        return response;
    }

    private void stopOperations() {
        PacketBridge.OpsLease leaseToClose;
        synchronized (injectionLock) {
            if (activeInjector != null) activeInjector.terminate();
            if (activeHandshake != null) activeHandshake.terminate();
            if (activePmkid != null) activePmkid.terminate();
            if (activeBeacon != null) {
                activeBeacon.terminate();
                activeBeacon = null;
            }
            if (activeEvilTwin != null) {
                activeEvilTwin.terminate();
                activeEvilTwin = null;
            }
            leaseToClose = activeOpsLease;
            activeOpsLease = null;
        }
        closeLeaseQuietly(leaseToClose);
    }

    private static void closeLeaseQuietly(PacketBridge.OpsLease lease) {
        if (lease != null) {
            try {
                lease.close();
            } catch (RuntimeException failure) {
                LOG.log(System.Logger.Level.WARNING, "Failed to release radio lease", failure);
            }
        }
    }

    private void releaseIdleLease() {
        PacketBridge.OpsLease stale = null;
        synchronized (injectionLock) {
            if (activeInjector == null && activeHandshake == null && activePmkid == null
                    && !beaconActive() && !evilTwinActive()) {
                stale = activeOpsLease;
                activeOpsLease = null;
            }
        }
        closeLeaseQuietly(stale);
    }

    private PacketBridge.OpsLease acquireLeaseOutsideLock(String iface, boolean pauseCapture,
                                                          java.util.function.BooleanSupplier stillReserved,
                                                          Runnable clearSlot) {
        final PacketBridge.OpsLease lease;
        try {
            lease = wifi.acquireOpsLease(iface, pauseCapture);
        } catch (RuntimeException failure) {
            synchronized (injectionLock) { clearSlot.run(); }
            throw failure;
        }
        boolean keep;
        synchronized (injectionLock) {
            keep = !closing && stillReserved.getAsBoolean();
            if (keep) activeOpsLease = lease;
            else clearSlot.run();
        }
        if (!keep) {
            closeLeaseQuietly(lease);
            throw new IllegalStateException("Operation was stopped while acquiring radio control");
        }
        return lease;
    }

    private void releaseOperation(PacketBridge.OpsLease lease, Runnable clearSlot) {
        PacketBridge.OpsLease toClose = null;
        synchronized (injectionLock) {
            clearSlot.run();
            if (lease != null && activeOpsLease == lease) {
                toClose = lease;
                activeOpsLease = null;
            }
        }
        closeLeaseQuietly(toClose);
    }

    private FrameInjector.Status deauthStatus() {
        FrameInjector latest = latestInjector;
        return latest == null ? new FrameInjector.Status(false, "", "", null) : latest.status();
    }

    private HandshakeAnalyzer.Status handshakeStatus() {
        HandshakeAnalyzer latest = latestHandshake;
        return latest == null ? new HandshakeAnalyzer.Status(false, "Ready") : latest.status();
    }

    private PmkidCapture.Status pmkidStatus() {
        PmkidCapture latest = latestPmkid;
        return latest == null ? new PmkidCapture.Status(false, "Ready") : latest.status();
    }

    private BeaconFlood.Status beaconStatus() {
        BeaconFlood latest = latestBeacon;
        var status = latest == null ? new BeaconFlood.Status(false, "", "", "", null) : latest.status();
        if (latest != null && !status.running()) releaseIdleLease();
        return status;
    }

    private EvilTwin.Status evilTwinStatus() {
        EvilTwin latest = latestEvilTwin;
        var status = latest == null
                ? new EvilTwin.Status(false, "Ready", null, null, List.of(), null, null, null, null)
                : latest.status();
        if (latest != null && !status.running()) releaseIdleLease();
        return status;
    }

    private List<Map<String, Object>> opsTargets() {
        var session = wifi.getPassiveWifi();
        if (session != null) {
            return session.evidencedTargets(wifi.getProfiler()).stream().map(target -> {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("id", target.id());
                row.put("mac", target.mac());
                row.put("type", target.type());
                row.put("vendor", target.vendor());
                row.put("label", target.label());
                row.put("rssi", target.rssi());
                row.put("apId", target.apId());
                row.put("apBssid", target.apBssid());
                row.put("apSsid", target.apSsid());
                row.put("channel", target.channel());
                row.put("frequencyMhz", target.frequencyMhz());
                row.put("evidenceSource", target.evidenceSource());
                row.put("lastSeen", target.lastSeen());
                row.put("sessionId", target.sessionId().toString());
                return row;
            }).toList();
        }
        return wifi.getProfiler().all().stream().map(profile -> Map.<String, Object>of(
                "id", profile.mac(),
                "mac", profile.mac(), "type", profile.guessedType(),
                "label", profile.guessedType() + " · " + profile.vendor(),
                "rssi", profile.lastRssi())).toList();
    }

    private List<WifiAccessPoints.AccessPoint> cachedAccessPoints() throws java.io.IOException {
        return accessPoints.all();
    }

    private List<LanScanner.Device> cachedLanHosts() throws java.io.IOException {
        return lanScanner.scan();
    }

    private Integer optionalFrequency(com.fasterxml.jackson.databind.JsonNode body) {
        boolean hasFreq = body.has("frequencyMhz") && !body.path("frequencyMhz").isNull();
        boolean hasChannel = body.has("channel") && !body.path("channel").isNull();
        boolean hasBand = body.has("band") && !body.path("band").isNull();
        if (hasFreq && (hasChannel || hasBand)) {
            throw new IllegalArgumentException("frequencyMhz cannot be combined with channel or band");
        }
        if (hasFreq) return integer(body, "frequencyMhz", 2412, 2300, 7125);
        if (hasBand && !hasChannel) throw new IllegalArgumentException("band requires channel");
        if (!hasChannel) return null;
        int ch = integer(body, "channel", 1, 1, 233);
        String band = null;
        if (hasBand) {
            if (!body.path("band").isTextual()) throw new IllegalArgumentException("band must be a string");
            band = body.path("band").textValue();
        }
        return ewave.Ewave.resolveFrequency(ch, band);
    }

    private void handleCaptureStart(Context ctx) {
        try {
            var body = mapper.readTree(ctx.body());
            if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
            String mode = requiredText(body, "mode").toLowerCase(Locale.ROOT);
            String iface = body.has("interface") && !body.path("interface").isNull()
                    ? requiredText(body, "interface")
                    : Objects.toString(wifi.getCaptureStatus().get("captureInterface"), "wlo1");
            Integer frequencyMhz = optionalFrequency(body);
            Path replayFile = body.has("replayPath") && !body.path("replayPath").isNull()
                    ? Path.of(requiredText(body, "replayPath")) : null;
            int bands = integer(body, "bands", 13, 1, 64);
            if ("replay".equals(mode)) {
                if (replayFile == null) throw new IllegalArgumentException("replayPath is required for replay mode");
                if (frequencyMhz != null) throw new IllegalArgumentException("frequencyMhz/channel cannot be combined with replay");
            } else if (replayFile != null) {
                throw new IllegalArgumentException("replayPath can only be used with replay mode");
            }
            var requireIdle = body.path("requireIdle");
            if (!requireIdle.isMissingNode() && !requireIdle.isBoolean())
                throw new IllegalArgumentException("requireIdle must be a boolean");
            ctx.json(wifi.configureRuntimeCapture(mode, iface, frequencyMhz, replayFile, bands, operations,
                    requireIdle.asBoolean(false)));
        } catch (JsonProcessingException | IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid capture request")));
        } catch (IllegalStateException conflict) {
            ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Capture mode cannot be changed now")));
        } catch (java.io.IOException failure) {
            ctx.status(500).json(Map.of("error", Objects.toString(failure.getMessage(), "Failed to start capture")));
        }
    }

    private void handleRecordingUpload(Context ctx) {
        if (!"application/octet-stream".equalsIgnoreCase(ctx.header("Content-Type"))) {
            ctx.status(415).json(Map.of("error", "Send an 802.11 PCAP as application/octet-stream"));
            return;
        }
        if (ctx.req().getContentLengthLong() > RecordingLibrary.MAX_BYTES) {
            ctx.status(413).json(Map.of("error", "Recording exceeds 128 MiB"));
            return;
        }
        try (var input = ctx.req().getInputStream()) {
            ctx.status(201).json(recordingLibrary.add(ctx.queryParam("name"), input));
        } catch (RecordingLibrary.TooLarge tooLarge) {
            ctx.status(413).json(Map.of("error", "Recording exceeds 128 MiB"));
        } catch (IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid recording")));
        } catch (java.io.IOException failure) {
            LOG.log(System.Logger.Level.WARNING, "Could not import recording", failure);
            ctx.status(500).json(Map.of("error", "Could not save the recording"));
        }
    }

    private void handleRecordingReplay(Context ctx) {
        try {
            UUID id = UUID.fromString(ctx.pathParam("id"));
            var recording = recordingLibrary.find(id);
            if (recording == null) {
                ctx.status(404).json(Map.of("error", "Recording is unavailable"));
                return;
            }
            ctx.json(wifi.startReplay(recordingLibrary.file(id), recording.name(), id));
        } catch (IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", "Invalid recording ID"));
        } catch (IllegalStateException conflict) {
            ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Replay is unavailable")));
        } catch (java.io.IOException failure) {
            LOG.log(System.Logger.Level.WARNING, "Could not replay recording", failure);
            ctx.status(500).json(Map.of("error", "Could not replay the recording"));
        }
    }

    private void handleCaptureChannel(Context ctx) {
        try {
            var body = mapper.readTree(ctx.body());
            if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
            Integer frequencyMhz = optionalFrequency(body);
            if (frequencyMhz == null) throw new IllegalArgumentException("frequencyMhz or channel is required");
            ctx.json(wifi.tuneChannel(frequencyMhz));
        } catch (JsonProcessingException | IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid channel request")));
        } catch (IllegalStateException conflict) {
            ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Channel cannot be tuned right now")));
        } catch (java.io.IOException failure) {
            ctx.status(500).json(Map.of("error", Objects.toString(failure.getMessage(), "Failed to tune channel")));
        }
    }

    private void handleSniperStart(Context ctx) {
        try {
            var body = mapper.readTree(ctx.body());
            if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
            if (body.has("ssidBase64") && !body.path("ssidBase64").isNull()) {
                byte[] bytes = Base64.getDecoder().decode(requiredText(body, "ssidBase64"));
                String display = body.has("ssid") && body.path("ssid").isTextual() ? body.path("ssid").textValue() : null;
                ctx.json(wifi.startSniperBySsidBytes(bytes, display));
            } else if (body.has("apId") && !body.path("apId").isNull()) {
                ctx.json(wifi.startSniperByApId(requiredText(body, "apId")));
            } else if (body.has("ssid") && !body.path("ssid").isNull()) {
                ctx.json(wifi.startSniperBySsid(requiredText(body, "ssid")));
            } else {
                throw new IllegalArgumentException("Provide ssid, ssidBase64, or apId");
            }
        } catch (JsonProcessingException | IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid Sniper request")));
        } catch (IllegalStateException conflict) {
            ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Sniper unavailable")));
        }
    }

    private void handleSniperSelect(Context ctx) {
        try {
            var body = mapper.readTree(ctx.body());
            if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
            ctx.json(wifi.selectSniperCandidate(requiredText(body, "apId")));
        } catch (JsonProcessingException | IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid Sniper candidate")));
        } catch (IllegalStateException conflict) {
            ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Sniper is not selecting candidates")));
        }
    }

    private void registerOperations() {
        io.javalin.http.Handler stopHandler = ctx -> {
            stopOperations();
            ctx.json(Map.of("stopped", true));
        };
        io.javalin.http.Handler targetsHandler = ctx -> ctx.json(opsTargets());
        io.javalin.http.Handler apsHandler = ctx -> {
            try {
                ctx.json(cachedAccessPoints());
            } catch (java.nio.file.NoSuchFileException missing) {
                ctx.status(404).json(Map.of("error", "No Wi-Fi AP cache found. Restore managed Wi-Fi and recreate /tmp/ewave-wifi-aps.txt; see README, 'Restoring networking after a live session'."));
            } catch (java.io.IOException failure) {
                ctx.status(500).json(Map.of("error", "Cannot read Wi-Fi AP cache: " + failure.getMessage()));
            }
        };
        io.javalin.http.Handler scanLanHandler = ctx -> {
            try {
                ctx.json(cachedLanHosts());
            } catch (java.nio.file.NoSuchFileException missing) {
                ctx.status(404).json(Map.of("error", "No LAN cache found. Restore managed Wi-Fi and recreate /tmp/ewave-lan-hosts.txt; see README, 'Restoring networking after a live session'."));
            } catch (java.io.IOException failure) {
                ctx.status(500).json(Map.of("error", "Cannot read LAN cache: " + failure.getMessage()));
            }
        };
        io.javalin.http.Handler deauthStatusHandler = ctx -> ctx.json(deauthStatus());
        io.javalin.http.Handler deauthHandler = ctx -> {
            final String ap, client, monitor;
            final int count;
            final WifiAccessPoints.AccessPoint target;
            final FrameInjector injector;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                var apNode = body.path("apBssid");
                var clientNode = body.path("clientMac");
                var countNode = body.path("count");
                var interfaceNode = body.path("interface");
                if (!apNode.isTextual() || !MAC.matcher(apNode.textValue()).matches())
                    throw new IllegalArgumentException("apBssid must be a MAC address");
                if (!clientNode.isMissingNode() && !clientNode.isNull()
                        && (!clientNode.isTextual() || !MAC.matcher(clientNode.textValue()).matches()))
                    throw new IllegalArgumentException("clientMac must be a MAC address or null for broadcast");
                if (!countNode.isIntegralNumber() || !countNode.canConvertToInt() || countNode.intValue() < 0)
                    throw new IllegalArgumentException("count must be a nonnegative integer");
                if (!interfaceNode.isTextual()) throw new IllegalArgumentException("interface is required");
                ap = apNode.textValue();
                client = clientNode.isTextual() ? clientNode.textValue() : null;
                count = countNode.intValue();
                monitor = interfaceNode.textValue();
                injector = injectorFactory.apply(monitor);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            try {
                target = accessPoints.all().stream().filter(point -> point.bssid().equalsIgnoreCase(ap))
                        .findFirst().orElse(null);
                if (target == null) {
                    ctx.status(400).json(Map.of("error", "Select an actual Wi-Fi BSSID from the cached AP list"));
                    return;
                }
            } catch (java.io.IOException failure) {
                ctx.status(400).json(Map.of("error", "Wi-Fi AP cache unavailable. Restore managed Wi-Fi and recreate /tmp/ewave-wifi-aps.txt; see README, 'Restoring networking after a live session'."));
                return;
            }
            int channel = target.channel();
            var snapshot = Objects.equals(PacketBridge.channelFrequencyMhz(channel), target.frequencyMhz())
                    ? wifi.getChannelSnapshot() : null;
            String warning = channelWarning(snapshot, channel);
            releaseIdleLease();
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An injection is already running or the server is stopping"));
                    return;
                }
                activeInjector = injector;
                latestInjector = injector;
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(monitor, false,
                        () -> activeInjector == injector, () -> { if (activeInjector == injector) activeInjector = null; });
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var result = injector.sendDeauthFrames(ap, client, count, target.frequencyMhz());
                if (result.success() && snapshot != null) {
                    synchronized (injectionLock) {
                        if (!closing) reconnectWatches.put(channel, Instant.now());
                    }
                }
                if (warning == null) ctx.json(result);
                else {
                    ObjectNode response = mapper.valueToTree(result);
                    ctx.json(response.put("channelWarning", warning));
                }
            } finally {
                releaseOperation(lease, () -> { if (activeInjector == injector) activeInjector = null; });
            }
        };
        io.javalin.http.Handler handshakeStatusHandler = ctx -> ctx.json(handshakeStatus());
        io.javalin.http.Handler uncloakHandler = ctx -> {
            final String requested, monitor;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                var bssidNode = body.path("bssid");
                if (!bssidNode.isTextual() || bssidNode.textValue().isBlank())
                    throw new IllegalArgumentException("bssid must be a nonempty string");
                requested = bssidNode.textValue();
                monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            var session = wifi.getPassiveWifi();
            if (session == null) {
                ctx.status(400).json(Map.of("error", "Wi-Fi topology is unavailable"));
                return;
            }
            var topology = session.topology();
            var target = topologyTarget(topology, requested, session);
            if (target == null) {
                ctx.status(400).json(Map.of("error", "Access point is not in the current topology"));
                return;
            }
            if (!target.ssidHidden()) {
                var known = mapper.createObjectNode().put("error", "SSID already known");
                known.put("ssid", target.ssidToken());
                ctx.status(400).json(known);
                return;
            }
            var edge = topology.edges().stream()
                    .filter(candidate -> candidate.bssid().equalsIgnoreCase(target.bssid())).findFirst().orElse(null);
            if (edge == null) {
                ctx.status(400).json(Map.of("error", "No associated clients visible"));
                return;
            }
            String apBssid = session.observedBssid(target.bssid());
            if (apBssid == null && MAC.matcher(requested).matches()) apBssid = requested;
            if (apBssid == null || !MAC.matcher(apBssid).matches()) {
                ctx.status(400).json(Map.of("error", "Access point address is no longer available"));
                return;
            }
            String clientMac = session.observedClient(edge.clientId());
            if (clientMac == null && MAC.matcher(edge.clientId()).matches()) clientMac = edge.clientId();
            if (clientMac == null) {
                ctx.status(400).json(Map.of("error", "Associated client address is no longer available"));
                return;
            }
            int frequency = 0;
            final String resolvedApBssid = apBssid;
            try {
                var cached = accessPoints.all().stream()
                        .filter(point -> point.bssid().equalsIgnoreCase(resolvedApBssid)).findFirst().orElse(null);
                if (cached != null) frequency = cached.frequencyMhz();
            } catch (java.io.IOException ignored) { /* Channel mapping below remains available. */ }
            if (frequency == 0) frequency = HandshakeAnalyzer.frequencyMhz(target.channel());
            final FrameInjector injector;
            try {
                injector = injectorFactory.apply(monitor);
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            releaseIdleLease();
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An injection is already running or the server is stopping"));
                    return;
                }
                activeInjector = injector;
                latestInjector = injector;
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(monitor, false,
                        () -> activeInjector == injector, () -> { if (activeInjector == injector) activeInjector = null; });
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var result = injector.sendDeauthFrames(apBssid, clientMac, 8, frequency);
                if (!result.success()) {
                    ctx.status(500).json(Map.of("error", "Deauth injection failed",
                            "output", Objects.toString(result.output(), "")));
                    return;
                }
                ctx.json(Map.of("status", "deauth_sent", "targetClient", clientMac,
                        "message", "SSID will appear in Map within 10s if client reconnects."));
            } finally {
                releaseOperation(lease, () -> { if (activeInjector == injector) activeInjector = null; });
            }
        };
        io.javalin.http.Handler pmkidStatusHandler = ctx -> ctx.json(pmkidStatus());
        io.javalin.http.Handler pmkidHandler = ctx -> {
            final PmkidCapture capture;
            final String wordlist, monitor;
            final int duration;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
                wordlist = requiredText(body, "wordlistPath");
                duration = integer(body, "durationSeconds", 30, 1, 300);
                HandshakeAnalyzer.readableFile(wordlist, HandshakeAnalyzer.WORDLIST_MISSING);
                capture = pmkidFactory.apply(new PmkidSettings(monitor, wordlist, duration));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            } catch (java.io.IOException missing) {
                ctx.status(404).json(Map.of("error", missing.getMessage()));
                return;
            }
            releaseIdleLease();
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activePmkid = capture;
                latestPmkid = capture;
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(monitor, true,
                        () -> activePmkid == capture, () -> { if (activePmkid == capture) activePmkid = null; });
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            runPmkid(ctx, capture, lease, wordlist, duration);
        };
        io.javalin.http.Handler beaconStatusHandler = ctx -> ctx.json(beaconStatus());
        io.javalin.http.Handler beaconHandler = ctx -> {
            final BeaconSettings settings;
            final BeaconFlood flood;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
                String ssid = requiredText(body, "ssid");
                int channel = integer(body, "channel", 6, 1, 233);
                int rate = integer(body, "rate", 100, 1, 10_000);
                settings = new BeaconSettings(monitor, ssid, channel, rate);
                flood = beaconFactory.apply(settings);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            releaseIdleLease();
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activeBeacon = flood;
                latestBeacon = flood;
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(settings.monitorInterface(), false,
                        () -> activeBeacon == flood, () -> { if (activeBeacon == flood) activeBeacon = null; });
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var status = flood.start(settings.ssid(), settings.channel(), settings.rate());
                if (!status.running()) {
                    releaseOperation(lease, () -> { if (activeBeacon == flood) activeBeacon = null; });
                }
                ctx.json(status);
            } catch (java.io.IOException failure) {
                releaseOperation(lease, () -> { if (activeBeacon == flood) activeBeacon = null; });
                ctx.status(500).json(Map.of("error", Objects.toString(failure.getMessage(), "Beacon flood failed")));
            } catch (IllegalArgumentException invalid) {
                releaseOperation(lease, () -> { if (activeBeacon == flood) activeBeacon = null; });
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (IllegalStateException conflict) {
                releaseOperation(lease, () -> { if (activeBeacon == flood) activeBeacon = null; });
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
            }
        };
        io.javalin.http.Handler evilTwinStatusHandler = ctx -> ctx.json(evilTwinStatus());
        io.javalin.http.Handler evilTwinHandler = ctx -> {
            final EvilTwinSettings settings;
            final EvilTwin twin;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String ssid = requiredText(body, "ssid");
                String apInterface = body.has("interface") ? requiredText(body, "interface") : "wlo1ap";
                int channel = integer(body, "channel", 6, 1, 233);
                int portalPort = integer(body, "portalPort", 80, 1, 65_535);
                settings = new EvilTwinSettings(apInterface, ssid, channel, portalPort);
                twin = evilTwinFactory.apply(settings);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            releaseIdleLease();
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activeEvilTwin = twin;
                latestEvilTwin = twin;
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(settings.apInterface(), true,
                        () -> activeEvilTwin == twin, () -> { if (activeEvilTwin == twin) activeEvilTwin = null; });
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var status = twin.start();
                if (!status.running()) {
                    releaseOperation(lease, () -> { if (activeEvilTwin == twin) activeEvilTwin = null; });
                }
                ctx.json(status);
            } catch (java.io.IOException failure) {
                releaseOperation(lease, () -> { if (activeEvilTwin == twin) activeEvilTwin = null; });
                ctx.status(500).json(Map.of("error", Objects.toString(failure.getMessage(), "Evil twin failed to start")));
            } catch (IllegalArgumentException invalid) {
                releaseOperation(lease, () -> { if (activeEvilTwin == twin) activeEvilTwin = null; });
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (IllegalStateException conflict) {
                releaseOperation(lease, () -> { if (activeEvilTwin == twin) activeEvilTwin = null; });
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
            }
        };
        io.javalin.http.Handler handshakeHandler = ctx -> {
            final HandshakeAnalyzer analyzer;
            final String monitor;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String ap = requiredText(body, "apBssid");
                var clientNode = body.path("clientMac");
                String client = clientNode.isMissingNode() || clientNode.isNull() ? null : requiredText(body, "clientMac");
                var channelNode = body.path("channel");
                if (!channelNode.isMissingNode() && !channelNode.isNull()
                        && (!channelNode.isIntegralNumber() || !channelNode.canConvertToInt()))
                    throw new IllegalArgumentException("channel must be an integer in 1–233");
                int channel = HandshakeAnalyzer.normalizeChannel(channelNode.asInt(6));
                HandshakeAnalyzer.validateTarget(ap, client, channel);
                var ssidNode = body.path("ssid");
                if (!ssidNode.isMissingNode() && !ssidNode.isNull() && !ssidNode.isTextual())
                    throw new IllegalArgumentException("ssid must be a string");
                String ssid = ssidNode.isTextual() ? ssidNode.textValue() : null;
                var frequencyNode = body.path("frequencyMhz");
                Integer requestedFrequency = null;
                if (!frequencyNode.isMissingNode() && !frequencyNode.isNull()) {
                    if (!frequencyNode.isIntegralNumber() || !frequencyNode.canConvertToInt())
                        throw new IllegalArgumentException("frequencyMhz must be an integer");
                    requestedFrequency = frequencyNode.intValue();
                    HandshakeAnalyzer.validateFrequency(requestedFrequency);
                }
                WifiAccessPoints.AccessPoint target = null;
                try {
                    target = accessPoints.all().stream().filter(point -> point.bssid().equalsIgnoreCase(ap)).findFirst().orElse(null);
                } catch (java.io.IOException ignored) { /* Explicit and legacy channel-only clients can supply a target. */ }
                int frequency;
                if (target != null) {
                    if (requestedFrequency != null && requestedFrequency != target.frequencyMhz())
                        throw new IllegalArgumentException("AP frequency changed. Select the AP again from the refreshed list.");
                    frequency = target.frequencyMhz();
                    channel = target.channel();
                    if (ssid == null) ssid = target.ssid();
                } else {
                    frequency = requestedFrequency == null ? HandshakeAnalyzer.frequencyMhz(channel) : requestedFrequency;
                }
                monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
                analyzer = handshakeFactory.apply(new HandshakeSettings(monitor, ap, client, channel, ssid, frequency));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            runHandshake(ctx, analyzer, monitor, true, analyzer::capture);
        };
        io.javalin.http.Handler handshakeVerifyHandler = ctx -> {
            final HandshakeAnalyzer analyzer;
            final String cap, wordlist;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                cap = requiredText(body, "capFilePath");
                wordlist = requiredText(body, "wordlistPath");
                // Check the dictionary first to preserve the actionable missing-wordlist response.
                HandshakeAnalyzer.readableFile(wordlist, HandshakeAnalyzer.WORDLIST_MISSING);
                HandshakeAnalyzer.readableFile(cap, "Capture file not found or unreadable");
                analyzer = handshakeFactory.apply(new HandshakeSettings("wlo1", null, null, 0));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            } catch (java.io.IOException missing) {
                ctx.status(404).json(Map.of("error", missing.getMessage()));
                return;
            }
            runHandshake(ctx, analyzer, null, false, () -> analyzer.verifyPsk(cap, wordlist));
        };

        for (String prefix : List.of("/api/ops", "/api/attack")) {
            app.post(prefix + "/stop", stopHandler);
            app.get(prefix + "/targets", targetsHandler);
            app.get(prefix + "/aps", apsHandler);
            app.get(prefix + "/scan-lan", scanLanHandler);
            app.get(prefix + "/status", deauthStatusHandler);
            app.post(prefix + "/deauth", deauthHandler);
            app.post(prefix + "/uncloak", uncloakHandler);
            app.get(prefix + "/handshake/status", handshakeStatusHandler);
            app.post(prefix + "/handshake", handshakeHandler);
            app.post(prefix + "/handshake/verify", handshakeVerifyHandler);
            app.get(prefix + "/pmkid/status", pmkidStatusHandler);
            app.post(prefix + "/pmkid", pmkidHandler);
            app.get(prefix + "/beacon/status", beaconStatusHandler);
            app.post(prefix + "/beacon", beaconHandler);
            app.get(prefix + "/evil-twin/status", evilTwinStatusHandler);
            app.post(prefix + "/evil-twin", evilTwinHandler);
        }
    }

    private static void unavailable(Context ctx, String radio) {
        ctx.status(404).json(Map.of("error", radio + " passive capture is disabled"));
    }

    private static String requiredText(com.fasterxml.jackson.databind.JsonNode body, String field) {
        var node = body.path(field);
        if (!node.isTextual() || node.textValue().isBlank())
            throw new IllegalArgumentException(field + " must be a nonempty string");
        return node.textValue();
    }

    private static int integer(com.fasterxml.jackson.databind.JsonNode body, String field, int fallback, int min, int max) {
        var node = body.path(field);
        if (node.isMissingNode() || node.isNull()) return fallback;
        if (!node.isIntegralNumber() || !node.canConvertToInt())
            throw new IllegalArgumentException(field + " must be an integer in " + min + "–" + max);
        int value = node.intValue();
        if (value < min || value > max)
            throw new IllegalArgumentException(field + " must be an integer in " + min + "–" + max);
        return value;
    }

    /** Called while holding injectionLock so a naturally exited beacon stops blocking new operations. */
    private boolean beaconActive() {
        if (activeBeacon != null && !activeBeacon.status().running()) activeBeacon = null;
        return activeBeacon != null;
    }

    /** Called while holding injectionLock so a stopped evil twin stops blocking new operations. */
    private boolean evilTwinActive() {
        if (activeEvilTwin != null && !activeEvilTwin.status().running()) activeEvilTwin = null;
        return activeEvilTwin != null;
    }

    private boolean anyActive() {
        return activeInjector != null || activeHandshake != null || activePmkid != null
                || beaconActive() || evilTwinActive();
    }

    /** Dashboard rows carry session tokens; accept an actual BSSID as well for direct lab calls. */
    private static TopologyBuilder.AccessPoint topologyTarget(TopologyBuilder.Snapshot topology, String requested,
                                                              PassiveWifiSession session) {
        var direct = topology.accessPoints().stream()
                .filter(point -> point.bssid().equalsIgnoreCase(requested)).findFirst();
        if (direct.isPresent()) return direct.get();
        if (!MAC.matcher(requested).matches()) return null;
        String token = session.addressId(requested);
        return topology.accessPoints().stream().filter(point -> point.bssid().equalsIgnoreCase(token))
                .findFirst().orElse(null);
    }

    private void runPmkid(io.javalin.http.Context ctx, PmkidCapture capture, PacketBridge.OpsLease lease,
                          String wordlist, int duration) {
        var timedOut = new AtomicBoolean();
        try {
            ctx.async(config -> {
                config.timeout = Math.min(900_000L, (duration + 330L) * 1000L);
                config.onTimeout(context -> {
                    timedOut.set(true);
                    capture.terminate();
                    context.status(504).json(Map.of("error", "PMKID capture timed out"));
                });
            }, () -> {
                try {
                    Object result = capture.run(wordlist, duration);
                    if (!timedOut.get()) ctx.json(result);
                } catch (Exception failure) {
                    if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
                    int status = failure instanceof TimeoutException ? 504
                            : failure instanceof CancellationException || failure instanceof InterruptedException ? 409 : 500;
                    if (!timedOut.get()) ctx.status(status).json(Map.of("error",
                            Objects.toString(failure.getMessage(), "PMKID operation failed")));
                } finally {
                    releaseOperation(lease, () -> { if (activePmkid == capture) activePmkid = null; });
                }
            });
        } catch (RuntimeException failure) {
            releaseOperation(lease, () -> { if (activePmkid == capture) activePmkid = null; });
            throw failure;
        }
    }

    private void runHandshake(io.javalin.http.Context ctx, HandshakeAnalyzer analyzer, String monitor,
                              boolean capture, Callable<?> operation) {
        if (capture) releaseIdleLease();
        synchronized (injectionLock) {
            if (closing || anyActive()) {
                ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                return;
            }
            activeHandshake = analyzer;
            if (capture) latestHandshake = analyzer;
        }
        final PacketBridge.OpsLease lease;
        if (capture) {
            try {
                lease = acquireLeaseOutsideLock(monitor, false,
                        () -> activeHandshake == analyzer, () -> { if (activeHandshake == analyzer) activeHandshake = null; });
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
        } else {
            lease = null;
        }
        var timedOut = new AtomicBoolean();
        try {
            ctx.async(config -> {
                // Allow time for tuning, the 90-second capture, and decoder shutdown.
                config.timeout = capture ? 110_000 : 310_000;
                config.onTimeout(context -> {
                    timedOut.set(true);
                    analyzer.terminate();
                    context.status(504).json(Map.of("error", capture ? "Handshake capture timed out" : "PSK verification timed out"));
                });
            }, () -> {
                try {
                    Object result = operation.call();
                    if (!timedOut.get()) ctx.json(result);
                } catch (Exception failure) {
                    if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
                    int status = failure instanceof TimeoutException ? 504
                            : failure instanceof CancellationException || failure instanceof InterruptedException ? 409 : 500;
                    if (!timedOut.get()) ctx.status(status).json(Map.of("error", Objects.toString(failure.getMessage(), "Handshake operation failed")));
                } finally {
                    releaseOperation(lease, () -> { if (activeHandshake == analyzer) activeHandshake = null; });
                }
            });
        } catch (RuntimeException failure) {
            releaseOperation(lease, () -> { if (activeHandshake == analyzer) activeHandshake = null; });
            throw failure;
        }
    }

    public PassiveRfServer start() { return start(PORT); }

    /** Port 0 selects an available port, useful for embedding and integration tests. */
    public synchronized PassiveRfServer start(int port) {
        if (eventThread != null) throw new IllegalStateException("UI server is already running");
        synchronized (injectionLock) { closing = false; }
        app.start("127.0.0.1", port);
        eventThread = new Thread(this::consumeEvents, "ewave-api-events");
        eventThread.setDaemon(true);
        eventThread.start();
        if (operations) {
            scannerEvents = Executors.newSingleThreadScheduledExecutor(
                    Thread.ofPlatform().daemon().name("ewave-api-scanner").factory());
            Map<Integer, Instant> suggestedAt = new HashMap<>();
            Map<Integer, Instant> suggestedFlags = new HashMap<>();
            scannerEvents.scheduleWithFixedDelay(() -> pollScannerEvents(suggestedAt, suggestedFlags), 0,
                    Math.min(100, wifi.getTickMs()), TimeUnit.MILLISECONDS);
        }
        return this;
    }

    public int port() { return app.port(); }

    /** Serialize once and isolate failed/disconnected clients from the rest. */
    public void broadcast(EwaveEvent event) {
        Objects.requireNonNull(event, "event");
        if (!operations && (event.payload() != null || !switch (event.type()) {
            case "WIFI_DEVICE_SEEN", "PROBE_RECEIVED" -> true;
            default -> false;
        })) return;
        sendEvent(event);
    }

    private void sendEvent(Object event) {
        final String json;
        try {
            json = mapper.writeValueAsString(event);
        } catch (JsonProcessingException failure) {
            throw new IllegalArgumentException("Cannot serialize WebSocket event", failure);
        }
        for (WsContext client : clients) {
            try {
                synchronized (client.session) {
                    if (client.session.isOpen()) client.send(json);
                    else clients.remove(client);
                }
            } catch (Exception failure) {
                clients.remove(client);
                LOG.log(System.Logger.Level.DEBUG, "Removing failed WebSocket client", failure);
            }
        }
    }

    private static String channelWarning(PacketBridge.ChannelSnapshot snapshot, int channel) {
        if (snapshot == null) return null;
        var scores = snapshot.scanner().scores();
        if (channel < 1 || channel > scores.length || !(scores[channel - 1] < 0.10)) return null;
        return String.format(Locale.ROOT, "Channel %d score %.2f is low. The scanner measures channel activity, so check the cached AP channel.",
                channel, scores[channel - 1]);
    }

    private void pollScannerEvents(Map<Integer, Instant> suggestedAt, Map<Integer, Instant> suggestedFlags) {
        try {
            releaseIdleLease();
            if (clients.isEmpty() && reconnectWatches.isEmpty()) return;
            var snapshot = wifi.getChannelSnapshot();
            Instant now = Instant.now();
            reconnectWatches.forEach((channel, started) -> {
                if (!now.isBefore(started.plusSeconds(30))) {
                    reconnectWatches.remove(channel, started);
                    return;
                }
                var flag = snapshot == null ? null : snapshot.scanner().anomalies().get(channel);
                if (flag != null && !flag.detectedAt().isBefore(started)
                        && (flag.reason().equals("NEW_ACTIVITY") || flag.reason().equals("UNUSUAL_BURST"))
                        && reconnectWatches.remove(channel, started)) {
                    sendEvent(Map.of("type", "eapol_window", "channel", channel,
                            "reason", flag.reason(), "deviation", flag.deviation()));
                }
            });
            if (snapshot == null) return;
            snapshot.scanner().anomalies().forEach((channel, flag) -> {
                if (PacketBridge.channelFrequencyMhz(channel) == null || !flag.reason().equals("NEW_ACTIVITY")
                        || flag.detectedAt().equals(suggestedFlags.get(channel))) return;
                Instant last = suggestedAt.get(channel);
                if (last != null && now.isBefore(last.plusSeconds(60))) return;
                suggestedAt.put(channel, now);
                suggestedFlags.put(channel, flag.detectedAt());
                var fingerprint = snapshot.scanner().fingerprints().get(channel - 1);
                sendEvent(Map.of("type", "anomaly_target", "channel", channel, "deviation", flag.deviation(),
                        "deviceHint", Objects.toString(fingerprint.deviceHint(), "Unknown device"),
                        "detectedAt", flag.detectedAt().toString()));
            });
        } catch (RuntimeException failure) {
            LOG.log(System.Logger.Level.WARNING, "Could not broadcast scanner event", failure);
        }
    }

    private void consumeEvents() {
        while (!closing && !Thread.currentThread().isInterrupted()) {
            try {
                EwaveEvent event = events.take();
                if (closing) break;
                broadcast(event);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (RuntimeException failure) {
                if (!closing) LOG.log(System.Logger.Level.WARNING, "Could not broadcast event", failure);
            }
        }
    }

    public synchronized void stop() {
        PacketBridge.OpsLease leaseToClose;
        synchronized (injectionLock) {
            closing = true;
            if (activeInjector != null) activeInjector.terminate();
            if (activeHandshake != null) activeHandshake.terminate();
            if (activePmkid != null) activePmkid.terminate();
            if (activeBeacon != null) {
                activeBeacon.terminate();
                activeBeacon = null;
            }
            if (activeEvilTwin != null) {
                activeEvilTwin.terminate();
                activeEvilTwin = null;
            }
            leaseToClose = activeOpsLease;
            activeOpsLease = null;
        }
        closeLeaseQuietly(leaseToClose);
        if (eventThread == null) return;
        eventThread.interrupt();
        if (scannerEvents != null) {
            scannerEvents.shutdownNow();
            scannerEvents = null;
        }
        reconnectWatches.clear();
        try {
            app.stop();
            eventThread.interrupt();
            eventThread.join(2_000);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } finally {
            clients.clear();
            eventThread = null;
        }
    }

    @Override public void close() { stop(); }
}
