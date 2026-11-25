package ewave.ui;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
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
import ewave.active.OpsCapabilities;
import ewave.active.OpsTargets;
import ewave.active.WifiAccessPoints;
import ewave.capture.PacketBridge;
import ewave.capture.ProbeDemo;
import ewave.capture.RadioStatus;
import ewave.core.ScannerDemo;
import ewave.model.EwaveEvent;
import ewave.model.HandshakeResult;
import ewave.model.PskVerificationResult;
import ewave.passive.TopologyBuilder;
import ewave.passive.MyNetworkProfile;
import ewave.passive.PassiveWifiSession;
import ewave.passive.ApSecurityAuditor;
import io.javalin.http.Context;
import io.javalin.http.ForbiddenResponse;
import io.javalin.http.NotFoundResponse;
import io.javalin.Javalin;
import io.javalin.json.JavalinJackson;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
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
    private final EventStream eventStream = new EventStream(mapper);
    private final RecordingLibrary recordingLibrary = new RecordingLibrary(mapper);
    private final SessionSnapshotStore snapshots = new SessionSnapshotStore(mapper);
    private final BlockingQueue<EwaveEvent> events;
    private static final Pattern LOOPBACK_HOST = Pattern.compile("(?i)(?:127\\.0\\.0\\.1|localhost|\\[::1\\])(?::[0-9]{1,5})?");
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
    private static final int OPERATION_HISTORY_LIMIT = 50;
    private PacketBridge.OpsLease activeOpsLease;
    private UUID activeOperationId;
    private PendingRun activeRun;
    private final ArrayDeque<OperationHistoryEntry> operationHistory = new ArrayDeque<>();
    private volatile HandshakeAnalyzer latestHandshake;
    private volatile HandshakeAnalyzer latestVerification;
    private volatile boolean showingVerification;
    private boolean activeHandshakeVerification;
    private boolean activePmkidVerification;
    private volatile FrameInjector latestInjector;
    private volatile PmkidCapture latestPmkid;
    private volatile PmkidCapture latestPmkidCapture;
    private volatile BeaconFlood latestBeacon;
    private volatile EvilTwin latestEvilTwin;
    private volatile boolean closing;
    private Thread eventThread;
    private ScheduledExecutorService scannerEvents;
    private final Map<Integer, Instant> reconnectWatches = new ConcurrentHashMap<>();

    public record HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel, String ssid,
                                    int frequencyMhz, boolean allowMacRotation, int timeoutSeconds) {
        public HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel) {
            this(monitorInterface, apBssid, clientMac, channel, null, HandshakeAnalyzer.frequencyMhz(channel), false, 90);
        }

        public HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel, String ssid,
                                 int frequencyMhz) {
            this(monitorInterface, apBssid, clientMac, channel, ssid, frequencyMhz, false, 90);
        }

        public HandshakeSettings(String monitorInterface, String apBssid, String clientMac, int channel, String ssid,
                                 int frequencyMhz, boolean allowMacRotation) {
            this(monitorInterface, apBssid, clientMac, channel, ssid, frequencyMhz, allowMacRotation, 90);
        }
    }

    public record PmkidSettings(String monitorInterface, String wordlistPath, int durationSeconds,
                                String apBssid, int frequencyMhz, boolean captureOnly) {
        public PmkidSettings(String monitorInterface, String wordlistPath, int durationSeconds) {
            this(monitorInterface, wordlistPath, durationSeconds, null, 0, false);
        }

        public PmkidSettings(String monitorInterface, String wordlistPath, int durationSeconds,
                             String apBssid, int frequencyMhz) {
            this(monitorInterface, wordlistPath, durationSeconds, apBssid, frequencyMhz, false);
        }
    }

    public record BeaconSettings(String monitorInterface, String ssid, int channel, int rate, List<String> ssids) {
        public BeaconSettings {
            ssids = ssids == null ? (ssid == null ? List.of() : List.of(ssid)) : List.copyOf(ssids);
        }

        public BeaconSettings(String monitorInterface, String ssid, int channel, int rate) {
            this(monitorInterface, ssid, channel, rate, ssid == null ? List.of() : List.of(ssid));
        }
    }

    public record EvilTwinSettings(String apInterface, String ssid, int channel, int portalPort,
                                   boolean configureAddress) {
        public EvilTwinSettings(String apInterface, String ssid, int channel, int portalPort) {
            this(apInterface, ssid, channel, portalPort, false);
        }
    }

    public record OperationHistoryEntry(UUID id, String operation, String target, String interfaceName,
                                        Instant startedAt, Instant endedAt, long durationMs,
                                        String outcome, boolean success) {}

    private record PendingRun(UUID id, String operation, String target, String interfaceName,
                              Instant startedAt, AtomicBoolean finalized) {}

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
                        settings.channel(), settings.frequencyMhz(), settings.allowMacRotation(),
                        settings.timeoutSeconds()));
    }

    public PassiveRfServer(PacketBridge bridge, boolean operations,
                           Function<String, FrameInjector> injectorFactory, LanScanner lanScanner,
                           WifiAccessPoints accessPoints, Function<HandshakeSettings, HandshakeAnalyzer> handshakeFactory) {
        this(bridge, operations, injectorFactory, lanScanner, accessPoints, handshakeFactory,
                settings -> new PmkidCapture(settings.monitorInterface(), settings.apBssid(), settings.frequencyMhz()),
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
                        settings.portalPort(), settings.configureAddress()));
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
            if (!isLocal(ctx.header("Host"), ctx.header("Origin"), ctx.header("Sec-Fetch-Site")))
                throw new ForbiddenResponse("Same-origin loopback access required");
            if (!operationsEnabled() && (ctx.path().startsWith("/api/attack/") || ctx.path().startsWith("/api/ops/")))
                throw new NotFoundResponse("Lab operations require a live capture session");
            if (ctx.method() == io.javalin.http.HandlerType.POST && ctx.path().startsWith("/api/")) {
                String expected = ctx.path().equals("/api/recordings") ? "application/octet-stream" : "application/json";
                String contentType = ctx.header("Content-Type");
                if (contentType == null || !contentType.split(";", 2)[0].trim().equalsIgnoreCase(expected))
                    throw new io.javalin.http.UnsupportedMediaTypeResponse("Content-Type must be " + expected);
            }
        });
        registerReports();
        registerSnapshots();
        BundledFrontend.register(app);
        registerOperations();
        app.ws("/ws/events", ws -> {
            ws.onConnect(ctx -> {
                if (isLocal(ctx.header("Host"), ctx.header("Origin"), ctx.header("Sec-Fetch-Site")))
                    eventStream.connect(ctx, wifi.reportProgress());
                else ctx.closeSession(1008, "Same-origin loopback access required");
            });
            ws.onClose(eventStream::disconnect);
            ws.onError(eventStream::disconnect);
        });
    }

    static boolean isLocal(String host, String origin, String fetchSite) {
        return host != null && LOOPBACK_HOST.matcher(host).matches()
                && (origin == null || origin.equalsIgnoreCase("http://" + host))
                && (fetchSite == null || fetchSite.equalsIgnoreCase("same-origin") || fetchSite.equalsIgnoreCase("none"));
    }

    private boolean operationsEnabled() {
        return operations && !wifi.isReplaySession();
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
            else if (operations) ctx.json(List.of());
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
            PacketBridge.ChannelSnapshot state;
            PassiveWifiSession session;
            synchronized (wifi) {
                state = wifi.getChannelSnapshot();
                session = wifi.getPassiveWifi();
            }
            if (state == null) ctx.status(503).json(Map.of("error", "no scanner attached"));
            else ctx.json(channelResponse(state, session == null ? null : session.topology()));
        };

        app.get("/api/status", ctx -> ctx.json(Map.of("wifi", wifi.getCaptureStatus(),
                "startedAt", startedAt, "operationsEnabled", operationsEnabled())));
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
        app.post("/api/sniper/link", this::handleSniperLink);
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
            ctx.json(spotter(session.topology(), session.inventory()));
        });
        app.get("/api/whistleblower", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) { unavailable(ctx, "Wi-Fi"); return; }
            ctx.json(whistleblower(session.topology()));
        });
        app.get("/api/decloaker", probeAuditHandler);
        app.get("/api/decloaker/demo", ctx -> ctx.json(ProbeDemo.replay()));
        app.get("/api/capture/access-points", ctx -> {
            var session = wifi.getPassiveWifi();
            ctx.json(Map.of("accessPoints", session == null ? List.of() : session.selectableAccessPoints()));
        });
        app.get("/api/inspector", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) { unavailable(ctx, "Wi-Fi"); return; }
            ctx.json(inspector(session.topology()));
        });
        app.get("/api/profiler", ctx -> {
            var session = wifi.getPassiveWifi();
            if (session == null) inventoryList.handle(ctx);
            else ctx.json(session.profilerReport());
        });
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
            ctx.json(tracker(session.topology(), session.trackerDevices()));
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

    private static Map<String, Object> spotter(TopologyBuilder.Snapshot topology, List<?> devices) {
        return Map.of("accessPoints", topology.accessPoints(), "edges", topology.edges(),
                "devices", devices, "essGroups", topology.essGroups(), "meshLinks", topology.meshLinks());
    }

    private static Map<String, Object> whistleblower(TopologyBuilder.Snapshot topology) {
        var hidden = topology.accessPoints().stream().filter(TopologyBuilder.AccessPoint::ssidHidden).toList();
        long revealed = hidden.stream().filter(ap -> ap.ssidToken() != null).count();
        return Map.of("accessPoints", hidden, "hiddenCount", hidden.size(), "revealedCount", revealed);
    }

    private record InspectorAccessPoint(@JsonUnwrapped TopologyBuilder.AccessPoint accessPoint,
                                        List<ApSecurityAuditor.SecurityFinding> securityFindings) { }

    private static Map<String, Object> inspector(TopologyBuilder.Snapshot topology) {
        var findings = ApSecurityAuditor.audit(topology);
        var accessPoints = topology.accessPoints().stream()
                .map(ap -> new InspectorAccessPoint(ap, findings.get(ap.bssid()))).toList();
        int findingsCount = accessPoints.stream().mapToInt(row -> row.securityFindings().size()).sum();
        long evilTwinSuspects = accessPoints.stream().filter(row -> row.securityFindings().stream()
                .anyMatch(finding -> "ESS_SECURITY_DOWNGRADE".equals(finding.code()))).count();
        return Map.of("accessPoints", accessPoints, "essGroups", topology.essGroups(),
                "findingsCount", findingsCount, "evilTwinSuspects", evilTwinSuspects);
    }

    private static Map<String, Object> tracker(TopologyBuilder.Snapshot topology, List<?> devices) {
        return Map.of("roams", topology.roams(), "edges", topology.edges(), "devices", devices,
                "accessPoints", topology.accessPoints(), "btmRejections", topology.btmRejections());
    }

    private void registerSnapshots() {
        app.get("/api/sessions", ctx -> serveSnapshot(ctx, () -> ctx.json(snapshots.list())));
        app.post("/api/sessions", ctx -> serveSnapshot(ctx, () -> saveSnapshot(ctx)));
        app.get("/api/sessions/{id}", ctx -> serveSnapshot(ctx, () -> {
            UUID id = UUID.fromString(ctx.pathParam("id"));
            var snapshot = snapshots.load(id);
            if (snapshot == null) throw new NotFoundResponse("Snapshot unavailable");
            if ("true".equals(ctx.queryParam("download"))) {
                ctx.header("Content-Disposition", "attachment; filename=ewave-session-" + id + ".json");
            }
            ctx.json(snapshot);
        }));
        app.delete("/api/sessions/{id}", ctx -> serveSnapshot(ctx, () -> {
            if (!snapshots.delete(UUID.fromString(ctx.pathParam("id"))))
                throw new NotFoundResponse("Snapshot unavailable");
            ctx.json(Map.of("deleted", true));
        }));
    }

    private void saveSnapshot(Context ctx) throws IOException {
        byte[] request = ctx.bodyInputStream().readNBytes(2049);
        if (request.length > 2048) {
            ctx.status(413).json(Map.of("error", "Snapshot request exceeds 2 KiB"));
            return;
        }
        var body = mapper.readTree(request);
        if (body == null || !body.isObject()) throw new IllegalArgumentException("Provide a snapshot name");
        String name = requiredText(body, "name");
        UUID sessionId;
        Map<String, Object> reports = new LinkedHashMap<>();
        PacketBridge.ChannelSnapshot scanner;
        TopologyBuilder.Snapshot topology;
        synchronized (wifi) {
            var session = wifi.getPassiveWifi();
            if (session == null || (body.has("sessionId")
                    && !session.sessionId().toString().equals(body.path("sessionId").asText()))) {
                ctx.status(409).json(Map.of("error", "No matching observation session. Refresh and try again."));
                return;
            }
            sessionId = session.sessionId();
            synchronized (session) {
                topology = session.topology();
                var inventory = session.profilerReport();
                var devices = inventory.stream().map(PassiveWifiSession.ProfilerDevice::device).toList();
                reports.put("spotter", spotter(topology, devices));
                reports.put("whistleblower", whistleblower(topology));
                reports.put("decloaker", session.audit());
                reports.put("inspector", inspector(topology));
                reports.put("profiler", inventory);
                reports.put("tracker", tracker(topology, inventory.stream()
                        .map(device -> new PassiveWifiSession.TrackerDevice(device.device(), device.enrolledLabel())).toList()));
                scanner = wifi.getChannelSnapshot();
            }
        }
        reports.put("lookout", scanner == null ? null : channelResponse(scanner, topology));
        ctx.status(201).json(snapshots.save(name, sessionId, mapper.valueToTree(reports)));
    }

    @FunctionalInterface
    private interface SnapshotRequest {
        void run() throws IOException;
    }

    private void serveSnapshot(Context ctx, SnapshotRequest request) {
        try {
            request.run();
        } catch (SessionSnapshotStore.Limit limit) {
            ctx.status(409).json(Map.of("error", limit.getMessage()));
        } catch (JsonProcessingException invalid) {
            ctx.status(400).json(Map.of("error", "Invalid snapshot request"));
        } catch (IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", invalid.getMessage()));
        } catch (IOException failure) {
            LOG.log(System.Logger.Level.WARNING, "Could not access the snapshot library", failure);
            ctx.status(500).json(Map.of("error", "Could not access the local snapshot library"));
        }
    }

    private record ChannelDetails(int channel, int freqMhz, long sampleCount, Boolean noIr, Boolean radarDetection,
                                  double score, double occupancyMean,
                                  double fittedPeriodMs, double fitConfidence, String deviceHint,
                                  List<Integer> coupledWith, List<Integer> coupledFrequenciesMhz, ChannelAnomaly anomaly,
                                  Double estimatedAirtime, Integer medianNoiseDbm, Long dwellMs, Integer apCount,
                                  Integer activeClientCount, Double qbssUtilization, boolean nonWifiInterferenceSuspected) {}

    private record ChannelAnomaly(double deviation, Instant detectedAt, String reason, long durationMs,
                                  Instant lastActiveAt, String floodType, boolean activeNow) {}

    private static final class ChannelTopology {
        int apCount;
        Integer peakQbss;
        final HashSet<String> activeClients = new HashSet<>();
    }

    private static Map<Integer, ChannelTopology> channelTopology(List<RadioStatus.Channel> channels,
                                                                 TopologyBuilder.Snapshot topology) {
        if (topology == null) return Map.of();
        var byFrequency = new HashMap<Integer, ChannelTopology>();
        var uniqueFrequency = new HashMap<Integer, Integer>();
        for (var channel : channels) {
            byFrequency.put(channel.frequencyMhz(), new ChannelTopology());
            uniqueFrequency.merge(channel.channel(), channel.frequencyMhz(), (first, second) -> 0);
        }
        for (var ap : topology.accessPoints()) {
            int frequency = ap.frequencyMhz() > 0 ? ap.frequencyMhz() : uniqueFrequency.getOrDefault(ap.channel(), 0);
            var channel = byFrequency.get(frequency);
            if (channel == null) continue;
            channel.apCount++;
            if (ap.channelUtilization() != null) {
                channel.peakQbss = channel.peakQbss == null ? ap.channelUtilization()
                        : Math.max(channel.peakQbss, ap.channelUtilization());
            }
        }
        for (var edge : topology.edges()) {
            if (!"ACTIVE".equals(edge.state())) continue;
            int frequency = edge.frequencyMhz() > 0 ? edge.frequencyMhz() : uniqueFrequency.getOrDefault(edge.channel(), 0);
            var channel = byFrequency.get(frequency);
            if (channel != null) channel.activeClients.add(edge.clientId());
        }
        return byFrequency;
    }

    private ObjectNode channelResponse(PacketBridge.ChannelSnapshot state, TopologyBuilder.Snapshot topology) {
        var snapshot = state.scanner();
        double[] scores = snapshot.scores(), means = snapshot.means();
        long[] counts = snapshot.counts();
        int[] coupledMembers = snapshot.coupledMembers();
        var channels = new ArrayList<ChannelDetails>();
        var topologyByFrequency = channelTopology(state.channels(), topology);
        for (int band = 0; band < state.channels().size(); band++) {
            var channel = state.channels().get(band);
            var fingerprint = snapshot.fingerprints().get(band);
            int slot = band;
            var peers = Arrays.binarySearch(coupledMembers, band) < 0 ? List.<RadioStatus.Channel>of()
                    : Arrays.stream(coupledMembers).filter(index -> index != slot).mapToObj(state.channels()::get).toList();
            var flag = snapshot.anomalies().get(band + 1);
            var held = state.heldAnomalies().get(channel.frequencyMhz());
            ChannelAnomaly anomaly = null;
            if (flag != null) {
                anomaly = new ChannelAnomaly(flag.deviation(), flag.detectedAt(), flag.reason(),
                        flag.durationMillis(state.timestamp()), held == null ? state.timestamp() : held.lastActiveAt(),
                        held == null ? null : held.floodType(), true);
            } else if (held != null) {
                long duration = Math.max(0, Duration.between(held.detectedAt(), held.lastActiveAt()).toMillis());
                anomaly = new ChannelAnomaly(held.deviation(), held.detectedAt(), held.reason(),
                        duration, held.lastActiveAt(), held.floodType(), held.activeNow());
            }
            var coverage = state.radio().coverage().get(band);
            long dwellMs = state.radio().dwellMs().get(band);
            Double airtime = dwellMs < 100 ? null : Math.min(1.0, coverage.airtimeMicrosWhileTuned() / (1000.0 * dwellMs));
            var observed = topologyByFrequency.get(channel.frequencyMhz());
            Double qbss = observed == null || observed.peakQbss == null ? null : observed.peakQbss / 255.0;
            Integer noise = coverage.medianNoiseDbm();
            boolean interference = qbss != null && airtime != null && dwellMs >= 500 && qbss - airtime >= 0.35
                    || noise != null && noise >= -75;
            channels.add(new ChannelDetails(channel.channel(), channel.frequencyMhz(), counts[band],
                    channel.noIr(), channel.radarDetection(), scores[band],
                    means[band], fingerprint.fittedPeriodMs(), fingerprint.fitConfidence(), fingerprint.deviceHint(),
                    peers.stream().map(RadioStatus.Channel::channel).toList(),
                    peers.stream().map(RadioStatus.Channel::frequencyMhz).toList(), anomaly,
                    airtime, noise, dwellMs, observed == null ? null : observed.apCount,
                    observed == null ? null : observed.activeClients.size(), qbss, interference));
        }

        // Preserve the score arrays in the public channel API.
        ObjectNode response = mapper.valueToTree(snapshot);
        if (channels.isEmpty()) {
            for (String field : List.of("means", "spreads", "scores", "periods", "counts", "fingerprints")) {
                response.putArray(field);
            }
        }
        response.put("tickMs", wifi.getTickMs());
        response.set("radio", mapper.valueToTree(state.radio()));
        response.put("activeChannel", state.activeChannel());
        response.put("lastChosen", state.lastChosen());
        response.put("lastChosenFreqMhz", state.lastChosenFrequencyMhz());
        response.put("activeFrequencyMhz", state.radio().lastConfirmedFrequencyMhz());
        response.put("timestamp", state.timestamp().toString());
        response.set("channels", mapper.valueToTree(channels));
        response.set("recentAnomalies", mapper.valueToTree(state.recentAnomalies()));
        return response;
    }

    private void stopOperations() {
        PacketBridge.OpsLease leaseToClose;
        synchronized (injectionLock) {
            leaseToClose = stopOperationsLocked();
        }
        closeLeaseQuietly(leaseToClose);
    }

    /** Called while holding injectionLock. */
    private PacketBridge.OpsLease stopOperationsLocked() {
        beaconActive();
        evilTwinActive();
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
        finishActiveRunLocked("STOPPED", true, true);
        PacketBridge.OpsLease leaseToClose = activeOpsLease;
        activeOpsLease = null;
        return leaseToClose;
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
        HandshakeAnalyzer latest = showingVerification ? latestVerification : latestHandshake;
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
            var apById = new HashMap<String, TopologyBuilder.AccessPoint>();
            for (var ap : session.topology().accessPoints()) apById.put(ap.bssid(), ap);
            var lanByMac = lanIpByMac();
            return session.evidencedTargets(wifi.getProfiler()).stream().map(target -> {
                var ap = apById.get(target.apId());
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
                row.put("apSecurity", ap == null ? null : ap.security());
                row.put("pmfStatus", ap == null ? null : PassiveWifiSession.summarizePmf(ap.advertisedSecurity()));
                row.put("akmSuites", ap == null ? List.of() : PassiveWifiSession.akmSuitesOf(ap.advertisedSecurity()));
                row.put("dfsChannel", PassiveWifiSession.isDfsFrequency(target.frequencyMhz()));
                row.put("lanIp", target.mac() == null ? null : lanByMac.get(target.mac().toLowerCase(Locale.ROOT)));
                return row;
            }).toList();
        }
        return wifi.getProfiler().all().stream().map(profile -> Map.<String, Object>of(
                "id", profile.mac(),
                "mac", profile.mac(), "type", profile.guessedType(),
                "label", profile.guessedType() + " · " + profile.vendor(),
                "rssi", profile.lastRssi())).toList();
    }

    private Map<String, String> lanIpByMac() {
        if (!Files.isRegularFile(lanScanner.cachePath())) return Map.of();
        try {
            var map = new HashMap<String, String>();
            for (var host : lanScanner.scan()) {
                if (host.mac() != null && host.ip() != null) {
                    map.putIfAbsent(host.mac().toLowerCase(Locale.ROOT), host.ip());
                }
            }
            return map;
        } catch (IOException ignored) {
            return Map.of();
        }
    }

    private String targetPmfStatus(OpsTargets.Resolved target) {
        var session = wifi.getPassiveWifi();
        if (session == null) return null;
        String id = target.apId() != null ? target.apId()
                : target.apBssid() != null ? session.addressId(target.apBssid()) : null;
        if (id == null) return null;
        return session.topology().accessPoints().stream()
                .filter(ap -> id.equals(ap.bssid()))
                .findFirst()
                .map(ap -> PassiveWifiSession.summarizePmf(ap.advertisedSecurity()))
                .orElse(null);
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

    private void handleSniperLink(Context ctx) {
        try {
            var body = mapper.readTree(ctx.body());
            if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
            if (!body.hasNonNull("frequencyMhz")) {
                throw new IllegalArgumentException("frequencyMhz is required");
            }
            ctx.json(wifi.switchSniperAffiliatedLink(integer(body, "frequencyMhz", 0, 2300, 7125)));
        } catch (JsonProcessingException | IllegalArgumentException invalid) {
            ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid Sniper link")));
        } catch (IllegalStateException conflict) {
            ctx.status(409).json(Map.of("error", Objects.toString(conflict.getMessage(), "Sniper cannot follow a link")));
        }
    }

    private void registerOperations() {
        io.javalin.http.Handler capabilitiesHandler = ctx -> {
            List<String> monitors;
            try {
                monitors = RadioStatus.monitorInterfaces();
            } catch (java.io.IOException unavailable) {
                monitors = List.of();
            }
            Map<String, Object> capture = new LinkedHashMap<>();
            capture.put("status", wifi.getCaptureStatus());
            var health = wifi.getCaptureHealth();
            if (health != null) capture.put("health", health);
            String activeOp;
            String activeId;
            synchronized (injectionLock) {
                activeOp = activeOperation();
                activeId = activeOp == null || activeOperationId == null ? null : activeOperationId.toString();
            }
            ctx.json(OpsCapabilities.snapshot(accessPoints.cachePath(), lanScanner.cachePath(), configuredWordlist(),
                    monitors, OpsCapabilities.systemInterfaces(), capture, activeOp,
                    activeId, OpsCapabilities.systemPath()));
        };
        io.javalin.http.Handler historyHandler = ctx -> ctx.json(operationHistory());
        io.javalin.http.Handler clearHistoryHandler = ctx -> {
            clearOperationHistory();
            ctx.json(Map.of("cleared", true));
        };
        io.javalin.http.Handler stopHandler = ctx -> {
            UUID requestedId = null;
            String rawBody = ctx.body();
            if (rawBody != null && !rawBody.isBlank()) {
                try {
                    var body = mapper.readTree(rawBody);
                    if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                    String rawOperationId = optionalText(body, "operationId");
                    if (rawOperationId != null) {
                        try {
                            requestedId = UUID.fromString(rawOperationId);
                        } catch (IllegalArgumentException badUuid) {
                            throw new IllegalArgumentException("operationId must be a valid UUID");
                        }
                    }
                } catch (JsonProcessingException | IllegalArgumentException invalid) {
                    ctx.status(400).json(Map.of("error", invalid.getMessage()));
                    return;
                }
            }
            if (requestedId == null) {
                stopOperations();
                ctx.json(Map.of("stopped", true));
                return;
            }
            PacketBridge.OpsLease leaseToClose;
            synchronized (injectionLock) {
                beaconActive();
                evilTwinActive();
                if (!anyActive()) {
                    ctx.json(Map.of("stopped", false));
                    return;
                }
                if (activeOperationId == null || !activeOperationId.equals(requestedId)) {
                    Map<String, Object> conflict = new LinkedHashMap<>();
                    conflict.put("error", "Active operation does not match operationId");
                    if (activeOperationId != null) conflict.put("activeOperationId", activeOperationId.toString());
                    ctx.status(409).json(conflict);
                    return;
                }
                leaseToClose = stopOperationsLocked();
            }
            closeLeaseQuietly(leaseToClose);
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
        io.javalin.http.Handler lanHostsHandler = ctx -> {
            if (!Files.isRegularFile(lanScanner.cachePath())) {
                ctx.json(Map.of("available", false, "hosts", List.of()));
                return;
            }
            try {
                var hosts = cachedLanHosts();
                var session = wifi.getPassiveWifi();
                var targetByMac = new HashMap<String, PassiveWifiSession.EvidencedTarget>();
                if (session != null) {
                    for (var target : session.evidencedTargets(wifi.getProfiler())) {
                        if (target.mac() != null) targetByMac.putIfAbsent(target.mac().toLowerCase(Locale.ROOT), target);
                    }
                }
                var rows = hosts.stream().map(host -> {
                    var matched = host.mac() == null ? null : targetByMac.get(host.mac().toLowerCase(Locale.ROOT));
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("ip", host.ip());
                    row.put("mac", host.mac());
                    row.put("vendor", host.vendor());
                    row.put("wirelessMatched", matched != null);
                    row.put("targetId", matched == null ? null : matched.id());
                    row.put("apSsid", matched == null ? null : matched.apSsid());
                    row.put("channel", matched == null ? null : matched.channel());
                    row.put("rssi", matched == null ? null : matched.rssi());
                    return row;
                }).toList();
                ctx.json(Map.of("available", true, "hosts", rows));
            } catch (IOException failure) {
                ctx.json(Map.of("available", false, "hosts", List.of()));
            }
        };
        io.javalin.http.Handler deauthStatusHandler = ctx -> ctx.json(deauthStatus());
        io.javalin.http.Handler deauthHandler = ctx -> {
            final String monitor;
            final int count;
            final OpsTargets.Resolved target;
            final FrameInjector injector;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String targetId = optionalText(body, "targetId");
                String apId = optionalText(body, "apId");
                String apBssid = optionalText(body, "apBssid");
                String clientMac = optionalText(body, "clientMac");
                if (targetId == null && apId == null && apBssid == null)
                    throw new IllegalArgumentException("targetId, apId, or apBssid is required");
                var countNode = body.path("count");
                if (!countNode.isIntegralNumber() || !countNode.canConvertToInt() || countNode.intValue() < 0)
                    throw new IllegalArgumentException("count must be a nonnegative integer");
                var interfaceNode = body.path("interface");
                if (!interfaceNode.isTextual() || interfaceNode.textValue().isBlank())
                    throw new IllegalArgumentException("interface is required");
                count = countNode.intValue();
                monitor = interfaceNode.textValue();
                target = resolveOpsTarget(targetId, apId, apBssid, clientMac, false);
                injector = injectorFactory.apply(monitor);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            int channel = target.channel();
            var snapshot = Objects.equals(PacketBridge.channelFrequencyMhz(channel), target.frequencyMhz())
                    ? wifi.getChannelSnapshot() : null;
            String warning = channelWarning(snapshot, channel);
            String pmfStatus = targetPmfStatus(target);
            boolean dfsChannel = PassiveWifiSession.isDfsFrequency(target.frequencyMhz());
            boolean opsRoute = ctx.path().startsWith("/api/ops/");
            releaseIdleLease();
            final UUID runId;
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An injection is already running or the server is stopping"));
                    return;
                }
                activeInjector = injector;
                latestInjector = injector;
                String targetSummary = target.clientMac() != null
                        ? target.apBssid() + " -> " + target.clientMac()
                        : target.apBssid();
                runId = startRunLocked("deauth", targetSummary, monitor);
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(monitor, false,
                        () -> activeInjector == injector, () -> clearInjectorSlotLocked(injector, runId));
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var result = injector.sendDeauthFrames(target.apBssid(), target.clientMac(), count, target.frequencyMhz());
                finishRun(runId, result.success() ? "SENT" : "FAILED", result.success());
                if (result.success() && target.frequencyMhz() > 0) {
                    wifi.holdPassiveFrequency(target.frequencyMhz(), Duration.ofSeconds(10));
                }
                if (result.success() && snapshot != null) {
                    synchronized (injectionLock) {
                        if (!closing) reconnectWatches.put(channel, Instant.now());
                    }
                }
                if (!opsRoute) {
                    if (warning == null) ctx.json(result);
                    else {
                        ObjectNode response = mapper.valueToTree(result);
                        ctx.json(response.put("channelWarning", warning));
                    }
                } else {
                    ObjectNode response = mapper.valueToTree(result);
                    response.put("holdSeconds", 10);
                    response.put("channel", channel);
                    response.put("frequencyMhz", target.frequencyMhz());
                    if (pmfStatus == null) response.putNull("pmfStatus");
                    else response.put("pmfStatus", pmfStatus);
                    response.put("dfsChannel", dfsChannel);
                    if ("Required".equalsIgnoreCase(pmfStatus)) {
                        response.put("pmfWarning",
                                "Target AP requires 802.11w PMF; compliant stations ignore unsigned deauthentication frames.");
                    }
                    if (warning != null) response.put("channelWarning", warning);
                    ctx.json(response);
                }
            } finally {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearInjectorSlotLocked(injector, runId));
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
            if (session == null || session.isReplaySession()) {
                ctx.status(400).json(Map.of("error", "Wi-Fi topology is unavailable"));
                return;
            }
            var topology = session.topology();
            var target = topologyTarget(topology, requested, session);
            if (target == null) {
                ctx.status(400).json(Map.of("error", "Access point is not in the current topology"));
                return;
            }
            if (!target.ssidHidden() || target.ssid() != null && !target.ssid().isEmpty()) {
                var known = mapper.createObjectNode().put("error", "SSID already known");
                known.put("ssid", target.ssidToken());
                ctx.status(400).json(known);
                return;
            }
            var edge = topology.edges().stream()
                    .filter(candidate -> candidate.bssid().equalsIgnoreCase(target.bssid()))
                    .filter(candidate -> session.hasAssociationEvidence(candidate.clientId(), candidate.bssid()))
                    .findFirst().orElse(null);
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
            var details = session.directlyObservedAp(target.bssid());
            if (details == null || details.frequencyMhz() <= 0) {
                ctx.status(400).json(Map.of("error", "AP frequency is unknown or expired. Refresh the AP list."));
                return;
            }
            int frequency = details.frequencyMhz();
            final FrameInjector injector;
            try {
                injector = injectorFactory.apply(monitor);
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            releaseIdleLease();
            final UUID runId;
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An injection is already running or the server is stopping"));
                    return;
                }
                activeInjector = injector;
                latestInjector = injector;
                runId = startRunLocked("uncloak", apBssid + " -> " + clientMac, monitor);
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(monitor, false,
                        () -> activeInjector == injector, () -> clearInjectorSlotLocked(injector, runId));
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var result = injector.sendDeauthFrames(apBssid, clientMac, 8, frequency);
                finishRun(runId, result.success() ? "DEAUTH_SENT" : "FAILED", result.success());
                if (!result.success()) {
                    ctx.status(500).json(Map.of("error", "Deauth injection failed",
                            "output", Objects.toString(result.output(), "")));
                    return;
                }
                wifi.holdPassiveFrequency(frequency, Duration.ofSeconds(10));
                if (!ctx.path().startsWith("/api/ops/")) {
                    ctx.json(Map.of("status", "deauth_sent", "targetClient", clientMac,
                            "message", "SSID will appear in Whistleblower within 10s if the client reconnects."));
                } else {
                    String pmfStatus = PassiveWifiSession.summarizePmf(target.advertisedSecurity());
                    Map<String, Object> response = new LinkedHashMap<>();
                    response.put("status", "deauth_sent");
                    response.put("targetClient", clientMac);
                    response.put("message", "SSID will appear in Whistleblower within 10s if the client reconnects.");
                    response.put("apId", target.bssid());
                    response.put("channel", details.channel());
                    response.put("frequencyMhz", frequency);
                    response.put("holdSeconds", 10);
                    response.put("pmfStatus", pmfStatus);
                    response.put("dfsChannel", PassiveWifiSession.isDfsFrequency(frequency));
                    if ("Required".equalsIgnoreCase(pmfStatus)) {
                        response.put("pmfWarning",
                                "Target AP requires 802.11w PMF; compliant stations ignore unsigned deauthentication frames.");
                    }
                    ctx.json(response);
                }
            } finally {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearInjectorSlotLocked(injector, runId));
            }
        };
        io.javalin.http.Handler pmkidStatusHandler = ctx -> ctx.json(pmkidStatus());
        io.javalin.http.Handler pmkidHandler = ctx -> {
            final PmkidCapture capture;
            final String wordlist, monitor, resolvedAp;
            final int duration;
            final boolean captureOnly;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
                captureOnly = optionalBoolean(body, "captureOnly", false);
                wordlist = captureOnly ? optionalText(body, "wordlistPath") : requiredWordlist(body);
                duration = integer(body, "durationSeconds", 30, 1, 300);
                String targetId = optionalText(body, "targetId");
                String apId = optionalText(body, "apId");
                String ap = optionalText(body, "apBssid");
                Integer requestedFrequency = optionalOpsFrequency(body);
                String scopedAp = null;
                int resolvedFrequency = requestedFrequency == null ? 0 : requestedFrequency;
                if (targetId != null || apId != null || ap != null) {
                    OpsTargets.Resolved resolved = tryResolveTarget(targetId, apId, ap, null);
                    if (resolved != null) {
                        scopedAp = resolved.apBssid();
                        resolvedFrequency = resolved.frequencyMhz();
                        if (requestedFrequency != null && requestedFrequency != resolvedFrequency)
                            throw new IllegalArgumentException("AP frequency changed. Select the AP again from the refreshed list.");
                    } else {
                        HandshakeAnalyzer.validateTarget(ap, null, 6);
                        scopedAp = ap.strip();
                    }
                }
                resolvedAp = scopedAp;
                if (!captureOnly) HandshakeAnalyzer.readableFile(wordlist, HandshakeAnalyzer.WORDLIST_MISSING);
                capture = pmkidFactory.apply(new PmkidSettings(monitor, wordlist, duration, resolvedAp,
                        resolvedFrequency, captureOnly));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            } catch (java.io.IOException missing) {
                ctx.status(404).json(Map.of("error", missing.getMessage()));
                return;
            }
            releaseIdleLease();
            final UUID runId;
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activePmkid = capture;
                activePmkidVerification = false;
                latestPmkid = capture;
                latestPmkidCapture = capture;
                runId = startRunLocked("pmkid", resolvedAp != null ? resolvedAp : "All nearby APs", monitor);
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(monitor, true,
                        () -> activePmkid == capture, () -> clearPmkidSlotLocked(capture, runId));
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            runPmkid(ctx, capture, lease, runId, duration, () -> capture.run(wordlist, duration, captureOnly));
        };
        io.javalin.http.Handler pmkidFinishHandler = ctx -> {
            PmkidCapture current;
            synchronized (injectionLock) {
                current = activePmkid != null && !activePmkidVerification ? activePmkid : null;
            }
            ctx.json(Map.of("finishing", current != null && current.finishCaptureEarly()));
        };
        io.javalin.http.Handler pmkidVerifyHandler = ctx -> {
            final PmkidCapture verifier;
            final String wordlist;
            final Path hashFile;
            final String targetSummary;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                wordlist = requiredWordlist(body);
                HandshakeAnalyzer.readableFile(wordlist, HandshakeAnalyzer.WORDLIST_MISSING);
                String requestedHash = optionalText(body, "hashPath");
                String apBssid = optionalText(body, "apBssid");
                if (apBssid != null) {
                    HandshakeAnalyzer.validateTarget(apBssid, null, 6);
                    apBssid = apBssid.strip();
                }
                PmkidCapture latest = latestPmkidCapture != null ? latestPmkidCapture : latestPmkid;
                Path retained = latest == null ? null : latest.capturedHashFile();
                if (retained == null || !Files.isRegularFile(retained)) {
                    ctx.status(404).json(Map.of("error", "No captured PMKID hash file is available"));
                    return;
                }
                if (requestedHash != null && !Path.of(requestedHash).toAbsolutePath().normalize().equals(retained)) {
                    throw new IllegalArgumentException("hashPath must match the latest PMKID capture");
                }
                hashFile = retained;
                targetSummary = apBssid != null ? hashFile.getFileName() + " (" + apBssid + ")"
                        : hashFile.getFileName().toString();
                verifier = pmkidFactory.apply(new PmkidSettings("wlo1", wordlist, 30, apBssid, 0, false));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            } catch (IOException missing) {
                ctx.status(404).json(Map.of("error", missing.getMessage()));
                return;
            }
            final UUID runId;
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activePmkid = verifier;
                activePmkidVerification = true;
                latestPmkid = verifier;
                runId = startRunLocked("pmkid-verify", targetSummary, null);
            }
            runPmkid(ctx, verifier, null, runId, 300, () -> verifier.verifyCapturedHashes(hashFile, wordlist));
        };
        io.javalin.http.Handler beaconStatusHandler = ctx -> ctx.json(beaconStatus());
        io.javalin.http.Handler beaconHandler = ctx -> {
            final BeaconSettings settings;
            final BeaconFlood flood;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String monitor = body.has("interface") ? requiredText(body, "interface") : "wlo1";
                List<String> ssids;
                String ssid;
                if (body.has("ssids") && !body.path("ssids").isNull()) {
                    var node = body.path("ssids");
                    if (!node.isArray() || node.isEmpty() || node.size() > 50)
                        throw new IllegalArgumentException("ssids must be an array of 1–50 network names");
                    var parsed = new ArrayList<String>(node.size());
                    for (var item : node) {
                        if (!item.isTextual() || item.textValue().isBlank())
                            throw new IllegalArgumentException("Each SSID in ssids must be a nonempty string");
                        String value = item.textValue();
                        if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 32
                                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
                            throw new IllegalArgumentException("ssid must be 1–32 UTF-8 bytes on one line");
                        }
                        parsed.add(value);
                    }
                    ssids = List.copyOf(parsed);
                    ssid = ssids.getFirst();
                } else {
                    ssid = requiredText(body, "ssid");
                    ssids = List.of(ssid);
                }
                int channel = integer(body, "channel", 6, 1, 233);
                int rate = integer(body, "rate", 100, 1, 10_000);
                settings = new BeaconSettings(monitor, ssid, channel, rate, ssids);
                flood = beaconFactory.apply(settings);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            releaseIdleLease();
            final UUID runId;
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activeBeacon = flood;
                latestBeacon = flood;
                String targetSummary = settings.ssids().size() > 1
                        ? settings.ssids().getFirst() + " (+" + (settings.ssids().size() - 1) + ")"
                        : settings.ssid();
                runId = startRunLocked("beacon", targetSummary, settings.monitorInterface());
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(settings.monitorInterface(), false,
                        () -> activeBeacon == flood, () -> clearBeaconSlotLocked(flood, runId));
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var status = settings.ssids().size() > 1
                        ? flood.start(settings.ssids(), settings.channel(), settings.rate())
                        : flood.start(settings.ssid(), settings.channel(), settings.rate());
                if (!status.running()) {
                    finishRun(runId, "FAILED", false);
                    releaseOperation(lease, () -> clearBeaconSlotLocked(flood, runId));
                }
                ctx.json(status);
            } catch (java.io.IOException failure) {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearBeaconSlotLocked(flood, runId));
                ctx.status(500).json(Map.of("error", Objects.toString(failure.getMessage(), "Beacon flood failed")));
            } catch (IllegalArgumentException invalid) {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearBeaconSlotLocked(flood, runId));
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (IllegalStateException conflict) {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearBeaconSlotLocked(flood, runId));
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
                boolean configureAddress = optionalBoolean(body, "configureAddress", false);
                settings = new EvilTwinSettings(apInterface, ssid, channel, portalPort, configureAddress);
                twin = evilTwinFactory.apply(settings);
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            releaseIdleLease();
            final UUID runId;
            synchronized (injectionLock) {
                if (closing || anyActive()) {
                    ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                    return;
                }
                activeEvilTwin = twin;
                latestEvilTwin = twin;
                runId = startRunLocked("evil-twin", settings.ssid(), settings.apInterface());
            }
            final PacketBridge.OpsLease lease;
            try {
                lease = acquireLeaseOutsideLock(settings.apInterface(), true,
                        () -> activeEvilTwin == twin, () -> clearEvilTwinSlotLocked(twin, runId));
            } catch (IllegalStateException conflict) {
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
                return;
            }
            try {
                var status = twin.start();
                if (!status.running()) {
                    finishRun(runId, "FAILED", false);
                    releaseOperation(lease, () -> clearEvilTwinSlotLocked(twin, runId));
                }
                ctx.json(status);
            } catch (java.io.IOException failure) {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearEvilTwinSlotLocked(twin, runId));
                ctx.status(500).json(Map.of("error", Objects.toString(failure.getMessage(), "Evil twin failed to start")));
            } catch (IllegalArgumentException invalid) {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearEvilTwinSlotLocked(twin, runId));
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
            } catch (IllegalStateException conflict) {
                finishRun(runId, "FAILED", false);
                releaseOperation(lease, () -> clearEvilTwinSlotLocked(twin, runId));
                ctx.status(409).json(Map.of("error", conflict.getMessage()));
            }
        };
        io.javalin.http.Handler handshakeHandler = ctx -> {
            final HandshakeAnalyzer analyzer;
            final String monitor, targetSummary;
            final int timeoutSeconds;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                String targetId = optionalText(body, "targetId");
                String apId = optionalText(body, "apId");
                String ap = optionalText(body, "apBssid");
                if (targetId == null && apId == null && ap == null)
                    throw new IllegalArgumentException("targetId, apId, or apBssid is required");
                String client = optionalText(body, "clientMac");
                String ssid = optionalText(body, "ssid");
                timeoutSeconds = integer(body, "timeoutSeconds", 90, 10, 180);
                var channelNode = body.path("channel");
                Integer requestedChannel = null;
                if (!channelNode.isMissingNode() && !channelNode.isNull()) {
                    if (!channelNode.isIntegralNumber() || !channelNode.canConvertToInt())
                        throw new IllegalArgumentException("channel must be an integer in 1–233");
                    requestedChannel = channelNode.intValue();
                }
                int hintedChannel = requestedChannel == null ? 0 : HandshakeAnalyzer.normalizeChannel(requestedChannel);
                if (hintedChannel > 233) throw new IllegalArgumentException("channel must be an integer in 1–233");
                Integer requestedFrequency = optionalOpsFrequency(body);
                OpsTargets.Resolved resolved = tryResolveTarget(targetId, apId, ap, client);
                int channel;
                int frequency;
                if (resolved != null) {
                    ap = resolved.apBssid();
                    client = resolved.clientMac();
                    channel = resolved.channel();
                    frequency = resolved.frequencyMhz();
                    if (ssid == null) ssid = resolved.ssid();
                    if (requestedFrequency != null && requestedFrequency != frequency)
                        throw new IllegalArgumentException("AP frequency changed. Select the AP again from the refreshed list.");
                } else {
                    frequency = requestedFrequency == null ? HandshakeAnalyzer.frequencyMhz(hintedChannel) : requestedFrequency;
                    channel = requestedFrequency == null ? hintedChannel : ewave.decoder.Dot11FrameDecoder.channel(frequency);
                    if (requestedChannel != null && requestedChannel != channel)
                        throw new IllegalArgumentException("channel does not match frequencyMhz");
                    HandshakeAnalyzer.validateTarget(ap, client, channel);
                }
                boolean allowMacRotation = optionalBoolean(body, "allowMacRotation", false);
                monitor = optionalText(body, "interface") == null ? "wlo1" : requiredText(body, "interface");
                targetSummary = ssid != null && !ssid.isBlank() ? ap + " (" + ssid + ")" : ap;
                analyzer = handshakeFactory.apply(new HandshakeSettings(monitor, ap, client, channel, ssid,
                        frequency, allowMacRotation, timeoutSeconds));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            }
            runHandshake(ctx, analyzer, monitor, true, timeoutSeconds, targetSummary, analyzer::capture);
        };
        io.javalin.http.Handler handshakeFinishHandler = ctx -> {
            HandshakeAnalyzer current;
            synchronized (injectionLock) {
                current = activeHandshake != null && !activeHandshakeVerification ? activeHandshake : null;
            }
            ctx.json(Map.of("finishing", current != null && current.finishEarly()));
        };
        io.javalin.http.Handler handshakeSaveRecordingHandler = ctx -> {
            String requestedCap = null, requestedName = null;
            String rawBody = ctx.body();
            if (rawBody != null && !rawBody.isBlank()) {
                try {
                    var body = mapper.readTree(rawBody);
                    if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                    requestedCap = optionalText(body, "capFilePath");
                    requestedName = optionalText(body, "name");
                } catch (JsonProcessingException | IllegalArgumentException invalid) {
                    ctx.status(400).json(Map.of("error", invalid.getMessage()));
                    return;
                }
            }
            HandshakeAnalyzer latest = latestHandshake;
            Path captured = latest == null ? null : latest.capturedFile();
            if (captured == null || !Files.isRegularFile(captured)) {
                ctx.status(404).json(Map.of("error", "No captured handshake file is available"));
                return;
            }
            if (requestedCap != null && !Path.of(requestedCap).toAbsolutePath().normalize().equals(captured)) {
                ctx.status(400).json(Map.of("error", "capFilePath must match the latest handshake capture"));
                return;
            }
            String filename = requestedName != null
                    ? requestedName.strip()
                    : captured.getFileName().toString().replaceFirst("\\.cap$", ".pcap");
            try (var input = Files.newInputStream(captured)) {
                ctx.status(201).json(recordingLibrary.add(filename, input));
            } catch (RecordingLibrary.TooLarge tooLarge) {
                ctx.status(413).json(Map.of("error", "Recording exceeds 128 MiB"));
            } catch (IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", Objects.toString(invalid.getMessage(), "Invalid capture file")));
            } catch (IOException failure) {
                ctx.status(500).json(Map.of("error", "Could not save handshake recording: " + failure.getMessage()));
            }
        };
        io.javalin.http.Handler handshakeVerifyHandler = ctx -> {
            final HandshakeAnalyzer analyzer;
            final String cap, wordlist, targetSummary;
            try {
                var body = mapper.readTree(ctx.body());
                if (body == null || !body.isObject()) throw new IllegalArgumentException("Expected a JSON object");
                cap = requiredText(body, "capFilePath");
                wordlist = requiredWordlist(body);
                // Check the dictionary first to preserve the actionable missing-wordlist response.
                HandshakeAnalyzer.readableFile(wordlist, HandshakeAnalyzer.WORDLIST_MISSING);
                HandshakeAnalyzer.readableFile(cap, "Capture file not found or unreadable");
                String ap = optionalText(body, "apBssid");
                if (ap == null && latestHandshake != null)
                    ap = latestHandshake.capturedBssid(Path.of(cap).toAbsolutePath().normalize());
                if (ap == null) throw new IllegalArgumentException("apBssid is required for an imported capture");
                HandshakeAnalyzer.validateTarget(ap, null, 6);
                targetSummary = Path.of(cap).getFileName() + " (" + ap + ")";
                analyzer = handshakeFactory.apply(new HandshakeSettings("wlo1", ap, null, 6));
            } catch (JsonProcessingException | IllegalArgumentException invalid) {
                ctx.status(400).json(Map.of("error", invalid.getMessage()));
                return;
            } catch (java.io.IOException missing) {
                ctx.status(404).json(Map.of("error", missing.getMessage()));
                return;
            }
            runHandshake(ctx, analyzer, null, false, 300, targetSummary, () -> analyzer.verifyPsk(cap, wordlist));
        };

        for (String prefix : List.of("/api/ops", "/api/attack")) {
            app.post(prefix + "/stop", stopHandler);
            app.get(prefix + "/capabilities", capabilitiesHandler);
            app.get(prefix + "/history", historyHandler);
            app.delete(prefix + "/history", clearHistoryHandler);
            app.get(prefix + "/targets", targetsHandler);
            app.get(prefix + "/aps", apsHandler);
            app.get(prefix + "/scan-lan", scanLanHandler);
            app.get(prefix + "/lan-hosts", lanHostsHandler);
            app.get(prefix + "/status", deauthStatusHandler);
            app.post(prefix + "/deauth", deauthHandler);
            app.post(prefix + "/uncloak", uncloakHandler);
            app.get(prefix + "/handshake/status", handshakeStatusHandler);
            app.post(prefix + "/handshake", handshakeHandler);
            app.post(prefix + "/handshake/finish", handshakeFinishHandler);
            app.post(prefix + "/handshake/save-recording", handshakeSaveRecordingHandler);
            app.post(prefix + "/handshake/verify", handshakeVerifyHandler);
            app.get(prefix + "/pmkid/status", pmkidStatusHandler);
            app.post(prefix + "/pmkid", pmkidHandler);
            app.post(prefix + "/pmkid/finish", pmkidFinishHandler);
            app.post(prefix + "/pmkid/verify", pmkidVerifyHandler);
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

    private static String optionalText(com.fasterxml.jackson.databind.JsonNode body, String field) {
        var node = body.path(field);
        if (node.isMissingNode() || node.isNull()) return null;
        if (!node.isTextual()) throw new IllegalArgumentException(field + " must be a string");
        String value = node.textValue();
        return value == null || value.isBlank() ? null : value;
    }

    private static boolean optionalBoolean(com.fasterxml.jackson.databind.JsonNode body, String field, boolean fallback) {
        var node = body.path(field);
        if (node.isMissingNode() || node.isNull()) return fallback;
        if (!node.isBoolean()) throw new IllegalArgumentException(field + " must be a boolean");
        return node.booleanValue();
    }

    private static Integer optionalOpsFrequency(com.fasterxml.jackson.databind.JsonNode body) {
        var node = body.path("frequencyMhz");
        if (node.isMissingNode() || node.isNull()) return null;
        if (!node.isIntegralNumber() || !node.canConvertToInt())
            throw new IllegalArgumentException("frequencyMhz must be an integer");
        int frequency = node.intValue();
        HandshakeAnalyzer.validateFrequency(frequency);
        return frequency;
    }

    private OpsTargets.Resolved tryResolveTarget(String targetId, String apId, String apBssid, String clientMac) {
        boolean liveSelector = targetId != null || apId != null;
        if (!liveSelector && apBssid == null) return null;
        try {
            return resolveOpsTarget(targetId, apId, apBssid, clientMac, false);
        } catch (IllegalArgumentException unresolved) {
            var current = wifi.getPassiveWifi();
            if (liveSelector || current != null && apBssid != null && current.observedAp(current.addressId(apBssid)) != null)
                throw unresolved;
            return null;
        }
    }

    private static String requiredWordlist(com.fasterxml.jackson.databind.JsonNode body) {
        var node = body.path("wordlistPath");
        if (!node.isMissingNode() && !node.isNull() && !node.isTextual())
            throw new IllegalArgumentException("wordlistPath must be a nonempty string");
        if (node.isTextual() && !node.textValue().isBlank()) return node.textValue();
        String configured = configuredWordlist();
        if (configured != null) return configured;
        throw new IllegalArgumentException("wordlistPath is required (or set -Drf.wordlist=/path/to/wordlist)");
    }

    private static String configuredWordlist() {
        String property = System.getProperty("rf.wordlist");
        if (property != null && !property.isBlank()) return property;
        String environment = System.getenv("EWAVE_WORDLIST");
        return environment == null || environment.isBlank() ? null : environment;
    }

    /**
     * Resolves a live Ops target before any radio lease is taken. Dashboard target ids and AP tokens
     * keep real addresses server-side; raw MACs remain available for direct lab calls.
     */
    private OpsTargets.Resolved resolveOpsTarget(String targetId, String apId, String apBssid, String clientMac,
                                                  boolean clientRequired) {
        var session = wifi.getPassiveWifi();
        if (session != null && session.isReplaySession()) {
            throw new IllegalArgumentException("Lab operations are unavailable for replay sessions");
        }
        List<PassiveWifiSession.EvidencedTarget> targets = session == null
                ? List.of() : session.evidencedTargets(wifi.getProfiler());
        List<TopologyBuilder.AccessPoint> observed = session == null
                ? List.of() : session.topology().accessPoints();
        Function<String, PassiveWifiSession.ObservedApDetails> lookup = session == null ? ignored -> null : session::directlyObservedAp;
        List<WifiAccessPoints.AccessPoint> cached;
        try {
            cached = accessPoints.all();
        } catch (java.io.IOException missing) {
            cached = List.of();
        }
        return OpsTargets.resolve(targetId, apId, apBssid, clientMac, targets, observed, lookup, cached, clientRequired);
    }

    private UUID startRunLocked(String operation, String target, String interfaceName) {
        UUID id = UUID.randomUUID();
        activeRun = new PendingRun(id, operation, blankToNull(target), blankToNull(interfaceName),
                Instant.now(), new AtomicBoolean());
        activeOperationId = id;
        return id;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    private void finishRun(UUID runId, String outcome, boolean success) {
        if (runId == null) return;
        synchronized (injectionLock) {
            if (activeRun != null && activeRun.id().equals(runId) && activeRun.finalized().compareAndSet(false, true)) {
                recordCompletedLocked(activeRun, outcome, success);
            }
        }
    }

    /** Called while holding injectionLock. */
    private void finishActiveRunLocked(String outcome, boolean success, boolean clearIfIdle) {
        if (activeRun != null && activeRun.finalized().compareAndSet(false, true)) {
            recordCompletedLocked(activeRun, outcome, success);
        }
        if (clearIfIdle && !anySlotOccupiedLocked()) {
            activeRun = null;
            activeOperationId = null;
        }
    }

    private void recordCompletedLocked(PendingRun run, String outcome, boolean success) {
        Instant endedAt = Instant.now();
        long durationMs = Math.max(0L, Duration.between(run.startedAt(), endedAt).toMillis());
        operationHistory.addFirst(new OperationHistoryEntry(
                run.id(), run.operation(), run.target(), run.interfaceName(),
                run.startedAt(), endedAt, durationMs, outcome, success));
        while (operationHistory.size() > OPERATION_HISTORY_LIMIT) operationHistory.removeLast();
    }

    private void clearRunLocked(UUID runId) {
        if (runId != null && activeRun != null && activeRun.id().equals(runId)) {
            if (activeRun.finalized().compareAndSet(false, true)) {
                recordCompletedLocked(activeRun, "FAILED", false);
            }
            activeRun = null;
            activeOperationId = null;
        }
    }

    private void clearInjectorSlotLocked(FrameInjector injector, UUID runId) {
        if (activeInjector == injector) activeInjector = null;
        clearRunLocked(runId);
    }

    private void clearPmkidSlotLocked(PmkidCapture capture, UUID runId) {
        if (activePmkid == capture) {
            activePmkid = null;
            activePmkidVerification = false;
        }
        clearRunLocked(runId);
    }

    private void clearBeaconSlotLocked(BeaconFlood flood, UUID runId) {
        if (activeBeacon == flood) activeBeacon = null;
        clearRunLocked(runId);
    }

    private void clearEvilTwinSlotLocked(EvilTwin twin, UUID runId) {
        if (activeEvilTwin == twin) activeEvilTwin = null;
        clearRunLocked(runId);
    }

    private void clearHandshakeSlotLocked(HandshakeAnalyzer analyzer, UUID runId) {
        if (activeHandshake == analyzer) activeHandshake = null;
        clearRunLocked(runId);
    }

    private List<OperationHistoryEntry> operationHistory() {
        synchronized (injectionLock) {
            activeOperation();
            return List.copyOf(operationHistory);
        }
    }

    private void clearOperationHistory() {
        synchronized (injectionLock) {
            operationHistory.clear();
        }
    }

    /** The single server-wide operation slot, exposed to the Ops console. */
    private String activeOperation() {
        synchronized (injectionLock) {
            if (activeInjector != null) return "deauth";
            if (activeHandshake != null) return activeHandshakeVerification ? "handshake-verify" : "handshake";
            if (activePmkid != null) return activePmkidVerification ? "pmkid-verify" : "pmkid";
            if (beaconActive()) return "beacon";
            if (evilTwinActive()) return "evil-twin";
            return null;
        }
    }

    /** Called while holding injectionLock so a naturally exited beacon stops blocking new operations. */
    private boolean beaconActive() {
        if (activeBeacon != null && !activeBeacon.status().running()) {
            activeBeacon = null;
            finishActiveRunLocked("STOPPED", true, true);
        }
        return activeBeacon != null;
    }

    /** Called while holding injectionLock so a stopped evil twin stops blocking new operations. */
    private boolean evilTwinActive() {
        if (activeEvilTwin != null) {
            var status = activeEvilTwin.status();
            if (!status.running()) {
                activeEvilTwin = null;
                boolean failed = status.error() != null && !status.error().isBlank();
                finishActiveRunLocked(failed ? "FAILED" : "STOPPED", !failed, true);
            }
        }
        return activeEvilTwin != null;
    }

    private boolean anySlotOccupiedLocked() {
        return activeInjector != null || activeHandshake != null || activePmkid != null
                || activeBeacon != null || activeEvilTwin != null;
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
                          UUID runId, int duration, Callable<PmkidCapture.Result> task) {
        var timedOut = new AtomicBoolean();
        try {
            ctx.async(config -> {
                config.timeout = Math.min(900_000L, (duration + 330L) * 1000L);
                config.onTimeout(context -> {
                    timedOut.set(true);
                    capture.terminate();
                    finishRun(runId, "TIMED_OUT", false);
                    context.status(504).json(Map.of("error", "PMKID capture timed out"));
                });
            }, () -> {
                try {
                    PmkidCapture.Result result = task.call();
                    String outcome = result.vulnerable() ? "PSK_FOUND"
                            : result.captured() && result.verificationSkipped() ? "PMKID_CAPTURED"
                            : (result.captured() ? "CAPTURED" : "NO_PMKID");
                    finishRun(runId, outcome, true);
                    if (!timedOut.get()) ctx.json(result);
                } catch (Exception failure) {
                    if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
                    if (failure instanceof TimeoutException) {
                        finishRun(runId, "TIMED_OUT", false);
                    } else if (failure instanceof CancellationException || failure instanceof InterruptedException) {
                        finishRun(runId, "STOPPED", true);
                    } else {
                        finishRun(runId, "FAILED", false);
                    }
                    int status = failure instanceof TimeoutException ? 504
                            : failure instanceof CancellationException || failure instanceof InterruptedException ? 409 : 500;
                    if (!timedOut.get()) ctx.status(status).json(Map.of("error",
                            Objects.toString(failure.getMessage(), "PMKID operation failed")));
                } finally {
                    finishRun(runId, timedOut.get() ? "TIMED_OUT" : "FAILED", false);
                    releaseOperation(lease, () -> clearPmkidSlotLocked(capture, runId));
                }
            });
        } catch (RuntimeException failure) {
            finishRun(runId, "FAILED", false);
            releaseOperation(lease, () -> clearPmkidSlotLocked(capture, runId));
            throw failure;
        }
    }

    private void runHandshake(io.javalin.http.Context ctx, HandshakeAnalyzer analyzer, String monitor,
                              boolean capture, int timeoutSeconds, String targetSummary, Callable<?> operation) {
        if (capture) releaseIdleLease();
        final UUID runId;
        synchronized (injectionLock) {
            if (closing || anyActive()) {
                ctx.status(409).json(Map.of("error", "An active operation is already running or the server is stopping"));
                return;
            }
            activeHandshake = analyzer;
            activeHandshakeVerification = !capture;
            showingVerification = !capture;
            if (capture) latestHandshake = analyzer;
            else latestVerification = analyzer;
            runId = startRunLocked(capture ? "handshake" : "handshake-verify", targetSummary, monitor);
        }
        final PacketBridge.OpsLease lease;
        if (capture) {
            try {
                lease = acquireLeaseOutsideLock(monitor, false,
                        () -> activeHandshake == analyzer, () -> clearHandshakeSlotLocked(analyzer, runId));
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
                // Allow time for tuning, the configured capture window, and decoder shutdown.
                config.timeout = capture ? Math.max(110_000L, (timeoutSeconds + 25L) * 1000L) : 310_000L;
                config.onTimeout(context -> {
                    timedOut.set(true);
                    analyzer.terminate();
                    finishRun(runId, "TIMED_OUT", false);
                    context.status(504).json(Map.of("error", capture ? "Handshake capture timed out" : "PSK verification timed out"));
                });
            }, () -> {
                try {
                    Object result = operation.call();
                    String outcome = "COMPLETE";
                    if (result instanceof HandshakeResult hr) outcome = hr.outcome().name();
                    else if (result instanceof PskVerificationResult pvr)
                        outcome = pvr.vulnerable() ? "KEY_FOUND" : "KEY_NOT_FOUND";
                    finishRun(runId, outcome, true);
                    if (!timedOut.get()) ctx.json(result);
                } catch (Exception failure) {
                    if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
                    if (failure instanceof TimeoutException) {
                        finishRun(runId, "TIMED_OUT", false);
                    } else if (failure instanceof CancellationException || failure instanceof InterruptedException) {
                        finishRun(runId, "STOPPED", true);
                    } else {
                        finishRun(runId, "FAILED", false);
                    }
                    int status = failure instanceof TimeoutException ? 504
                            : failure instanceof CancellationException || failure instanceof InterruptedException ? 409 : 500;
                    if (!timedOut.get()) ctx.status(status).json(Map.of("error", Objects.toString(failure.getMessage(), "Handshake operation failed")));
                } finally {
                    finishRun(runId, timedOut.get() ? "TIMED_OUT" : "FAILED", false);
                    releaseOperation(lease, () -> clearHandshakeSlotLocked(analyzer, runId));
                }
            });
        } catch (RuntimeException failure) {
            finishRun(runId, "FAILED", false);
            releaseOperation(lease, () -> clearHandshakeSlotLocked(analyzer, runId));
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

    public void broadcast(EwaveEvent event) {
        Objects.requireNonNull(event, "event");
        if (event.type().equals("WIFI_DEVICE_SEEN") || event.type().equals("PROBE_RECEIVED")) return;
        sendEvent(event);
    }

    private void sendEvent(Object event) {
        synchronized (wifi) {
            if (!operationsEnabled()) return;
            var session = wifi.getPassiveWifi();
            eventStream.publish(event, session == null ? null : session.sessionId());
        }
    }

    private static String channelWarning(PacketBridge.ChannelSnapshot snapshot, int channel) {
        if (snapshot == null) return null;
        Integer frequency = PacketBridge.channelFrequencyMhz(channel);
        if (frequency == null) return null;
        int slot = snapshot.slotForFrequency(frequency);
        var scores = snapshot.scanner().scores();
        if (slot < 0 || !(scores[slot] < 0.10)) return null;
        return String.format(Locale.ROOT, "Channel %d score %.2f is low. The scanner measures channel activity, so check the cached AP channel.",
                channel, scores[slot]);
    }

    private void pollScannerEvents(Map<Integer, Instant> suggestedAt, Map<Integer, Instant> suggestedFlags) {
        try {
            releaseIdleLease();
            if (!operationsEnabled()) return;
            if (eventStream.isEmpty() && reconnectWatches.isEmpty()) return;
            var snapshot = wifi.getChannelSnapshot();
            Instant now = Instant.now();
            reconnectWatches.forEach((channel, started) -> {
                if (!now.isBefore(started.plusSeconds(30))) {
                    reconnectWatches.remove(channel, started);
                    return;
                }
                Integer frequency = PacketBridge.channelFrequencyMhz(channel);
                var flag = snapshot == null || frequency == null ? null
                        : snapshot.scanner().anomalies().get(snapshot.slotForFrequency(frequency) + 1);
                if (flag != null && !flag.detectedAt().isBefore(started)
                        && (flag.reason().equals("NEW_ACTIVITY") || flag.reason().equals("UNUSUAL_BURST"))
                        && reconnectWatches.remove(channel, started)) {
                    sendEvent(Map.of("type", "eapol_window", "channel", channel,
                            "reason", flag.reason(), "deviation", flag.deviation()));
                }
            });
            if (snapshot == null) return;
            snapshot.scanner().anomalies().forEach((index, flag) -> {
                var target = snapshot.channels().get(index - 1);
                int channel = target.channel();
                if (!Objects.equals(PacketBridge.channelFrequencyMhz(channel), target.frequencyMhz())
                        || !flag.reason().equals("NEW_ACTIVITY")
                        || flag.detectedAt().equals(suggestedFlags.get(channel))) return;
                Instant last = suggestedAt.get(channel);
                if (last != null && now.isBefore(last.plusSeconds(60))) return;
                suggestedAt.put(channel, now);
                suggestedFlags.put(channel, flag.detectedAt());
                var fingerprint = snapshot.scanner().fingerprints().get(index - 1);
                sendEvent(Map.of("type", "anomaly_target", "channel", channel, "deviation", flag.deviation(),
                        "deviceHint", Objects.toString(fingerprint.deviceHint(), "Unknown device"),
                        "detectedAt", flag.detectedAt().toString()));
            });
        } catch (RuntimeException failure) {
            LOG.log(System.Logger.Level.WARNING, "Could not broadcast scanner event", failure);
        }
    }

    private void consumeEvents() {
        long interval = TimeUnit.SECONDS.toNanos(1);
        long nextFlush = System.nanoTime() + interval;
        while (!closing && !Thread.currentThread().isInterrupted()) {
            try {
                long remaining = nextFlush - System.nanoTime();
                if (remaining <= 0) {
                    nextFlush = System.nanoTime() + interval;
                    if (!eventStream.isEmpty()) eventStream.flush(wifi.reportProgress());
                    continue;
                }
                EwaveEvent event = events.poll(remaining, TimeUnit.NANOSECONDS);
                if (!closing && event != null) broadcast(event);
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
            leaseToClose = stopOperationsLocked();
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
            eventStream.clear();
            eventThread = null;
        }
    }

    @Override public void close() { stop(); }
}
